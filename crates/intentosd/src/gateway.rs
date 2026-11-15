#![forbid(unsafe_code)]

//! Model Gateway (WP08, §5.3, §5.4):
//! - Single model egress point for IntentOS
//! - Validates `run_token` -> `(task_id, data_class, profile)`
//! - Enforces Egress Matrix (`DataClass × ProviderTrust`) before upstream call
//! - Injects credentials from Secret Service / Core-only memory (never exposed to Worker or logs)
//! - Serves HTTP-over-Unix-Socket (`gateway.sock`) for zero-network Agent Workers

use crate::config::{
    BrainConfig, EgressVerdict, ProfileConfig, ProviderConfig, XdgPaths, check_egress_matrix,
};
use crate::db::StateDb;
use intentos_protocol::DataClass;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Clone)]
pub struct RunLease {
    pub run_token: String,
    pub task_id: String,
    pub profile_name: String,
    pub data_class: DataClass,
    pub cancelled: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GatewayMetrics {
    pub total_requests: u64,
    pub blocked_egress: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("egress_denied: {0}")]
    EgressDenied(String),
    #[error("invalid_or_cancelled_run_token")]
    InvalidToken,
    #[error("model_not_configured: {0}")]
    NotConfigured(String),
    #[error("upstream_error: {0}")]
    Upstream(String),
}

pub struct ModelGateway {
    brain: Mutex<BrainConfig>,
    paths: Mutex<Option<XdgPaths>>,
    state_db: Arc<StateDb>,
    http_client: reqwest::Client,
    local_client: reqwest::Client,
    leases: Mutex<HashMap<String, RunLease>>,
    req_counter: AtomicU64,
    blocked_counter: AtomicU64,
    in_tokens: AtomicU64,
    out_tokens: AtomicU64,
    /// Optional mock/replay responder URL or handler for deterministic testing without internet
    mock_upstream_url: Mutex<Option<String>>,
}

impl ModelGateway {
    pub fn new(brain: BrainConfig, state_db: Arc<StateDb>) -> anyhow::Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let local_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        Ok(Self {
            brain: Mutex::new(brain),
            paths: Mutex::new(None),
            state_db,
            http_client,
            local_client,
            leases: Mutex::new(HashMap::new()),
            req_counter: AtomicU64::new(0),
            blocked_counter: AtomicU64::new(0),
            in_tokens: AtomicU64::new(0),
            out_tokens: AtomicU64::new(0),
            mock_upstream_url: Mutex::new(None),
        })
    }

    pub fn set_paths(&self, paths: XdgPaths) {
        *self.paths.lock().unwrap() = Some(paths);
    }

    pub fn update_brain_config(&self, new_brain: BrainConfig) {
        *self.brain.lock().unwrap() = new_brain;
    }

    pub fn reload_from_disk_if_available(&self) {
        let maybe_paths = self.paths.lock().unwrap().clone();
        if let Some(paths) = maybe_paths {
            let b_path = paths.config_dir.join("brain.toml");
            if b_path.exists()
                && let Ok(raw) = std::fs::read_to_string(&b_path)
                && let Ok(parsed) = toml::from_str::<BrainConfig>(&raw)
            {
                *self.brain.lock().unwrap() = parsed;
            }
        }
    }

    pub fn set_mock_upstream_url(&self, url: Option<String>) {
        *self.mock_upstream_url.lock().unwrap() = url;
    }

    pub fn has_usable_credentials(&self) -> bool {
        if self.mock_upstream_url.lock().unwrap().is_some() {
            return true;
        }
        self.reload_from_disk_if_available();
        let (_, provider) = match self.resolve_profile("main") {
            Ok(p) => p,
            Err(_) => return false,
        };
        // Local proxy (127.0.0.1 / localhost) may not require a key, or key exists in vault / env / secret-tool
        if provider.base_url.contains("127.0.0.1") || provider.base_url.contains("localhost") {
            return true;
        }
        self.lookup_credential_with_vault(&provider.id, &provider.credential_ref)
            .is_some()
    }

    pub fn metrics(&self) -> GatewayMetrics {
        GatewayMetrics {
            total_requests: self.req_counter.load(Ordering::Relaxed),
            blocked_egress: self.blocked_counter.load(Ordering::Relaxed),
            total_input_tokens: self.in_tokens.load(Ordering::Relaxed),
            total_output_tokens: self.out_tokens.load(Ordering::Relaxed),
        }
    }

    pub fn issue_run_lease(
        &self,
        task_id: &str,
        profile_name: &str,
        data_class: DataClass,
    ) -> String {
        let token = format!("rtk_{}", uuid::Uuid::new_v4().simple());
        self.leases.lock().unwrap().insert(
            token.clone(),
            RunLease {
                run_token: token.clone(),
                task_id: task_id.to_string(),
                profile_name: profile_name.to_string(),
                data_class,
                cancelled: false,
            },
        );
        token
    }

    pub fn cancel_task_leases(&self, task_id: &str) {
        let mut map = self.leases.lock().unwrap();
        for lease in map.values_mut() {
            if lease.task_id == task_id {
                lease.cancelled = true;
            }
        }
    }

    pub fn revoke_lease(&self, run_token: &str) {
        self.leases.lock().unwrap().remove(run_token);
    }

    pub fn resolve_profile(
        &self,
        profile_name: &str,
    ) -> Result<(ProfileConfig, ProviderConfig), GatewayError> {
        let brain = self.brain.lock().unwrap();
        let prof = brain
            .profiles
            .get(profile_name)
            .or_else(|| brain.profiles.get(&brain.default_profile))
            .ok_or_else(|| GatewayError::NotConfigured(format!("profile '{}'", profile_name)))?
            .clone();
        let prov = brain
            .providers
            .iter()
            .find(|p| p.id == prof.provider && p.enabled)
            .ok_or_else(|| GatewayError::NotConfigured(format!("provider '{}'", prof.provider)))?
            .clone();
        Ok((prof, prov))
    }

    /// Execute an OpenAI-compatible `/chat/completions` call through the Gateway checks.
    pub async fn proxy_chat_completion(
        &self,
        run_token: &str,
        body: Value,
    ) -> Result<Value, GatewayError> {
        let (val, _) = self
            .proxy_chat_completion_streaming(run_token, body, false, None, |_| {})
            .await?;
        Ok(val)
    }

    /// Execute an OpenAI-compatible `/chat/completions` call through the Gateway checks with
    /// optional SSE (`text/event-stream`) incremental parsing and honest `application/json` fallback (`H10`).
    pub async fn proxy_chat_completion_streaming<F>(
        &self,
        run_token: &str,
        mut body: Value,
        prefer_sse: bool,
        turn_handle: Option<&crate::backend_bridge::turn_checkpoint::ActiveTurnHandle>,
        mut on_delta: F,
    ) -> Result<(Value, bool), GatewayError>
    where
        F: FnMut(&str),
    {
        self.reload_from_disk_if_available();
        let lease = {
            let map = self.leases.lock().unwrap();
            let Some(l) = map.get(run_token) else {
                return Err(GatewayError::InvalidToken);
            };
            if l.cancelled {
                return Err(GatewayError::InvalidToken);
            }
            l.clone()
        };

        let (profile, provider) = self.resolve_profile(&lease.profile_name)?;

        // 1. Egress Matrix Check (§5.4)
        let verdict = check_egress_matrix(lease.data_class, provider.trust);
        if verdict == EgressVerdict::Deny {
            self.blocked_counter.fetch_add(1, Ordering::Relaxed);
            let msg = format!(
                "外发矩阵阻断：任务数据分级 {:?} 不允许发往 {:?} 信任等级供应商 '{}'",
                lease.data_class, provider.trust, provider.id
            );
            let _ = self.state_db.record_audit(
                Some(&lease.task_id),
                "gateway.egress",
                "agent_worker",
                "egress",
                "egress_denied",
                "denied",
                &json!({ "provider": provider.id, "data_class": lease.data_class }),
                Some(&msg),
            );
            return Err(GatewayError::EgressDenied(msg));
        }

        // 2. Scan outgoing payload for accidental forbidden markers (`PRIVATE KEY`, etc.)
        let serialized_check = body.to_string();
        if serialized_check.contains("BEGIN OPENSSH PRIVATE KEY")
            || serialized_check.contains("BEGIN RSA PRIVATE KEY")
        {
            self.blocked_counter.fetch_add(1, Ordering::Relaxed);
            return Err(GatewayError::EgressDenied(
                "检测到疑似私钥内容，网关强制阻断外发".into(),
            ));
        }

        // 3. Inject profile model if missing, and request SSE when `prefer_sse` is enabled
        if let Some(obj) = body.as_object_mut() {
            if !obj.contains_key("model") {
                obj.insert("model".into(), json!(profile.model));
            }
            if prefer_sse && !obj.contains_key("stream") {
                obj.insert("stream".into(), json!(true));
            }
        }

        let mock_url = self.mock_upstream_url.lock().unwrap().clone();
        let target_url = match mock_url {
            Some(ref mu) => format!("{}/chat/completions", mu.trim_end_matches('/')),
            None => {
                let clean_base = provider.base_url.trim_end_matches('/');
                if clean_base.ends_with("/chat/completions") {
                    clean_base.to_string()
                } else {
                    format!("{}/chat/completions", clean_base)
                }
            }
        };

        let api_key = if mock_url.is_some() {
            Some("mock-gateway-injected-key".to_string())
        } else {
            self.lookup_credential_with_vault(&provider.id, &provider.credential_ref)
        };

        if api_key.is_none()
            && !provider.base_url.contains("127.0.0.1")
            && !provider.base_url.contains("localhost")
        {
            return Err(GatewayError::NotConfigured(
                "未检测到模型 API 凭据（可在顶部「接入大模型」或 11 页设置中心 -> 大脑与网关 中填入 API Key）"
                    .into(),
            ));
        }

        self.req_counter.fetch_add(1, Ordering::Relaxed);
        let client = if target_url.starts_with("http://127.0.0.1")
            || target_url.starts_with("http://localhost")
        {
            &self.local_client
        } else {
            &self.http_client
        };
        let mut req = client.post(&target_url).json(&body);
        if prefer_sse {
            req = req.header(
                reqwest::header::ACCEPT,
                "text/event-stream, application/json",
            );
        }
        if let Some(ref key) = api_key {
            req = req.bearer_auth(key);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| GatewayError::Upstream(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Upstream(format!(
                "HTTP {}: {}",
                status, err_text
            )));
        }

        let (resp_json, streamed_sse) =
            crate::backend_bridge::providers_http::decode_openai_http_or_sse_response(
                resp,
                turn_handle,
                &mut on_delta,
            )
            .await
            .map_err(|e| GatewayError::Upstream(format!("HTTP {} parse error: {}", status, e)))?;

        // 4. Meter token usage from response (§5.3)
        if let Some(usage) = resp_json.get("usage") {
            let pt = usage
                .get("prompt_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let ct = usage
                .get("completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            self.in_tokens.fetch_add(pt, Ordering::Relaxed);
            self.out_tokens.fetch_add(ct, Ordering::Relaxed);
        }

        let _ = self.state_db.record_audit(
            Some(&lease.task_id),
            "gateway.chat_completions",
            "agent_worker",
            "egress",
            "allow",
            "ok",
            &json!({ "provider": provider.id, "model": body.get("model"), "streamed": streamed_sse }),
            None,
        );

        Ok((resp_json, streamed_sse))
    }

    /// Spawn Unix domain socket HTTP listener (`gateway.sock`) for zero-network Workers (§5.3, Spike S2).
    pub fn spawn_unix_socket_server(self: Arc<Self>, sock_path: &Path) -> anyhow::Result<()> {
        if sock_path.exists() {
            let _ = std::fs::remove_file(sock_path);
        }
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let listener = UnixListener::bind(sock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600));
        }
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let gw = self.clone();
                tokio::spawn(async move {
                    let _ = handle_gateway_unix_http(gw, stream).await;
                });
            }
        });
        Ok(())
    }

    fn lookup_credential_with_vault(&self, provider_id: &str, cred_ref: &str) -> Option<String> {
        let maybe_paths = self.paths.lock().unwrap().clone();
        if let Some(ref paths) = maybe_paths
            && let Some(k) =
                crate::config_center::brain_manager::lookup_provider_credential(paths, provider_id)
        {
            return Some(k);
        }
        Self::lookup_credential(provider_id, cred_ref)
    }

    fn lookup_credential(provider_id: &str, _cred_ref: &str) -> Option<String> {
        // 1. Try Secret Service via `secret-tool lookup service intentos provider <id>`
        if let Ok(out) = Command::new("secret-tool")
            .args(["lookup", "service", "intentos", "provider", provider_id])
            .output()
            && out.status.success()
        {
            let secret = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !secret.is_empty() {
                return Some(secret);
            }
        }
        // 2. Core-only environment fallback for developer CLI sessions (never forwarded to sandboxed Worker!)
        for env_key in [
            "INTENTOS_API_KEY",
            "OPENAI_API_KEY",
            "DEEPSEEK_API_KEY",
            "DASHSCOPE_API_KEY",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
        ] {
            if let Ok(val) = std::env::var(env_key)
                && !val.trim().is_empty()
            {
                return Some(val.trim().to_string());
            }
        }
        None
    }
}

/// Minimal HTTP/1.1 handler over Unix socket so Node/Pi HTTP clients can talk to `gateway.sock` directly.
async fn handle_gateway_unix_http(gw: Arc<ModelGateway>, stream: UnixStream) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut req_line = String::new();
    if reader.read_line(&mut req_line).await? == 0 {
        return Ok(());
    }

    let mut content_length = 0usize;
    let mut run_token = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let vt = v.trim();
            if kl == "content-length" {
                content_length = vt.parse().unwrap_or(0);
            } else if kl == "x-intentos-run-token" {
                run_token = vt.to_string();
            } else if kl == "authorization"
                && run_token.is_empty()
                && let Some(tok) = vt.strip_prefix("Bearer ")
            {
                run_token = tok.trim().to_string();
            }
        }
    }

    let mut body_bytes = vec![0u8; content_length.min(4 * 1024 * 1024)];
    reader.read_exact(&mut body_bytes).await?;
    let body_val: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|_| json!({}));

    let (http_code, payload) = match gw.proxy_chat_completion(&run_token, body_val).await {
        Ok(resp) => ("200 OK", serde_json::to_vec(&resp)?),
        Err(GatewayError::EgressDenied(msg)) => (
            "403 Forbidden",
            serde_json::to_vec(&json!({
                "error": { "code": "egress_denied", "message": msg }
            }))?,
        ),
        Err(err) => (
            "502 Bad Gateway",
            serde_json::to_vec(&json!({
                "error": { "code": "gateway_error", "message": err.to_string() }
            }))?,
        ),
    };

    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        http_code,
        payload.len()
    );
    write_half.write_all(header.as_bytes()).await?;
    write_half.write_all(&payload).await?;
    write_half.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrainConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn gateway_blocks_sensitive_data_to_standard_provider() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(StateDb::open(&tmp.path().join("state.db")).unwrap());
        let gw = ModelGateway::new(BrainConfig::default(), db).unwrap();

        // Standard trust provider + Sensitive data_class MUST be denied with `egress_denied` (§5.4, §19.2)!
        let token = gw.issue_run_lease("task_sec", "main", DataClass::Sensitive);
        let err = gw
            .proxy_chat_completion(
                &token,
                json!({"messages": [{"role": "user", "content": "secret"}]}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::EgressDenied(_)));
        assert_eq!(gw.metrics().blocked_egress, 1);
    }
}
