#![forbid(unsafe_code)]

//! Provider Connection Tester (`B-03`: distinguishes `ok`, `auth_failed`, `unreachable`,
//! `timeout`, `model_not_found`, with `latency_ms`) and Structured Tool-Call Capability
//! Tester (`B-04`: `test_provider_tools`).

use crate::config::XdgPaths;
use crate::config_center::brain_manager::lookup_provider_credential;
use crate::config_center::schema::FullDomainsConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionTestStatus {
    Ok,
    AuthFailed,
    Unreachable,
    Timeout,
    ModelNotFound,
}

impl ConnectionTestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::AuthFailed => "auth_failed",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::ModelNotFound => "model_not_found",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTestResult {
    pub provider_id: String,
    pub status: ConnectionTestStatus,
    pub latency_ms: u64,
    pub message: String,
    pub discovered_models: Vec<String>,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolTestResult {
    pub provider_id: String,
    pub model: String,
    pub supported: bool,
    pub status: String,
    pub latency_ms: u64,
    pub details: String,
}

fn is_local_endpoint(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.contains("127.0.0.1") || lower.contains("localhost") || lower.contains("[::1]")
}

fn build_client(url: &str, timeout_ms: u64) -> anyhow::Result<reqwest::Client> {
    let mut builder =
        reqwest::Client::builder().timeout(Duration::from_millis(timeout_ms.clamp(50, 30_000)));
    if is_local_endpoint(url) {
        builder = builder.no_proxy();
    }
    Ok(builder.build()?)
}

/// Execute B-03 Provider Connection Test (`test_provider_connection`).
/// Distinguishes:
/// - `ok`
/// - `auth_failed` (HTTP 401 / 403)
/// - `unreachable` (Connection refused / DNS / transport error)
/// - `timeout` (Request timeout exceeded)
/// - `model_not_found` (HTTP 404 or requested model absent from `/models` list)
pub async fn test_provider_connection(
    paths: &XdgPaths,
    cfg: &FullDomainsConfig,
    payload: &Value,
) -> anyhow::Result<Value> {
    let provider_id = payload
        .get("provider_id")
        .or_else(|| payload.get("id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("default-openai");

    let provider_opt = cfg.brain.providers.iter().find(|p| p.id == provider_id);

    let base_url = payload
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| provider_opt.map(|p| p.base_url.clone()))
        .ok_or_else(|| anyhow::anyhow!("未找到供应商 '{}' 且未提供 base_url", provider_id))?;

    let kind = payload
        .get("kind")
        .and_then(|v| v.as_str())
        .or_else(|| provider_opt.map(|p| p.kind.as_str()))
        .unwrap_or("openai-compatible");

    let requested_model = payload
        .get("model")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let timeout_ms = payload
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(4_000);

    let api_key = payload
        .get("api_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| lookup_provider_credential(paths, provider_id));

    let started = Instant::now();

    let client = build_client(&base_url, timeout_ms)?;
    let models_url = format!("{}/models", base_url.trim_end_matches('/'));

    let mut req = client.get(&models_url);
    if let Some(ref key) = api_key {
        if kind == "anthropic" {
            req = req
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01");
        } else {
            req = req.bearer_auth(key);
        }
    }

    match req.send().await {
        Err(err) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            let (status, message) = if err.is_timeout() {
                (
                    ConnectionTestStatus::Timeout,
                    format!("连接超时（>{}ms）：{}", timeout_ms, models_url),
                )
            } else {
                (
                    ConnectionTestStatus::Unreachable,
                    format!("端点不可达（{}）：{}", models_url, err),
                )
            };
            let out = ConnectionTestResult {
                provider_id: provider_id.to_string(),
                status,
                latency_ms,
                message,
                discovered_models: Vec::new(),
                http_status: None,
            };
            Ok(serde_json::to_value(out)?)
        }
        Ok(resp) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            let code = resp.status().as_u16();
            let body_val: Value = resp.json().await.unwrap_or_else(|_| json!({}));

            if code == 401 || code == 403 {
                let out = ConnectionTestResult {
                    provider_id: provider_id.to_string(),
                    status: ConnectionTestStatus::AuthFailed,
                    latency_ms,
                    message: format!("认证失败 (HTTP {})：请检查 API Key 是否有效", code),
                    discovered_models: Vec::new(),
                    http_status: Some(code),
                };
                return Ok(serde_json::to_value(out)?);
            }

            if code == 404 {
                let out = ConnectionTestResult {
                    provider_id: provider_id.to_string(),
                    status: ConnectionTestStatus::ModelNotFound,
                    latency_ms,
                    message: "模型或接口路径不存在 (HTTP 404)".to_string(),
                    discovered_models: Vec::new(),
                    http_status: Some(code),
                };
                return Ok(serde_json::to_value(out)?);
            }

            if !(200..300).contains(&code) {
                let out = ConnectionTestResult {
                    provider_id: provider_id.to_string(),
                    status: ConnectionTestStatus::Unreachable,
                    latency_ms,
                    message: format!("上游返回异常状态码 HTTP {}", code),
                    discovered_models: Vec::new(),
                    http_status: Some(code),
                };
                return Ok(serde_json::to_value(out)?);
            }

            // Extract discovered model IDs (B-02)
            let mut discovered = Vec::new();
            if let Some(arr) = body_val.get("data").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                        discovered.push(id.to_string());
                    }
                }
            } else if let Some(arr) = body_val.get("models").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(id) = item
                        .get("id")
                        .or_else(|| item.get("name"))
                        .and_then(|v| v.as_str())
                    {
                        discovered.push(id.to_string());
                    }
                }
            }

            if let Some(target_model) = requested_model
                && !discovered.is_empty()
                && !discovered.iter().any(|m| m == target_model)
            {
                let out = ConnectionTestResult {
                    provider_id: provider_id.to_string(),
                    status: ConnectionTestStatus::ModelNotFound,
                    latency_ms,
                    message: format!(
                        "端点连通正常，但未在模型列表中找到指定模型 '{}'（共发现 {} 个模型）",
                        target_model,
                        discovered.len()
                    ),
                    discovered_models: discovered,
                    http_status: Some(code),
                };
                return Ok(serde_json::to_value(out)?);
            }

            let out = ConnectionTestResult {
                provider_id: provider_id.to_string(),
                status: ConnectionTestStatus::Ok,
                latency_ms,
                message: format!(
                    "连接检测通过 ({}ms，发现 {} 个可用模型)",
                    latency_ms,
                    discovered.len()
                ),
                discovered_models: discovered,
                http_status: Some(code),
            };
            Ok(serde_json::to_value(out)?)
        }
    }
}

/// Execute B-04 Structured Tool-Calling Capability Test (`test_provider_tools`).
/// Sends a minimal `ping_tool` schema to `{base_url}/chat/completions` and verifies
/// whether the provider/model supports structured `tool_calls`.
pub async fn test_provider_tools(
    paths: &XdgPaths,
    cfg: &FullDomainsConfig,
    payload: &Value,
) -> anyhow::Result<Value> {
    let provider_id = payload
        .get("provider_id")
        .or_else(|| payload.get("id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("default-openai");

    let provider_opt = cfg.brain.providers.iter().find(|p| p.id == provider_id);

    let base_url = payload
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| provider_opt.map(|p| p.base_url.clone()))
        .ok_or_else(|| anyhow::anyhow!("未找到供应商 '{}' 且未提供 base_url", provider_id))?;

    let model = payload
        .get("model")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| {
            cfg.brain
                .profiles
                .get("main")
                .map(|p| p.model.clone())
                .or_else(|| {
                    provider_opt
                        .and_then(|p| p.available_models.first().cloned())
                })
        })
        .unwrap_or_else(|| "gpt-4o-mini".to_string());

    let timeout_ms = payload
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(6_000);

    let api_key = payload
        .get("api_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| lookup_provider_credential(paths, provider_id));

    let started = Instant::now();
    let client = build_client(&base_url, timeout_ms)?;
    let chat_url = format!("{}/chat/completions", base_url.trim_end_matches('/'));

    let req_body = json!({
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": "Call ping_tool with echo='intentos_b04_probe'"
            }
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "ping_tool",
                    "description": "IntentOS B-04 structured tool capability probe",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "echo": { "type": "string" }
                        },
                        "required": ["echo"]
                    }
                }
            }
        ],
        "tool_choice": "auto",
        "max_tokens": 64,
        "temperature": 0.0
    });

    let mut req = client.post(&chat_url).json(&req_body);
    if let Some(ref key) = api_key {
        req = req.bearer_auth(key);
    }

    match req.send().await {
        Err(err) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            let status = if err.is_timeout() {
                "timeout"
            } else {
                "unreachable"
            };
            let out = ToolTestResult {
                provider_id: provider_id.to_string(),
                model,
                supported: false,
                status: status.to_string(),
                latency_ms,
                details: format!("工具调用实测请求失败 ({}): {}", status, err),
            };
            Ok(serde_json::to_value(out)?)
        }
        Ok(resp) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            let code = resp.status().as_u16();
            let body_val: Value = resp.json().await.unwrap_or_else(|_| json!({}));

            if code == 401 || code == 403 {
                let out = ToolTestResult {
                    provider_id: provider_id.to_string(),
                    model,
                    supported: false,
                    status: "auth_failed".to_string(),
                    latency_ms,
                    details: format!("认证失败 (HTTP {})", code),
                };
                return Ok(serde_json::to_value(out)?);
            }

            if code == 404 {
                let out = ToolTestResult {
                    provider_id: provider_id.to_string(),
                    model,
                    supported: false,
                    status: "model_not_found".to_string(),
                    latency_ms,
                    details: "模型或接口不存在 (HTTP 404)".to_string(),
                };
                return Ok(serde_json::to_value(out)?);
            }

            if !(200..300).contains(&code) {
                let out = ToolTestResult {
                    provider_id: provider_id.to_string(),
                    model,
                    supported: false,
                    status: "unsupported".to_string(),
                    latency_ms,
                    details: format!("上游返回 HTTP {}，可能不支持 tools 字段: {}", code, body_val),
                };
                return Ok(serde_json::to_value(out)?);
            }

            let has_tool_calls = body_val
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|c0| c0.get("message"))
                .and_then(|m| {
                    m.get("tool_calls")
                        .and_then(|tc| tc.as_array())
                        .filter(|a| !a.is_empty())
                        .or_else(|| {
                            m.get("function_call")
                                .filter(|fc| fc.is_object())
                                .map(|_| {
                                    static DUMMY: Vec<Value> = Vec::new();
                                    &DUMMY
                                })
                        })
                })
                .is_some();

            let out = ToolTestResult {
                provider_id: provider_id.to_string(),
                model: model.clone(),
                supported: has_tool_calls,
                status: if has_tool_calls { "ok" } else { "unsupported" }.to_string(),
                latency_ms,
                details: if has_tool_calls {
                    format!(
                        "模型 '{}' 支持结构化 tool_calls 返回 ({}ms)",
                        model, latency_ms
                    )
                } else {
                    format!(
                        "模型 '{}' 响应成功但未触发结构化 tool_calls ({}ms)",
                        model, latency_ms
                    )
                },
            };
            Ok(serde_json::to_value(out)?)
        }
    }
}
