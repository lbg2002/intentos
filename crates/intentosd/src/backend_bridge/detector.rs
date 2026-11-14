#![forbid(unsafe_code)]

//! Read-Only Local AI Backend & Provider Catalog Auto-Discovery (`detector.rs`).
//!
//! Discovers and normalizes four AI backend families inspired by `gnome-quick-chat`:
//! - `zcode`: `/opt/ZCode/resources/glm/zcode.cjs` or `zcode` CLI + `~/.zcode/v2/{provider_config,config}.json` & `~/.zcode/cli/config.json`
//! - `codex`: `codex` CLI + `~/.codex/config.toml` & `~/.codex/models_cache.json`
//! - `pi`: `pi` CLI + `~/.pi/agent/models.json`
//! - `openai`: IntentOS `config_center` providers + `0600` vault / env vars + live `400ms` local Ollama probe (`127.0.0.1:11434/api/tags`)
//!
//! SECURITY INVARIANTS:
//! 1. Strictly READ-ONLY against all external user directories (`~/.zcode`, `~/.codex`, `~/.pi`).
//! 2. Raw API keys / tokens are kept exclusively in Core process memory (`DISCOVERED_EPHEMERAL_KEYS`)
//!    and are NEVER serialized into RPC catalog responses or `config_dir` files.

use crate::config::XdgPaths;
use crate::config_center::brain_manager::lookup_provider_credential;
use crate::config_center::store::load_domains_config;
use crate::core::IntentOsCore;
use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const LIVE_MODELS_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct CachedLiveModels {
    models: Vec<String>,
    fetched_at: Instant,
}

static LIVE_MODELS_CACHE: OnceLock<Mutex<HashMap<String, CachedLiveModels>>> = OnceLock::new();

fn live_models_cache() -> &'static Mutex<HashMap<String, CachedLiveModels>> {
    LIVE_MODELS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Clear the in-memory live `/models` TTL cache (useful for deterministic unit tests).
pub fn clear_live_models_cache() {
    live_models_cache().lock().unwrap().clear();
}

static DISCOVERED_EPHEMERAL_KEYS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn ephemeral_keys() -> &'static Mutex<HashMap<String, String>> {
    DISCOVERED_EPHEMERAL_KEYS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Store a discovered or user-supplied API key strictly in Core process memory.
pub(crate) fn store_ephemeral_backend_key(backend: &str, provider_id: &str, api_key: &str) {
    let trimmed = api_key.trim();
    if trimmed.is_empty() || trimmed == "****" || trimmed == "[REDACTED]" {
        return;
    }
    let composite = format!("{}:{}", backend.trim(), provider_id.trim());
    ephemeral_keys()
        .lock()
        .unwrap()
        .insert(composite, trimmed.to_string());
}

/// Look up an API key from Core-only memory or the `0600` runtime vault / Secret Service.
pub(crate) fn lookup_ephemeral_backend_key(
    paths: &XdgPaths,
    backend: &str,
    provider_id: &str,
    allow_env_fallback: bool,
) -> Option<String> {
    let composite = format!("{}:{}", backend.trim(), provider_id.trim());
    if let Some(k) = ephemeral_keys().lock().unwrap().get(&composite).cloned()
        && !k.is_empty()
    {
        return Some(k);
    }

    if let Some(k) = lookup_provider_credential(paths, &composite)
        && !k.trim().is_empty()
    {
        return Some(k);
    }

    if backend == "openai"
        && let Some(k) = lookup_provider_credential(paths, provider_id)
        && !k.trim().is_empty()
    {
        return Some(k);
    }

    if allow_env_fallback {
        for env_name in [
            "INTENTOS_API_KEY",
            "OPENAI_API_KEY",
            "DEEPSEEK_API_KEY",
            "DASHSCOPE_API_KEY",
            "ZHIPU_API_KEY",
        ] {
            if let Ok(val) = std::env::var(env_name)
                && !val.trim().is_empty()
            {
                return Some(val.trim().to_string());
            }
        }
    }

    None
}

/// Normalize reasoning effort into `"default" | "fast" | "medium" | "high"`.
pub fn normalize_reasoning_effort(raw: Option<&str>) -> String {
    let Some(s) = raw else {
        return "default".to_string();
    };
    match s.trim().to_ascii_lowercase().as_str() {
        "fast" | "low" | "minimal" | "off" | "quick" | "快" => "fast".to_string(),
        "medium" | "standard" | "normal" | "balanced" | "标准" => "medium".to_string(),
        "high" | "deep" | "max" | "xhigh" | "thorough" | "深入" => "high".to_string(),
        _ => "default".to_string(),
    }
}

/// Human-friendly display title for a backend family.
pub fn backend_display_name(backend: &str) -> &'static str {
    match backend {
        "zcode" => "ZCode",
        "codex" => "Codex",
        "pi" => "Pi",
        "openai" => "OpenAI API",
        _ => "Auto",
    }
}

/// Sanitize a base URL so embedded userinfo credentials or secret query parameters never leak.
pub fn sanitize_url_no_secrets(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return None;
    }

    let (scheme, rest) = trimmed.split_once("://")?;
    // Strip optional `user:pass@` authority prefix
    let without_userinfo = if let Some((authority_part, tail)) = rest.split_once('/') {
        let host = authority_part
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority_part);
        format!("{}/{}", host, tail)
    } else {
        rest.rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(rest)
            .to_string()
    };

    // Strip query parameters whose keys look like credentials
    let cleaned = if let Some((path_part, query)) = without_userinfo.split_once('?') {
        let safe_pairs: Vec<&str> = query
            .split('&')
            .filter(|pair| {
                let key = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
                !key.contains("key")
                    && !key.contains("token")
                    && !key.contains("secret")
                    && !key.contains("auth")
                    && !key.contains("password")
                    && !key.contains("sig")
            })
            .collect();
        if safe_pairs.is_empty() {
            path_part.to_string()
        } else {
            format!("{}?{}", path_part, safe_pairs.join("&"))
        }
    } else {
        without_userinfo
    };

    Some(format!("{}://{}", scheme, cleaned.trim_end_matches('/')))
}

/// Recursively scrub any accidental secret keys or `sk-...` token values from an outgoing JSON payload.
pub fn scrub_json_secrets(val: &mut Value) {
    match val {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let norm = k.to_ascii_lowercase().replace(['-', '_'], "");
                let is_secret_field = matches!(
                    norm.as_str(),
                    "apikey"
                        | "secret"
                        | "secretkey"
                        | "accesstoken"
                        | "refreshtoken"
                        | "authtoken"
                        | "bearertoken"
                        | "privatekey"
                        | "password"
                        | "clientsecret"
                );
                if is_secret_field {
                    map.remove(&k);
                } else if let Some(child) = map.get_mut(&k) {
                    scrub_json_secrets(child);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                scrub_json_secrets(item);
            }
        }
        Value::String(s) => {
            let t = s.trim();
            if t.starts_with("sk-")
                || t.starts_with("rk-")
                || t.starts_with("ghp_")
                || t.starts_with("xoxb-")
                || t.starts_with("Bearer ")
                || t.contains("BEGIN OPENSSH PRIVATE KEY")
                || t.contains("BEGIN RSA PRIVATE KEY")
            {
                *s = "[REDACTED]".to_string();
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveBackendSelection {
    pub backend: String,
    pub provider: String,
    pub model: String,
    pub reasoning_effort: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub auto_selected: bool,
    #[serde(default)]
    pub direct_http_capable: bool,
    #[serde(default)]
    pub pill_label: String,
}

impl ActiveBackendSelection {
    pub fn with_computed_label(mut self) -> Self {
        let b_title = backend_display_name(&self.backend);
        let short_model = if self.model.trim().is_empty() {
            "auto"
        } else {
            self.model.trim()
        };
        self.pill_label = format!("{} · {}", b_title, short_model);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredProvider {
    pub id: String,
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    pub models: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    pub enabled: bool,
    pub has_api_key: bool,
    pub direct_openai_compatible: bool,
    #[serde(default)]
    pub live_models_fetched: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredBackend {
    pub id: String,
    pub name: String,
    pub label: String,
    pub available: bool,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    pub default_reasoning_effort: String,
    pub models: Vec<String>,
    pub providers: Vec<DiscoveredProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogBackends {
    pub zcode: DiscoveredBackend,
    pub codex: DiscoveredBackend,
    pub pi: DiscoveredBackend,
    pub openai: DiscoveredBackend,
}

impl CatalogBackends {
    pub fn get(&self, id: &str) -> Option<&DiscoveredBackend> {
        match id {
            "zcode" => Some(&self.zcode),
            "codex" => Some(&self.codex),
            "pi" => Some(&self.pi),
            "openai" => Some(&self.openai),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendsCatalog {
    pub active: ActiveBackendSelection,
    pub backend_order: Vec<String>,
    pub reasoning_efforts: Vec<Value>,
    pub backends: CatalogBackends,
}

/// Configurable discovery options for production system scan and deterministic isolated unit tests.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub home_dir: PathBuf,
    pub extra_bin_dirs: Vec<PathBuf>,
    pub include_system_paths: bool,
    pub opt_zcode_cjs: Option<PathBuf>,
    pub ollama_tags_url: Option<String>,
    pub ollama_timeout_ms: u64,
    pub allow_env_keys: bool,
    pub probe_remote_models: bool,
    pub force_refresh_models: bool,
}

impl DiscoveryOptions {
    pub fn for_system() -> Self {
        let home_dir = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        Self {
            home_dir,
            extra_bin_dirs: Vec::new(),
            include_system_paths: true,
            opt_zcode_cjs: Some(PathBuf::from("/opt/ZCode/resources/glm/zcode.cjs")),
            ollama_tags_url: Some("http://127.0.0.1:11434/api/tags".to_string()),
            ollama_timeout_ms: 400,
            allow_env_keys: true,
            probe_remote_models: true,
            force_refresh_models: false,
        }
    }

    /// Build `DiscoveryOptions` derived from `IntentOsCore`:
    /// - In real system mode (`config_dir` ends with `intentos`), probes full system paths + live `/models`.
    /// - In custom test `XdgPaths` mode (`config_dir` is `<base>/config`), uses `<base>` as `home_dir`
    ///   without polluting tests with host binaries/env keys, while STILL enabling live `/models` probing
    ///   for configured mock/local providers!
    pub fn from_core(core: &IntentOsCore, force_refresh: bool) -> Self {
        let is_custom_test_base = core
            .paths
            .config_dir
            .file_name()
            .and_then(|s| s.to_str())
            == Some("config");

        if is_custom_test_base {
            let base = core
                .paths
                .config_dir
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            let cjs = [
                base.join("zcode.cjs"),
                base.join("opt_zcode/resources/glm/zcode.cjs"),
            ]
            .into_iter()
            .find(|p| p.is_file());
            Self {
                home_dir: base,
                extra_bin_dirs: Vec::new(),
                include_system_paths: false,
                opt_zcode_cjs: cjs,
                ollama_tags_url: None,
                ollama_timeout_ms: 200,
                allow_env_keys: false,
                probe_remote_models: true,
                force_refresh_models: force_refresh,
            }
        } else {
            let mut opts = Self::for_system();
            opts.probe_remote_models = true;
            opts.force_refresh_models = force_refresh;
            opts
        }
    }

    pub fn hermetic_test(mock_home: PathBuf) -> Self {
        Self::isolated_for_test(mock_home)
    }

    pub fn isolated_for_test(mock_home: PathBuf) -> Self {
        Self {
            home_dir: mock_home,
            extra_bin_dirs: Vec::new(),
            include_system_paths: false,
            opt_zcode_cjs: None,
            ollama_tags_url: None,
            ollama_timeout_ms: 200,
            allow_env_keys: false,
            probe_remote_models: false,
            force_refresh_models: false,
        }
    }
}

/// Build ordered binary search directories:
/// `extra_bin_dirs` -> `$PATH` -> `~/.nvm/versions/node/*/bin` -> `~/.local/bin` -> `~/bin` ->
/// `~/.cargo/bin` -> `/opt/ZCode` -> `/usr/local/bin` -> `/usr/bin`.
pub fn build_search_dirs(opts: &DiscoveryOptions) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut seen = HashSet::new();
    let mut push_unique = |p: PathBuf| {
        if seen.insert(p.clone()) {
            dirs.push(p);
        }
    };

    for d in &opts.extra_bin_dirs {
        push_unique(d.clone());
    }

    if opts.include_system_paths
        && let Some(path_os) = std::env::var_os("PATH")
    {
        for p in std::env::split_paths(&path_os) {
            push_unique(p);
        }
    }

    // `~/.nvm/versions/node/*/bin` sorted newest-first
    let nvm_nodes = opts.home_dir.join(".nvm/versions/node");
    if let Ok(entries) = std::fs::read_dir(&nvm_nodes) {
        let mut versions: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|x| x.path()))
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        versions.reverse();
        for v in versions {
            push_unique(v.join("bin"));
        }
    }

    push_unique(opts.home_dir.join(".local/bin"));
    push_unique(opts.home_dir.join("bin"));
    push_unique(opts.home_dir.join(".cargo/bin"));

    if opts.include_system_paths {
        push_unique(PathBuf::from("/opt/ZCode"));
        push_unique(PathBuf::from("/opt/ZCode/resources/glm/node-runtime/bin"));
        push_unique(PathBuf::from("/usr/local/bin"));
        push_unique(PathBuf::from("/usr/bin"));
    }

    dirs
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub fn find_binary_in_dirs(name: &str, search_dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in search_dirs {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn push_dedup(vec: &mut Vec<String>, item: impl Into<String>) {
    let s = item.into().trim().to_string();
    if !s.is_empty() && !vec.iter().any(|existing| existing == &s) {
        vec.push(s);
    }
}

pub(crate) fn is_local_url(url: &str) -> bool {
    url.contains("://127.0.0.1") || url.contains("://localhost") || url.contains("://[::1]")
}

pub(crate) fn is_anthropic_endpoint(kind: &str, base_url: Option<&str>) -> bool {
    let Some(url) = base_url else {
        return false;
    };
    let kl = kind.to_ascii_lowercase();
    let ul = url.trim_end_matches('/').to_ascii_lowercase();
    if !ul.starts_with("http://") && !ul.starts_with("https://") {
        return false;
    }
    kl.contains("anthropic") || ul.ends_with("/anthropic") || ul.contains("/anthropic/")
}

pub(crate) fn is_openai_compatible_endpoint(kind: &str, base_url: Option<&str>) -> bool {
    let Some(url) = base_url else {
        return false;
    };
    let ul = url.to_ascii_lowercase();
    if is_anthropic_endpoint(kind, base_url) {
        return false;
    }
    ul.starts_with("http://") || ul.starts_with("https://")
}

pub(crate) fn is_direct_http_endpoint(kind: &str, base_url: Option<&str>) -> bool {
    is_openai_compatible_endpoint(kind, base_url) || is_anthropic_endpoint(kind, base_url)
}

/// Filter out non-chat utility models (`*embedding*`, `*rerank*`, `omni-moderation*`,
/// `text-moderation*`, `whisper*`, `tts-*`, `dall-e*`, `gpt-image*`, `*realtime*`, `*transcribe*`),
/// keeping all chat, coding, multimodal, and reasoning models.
pub fn is_non_chat_utility_model(model_id: &str) -> bool {
    let full = model_id.trim().to_ascii_lowercase();
    if full.is_empty() {
        return true;
    }
    let leaf = full.rsplit('/').next().unwrap_or(full.as_str());

    if full.contains("embedding")
        || full.contains("rerank")
        || full.contains("realtime")
        || full.contains("transcribe")
    {
        return true;
    }

    for prefix in [
        "omni-moderation",
        "text-moderation",
        "whisper",
        "tts-",
        "dall-e",
        "gpt-image",
    ] {
        if full.starts_with(prefix) || leaf.starts_with(prefix) {
            return true;
        }
    }

    false
}

/// Build ordered `/models` endpoint candidates for a provider `base_url`.
pub fn build_models_candidate_urls(base_url: &str, kind: &str) -> Vec<String> {
    let clean = base_url.trim().trim_end_matches('/');
    if clean.is_empty() {
        return Vec::new();
    }
    let lower = clean.to_ascii_lowercase();
    if lower.ends_with("/models") {
        return vec![clean.to_string()];
    }
    if lower.ends_with("/v1") || lower.ends_with("/api/v3") || lower.ends_with("/v4") {
        return vec![format!("{}/models", clean)];
    }
    if lower.ends_with("/anthropic") || is_anthropic_endpoint(kind, Some(clean)) {
        return vec![
            format!("{}/models", clean),
            format!("{}/v1/models", clean),
        ];
    }
    vec![
        format!("{}/v1/models", clean),
        format!("{}/models", clean),
    ]
}

/// Parse OpenAI / Anthropic / vLLM / LiteLLM / Ollama `/models` JSON responses and filter non-chat utility models.
pub fn parse_models_response_json(body: &Value) -> Vec<String> {
    let mut models = Vec::new();
    let arr_opt = body
        .get("data")
        .and_then(|v| v.as_array())
        .or_else(|| body.get("models").and_then(|v| v.as_array()))
        .or_else(|| body.as_array());

    let Some(arr) = arr_opt else {
        return models;
    };

    for item in arr {
        if let Some(supported) = item.get("supported_in_api").and_then(|v| v.as_bool())
            && !supported
        {
            continue;
        }
        let raw_id = item
            .as_str()
            .or_else(|| item.get("id").and_then(|v| v.as_str()))
            .or_else(|| item.get("slug").and_then(|v| v.as_str()))
            .or_else(|| item.get("model").and_then(|v| v.as_str()))
            .or_else(|| item.get("name").and_then(|v| v.as_str()));

        if let Some(id_str) = raw_id {
            let trimmed = id_str.trim();
            if !trimmed.is_empty() && !is_non_chat_utility_model(trimmed) {
                push_dedup(&mut models, trimmed);
            }
        }
    }

    models
}

/// Fetch live `/models` for a single provider with a 300s in-memory TTL cache.
pub async fn fetch_live_models_for_provider(
    base_url: &str,
    kind: &str,
    api_key: Option<&str>,
    force_refresh: bool,
) -> Option<Vec<String>> {
    let clean_url = base_url.trim().trim_end_matches('/');
    if !clean_url.starts_with("http://") && !clean_url.starts_with("https://") {
        return None;
    }

    let key_trimmed = api_key.map(str::trim).filter(|s| !s.is_empty());
    let mut hasher = Sha256::new();
    hasher.update(key_trimmed.unwrap_or("none").as_bytes());
    let key_hash = hex::encode(&hasher.finalize()[..8]);
    let cache_key = format!("{}|{}|{}", kind.to_ascii_lowercase(), clean_url, key_hash);

    if !force_refresh
        && let Some(entry) = live_models_cache().lock().unwrap().get(&cache_key).cloned()
        && entry.fetched_at.elapsed() < LIVE_MODELS_CACHE_TTL
    {
        return Some(entry.models);
    }

    let candidates = build_models_candidate_urls(clean_url, kind);
    if candidates.is_empty() {
        return None;
    }

    let is_local = is_local_url(clean_url);
    let timeout_ms = if is_local { 900 } else { 2200 };
    let mut client_builder = reqwest::Client::builder().timeout(Duration::from_millis(timeout_ms));
    if is_local {
        client_builder = client_builder.no_proxy();
    }
    let client = client_builder.build().ok()?;
    let is_anth = is_anthropic_endpoint(kind, Some(clean_url));

    for url in candidates {
        let mut req = client.get(&url).header("Accept", "application/json");
        if let Some(k) = key_trimmed {
            req = req.bearer_auth(k);
            if is_anth {
                req = req.header("x-api-key", k);
            }
        }
        if is_anth {
            req = req.header("anthropic-version", "2023-06-01");
        }

        let Ok(resp) = req.send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<Value>().await else {
            continue;
        };
        let parsed = parse_models_response_json(&body);
        if !parsed.is_empty() {
            live_models_cache().lock().unwrap().insert(
                cache_key,
                CachedLiveModels {
                    models: parsed.clone(),
                    fetched_at: Instant::now(),
                },
            );
            return Some(parsed);
        }
    }

    None
}

/// Discover ZCode (`zcode`) read-only from binary paths and `~/.zcode/{v2,cli}/*.json`.
pub fn discover_zcode_backend(
    opts: &DiscoveryOptions,
    search_dirs: &[PathBuf],
) -> DiscoveredBackend {
    let node_bin = find_binary_in_dirs("node", search_dirs);
    let cli_bin = find_binary_in_dirs("zcode", search_dirs);

    let cjs_candidate = opts.opt_zcode_cjs.clone().filter(|p| p.is_file());

    let (binary_path, runner_program) = if let Some(bin) = cli_bin {
        (Some(bin.to_string_lossy().to_string()), None)
    } else if let Some(cjs) = cjs_candidate {
        let runner = node_bin
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| {
                if is_executable_file(&cjs) {
                    None
                } else {
                    Some("node".to_string())
                }
            });
        (Some(cjs.to_string_lossy().to_string()), runner)
    } else {
        (None, None)
    };

    let zcode_dir = opts.home_dir.join(".zcode");
    let v2_provider_cfg = zcode_dir.join("v2/provider_config.json");
    let v2_cfg = zcode_dir.join("v2/config.json");
    let cli_cfg = zcode_dir.join("cli/config.json");

    let mut providers_by_id: HashMap<String, DiscoveredProvider> = HashMap::new();
    let mut provider_order: Vec<String> = Vec::new();
    let mut explicit_default_provider: Option<String> = None;
    let mut explicit_default_model: Option<String> = None;
    let mut default_effort = "default".to_string();

    // 1. Parse `~/.zcode/v2/provider_config.json` (both ZCode v2 rule schema & simplified flat schema)
    if v2_provider_cfg.is_file()
        && let Ok(raw) = std::fs::read_to_string(&v2_provider_cfg)
        && let Ok(doc) = serde_json::from_str::<Value>(&raw)
    {
        let root_cfg = doc.get("config").unwrap_or(&doc);

        if let Some(order_arr) = root_cfg
            .get("providerOrder")
            .or_else(|| doc.get("providerOrder"))
            .and_then(|v| v.as_array())
        {
            for item in order_arr {
                if let Some(pid) = item.as_str() {
                    push_dedup(&mut provider_order, pid);
                }
            }
        }

        for key in [
            "activeProvider",
            "defaultProvider",
            "currentProvider",
            "selectedProvider",
        ] {
            if explicit_default_provider.is_none()
                && let Some(s) = root_cfg
                    .get(key)
                    .or_else(|| doc.get(key))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            {
                explicit_default_provider = Some(s.to_string());
            }
        }
        for key in ["activeModel", "defaultModel", "model"] {
            if explicit_default_model.is_none()
                && let Some(s) = root_cfg
                    .get(key)
                    .or_else(|| doc.get(key))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            {
                explicit_default_model = Some(s.to_string());
            }
        }

        // Collect disabled `(providerId, modelId)` rules + explicitly enabled rules
        let mut disabled_models: HashSet<(String, String)> = HashSet::new();
        let mut enabled_rule_models: HashMap<String, Vec<String>> = HashMap::new();
        if let Some(model_rules_obj) = root_cfg.get("modelConfigRules") {
            for arr_key in ["providerModelRules", "manualProviderModelRules"] {
                if let Some(arr) = model_rules_obj.get(arr_key).and_then(|v| v.as_array()) {
                    for rule in arr {
                        let pid = rule
                            .get("providerId")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .trim();
                        let mid = rule
                            .get("modelId")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .trim();
                        if pid.is_empty() || mid.is_empty() {
                            continue;
                        }
                        let enabled = rule
                            .get("config")
                            .and_then(|c| c.get("enabled"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                        if !enabled {
                            disabled_models.insert((pid.to_string(), mid.to_string()));
                        } else {
                            push_dedup(
                                enabled_rule_models.entry(pid.to_string()).or_default(),
                                mid,
                            );
                        }
                    }
                }
            }
        }

        // Parse `providerConfigRules.providerRules` array
        if let Some(rules) = root_cfg
            .get("providerConfigRules")
            .and_then(|p| p.get("providerRules"))
            .and_then(|v| v.as_array())
        {
            for rule in rules {
                let Some(pid) = rule
                    .get("providerId")
                    .or_else(|| rule.get("id"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                else {
                    continue;
                };
                let pname = rule
                    .get("providerName")
                    .or_else(|| rule.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(pid)
                    .trim()
                    .to_string();
                let template = rule
                    .get("templateId")
                    .or_else(|| rule.get("kind"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("openai-compatible")
                    .to_string();
                let inner = rule.get("config").unwrap_or(rule);
                let enabled = inner
                    .get("enabled")
                    .or_else(|| rule.get("enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                let raw_url = inner
                    .get("api")
                    .and_then(|a| {
                        a.get("baseUrl")
                            .or_else(|| a.get("baseURL"))
                            .or_else(|| a.get("base_url"))
                    })
                    .or_else(|| inner.get("baseUrl"))
                    .or_else(|| inner.get("baseURL"))
                    .or_else(|| inner.get("base_url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let base_url = sanitize_url_no_secrets(raw_url);

                let raw_key = inner
                    .get("access")
                    .and_then(|a| {
                        a.get("apiKey")
                            .or_else(|| a.get("api_key"))
                            .or_else(|| a.get("token"))
                    })
                    .or_else(|| inner.get("apiKey"))
                    .or_else(|| inner.get("api_key"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();

                if !raw_key.is_empty() {
                    store_ephemeral_backend_key("zcode", pid, raw_key);
                }

                let mut models = Vec::new();
                for list_key in [
                    "modelOrder",
                    "models",
                    "personalModelIds",
                    "availableModels",
                ] {
                    if let Some(arr) = inner.get(list_key).and_then(|v| v.as_array()) {
                        for item in arr {
                            let m_opt = item
                                .as_str()
                                .or_else(|| item.get("id").and_then(|v| v.as_str()))
                                .or_else(|| item.get("modelId").and_then(|v| v.as_str()));
                            if let Some(m) = m_opt {
                                let mt = m.trim();
                                if !mt.is_empty()
                                    && !disabled_models.contains(&(pid.to_string(), mt.to_string()))
                                {
                                    push_dedup(&mut models, mt);
                                }
                            }
                        }
                    }
                }
                if let Some(extra) = enabled_rule_models.get(pid) {
                    for m in extra {
                        if !disabled_models.contains(&(pid.to_string(), m.clone())) {
                            push_dedup(&mut models, m);
                        }
                    }
                }

                let def_model = inner
                    .get("defaultModel")
                    .or_else(|| inner.get("model"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .or_else(|| models.first().cloned());

                let has_api_key =
                    !raw_key.is_empty() || base_url.as_deref().is_some_and(is_local_url);
                let direct_openai = enabled
                    && has_api_key
                    && is_openai_compatible_endpoint(&template, base_url.as_deref());

                push_dedup(&mut provider_order, pid);
                providers_by_id.insert(
                    pid.to_string(),
                    DiscoveredProvider {
                        id: pid.to_string(),
                        name: pname,
                        kind: template,
                        base_url,
                        models,
                        default_model: def_model,
                        enabled,
                        has_api_key,
                        direct_openai_compatible: direct_openai,
                        live_models_fetched: false,
                        source: "zcode:v2/provider_config.json".to_string(),
                    },
                );
            }
        }

        // Also support simplified `"providers"` object/array inside `provider_config.json`
        parse_generic_zcode_providers_node(
            root_cfg.get("providers").or_else(|| doc.get("providers")),
            "zcode:v2/provider_config.json",
            &mut provider_order,
            &mut providers_by_id,
        );
    }

    // 2. Parse `~/.zcode/v2/config.json`
    if v2_cfg.is_file()
        && let Ok(raw) = std::fs::read_to_string(&v2_cfg)
        && let Ok(doc) = serde_json::from_str::<Value>(&raw)
    {
        if explicit_default_model.is_none()
            && let Some(m) = doc
                .get("model")
                .or_else(|| doc.get("defaultModel"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            if let Some((prov_prefix, model_rest)) = m.split_once('/') {
                if explicit_default_provider.is_none() {
                    explicit_default_provider = Some(prov_prefix.to_string());
                }
                explicit_default_model = Some(model_rest.to_string());
            } else {
                explicit_default_model = Some(m.to_string());
            }
        }
        if let Some(eff) = doc.get("reasoningEffort").and_then(|v| v.as_str()) {
            default_effort = normalize_reasoning_effort(Some(eff));
        }

        parse_generic_zcode_providers_node(
            doc.get("provider").or_else(|| doc.get("providers")),
            "zcode:v2/config.json",
            &mut provider_order,
            &mut providers_by_id,
        );
    }

    // 3. Parse `~/.zcode/cli/config.json`
    if cli_cfg.is_file()
        && let Ok(raw) = std::fs::read_to_string(&cli_cfg)
        && let Ok(doc) = serde_json::from_str::<Value>(&raw)
    {
        if explicit_default_provider.is_none()
            && let Some(p) = doc
                .get("providerId")
                .or_else(|| doc.get("activeProvider"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            explicit_default_provider = Some(p.to_string());
        }
        if explicit_default_model.is_none()
            && let Some(m) = doc
                .get("model")
                .or_else(|| doc.get("defaultModel"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            explicit_default_model = Some(m.to_string());
        }
        parse_generic_zcode_providers_node(
            doc.get("providers").or_else(|| doc.get("provider")),
            "zcode:cli/config.json",
            &mut provider_order,
            &mut providers_by_id,
        );
    }

    let mut providers = Vec::new();
    for pid in &provider_order {
        if let Some(p) = providers_by_id.remove(pid) {
            providers.push(p);
        }
    }
    let mut remaining: Vec<DiscoveredProvider> = providers_by_id.into_values().collect();
    remaining.sort_by(|a, b| a.id.cmp(&b.id));
    providers.extend(remaining);

    // Flatten models (enabled providers first)
    let mut all_models = Vec::new();
    for p in providers.iter().filter(|p| p.enabled) {
        for m in &p.models {
            push_dedup(&mut all_models, m);
        }
    }
    for p in providers.iter().filter(|p| !p.enabled) {
        for m in &p.models {
            push_dedup(&mut all_models, m);
        }
    }

    let chosen_provider = explicit_default_provider
        .filter(|id| providers.iter().any(|p| &p.id == id))
        .or_else(|| {
            providers
                .iter()
                .find(|p| p.enabled && p.has_api_key && !p.models.is_empty())
                .map(|p| p.id.clone())
        })
        .or_else(|| providers.iter().find(|p| p.enabled).map(|p| p.id.clone()))
        .or_else(|| providers.first().map(|p| p.id.clone()));

    let chosen_model = explicit_default_model
        .or_else(|| {
            chosen_provider
                .as_ref()
                .and_then(|pid| providers.iter().find(|p| &p.id == pid))
                .and_then(|p| {
                    p.default_model
                        .clone()
                        .or_else(|| p.models.first().cloned())
                })
        })
        .or_else(|| all_models.first().cloned());

    let has_direct = providers.iter().any(|p| {
        p.enabled
            && p.has_api_key
            && is_direct_http_endpoint(&p.kind, p.base_url.as_deref())
            && !p.models.is_empty()
    });
    let installed = binary_path.is_some();
    let available = installed || has_direct;

    DiscoveredBackend {
        id: "zcode".to_string(),
        name: "ZCode".to_string(),
        label: "ZCode".to_string(),
        available,
        installed,
        binary_path,
        runner_program,
        default_provider: chosen_provider,
        default_model: chosen_model,
        default_reasoning_effort: default_effort,
        models: all_models,
        providers,
    }
}

fn parse_generic_zcode_providers_node(
    node: Option<&Value>,
    source_label: &str,
    provider_order: &mut Vec<String>,
    providers_by_id: &mut HashMap<String, DiscoveredProvider>,
) {
    let Some(val) = node else {
        return;
    };
    let mut entries: Vec<(String, &Value)> = Vec::new();
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                entries.push((k.clone(), v));
            }
        }
        Value::Array(arr) => {
            for item in arr {
                if let Some(id) = item
                    .get("id")
                    .or_else(|| item.get("providerId"))
                    .and_then(|v| v.as_str())
                {
                    entries.push((id.to_string(), item));
                }
            }
        }
        _ => {}
    }

    for (raw_id, item) in entries {
        let pid = raw_id.trim();
        if pid.is_empty() {
            continue;
        }
        let pname = item
            .get("name")
            .or_else(|| item.get("providerName"))
            .and_then(|v| v.as_str())
            .unwrap_or(pid)
            .trim()
            .to_string();
        let kind = item
            .get("kind")
            .or_else(|| item.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("openai-compatible")
            .to_string();

        let sys_disabled = item
            .get("systemDisabledReason")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty());
        let enabled = item
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(!sys_disabled);

        let opts_obj = item.get("options").unwrap_or(item);
        let raw_url = opts_obj
            .get("baseURL")
            .or_else(|| opts_obj.get("baseUrl"))
            .or_else(|| opts_obj.get("base_url"))
            .or_else(|| item.get("baseURL"))
            .or_else(|| item.get("baseUrl"))
            .or_else(|| item.get("base_url"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let base_url = sanitize_url_no_secrets(raw_url);

        let raw_key = opts_obj
            .get("apiKey")
            .or_else(|| opts_obj.get("api_key"))
            .or_else(|| item.get("apiKey"))
            .or_else(|| item.get("api_key"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if !raw_key.is_empty() {
            store_ephemeral_backend_key("zcode", pid, raw_key);
        }

        let mut models = Vec::new();
        if let Some(m_node) = item.get("models") {
            match m_node {
                Value::Object(m_map) => {
                    for mk in m_map.keys() {
                        push_dedup(&mut models, mk);
                    }
                }
                Value::Array(m_arr) => {
                    for mv in m_arr {
                        if let Some(ms) = mv
                            .as_str()
                            .or_else(|| mv.get("id").and_then(|v| v.as_str()))
                            .or_else(|| mv.get("name").and_then(|v| v.as_str()))
                        {
                            push_dedup(&mut models, ms);
                        }
                    }
                }
                _ => {}
            }
        }

        let def_model = item
            .get("defaultModel")
            .or_else(|| item.get("model"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| models.first().cloned());

        let has_api_key = !raw_key.is_empty() || base_url.as_deref().is_some_and(is_local_url);
        let direct_openai =
            enabled && has_api_key && is_openai_compatible_endpoint(&kind, base_url.as_deref());

        push_dedup(provider_order, pid);
        if let Some(existing) = providers_by_id.get_mut(pid) {
            for m in models {
                push_dedup(&mut existing.models, m);
            }
            if existing.base_url.is_none() && base_url.is_some() {
                existing.base_url = base_url;
            }
            if !existing.has_api_key && has_api_key {
                existing.has_api_key = true;
            }
            if !existing.direct_openai_compatible && direct_openai {
                existing.direct_openai_compatible = true;
            }
            if existing.default_model.is_none() {
                existing.default_model = def_model;
            }
        } else {
            providers_by_id.insert(
                pid.to_string(),
                DiscoveredProvider {
                    id: pid.to_string(),
                    name: pname,
                    kind,
                    base_url,
                    models,
                    default_model: def_model,
                    enabled,
                    has_api_key,
                    direct_openai_compatible: direct_openai,
                    live_models_fetched: false,
                    source: source_label.to_string(),
                },
            );
        }
    }
}

/// Discover Codex (`codex`) read-only from `codex` binary, `~/.codex/config.toml`, and `~/.codex/models_cache.json`.
pub fn discover_codex_backend(
    opts: &DiscoveryOptions,
    search_dirs: &[PathBuf],
) -> DiscoveredBackend {
    let cli_bin = find_binary_in_dirs("codex", search_dirs);
    let codex_dir = opts.home_dir.join(".codex");
    let config_toml_path = codex_dir.join("config.toml");
    let models_cache_path = codex_dir.join("models_cache.json");
    let auth_json_path = codex_dir.join("auth.json");

    let has_codex_auth_file = auth_json_path
        .metadata()
        .is_ok_and(|m| m.is_file() && m.len() > 4);

    let mut cfg_model: Option<String> = None;
    let mut cfg_provider: String = "openai".to_string();
    let mut cfg_effort: String = "default".to_string();
    let mut top_base_url: Option<String> = None;
    let mut top_has_key = false;
    let mut auth_json_api_key: Option<String> = None;
    let mut providers: Vec<DiscoveredProvider> = Vec::new();
    let mut cached_models: Vec<String> = Vec::new();

    // 0. Read `~/.codex/auth.json` strictly read-only for API key if present
    if has_codex_auth_file
        && let Ok(raw_auth) = std::fs::read_to_string(&auth_json_path)
        && let Ok(auth_doc) = serde_json::from_str::<Value>(&raw_auth)
    {
        for key_field in ["OPENAI_API_KEY", "api_key", "apiKey"] {
            if let Some(k) = auth_doc
                .get(key_field)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                auth_json_api_key = Some(k.to_string());
                top_has_key = true;
                break;
            }
        }
    }

    // 1. Read `~/.codex/models_cache.json`
    if models_cache_path.is_file()
        && let Ok(raw) = std::fs::read_to_string(&models_cache_path)
        && let Ok(doc) = serde_json::from_str::<Value>(&raw)
        && let Some(arr) = doc
            .get("models")
            .or_else(|| doc.get("data"))
            .and_then(|v| v.as_array())
            .or_else(|| doc.as_array())
    {
        for item in arr {
            if let Some(s) = item.as_str() {
                push_dedup(&mut cached_models, s);
                continue;
            }
            let supported = item
                .get("supported_in_api")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if !supported {
                continue;
            }
            if let Some(slug) = item
                .get("slug")
                .or_else(|| item.get("id"))
                .or_else(|| item.get("model"))
                .and_then(|v| v.as_str())
            {
                push_dedup(&mut cached_models, slug);
            }
        }
    }

    // 2. Read `~/.codex/config.toml`
    if config_toml_path.is_file()
        && let Ok(raw) = std::fs::read_to_string(&config_toml_path)
        && let Ok(doc) = toml::from_str::<toml::Value>(&raw)
    {
        if let Some(m) = doc.get("model").and_then(|v| v.as_str()).map(str::trim)
            && !m.is_empty()
        {
            cfg_model = Some(m.to_string());
        }
        if let Some(mp) = doc
            .get("model_provider")
            .and_then(|v| v.as_str())
            .map(str::trim)
            && !mp.is_empty()
        {
            cfg_provider = mp.to_string();
        }
        if let Some(eff) = doc.get("model_reasoning_effort").and_then(|v| v.as_str()) {
            cfg_effort = normalize_reasoning_effort(Some(eff));
        }
        if let Some(u) = doc
            .get("openai_base_url")
            .or_else(|| doc.get("base_url"))
            .and_then(|v| v.as_str())
        {
            top_base_url = sanitize_url_no_secrets(u);
        }
        if let Some(k) = doc
            .get("api_key")
            .or_else(|| doc.get("openai_api_key"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            store_ephemeral_backend_key("codex", &cfg_provider, k);
            top_has_key = true;
        }

        if let Some(mp_table) = doc.get("model_providers").and_then(|v| v.as_table()) {
            for (pid, pval) in mp_table {
                let pname = pval
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(pid)
                    .to_string();
                let raw_url = pval
                    .get("base_url")
                    .or_else(|| pval.get("baseUrl"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let base_url = sanitize_url_no_secrets(raw_url);

                let mut has_key = false;
                if let Some(k) = pval
                    .get("api_key")
                    .or_else(|| pval.get("apiKey"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    store_ephemeral_backend_key("codex", pid, k);
                    has_key = true;
                }
                if opts.allow_env_keys
                    && let Some(env_key_name) = pval.get("env_key").and_then(|v| v.as_str())
                    && let Ok(env_secret) = std::env::var(env_key_name.trim())
                    && !env_secret.trim().is_empty()
                {
                    store_ephemeral_backend_key("codex", pid, env_secret.trim());
                    has_key = true;
                }
                if base_url.as_deref().is_some_and(is_local_url) {
                    has_key = true;
                }

                let mut p_models = Vec::new();
                if let Some(arr) = pval.get("models").and_then(|v| v.as_array()) {
                    for m in arr {
                        if let Some(ms) = m.as_str() {
                            push_dedup(&mut p_models, ms);
                        }
                    }
                }
                if pid == &cfg_provider
                    && let Some(ref cm) = cfg_model
                {
                    push_dedup(&mut p_models, cm);
                }
                for cm in &cached_models {
                    push_dedup(&mut p_models, cm);
                }

                let direct_openai = has_key
                    && is_openai_compatible_endpoint("openai-compatible", base_url.as_deref());

                providers.push(DiscoveredProvider {
                    id: pid.clone(),
                    name: pname,
                    kind: "openai-compatible".to_string(),
                    base_url,
                    default_model: p_models.first().cloned(),
                    models: p_models,
                    enabled: true,
                    has_api_key: has_key,
                    direct_openai_compatible: direct_openai,
                    live_models_fetched: false,
                    source: "codex:config.toml".to_string(),
                });
            }
        }
    }

    if let Some(ref auth_key) = auth_json_api_key {
        store_ephemeral_backend_key("codex", &cfg_provider, auth_key);
    }

    // Ensure the primary `cfg_provider` entry exists if no `[model_providers.<cfg_provider>]` was defined
    if !providers.iter().any(|p| p.id == cfg_provider)
        && (cli_bin.is_some()
            || cfg_model.is_some()
            || !cached_models.is_empty()
            || top_base_url.is_some()
            || has_codex_auth_file)
    {
        let mut p_models = Vec::new();
        if let Some(ref cm) = cfg_model {
            push_dedup(&mut p_models, cm);
        }
        for cm in &cached_models {
            push_dedup(&mut p_models, cm);
        }
        let effective_url = top_base_url.or_else(|| {
            if auth_json_api_key.is_some() && cfg_provider == "openai" {
                Some("https://api.openai.com/v1".to_string())
            } else {
                None
            }
        });
        let direct_openai = (top_has_key || effective_url.as_deref().is_some_and(is_local_url))
            && is_openai_compatible_endpoint("openai-compatible", effective_url.as_deref());
        providers.insert(
            0,
            DiscoveredProvider {
                id: cfg_provider.clone(),
                name: if cfg_provider == "openai" {
                    "Codex OpenAI".to_string()
                } else {
                    cfg_provider.clone()
                },
                kind: if direct_openai {
                    "openai-compatible".to_string()
                } else {
                    "codex-cli".to_string()
                },
                base_url: effective_url,
                default_model: cfg_model.clone().or_else(|| p_models.first().cloned()),
                models: p_models,
                enabled: true,
                has_api_key: top_has_key || has_codex_auth_file,
                direct_openai_compatible: direct_openai,
                live_models_fetched: false,
                source: "codex:config.toml".to_string(),
            },
        );
    }

    let mut all_models = Vec::new();
    if let Some(ref cm) = cfg_model {
        push_dedup(&mut all_models, cm);
    }
    for p in &providers {
        for m in &p.models {
            push_dedup(&mut all_models, m);
        }
    }
    for cm in &cached_models {
        push_dedup(&mut all_models, cm);
    }

    let default_provider = providers
        .iter()
        .find(|p| p.id == cfg_provider)
        .map(|p| p.id.clone())
        .or_else(|| providers.first().map(|p| p.id.clone()));
    let default_model = cfg_model.or_else(|| all_models.first().cloned());

    let installed = cli_bin.is_some();
    let has_direct = providers
        .iter()
        .any(|p| p.direct_openai_compatible && !p.models.is_empty());
    let available = installed || has_direct;

    DiscoveredBackend {
        id: "codex".to_string(),
        name: "Codex".to_string(),
        label: "Codex".to_string(),
        available,
        installed,
        binary_path: cli_bin.map(|p| p.to_string_lossy().to_string()),
        runner_program: None,
        default_provider,
        default_model,
        default_reasoning_effort: cfg_effort,
        models: all_models,
        providers,
    }
}

/// Discover Pi (`pi`) read-only from `pi` binary and `~/.pi/agent/models.json`.
pub fn discover_pi_backend(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
    search_dirs: &[PathBuf],
) -> DiscoveredBackend {
    let cli_bin = find_binary_in_dirs("pi", search_dirs);
    let adapter_exists = opts.include_system_paths && core.paths.pi_adapter_script().is_file();
    let models_json_path = opts.home_dir.join(".pi/agent/models.json");

    let mut providers: Vec<DiscoveredProvider> = Vec::new();
    let mut explicit_provider: Option<String> = None;
    let mut explicit_model: Option<String> = None;

    if models_json_path.is_file()
        && let Ok(raw) = std::fs::read_to_string(&models_json_path)
        && let Ok(doc) = serde_json::from_str::<Value>(&raw)
    {
        explicit_provider = doc
            .get("defaultProvider")
            .or_else(|| doc.get("activeProvider"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
        explicit_model = doc
            .get("defaultModel")
            .or_else(|| doc.get("model"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);

        if let Some(prov_map) = doc.get("providers").and_then(|v| v.as_object()) {
            for (pid, pval) in prov_map {
                let pname = pval
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(pid)
                    .to_string();
                let kind = pval
                    .get("api")
                    .or_else(|| pval.get("kind"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("openai-compatible")
                    .to_string();
                let raw_url = pval
                    .get("baseUrl")
                    .or_else(|| pval.get("base_url"))
                    .or_else(|| pval.get("baseURL"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let base_url = sanitize_url_no_secrets(raw_url);

                let mut has_key = false;
                if let Some(k) = pval
                    .get("apiKey")
                    .or_else(|| pval.get("api_key"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    // Pi supports either an env var identifier (`OPENAI_API_KEY`) or a direct key
                    if opts.allow_env_keys
                        && k.chars()
                            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                        && let Ok(env_val) = std::env::var(k)
                        && !env_val.trim().is_empty()
                    {
                        store_ephemeral_backend_key("pi", pid, env_val.trim());
                        has_key = true;
                    } else if !k.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                        store_ephemeral_backend_key("pi", pid, k);
                        has_key = true;
                    }
                }
                if base_url.as_deref().is_some_and(is_local_url) {
                    has_key = true;
                }

                let mut p_models = Vec::new();
                if let Some(m_arr) = pval.get("models").and_then(|v| v.as_array()) {
                    for mv in m_arr {
                        if let Some(ms) = mv
                            .as_str()
                            .or_else(|| mv.get("id").and_then(|v| v.as_str()))
                            .or_else(|| mv.get("name").and_then(|v| v.as_str()))
                        {
                            push_dedup(&mut p_models, ms);
                        }
                    }
                }

                let direct_openai =
                    has_key && is_openai_compatible_endpoint(&kind, base_url.as_deref());
                providers.push(DiscoveredProvider {
                    id: pid.clone(),
                    name: pname,
                    kind,
                    base_url,
                    default_model: p_models.first().cloned(),
                    models: p_models,
                    enabled: true,
                    has_api_key: has_key,
                    direct_openai_compatible: direct_openai,
                    live_models_fetched: false,
                    source: "pi:agent/models.json".to_string(),
                });
            }
        } else if let Some(m_arr) = doc
            .get("models")
            .and_then(|v| v.as_array())
            .or_else(|| doc.as_array())
        {
            let mut flat_models = Vec::new();
            for mv in m_arr {
                if let Some(ms) = mv
                    .as_str()
                    .or_else(|| mv.get("id").and_then(|v| v.as_str()))
                    .or_else(|| mv.get("model").and_then(|v| v.as_str()))
                {
                    push_dedup(&mut flat_models, ms);
                }
            }
            if !flat_models.is_empty() {
                providers.push(DiscoveredProvider {
                    id: "pi-default".to_string(),
                    name: "Pi Agent Models".to_string(),
                    kind: "pi-cli".to_string(),
                    base_url: None,
                    default_model: flat_models.first().cloned(),
                    models: flat_models,
                    enabled: true,
                    has_api_key: cli_bin.is_some(),
                    direct_openai_compatible: false,
                    live_models_fetched: false,
                    source: "pi:agent/models.json".to_string(),
                });
            }
        }
    }

    let mut all_models = Vec::new();
    for p in &providers {
        for m in &p.models {
            push_dedup(&mut all_models, m);
        }
    }

    let default_provider = explicit_provider
        .filter(|id| providers.iter().any(|p| &p.id == id))
        .or_else(|| providers.first().map(|p| p.id.clone()));
    let default_model = explicit_model.or_else(|| all_models.first().cloned());

    let installed = cli_bin.is_some() || adapter_exists;
    let has_direct = providers
        .iter()
        .any(|p| p.direct_openai_compatible && !p.models.is_empty());
    let available = (cli_bin.is_some() && !all_models.is_empty()) || has_direct;

    DiscoveredBackend {
        id: "pi".to_string(),
        name: "Pi".to_string(),
        label: "Pi".to_string(),
        available,
        installed,
        binary_path: cli_bin.map(|p| p.to_string_lossy().to_string()),
        runner_program: None,
        default_provider,
        default_model,
        default_reasoning_effort: "default".to_string(),
        models: all_models,
        providers,
    }
}

/// Probe local Ollama `http://127.0.0.1:11434/api/tags` with a short timeout (400ms default).
pub async fn probe_ollama_models(tags_url: &str, timeout_ms: u64) -> Option<Vec<String>> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(timeout_ms.max(50)))
        .build()
        .ok()?;
    let resp = client.get(tags_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: Value = resp.json().await.ok()?;
    let mut models = Vec::new();
    if let Some(arr) = body.get("models").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(name) = item
                .get("name")
                .or_else(|| item.get("model"))
                .and_then(|v| v.as_str())
            {
                push_dedup(&mut models, name);
            }
        }
    }
    Some(models)
}

/// Discover OpenAI-compatible & Ollama providers from `config_center`, `0600` vault, env vars, and Ollama probe.
pub async fn discover_openai_backend(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
) -> DiscoveredBackend {
    let mut providers: Vec<DiscoveredProvider> = Vec::new();
    let mut main_provider_id: Option<String> = None;
    let mut main_model_id: Option<String> = None;
    let mut main_effort = "default".to_string();

    if let Ok(cfg) = load_domains_config(core) {
        if let Some(mp) = cfg.brain.profiles.get("main") {
            main_provider_id = Some(mp.provider.clone());
            main_model_id = Some(mp.model.clone());
            main_effort = normalize_reasoning_effort(Some(&mp.thinking));
        }

        for p in &cfg.brain.providers {
            let base_url = sanitize_url_no_secrets(&p.base_url);
            let explicit_vault_key =
                lookup_ephemeral_backend_key(&core.paths, "openai", &p.id, opts.allow_env_keys);
            // Note: If gateway has a deterministic mock upstream set, treat main provider as usable
            let gateway_ready = main_provider_id.as_deref() == Some(p.id.as_str())
                && core.gateway.has_usable_credentials()
                && opts.allow_env_keys;
            let is_local = base_url.as_deref().is_some_and(is_local_url);
            // Local Ollama in `config_center` is marked `has_api_key` below once probed or if explicitly non-11434 local proxy
            let has_key = explicit_vault_key.is_some()
                || gateway_ready
                || (is_local && !p.base_url.contains(":11434"));

            let mut p_models = Vec::new();
            for m in &p.available_models {
                push_dedup(&mut p_models, m);
            }
            if main_provider_id.as_deref() == Some(p.id.as_str())
                && let Some(ref mm) = main_model_id
            {
                push_dedup(&mut p_models, mm);
            }

            let direct_openai =
                p.enabled && has_key && is_openai_compatible_endpoint(&p.kind, base_url.as_deref());

            providers.push(DiscoveredProvider {
                id: p.id.clone(),
                name: p.name.clone(),
                kind: p.kind.clone(),
                base_url,
                default_model: p_models.first().cloned(),
                models: p_models,
                enabled: p.enabled,
                has_api_key: has_key,
                direct_openai_compatible: direct_openai,
                live_models_fetched: false,
                source: "config_center".to_string(),
            });
        }
    }

    // Probe local Ollama (`http://127.0.0.1:11434/api/tags`) with 400ms timeout
    if let Some(ref tags_url) = opts.ollama_tags_url
        && let Some(ollama_models) = probe_ollama_models(tags_url, opts.ollama_timeout_ms).await
        && !ollama_models.is_empty()
    {
        let ollama_v1 = tags_url
            .strip_suffix("/api/tags")
            .map(|prefix| format!("{}/v1", prefix.trim_end_matches('/')))
            .and_then(|u| sanitize_url_no_secrets(&u))
            .unwrap_or_else(|| "http://127.0.0.1:11434/v1".to_string());

        if let Some(existing) = providers
            .iter_mut()
            .find(|p| p.id == "ollama-local" || p.kind == "ollama-local")
        {
            for m in ollama_models {
                push_dedup(&mut existing.models, m);
            }
            existing.default_model = existing.models.first().cloned();
            existing.has_api_key = true;
            existing.enabled = true;
            existing.direct_openai_compatible = true;
            existing.live_models_fetched = true;
            existing.base_url = Some(ollama_v1);
        } else {
            providers.push(DiscoveredProvider {
                id: "ollama-local".to_string(),
                name: "Ollama (Local)".to_string(),
                kind: "ollama-local".to_string(),
                base_url: Some(ollama_v1),
                default_model: ollama_models.first().cloned(),
                models: ollama_models,
                enabled: true,
                has_api_key: true,
                direct_openai_compatible: true,
                live_models_fetched: true,
                source: "ollama:11434".to_string(),
            });
        }
    }

    let mut all_models = Vec::new();
    for p in providers.iter().filter(|p| p.enabled) {
        for m in &p.models {
            push_dedup(&mut all_models, m);
        }
    }

    let default_provider = providers
        .iter()
        .find(|p| p.enabled && p.has_api_key && !p.models.is_empty())
        .map(|p| p.id.clone())
        .or(main_provider_id)
        .or_else(|| providers.first().map(|p| p.id.clone()));

    let default_model = default_provider
        .as_ref()
        .and_then(|pid| providers.iter().find(|p| &p.id == pid))
        .and_then(|p| {
            if main_model_id
                .as_ref()
                .is_some_and(|mm| p.models.iter().any(|x| x == mm))
            {
                main_model_id.clone()
            } else {
                p.default_model
                    .clone()
                    .or_else(|| p.models.first().cloned())
            }
        })
        .or(main_model_id)
        .or_else(|| all_models.first().cloned());

    let available = providers
        .iter()
        .any(|p| p.enabled && p.has_api_key && !p.models.is_empty());

    DiscoveredBackend {
        id: "openai".to_string(),
        name: "OpenAI API".to_string(),
        label: "OpenAI API".to_string(),
        available,
        installed: true,
        binary_path: None,
        runner_program: None,
        default_provider,
        default_model,
        default_reasoning_effort: main_effort,
        models: all_models,
        providers,
    }
}

/// Auto-select the best working `(backend, provider, model, reasoning_effort)` out of the box!
pub fn auto_select_best_backend(backends: &CatalogBackends) -> ActiveBackendSelection {
    let is_direct_ready = |p: &DiscoveredProvider| {
        p.enabled
            && p.has_api_key
            && (p.direct_openai_compatible || is_direct_http_endpoint(&p.kind, p.base_url.as_deref()))
            && !p.models.is_empty()
    };

    // 1. Explicit `config_center` / vault HTTP provider with real credentials (excluding auto-probed ollama-local first)
    if let Some(p) = backends
        .openai
        .providers
        .iter()
        .find(|p| is_direct_ready(p) && p.source == "config_center")
    {
        let model = backends
            .openai
            .default_model
            .clone()
            .filter(|m| p.models.contains(m))
            .or_else(|| p.default_model.clone())
            .or_else(|| p.models.first().cloned())
            .unwrap_or_else(|| "gpt-4o-mini".to_string());
        return ActiveBackendSelection {
            backend: "openai".to_string(),
            provider: p.id.clone(),
            model,
            reasoning_effort: backends.openai.default_reasoning_effort.clone(),
            base_url: p.base_url.clone(),
            pinned: false,
            auto_selected: true,
            direct_http_capable: true,
            pill_label: String::new(),
        }
        .with_computed_label();
    }

    // 2. ZCode with direct OpenAI/Anthropic HTTP endpoint OR installed ZCode CLI with configured models
    if let Some(p) = backends.zcode.providers.iter().find(|p| is_direct_ready(p)) {
        let model = p
            .default_model
            .clone()
            .or_else(|| p.models.first().cloned())
            .unwrap_or_default();
        return ActiveBackendSelection {
            backend: "zcode".to_string(),
            provider: p.id.clone(),
            model,
            reasoning_effort: backends.zcode.default_reasoning_effort.clone(),
            base_url: p.base_url.clone(),
            pinned: false,
            auto_selected: true,
            direct_http_capable: true,
            pill_label: String::new(),
        }
        .with_computed_label();
    }
    if backends.zcode.installed
        && let Some(ref model) = backends.zcode.default_model
    {
        let prov_id = backends
            .zcode
            .default_provider
            .clone()
            .unwrap_or_else(|| "zcode-default".to_string());
        let base_url = backends
            .zcode
            .providers
            .iter()
            .find(|p| p.id == prov_id)
            .and_then(|p| p.base_url.clone());
        return ActiveBackendSelection {
            backend: "zcode".to_string(),
            provider: prov_id,
            model: model.clone(),
            reasoning_effort: backends.zcode.default_reasoning_effort.clone(),
            base_url,
            pinned: false,
            auto_selected: true,
            direct_http_capable: false,
            pill_label: String::new(),
        }
        .with_computed_label();
    }

    // 3. Codex with direct OpenAI/Anthropic HTTP endpoint OR installed Codex CLI with configured models
    if let Some(p) = backends.codex.providers.iter().find(|p| is_direct_ready(p)) {
        let model = p
            .default_model
            .clone()
            .or_else(|| p.models.first().cloned())
            .unwrap_or_default();
        return ActiveBackendSelection {
            backend: "codex".to_string(),
            provider: p.id.clone(),
            model,
            reasoning_effort: backends.codex.default_reasoning_effort.clone(),
            base_url: p.base_url.clone(),
            pinned: false,
            auto_selected: true,
            direct_http_capable: true,
            pill_label: String::new(),
        }
        .with_computed_label();
    }
    if backends.codex.installed
        && let Some(ref model) = backends.codex.default_model
    {
        let prov_id = backends
            .codex
            .default_provider
            .clone()
            .unwrap_or_else(|| "openai".to_string());
        return ActiveBackendSelection {
            backend: "codex".to_string(),
            provider: prov_id,
            model: model.clone(),
            reasoning_effort: backends.codex.default_reasoning_effort.clone(),
            base_url: None,
            pinned: false,
            auto_selected: true,
            direct_http_capable: false,
            pill_label: String::new(),
        }
        .with_computed_label();
    }

    // 4. Pi with direct OpenAI/Anthropic HTTP endpoint OR installed Pi CLI with configured models
    if let Some(p) = backends.pi.providers.iter().find(|p| is_direct_ready(p)) {
        let model = p
            .default_model
            .clone()
            .or_else(|| p.models.first().cloned())
            .unwrap_or_default();
        return ActiveBackendSelection {
            backend: "pi".to_string(),
            provider: p.id.clone(),
            model,
            reasoning_effort: "default".to_string(),
            base_url: p.base_url.clone(),
            pinned: false,
            auto_selected: true,
            direct_http_capable: true,
            pill_label: String::new(),
        }
        .with_computed_label();
    }
    if backends.pi.available
        && let Some(ref model) = backends.pi.default_model
    {
        let prov_id = backends
            .pi
            .default_provider
            .clone()
            .unwrap_or_else(|| "pi-default".to_string());
        return ActiveBackendSelection {
            backend: "pi".to_string(),
            provider: prov_id,
            model: model.clone(),
            reasoning_effort: "default".to_string(),
            base_url: None,
            pinned: false,
            auto_selected: true,
            direct_http_capable: false,
            pill_label: String::new(),
        }
        .with_computed_label();
    }

    // 5. Local Ollama discovered via live probe
    if let Some(p) = backends
        .openai
        .providers
        .iter()
        .find(|p| is_direct_ready(p))
    {
        let model = p
            .default_model
            .clone()
            .or_else(|| p.models.first().cloned())
            .unwrap_or_else(|| "llama3".to_string());
        return ActiveBackendSelection {
            backend: "openai".to_string(),
            provider: p.id.clone(),
            model,
            reasoning_effort: "default".to_string(),
            base_url: p.base_url.clone(),
            pinned: false,
            auto_selected: true,
            direct_http_capable: true,
            pill_label: String::new(),
        }
        .with_computed_label();
    }

    // 6. Clean offline-capable fallback selection
    let fallback_prov = backends
        .openai
        .default_provider
        .clone()
        .unwrap_or_else(|| "default-openai".to_string());
    let fallback_model = backends
        .openai
        .default_model
        .clone()
        .unwrap_or_else(|| "gpt-4o-mini".to_string());
    ActiveBackendSelection {
        backend: "openai".to_string(),
        provider: fallback_prov,
        model: fallback_model,
        reasoning_effort: "default".to_string(),
        base_url: None,
        pinned: false,
        auto_selected: true,
        direct_http_capable: false,
        pill_label: String::new(),
    }
    .with_computed_label()
}

fn recompute_backend_rollup(backend: &mut DiscoveredBackend) {
    let mut all_models = Vec::new();
    for p in backend.providers.iter().filter(|p| p.enabled) {
        for m in &p.models {
            push_dedup(&mut all_models, m);
        }
    }
    if all_models.is_empty() {
        for p in backend.providers.iter().filter(|p| !p.enabled) {
            for m in &p.models {
                push_dedup(&mut all_models, m);
            }
        }
    }
    if let Some(ref dm) = backend.default_model
        && !is_non_chat_utility_model(dm)
    {
        push_dedup(&mut all_models, dm);
    }
    backend.models = all_models;

    let current_prov_valid = backend
        .default_provider
        .as_ref()
        .and_then(|pid| backend.providers.iter().find(|p| &p.id == pid))
        .is_some_and(|p| p.enabled && !p.models.is_empty());

    if !current_prov_valid
        && let Some(best_p) = backend
            .providers
            .iter()
            .find(|p| p.enabled && p.has_api_key && !p.models.is_empty())
            .or_else(|| {
                backend
                    .providers
                    .iter()
                    .find(|p| p.enabled && !p.models.is_empty())
            })
    {
        backend.default_provider = Some(best_p.id.clone());
    }

    if backend.default_model.is_none() {
        backend.default_model = backend
            .default_provider
            .as_ref()
            .and_then(|pid| backend.providers.iter().find(|p| &p.id == pid))
            .and_then(|p| {
                p.default_model
                    .clone()
                    .or_else(|| p.models.first().cloned())
            })
            .or_else(|| backend.models.first().cloned());
    }

    let has_direct = backend.providers.iter().any(|p| {
        p.enabled
            && p.has_api_key
            && is_direct_http_endpoint(&p.kind, p.base_url.as_deref())
            && !p.models.is_empty()
    });

    backend.available = match backend.id.as_str() {
        "openai" => backend
            .providers
            .iter()
            .any(|p| p.enabled && p.has_api_key && !p.models.is_empty()),
        "pi" => (backend.binary_path.is_some() && !backend.models.is_empty()) || has_direct,
        _ => backend.installed || has_direct,
    };
}

async fn enrich_backends_with_live_models_and_proxy_sharing(
    backends: &mut CatalogBackends,
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
) {
    if opts.probe_remote_models {
        struct ProbeJob {
            backend_id: &'static str,
            provider_idx: usize,
            base_url: String,
            kind: String,
            api_key: Option<String>,
        }

        let mut jobs: Vec<ProbeJob> = Vec::new();
        let groups: [(&'static str, &[DiscoveredProvider]); 4] = [
            ("zcode", &backends.zcode.providers),
            ("codex", &backends.codex.providers),
            ("pi", &backends.pi.providers),
            ("openai", &backends.openai.providers),
        ];

        for (bid, provs) in groups {
            for (idx, p) in provs.iter().enumerate() {
                if !p.enabled || p.kind == "ollama-local" {
                    continue;
                }
                let Some(ref url) = p.base_url else {
                    continue;
                };
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    continue;
                }
                let api_key =
                    lookup_ephemeral_backend_key(&core.paths, bid, &p.id, opts.allow_env_keys);
                let should_probe = p.has_api_key || api_key.is_some() || is_local_url(url);
                if !should_probe {
                    continue;
                }
                jobs.push(ProbeJob {
                    backend_id: bid,
                    provider_idx: idx,
                    base_url: url.clone(),
                    kind: p.kind.clone(),
                    api_key,
                });
            }
        }

        let force = opts.force_refresh_models;
        let results = join_all(jobs.iter().map(|job| async move {
            fetch_live_models_for_provider(
                &job.base_url,
                &job.kind,
                job.api_key.as_deref(),
                force,
            )
            .await
        }))
        .await;

        for (job, live_opt) in jobs.into_iter().zip(results) {
            let Some(live_models) = live_opt else {
                continue;
            };
            if live_models.is_empty() {
                continue;
            }
            let target_provs = match job.backend_id {
                "zcode" => &mut backends.zcode.providers,
                "codex" => &mut backends.codex.providers,
                "pi" => &mut backends.pi.providers,
                "openai" => &mut backends.openai.providers,
                _ => continue,
            };
            if let Some(prov) = target_provs.get_mut(job.provider_idx) {
                let mut merged = Vec::new();
                for existing in &prov.models {
                    if !is_non_chat_utility_model(existing) {
                        push_dedup(&mut merged, existing);
                    }
                }
                for lm in live_models {
                    if !is_non_chat_utility_model(&lm) {
                        push_dedup(&mut merged, lm);
                    }
                }
                prov.models = merged;
                if prov
                    .default_model
                    .as_ref()
                    .is_none_or(|dm| is_non_chat_utility_model(dm))
                {
                    prov.default_model = prov.models.first().cloned();
                }
                prov.live_models_fetched = true;
            }
        }
    }

    // Bridge local OpenAI-compatible proxy from ZCode or `config_center` (`openai`) into `codex`
    // so Codex also shows full live models when a local gateway (e.g., `http://localhost:8317/v1`) is active!
    let mut local_proxy_candidates: Vec<(&'static str, DiscoveredProvider)> = Vec::new();
    for p in &backends.zcode.providers {
        if p.enabled
            && p.direct_openai_compatible
            && p.kind != "ollama-local"
            && p.base_url.as_deref().is_some_and(is_local_url)
            && !p.models.is_empty()
        {
            local_proxy_candidates.push(("zcode", p.clone()));
        }
    }
    for p in &backends.openai.providers {
        if p.enabled
            && p.direct_openai_compatible
            && p.kind != "ollama-local"
            && p.base_url.as_deref().is_some_and(is_local_url)
            && !p.models.is_empty()
        {
            local_proxy_candidates.push(("openai", p.clone()));
        }
    }

    if backends.codex.installed || !backends.codex.providers.is_empty() {
        for (src_backend, proxy_prov) in local_proxy_candidates {
            let Some(ref proxy_url) = proxy_prov.base_url else {
                continue;
            };
            if let Some(existing_same_url) = backends
                .codex
                .providers
                .iter_mut()
                .find(|cp| cp.base_url.as_deref() == Some(proxy_url.as_str()))
            {
                for m in &proxy_prov.models {
                    push_dedup(&mut existing_same_url.models, m);
                }
                if proxy_prov.live_models_fetched {
                    existing_same_url.live_models_fetched = true;
                }
                continue;
            }

            let bridged_id = if backends
                .codex
                .providers
                .iter()
                .any(|cp| cp.id == proxy_prov.id)
            {
                format!("{}-local-proxy", src_backend)
            } else {
                proxy_prov.id.clone()
            };

            if let Some(k) = lookup_ephemeral_backend_key(
                &core.paths,
                src_backend,
                &proxy_prov.id,
                opts.allow_env_keys,
            ) {
                store_ephemeral_backend_key("codex", &bridged_id, &k);
            }

            // Also enrich a bare `codex-cli` provider (no explicit base_url) with the local proxy's models
            for cp in &mut backends.codex.providers {
                if cp.base_url.is_none() {
                    for m in &proxy_prov.models {
                        push_dedup(&mut cp.models, m);
                    }
                }
            }

            backends.codex.providers.push(DiscoveredProvider {
                id: bridged_id,
                name: format!("{} ({})", proxy_prov.name, src_backend),
                kind: "openai-compatible".to_string(),
                base_url: Some(proxy_url.clone()),
                default_model: proxy_prov.default_model.clone(),
                models: proxy_prov.models.clone(),
                enabled: true,
                has_api_key: true,
                direct_openai_compatible: true,
                live_models_fetched: proxy_prov.live_models_fetched,
                source: format!("{}:local-proxy", src_backend),
            });
        }
    }

    recompute_backend_rollup(&mut backends.zcode);
    recompute_backend_rollup(&mut backends.codex);
    recompute_backend_rollup(&mut backends.pi);
    recompute_backend_rollup(&mut backends.openai);
}

/// Discover the complete multi-backend catalog and resolve active selection.
pub async fn discover_backends_catalog(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
) -> BackendsCatalog {
    let search_dirs = build_search_dirs(opts);
    let zcode = discover_zcode_backend(opts, &search_dirs);
    let codex = discover_codex_backend(opts, &search_dirs);
    let pi = discover_pi_backend(core, opts, &search_dirs);
    let openai = discover_openai_backend(core, opts).await;

    let mut backends = CatalogBackends {
        zcode,
        codex,
        pi,
        openai,
    };

    enrich_backends_with_live_models_and_proxy_sharing(&mut backends, core, opts).await;

    let active = crate::backend_bridge::turn_engine::resolve_active_selection(core, &backends);

    BackendsCatalog {
        active,
        backend_order: vec![
            "zcode".to_string(),
            "codex".to_string(),
            "pi".to_string(),
            "openai".to_string(),
        ],
        reasoning_efforts: vec![
            json!({ "id": "default", "label": "默认" }),
            json!({ "id": "fast", "label": "快" }),
            json!({ "id": "medium", "label": "标准" }),
            json!({ "id": "high", "label": "深入" }),
        ],
        backends,
    }
}
