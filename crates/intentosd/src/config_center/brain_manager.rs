#![forbid(unsafe_code)]

//! Multi-Provider CRUD (`B-01`, `B-02`), Secret Service / `0600` Credential Vault (`§5.6`),
//! 5 Model Roles (`main`, `fast`, `decision`, `vision`, `memory` — `B-05`, `B-06`),
//! and Runtime / Budget Limits (`B-07`..`B-09`).

use crate::config::XdgPaths;
use crate::config_center::schema::{
    BrainDomainConfig, ExtendedRuntimeLimits, FullDomainsConfig, MODEL_ROLES, ManagedProvider,
    ModelRoleProfile, RoutingConfig, default_five_model_profiles,
};
use intentos_protocol::ProviderTrust;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

static IN_MEMORY_VAULT: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn memory_vault() -> &'static Mutex<HashMap<String, String>> {
    IN_MEMORY_VAULT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Securely store a provider API key.
/// 1. Tries `secret-tool store --label="IntentOS" service intentos provider <id>` via stdin.
/// 2. Stores in Core-only in-memory vault and a `0600` runtime vault file under `${runtime_dir}/vault/`.
///
/// NEVER writes to `config_dir` (`config.toml`, `brain.toml`, `domains.json`) or logs (§5.6).
pub fn store_provider_credential(
    paths: &XdgPaths,
    provider_id: &str,
    api_key: &str,
) -> anyhow::Result<String> {
    let clean_id = provider_id.trim();
    let clean_key = api_key.trim();
    if clean_id.is_empty() {
        anyhow::bail!("provider_id 不能为空");
    }
    if clean_key.is_empty() {
        return Ok(format!("secret-service://intentos/{}", clean_id));
    }

    // 1. Store in in-memory vault
    memory_vault()
        .lock()
        .unwrap()
        .insert(clean_id.to_string(), clean_key.to_string());

    // 2. Best-effort `secret-tool store` (stdin, never argv!)
    if let Ok(mut child) = Command::new("secret-tool")
        .args([
            "store",
            "--label=IntentOS Model Provider Key",
            "service",
            "intentos",
            "provider",
            clean_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(clean_key.as_bytes());
        }
        let _ = child.wait();
    }

    // 3. Controlled `0600` runtime credential slot (outside `config_dir`)
    let vault_dir = paths.runtime_dir.join("vault");
    std::fs::create_dir_all(&vault_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o700));
    }
    let vault_file = vault_dir.join("credentials.json");
    let mut map: HashMap<String, String> = if vault_file.exists() {
        std::fs::read_to_string(&vault_file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    map.insert(clean_id.to_string(), clean_key.to_string());
    std::fs::write(&vault_file, serde_json::to_vec(&map)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&vault_file, std::fs::Permissions::from_mode(0o600));
    }

    Ok(format!("secret-service://intentos/{}", clean_id))
}

/// Remove a provider credential from the vault and `secret-tool`.
pub fn remove_provider_credential(paths: &XdgPaths, provider_id: &str) {
    let clean_id = provider_id.trim();
    memory_vault().lock().unwrap().remove(clean_id);

    let _ = Command::new("secret-tool")
        .args(["clear", "service", "intentos", "provider", clean_id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let vault_file = paths.runtime_dir.join("vault/credentials.json");
    if vault_file.exists()
        && let Ok(raw) = std::fs::read_to_string(&vault_file)
        && let Ok(mut map) = serde_json::from_str::<HashMap<String, String>>(&raw)
    {
        map.remove(clean_id);
        let _ = std::fs::write(&vault_file, serde_json::to_vec(&map).unwrap_or_default());
    }
}

/// Lookup a provider API key from in-memory vault, `0600` runtime vault, `secret-tool`, or Core env.
pub fn lookup_provider_credential(paths: &XdgPaths, provider_id: &str) -> Option<String> {
    let clean_id = provider_id.trim();
    if let Some(val) = memory_vault().lock().unwrap().get(clean_id).cloned()
        && !val.is_empty()
    {
        return Some(val);
    }

    let vault_file = paths.runtime_dir.join("vault/credentials.json");
    if vault_file.exists()
        && let Ok(raw) = std::fs::read_to_string(&vault_file)
        && let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&raw)
        && let Some(val) = map.get(clean_id)
        && !val.trim().is_empty()
    {
        return Some(val.clone());
    }

    if let Ok(out) = Command::new("secret-tool")
        .args(["lookup", "service", "intentos", "provider", clean_id])
        .output()
        && out.status.success()
    {
        let secret = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !secret.is_empty() {
            return Some(secret);
        }
    }

    std::env::var("INTENTOS_API_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("OPENAI_API_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
}

pub fn has_provider_credential(paths: &XdgPaths, provider_id: &str, base_url: &str) -> bool {
    if base_url.contains("127.0.0.1") || base_url.contains("localhost") {
        return true;
    }
    lookup_provider_credential(paths, provider_id).is_some()
}

/// Refresh `has_api_key` flags across all providers without exposing any key values.
pub fn refresh_provider_key_flags(paths: &XdgPaths, brain: &mut BrainDomainConfig) {
    for p in &mut brain.providers {
        p.has_api_key = has_provider_credential(paths, &p.id, &p.base_url);
        if p.credential_ref.trim().is_empty() {
            p.credential_ref = format!("secret-service://intentos/{}", p.id);
        }
        if p.name.trim().is_empty() {
            p.name = p.id.clone();
        }
    }
}

fn parse_trust(raw: Option<&Value>) -> anyhow::Result<ProviderTrust> {
    let Some(v) = raw else {
        return Ok(ProviderTrust::Standard);
    };
    let s = v.as_str().unwrap_or("standard").trim().to_ascii_lowercase();
    match s.as_str() {
        "trusted" => Ok(ProviderTrust::Trusted),
        "standard" => Ok(ProviderTrust::Standard),
        "untrusted" => Ok(ProviderTrust::Untrusted),
        other => anyhow::bail!(
            "无效的供应商信任等级 '{}': 仅支持 trusted / standard / untrusted",
            other
        ),
    }
}

/// Add or update a model provider (`upsert_provider`, B-01 & B-02).
/// Supports `{ "provider": {...}, "api_key": "..." }` or flat `{ "id": "...", "api_key": "..." }`.
pub fn upsert_provider(
    paths: &XdgPaths,
    cfg: &mut FullDomainsConfig,
    payload: &Value,
) -> anyhow::Result<ManagedProvider> {
    let prov_obj = payload.get("provider").unwrap_or(payload);
    let id = prov_obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("upsert_provider 缺少有效的 provider.id"))?
        .to_string();

    let existing = cfg.brain.providers.iter().find(|p| p.id == id).cloned();

    let name = prov_obj
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| existing.as_ref().map(|e| e.name.clone()))
        .unwrap_or_else(|| id.clone());

    let kind = prov_obj
        .get("kind")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| existing.as_ref().map(|e| e.kind.clone()))
        .unwrap_or_else(|| "openai-compatible".to_string());

    let base_url = prov_obj
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| existing.as_ref().map(|e| e.base_url.clone()))
        .unwrap_or_else(|| match kind.as_str() {
            "ollama-local" => "http://127.0.0.1:11434/v1".to_string(),
            "anthropic" => "https://api.anthropic.com/v1".to_string(),
            "gemini" => "https://generativelanguage.googleapis.com/v1beta/openai".to_string(),
            _ => "https://api.openai.com/v1".to_string(),
        });

    let trust = if prov_obj.get("trust").is_some() {
        parse_trust(prov_obj.get("trust"))?
    } else if let Some(ref ex) = existing {
        ex.trust
    } else {
        ProviderTrust::Standard
    };

    let enabled = prov_obj
        .get("enabled")
        .and_then(|v| v.as_bool())
        .or_else(|| existing.as_ref().map(|e| e.enabled))
        .unwrap_or(true);

    let available_models: Vec<String> = prov_obj
        .get("available_models")
        .or_else(|| prov_obj.get("models"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::trim))
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .or_else(|| existing.as_ref().map(|e| e.available_models.clone()))
        .unwrap_or_else(|| vec!["gpt-4o-mini".to_string()]);

    let notes = prov_obj
        .get("notes")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| existing.as_ref().map(|e| e.notes.clone()))
        .unwrap_or_default();

    // Handle API Key securely (never persisted in ManagedProvider or TOML/JSON)
    let api_key_opt = payload
        .get("api_key")
        .or_else(|| prov_obj.get("api_key"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let credential_ref = if let Some(key) = api_key_opt {
        store_provider_credential(paths, &id, key)?
    } else {
        prov_obj
            .get("credential_ref")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty() && !s.starts_with("sk-"))
            .map(String::from)
            .or_else(|| existing.as_ref().map(|e| e.credential_ref.clone()))
            .unwrap_or_else(|| format!("secret-service://intentos/{}", id))
    };

    let provider = ManagedProvider {
        id: id.clone(),
        name,
        kind,
        base_url: base_url.clone(),
        credential_ref,
        trust,
        enabled,
        available_models,
        notes,
        has_api_key: has_provider_credential(paths, &id, &base_url),
    };
    provider.validate()?;

    if let Some(slot) = cfg.brain.providers.iter_mut().find(|p| p.id == id) {
        *slot = provider.clone();
    } else {
        cfg.brain.providers.push(provider.clone());
    }

    Ok(provider)
}

/// Delete a provider by ID (`delete_provider`), protecting the last provider and the `main` role's provider.
pub fn delete_provider(
    paths: &XdgPaths,
    cfg: &mut FullDomainsConfig,
    payload: &Value,
) -> anyhow::Result<Value> {
    let provider_id = payload
        .get("provider_id")
        .or_else(|| payload.get("id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("delete_provider 缺少 provider_id"))?;

    if !cfg.brain.providers.iter().any(|p| p.id == provider_id) {
        anyhow::bail!("未找到供应商 '{}'", provider_id);
    }

    if cfg.brain.providers.len() <= 1 {
        anyhow::bail!("保护策略拦截：不能删除系统中最后一个模型供应商");
    }

    if let Some(main_prof) = cfg.brain.profiles.get("main")
        && main_prof.provider == provider_id
    {
        anyhow::bail!(
            "保护策略拦截：供应商 '{}' 当前正被 main（主推理）角色引用，请先将 main 角色切换至其他供应商后再删除",
            provider_id
        );
    }

    cfg.brain.providers.retain(|p| p.id != provider_id);
    remove_provider_credential(paths, provider_id);

    Ok(json!({
        "deleted": true,
        "provider_id": provider_id,
        "remaining_providers": cfg.brain.providers.len(),
    }))
}

/// Update the 5 Model Role Profiles (`main`, `fast`, `decision`, `vision`, `memory`) and optional runtime/routing limits (`B-05`, `B-06`, `B-07`, `B-08`).
pub fn update_model_profiles(
    cfg: &mut FullDomainsConfig,
    payload: &Value,
) -> anyhow::Result<Value> {
    let profiles_val = payload.get("profiles").unwrap_or(payload);
    let defaults = default_five_model_profiles();

    if let Some(obj) = profiles_val.as_object() {
        for role in MODEL_ROLES {
            if let Some(role_patch) = obj.get(role).and_then(|v| v.as_object()) {
                let mut current = cfg
                    .brain
                    .profiles
                    .get(role)
                    .cloned()
                    .or_else(|| defaults.get(role).cloned())
                    .unwrap_or_else(|| defaults["main"].clone());

                if let Some(v) = role_patch.get("provider").and_then(|v| v.as_str())
                    && !v.trim().is_empty()
                {
                    current.provider = v.trim().to_string();
                }
                if let Some(v) = role_patch.get("model").and_then(|v| v.as_str())
                    && !v.trim().is_empty()
                {
                    current.model = v.trim().to_string();
                }
                if let Some(v) = role_patch.get("inherit") {
                    current.inherit = v
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && *s != "none")
                        .map(String::from);
                }
                if let Some(v) = role_patch.get("context_budget").and_then(|v| v.as_u64()) {
                    current.context_budget = v as usize;
                }
                if let Some(v) = role_patch.get("max_output_tokens").and_then(|v| v.as_u64()) {
                    current.max_output_tokens = v as usize;
                }
                if let Some(v) = role_patch.get("thinking").and_then(|v| v.as_str()) {
                    current.thinking = v.trim().to_ascii_lowercase();
                }
                if let Some(v) = role_patch.get("temperature").and_then(|v| v.as_f64()) {
                    current.temperature = v;
                }
                if let Some(v) = role_patch.get("enabled").and_then(|v| v.as_bool()) {
                    current.enabled = v;
                }
                if let Some(v) = role_patch.get("kind").and_then(|v| v.as_str())
                    && !v.trim().is_empty()
                {
                    current.kind = Some(v.trim().to_ascii_lowercase());
                }
                if let Some(v) = role_patch.get("direct_threshold").and_then(|v| v.as_f64()) {
                    current.direct_threshold = Some(v.clamp(0.1, 1.0));
                }
                if let Some(v) = role_patch.get("margin_threshold").and_then(|v| v.as_f64()) {
                    current.margin_threshold = Some(v.clamp(0.0, 1.0));
                }
                if let Some(v) = role_patch.get("clarify_threshold").and_then(|v| v.as_f64()) {
                    current.clarify_threshold = Some(v.clamp(0.0, 1.0));
                }

                current.validate(role)?;
                cfg.brain.profiles.insert(role.to_string(), current);
            }
        }
    }

    // Also support single-role update `{ "role": "fast", "profile": {...} }`
    if let Some(role) = payload.get("role").and_then(|v| v.as_str())
        && MODEL_ROLES.contains(&role)
        && let Some(role_patch) = payload.get("profile").and_then(|v| v.as_object())
    {
        let mut wrapper = serde_json::Map::new();
        wrapper.insert(role.to_string(), Value::Object(role_patch.clone()));
        let mut outer = serde_json::Map::new();
        outer.insert("profiles".to_string(), Value::Object(wrapper));
        return update_model_profiles(cfg, &Value::Object(outer));
    }

    // Optional runtime & budget limits inside the same call
    if let Some(rt) = payload.get("runtime").and_then(|v| v.as_str()) {
        cfg.brain.runtime = if rt.trim() == "native" {
            "native".to_string()
        } else {
            "pi".to_string()
        };
    }
    if let Some(lim_obj) = payload.get("runtime_limits").and_then(|v| v.as_object()) {
        apply_runtime_limits_patch(
            &mut cfg.brain.runtime_limits,
            &mut cfg.brain.routing,
            lim_obj,
        );
    }
    if let Some(rout_obj) = payload.get("routing").and_then(|v| v.as_object()) {
        apply_routing_patch(
            &mut cfg.brain.routing,
            &mut cfg.brain.runtime_limits,
            rout_obj,
        );
    }

    cfg.enforce_invariants();

    Ok(json!({
        "saved": true,
        "runtime": cfg.brain.runtime,
        "profiles": cfg.brain.profiles,
        "runtime_limits": cfg.brain.runtime_limits,
        "routing": cfg.brain.routing,
    }))
}

pub fn apply_runtime_limits_patch(
    limits: &mut ExtendedRuntimeLimits,
    routing: &mut RoutingConfig,
    obj: &serde_json::Map<String, Value>,
) {
    if let Some(v) = obj.get("max_tool_calls").and_then(|v| v.as_u64()) {
        limits.max_tool_calls = (v as u32).max(1);
    }
    if let Some(v) = obj.get("max_runtime_seconds").and_then(|v| v.as_u64()) {
        limits.max_runtime_seconds = v.max(5);
    }
    if let Some(v) = obj.get("max_concurrent_sessions").and_then(|v| v.as_u64()) {
        limits.max_concurrent_sessions = (v as usize).max(1);
    }
    if let Some(v) = obj
        .get("session_idle_timeout_minutes")
        .and_then(|v| v.as_u64())
    {
        limits.session_idle_timeout_minutes = v.max(1);
    }
    if let Some(v) = obj.get("single_task_cost_limit").and_then(|v| v.as_f64()) {
        limits.single_task_cost_limit = v.max(0.0);
    }
    if let Some(v) = obj.get("daily_cost_limit").and_then(|v| v.as_f64()) {
        limits.daily_cost_limit = v.max(0.0);
    }
    if let Some(v) = obj.get("daily_token_limit").and_then(|v| v.as_u64()) {
        limits.daily_token_limit = v;
    }
    if let Some(v) = obj.get("fallback_enabled").and_then(|v| v.as_bool()) {
        limits.fallback_enabled = v;
        routing.fallback_enabled = v;
    }
}

pub fn apply_routing_patch(
    routing: &mut RoutingConfig,
    limits: &mut ExtendedRuntimeLimits,
    obj: &serde_json::Map<String, Value>,
) {
    if let Some(v) = obj.get("l0_enabled").and_then(|v| v.as_bool()) {
        routing.l0_enabled = v;
    }
    if let Some(v) = obj.get("l1_enabled").and_then(|v| v.as_bool()) {
        routing.l1_enabled = v;
    }
    if let Some(v) = obj.get("fallback_enabled").and_then(|v| v.as_bool()) {
        routing.fallback_enabled = v;
        limits.fallback_enabled = v;
    }
    if let Some(v) = obj.get("fallback_provider") {
        routing.fallback_provider = v
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
    }
}

/// Resolve the effective `ModelRoleProfile` for a role, applying `inherit` chain if configured.
pub fn resolve_effective_role_profile(
    brain: &BrainDomainConfig,
    role: &str,
) -> Option<ModelRoleProfile> {
    let prof = brain.profiles.get(role)?.clone();
    if let Some(ref parent_role) = prof.inherit
        && parent_role != role
        && let Some(parent) = brain.profiles.get(parent_role)
    {
        return Some(ModelRoleProfile {
            provider: if prof.provider.trim().is_empty() {
                parent.provider.clone()
            } else {
                prof.provider
            },
            model: if prof.model.trim().is_empty() {
                parent.model.clone()
            } else {
                prof.model
            },
            ..prof
        });
    }
    Some(prof)
}
