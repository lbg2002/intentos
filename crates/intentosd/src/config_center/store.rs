#![forbid(unsafe_code)]

//! Configuration Persistence Layer (`store.rs`):
//! - Reads and writes `${config_dir}/config.toml`, `${config_dir}/brain.toml`, and `${config_dir}/domains.json`
//! - Keeps `IntentOsCore` state and live metrics in sync
//! - Enforces the security rule that API keys are NEVER written to TOML or JSON files (§5.6, §16.1).

use crate::config::{AppConfig, BrainConfig, XdgPaths};
use crate::config_center::brain_manager::{
    has_provider_credential, refresh_provider_key_flags, store_provider_credential,
};
use crate::config_center::egress_matrix::normalize_sensitive_directories;
use crate::config_center::schema::{
    AutomationDomainConfig, BrainDomainConfig, CapabilitiesDomainConfig, CliDependencyStatus,
    FullDomainsConfig, InteractionDomainConfig, MaintenanceDomainConfig, MemoryDomainConfig,
    OverviewDomain, PermissionsDomainConfig, ResourcesDomainConfig, StorageUsageStats,
    UndoDomainConfig, WebDomainConfig, normalize_domain_key,
};
use crate::config_center::web_and_sites::{
    ALLOWED_BROWSERS, scrub_secrets, validate_safe_http_url,
};
use crate::core::IntentOsCore;
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_protocol::PROTOCOL_VERSION;
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

static CACHED_CLI_DEPS: OnceLock<Mutex<Option<Vec<CliDependencyStatus>>>> = OnceLock::new();

pub fn domains_json_path(paths: &XdgPaths) -> std::path::PathBuf {
    paths.config_dir.join("domains.json")
}

pub fn config_toml_path(paths: &XdgPaths) -> std::path::PathBuf {
    paths.config_dir.join("config.toml")
}

pub fn brain_toml_path(paths: &XdgPaths) -> std::path::PathBuf {
    paths.config_dir.join("brain.toml")
}

/// Probe CLI dependencies (`wpctl`, `gsettings`, `nmcli`, `rg`, `fd`, `bwrap`, `git`, `secret-tool`, etc., §8.7).
pub fn probe_cli_dependencies() -> Vec<CliDependencyStatus> {
    let cache = CACHED_CLI_DEPS.get_or_init(|| Mutex::new(None));
    if let Some(ref existing) = *cache.lock().unwrap() {
        return existing.clone();
    }

    let specs = [
        ("wpctl", "--version", "audio"),
        ("gsettings", "--version", "desktop"),
        ("nmcli", "--version", "network"),
        ("rg", "--version", "search"),
        ("fd", "--version", "search"),
        ("fdfind", "--version", "search"),
        ("bwrap", "--version", "sandbox"),
        ("git", "--version", "devtools"),
        ("secret-tool", "--version", "security"),
        ("fc-list", "--version", "desktop"),
        ("xdg-open", "--version", "desktop"),
    ];

    let mut out = Vec::with_capacity(specs.len());
    for (bin, ver_flag, category) in specs {
        if let Some(path_buf) = resolve_trusted_executable(bin) {
            let ver = Command::new(&path_buf)
                .arg(ver_flag)
                .output()
                .ok()
                .and_then(|o| {
                    let s = if o.stdout.is_empty() {
                        String::from_utf8_lossy(&o.stderr).to_string()
                    } else {
                        String::from_utf8_lossy(&o.stdout).to_string()
                    };
                    s.lines().next().map(|l| l.trim().to_string())
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "installed".to_string());
            out.push(CliDependencyStatus {
                name: bin.to_string(),
                available: true,
                path: Some(path_buf.to_string_lossy().to_string()),
                version: ver,
                category: category.to_string(),
            });
        } else {
            out.push(CliDependencyStatus {
                name: bin.to_string(),
                available: false,
                path: None,
                version: "missing".to_string(),
                category: category.to_string(),
            });
        }
    }

    *cache.lock().unwrap() = Some(out.clone());
    out
}

fn file_size_or_zero(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Load `FullDomainsConfig` from `${config_dir}/domains.json`, `${config_dir}/config.toml`,
/// and `${config_dir}/brain.toml`, and enrich with live `IntentOsCore` telemetry.
pub fn load_domains_config(core: &IntentOsCore) -> anyhow::Result<FullDomainsConfig> {
    core.paths.ensure_dirs()?;
    let d_path = domains_json_path(&core.paths);
    let c_path = config_toml_path(&core.paths);
    let b_path = brain_toml_path(&core.paths);

    let disk_app: AppConfig = if c_path.exists() {
        std::fs::read_to_string(&c_path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_else(|| core.app_config.clone())
    } else {
        core.app_config.clone()
    };

    let disk_brain: BrainConfig = if b_path.exists() {
        std::fs::read_to_string(&b_path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_else(|| core.brain_config.clone())
    } else {
        core.brain_config.clone()
    };

    let mut cfg: FullDomainsConfig = if d_path.exists() {
        let raw = std::fs::read_to_string(&d_path)?;
        serde_json::from_str(&raw).unwrap_or_else(|_| {
            let mut def = FullDomainsConfig::default();
            def.merge_from_core_configs(&disk_app, &disk_brain);
            def
        })
    } else {
        let mut def = FullDomainsConfig::default();
        def.merge_from_core_configs(&disk_app, &disk_brain);
        // Persist initial `domains.json` so all 3 files exist
        let _ = save_domains_config(core, &mut def);
        def
    };

    cfg.enforce_invariants();
    enrich_live_metrics(core, &mut cfg);
    Ok(cfg)
}

/// Enrich `FullDomainsConfig` with real-time statistics from `IntentOsCore`.
pub fn enrich_live_metrics(core: &IntentOsCore, cfg: &mut FullDomainsConfig) {
    let status = core.status();
    let fonts_count = core.index_db.list_fonts().len();
    let state_db_bytes = file_size_or_zero(&core.paths.state_db_path());
    let index_db_bytes = file_size_or_zero(&core.paths.index_db_path());
    let undo_backup_bytes = status.undo_backup_bytes;
    let cli_deps = probe_cli_dependencies();

    refresh_provider_key_flags(&core.paths, &mut cfg.brain);

    let main_has_cred = cfg
        .brain
        .profiles
        .get("main")
        .and_then(|m| cfg.brain.providers.iter().find(|p| p.id == m.provider))
        .map(|p| has_provider_credential(&core.paths, &p.id, &p.base_url))
        .unwrap_or(false)
        || status.main_model_configured;

    cfg.overview = OverviewDomain {
        daemon_version: status.version,
        protocol_version: PROTOCOL_VERSION,
        pid: status.pid,
        uptime_seconds: status.uptime_seconds,
        runtime_mode: status.runtime_mode.clone(),
        runtime_healthy: true,
        main_model_configured: main_has_cred,
        indexed_apps: status.indexed_apps,
        indexed_files: status.indexed_files,
        indexed_sites: cfg.web_config.sites.len(),
        indexed_fonts: fonts_count,
        registered_capabilities: status.registered_capabilities,
        active_sessions: status.active_sessions,
        pending_approvals: status.pending_approvals,
        storage_usage: StorageUsageStats {
            state_db_bytes,
            index_db_bytes,
            undo_backup_bytes,
            total_bytes: state_db_bytes + index_db_bytes + undo_backup_bytes,
        },
        cli_dependencies: cli_deps.clone(),
    };

    cfg.brain.active_runtime = status.runtime_mode;
    cfg.brain.main_model_configured = main_has_cred;
    cfg.brain.gateway_metrics =
        serde_json::to_value(core.gateway.metrics()).unwrap_or_else(|_| json!({}));

    let memories = core
        .state_db
        .list_memory_entries()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| serde_json::to_value(m).ok())
        .collect::<Vec<_>>();
    cfg.memory_config.active_memories_count = memories.len();
    cfg.memory_config.memories = memories;

    cfg.capabilities_config.cli_dependencies = cli_deps;
    cfg.capabilities_config.total_registered = status.registered_capabilities;

    cfg.resources_config.indexed_apps = status.indexed_apps;
    cfg.resources_config.indexed_files = status.indexed_files;
    cfg.resources_config.indexed_sites = cfg.web_config.sites.len();
    cfg.resources_config.indexed_fonts = fonts_count;
    if cfg.resources_config.sensitive_directories.is_empty()
        && !cfg.brain.sensitive_directories.is_empty()
    {
        cfg.resources_config.sensitive_directories = cfg.brain.sensitive_directories.clone();
    }

    cfg.permissions_config.recent_audit = core.state_db.list_recent_audit(25);

    cfg.undo_config.current_backup_bytes = undo_backup_bytes;
    cfg.undo_config.changesets_available = status.undo_changesets_available;
}

/// Persist `FullDomainsConfig` to `${config_dir}/config.toml`, `${config_dir}/brain.toml`,
/// and `${config_dir}/domains.json`, stripping any secrets so API keys never touch disk in `config_dir`.
pub fn save_domains_config(core: &IntentOsCore, cfg: &mut FullDomainsConfig) -> anyhow::Result<()> {
    core.paths.ensure_dirs()?;
    cfg.enforce_invariants();

    // Keep sensitive_directories synchronized between brain and resources_config
    if !cfg.brain.sensitive_directories.is_empty() {
        cfg.resources_config.sensitive_directories = cfg.brain.sensitive_directories.clone();
    } else if !cfg.resources_config.sensitive_directories.is_empty() {
        cfg.brain.sensitive_directories = cfg.resources_config.sensitive_directories.clone();
    }

    let (app_cfg, brain_cfg) =
        cfg.to_core_configs(core.app_config.allow_simulated_hardware_fallback);

    let cfg_toml_str = toml::to_string_pretty(&app_cfg)?;
    let brain_toml_str = toml::to_string_pretty(&brain_cfg)?;

    std::fs::write(config_toml_path(&core.paths), cfg_toml_str)?;
    std::fs::write(brain_toml_path(&core.paths), brain_toml_str)?;

    if let Ok(mut live_guard) = core.live_configs.lock() {
        *live_guard = (app_cfg, brain_cfg.clone());
    }
    core.gateway.update_brain_config(brain_cfg);

    // Scrub ephemeral lists and secrets before writing `domains.json`
    let mut disk_copy = cfg.clone();
    for p in &mut disk_copy.brain.providers {
        p.credential_ref = format!("secret-service://intentos/{}", p.id);
    }
    disk_copy.memory_config.memories.clear();
    disk_copy.permissions_config.recent_audit.clear();

    let clean_val = scrub_secrets(&serde_json::to_value(&disk_copy)?);
    std::fs::write(
        domains_json_path(&core.paths),
        serde_json::to_string_pretty(&clean_val)?,
    )?;

    enrich_live_metrics(core, cfg);
    Ok(())
}

/// Deep merge `patch` into `target` JSON value.
fn merge_json_value(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(t_map), Value::Object(p_map)) => {
            for (k, v) in p_map {
                if k == "api_key" || k == "apikey" {
                    continue;
                }
                if let Some(existing) = t_map.get_mut(k)
                    && existing.is_object()
                    && v.is_object()
                {
                    merge_json_value(existing, v);
                    continue;
                }
                t_map.insert(k.clone(), v.clone());
            }
        }
        (t, p) => {
            *t = p.clone();
        }
    }
}

/// Update one of the 11 domains by `domain_key` and persist to `config.toml`, `brain.toml`, and `domains.json`.
pub fn update_domain_in_store(
    core: &IntentOsCore,
    cfg: &mut FullDomainsConfig,
    raw_domain_key: &str,
    data: &Value,
) -> anyhow::Result<Value> {
    let canonical = normalize_domain_key(raw_domain_key)
        .ok_or_else(|| anyhow::anyhow!("未知的配置域 key: '{}'", raw_domain_key))?;

    match canonical {
        "overview" => {
            // Overview is a read-only aggregation domain; refresh and return
            enrich_live_metrics(core, cfg);
        }
        "brain" => {
            // Extract any inline provider API keys into the secure vault first
            if let Some(provs) = data.get("providers").and_then(|v| v.as_array()) {
                for p in provs {
                    if let (Some(id), Some(key)) = (
                        p.get("id").and_then(|v| v.as_str()),
                        p.get("api_key").and_then(|v| v.as_str()),
                    ) && !key.trim().is_empty()
                    {
                        let _ = store_provider_credential(&core.paths, id, key);
                    }
                }
            }
            let mut cur_val = serde_json::to_value(&cfg.brain)?;
            merge_json_value(&mut cur_val, data);
            let mut next_brain: BrainDomainConfig = serde_json::from_value(cur_val)?;
            // Enforce forbidden = deny invariant on egress_matrix
            next_brain.egress_matrix.enforce_invariants();
            for prov in &next_brain.providers {
                prov.validate()?;
            }
            for (role, prof) in &next_brain.profiles {
                prof.validate(role)?;
            }
            cfg.brain = next_brain;
        }
        "memory_config" => {
            let mut cur_val = serde_json::to_value(&cfg.memory_config)?;
            merge_json_value(&mut cur_val, data);
            let next: MemoryDomainConfig = serde_json::from_value(cur_val)?;
            cfg.memory_config = next;
        }
        "capabilities_config" => {
            let mut cur_val = serde_json::to_value(&cfg.capabilities_config)?;
            merge_json_value(&mut cur_val, data);
            let next: CapabilitiesDomainConfig = serde_json::from_value(cur_val)?;
            cfg.capabilities_config = next;
        }
        "resources_config" => {
            let mut cur_val = serde_json::to_value(&cfg.resources_config)?;
            merge_json_value(&mut cur_val, data);
            let mut next: ResourcesDomainConfig = serde_json::from_value(cur_val)?;
            next.authorized_directories = next
                .authorized_directories
                .into_iter()
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty())
                .collect();
            next.sensitive_directories =
                normalize_sensitive_directories(next.sensitive_directories)?;
            cfg.brain.sensitive_directories = next.sensitive_directories.clone();
            cfg.resources_config = next;
        }
        "web_config" => {
            let mut cur_val = serde_json::to_value(&cfg.web_config)?;
            merge_json_value(&mut cur_val, data);
            let mut next: WebDomainConfig = serde_json::from_value(cur_val)?;
            next.open_with = next.open_with.trim().to_ascii_lowercase();
            if !ALLOWED_BROWSERS.contains(&next.open_with.as_str()) {
                anyhow::bail!(
                    "不支持的默认浏览器 '{}': 仅支持 {:?}",
                    next.open_with,
                    ALLOWED_BROWSERS
                );
            }
            for eng in &next.search_engines {
                validate_safe_http_url(&eng.url, true)?;
            }
            for site in &next.sites {
                validate_safe_http_url(&site.url, false)?;
                if let Some(ref s) = site.search
                    && !s.trim().is_empty()
                {
                    validate_safe_http_url(s, false)?;
                }
            }
            cfg.web_config = next;
        }
        "permissions_config" => {
            let mut cur_val = serde_json::to_value(&cfg.permissions_config)?;
            merge_json_value(&mut cur_val, data);
            let next: PermissionsDomainConfig = serde_json::from_value(cur_val)?;
            cfg.permissions_config = next;
        }
        "undo_config" => {
            let mut cur_val = serde_json::to_value(&cfg.undo_config)?;
            merge_json_value(&mut cur_val, data);
            let mut next: UndoDomainConfig = serde_json::from_value(cur_val)?;
            next.quota_gb = next.quota_gb.max(1);
            next.retention_days = next.retention_days.max(1);
            next.single_file_max_ratio_percent = next.single_file_max_ratio_percent.clamp(5, 100);
            cfg.undo_config = next;
        }
        "automation_config" => {
            let mut cur_val = serde_json::to_value(&cfg.automation_config)?;
            merge_json_value(&mut cur_val, data);
            let next: AutomationDomainConfig = serde_json::from_value(cur_val)?;
            if !matches!(
                next.autonomy_level.as_str(),
                "L0_Manual" | "L1_Suggest" | "L2_Authorized_Auto"
            ) {
                anyhow::bail!(
                    "无效的自主性等级 '{}': 仅允许 L0_Manual / L1_Suggest / L2_Authorized_Auto",
                    next.autonomy_level
                );
            }
            cfg.automation_config = next;
        }
        "interaction_config" => {
            let mut cur_val = serde_json::to_value(&cfg.interaction_config)?;
            merge_json_value(&mut cur_val, data);
            let mut next: InteractionDomainConfig = serde_json::from_value(cur_val)?;
            if !(85..=135).contains(&next.ui_scale_percent) {
                next.ui_scale_percent = next.ui_scale_percent.clamp(85, 135);
            }
            if !matches!(next.default_surface_mode.as_str(), "floating" | "workspace") {
                anyhow::bail!(
                    "无效的界面模式 '{}': 仅允许 floating / workspace",
                    next.default_surface_mode
                );
            }
            if !matches!(next.theme.as_str(), "system" | "dark" | "light") {
                anyhow::bail!("无效的主题 '{}': 仅允许 system / dark / light", next.theme);
            }
            if !matches!(
                next.voice_asr_mode.as_str(),
                "disabled" | "local_cpu" | "gateway_cloud"
            ) {
                anyhow::bail!(
                    "无效的语音 ASR 模式 '{}': 仅允许 disabled / local_cpu / gateway_cloud",
                    next.voice_asr_mode
                );
            }
            cfg.interaction_config = next;
        }
        "maintenance_config" => {
            let mut cur_val = serde_json::to_value(&cfg.maintenance_config)?;
            merge_json_value(&mut cur_val, data);
            let mut next: MaintenanceDomainConfig = serde_json::from_value(cur_val)?;
            if next.transcript_retention_days == 0 {
                next.transcript_retention_days = 7;
            }
            cfg.maintenance_config = next;
        }
        _ => anyhow::bail!("不支持更新配置域 '{}'", canonical),
    }

    save_domains_config(core, cfg)?;

    let updated_domain_val = get_single_domain_value(cfg, canonical);
    Ok(json!({
        "saved": true,
        "domain_key": canonical,
        "data": updated_domain_val,
    }))
}

pub fn get_single_domain_value(cfg: &FullDomainsConfig, canonical_key: &str) -> Value {
    match canonical_key {
        "overview" => serde_json::to_value(&cfg.overview).unwrap_or_default(),
        "brain" => serde_json::to_value(&cfg.brain).unwrap_or_default(),
        "memory_config" => serde_json::to_value(&cfg.memory_config).unwrap_or_default(),
        "capabilities_config" => serde_json::to_value(&cfg.capabilities_config).unwrap_or_default(),
        "resources_config" => serde_json::to_value(&cfg.resources_config).unwrap_or_default(),
        "web_config" => serde_json::to_value(&cfg.web_config).unwrap_or_default(),
        "permissions_config" => serde_json::to_value(&cfg.permissions_config).unwrap_or_default(),
        "undo_config" => serde_json::to_value(&cfg.undo_config).unwrap_or_default(),
        "automation_config" => serde_json::to_value(&cfg.automation_config).unwrap_or_default(),
        "interaction_config" => serde_json::to_value(&cfg.interaction_config).unwrap_or_default(),
        "maintenance_config" => serde_json::to_value(&cfg.maintenance_config).unwrap_or_default(),
        _ => Value::Null,
    }
}

/// Reset a specific domain or `"all"` domains to safe factory defaults (`reset_to_defaults`).
pub fn reset_to_defaults(
    core: &IntentOsCore,
    cfg: &mut FullDomainsConfig,
    payload: &Value,
) -> anyhow::Result<Value> {
    let raw_key = payload
        .get("domain_key")
        .or_else(|| payload.get("domain"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("all");

    if raw_key.eq_ignore_ascii_case("all") {
        let mut fresh = FullDomainsConfig::default();
        // Preserve test-configured authorized_directories if core had custom directories
        if !core.app_config.authorized_directories.is_empty() {
            fresh.resources_config.authorized_directories =
                core.app_config.authorized_directories.clone();
        }
        *cfg = fresh;
        save_domains_config(core, cfg)?;
        return Ok(json!({
            "reset": true,
            "domain_key": "all",
            "domains": serialize_all_domains_response(cfg),
        }));
    }

    let canonical = normalize_domain_key(raw_key)
        .ok_or_else(|| anyhow::anyhow!("未知的配置域 key: '{}'", raw_key))?;

    match canonical {
        "brain" => cfg.brain = BrainDomainConfig::default(),
        "memory_config" => cfg.memory_config = MemoryDomainConfig::default(),
        "capabilities_config" => cfg.capabilities_config = CapabilitiesDomainConfig::default(),
        "resources_config" => {
            cfg.resources_config = ResourcesDomainConfig {
                authorized_directories: core.app_config.authorized_directories.clone(),
                ..ResourcesDomainConfig::default()
            };
        }
        "web_config" => cfg.web_config = WebDomainConfig::default(),
        "permissions_config" => cfg.permissions_config = PermissionsDomainConfig::default(),
        "undo_config" => cfg.undo_config = UndoDomainConfig::default(),
        "automation_config" => cfg.automation_config = AutomationDomainConfig::default(),
        "interaction_config" => cfg.interaction_config = InteractionDomainConfig::default(),
        "maintenance_config" => cfg.maintenance_config = MaintenanceDomainConfig::default(),
        "overview" => {}
        _ => {}
    }

    save_domains_config(core, cfg)?;
    Ok(json!({
        "reset": true,
        "domain_key": canonical,
        "data": get_single_domain_value(cfg, canonical),
    }))
}

/// Format the full 11-domain response with both canonical keys (`*_config`) and shorthand aliases.
pub fn serialize_all_domains_response(cfg: &FullDomainsConfig) -> Value {
    json!({
        "overview": cfg.overview,
        "brain": cfg.brain,
        "memory_config": cfg.memory_config,
        "capabilities_config": cfg.capabilities_config,
        "resources_config": cfg.resources_config,
        "web_config": cfg.web_config,
        "permissions_config": cfg.permissions_config,
        "undo_config": cfg.undo_config,
        "automation_config": cfg.automation_config,
        "interaction_config": cfg.interaction_config,
        "maintenance_config": cfg.maintenance_config,
        // Shorthand aliases for backward/frontend compatibility
        "memory": cfg.memory_config,
        "capabilities": cfg.capabilities_config,
        "resources": cfg.resources_config,
        "web": cfg.web_config,
        "permissions": cfg.permissions_config,
        "undo": cfg.undo_config,
        "automation": cfg.automation_config,
        "interaction": cfg.interaction_config,
        "maintenance": cfg.maintenance_config,
    })
}
