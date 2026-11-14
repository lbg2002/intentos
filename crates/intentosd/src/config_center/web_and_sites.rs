#![forbid(unsafe_code)]

//! Web & Search Configuration (`§4.7`: search engines CRUD, site shortcuts & site-search
//! templates CRUD with strict `http://` / `https://` validation, browser & bookmark/history
//! authorization flags), Hotkey Conflict Detector (`§3.1`), and Secret-Free Config Bundle
//! Export/Import (`M-08`, `§5.6`).

use crate::config::{SearchEngineEntry, SiteEntry};
use crate::config_center::schema::FullDomainsConfig;
use chrono::Utc;
use serde_json::{Value, json};

pub const ALLOWED_BROWSERS: [&str; 5] = [
    "default",
    "firefox",
    "google-chrome",
    "chromium",
    "brave",
];

/// Strictly validate that a URL uses `http://` or `https://` and reject dangerous schemes
/// (`javascript:`, `file:`, `data:`, `vbscript:`, `about:`, `blob:`) per §4.7 & §5.
pub fn validate_safe_http_url(raw_url: &str, require_query_placeholder: bool) -> anyhow::Result<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        anyhow::bail!("URL 不能为空");
    }

    let lower = trimmed.to_ascii_lowercase();
    for forbidden_scheme in [
        "javascript:",
        "file:",
        "data:",
        "vbscript:",
        "about:",
        "blob:",
        "ftp:",
        "ws:",
        "wss:",
    ] {
        if lower.starts_with(forbidden_scheme) {
            anyhow::bail!(
                "安全拦截：严禁使用危险或非网页协议 '{}'（仅允许 http:// 或 https://）",
                forbidden_scheme
            );
        }
    }

    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if let Some(r) = lower.strip_prefix("http://") {
        r
    } else {
        anyhow::bail!(
            "安全拦截：URL '{}' 必须以 http:// 或 https:// 开头",
            trimmed
        );
    };

    if rest.trim().is_empty() || rest.starts_with('/') {
        anyhow::bail!("URL '{}' 缺少有效的主机域名", trimmed);
    }

    if require_query_placeholder && !trimmed.contains("{query}") {
        anyhow::bail!("搜索模板 URL '{}' 必须包含 '{{query}}' 占位符", trimmed);
    }

    Ok(trimmed.to_string())
}

/// Add or update a site shortcut and optional site-search template (`upsert_site_shortcut`, §4.7).
pub fn upsert_site_shortcut(
    cfg: &mut FullDomainsConfig,
    payload: &Value,
) -> anyhow::Result<SiteEntry> {
    let site_obj = payload.get("site").unwrap_or(payload);

    let id = site_obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("upsert_site_shortcut 缺少有效的 site.id"))?
        .to_ascii_lowercase();

    let raw_url = site_obj
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("upsert_site_shortcut 缺少 site.url"))?;
    let clean_url = validate_safe_http_url(raw_url, false)?;

    let search = match site_obj.get("search").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => {
            let validated = validate_safe_http_url(s, false)?;
            Some(validated)
        }
        _ => None,
    };

    let mut names: Vec<String> = Vec::new();
    if let Some(arr) = site_obj.get("names").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                let clean = s.trim();
                if !clean.is_empty() && !names.iter().any(|x| x == clean) {
                    names.push(clean.to_string());
                }
            }
        }
    } else if let Some(csv) = site_obj.get("names").and_then(|v| v.as_str()) {
        for part in csv.split(',') {
            let clean = part.trim();
            if !clean.is_empty() && !names.iter().any(|x| x == clean) {
                names.push(clean.to_string());
            }
        }
    }
    if let Some(single_name) = site_obj.get("name").and_then(|v| v.as_str()) {
        let clean = single_name.trim();
        if !clean.is_empty() && !names.iter().any(|x| x == clean) {
            names.insert(0, clean.to_string());
        }
    }
    if names.is_empty() {
        names.push(id.clone());
    }

    let entry = SiteEntry {
        id: id.clone(),
        names,
        url: clean_url,
        search,
    };

    if let Some(existing) = cfg.web_config.sites.iter_mut().find(|s| s.id == id) {
        *existing = entry.clone();
    } else {
        cfg.web_config.sites.push(entry.clone());
    }

    Ok(entry)
}

/// Delete a site shortcut by ID (`delete_site_shortcut`).
pub fn delete_site_shortcut(cfg: &mut FullDomainsConfig, payload: &Value) -> anyhow::Result<Value> {
    let site_id = payload
        .get("site_id")
        .or_else(|| payload.get("id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("delete_site_shortcut 缺少 site_id"))?;

    let before = cfg.web_config.sites.len();
    cfg.web_config
        .sites
        .retain(|s| !s.id.eq_ignore_ascii_case(site_id));
    let deleted = cfg.web_config.sites.len() < before;
    if !deleted {
        anyhow::bail!("未找到站点别名 '{}'", site_id);
    }

    Ok(json!({
        "deleted": true,
        "site_id": site_id,
        "remaining_sites": cfg.web_config.sites.len(),
    }))
}

/// Add or update a search engine and optionally set it as the default (`upsert_search_engine`, §4.7).
pub fn upsert_search_engine(cfg: &mut FullDomainsConfig, payload: &Value) -> anyhow::Result<Value> {
    let eng_obj = payload.get("engine").unwrap_or(payload);

    let id = eng_obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("upsert_search_engine 缺少 engine.id"))?
        .to_ascii_lowercase();

    let name = eng_obj
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&id)
        .to_string();

    let raw_url = eng_obj
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("upsert_search_engine 缺少 engine.url"))?;

    let clean_url = validate_safe_http_url(raw_url, true)?;

    let entry = SearchEngineEntry {
        id: id.clone(),
        name,
        url: clean_url,
    };

    if let Some(existing) = cfg
        .web_config
        .search_engines
        .iter_mut()
        .find(|e| e.id == id)
    {
        *existing = entry.clone();
    } else {
        cfg.web_config.search_engines.push(entry.clone());
    }

    let set_default = payload
        .get("set_default")
        .or_else(|| eng_obj.get("set_default"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if set_default {
        cfg.web_config.default_search = id.clone();
    }

    Ok(json!({
        "engine": entry,
        "default_search": cfg.web_config.default_search,
        "search_engines": cfg.web_config.search_engines,
    }))
}

/// Check whether a hotkey conflicts with Ubuntu GNOME / IBus / Fcitx5 system shortcuts (§3.1).
pub fn check_hotkey_conflict(cfg: &FullDomainsConfig, payload: &Value) -> anyhow::Result<Value> {
    let raw_hotkey = payload
        .get("hotkey")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cfg.interaction_config.hotkey);

    let normalized = raw_hotkey
        .to_ascii_lowercase()
        .replace([' ', '+'], "")
        .replace("<meta>", "<super>")
        .replace("super", "<super>")
        .replace("shift", "<shift>")
        .replace("control", "<ctrl>")
        .replace("ctrl", "<ctrl>")
        .replace("alt", "<alt>")
        .replace(">>", ">")
        .replace("<<", "<");

    let has_super = normalized.contains("<super>");
    let has_shift = normalized.contains("<shift>");
    let has_ctrl = normalized.contains("<ctrl>");
    let has_alt = normalized.contains("<alt>");
    let ends_space = normalized.ends_with("space");

    if has_super && !has_shift && !has_ctrl && !has_alt && ends_space {
        return Ok(json!({
            "hotkey": raw_hotkey,
            "conflict": true,
            "has_conflict": true,
            "severity": "high",
            "conflicting_component": "Ubuntu GNOME / IBus / Fcitx5 输入法切换",
            "message": "检测到冲突：`<Super>space` 在 Ubuntu 桌面中默认用于切换中英文输入法（IBus/Fcitx5），建议改为 `<Super><Shift>space`",
            "recommended_hotkey": "<Super><Shift>space",
        }));
    }

    if has_ctrl && !has_super && !has_shift && !has_alt && ends_space {
        return Ok(json!({
            "hotkey": raw_hotkey,
            "conflict": true,
            "has_conflict": true,
            "severity": "warning",
            "conflicting_component": "Fcitx5 / Rime 输入法激活热键",
            "message": "检测到冲突：`<Control>space` 常被中文输入法占用，建议使用 `<Super><Shift>space`",
            "recommended_hotkey": "<Super><Shift>space",
        }));
    }

    if (has_super && !has_shift && !has_ctrl && !has_alt && normalized.ends_with("l"))
        || (has_alt && !has_super && !has_shift && !has_ctrl && normalized.ends_with("f2"))
        || (has_alt && !has_super && !has_ctrl && normalized.ends_with("tab"))
    {
        return Ok(json!({
            "hotkey": raw_hotkey,
            "conflict": true,
            "has_conflict": true,
            "severity": "warning",
            "conflicting_component": "GNOME Shell 系统保留快捷键",
            "message": format!("检测到冲突：`{}` 与 GNOME 桌面系统快捷键冲突，建议使用 `<Super><Shift>space`", raw_hotkey),
            "recommended_hotkey": "<Super><Shift>space",
        }));
    }

    Ok(json!({
        "hotkey": raw_hotkey,
        "conflict": false,
        "has_conflict": false,
        "severity": "none",
        "conflicting_component": Value::Null,
        "message": format!("快捷键 `{}` 未检测到与 Ubuntu / IBus / Fcitx5 的已知冲突", raw_hotkey),
        "recommended_hotkey": "<Super><Shift>space",
    }))
}

/// Deep-scrub any accidental credential or secret keys from an arbitrary JSON value.
pub fn scrub_secrets(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut clean = serde_json::Map::new();
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                if lower == "api_key"
                    || lower == "apikey"
                    || lower == "secret"
                    || lower == "password"
                    || lower == "access_token"
                    || lower == "private_key"
                {
                    continue;
                }
                clean.insert(k.clone(), scrub_secrets(v));
            }
            Value::Object(clean)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(scrub_secrets).collect()),
        Value::String(s) => {
            if s.starts_with("sk-") || s.contains("BEGIN OPENSSH PRIVATE KEY") {
                Value::String("[REDACTED_SECRET]".into())
            } else {
                Value::String(s.clone())
            }
        }
        other => other.clone(),
    }
}

/// Export a complete secret-free configuration bundle (`export_config_bundle`, M-08, §5.6).
pub fn export_config_bundle(cfg: &FullDomainsConfig, allow_sim_fallback: bool) -> anyhow::Result<Value> {
    let mut sanitized = cfg.clone();
    sanitized.enforce_invariants();
    for prov in &mut sanitized.brain.providers {
        prov.has_api_key = false;
        prov.credential_ref = format!("secret-service://intentos/{}", prov.id);
    }
    // Clear ephemeral runtime overview metrics from the static export bundle
    sanitized.memory_config.memories.clear();
    sanitized.permissions_config.recent_audit.clear();

    let (app_cfg, brain_cfg) = sanitized.to_core_configs(allow_sim_fallback);
    let config_toml = toml::to_string_pretty(&app_cfg)?;
    let brain_toml = toml::to_string_pretty(&brain_cfg)?;
    let domains_val = scrub_secrets(&serde_json::to_value(&sanitized)?);

    Ok(json!({
        "bundle_version": 1,
        "exported_at": Utc::now().to_rfc3339(),
        "secret_free": true,
        "domains": domains_val,
        "config_toml": config_toml,
        "brain_toml": brain_toml,
    }))
}

/// Validate and import a configuration bundle (`import_config_bundle`, M-08).
pub fn import_config_bundle(
    cfg: &mut FullDomainsConfig,
    payload: &Value,
) -> anyhow::Result<Value> {
    let bundle = payload.get("bundle").unwrap_or(payload);
    let domains_json = bundle.get("domains").unwrap_or(bundle);
    let clean_json = scrub_secrets(domains_json);

    let mut imported: FullDomainsConfig = serde_json::from_value(clean_json)
        .map_err(|e| anyhow::anyhow!("配置包格式解析失败: {}", e))?;

    // Validate all site URLs and search engine URLs in the imported bundle
    for site in &imported.web_config.sites {
        validate_safe_http_url(&site.url, false)?;
        if let Some(ref s) = site.search
            && !s.trim().is_empty()
        {
            validate_safe_http_url(s, false)?;
        }
    }
    for eng in &imported.web_config.search_engines {
        validate_safe_http_url(&eng.url, true)?;
    }
    for prov in &mut imported.brain.providers {
        prov.validate()?;
        prov.credential_ref = format!("secret-service://intentos/{}", prov.id);
    }
    for (role, prof) in &imported.brain.profiles {
        prof.validate(role)?;
    }

    // Enforce security invariants (`forbidden` -> `deny`, scale bounds, 5 model roles)
    imported.enforce_invariants();

    *cfg = imported;

    Ok(json!({
        "imported": true,
        "secret_free": true,
        "providers_count": cfg.brain.providers.len(),
        "sites_count": cfg.web_config.sites.len(),
        "search_engines_count": cfg.web_config.search_engines.len(),
    }))
}
