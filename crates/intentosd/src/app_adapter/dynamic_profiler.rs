#![forbid(unsafe_code)]

//! Dynamic Desktop Software Profiler, Custom Translation Store & Multi-Stage Verified App Close
//! (`crates/intentosd/src/app_adapter/dynamic_profiler.rs`).
//!
//! Capabilities:
//! 1. Auto-discovers ALL user-installed desktop software from Freedesktop `.desktop` manifests across
//!    system, user, Snap, and Flatpak directories (`Name`, `Name[zh_CN]`, `GenericName`, `Comment`,
//!    `Keywords` such as `sodam.desktop`'s `music;qishui;soda;sodam;`, `Exec` path & basename,
//!    `StartupWMClass`, `Categories`, `MimeType` `x-scheme-handler/*`, `DBusActivatable`, and
//!    `[Desktop Action ...]`), inferring adaptation channels automatically even for zero-CLI apps.
//! 2. Loads, saves, and deletes user-customized software translation profiles at
//!    `${core.paths.config_dir}/adapters/custom_apps.json` (`dbus` | `uri` | `argv` | `shortcut` | `quit`).
//! 3. Executes real multi-stage verified application close (`close_application_verified`) with
//!    UID-scoped `/proc` enumeration, protected system process guards, MPRIS2 Quit + `wmctrl` +
//!    tray-aware `SIGTERM` + `/proc/<pid>/status` exit readback verification + approval-gated `SIGKILL`.

use crate::app_adapter::gui_bridge;
use crate::app_adapter::mpris_dbus;
use crate::app_adapter::registry::{
    AdaptationChannel, AdapterRegistry, AppAdapterProfile, SemanticAppAction,
};
use crate::app_adapter::sni_dbusmenu;
use crate::app_adapter::uri_desktop::validate_uri_safety;
use crate::core::IntentOsCore;
use crate::resource::to_pinyin_pair;
use chrono::Utc;
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_protocol::{VerificationReport, VerificationState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const SYSTEM_DESKTOP_CACHE_TTL: Duration = Duration::from_secs(60);
const CUSTOM_APPS_FILENAME: &str = "custom_apps.json";

/// Protected system, session, shell, and IntentOS processes that MUST NEVER be signaled.
const PROTECTED_PROCESS_NAMES: &[&str] = &[
    "intentosd",
    "intentosctl",
    "intentos-launcher",
    "intentos-settings",
    "antigravity",
    "gnome-shell",
    "gnome-session",
    "gnome-session-binary",
    "systemd",
    "dbus-daemon",
    "dbus-broker",
    "pipewire",
    "pipewire-pulse",
    "wireplumber",
    "xorg",
    "xwayland",
    "ibus-daemon",
    "fcitx5",
    "bash",
    "zsh",
    "sh",
    "dash",
    "fish",
    "sshd",
    "tmux",
    "init",
    "cargo",
    "rustc",
];

/// Generic software category suffixes stripped during smart app-name normalization
/// (e.g., `"SODAM音乐"` -> `"sodam"`, `"汽水音乐"` -> `"汽水"` -> pinyin `"qishui"`).
const GENERIC_APP_WORDS: &[&str] = &[
    "音乐播放器",
    "视频播放器",
    "桌面客户端",
    "客户端",
    "播放器",
    "浏览器",
    "桌面版",
    "音乐",
    "云盘",
    "网盘",
    "办公",
    "软件",
    "应用",
    "程序",
    "player",
    "music",
    "client",
    "browser",
    "desktop",
    "app",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDesktopAction {
    pub id: String,
    pub name: String,
    pub exec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDesktopSoftware {
    pub id: String,
    pub desktop_id: String,
    pub desktop_file_path: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_zh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_name_zh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub keywords: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_wm_class: Option<String>,
    pub categories: Vec<String>,
    pub mime_types: Vec<String>,
    pub uri_schemes: Vec<String>,
    pub dbus_activatable: bool,
    pub desktop_actions: Vec<DiscoveredDesktopAction>,
    pub inferred_channels: Vec<AdaptationChannel>,
    pub inferred_category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomActionMapping {
    /// `"dbus"` | `"uri"` | `"argv"` | `"shortcut"` | `"quit"`
    #[serde(default = "default_custom_channel")]
    pub channel: String,
    #[serde(
        default,
        alias = "target",
        alias = "command",
        alias = "template",
        alias = "target_template"
    )]
    pub command_or_target: String,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

fn default_custom_channel() -> String {
    "quit".to_string()
}

fn default_custom_category() -> String {
    "personal_custom".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSoftwareProfile {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_id: Option<String>,
    #[serde(
        default,
        alias = "process_name",
        alias = "executable",
        skip_serializing_if = "Option::is_none"
    )]
    pub binary_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_path: Option<String>,
    #[serde(
        default,
        alias = "startup_wm_class",
        skip_serializing_if = "Option::is_none"
    )]
    pub wm_class: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "default_custom_category")]
    pub category: String,
    #[serde(default)]
    pub actions: BTreeMap<String, CustomActionMapping>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomAppsStoreFile {
    #[serde(default = "default_schema_v1")]
    pub schema_version: u32,
    #[serde(default, alias = "adapters")]
    pub custom_apps: Vec<CustomSoftwareProfile>,
}

fn default_schema_v1() -> u32 {
    1
}

type SystemDesktopCache = Option<(Instant, Vec<DiscoveredDesktopSoftware>)>;

static SYSTEM_DESKTOP_CACHE: OnceLock<Mutex<SystemDesktopCache>> = OnceLock::new();

fn system_desktop_cache() -> &'static Mutex<SystemDesktopCache> {
    SYSTEM_DESKTOP_CACHE.get_or_init(|| Mutex::new(None))
}

/// Clear the cached system `.desktop` scan (used in tests if needed).
pub fn clear_desktop_discovery_cache() {
    *system_desktop_cache().lock().unwrap() = None;
}

fn system_desktop_directories() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
    ];
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        dirs.push(home.join(".local/share/applications"));
        dirs.push(home.join(".local/share/flatpak/exports/share/applications"));
    }
    dirs.push(PathBuf::from("/var/lib/snapd/desktop/applications"));
    dirs.push(PathBuf::from("/var/lib/flatpak/exports/share/applications"));
    dirs
}

fn custom_test_desktop_directories(config_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(cfg) = config_dir {
        dirs.push(cfg.join("applications"));
        if let Some(base) = cfg.parent() {
            dirs.push(base.join("applications"));
            dirs.push(base.join("mock_applications"));
            dirs.push(base.join(".local/share/applications"));
        }
    }
    dirs
}

fn push_unique_ci(vec: &mut Vec<String>, item: &str) {
    let trimmed = item.trim();
    if !trimmed.is_empty() && !vec.iter().any(|x| x.eq_ignore_ascii_case(trimmed)) {
        vec.push(trimmed.to_string());
    }
}

fn split_desktop_list(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in raw.split([';', ',']) {
        push_unique_ci(&mut out, part);
    }
    out
}

fn unquote_exec_tokens(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' if !in_single => {
                if let Some(next_ch) = chars.next() {
                    cur.push(next_ch);
                }
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            other => cur.push(other),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Extract `(exec_path, binary_name)` from a Freedesktop `Exec=` line, skipping `env KEY=VAL` wrappers.
pub fn extract_exec_binary(exec_raw: &str) -> (Option<String>, Option<String>) {
    let tokens = unquote_exec_tokens(exec_raw);
    let mut idx = 0;
    while idx < tokens.len() {
        let tok = tokens[idx].trim();
        if tok == "env" || tok == "/usr/bin/env" || tok == "/bin/env" {
            idx += 1;
            continue;
        }
        if tok.contains('=') && !tok.starts_with('/') && !tok.starts_with('.') {
            idx += 1;
            continue;
        }
        if tok.starts_with('%') {
            idx += 1;
            continue;
        }
        let exec_path = tok.to_string();
        let basename = Path::new(&exec_path)
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
        return (Some(exec_path), basename);
    }
    (None, None)
}

fn sanitize_slug(raw: &str) -> String {
    let mut slug = String::new();
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '-' | '_' | '.' | ' ') && !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let cleaned = slug.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "desktop-app".to_string()
    } else {
        cleaned
    }
}

/// Parse a single Freedesktop `.desktop` file into `DiscoveredDesktopSoftware`.
pub fn parse_desktop_software_file(path: &Path) -> Option<DiscoveredDesktopSoftware> {
    let content = fs::read_to_string(path).ok()?;
    let desktop_id = path.file_name()?.to_str()?.to_string();

    let mut current_section = String::new();
    let mut is_app_type = true;
    let mut hidden = false;
    let mut no_display = false;

    let mut name: Option<String> = None;
    let mut name_zh: Option<String> = None;
    let mut generic_name: Option<String> = None;
    let mut generic_name_zh: Option<String> = None;
    let mut comment: Option<String> = None;
    let mut keywords: Vec<String> = Vec::new();
    let mut exec_raw: Option<String> = None;
    let mut startup_wm_class: Option<String> = None;
    let mut categories: Vec<String> = Vec::new();
    let mut mime_types: Vec<String> = Vec::new();
    let mut dbus_activatable = false;
    type DesktopActionRawTuple = (Option<String>, Option<String>, Option<String>);
    let mut actions_map: BTreeMap<String, DesktopActionRawTuple> = BTreeMap::new();
    let mut action_order: Vec<String> = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].trim().to_string();
            if let Some(act_id) = current_section.strip_prefix("Desktop Action ") {
                let clean_id = act_id.trim().to_string();
                if !clean_id.is_empty() && !action_order.contains(&clean_id) {
                    action_order.push(clean_id.clone());
                    actions_map.entry(clean_id).or_default();
                }
            }
            continue;
        }

        let Some((k_raw, v_raw)) = line.split_once('=') else {
            continue;
        };
        let key = k_raw.trim();
        let val = v_raw.trim();

        if current_section == "Desktop Entry" {
            match key {
                "Type" => {
                    is_app_type = val.eq_ignore_ascii_case("Application");
                }
                "Hidden" => {
                    hidden = val.eq_ignore_ascii_case("true");
                }
                "NoDisplay" => {
                    no_display = val.eq_ignore_ascii_case("true");
                }
                "Name" => {
                    if !val.is_empty() {
                        name = Some(val.to_string());
                    }
                }
                "Name[zh_CN]" | "Name[zh]" | "Name[zh_TW]" => {
                    if name_zh.is_none() && !val.is_empty() {
                        name_zh = Some(val.to_string());
                    }
                }
                "GenericName" => {
                    if !val.is_empty() {
                        generic_name = Some(val.to_string());
                    }
                }
                "GenericName[zh_CN]" | "GenericName[zh]" => {
                    if generic_name_zh.is_none() && !val.is_empty() {
                        generic_name_zh = Some(val.to_string());
                    }
                }
                "Comment" | "Comment[zh_CN]" => {
                    if (comment.is_none() || key == "Comment[zh_CN]") && !val.is_empty() {
                        comment = Some(val.to_string());
                    }
                }
                "Keywords" | "Keywords[zh_CN]" | "Keywords[zh]" | "X-Ubuntu-Gettext-Domain" => {
                    for kw in split_desktop_list(val) {
                        push_unique_ci(&mut keywords, &kw);
                    }
                }
                "Exec" => {
                    if !val.is_empty() {
                        exec_raw = Some(val.to_string());
                    }
                }
                "StartupWMClass" => {
                    if !val.is_empty() {
                        startup_wm_class = Some(val.to_string());
                    }
                }
                "Categories" => {
                    for cat in split_desktop_list(val) {
                        push_unique_ci(&mut categories, &cat);
                    }
                }
                "MimeType" => {
                    for mt in split_desktop_list(val) {
                        push_unique_ci(&mut mime_types, &mt);
                    }
                }
                "DBusActivatable" => {
                    dbus_activatable = val.eq_ignore_ascii_case("true");
                }
                _ => {}
            }
        } else if let Some(act_id) = current_section.strip_prefix("Desktop Action ") {
            let entry = actions_map.entry(act_id.trim().to_string()).or_default();
            match key {
                "Name" => entry.0 = Some(val.to_string()),
                "Name[zh_CN]" | "Name[zh]" => entry.1 = Some(val.to_string()),
                "Exec" => entry.2 = Some(val.to_string()),
                _ => {}
            }
        }
    }

    if !is_app_type || hidden {
        return None;
    }

    let primary_name = name.or_else(|| name_zh.clone())?;
    let (exec_path, binary_name) = exec_raw
        .as_deref()
        .map(extract_exec_binary)
        .unwrap_or((None, None));

    // Filter out pure uninstaller `.desktop` entries (e.g. `yozo-uninstall.desktop`)
    let id_lc = desktop_id.to_ascii_lowercase();
    let exec_lc = exec_path.as_deref().unwrap_or("").to_ascii_lowercase();
    let pname_lc = primary_name.to_ascii_lowercase();
    if id_lc.contains("uninstall")
        || id_lc.starts_with("remove-")
        || exec_lc.ends_with("/uninstall")
        || exec_lc.contains("/uninstall/")
        || pname_lc.starts_with("uninstall ")
        || pname_lc.starts_with("remove ")
        || name_zh.as_deref().is_some_and(|z| z.starts_with("卸载"))
    {
        return None;
    }

    // Skip internal helper `.desktop` handlers (`NoDisplay=true` without URI scheme or startup WM class)
    let mut uri_schemes = Vec::new();
    for mt in &mime_types {
        if let Some(scheme) = mt
            .to_ascii_lowercase()
            .strip_prefix("x-scheme-handler/")
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            push_unique_ci(&mut uri_schemes, scheme);
        }
    }
    if no_display && uri_schemes.is_empty() && startup_wm_class.is_none() {
        return None;
    }

    let mut desktop_actions = Vec::new();
    for act_id in action_order {
        if let Some((en_name, zh_name, Some(exec_str))) = actions_map.remove(&act_id) {
            desktop_actions.push(DiscoveredDesktopAction {
                name: zh_name.or(en_name).unwrap_or_else(|| act_id.clone()),
                id: act_id,
                exec: exec_str,
            });
        }
    }

    let cat_joined = categories.join(";").to_ascii_lowercase();
    let kw_joined = keywords.join(";").to_ascii_lowercase();
    let is_media = ["audio", "music", "player", "video", "audiovideo"]
        .iter()
        .any(|tag| cat_joined.contains(tag) || kw_joined.contains(tag));

    let inferred_category = crate::app_adapter::local_scanner::classify_software_category(
        &desktop_id,
        exec_path
            .as_deref()
            .or(binary_name.as_deref())
            .unwrap_or(&desktop_id),
        &primary_name,
        name_zh.as_deref(),
        startup_wm_class.as_deref(),
        &uri_schemes,
        &mime_types,
        &categories,
    )
    .id
    .to_string();

    let mut inferred_channels = Vec::new();
    let mut push_ch = |ch: AdaptationChannel| {
        if !inferred_channels.contains(&ch) {
            inferred_channels.push(ch);
        }
    };
    if is_media {
        push_ch(AdaptationChannel::DbusMpris);
    }
    if dbus_activatable {
        push_ch(AdaptationChannel::DbusFreedesktop);
    }
    if !uri_schemes.is_empty() {
        push_ch(AdaptationChannel::UriScheme);
    }
    if !desktop_actions.is_empty() {
        push_ch(AdaptationChannel::DesktopAction);
    }
    push_ch(AdaptationChannel::ProcessLifecycle);
    push_ch(AdaptationChannel::GuiAtspi);

    let stem = desktop_id.trim_end_matches(".desktop");
    let id = if let Some(ref bin) = binary_name
        && stem.contains('.')
        && !PROTECTED_PROCESS_NAMES.contains(&bin.to_ascii_lowercase().as_str())
    {
        sanitize_slug(bin)
    } else {
        sanitize_slug(stem)
    };

    Some(DiscoveredDesktopSoftware {
        id,
        desktop_id,
        desktop_file_path: path.to_string_lossy().to_string(),
        name: primary_name,
        name_zh,
        generic_name,
        generic_name_zh,
        comment,
        keywords,
        exec_raw,
        exec_path,
        binary_name,
        startup_wm_class,
        categories,
        mime_types,
        uri_schemes,
        dbus_activatable,
        desktop_actions,
        inferred_channels,
        inferred_category,
    })
}

fn scan_desktop_dirs(dirs: &[PathBuf]) -> Vec<DiscoveredDesktopSoftware> {
    let mut seen_desktop_ids = HashSet::new();
    let mut discovered = Vec::new();

    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if p.extension().and_then(|s| s.to_str()) != Some("desktop") {
                continue;
            }
            if let Some(parsed) = parse_desktop_software_file(&p)
                && seen_desktop_ids.insert(parsed.desktop_id.to_ascii_lowercase())
            {
                discovered.push(parsed);
            }
        }
    }

    discovered
}

/// Discover all installed desktop software across local test dirs + cached system `.desktop` dirs.
pub fn discover_installed_desktop_apps(
    config_dir: Option<&Path>,
) -> Vec<DiscoveredDesktopSoftware> {
    let custom_dirs = custom_test_desktop_directories(config_dir);
    let mut combined = scan_desktop_dirs(&custom_dirs);
    let mut seen_ids: HashSet<String> = combined
        .iter()
        .map(|d| d.desktop_id.to_ascii_lowercase())
        .collect();

    let system_entries = {
        let mut guard = system_desktop_cache().lock().unwrap();
        if let Some((ts, ref cached)) = *guard
            && ts.elapsed() < SYSTEM_DESKTOP_CACHE_TTL
        {
            cached.clone()
        } else {
            let scanned = scan_desktop_dirs(&system_desktop_directories());
            *guard = Some((Instant::now(), scanned.clone()));
            scanned
        }
    };

    for entry in system_entries {
        if seen_ids.insert(entry.desktop_id.to_ascii_lowercase()) {
            combined.push(entry);
        }
    }

    combined
}

/// Built-in alias expansion table for popular Chinese/domestic Linux desktop & tray apps.
pub fn builtin_domestic_app_aliases(
    id_or_stem: &str,
    binary_name: Option<&str>,
) -> Vec<&'static str> {
    let key = id_or_stem.trim().to_ascii_lowercase();
    let bin = binary_name.unwrap_or("").trim().to_ascii_lowercase();
    let matches_any = |cands: &[&str]| {
        cands
            .iter()
            .any(|c| key == *c || (!bin.is_empty() && bin == *c))
    };

    if matches_any(&["sodam", "汽水音乐", "qishui", "soda"]) {
        vec!["汽水音乐", "sodam", "qishui", "soda"]
    } else if matches_any(&["qqmusic", "qq音乐", "com.qq.music"]) {
        vec!["QQ音乐", "qqmusic", "腾讯音乐", "qqyy"]
    } else if matches_any(&["qq", "linuxqq", "腾讯qq"]) {
        vec!["腾讯QQ", "QQ", "linuxqq", "qq"]
    } else if matches_any(&["wechat", "weixin", "微信", "com.tencent.wechat"]) {
        vec!["微信", "wechat", "weixin"]
    } else if matches_any(&["bytedance-feishu", "feishu", "lark", "飞书"]) {
        vec!["飞书", "feishu", "lark", "bytedance-feishu"]
    } else if matches_any(&["wemeetapp", "wemeet", "腾讯会议", "com.tencent.wemeet"]) {
        vec!["腾讯会议", "wemeet", "wemeetapp", "tengxunhuiyi"]
    } else if matches_any(&["baidunetdisk", "百度网盘", "百度云"]) {
        vec!["百度网盘", "百度云", "baidunetdisk"]
    } else if matches_any(&["mcloud", "移动云盘", "中国移动云盘"]) {
        vec!["移动云盘", "中国移动云盘", "mcloud"]
    } else if matches_any(&[
        "betternotes",
        "轻笺",
        "pinplan",
        "com.github.paperhead.betternotes",
    ]) {
        vec!["轻笺", "betternotes", "pinplan"]
    } else if matches_any(&["flclash", "clash", "代理", "系统代理"]) {
        vec!["FlClash", "flclash", "clash", "代理", "系统代理"]
    } else if matches_any(&["discforge", "光铸"]) {
        vec!["光铸", "discforge"]
    } else if matches_any(&["yozo", "yozo-office", "永中", "永中office"]) {
        vec!["永中", "永中Office", "yozo", "yozo-office"]
    } else if matches_any(&[
        "wps",
        "wps-office",
        "wpscloudsvr",
        "qing",
        "wps云盘",
        "et",
        "wpp",
    ]) {
        vec![
            "WPS",
            "WPS云盘",
            "金山办公",
            "wps-office",
            "wpscloudsvr",
            "qing",
        ]
    } else if matches_any(&["localsend", "localsend_app", "局域网互传", "隔空投送"]) {
        vec!["LocalSend", "localsend", "localsend_app", "局域网互传"]
    } else if matches_any(&["tailscale", "组网", "内网穿透"]) {
        vec!["Tailscale", "tailscale", "异地组网"]
    } else if matches_any(&["rustdesk", "远程桌面", "远控"]) {
        vec!["RustDesk", "rustdesk", "远程桌面", "远控"]
    } else if matches_any(&["virtualbox", "vbox", "vboxmanage", "虚拟机"]) {
        vec!["VirtualBox", "virtualbox", "vbox", "虚拟机"]
    } else if matches_any(&["drawio", "diagrams.net", "流程图"]) {
        vec!["draw.io", "drawio", "流程图"]
    } else if matches_any(&["typora", "markdown编辑器"]) {
        vec!["Typora", "typora", "Markdown笔记"]
    } else if matches_any(&["onlyoffice", "onlyoffice-desktopeditors"]) {
        vec!["ONLYOFFICE", "onlyoffice", "onlyoffice-desktopeditors"]
    } else if matches_any(&["pdfarranger", "pdf合并", "pdf拆分"]) {
        vec!["PDF Arranger", "pdfarranger", "PDF合并拆分"]
    } else if matches_any(&["fcitx5", "fcitx", "org.fcitx.fcitx5", "输入法"]) {
        vec!["Fcitx5", "fcitx5", "中文输入法", "输入法"]
    } else if matches_any(&["wowtype", "wowtype-config", "语音输入"]) {
        vec!["WowType", "wowtype", "语音输入配置"]
    } else if matches_any(&["omni-mouse-studio", "鼠标智控", "多功能鼠标智控中心"]) {
        vec!["Omni Mouse", "omni-mouse-studio", "多功能鼠标智控中心", "鼠标驱动"]
    } else if matches_any(&["trae-cn", "trae"]) {
        vec!["Trae CN", "trae-cn", "trae"]
    } else if matches_any(&["antigravity-ide", "antigravity-app", "agy"]) {
        vec!["Antigravity", "antigravity-ide", "agy"]
    } else if matches_any(&["workbuddy"]) {
        vec!["WorkBuddy", "workbuddy"]
    } else if matches_any(&["hopper", "crypticapps-com.hopperapp.hopper", "反汇编"]) {
        vec!["Hopper", "hopper", "逆向反汇编"]
    } else if matches_any(&["nvidia-settings", "nvidia-smi", "显卡设置", "显卡状态"]) {
        vec!["NVIDIA显卡设置", "nvidia-settings", "nvidia-smi", "GPU遥测"]
    } else if matches_any(&["douyin", "抖音"]) {
        vec!["抖音", "douyin"]
    } else {
        Vec::new()
    }
}

/// Convert a `DiscoveredDesktopSoftware` manifest into a full `AppAdapterProfile`.
pub fn desktop_software_to_adapter_profile(sw: &DiscoveredDesktopSoftware) -> AppAdapterProfile {
    let display_name = sw.name_zh.clone().unwrap_or_else(|| sw.name.clone());
    let mut aliases = Vec::new();
    push_unique_ci(&mut aliases, &sw.name);
    if let Some(ref zh) = sw.name_zh {
        push_unique_ci(&mut aliases, zh);
    }
    if let Some(ref gn) = sw.generic_name {
        push_unique_ci(&mut aliases, gn);
    }
    if let Some(ref gn_zh) = sw.generic_name_zh {
        push_unique_ci(&mut aliases, gn_zh);
    }
    for kw in &sw.keywords {
        push_unique_ci(&mut aliases, kw);
    }
    if let Some(ref bin) = sw.binary_name {
        push_unique_ci(&mut aliases, bin);
    }
    if let Some(ref wmc) = sw.startup_wm_class {
        push_unique_ci(&mut aliases, wmc);
    }
    let stem = sw.desktop_id.trim_end_matches(".desktop");
    push_unique_ci(&mut aliases, stem);
    for extra in builtin_domestic_app_aliases(&sw.id, sw.binary_name.as_deref()) {
        push_unique_ci(&mut aliases, extra);
    }
    for extra in builtin_domestic_app_aliases(stem, sw.binary_name.as_deref()) {
        push_unique_ci(&mut aliases, extra);
    }

    let mut mpris_bus_hints = Vec::new();
    if sw.inferred_channels.contains(&AdaptationChannel::DbusMpris) {
        if let Some(ref bin) = sw.binary_name {
            push_unique_ci(&mut mpris_bus_hints, bin);
        }
        push_unique_ci(&mut mpris_bus_hints, &sw.id);
        if let Some(ref wmc) = sw.startup_wm_class {
            push_unique_ci(&mut mpris_bus_hints, &wmc.to_ascii_lowercase());
        }
    }

    let mut cli_executables = Vec::new();
    if let Some(ref bin) = sw.binary_name {
        push_unique_ci(&mut cli_executables, bin);
    }
    if let Some(ref ep) = sw.exec_path {
        push_unique_ci(&mut cli_executables, ep);
    }

    let mut supported_actions = Vec::new();
    if sw.inferred_channels.contains(&AdaptationChannel::DbusMpris) {
        supported_actions.push(SemanticAppAction {
            action: "play_pause".into(),
            aliases: vec!["播放暂停".into(), "toggle".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: format!("切换「{}」播放/暂停状态 (MPRIS2)", display_name),
            target_template: Some("org.mpris.MediaPlayer2.Player.PlayPause".into()),
            requires_approval: false,
            reversible: true,
        });
        supported_actions.push(SemanticAppAction {
            action: "play".into(),
            aliases: vec!["播放".into(), "继续播放".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: format!("开始「{}」播放 (MPRIS2)", display_name),
            target_template: Some("org.mpris.MediaPlayer2.Player.Play".into()),
            requires_approval: false,
            reversible: true,
        });
        supported_actions.push(SemanticAppAction {
            action: "pause".into(),
            aliases: vec!["暂停".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: format!("暂停「{}」播放 (MPRIS2)", display_name),
            target_template: Some("org.mpris.MediaPlayer2.Player.Pause".into()),
            requires_approval: false,
            reversible: true,
        });
        supported_actions.push(SemanticAppAction {
            action: "next".into(),
            aliases: vec!["下一首".into(), "切歌".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: format!("「{}」切换到下一首 (MPRIS2)", display_name),
            target_template: Some("org.mpris.MediaPlayer2.Player.Next".into()),
            requires_approval: false,
            reversible: true,
        });
        supported_actions.push(SemanticAppAction {
            action: "previous".into(),
            aliases: vec!["上一首".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: format!("「{}」返回上一首 (MPRIS2)", display_name),
            target_template: Some("org.mpris.MediaPlayer2.Player.Previous".into()),
            requires_approval: false,
            reversible: true,
        });
        supported_actions.push(SemanticAppAction {
            action: "get_now_playing".into(),
            aliases: vec!["当前播放".into(), "正在播放".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: format!("查询「{}」当前播放曲目 (MPRIS2)", display_name),
            target_template: Some("org.freedesktop.DBus.Properties.GetAll".into()),
            requires_approval: false,
            reversible: false,
        });
    }

    if !sw.uri_schemes.is_empty() {
        let primary_scheme = &sw.uri_schemes[0];
        supported_actions.push(SemanticAppAction {
            action: "open_uri".into(),
            aliases: vec!["打开链接".into(), "deep_link".into()],
            channel: AdaptationChannel::UriScheme,
            summary: format!(
                "通过 `{}://` 协议深度唤起「{}」",
                primary_scheme, display_name
            ),
            target_template: Some(format!("{}://{{target}}", primary_scheme)),
            requires_approval: false,
            reversible: false,
        });
    }

    for da in &sw.desktop_actions {
        let act_slug = sanitize_slug(&da.id).replace('-', "_");
        supported_actions.push(SemanticAppAction {
            action: act_slug,
            aliases: vec![da.id.clone(), da.name.clone()],
            channel: AdaptationChannel::DesktopAction,
            summary: format!("执行「{}」桌面快捷动作：{}", display_name, da.name),
            target_template: Some(da.id.clone()),
            requires_approval: false,
            reversible: false,
        });
    }

    supported_actions.push(SemanticAppAction {
        action: "focus_window".into(),
        aliases: vec!["聚焦窗口".into(), "切换窗口".into()],
        channel: AdaptationChannel::GuiAtspi,
        summary: format!("聚焦「{}」桌面窗口", display_name),
        target_template: sw.startup_wm_class.clone(),
        requires_approval: false,
        reversible: false,
    });
    supported_actions.push(SemanticAppAction::quit_app(&display_name));

    let dbus_name = if sw.dbus_activatable && sw.desktop_id.contains('.') {
        Some(sw.desktop_id.trim_end_matches(".desktop").to_string())
    } else {
        None
    };

    AppAdapterProfile {
        id: sw.id.clone(),
        name: display_name,
        desktop_ids: vec![sw.desktop_id.clone()],
        aliases,
        category: sw.inferred_category.clone(),
        channels: sw.inferred_channels.clone(),
        mpris_bus_hints,
        dbus_name,
        uri_schemes: sw.uri_schemes.clone(),
        cli_executables,
        supported_actions,
        source: format!("desktop_auto:{}", sw.desktop_id),
        notes: sw
            .comment
            .clone()
            .unwrap_or_else(|| "基于 Freedesktop .desktop 自动特征推断生成的软件指令转译配置".to_string()),
    }
}

/// Path to `${config_dir}/adapters/custom_apps.json`.
pub fn custom_apps_file_path(config_dir: &Path) -> PathBuf {
    config_dir.join("adapters").join(CUSTOM_APPS_FILENAME)
}

/// Load `CustomSoftwareProfile` entries from `${config_dir}/adapters/custom_apps.json`.
pub fn load_custom_apps_store(config_dir: &Path) -> CustomAppsStoreFile {
    let path = custom_apps_file_path(config_dir);
    let Ok(raw) = fs::read_to_string(&path) else {
        return CustomAppsStoreFile {
            schema_version: 1,
            custom_apps: Vec::new(),
        };
    };
    if let Ok(store) = serde_json::from_str::<CustomAppsStoreFile>(&raw) {
        return store;
    }
    if let Ok(vec) = serde_json::from_str::<Vec<CustomSoftwareProfile>>(&raw) {
        return CustomAppsStoreFile {
            schema_version: 1,
            custom_apps: vec,
        };
    }
    CustomAppsStoreFile {
        schema_version: 1,
        custom_apps: Vec::new(),
    }
}

pub fn save_custom_apps_store(
    config_dir: &Path,
    store: &CustomAppsStoreFile,
) -> anyhow::Result<PathBuf> {
    let path = custom_apps_file_path(config_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_vec_pretty(store)?;
    fs::write(&path, serialized)?;
    Ok(path)
}

pub fn map_custom_channel_name(raw: &str) -> AdaptationChannel {
    match raw.trim().to_ascii_lowercase().as_str() {
        "dbus" | "dbus_mpris" | "mpris" => AdaptationChannel::DbusMpris,
        "tray" | "dbusmenu" | "sni" | "sni_dbusmenu" => AdaptationChannel::SniDbusMenu,
        "dbus_freedesktop" | "freedesktop" => AdaptationChannel::DbusFreedesktop,
        "uri" | "uri_scheme" | "deeplink" => AdaptationChannel::UriScheme,
        "desktop_action" | "desktop" => AdaptationChannel::DesktopAction,
        "headless" | "headless_cli" => AdaptationChannel::HeadlessCli,
        "argv" | "cli" | "cli_wrapper" => AdaptationChannel::CliWrapper,
        "shortcut" | "gui" | "gui_atspi" | "atspi" => AdaptationChannel::GuiAtspi,
        _ => AdaptationChannel::ProcessLifecycle,
    }
}

/// Convert a `CustomSoftwareProfile` into an `AppAdapterProfile` for unified registry resolution.
pub fn custom_software_to_adapter_profile(custom: &CustomSoftwareProfile) -> AppAdapterProfile {
    let mut aliases = Vec::new();
    push_unique_ci(&mut aliases, &custom.name);
    for a in &custom.aliases {
        push_unique_ci(&mut aliases, a);
    }
    for kw in &custom.keywords {
        push_unique_ci(&mut aliases, kw);
    }
    if let Some(ref b) = custom.binary_name {
        push_unique_ci(&mut aliases, b);
    }
    if let Some(ref wmc) = custom.wm_class {
        push_unique_ci(&mut aliases, wmc);
    }

    let mut channels = Vec::new();
    let mut uri_schemes = Vec::new();
    let mut supported_actions = Vec::new();

    for (act_name, mapping) in &custom.actions {
        let ch = map_custom_channel_name(&mapping.channel);
        if !channels.contains(&ch) {
            channels.push(ch);
        }
        if ch == AdaptationChannel::UriScheme
            && let Some((scheme, _)) = mapping.command_or_target.split_once("://")
        {
            push_unique_ci(&mut uri_schemes, scheme);
        }
        let default_req_approval =
            mapping.requires_approval || matches!(mapping.channel.as_str(), "shortcut" | "gui_atspi");
        supported_actions.push(SemanticAppAction {
            action: act_name.clone(),
            aliases: mapping.aliases.clone(),
            channel: ch,
            summary: mapping
                .summary
                .clone()
                .unwrap_or_else(|| format!("自定义转译动作 `{}` -> `{}`", act_name, mapping.command_or_target)),
            target_template: Some(mapping.command_or_target.clone()),
            requires_approval: default_req_approval,
            reversible: false,
        });
    }

    if !channels.contains(&AdaptationChannel::ProcessLifecycle) {
        channels.push(AdaptationChannel::ProcessLifecycle);
    }
    if !supported_actions.iter().any(|a| a.action == "quit") {
        supported_actions.push(SemanticAppAction::quit_app(&custom.name));
    }

    let mut cli_executables = Vec::new();
    if let Some(ref b) = custom.binary_name {
        push_unique_ci(&mut cli_executables, b);
    }
    if let Some(ref ep) = custom.exec_path {
        push_unique_ci(&mut cli_executables, ep);
    }

    let desktop_ids = custom
        .desktop_id
        .iter()
        .cloned()
        .collect::<Vec<String>>();

    AppAdapterProfile {
        id: custom.id.clone(),
        name: custom.name.clone(),
        desktop_ids,
        aliases,
        category: custom.category.clone(),
        channels,
        mpris_bus_hints: cli_executables.clone(),
        dbus_name: None,
        uri_schemes,
        cli_executables,
        supported_actions,
        source: format!("user_custom:{}", CUSTOM_APPS_FILENAME),
        notes: if custom.notes.trim().is_empty() {
            "用户个性化无 CLI 软件自定义指令转译配置".to_string()
        } else {
            custom.notes.clone()
        },
    }
}

/// Upsert a `CustomSoftwareProfile` into `${config_dir}/adapters/custom_apps.json` from flexible RPC payload.
pub fn upsert_custom_adapter_from_payload(
    core: &IntentOsCore,
    payload: &Value,
) -> anyhow::Result<Value> {
    let root = payload
        .get("adapter")
        .or_else(|| payload.get("profile"))
        .unwrap_or(payload);

    let raw_name = root
        .get("name")
        .or_else(|| root.get("app_name"))
        .or_else(|| root.get("display_name"))
        .or_else(|| root.get("id"))
        .or_else(|| root.get("app_id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("save_custom_adapter: 缺少软件名称 `name` 或标识 `id`"))?;

    let id = root
        .get("id")
        .or_else(|| root.get("app_id"))
        .and_then(|v| v.as_str())
        .map(sanitize_slug)
        .unwrap_or_else(|| sanitize_slug(raw_name));

    let mut store = load_custom_apps_store(&core.paths.config_dir);
    let existing_opt = store
        .custom_apps
        .iter()
        .find(|c| c.id.eq_ignore_ascii_case(&id))
        .cloned();

    let mut actions = if root
        .get("replace_actions")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        BTreeMap::new()
    } else {
        existing_opt
            .as_ref()
            .map(|e| e.actions.clone())
            .unwrap_or_default()
    };

    if let Some(act_val) = root
        .get("actions")
        .or_else(|| root.get("custom_actions"))
        .or_else(|| root.get("supported_actions"))
    {
        match act_val {
            Value::Object(map) => {
                for (act_key, v) in map {
                    if let Ok(parsed_map) = serde_json::from_value::<CustomActionMapping>(v.clone())
                    {
                        actions.insert(act_key.trim().to_string(), parsed_map);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    let Some(act_key) = item
                        .get("action")
                        .or_else(|| item.get("action_name"))
                        .or_else(|| item.get("name"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    let channel = item
                        .get("channel")
                        .and_then(|v| v.as_str())
                        .unwrap_or("uri")
                        .to_string();
                    let command_or_target = item
                        .get("command_or_target")
                        .or_else(|| item.get("target_template"))
                        .or_else(|| item.get("target"))
                        .or_else(|| item.get("command"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let requires_approval = item
                        .get("requires_approval")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let summary = item
                        .get("summary")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let aliases = item
                        .get("aliases")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    actions.insert(
                        act_key.to_string(),
                        CustomActionMapping {
                            channel,
                            command_or_target,
                            requires_approval,
                            summary,
                            aliases,
                        },
                    );
                }
            }
            _ => {}
        }
    }

    // Also support flat single-action fields (`action_name` + `channel` + `command_or_target`)
    if let Some(single_act) = root
        .get("action_name")
        .or_else(|| root.get("intent_action"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let channel = root
            .get("channel")
            .and_then(|v| v.as_str())
            .unwrap_or("quit")
            .to_string();
        let command_or_target = root
            .get("command_or_target")
            .or_else(|| root.get("target"))
            .or_else(|| root.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let requires_approval = root
            .get("requires_approval")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        actions.insert(
            single_act.to_string(),
            CustomActionMapping {
                channel,
                command_or_target,
                requires_approval,
                summary: root
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                aliases: Vec::new(),
            },
        );
    }

    let parse_str_list = |key: &str| -> Vec<String> {
        match root.get(key) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|x| x.as_str().map(str::trim))
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            Some(Value::String(s)) => split_desktop_list(s),
            _ => Vec::new(),
        }
    };

    let mut aliases = existing_opt
        .as_ref()
        .map(|e| e.aliases.clone())
        .unwrap_or_default();
    for a in parse_str_list("aliases") {
        push_unique_ci(&mut aliases, &a);
    }

    let mut keywords = existing_opt
        .as_ref()
        .map(|e| e.keywords.clone())
        .unwrap_or_default();
    for kw in parse_str_list("keywords") {
        push_unique_ci(&mut keywords, &kw);
    }

    let binary_name = root
        .get("binary_name")
        .or_else(|| root.get("binary"))
        .or_else(|| root.get("process_name"))
        .or_else(|| root.get("executable"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| existing_opt.as_ref().and_then(|e| e.binary_name.clone()));

    let profile = CustomSoftwareProfile {
        id: id.clone(),
        name: raw_name.to_string(),
        desktop_id: root
            .get("desktop_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| existing_opt.as_ref().and_then(|e| e.desktop_id.clone())),
        binary_name,
        exec_path: root
            .get("exec_path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| existing_opt.as_ref().and_then(|e| e.exec_path.clone())),
        wm_class: root
            .get("wm_class")
            .or_else(|| root.get("startup_wm_class"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| existing_opt.as_ref().and_then(|e| e.wm_class.clone())),
        aliases,
        keywords,
        category: root
            .get("category")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| existing_opt.as_ref().map(|e| e.category.clone()))
            .unwrap_or_else(default_custom_category),
        actions,
        notes: root
            .get("notes")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| existing_opt.as_ref().map(|e| e.notes.clone()))
            .unwrap_or_default(),
        updated_at: Utc::now().to_rfc3339(),
    };

    if let Some(pos) = store
        .custom_apps
        .iter()
        .position(|c| c.id.eq_ignore_ascii_case(&id))
    {
        store.custom_apps[pos] = profile.clone();
    } else {
        store.custom_apps.push(profile.clone());
    }

    let saved_path = save_custom_apps_store(&core.paths.config_dir, &store)?;
    let adapter_profile = custom_software_to_adapter_profile(&profile);

    Ok(json!({
        "ok": true,
        "saved": true,
        "path": saved_path.to_string_lossy(),
        "custom_app": profile,
        "adapter": adapter_profile,
        "total_custom_apps": store.custom_apps.len(),
    }))
}

/// Delete a `CustomSoftwareProfile` by `id` from `${config_dir}/adapters/custom_apps.json`.
pub fn delete_custom_adapter_by_id(core: &IntentOsCore, payload: &Value) -> anyhow::Result<Value> {
    let target_id = payload
        .get("id")
        .or_else(|| payload.get("app_id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("delete_custom_adapter: 缺少 `id`"))?;

    let mut store = load_custom_apps_store(&core.paths.config_dir);
    let before = store.custom_apps.len();
    store
        .custom_apps
        .retain(|c| !c.id.eq_ignore_ascii_case(target_id));
    let removed = before.saturating_sub(store.custom_apps.len());
    save_custom_apps_store(&core.paths.config_dir, &store)?;

    Ok(json!({
        "ok": true,
        "deleted": removed > 0,
        "id": target_id,
        "remaining_custom_apps": store.custom_apps.len(),
    }))
}

/// Look up a custom action mapping in `custom_apps.json` for `(profile_id, canonical_action, raw_action)`.
pub fn find_custom_action_mapping(
    config_dir: &Path,
    profile_id: &str,
    canonical_action: &str,
    raw_action: &str,
) -> Option<(CustomSoftwareProfile, String, CustomActionMapping)> {
    let store = load_custom_apps_store(config_dir);
    let prof = store
        .custom_apps
        .into_iter()
        .find(|c| c.id.eq_ignore_ascii_case(profile_id))?;

    for (k, mapping) in &prof.actions {
        if k.eq_ignore_ascii_case(canonical_action)
            || k.eq_ignore_ascii_case(raw_action.trim())
            || mapping.aliases.iter().any(|al| {
                al.eq_ignore_ascii_case(canonical_action)
                    || al.eq_ignore_ascii_case(raw_action.trim())
            })
        {
            return Some((prof.clone(), k.clone(), mapping.clone()));
        }
    }
    None
}

fn expand_template_placeholders(template: &str, params: &Value, encode_values: bool) -> String {
    let mut rendered = template.to_string();
    if let Some(obj) = params.as_object() {
        for (k, v) in obj {
            let raw_val = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            let rep = if encode_values {
                urlencoding::encode(&raw_val).into_owned()
            } else {
                raw_val
            };
            rendered = rendered.replace(&format!("{{{}}}", k), &rep);
        }
    }
    rendered
}

/// Execute a user-defined custom software action mapping (`dbus` | `uri` | `argv` | `shortcut` | `quit`).
#[allow(clippy::type_complexity)]
pub async fn execute_custom_action_mapping(
    core: &IntentOsCore,
    adapter_profile: &AppAdapterProfile,
    custom: &CustomSoftwareProfile,
    action_key: &str,
    mapping: &CustomActionMapping,
    params: &Value,
    approved: bool,
) -> anyhow::Result<(
    bool,
    bool,
    Option<gui_bridge::GuiApprovalScope>,
    AdaptationChannel,
    String,
    String,
    Value,
    bool,
    VerificationReport,
)> {
    let ch_norm = mapping.channel.trim().to_ascii_lowercase();

    // 1. `"quit"` -> real multi-stage verified close
    if matches!(ch_norm.as_str(), "quit" | "close" | "process_lifecycle") {
        let target = if !mapping.command_or_target.trim().is_empty() {
            mapping.command_or_target.trim()
        } else {
            custom
                .binary_name
                .as_deref()
                .unwrap_or(custom.name.as_str())
        };
        let res = close_application_verified(core, target, approved).await?;
        let ok = res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        let req_app = res
            .get("requires_approval")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let summary = res
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("已完成应用关闭流程")
            .to_string();
        let quit_scope = if req_app {
            Some(gui_bridge::GuiApprovalScope {
                scope_id: format!("app_adapter.quit.{}", custom.id),
                app_id: custom.id.clone(),
                app_name: custom.name.clone(),
                action: "quit".into(),
                target_detail: target.to_string(),
                risk_badge: "sensitive_approval".into(),
                description: summary.clone(),
            })
        } else {
            None
        };
        let ver = res
            .get("verification")
            .and_then(|v| serde_json::from_value::<VerificationReport>(v.clone()).ok())
            .unwrap_or(VerificationReport {
                state: if ok {
                    VerificationState::Passed
                } else {
                    VerificationState::VerificationFailed
                },
                method: "close_application_verified".into(),
                checks: vec!["procfs_verified".into()],
                details: None,
            });
        return Ok((
            ok,
            req_app,
            quit_scope,
            AdaptationChannel::ProcessLifecycle,
            format!("close_application_verified({})", target),
            summary,
            res,
            false,
            ver,
        ));
    }

    // 2. Approval gate if `mapping.requires_approval` (or `"shortcut"` channel)
    let needs_approval =
        mapping.requires_approval || matches!(ch_norm.as_str(), "shortcut" | "gui_atspi");
    if needs_approval && !approved {
        let ch_enum = map_custom_channel_name(&ch_norm);
        let desc = format!(
            "执行用户自定义软件转译动作「{} · {}」需要显式授权确认",
            custom.name, action_key
        );
        let scope = gui_bridge::GuiApprovalScope {
            scope_id: format!("app_adapter.custom.{}.{}", custom.id, action_key),
            app_id: custom.id.clone(),
            app_name: custom.name.clone(),
            action: action_key.to_string(),
            target_detail: mapping.command_or_target.clone(),
            risk_badge: "sensitive_approval".into(),
            description: desc.clone(),
        };
        return Ok((
            false,
            true,
            Some(scope),
            ch_enum,
            mapping.command_or_target.clone(),
            desc,
            json!({ "custom_app_id": custom.id, "action": action_key }),
            false,
            VerificationReport {
                state: VerificationState::Skipped,
                method: "custom_adapter_approval_gate".into(),
                checks: vec!["requires_explicit_approval".into()],
                details: None,
            },
        ));
    }

    match ch_norm.as_str() {
        "tray" | "dbusmenu" | "sni" | "sni_dbusmenu" => {
            let rendered_label =
                expand_template_placeholders(&mapping.command_or_target, params, false);
            let label = if rendered_label.trim().is_empty() {
                action_key
            } else {
                rendered_label.trim()
            };
            if let Some(tray_res) = sni_dbusmenu::invoke_tray_menu_action(&custom.name, label).await? {
                let summary = tray_res
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("已执行系统托盘菜单动作")
                    .to_string();
                let cmd = tray_res
                    .get("translated_command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("sni_dbusmenu.Event")
                    .to_string();
                let ver = tray_res
                    .get("verification")
                    .and_then(|v| serde_json::from_value::<VerificationReport>(v.clone()).ok())
                    .unwrap_or(VerificationReport {
                        state: VerificationState::Passed,
                        method: "sni_dbusmenu_event_readback".into(),
                        checks: vec!["dbusmenu_event_exit_0".into()],
                        details: None,
                    });
                return Ok((
                    true,
                    false,
                    None,
                    AdaptationChannel::SniDbusMenu,
                    cmd,
                    summary,
                    tray_res,
                    false,
                    ver,
                ));
            }
            Ok((
                false,
                false,
                None,
                AdaptationChannel::SniDbusMenu,
                format!("sni_dbusmenu({} -> {})", custom.name, label),
                format!("当前未在系统托盘检测到「{}」或对应菜单项 `{}`", custom.name, label),
                json!({ "app": custom.name, "menu_label": label }),
                false,
                VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "sni_dbusmenu_lookup".into(),
                    checks: vec![],
                    details: Some("tray service or menu item not found".into()),
                },
            ))
        }
        "uri" | "uri_scheme" => {
            let rendered_uri =
                expand_template_placeholders(&mapping.command_or_target, params, true);
            let mut extra_schemes = adapter_profile.uri_schemes.clone();
            if let Some((scheme, _)) = rendered_uri.split_once("://") {
                push_unique_ci(&mut extra_schemes, scheme);
            }
            let safe_uri = validate_uri_safety(&rendered_uri, &extra_schemes)?;
            let force_dry_run = params
                .get("dry_run")
                .or_else(|| params.get("simulate"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut simulated = true;
            if !force_dry_run
                && mpris_dbus::has_gui_session()
                && let Some(gio) = resolve_trusted_executable("gio")
            {
                let mut cmd = std::process::Command::new(gio);
                sni_dbusmenu::apply_clean_desktop_env_std(&mut cmd);
                if cmd
                    .args(["open", &safe_uri])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .is_ok()
                {
                    simulated = false;
                }
            }
            Ok((
                true,
                false,
                None,
                AdaptationChannel::UriScheme,
                format!("gio open {}", safe_uri),
                format!("已通过自定义 URI 协议唤起「{}」(`{}`)", custom.name, safe_uri),
                json!({ "uri": safe_uri, "simulated": simulated }),
                simulated,
                VerificationReport {
                    state: VerificationState::Passed,
                    method: "custom_uri_deeplink".into(),
                    checks: vec!["uri_scheme_validated".into()],
                    details: None,
                },
            ))
        }
        "shortcut" | "gui_atspi" => {
            let mut merged_params = params.clone();
            if let Some(obj) = merged_params.as_object_mut() {
                obj.entry("shortcut".to_string())
                    .or_insert_with(|| json!(mapping.command_or_target));
            }
            let gui_res = gui_bridge::execute_gui_bridge_action(
                adapter_profile,
                "trigger_shortcut",
                &merged_params,
                approved,
            )
            .await?;
            Ok((
                gui_res.ok,
                gui_res.requires_approval,
                gui_res.approval_scope,
                AdaptationChannel::GuiAtspi,
                gui_res.translated_command,
                gui_res.summary,
                gui_res.data,
                gui_res.simulated,
                gui_res.verification,
            ))
        }
        "mpris" | "dbus_mpris" => {
            let mut mpris_prof = adapter_profile.clone();
            let rendered_bus =
                expand_template_placeholders(&mapping.command_or_target, params, false);
            if !rendered_bus.trim().is_empty() {
                push_unique_ci(&mut mpris_prof.mpris_bus_hints, rendered_bus.trim());
            }
            let res = mpris_dbus::execute_mpris_action(
                &mpris_prof,
                action_key,
                params,
                core.app_config.allow_simulated_hardware_fallback,
            )
            .await?;
            Ok((
                res.ok,
                false,
                None,
                res.channel_used,
                res.translated_command,
                res.summary,
                res.data,
                res.simulated,
                res.verification,
            ))
        }
        "dbus" | "dbus_freedesktop" => {
            let rendered = expand_template_placeholders(&mapping.command_or_target, params, false);
            let tokens = unquote_exec_tokens(&rendered);
            let mut simulated = true;
            if mpris_dbus::has_dbus_session_address()
                && let Some(gdbus) = resolve_trusted_executable("gdbus")
                && !tokens.is_empty()
            {
                let args: Vec<&str> = if tokens[0] == "gdbus" {
                    tokens[1..].iter().map(String::as_str).collect()
                } else {
                    tokens.iter().map(String::as_str).collect()
                };
                let mut cmd = tokio::process::Command::new(gdbus);
                sni_dbusmenu::apply_clean_desktop_env(&mut cmd);
                cmd.kill_on_drop(true).args(&args);
                if let Ok(Ok(out)) =
                    tokio::time::timeout(Duration::from_millis(2200), cmd.output()).await
                    && out.status.success()
                {
                    simulated = false;
                }
            }
            Ok((
                true,
                false,
                None,
                AdaptationChannel::DbusFreedesktop,
                rendered.clone(),
                format!("已执行「{}」自定义 D-Bus 转译动作 `{}`", custom.name, action_key),
                json!({ "dbus_target": rendered, "simulated": simulated }),
                simulated,
                VerificationReport {
                    state: if simulated {
                        VerificationState::RequestedUnverified
                    } else {
                        VerificationState::Passed
                    },
                    method: "custom_dbus_call".into(),
                    checks: vec!["non_shell_argv".into()],
                    details: None,
                },
            ))
        }
        _ => {
            // `"argv"` safe non-shell command execution
            let rendered = expand_template_placeholders(&mapping.command_or_target, params, false);
            let tokens = unquote_exec_tokens(&rendered);
            if tokens.is_empty() {
                anyhow::bail!("自定义 argv 转译动作缺少可执行程序参数");
            }
            let prog = &tokens[0];
            let prog_base = Path::new(prog)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(prog)
                .to_ascii_lowercase();
            if matches!(
                prog_base.as_str(),
                "sh" | "bash" | "dash" | "zsh" | "sudo" | "su" | "pkexec" | "rm" | "dd" | "mkfs"
            ) {
                anyhow::bail!("安全拦截：禁止在自定义软件转译中调用高危或 Shell 程序 `{}`", prog_base);
            }
            for arg in &tokens[1..] {
                if arg.starts_with('/') && core.fs_engine.is_forbidden(Path::new(arg)) {
                    anyhow::bail!("安全拦截：参数包含受保护路径 `{}`", arg);
                }
            }

            let mut simulated = true;
            if mpris_dbus::has_gui_session() {
                let resolved = if Path::new(prog).is_absolute() && Path::new(prog).is_file() {
                    Some(PathBuf::from(prog))
                } else {
                    resolve_trusted_executable(prog)
                };
                if let Some(bin) = resolved {
                    let mut cmd = std::process::Command::new(bin);
                    sni_dbusmenu::apply_clean_desktop_env_std(&mut cmd);
                    if cmd.args(&tokens[1..]).spawn().is_ok() {
                        simulated = false;
                    }
                }
            }

            Ok((
                true,
                false,
                None,
                AdaptationChannel::CliWrapper,
                tokens.join(" "),
                format!("已执行「{}」自定义参数转译动作 `{}`", custom.name, action_key),
                json!({ "argv": tokens, "simulated": simulated }),
                simulated,
                VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "custom_argv_spawn".into(),
                    checks: vec!["non_shell_argv".into(), "denylist_checked".into()],
                    details: None,
                },
            ))
        }
    }
}

/// Strip generic category words (`"音乐"`, `"播放器"`, `"客户端"`, etc.) for smart fuzzy app matching.
pub fn normalize_app_search_tokens(raw_query: &str) -> Vec<String> {
    let trimmed = raw_query.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut variants = Vec::new();
    let lower_full = trimmed.to_ascii_lowercase();
    push_unique_ci(&mut variants, &lower_full);

    let mut stripped = lower_full.clone();
    for word in GENERIC_APP_WORDS {
        if stripped.len() > word.len() {
            stripped = stripped.replace(word, " ");
        }
    }
    let compact = stripped
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("")
        .trim_matches(['-', '_', '.', '「', '」', '"', '\''])
        .to_string();
    if !compact.is_empty() {
        push_unique_ci(&mut variants, &compact);
    }

    for source in [trimmed, compact.as_str()] {
        if !source.is_ascii() {
            let (py_full, py_init) = to_pinyin_pair(source);
            if !py_full.is_empty() {
                push_unique_ci(&mut variants, &py_full);
            }
            if py_init.len() >= 2 {
                push_unique_ci(&mut variants, &py_init);
            }
        }
    }

    variants
}

#[derive(Debug, Clone)]
struct ResolvedCloseTarget {
    display_name: String,
    binary_names: Vec<String>,
    exec_path_segments: Vec<String>,
    wm_classes: Vec<String>,
    mpris_buses: Vec<String>,
}

fn score_desktop_software_match(sw: &DiscoveredDesktopSoftware, tokens: &[String]) -> f64 {
    let mut best = 0.0_f64;
    for (idx, tok) in tokens.iter().enumerate() {
        let tl = tok.to_ascii_lowercase();
        if tl.is_empty() {
            continue;
        }
        let mut token_best = 0.0_f64;
        if sw.id.eq_ignore_ascii_case(&tl)
            || sw.name.eq_ignore_ascii_case(&tl)
            || sw.name_zh.as_deref().is_some_and(|z| z.eq_ignore_ascii_case(&tl))
            || sw.binary_name.as_deref().is_some_and(|b| b.eq_ignore_ascii_case(&tl))
            || sw
                .startup_wm_class
                .as_deref()
                .is_some_and(|w| w.eq_ignore_ascii_case(&tl))
        {
            token_best = token_best.max(100.0);
        }
        if sw.keywords.iter().any(|k| k.eq_ignore_ascii_case(&tl)) {
            token_best = token_best.max(96.0);
        }
        // Bidirectional keyword <-> Pinyin matching (`Keywords=轻笺;` matched by `qingjian`/`qj`, and `Keywords=qishui;` matched by `汽水`->`qishui`)
        if sw.keywords.iter().any(|k| {
            if k.is_ascii() {
                false
            } else {
                let (kp_full, kp_init) = to_pinyin_pair(k);
                (!kp_full.is_empty() && kp_full == tl) || (kp_init.len() >= 2 && kp_init == tl)
            }
        }) {
            token_best = token_best.max(94.0);
        }
        let (py_full, py_init) = to_pinyin_pair(sw.name_zh.as_deref().unwrap_or(&sw.name));
        if (!py_full.is_empty() && py_full == tl) || (py_init.len() >= 2 && py_init == tl) {
            token_best = token_best.max(92.0);
        }
        if tl.len() >= 3
            && (sw.name.to_ascii_lowercase().contains(&tl)
                || sw
                    .keywords
                    .iter()
                    .any(|k| k.to_ascii_lowercase().contains(&tl)))
        {
            token_best = token_best.max(78.0);
        }
        // Derived/stripped tokens (`idx > 0`) are discounted so `"QQ音乐"` prefers `qqmusic` over stripped `"qq"`.
        if idx > 0 && token_best > 0.0 {
            token_best = (token_best - 12.0).clamp(0.0, 88.0);
        }
        best = best.max(token_best);
    }
    best
}

async fn resolve_close_target(core: &IntentOsCore, app_query: &str) -> anyhow::Result<ResolvedCloseTarget> {
    let tokens = normalize_app_search_tokens(app_query);
    if tokens.is_empty() {
        anyhow::bail!("请指定要关闭的应用名称");
    }

    // Refuse if user directly names a protected system/IntentOS daemon
    for tok in &tokens {
        if PROTECTED_PROCESS_NAMES.contains(&tok.to_ascii_lowercase().as_str()) {
            anyhow::bail!("安全保护：拒绝关闭系统核心或桌面会话守护进程 `{}`", app_query);
        }
    }

    let mut display_name: Option<String> = None;
    let mut binary_names: Vec<String> = Vec::new();
    let mut exec_path_segments: Vec<String> = Vec::new();
    let mut wm_classes: Vec<String> = Vec::new();
    let mut mpris_hints: Vec<String> = Vec::new();

    let push_bin = |bins: &mut Vec<String>, candidate: &str| {
        let cl = candidate.trim().to_ascii_lowercase();
        if !cl.is_empty()
            && !PROTECTED_PROCESS_NAMES.contains(&cl.as_str())
            && !bins.iter().any(|x| x == &cl)
        {
            bins.push(cl);
        }
    };

    // 1. Match against `custom_apps.json`
    let custom_store = load_custom_apps_store(&core.paths.config_dir);
    for c in &custom_store.custom_apps {
        let prof = custom_software_to_adapter_profile(c);
        let matched = tokens.iter().any(|t| {
            prof.id.eq_ignore_ascii_case(t)
                || prof.name.eq_ignore_ascii_case(t)
                || prof.aliases.iter().any(|a| a.eq_ignore_ascii_case(t))
        });
        if matched {
            display_name = Some(c.name.clone());
            if let Some(ref b) = c.binary_name {
                push_bin(&mut binary_names, b);
            }
            if let Some(ref w) = c.wm_class {
                push_unique_ci(&mut wm_classes, w);
            }
            if let Some(ref ep) = c.exec_path
                && let (_, Some(b)) = extract_exec_binary(ep)
            {
                push_bin(&mut binary_names, &b);
            }
        }
    }

    // 2. Match against `.desktop` manifests (`sodam.desktop`, `Keywords=music;qishui;soda;sodam;`, etc.)
    let desktop_apps = discover_installed_desktop_apps(Some(&core.paths.config_dir));
    let mut best_sw: Option<(&DiscoveredDesktopSoftware, f64)> = None;
    for sw in &desktop_apps {
        let sc = score_desktop_software_match(sw, &tokens);
        if sc > 0.0 {
            match best_sw {
                None => best_sw = Some((sw, sc)),
                Some((_, prev)) if sc > prev => best_sw = Some((sw, sc)),
                _ => {}
            }
        }
    }
    if let Some((sw, _)) = best_sw {
        if display_name.is_none() {
            display_name = Some(sw.name_zh.clone().unwrap_or_else(|| sw.name.clone()));
        }
        if let Some(ref b) = sw.binary_name {
            push_bin(&mut binary_names, b);
            exec_path_segments.push(format!("/{}/", b.to_ascii_lowercase()));
        }
        if let Some(ref ep) = sw.exec_path {
            let ep_lc = ep.to_ascii_lowercase();
            if ep_lc.starts_with("/opt/")
                && let Some(seg) = ep_lc.strip_prefix("/opt/").and_then(|r| r.split('/').next())
                && !seg.is_empty()
            {
                exec_path_segments.push(format!("/opt/{}/", seg));
            }
        }
        if let Some(ref wmc) = sw.startup_wm_class {
            push_unique_ci(&mut wm_classes, wmc);
        }
        push_unique_ci(&mut mpris_hints, &sw.id);
    }

    // 3. Match against merged `AdapterRegistry` (24 built-ins + user manifests)
    let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
    for tok in &tokens {
        let filtered = reg.list_filtered(Some(tok), None, None);
        if let Some(top) = filtered.first()
            && top.source != "dynamic_gui_fallback"
        {
            // Verify it's a genuine name/alias match rather than just category substring
            let is_strong = top.id.eq_ignore_ascii_case(tok)
                || top.name.eq_ignore_ascii_case(tok)
                || top.aliases.iter().any(|a| a.eq_ignore_ascii_case(tok))
                || {
                    let (pf, pi) = to_pinyin_pair(&top.name);
                    pf == *tok || (pi.len() >= 2 && pi == *tok)
                };
            if is_strong {
                if display_name.is_none() {
                    display_name = Some(top.name.clone());
                }
                for exe in &top.cli_executables {
                    if let (_, Some(b)) = extract_exec_binary(exe) {
                        push_bin(&mut binary_names, &b);
                    }
                }
                push_bin(&mut binary_names, &top.id);
                for mh in &top.mpris_bus_hints {
                    push_unique_ci(&mut mpris_hints, mh);
                }
                for d_id in &top.desktop_ids {
                    let stem = d_id.trim_end_matches(".desktop");
                    if !stem.contains('.') {
                        push_bin(&mut binary_names, stem);
                    }
                }
                break;
            }
        }
    }

    // 4. Fallback for ad-hoc / custom non-desktop binaries (e.g., spawned child processes in tests)
    for tok in &tokens {
        if tok
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            push_bin(&mut binary_names, tok);
            if tok.len() >= 4 {
                exec_path_segments.push(format!("/{}/", tok.to_ascii_lowercase()));
            }
            push_unique_ci(&mut mpris_hints, tok);
        }
    }

    // 5. Discover live matching `org.mpris.MediaPlayer2.*` services
    let mut mpris_buses = Vec::new();
    let mpris_report = mpris_dbus::discover_active_mpris_services().await;
    for svc in &mpris_report.services {
        let suffix = svc
            .strip_prefix("org.mpris.MediaPlayer2.")
            .unwrap_or(svc)
            .to_ascii_lowercase();
        let matched_bus = mpris_hints
            .iter()
            .chain(binary_names.iter())
            .any(|h| {
                let hl = h.to_ascii_lowercase();
                !hl.is_empty() && (suffix == hl || suffix.starts_with(&format!("{}.", hl)) || suffix.contains(&hl))
            });
        if matched_bus {
            push_unique_ci(&mut mpris_buses, svc);
        }
    }

    let final_display_name = display_name.unwrap_or_else(|| app_query.trim().to_string());
    push_unique_ci(&mut wm_classes, &final_display_name);

    Ok(ResolvedCloseTarget {
        display_name: final_display_name,
        binary_names,
        exec_path_segments,
        wm_classes,
        mpris_buses,
    })
}

#[derive(Debug, Clone)]
struct ProcStatusSummary {
    state_char: char,
    ppid: u32,
    sig_ign_mask: u64,
}

fn read_proc_status_summary(pid: u32) -> Option<ProcStatusSummary> {
    let raw = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let mut state_char = '?';
    let mut ppid = 0_u32;
    let mut sig_ign_mask = 0_u64;

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            if let Some(ch) = rest.trim().chars().next() {
                state_char = ch;
            }
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse::<u32>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("SigIgn:") {
            sig_ign_mask = u64::from_str_radix(rest.trim(), 16).unwrap_or(0);
        }
    }

    Some(ProcStatusSummary {
        state_char,
        ppid,
        sig_ign_mask,
    })
}

fn is_pid_alive_non_zombie(pid: u32) -> bool {
    let Some(st) = read_proc_status_summary(pid) else {
        return false;
    };
    !matches!(st.state_char, 'Z' | 'X' | 'x')
}

fn enumerate_matching_owned_pids(target: &ResolvedCloseTarget) -> anyhow::Result<(Vec<u32>, u32)> {
    #[cfg(unix)]
    let my_uid = std::os::unix::fs::MetadataExt::uid(&fs::metadata("/proc/self")?);
    #[cfg(not(unix))]
    let my_uid = 0_u32;

    let self_pid = std::process::id();
    let parent_pid = read_proc_status_summary(self_pid)
        .map(|s| s.ppid)
        .unwrap_or(0);

    if target.binary_names.is_empty() && target.exec_path_segments.is_empty() {
        return Ok((Vec::new(), my_uid));
    }

    let mut matched_pids = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Ok((Vec::new(), my_uid));
    };

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(pid_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid <= 1 || pid == self_pid || (parent_pid > 1 && pid == parent_pid) {
            continue;
        }

        let proc_dir = entry.path();
        #[cfg(unix)]
        {
            let Ok(meta) = fs::metadata(&proc_dir) else {
                continue;
            };
            if std::os::unix::fs::MetadataExt::uid(&meta) != my_uid {
                continue;
            }
        }

        let Some(status) = read_proc_status_summary(pid) else {
            continue;
        };
        // Ignore zombie / dead processes (`State:\tZ`)
        if matches!(status.state_char, 'Z' | 'X' | 'x') {
            continue;
        }

        let comm = fs::read_to_string(proc_dir.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let exe_path = fs::read_link(proc_dir.join("exe"))
            .ok()
            .map(|p| p.to_string_lossy().to_string());
        let exe_base = exe_path
            .as_deref()
            .and_then(|s| {
                Path::new(s.trim_end_matches(" (deleted)"))
                    .file_name()
                    .and_then(|f| f.to_str())
            })
            .unwrap_or("")
            .to_ascii_lowercase();

        let cmdline_bytes = fs::read(proc_dir.join("cmdline")).unwrap_or_default();
        let argv: Vec<String> = cmdline_bytes
            .split(|b| *b == 0)
            .filter(|slice| !slice.is_empty())
            .map(|slice| String::from_utf8_lossy(slice).to_string())
            .collect();

        let argv0 = argv.first().map(String::as_str).unwrap_or("");
        let argv0_base = Path::new(argv0.split_whitespace().next().unwrap_or(argv0))
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Check if `argv` is an interpreter (`sh`/`python3`/`node`/`electron`) executing a script path
        let script_arg_base = if matches!(
            argv0_base.as_str(),
            "sh" | "bash" | "dash" | "python" | "python3" | "node" | "electron"
        ) {
            argv.iter()
                .skip(1)
                .find(|a| !a.starts_with('-'))
                .and_then(|a| Path::new(a).file_name().and_then(|s| s.to_str()))
                .unwrap_or("")
                .to_ascii_lowercase()
        } else {
            String::new()
        };

        // Never touch protected desktop/system daemons or interactive shells!
        if PROTECTED_PROCESS_NAMES.contains(&comm.as_str())
            && (script_arg_base.is_empty()
                || PROTECTED_PROCESS_NAMES.contains(&script_arg_base.as_str()))
        {
            continue;
        }
        if PROTECTED_PROCESS_NAMES.contains(&exe_base.as_str())
            && !target.binary_names.iter().any(|b| b == &comm || b == &script_arg_base)
        {
            continue;
        }

        let cmdline_joined_lc = argv.join(" ").to_ascii_lowercase();

        let mut is_match = false;
        for bin in &target.binary_names {
            if comm == *bin
                || exe_base == *bin
                || argv0_base == *bin
                || (!script_arg_base.is_empty() && script_arg_base == *bin)
            {
                is_match = true;
                break;
            }
            // Handle Linux 15-byte `TASK_COMM_LEN - 1` truncation on `/proc/<pid>/comm`
            if bin.len() > 15 && comm.len() == 15 && bin.starts_with(&comm) && cmdline_joined_lc.contains(bin) {
                is_match = true;
                break;
            }
        }

        if !is_match && !target.exec_path_segments.is_empty() {
            for seg in &target.exec_path_segments {
                if cmdline_joined_lc.contains(seg)
                    || exe_path
                        .as_deref()
                        .is_some_and(|ep| ep.to_ascii_lowercase().contains(seg))
                {
                    is_match = true;
                    break;
                }
            }
        }

        if is_match {
            matched_pids.push(pid);
        }
    }

    matched_pids.sort_unstable();
    matched_pids.dedup();
    Ok((matched_pids, my_uid))
}

fn collect_direct_helper_children(parent_pids: &[u32], my_uid: u32, include_even_if_sigign: bool) -> Vec<u32> {
    let mut allowed_parents = HashSet::new();
    for &pp in parent_pids {
        if let Some(st) = read_proc_status_summary(pp) {
            // SIGTERM is signal 15 -> bit 14 (`0x4000`) in `/proc/<pid>/status` `SigIgn`
            let ignores_sigterm = (st.sig_ign_mask & (1_u64 << 14)) != 0;
            if include_even_if_sigign || !ignores_sigterm {
                allowed_parents.insert(pp);
            }
        }
    }
    if allowed_parents.is_empty() {
        return Vec::new();
    }

    let mut children = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return children;
    };
    for entry in entries.flatten() {
        let Some(pid_str) = entry.file_name().to_str().map(String::from) else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if parent_pids.contains(&pid) {
            continue;
        }
        #[cfg(unix)]
        {
            let Ok(meta) = fs::metadata(entry.path()) else {
                continue;
            };
            if std::os::unix::fs::MetadataExt::uid(&meta) != my_uid {
                continue;
            }
        }
        let Some(st) = read_proc_status_summary(pid) else {
            continue;
        };
        if matches!(st.state_char, 'Z' | 'X' | 'x') || !allowed_parents.contains(&st.ppid) {
            continue;
        }
        let comm = fs::read_to_string(entry.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if !PROTECTED_PROCESS_NAMES.contains(&comm.as_str()) {
            children.push(pid);
        }
    }
    children
}

/// Synchronously check `/proc` (UID-scoped, excluding zombies and protected daemons) for any running
/// processes belonging to `profile` or `app_hint`.
pub fn find_running_pids_for_profile_or_hint(
    profile: Option<&AppAdapterProfile>,
    app_hint: &str,
    config_dir: Option<&Path>,
) -> Vec<u32> {
    let mut binary_names: Vec<String> = Vec::new();
    let mut exec_path_segments: Vec<String> = Vec::new();

    let push_bin = |bins: &mut Vec<String>, candidate: &str| {
        let cl = candidate.trim().to_ascii_lowercase();
        if !cl.is_empty()
            && cl != "generic-gui-window"
            && !PROTECTED_PROCESS_NAMES.contains(&cl.as_str())
            && !bins.iter().any(|x| x == &cl)
        {
            bins.push(cl);
        }
    };

    if let Some(prof) = profile
        && prof.id != "generic-gui-window"
        && prof.source != "dynamic_gui_fallback"
    {
        push_bin(&mut binary_names, &prof.id);
        for exe in &prof.cli_executables {
            if let (_, Some(b)) = extract_exec_binary(exe) {
                push_bin(&mut binary_names, &b);
            }
        }
        for d_id in &prof.desktop_ids {
            let stem = d_id.trim_end_matches(".desktop");
            if !stem.contains('.') {
                push_bin(&mut binary_names, stem);
            }
        }
        for extra in builtin_domestic_app_aliases(&prof.id, None) {
            if extra.is_ascii() {
                push_bin(&mut binary_names, extra);
            }
        }
    }

    let tokens = normalize_app_search_tokens(app_hint);
    for tok in &tokens {
        for extra in builtin_domestic_app_aliases(tok, None) {
            if extra.is_ascii() {
                push_bin(&mut binary_names, extra);
            }
        }
        if tok
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            && tok.len() >= 2
        {
            push_bin(&mut binary_names, tok);
        }
    }

    let desktop_apps = discover_installed_desktop_apps(config_dir);
    let mut best_sw: Option<(&DiscoveredDesktopSoftware, f64)> = None;
    for sw in &desktop_apps {
        let sc = score_desktop_software_match(sw, &tokens);
        if sc > 0.0 {
            match best_sw {
                None => best_sw = Some((sw, sc)),
                Some((_, prev)) if sc > prev => best_sw = Some((sw, sc)),
                _ => {}
            }
        }
    }
    if let Some((sw, _)) = best_sw {
        if let Some(ref b) = sw.binary_name {
            push_bin(&mut binary_names, b);
            exec_path_segments.push(format!("/{}/", b.to_ascii_lowercase()));
        }
        if let Some(ref ep) = sw.exec_path {
            let ep_lc = ep.to_ascii_lowercase();
            if ep_lc.starts_with("/opt/")
                && let Some(seg) = ep_lc.strip_prefix("/opt/").and_then(|r| r.split('/').next())
                && !seg.is_empty()
            {
                exec_path_segments.push(format!("/opt/{}/", seg));
            }
        }
    }

    let target = ResolvedCloseTarget {
        display_name: app_hint.trim().to_string(),
        binary_names,
        exec_path_segments,
        wm_classes: Vec::new(),
        mpris_buses: Vec::new(),
    };
    enumerate_matching_owned_pids(&target)
        .map(|(pids, _)| pids)
        .unwrap_or_default()
}

/// Real Multi-Stage Verified App Close (`close_application_verified`):
/// 0. `sni_dbusmenu` native `'退出'` / `'Quit'` menu item click for tray-resident apps (with `/proc` readback)
/// 1. Smart alias/keyword/Pinyin resolution (`sodam.desktop` `Keywords=music;qishui;soda;sodam;`, etc.)
/// 2. UID-scoped `/proc` enumeration with protected system/IntentOS process guards & zombie filtering
/// 3. Honest `already_closed: true` reporting when not running
/// 4. MPRIS2 Stop/Quit -> `wmctrl` close -> `200ms` wait -> graceful `/bin/kill -s TERM` ->
///    `900ms` `/proc/<pid>/status` exit readback verification -> approval-gated `SIGKILL` fallback.
pub async fn close_application_verified(
    core: &IntentOsCore,
    app_query: &str,
    force_kill_approved: bool,
) -> anyhow::Result<Value> {
    let target = resolve_close_target(core, app_query).await?;
    let (initial_pids, my_uid) = enumerate_matching_owned_pids(&target)?;

    // Step 3: Honest Not-Running Check
    if initial_pids.is_empty() && target.mpris_buses.is_empty() {
        return Ok(json!({
            "ok": true,
            "already_closed": true,
            "app_name": target.display_name,
            "closed_pids": [],
            "summary": format!("未检测到正在运行的「{}」进程（当前已关闭）", target.display_name),
            "verification": {
                "state": "passed",
                "method": "procfs_uid_scan",
                "checks": ["no_running_pid"]
            }
        }));
    }

    let mut stages_used: Vec<String> = Vec::new();

    // Step 0: Native `StatusNotifierItem` + `com.canonical.dbusmenu` `'退出'` menu item click!
    // Scoped strictly to `initial_pids` or exact `target.binary_names` so isolated tests never touch real tray apps.
    if let Some(_tray_quit_info) =
        sni_dbusmenu::invoke_tray_quit_for_pids_or_bins(&initial_pids, &target.binary_names).await
    {
        stages_used.push("sni_dbusmenu_quit".to_string());
        for _ in 0..7 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if !initial_pids.is_empty() && initial_pids.iter().all(|&pid| !is_pid_alive_non_zombie(pid))
            {
                return Ok(json!({
                    "ok": true,
                    "already_closed": false,
                    "requires_approval": false,
                    "app_name": target.display_name,
                    "closed_pids": initial_pids,
                    "stages_used": stages_used,
                    "summary": format!("✓ 已通过系统托盘菜单原生退出并确认关闭「{}」（已验证进程 {:?} 退出）", target.display_name, initial_pids),
                    "verification": {
                        "state": "passed",
                        "method": "sni_dbusmenu_quit_procfs_readback",
                        "checks": ["uid_verified", "sni_dbusmenu_quit", "procfs_exited"]
                    }
                }));
            }
        }
    }

    // Step 4a: MPRIS2 Stop + Quit via `gdbus`
    if !target.mpris_buses.is_empty()
        && mpris_dbus::has_dbus_session_address()
        && let Some(gdbus) = resolve_trusted_executable("gdbus")
    {
        for bus in &target.mpris_buses {
            for method in [
                "org.mpris.MediaPlayer2.Player.Stop",
                "org.mpris.MediaPlayer2.Quit",
            ] {
                let mut cmd = tokio::process::Command::new(&gdbus);
                sni_dbusmenu::apply_clean_desktop_env(&mut cmd);
                cmd.kill_on_drop(true)
                    .args([
                        "call",
                        "--session",
                        "--timeout",
                        "1",
                        "--dest",
                        bus,
                        "--object-path",
                        "/org/mpris/MediaPlayer2",
                        "--method",
                        method,
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                let _ = tokio::time::timeout(Duration::from_millis(600), cmd.status()).await;
            }
        }
        stages_used.push("mpris2_quit".to_string());
    }

    // Step 4b: Window close via `wmctrl` if GUI session is active
    if mpris_dbus::has_gui_session()
        && let Some(wmctrl) = resolve_trusted_executable("wmctrl")
    {
        for wmc in &target.wm_classes {
            let mut cmd = tokio::process::Command::new(&wmctrl);
            sni_dbusmenu::apply_clean_desktop_env(&mut cmd);
            cmd.kill_on_drop(true)
                .args(["-x", "-c", wmc])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = tokio::time::timeout(Duration::from_millis(500), cmd.status()).await;
        }
        let mut cmd = tokio::process::Command::new(&wmctrl);
        sni_dbusmenu::apply_clean_desktop_env(&mut cmd);
        cmd.kill_on_drop(true)
            .args(["-c", &target.display_name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _ = tokio::time::timeout(Duration::from_millis(500), cmd.status()).await;
        stages_used.push("wmctrl_close".to_string());
    }

    // Step 4c: Tray-Aware Graceful `SIGTERM` (`SodaM` / `QQ` / Electron tray apps hide window on `wmctrl -c`)
    tokio::time::sleep(Duration::from_millis(200)).await;

    let alive_after_gui: Vec<u32> = initial_pids
        .iter()
        .copied()
        .filter(|&pid| is_pid_alive_non_zombie(pid))
        .collect();

    if !alive_after_gui.is_empty() {
        let mut term_pids = alive_after_gui.clone();
        for child_pid in collect_direct_helper_children(&alive_after_gui, my_uid, false) {
            if !term_pids.contains(&child_pid) {
                term_pids.push(child_pid);
            }
        }
        let pid_args: Vec<String> = term_pids.iter().map(u32::to_string).collect();
        let kill_bin = if Path::new("/bin/kill").is_file() {
            PathBuf::from("/bin/kill")
        } else {
            PathBuf::from("/usr/bin/kill")
        };
        let _ = tokio::process::Command::new(kill_bin)
            .arg("-s")
            .arg("TERM")
            .args(&pid_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        stages_used.push("sigterm".to_string());
    }

    // Step 4d: Post-Check Readback Verification (`100ms` intervals up to `900ms`)
    let mut remaining_pids: Vec<u32> = initial_pids
        .iter()
        .copied()
        .filter(|&pid| is_pid_alive_non_zombie(pid))
        .collect();

    for _ in 0..9 {
        if remaining_pids.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        remaining_pids.retain(|&pid| is_pid_alive_non_zombie(pid));
    }

    if remaining_pids.is_empty() {
        return Ok(json!({
            "ok": true,
            "already_closed": false,
            "requires_approval": false,
            "app_name": target.display_name,
            "closed_pids": initial_pids,
            "stages_used": stages_used,
            "summary": format!("✓ 已确认关闭「{}」（已验证进程 {:?} 退出）", target.display_name, initial_pids),
            "verification": {
                "state": "passed",
                "method": "procfs_post_close_readback",
                "checks": ["uid_verified", "procfs_exited"]
            }
        }));
    }

    // Remaining PIDs ignored `SIGTERM`!
    if force_kill_approved {
        let mut kill_pids = remaining_pids.clone();
        for child_pid in collect_direct_helper_children(&remaining_pids, my_uid, true) {
            if !kill_pids.contains(&child_pid) {
                kill_pids.push(child_pid);
            }
        }
        let pid_args: Vec<String> = kill_pids.iter().map(u32::to_string).collect();
        let kill_bin = if Path::new("/bin/kill").is_file() {
            PathBuf::from("/bin/kill")
        } else {
            PathBuf::from("/usr/bin/kill")
        };
        let _ = tokio::process::Command::new(kill_bin)
            .arg("-s")
            .arg("KILL")
            .args(&pid_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        stages_used.push("sigkill_approved".to_string());

        for _ in 0..6 {
            remaining_pids.retain(|&pid| is_pid_alive_non_zombie(pid));
            if remaining_pids.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if remaining_pids.is_empty() {
            return Ok(json!({
                "ok": true,
                "already_closed": false,
                "requires_approval": false,
                "forced_kill": true,
                "app_name": target.display_name,
                "closed_pids": initial_pids,
                "stages_used": stages_used,
                "summary": format!("✓ 已确认关闭「{}」（已批准强制结束并验证进程 {:?} 退出）", target.display_name, initial_pids),
                "verification": {
                    "state": "passed",
                    "method": "procfs_post_sigkill_readback",
                    "checks": ["uid_verified", "explicit_approval", "procfs_exited"]
                }
            }));
        }

        return Ok(json!({
            "ok": false,
            "requires_approval": false,
            "app_name": target.display_name,
            "alive_pids": remaining_pids,
            "stages_used": stages_used,
            "summary": format!("尝试强制结束「{}」后进程 {:?} 仍处于内核阻塞态", target.display_name, remaining_pids),
            "verification": {
                "state": "verification_failed",
                "method": "procfs_post_sigkill_readback",
                "checks": ["still_alive_after_sigkill"]
            }
        }));
    }

    Ok(json!({
        "ok": false,
        "requires_approval": true,
        "app_name": target.display_name,
        "alive_pids": remaining_pids,
        "surviving_pids": remaining_pids,
        "stages_used": stages_used,
        "summary": format!(
            "应用「{}」(PID {:?}) 未响应常规退出信号，是否批准强制结束该进程？",
            target.display_name, remaining_pids
        ),
        "verification": {
            "state": "verification_failed",
            "method": "procfs_post_close_readback",
            "checks": ["sigterm_unresponsive"]
        }
    }))
}

/// Universal Live App Inspector (`app_adapter_inspect_app` / `inspect_live_app`):
/// Combines `.desktop` metadata, `AdapterRegistry`, live `StatusNotifierItem` + `dbusmenu` tray items,
/// live `MPRIS2` bus state, UID-scoped `/proc` running PIDs, AT-SPI2 accessible UI controls, and user `custom_apps.json` rules.
pub async fn inspect_live_app(core: &IntentOsCore, app_query: &str) -> anyhow::Result<Value> {
    let query = app_query.trim();
    if query.is_empty() {
        anyhow::bail!("app_adapter_inspect_app: 缺少必填参数 `app`");
    }

    let mut tokens = normalize_app_search_tokens(query);
    let snap = tokens.clone();
    for tok in &snap {
        for extra in builtin_domestic_app_aliases(tok, None) {
            push_unique_ci(&mut tokens, extra);
        }
    }

    let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
    let (resolved_prof, _) = reg.resolve_adapter_and_action(query, "focus_window");
    let known_prof_opt = (resolved_prof.source != "dynamic_gui_fallback"
        && resolved_prof.id != "generic-gui-window")
        .then_some(&resolved_prof);

    let desktop_apps = discover_installed_desktop_apps(Some(&core.paths.config_dir));
    let mut best_sw: Option<(&DiscoveredDesktopSoftware, f64)> = None;
    for sw in &desktop_apps {
        let sc = score_desktop_software_match(sw, &tokens);
        if sc > 0.0 {
            match best_sw {
                None => best_sw = Some((sw, sc)),
                Some((_, prev)) if sc > prev => best_sw = Some((sw, sc)),
                _ => {}
            }
        }
    }
    let matched_desktop = best_sw.map(|(sw, _)| sw);

    // Discover live StatusNotifierItem tray services & MPRIS2 services concurrently
    let (tray_apps, mpris_disc) = tokio::join!(
        sni_dbusmenu::discover_live_tray_apps(),
        mpris_dbus::discover_active_mpris_services()
    );
    let matched_tray =
        sni_dbusmenu::match_tray_app_for_hint(&tray_apps, query, Some(&core.paths.config_dir));

    // Match live MPRIS2 bus specifically for this app
    let mut mpris_candidates = tokens.clone();
    if let Some(p) = known_prof_opt {
        push_unique_ci(&mut mpris_candidates, &p.id);
        for mh in &p.mpris_bus_hints {
            push_unique_ci(&mut mpris_candidates, mh);
        }
    }
    if let Some(sw) = matched_desktop
        && let Some(ref b) = sw.binary_name
    {
        push_unique_ci(&mut mpris_candidates, b);
    }

    let matched_mpris_bus = mpris_disc.services.iter().find(|svc| {
        let suffix = svc
            .strip_prefix("org.mpris.MediaPlayer2.")
            .unwrap_or(svc)
            .to_ascii_lowercase();
        mpris_candidates.iter().any(|cand| {
            let cl = cand.to_ascii_lowercase();
            cl.len() >= 2
                && cl != "chromium.instance"
                && (suffix == cl || suffix.starts_with(&format!("{}.", cl)) || suffix.contains(&cl))
        })
    });

    let mut running_pids =
        find_running_pids_for_profile_or_hint(known_prof_opt, query, Some(&core.paths.config_dir));
    if let Some(tray_pid) = matched_tray.and_then(|t| t.pid)
        && !running_pids.contains(&tray_pid)
    {
        running_pids.push(tray_pid);
        running_pids.sort_unstable();
    }

    let is_running =
        !running_pids.is_empty() || matched_tray.is_some() || matched_mpris_bus.is_some();

    let app_id = known_prof_opt
        .map(|p| p.id.clone())
        .or_else(|| matched_desktop.map(|d| d.id.clone()))
        .or_else(|| {
            matched_tray.map(|t| {
                t.comm
                    .clone()
                    .unwrap_or_else(|| sanitize_slug(&t.id))
            })
        })
        .unwrap_or_else(|| sanitize_slug(query));

    let name = matched_desktop
        .and_then(|d| d.name_zh.clone())
        .or_else(|| known_prof_opt.map(|p| p.name.clone()))
        .or_else(|| matched_desktop.map(|d| d.name.clone()))
        .or_else(|| matched_tray.and_then(|t| t.comm.clone()))
        .unwrap_or_else(|| query.to_string());

    let desktop_id = matched_desktop
        .map(|d| d.desktop_id.clone())
        .or_else(|| known_prof_opt.and_then(|p| p.desktop_ids.first().cloned()));

    let exec_cmd = matched_desktop
        .and_then(|d| d.exec_raw.clone().or_else(|| d.exec_path.clone()))
        .or_else(|| known_prof_opt.and_then(|p| p.cli_executables.first().cloned()))
        .or_else(|| matched_tray.and_then(|t| t.cmdline.clone()));

    let desktop_actions = matched_desktop
        .map(|d| d.desktop_actions.clone())
        .unwrap_or_default();

    let custom_store = load_custom_apps_store(&core.paths.config_dir);
    let custom_rules = custom_store
        .custom_apps
        .iter()
        .find(|c| {
            c.id.eq_ignore_ascii_case(&app_id)
                || c.name.eq_ignore_ascii_case(query)
                || c.aliases.iter().any(|a| a.eq_ignore_ascii_case(query))
        })
        .map(|c| json!(c.actions))
        .unwrap_or_else(|| json!({}));

    let atspi_controls = if is_running
        && mpris_dbus::has_gui_session()
        && mpris_dbus::has_dbus_session_address()
    {
        let hint_for_atspi = matched_desktop
            .and_then(|d| d.binary_name.as_deref())
            .unwrap_or(app_id.as_str());
        gui_bridge::probe_atspi_controls_readonly(hint_for_atspi).await
    } else {
        Vec::new()
    };

    let tray_bus_val = matched_tray.map(|t| {
        json!({
            "service": t.service,
            "interface": t.interface,
            "pid": t.pid,
            "comm": t.comm,
            "id": t.id,
            "title": t.title,
            "status": t.status,
            "menu_path": t.menu_path,
            "menu_items": t.menu_items,
        })
    });

    let found = known_prof_opt.is_some()
        || matched_desktop.is_some()
        || matched_tray.is_some()
        || matched_mpris_bus.is_some()
        || !running_pids.is_empty();

    let mut suggested_actions: Vec<String> = Vec::new();
    let push_sug = |vec: &mut Vec<String>, s: String| {
        if !vec.contains(&s) {
            vec.push(s);
        }
    };

    if let Some(tray) = matched_tray {
        for item in &tray.menu_items {
            if item.visible && item.enabled {
                push_sug(
                    &mut suggested_actions,
                    format!("click_tray_menu ({})", item.label),
                );
            }
        }
    }
    if matched_mpris_bus.is_some()
        || known_prof_opt
            .is_some_and(|p| p.channels.contains(&AdaptationChannel::DbusMpris))
    {
        for act in ["get_now_playing", "play_pause", "next", "previous"] {
            push_sug(&mut suggested_actions, act.to_string());
        }
    }
    for da in &desktop_actions {
        push_sug(&mut suggested_actions, da.id.clone());
    }
    if let Some(obj) = custom_rules.as_object() {
        for k in obj.keys() {
            push_sug(&mut suggested_actions, k.clone());
        }
    }
    if is_running {
        push_sug(&mut suggested_actions, "focus_window".to_string());
        push_sug(&mut suggested_actions, "quit".to_string());
    } else if desktop_id.is_some() || exec_cmd.is_some() {
        push_sug(
            &mut suggested_actions,
            "app_launch (当前未运行，需先启动该软件)".to_string(),
        );
    }

    let aliases = known_prof_opt
        .map(|p| p.aliases.clone())
        .unwrap_or_else(|| {
            matched_desktop
                .map(|d| d.keywords.clone())
                .unwrap_or_default()
        });
    let uri_schemes = matched_desktop
        .map(|d| d.uri_schemes.clone())
        .filter(|v| !v.is_empty())
        .or_else(|| known_prof_opt.map(|p| p.uri_schemes.clone()))
        .unwrap_or_default();
    let tray_menu_items = matched_tray
        .map(|t| t.menu_items.clone())
        .unwrap_or_default();
    let mpris_services: Vec<String> = matched_mpris_bus.into_iter().cloned().collect();

    let channel_used = if matched_tray.is_some() {
        "sni_dbusmenu"
    } else if !mpris_services.is_empty() {
        "dbus_mpris"
    } else if !atspi_controls.is_empty() {
        "gui_atspi"
    } else {
        "live_app_inspector"
    };

    let summary = if !found {
        format!(
            "未在本机发现已安装或运行中的「{}」（无匹配 .desktop、运行进程或系统托盘实例）",
            query
        )
    } else if is_running {
        let menu_labels: Vec<&str> = tray_menu_items
            .iter()
            .filter(|m| m.visible && m.enabled && !m.label.trim().is_empty())
            .map(|m| m.label.as_str())
            .take(6)
            .collect();
        let tray_note = if let Some(tray) = matched_tray {
            let title_part = if !tray.title.trim().is_empty()
                && !tray.title.eq_ignore_ascii_case(&name)
            {
                format!("，当前状态：{}", tray.title.trim())
            } else {
                String::new()
            };
            if menu_labels.is_empty() {
                format!("，已注册系统托盘 ({}{})", tray.service, title_part)
            } else {
                format!(
                    "，系统托盘菜单项：[{}]{}",
                    menu_labels.join(" / "),
                    title_part
                )
            }
        } else {
            String::new()
        };
        format!(
            "✓ 已探测应用「{}」({})：正在运行 (PID {:?}){}",
            name, app_id, running_pids, tray_note
        )
    } else {
        format!(
            "已探测应用「{}」({}，desktop={:?})：已安装但当前未运行，可调用 `app_launch` 启动",
            name, app_id, desktop_id
        )
    };

    Ok(json!({
        "ok": true,
        "found": found,
        "channel_used": channel_used,
        "summary": summary,
        "app_id": app_id,
        "name": name,
        "display_name": name,
        "aliases": aliases,
        "desktop_id": desktop_id,
        "exec_cmd": exec_cmd,
        "exec_binary": exec_cmd,
        "is_running": is_running,
        "running_pids": running_pids,
        "pids": running_pids,
        "tray_bus": tray_bus_val,
        "tray": tray_bus_val,
        "tray_menu_items": tray_menu_items,
        "mpris_bus": matched_mpris_bus.cloned(),
        "mpris_services": mpris_services,
        "uri_schemes": uri_schemes,
        "desktop_actions": desktop_actions,
        "atspi_controls": atspi_controls,
        "custom_rules": custom_rules,
        "suggested_actions": suggested_actions,
    }))
}
