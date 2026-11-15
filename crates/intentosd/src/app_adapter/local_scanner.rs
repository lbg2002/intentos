#![forbid(unsafe_code)]

//! Deep Multi-Source Local Software Scanner, 9-Category AIOS Classifier & Rich Translation Layer (`local_scanner.rs`).
//!
//! Discovers all desktop & companion CLI software installed on the Ubuntu host across:
//! - `/usr/share/applications`
//! - `/usr/local/share/applications`
//! - `/var/lib/snapd/desktop/applications`
//! - `/var/lib/flatpak/exports/share/applications`
//! - `~/.local/share/applications` (user overrides/merges system entry when sharing the same `desktop_id`)
//! - Companion CLI lookup (`/usr/bin`, `/usr/local/bin`, `/snap/bin`, `/opt`, `~/.local/bin`)
//! - Live runtime correlation (`sni_dbusmenu`, `mpris_dbus`, and UID-scoped `/proc` PIDs)

use crate::app_adapter::gui_bridge::GuiApprovalScope;
use crate::app_adapter::headless_bridge::ensure_authorized_path;
use crate::app_adapter::mpris_dbus::{
    DbusDispatchResult, discover_active_mpris_services, execute_mpris_action, has_gui_session,
    query_all_now_playing,
};
use crate::app_adapter::registry::{AdaptationChannel, AdapterRegistry, AppAdapterProfile};
use crate::app_adapter::sni_dbusmenu::{
    LiveTrayApp, TrayMenuItem, activate_or_show_tray_app, apply_clean_desktop_env,
    apply_clean_desktop_env_std, discover_live_tray_apps, invoke_tray_menu_action,
};
use crate::app_adapter::uri_desktop::{
    normalize_meeting_code, resolve_desktop_binary, tokenize_desktop_exec_with_env,
    validate_uri_safety,
};
use crate::app_adapter::{AdapterExecutionOutcome, AdapterTraceDot};
use crate::core::IntentOsCore;
use chrono::Utc;
use intentos_protocol::{VerificationReport, VerificationState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

/// Metadata for each of the 9 canonical AIOS software categories.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoftwareCategoryMeta {
    pub id: &'static str,
    pub category_zh: &'static str,
    pub short_zh: &'static str,
    pub icon: &'static str,
}

/// Canonical 9 AIOS local software categories.
pub const ALL_SOFTWARE_CATEGORIES: &[SoftwareCategoryMeta] = &[
    SoftwareCategoryMeta {
        id: "media_entertainment",
        category_zh: "🎵 影音与音乐娱乐",
        short_zh: "影音娱乐",
        icon: "🎵",
    },
    SoftwareCategoryMeta {
        id: "social_collab",
        category_zh: "💬 社交通讯与视频会议",
        short_zh: "社交会议",
        icon: "💬",
    },
    SoftwareCategoryMeta {
        id: "office_notes_doc",
        category_zh: "📄 办公文档、PDF 与知识笔记",
        short_zh: "办公笔记",
        icon: "📄",
    },
    SoftwareCategoryMeta {
        id: "cloud_transfer",
        category_zh: "☁ 云盘同步与局域网互传",
        short_zh: "云盘互传",
        icon: "☁",
    },
    SoftwareCategoryMeta {
        id: "network_browser",
        category_zh: "🌐 网络代理、VPN 与浏览器",
        short_zh: "网络代理",
        icon: "🌐",
    },
    SoftwareCategoryMeta {
        id: "dev_ai_ide",
        category_zh: "💻 AI 编程、IDE 与开发逆向",
        short_zh: "开发与AI",
        icon: "💻",
    },
    SoftwareCategoryMeta {
        id: "creative_disc",
        category_zh: "🎨 图形摄影、流程图与光盘刻录",
        short_zh: "创意刻录",
        icon: "🎨",
    },
    SoftwareCategoryMeta {
        id: "remote_vm",
        category_zh: "🖥 远程桌面与虚拟化容器",
        short_zh: "远程虚拟机",
        icon: "🖥",
    },
    SoftwareCategoryMeta {
        id: "hardware_system",
        category_zh: "🛠 硬件外设、输入法与系统工具",
        short_zh: "硬件系统",
        icon: "🛠",
    },
];

pub fn all_software_categories() -> &'static [SoftwareCategoryMeta] {
    ALL_SOFTWARE_CATEGORIES
}

pub fn category_meta(category_id: &str) -> &'static SoftwareCategoryMeta {
    let norm = normalize_software_category(category_id).unwrap_or("hardware_system");
    ALL_SOFTWARE_CATEGORIES
        .iter()
        .find(|c| c.id == norm)
        .unwrap_or(&ALL_SOFTWARE_CATEGORIES[8])
}

/// Normalize any category id, legacy short name, or Chinese label into one of the 9 canonical category IDs.
pub fn normalize_software_category(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") || trimmed == "全部" {
        return None;
    }
    let lc = trimmed.to_ascii_lowercase();
    match lc.as_str() {
        "media_entertainment"
        | "media"
        | "music"
        | "audio"
        | "video"
        | "player"
        | "影音娱乐"
        | "影音与音乐娱乐" => Some("media_entertainment"),
        "social_collab"
        | "social"
        | "communication"
        | "chat"
        | "im"
        | "meeting"
        | "email"
        | "mail"
        | "社交会议"
        | "社交通讯"
        | "社交通讯与视频会议" => Some("social_collab"),
        "office_notes_doc"
        | "office"
        | "notes"
        | "note"
        | "document"
        | "doc"
        | "pdf"
        | "办公笔记"
        | "办公文档"
        | "办公文档、pdf 与知识笔记" => Some("office_notes_doc"),
        "cloud_transfer"
        | "cloud"
        | "transfer"
        | "sync"
        | "netdisk"
        | "云盘互传"
        | "云盘同步与局域网互传" => Some("cloud_transfer"),
        "network_browser"
        | "browser"
        | "network"
        | "proxy"
        | "vpn"
        | "web"
        | "网络代理"
        | "网络代理、vpn 与浏览器" => Some("network_browser"),
        "dev_ai_ide"
        | "ide"
        | "dev"
        | "development"
        | "terminal"
        | "ai"
        | "coding"
        | "code"
        | "开发与ai"
        | "ai 编程、ide 与开发逆向" => Some("dev_ai_ide"),
        "creative_disc"
        | "creative"
        | "graphics"
        | "photo"
        | "diagram"
        | "disc"
        | "burn"
        | "创意刻录"
        | "图形摄影、流程图与光盘刻录" => Some("creative_disc"),
        "remote_vm"
        | "remote"
        | "vm"
        | "virtualization"
        | "container"
        | "rdp"
        | "vnc"
        | "远程虚拟机"
        | "远程桌面与虚拟化容器" => Some("remote_vm"),
        "hardware_system"
        | "hardware"
        | "system"
        | "file_manager"
        | "files"
        | "utility"
        | "tools"
        | "input_method"
        | "desktop_app"
        | "硬件系统"
        | "硬件外设、输入法与系统工具" => Some("hardware_system"),
        _ => {
            if trimmed.contains("影音") || trimmed.contains("音乐") {
                Some("media_entertainment")
            } else if trimmed.contains("社交") || trimmed.contains("会议") {
                Some("social_collab")
            } else if trimmed.contains("办公") || trimmed.contains("笔记") || lc.contains("pdf")
            {
                Some("office_notes_doc")
            } else if trimmed.contains("云盘") || trimmed.contains("互传") {
                Some("cloud_transfer")
            } else if trimmed.contains("网络")
                || trimmed.contains("代理")
                || trimmed.contains("浏览器")
            {
                Some("network_browser")
            } else if trimmed.contains("开发") || trimmed.contains("编程") {
                Some("dev_ai_ide")
            } else if trimmed.contains("创意")
                || trimmed.contains("刻录")
                || trimmed.contains("图形")
            {
                Some("creative_disc")
            } else if trimmed.contains("远程") || trimmed.contains("虚拟") {
                Some("remote_vm")
            } else if trimmed.contains("硬件")
                || trimmed.contains("系统")
                || trimmed.contains("输入法")
            {
                Some("hardware_system")
            } else {
                None
            }
        }
    }
}

/// Check whether an app/profile category matches a user/LLM filter category (supporting both 9-category IDs and legacy short names).
pub fn categories_match(entry_category: &str, filter_category: &str) -> bool {
    let f = filter_category.trim();
    if f.is_empty() || f.eq_ignore_ascii_case("all") || f == "全部" {
        return true;
    }
    if entry_category.eq_ignore_ascii_case(f) {
        return true;
    }
    match (
        normalize_software_category(entry_category),
        normalize_software_category(f),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => entry_category
            .to_ascii_lowercase()
            .contains(&f.to_ascii_lowercase()),
    }
}

/// Parsed `[Desktop Action <sec_id>]` entry on a discovered `.desktop` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScannedDesktopAction {
    pub action_id: String,
    pub name: String,
    pub name_zh: Option<String>,
    pub display_name: String,
    pub exec: String,
    pub icon: Option<String>,
}

/// Rich executable action descriptor exposed per scanned software entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizedActionSpec {
    pub action: String,
    pub label: String,
    pub channel: String,
    pub description: String,
    pub requires_approval: bool,
    pub source: String,
}

/// Companion CLI tool detected on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanionCliTool {
    pub name: String,
    pub binary_path: String,
    pub category_id: String,
    pub description: String,
}

/// Summary count per category in `DeepScanCatalog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScanSummary {
    pub id: String,
    pub category_id: String,
    pub name_zh: String,
    pub category_zh: String,
    pub short_zh: String,
    pub icon: String,
    pub category_icon: String,
    pub count: usize,
    pub running_count: usize,
}

/// Deeply scanned & classified local software entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedSoftwareEntry {
    pub id: String,
    pub desktop_id: String,
    pub desktop_path: String,
    pub install_source: String,
    pub source_badge: String,
    pub name: String,
    pub name_zh: Option<String>,
    pub display_name: String,
    pub comment: Option<String>,
    pub exec_raw: String,
    pub exec_binary: String,
    pub env_overrides: BTreeMap<String, String>,
    pub icon: Option<String>,
    pub startup_wm_class: Option<String>,
    pub dbus_activatable: bool,
    pub category_id: String,
    pub category: String,
    pub category_zh: String,
    pub category_icon: String,
    pub desktop_actions: Vec<ScannedDesktopAction>,
    pub uri_schemes: Vec<String>,
    pub supported_mime_types: Vec<String>,
    pub freedesktop_categories: Vec<String>,
    pub matched_adapter_id: Option<String>,
    pub aliases: Vec<String>,
    pub channels: Vec<String>,
    pub capabilities: Vec<SynthesizedActionSpec>,
    pub actions: Vec<String>,
    pub synthesized_actions: Vec<SynthesizedActionSpec>,
    pub translatable_actions: Vec<SynthesizedActionSpec>,
    pub is_running: bool,
    pub running: bool,
    pub running_pids: Vec<u32>,
    pub tray_service: Option<String>,
    pub tray_title: Option<String>,
    pub tray_menu_items: Vec<TrayMenuItem>,
    pub mpris_service: Option<String>,
    pub companion_clis: Vec<String>,
}

/// Options controlling `deep_scan_local_software`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalScanOptions {
    #[serde(default)]
    pub force_refresh: bool,
    #[serde(default)]
    pub include_hidden: bool,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub only_running: bool,
    /// Optional hermetic override directories (used by isolated tests when non-empty).
    #[serde(default)]
    pub scan_dirs: Vec<PathBuf>,
    /// Optional extra directories appended to standard XDG/Snap/Flatpak scan dirs.
    #[serde(default)]
    pub extra_dirs: Vec<PathBuf>,
}

/// Complete categorized deep-scan catalog returned by `deep_scan_local_software` and `get_categorized_catalog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanCatalog {
    pub total_scanned: usize,
    pub total_apps: usize,
    pub total_adapted: usize,
    pub total_interfaces: usize,
    pub total_actions_count: usize,
    pub translatable_actions_total: usize,
    pub running_count: usize,
    pub running_apps: usize,
    pub filtered_count: usize,
    pub categories: Vec<CategoryScanSummary>,
    pub apps: Vec<ScannedSoftwareEntry>,
    pub companion_cli_tools: Vec<CompanionCliTool>,
    pub scanned_at: String,
    pub cached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ScanCacheKey {
    dirs_list: Vec<(PathBuf, &'static str)>,
    include_hidden: bool,
}

struct CachedScanState {
    created_at: Instant,
    dirs_fingerprint: u64,
    catalog: DeepScanCatalog,
}

static DEEP_SCAN_CACHE: OnceLock<Mutex<HashMap<ScanCacheKey, CachedScanState>>> = OnceLock::new();
static DEEP_SCAN_SINGLEFLIGHT: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static DEEP_SCAN_EXECUTION_COUNT: AtomicU64 = AtomicU64::new(0);

/// Warm TTL (`120s`) for `deep_scan_local_software` directory-mtime snapshot cache (`H09.3`).
pub const SCAN_CACHE_TTL: Duration = Duration::from_secs(120);

fn deep_scan_cache() -> &'static Mutex<HashMap<ScanCacheKey, CachedScanState>> {
    DEEP_SCAN_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn deep_scan_singleflight() -> &'static tokio::sync::Mutex<()> {
    DEEP_SCAN_SINGLEFLIGHT.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Monotonic count of full `.desktop` + runtime scans executed since daemon start (`H09.3`).
pub fn deep_scan_execution_count() -> u64 {
    DEEP_SCAN_EXECUTION_COUNT.load(Ordering::Acquire)
}

/// Compute a fast (`< 80 µs`) directory-mtime + `.desktop` entry fingerprint across all scan sources.
fn compute_scan_dirs_fingerprint(
    scan_dirs: &[(PathBuf, &'static str)],
    registry: &AdapterRegistry,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    let profiles = registry.all_profiles();
    profiles.len().hash(&mut hasher);
    for prof in &profiles {
        prof.id.hash(&mut hasher);
    }

    scan_dirs.len().hash(&mut hasher);
    for (dir, kind) in scan_dirs {
        dir.hash(&mut hasher);
        kind.hash(&mut hasher);

        let Ok(meta) = fs::metadata(dir) else {
            0u8.hash(&mut hasher);
            continue;
        };
        if !meta.is_dir() {
            0u8.hash(&mut hasher);
            continue;
        }
        1u8.hash(&mut hasher);
        meta.len().hash(&mut hasher);
        if let Ok(modified) = meta.modified()
            && let Ok(dur) = modified.duration_since(UNIX_EPOCH)
        {
            dur.as_secs().hash(&mut hasher);
            dur.subsec_nanos().hash(&mut hasher);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            meta.ino().hash(&mut hasher);
            meta.ctime().hash(&mut hasher);
            meta.ctime_nsec().hash(&mut hasher);
        }

        if let Ok(rd) = fs::read_dir(dir) {
            let mut desktop_entries: Vec<(String, u64, PathBuf)> = Vec::new();
            for entry in rd.flatten() {
                let fname = entry.file_name();
                let Some(fname_str) = fname.to_str() else {
                    continue;
                };
                if !fname_str.ends_with(".desktop") {
                    continue;
                }
                #[cfg(unix)]
                let ino = {
                    use std::os::unix::fs::DirEntryExt;
                    entry.ino()
                };
                #[cfg(not(unix))]
                let ino = 0u64;
                desktop_entries.push((fname_str.to_string(), ino, entry.path()));
            }
            desktop_entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            desktop_entries.len().hash(&mut hasher);

            let inspect_files = desktop_entries.len() <= 32;
            for (name, ino, path) in desktop_entries {
                name.hash(&mut hasher);
                ino.hash(&mut hasher);
                if inspect_files && let Ok(fmeta) = fs::metadata(&path) {
                    fmeta.len().hash(&mut hasher);
                    if let Ok(fmod) = fmeta.modified()
                        && let Ok(fdur) = fmod.duration_since(UNIX_EPOCH)
                    {
                        fdur.as_secs().hash(&mut hasher);
                        fdur.subsec_nanos().hash(&mut hasher);
                    }
                    if fmeta.len() <= 16_384
                        && let Ok(bytes) = fs::read(&path)
                    {
                        bytes.hash(&mut hasher);
                    }
                }
            }
        }
    }

    hasher.finish()
}

/// Intermediate parsed representation of a single `.desktop` file before override merging & runtime correlation.
#[derive(Debug, Clone)]
struct RawDesktopRecord {
    desktop_id: String,
    stem_id: String,
    desktop_path: PathBuf,
    source_dir_kind: &'static str,
    name: String,
    name_zh: Option<String>,
    comment: Option<String>,
    comment_zh: Option<String>,
    exec_raw: String,
    exec_binary: String,
    env_overrides: BTreeMap<String, String>,
    icon: Option<String>,
    startup_wm_class: Option<String>,
    dbus_activatable: bool,
    no_display: bool,
    hidden: bool,
    entry_type: String,
    desktop_actions: Vec<ScannedDesktopAction>,
    uri_schemes: Vec<String>,
    supported_mime_types: Vec<String>,
    freedesktop_categories: Vec<String>,
}

fn is_pure_uninstaller_entry(rec: &RawDesktopRecord) -> bool {
    let id_lc = rec.desktop_id.to_ascii_lowercase();
    let bin_lc = rec.exec_binary.to_ascii_lowercase();
    let name_lc = rec.name.to_ascii_lowercase();
    let zh = rec.name_zh.as_deref().unwrap_or("");

    if id_lc.contains("uninstall") || id_lc.starts_with("remove-") {
        return true;
    }
    if bin_lc.ends_with("/uninstall")
        || bin_lc.ends_with("/uninstaller")
        || bin_lc.contains("/uninstall/")
    {
        return true;
    }
    if name_lc.starts_with("uninstall ") || name_lc.starts_with("remove ") || zh.starts_with("卸载")
    {
        return true;
    }
    false
}

/// Map hidden URL-handler `.desktop` stems (`trae-cn-url-handler`, `rustdesk-link`, `code-url-handler`, etc.)
/// to candidate parent `stem_id`s so their `x-scheme-handler/*` schemes enrich the main visible app.
fn url_handler_parent_candidates(stem_id: &str) -> Vec<String> {
    let lc = stem_id.to_ascii_lowercase();
    let mut out = Vec::new();
    for suffix in [
        "-url-handler",
        "-uri-handler",
        "-scheme-handler",
        "-link",
        "-handler",
    ] {
        if let Some(base) = lc.strip_suffix(suffix)
            && !base.is_empty()
        {
            out.push(base.to_string());
        }
    }
    if lc == "code-url-handler" {
        out.push("com.microsoft.vscode".into());
        out.push("code".into());
    }
    if lc == "flclash-url-handler" {
        out.push("flclash".into());
    }
    out
}

fn parse_raw_desktop_file(path: &Path, source_dir_kind: &'static str) -> Option<RawDesktopRecord> {
    let content = fs::read_to_string(path).ok()?;
    let desktop_id = path.file_name()?.to_str()?.to_string();
    if !desktop_id.ends_with(".desktop") {
        return None;
    }
    let stem_id = desktop_id.trim_end_matches(".desktop").to_string();

    let mut entry_type = String::from("Application");
    let mut name: Option<String> = None;
    let mut name_zh: Option<String> = None;
    let mut comment: Option<String> = None;
    let mut comment_zh: Option<String> = None;
    let mut exec_raw: Option<String> = None;
    let mut try_exec: Option<String> = None;
    let mut icon: Option<String> = None;
    let mut startup_wm_class: Option<String> = None;
    let mut dbus_activatable = false;
    let mut no_display = false;
    let mut hidden = false;
    let mut uri_schemes = BTreeSet::new();
    let mut supported_mime_types = BTreeSet::new();
    let mut freedesktop_categories = Vec::new();
    let mut declared_action_order = Vec::new();
    let mut action_map: BTreeMap<String, ScannedDesktopAction> = BTreeMap::new();

    #[derive(Clone)]
    enum Sec {
        None,
        Entry,
        Action(String),
    }

    let mut sec = Sec::None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let hdr = line[1..line.len() - 1].trim();
            if hdr == "Desktop Entry" {
                sec = Sec::Entry;
            } else if let Some(act_id) = hdr.strip_prefix("Desktop Action ") {
                let aid = act_id.trim().to_string();
                if !aid.is_empty() {
                    action_map
                        .entry(aid.clone())
                        .or_insert_with(|| ScannedDesktopAction {
                            action_id: aid.clone(),
                            name: aid.clone(),
                            name_zh: None,
                            display_name: aid.clone(),
                            exec: String::new(),
                            icon: None,
                        });
                    sec = Sec::Action(aid);
                } else {
                    sec = Sec::None;
                }
            } else {
                sec = Sec::None;
            }
            continue;
        }

        let Some(eq_idx) = line.find('=') else {
            continue;
        };
        let key = line[..eq_idx].trim();
        let val = line[eq_idx + 1..].trim();

        match &sec {
            Sec::Entry => match key {
                "Type" => entry_type = val.to_string(),
                "Name" => name = Some(val.to_string()),
                "Name[zh_CN]" | "Name[zh]" | "Name[zh_TW]" => {
                    if name_zh.is_none() || key == "Name[zh_CN]" {
                        name_zh = Some(val.to_string());
                    }
                }
                "Comment" => comment = Some(val.to_string()),
                "Comment[zh_CN]" | "Comment[zh]" => {
                    if comment_zh.is_none() || key == "Comment[zh_CN]" {
                        comment_zh = Some(val.to_string());
                    }
                }
                "Exec" => exec_raw = Some(val.to_string()),
                "TryExec" => try_exec = Some(val.to_string()),
                "Icon" if !val.is_empty() => icon = Some(val.to_string()),
                "StartupWMClass" if !val.is_empty() => startup_wm_class = Some(val.to_string()),
                "DBusActivatable" => dbus_activatable = val.eq_ignore_ascii_case("true"),
                "NoDisplay" => no_display = val.eq_ignore_ascii_case("true"),
                "Hidden" => hidden = val.eq_ignore_ascii_case("true"),
                "Actions" => {
                    declared_action_order = val
                        .split(';')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                }
                "Categories" => {
                    freedesktop_categories = val
                        .split(';')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                }
                "MimeType" => {
                    for m in val.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                        let mlc = m.to_ascii_lowercase();
                        if let Some(scheme) = mlc.strip_prefix("x-scheme-handler/") {
                            let clean_scheme = scheme.trim();
                            if !clean_scheme.is_empty() {
                                uri_schemes.insert(clean_scheme.to_string());
                            }
                        } else {
                            supported_mime_types.insert(mlc);
                        }
                    }
                }
                _ => {}
            },
            Sec::Action(aid) => {
                if let Some(act) = action_map.get_mut(aid) {
                    match key {
                        "Name" => act.name = val.to_string(),
                        "Name[zh_CN]" | "Name[zh]" => act.name_zh = Some(val.to_string()),
                        "Exec" => act.exec = val.to_string(),
                        "Icon" if !val.is_empty() => act.icon = Some(val.to_string()),
                        _ => {}
                    }
                }
            }
            Sec::None => {}
        }
    }

    if entry_type != "Application" {
        return None;
    }

    let raw_exec = exec_raw.or(try_exec)?;
    let (exec_binary, _args, env_vec) = match tokenize_desktop_exec_with_env(&raw_exec, None) {
        Ok(parsed) => parsed,
        Err(_) => {
            let fallback_bin = raw_exec
                .split_whitespace()
                .find(|t| !t.contains('=') && *t != "env")
                .unwrap_or(&stem_id)
                .trim_matches('"')
                .to_string();
            (fallback_bin, Vec::new(), Vec::new())
        }
    };

    let env_overrides: BTreeMap<String, String> = env_vec.into_iter().collect();

    // Order desktop actions cleanly (declared order first, then any extra `[Desktop Action ...]` sections)
    let mut desktop_actions = Vec::new();
    let mut visited_actions = BTreeSet::new();
    for aid in &declared_action_order {
        if let Some(mut act) = action_map.remove(aid)
            && !act.exec.is_empty()
        {
            act.display_name = act.name_zh.clone().unwrap_or_else(|| act.name.clone());
            visited_actions.insert(aid.clone());
            desktop_actions.push(act);
        }
    }
    for (aid, mut act) in action_map {
        if !visited_actions.contains(&aid) && !act.exec.is_empty() {
            act.display_name = act.name_zh.clone().unwrap_or_else(|| act.name.clone());
            desktop_actions.push(act);
        }
    }

    Some(RawDesktopRecord {
        desktop_id,
        stem_id: stem_id.clone(),
        desktop_path: path.to_path_buf(),
        source_dir_kind,
        name: name.unwrap_or(stem_id),
        name_zh,
        comment,
        comment_zh,
        exec_raw: raw_exec,
        exec_binary,
        env_overrides,
        icon,
        startup_wm_class,
        dbus_activatable,
        no_display,
        hidden,
        entry_type,
        desktop_actions,
        uri_schemes: uri_schemes.into_iter().collect(),
        supported_mime_types: supported_mime_types.into_iter().collect(),
        freedesktop_categories,
    })
}

fn merge_user_override(mut higher: RawDesktopRecord, lower: &RawDesktopRecord) -> RawDesktopRecord {
    if higher.name_zh.is_none() {
        higher.name_zh = lower.name_zh.clone();
    }
    if higher.comment_zh.is_none() {
        higher.comment_zh = lower.comment_zh.clone();
    }
    if higher.comment.is_none() {
        higher.comment = lower.comment.clone();
    }
    if higher.icon.is_none() {
        higher.icon = lower.icon.clone();
    }
    if higher.startup_wm_class.is_none() {
        higher.startup_wm_class = lower.startup_wm_class.clone();
    }
    if higher.desktop_actions.is_empty() && !lower.desktop_actions.is_empty() {
        higher.desktop_actions = lower.desktop_actions.clone();
    }
    for s in &lower.uri_schemes {
        if !higher.uri_schemes.iter().any(|x| x.eq_ignore_ascii_case(s)) {
            higher.uri_schemes.push(s.clone());
        }
    }
    for m in &lower.supported_mime_types {
        if !higher
            .supported_mime_types
            .iter()
            .any(|x| x.eq_ignore_ascii_case(m))
        {
            higher.supported_mime_types.push(m.clone());
        }
    }
    for c in &lower.freedesktop_categories {
        if !higher
            .freedesktop_categories
            .iter()
            .any(|x| x.eq_ignore_ascii_case(c))
        {
            higher.freedesktop_categories.push(c.clone());
        }
    }
    higher
}

fn determine_install_source(rec: &RawDesktopRecord) -> (&'static str, &'static str) {
    let id_lc = rec.desktop_id.to_ascii_lowercase();
    let exec_lc = rec.exec_raw.to_ascii_lowercase();
    let bin_lc = rec.exec_binary.to_ascii_lowercase();
    let path_str = rec.desktop_path.to_string_lossy();

    if id_lc.starts_with("chrome-")
        || id_lc.starts_with("brave-")
        || id_lc.starts_with("msedge-")
        || exec_lc.contains("--app-id=")
    {
        return ("chrome_pwa", "PWA");
    }
    if rec.source_dir_kind == "snap" || path_str.contains("/snapd/") || bin_lc.starts_with("/snap/")
    {
        return ("snap", "Snap");
    }
    if rec.source_dir_kind == "flatpak"
        || path_str.contains("/flatpak/")
        || exec_lc.contains("flatpak run")
    {
        return ("flatpak", "Flatpak");
    }
    if rec.source_dir_kind == "user_local" || path_str.contains("/.local/share/applications/") {
        return ("user_local", "Local");
    }
    if bin_lc.starts_with("/opt/") {
        return ("opt_vendor", "Vendor");
    }
    ("system_apt", "APT")
}

/// Classify any discovered software into one of the 9 rich AIOS categories.
#[allow(clippy::too_many_arguments)]
pub fn classify_software_category(
    desktop_id: &str,
    exec_binary: &str,
    name: &str,
    name_zh: Option<&str>,
    startup_wm_class: Option<&str>,
    uri_schemes: &[String],
    supported_mime_types: &[String],
    freedesktop_categories: &[String],
) -> &'static SoftwareCategoryMeta {
    let id_lc = desktop_id.trim_end_matches(".desktop").to_ascii_lowercase();
    let bin_base = Path::new(exec_binary)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(exec_binary)
        .to_ascii_lowercase();
    let bin_full_lc = exec_binary.to_ascii_lowercase();
    let name_lc = name.to_ascii_lowercase();
    let zh = name_zh.unwrap_or("");
    let zh_lc = zh.to_ascii_lowercase();
    let wm_lc = startup_wm_class.unwrap_or("").to_ascii_lowercase();

    let haystack = format!(
        "{} {} {} {} {} {}",
        id_lc, bin_base, bin_full_lc, name_lc, zh_lc, wm_lc
    );
    let has_any = |needles: &[&str]| needles.iter().any(|n| haystack.contains(n));

    // 1. Media & Music Entertainment (`media_entertainment`) — check BEFORE `qq` so `qqmusic` lands here!
    if has_any(&[
        "sodam",
        "baicaimusic",
        "汽水音乐",
        "qqmusic",
        "qq音乐",
        "netease-cloud-music",
        "yesplaymusic",
        "lx-music",
        "洛雪",
        "kugou",
        "kuwo",
        "vlc",
        "mpv",
        "celluloid",
        "totem",
        "smplayer",
        "rhythmbox",
        "spotify",
        "elisa",
        "audacious",
        "clementine",
        "strawberry",
        "amberol",
        "lollypop",
        "deadbeef",
        "douyin",
        "抖音",
        "bilibili",
        "哔哩哔哩",
        "parole",
        "haruna",
    ]) {
        return category_meta("media_entertainment");
    }

    // 2. Social, IM & Video Conferencing (`social_collab`)
    if id_lc == "qq"
        || bin_base == "qq"
        || id_lc == "linuxqq"
        || has_any(&[
            "tencent-qq",
            "wechat",
            "weixin",
            "微信",
            "feishu",
            "bytedance-feishu",
            "lark",
            "飞书",
            "wemeet",
            "腾讯会议",
            "dingtalk",
            "钉钉",
            "telegram",
            "discord",
            "vesktop",
            "zoom",
            "slack",
            "thunderbird",
            "geary",
            "evolution",
            "element",
            "signal-desktop",
            "mattermost",
            "skype",
        ])
        || uri_schemes.iter().any(|s| {
            matches!(
                s.as_str(),
                "wemeet" | "feishu" | "lark" | "tencent" | "weixin" | "tg"
            )
        })
    {
        return category_meta("social_collab");
    }

    // 3. Office, PDF & Knowledge Notes (`office_notes_doc`)
    if has_any(&[
        "wps-office",
        "wpspdf",
        "wpscloud",
        "金山",
        "yozo",
        "永中",
        "libreoffice",
        "soffice",
        "onlyoffice",
        "typora",
        "betternotes",
        "轻笺",
        "pinplan",
        "pdfarranger",
        "evince",
        "org.gnome.papers",
        "okular",
        "zathura",
        "sioyek",
        "xpdf",
        "foxit",
        "masterpdf",
        "xchm",
        "texdoctk",
        "obsidian",
        "notion",
        "logseq",
        "joplin",
        "zettlr",
        "marktext",
        "calibre",
        "foliate",
        "xmind",
        "anki",
    ]) || matches!(bin_base.as_str(), "wps" | "et" | "wpp" | "papers")
    {
        return category_meta("office_notes_doc");
    }

    // 4. Cloud Sync & LAN File Transfer (`cloud_transfer`)
    if has_any(&[
        "baidunetdisk",
        "百度网盘",
        "mcloud",
        "com.cmic.mcloud",
        "移动云盘",
        "中国移动云盘",
        "aliyundrive",
        "alipan",
        "阿里云盘",
        "quark",
        "夸克",
        "nutstore",
        "坚果云",
        "localsend",
        "warpinator",
        "nextcloud",
        "owncloud",
        "seafile",
        "syncthing",
        "onedrive",
        "dropbox",
        "megasync",
        "transmission",
        "qbittorrent",
        "deluge",
        "motrix",
        "filezilla",
    ]) {
        return category_meta("cloud_transfer");
    }

    // 8. Remote Desktop & Virtualization (`remote_vm`) — check before dev/network!
    if has_any(&[
        "rustdesk",
        "todesk",
        "sunlogin",
        "向日葵",
        "anydesk",
        "teamviewer",
        "remmina",
        "vinagre",
        "krdc",
        "tigervnc",
        "realvnc",
        "nomachine",
        "moonlight",
        "parsec",
        "virtualbox",
        "vbox",
        "vmware",
        "vmplayer",
        "virt-manager",
        "gnome-boxes",
        "qemu",
        "waydroid",
        "genymotion",
    ]) {
        return category_meta("remote_vm");
    }

    // 6. AI Coding, IDEs, Terminals & Reverse Engineering (`dev_ai_ide`)
    if has_any(&[
        "zcode",
        "trae",
        "antigravity",
        "workbuddy",
        "chatgpt",
        "claude",
        "deepseek",
        "doubao",
        "cherry-studio",
        "chatbox",
        "lmstudio",
        "vscode",
        "vscodium",
        "cursor",
        "windsurf",
        "sublime",
        "android-studio",
        "jetbrains",
        "intellij",
        "pycharm",
        "clion",
        "goland",
        "webstorm",
        "rustrover",
        "datagrip",
        "qtcreator",
        "hopper",
        "ghidra",
        "radare",
        "cutter",
        "ptyxis",
        "org.gnome.terminal",
        "gnome-terminal",
        "konsole",
        "alacritty",
        "kitty",
        "wezterm",
        "tilix",
        "terminator",
        "xfce4-terminal",
        "ghostty",
        "sysprof",
        "neovim",
        "nvim",
        "gvim",
        "emacs",
        "gedit",
        "gnome-text-editor",
        "kate",
        "meld",
        "postman",
        "insomnia",
        "apifox",
        "dbeaver",
        "gitkraken",
        "gitg",
        "devhelp",
    ]) || matches!(bin_base.as_str(), "code" | "vim" | "zed")
    {
        return category_meta("dev_ai_ide");
    }

    // 7. Creative Graphics, Diagramming & Optical Disc Burning (`creative_disc`)
    if has_any(&[
        "drawio",
        "diagrams.net",
        "darktable",
        "rawtherapee",
        "gimp",
        "krita",
        "inkscape",
        "scribus",
        "blender",
        "freecad",
        "openscad",
        "kicad",
        "display-im",
        "imagemagick",
        "hydrapaper",
        "discforge",
        "光铸",
        "brasero",
        "xfburn",
        "k3b",
        "org.gnome.loupe",
        "loupe",
        "eog",
        "gthumb",
        "gwenview",
        "flameshot",
        "shutter",
        "obs",
        "com.obsproject",
        "kdenlive",
        "shotcut",
        "openshot",
        "handbrake",
        "audacity",
        "ardour",
        "cheese",
        "org.gnome.snapshot",
        "simple-scan",
    ]) {
        return category_meta("creative_disc");
    }

    // 5. Network Proxy, VPN & Browsers (`network_browser`)
    if has_any(&[
        "flclash",
        "clash",
        "mihomo",
        "v2ray",
        "qv2ray",
        "nekoray",
        "nekobox",
        "sing-box",
        "hiddify",
        "shadowsocks",
        "wireguard",
        "openvpn",
        "tailscale",
        "zerotier",
        "google-chrome",
        "chromium",
        "brave-browser",
        "brave",
        "firefox",
        "microsoft-edge",
        "msedge",
        "vivaldi",
        "opera",
        "zen-browser",
        "epiphany",
        "nm-connection-editor",
        "wireshark",
    ]) || id_lc.starts_with("chrome-")
    {
        return category_meta("network_browser");
    }

    // 9. Explicit Hardware, Input Method & System Utilities (`hardware_system`)
    if has_any(&[
        "omni-mouse",
        "鼠标",
        "wowtype",
        "fcitx",
        "ibus",
        "输入法",
        "nvidia-settings",
        "nvidia",
        "nokyan.resources",
        "system-monitor",
        "diskutility",
        "gnome-disks",
        "gparted",
        "baobab",
        "fontmanager",
        "font-manager",
        "font-viewer",
        "extensionmanager",
        "extension-manager",
        "gnome-extensions",
        "desktop-security-center",
        "nautilus",
        "dolphin",
        "thunar",
        "nemo",
        "calculator",
        "clocks",
        "seahorse",
        "pavucontrol",
        "blueman",
        "gnome-control-center",
        "dconf-editor",
        "tweaks",
    ]) {
        return category_meta("hardware_system");
    }

    // Fallback to Freedesktop `Categories=` and `MimeType=` heuristics
    let fd_joined = freedesktop_categories.join(";").to_ascii_lowercase();
    if fd_joined.contains("instantmessaging")
        || fd_joined.contains("chat")
        || fd_joined.contains("videoconference")
        || fd_joined.contains("email")
    {
        return category_meta("social_collab");
    }
    if fd_joined.contains("webbrowser") || fd_joined.contains("vpn") {
        return category_meta("network_browser");
    }
    if fd_joined.contains("ide")
        || fd_joined.contains("development")
        || fd_joined.contains("terminalemulator")
        || fd_joined.contains("debugger")
    {
        return category_meta("dev_ai_ide");
    }
    if fd_joined.contains("office")
        || fd_joined.contains("wordprocessor")
        || fd_joined.contains("spreadsheet")
        || fd_joined.contains("presentation")
        || supported_mime_types.iter().any(|m| m == "application/pdf")
    {
        return category_meta("office_notes_doc");
    }
    if fd_joined.contains("discburning")
        || fd_joined.contains("graphics")
        || fd_joined.contains("photography")
        || fd_joined.contains("2dgraphics")
        || fd_joined.contains("3dgraphics")
    {
        return category_meta("creative_disc");
    }
    if fd_joined.contains("remoteaccess") || fd_joined.contains("emulator") {
        return category_meta("remote_vm");
    }
    if fd_joined.contains("filesharing") || fd_joined.contains("p2p") {
        return category_meta("cloud_transfer");
    }
    if fd_joined.contains("audiovideo")
        || fd_joined.contains("music")
        || fd_joined.contains("player")
    {
        return category_meta("media_entertainment");
    }

    category_meta("hardware_system")
}

/// Snapshot current user's running processes from `/proc` in a single fast pass.
#[derive(Debug, Clone)]
struct RunningProcessEntry {
    pid: u32,
    comm_lc: String,
    exe_lc: String,
    cmdline_lc: String,
}

fn current_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse::<u32>().ok();
        }
    }
    None
}

fn snapshot_user_running_processes() -> Vec<RunningProcessEntry> {
    let my_uid = current_uid();
    let my_pid = std::process::id();
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(pid_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == my_pid {
            continue;
        }
        let proc_dir = entry.path();
        if let Some(uid) = my_uid
            && let Ok(status) = fs::read_to_string(proc_dir.join("status"))
        {
            let proc_uid = status
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|r| r.split_whitespace().next())
                .and_then(|s| s.parse::<u32>().ok());
            if proc_uid != Some(uid) {
                continue;
            }
        }
        let comm_lc = fs::read_to_string(proc_dir.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let exe_lc = fs::read_link(proc_dir.join("exe"))
            .ok()
            .map(|p| p.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let cmdline_lc = fs::read(proc_dir.join("cmdline"))
            .ok()
            .map(|bytes| {
                bytes
                    .into_iter()
                    .map(|b| if b == 0 { b' ' } else { b })
                    .collect::<Vec<u8>>()
            })
            .map(|b| String::from_utf8_lossy(&b).to_ascii_lowercase())
            .unwrap_or_default();

        if !comm_lc.is_empty() || !exe_lc.is_empty() {
            out.push(RunningProcessEntry {
                pid,
                comm_lc,
                exe_lc,
                cmdline_lc,
            });
        }
    }
    out
}

/// Detect companion CLI tools installed across `/usr/bin`, `/usr/local/bin`, `/snap/bin`, `/opt`, and `~/.local/bin`.
pub fn detect_companion_cli_tools() -> Vec<CompanionCliTool> {
    let specs: &[(&str, &str, &str)] = &[
        (
            "libreoffice",
            "office_notes_doc",
            "LibreOffice 无头文档/PDF 转换引擎",
        ),
        (
            "evince",
            "office_notes_doc",
            "GNOME Evince PDF 页码跳转与全文检索",
        ),
        (
            "pdfarranger",
            "office_notes_doc",
            "PDF Arranger 页面合并与拆分工具",
        ),
        (
            "drawio",
            "creative_disc",
            "draw.io 流程图无头导出与编辑 CLI",
        ),
        (
            "VBoxManage",
            "remote_vm",
            "Oracle VirtualBox 虚拟机生命周期控制 CLI",
        ),
        (
            "rustdesk",
            "remote_vm",
            "RustDesk 远程桌面设备 ID 与受控连接 CLI",
        ),
        (
            "fcitx5-remote",
            "hardware_system",
            "Fcitx5 中文输入法状态探针与热切换 CLI",
        ),
        (
            "fcitx5-configtool",
            "hardware_system",
            "Fcitx5 输入法配置中心",
        ),
        (
            "nvidia-smi",
            "hardware_system",
            "NVIDIA GPU 温度/显存/利用率实时遥测 CLI",
        ),
        ("nvidia-settings", "hardware_system", "NVIDIA 显卡设置面板"),
        (
            "tailscale",
            "network_browser",
            "Tailscale 组网状态与虚拟 IP 查询 CLI",
        ),
        (
            "localsend_app",
            "cloud_transfer",
            "LocalSend 局域网高速传文件工具",
        ),
        (
            "code",
            "dev_ai_ide",
            "VS Code 工作区/行列跳转/双文件 Diff CLI",
        ),
        ("trae-cn", "dev_ai_ide", "Trae CN AI IDE CLI"),
        ("zcode", "dev_ai_ide", "ZCode AI IDE CLI"),
        (
            "nautilus",
            "hardware_system",
            "GNOME Files 文件定位与窗口唤起 CLI",
        ),
        (
            "vlc",
            "media_entertainment",
            "VLC 媒体播放与 MPRIS 控制 CLI",
        ),
    ];

    let mut found = Vec::new();
    for (bin_name, cat_id, desc) in specs {
        if let Some(resolved) = resolve_desktop_binary(bin_name) {
            found.push(CompanionCliTool {
                name: (*bin_name).to_string(),
                binary_path: resolved.to_string_lossy().to_string(),
                category_id: (*cat_id).to_string(),
                description: (*desc).to_string(),
            });
        }
    }
    found
}

fn match_running_pids(
    rec: &RawDesktopRecord,
    procs: &[RunningProcessEntry],
    matched_adapter_cli: &[String],
) -> Vec<u32> {
    let bin_base = Path::new(&rec.exec_binary)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&rec.exec_binary)
        .to_ascii_lowercase();
    let bin_full = rec.exec_binary.to_ascii_lowercase();
    let wm_lc = rec
        .startup_wm_class
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();

    // Avoid false-positive matching on generic launcher binaries (`google-chrome` for PWAs unless `--app-id=` matches)
    if rec.desktop_id.starts_with("chrome-") {
        if let Some(app_id) = rec
            .exec_raw
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("--app-id="))
        {
            let needle = format!("--app-id={}", app_id.to_ascii_lowercase());
            let mut pids: Vec<u32> = procs
                .iter()
                .filter(|p| p.cmdline_lc.contains(&needle))
                .map(|p| p.pid)
                .collect();
            pids.sort_unstable();
            pids.dedup();
            return pids;
        }
        return Vec::new();
    }

    let mut pids = Vec::new();
    for p in procs {
        let matched = (!bin_full.is_empty() && bin_full.starts_with('/') && p.exe_lc == bin_full)
            || (!bin_base.is_empty()
                && bin_base.len() >= 2
                && !matches!(bin_base.as_str(), "env" | "flatpak" | "snap" | "xdg-open")
                && (p.comm_lc == bin_base || p.exe_lc.ends_with(&format!("/{}", bin_base))))
            || (!wm_lc.is_empty() && wm_lc.len() >= 3 && p.comm_lc == wm_lc)
            || matched_adapter_cli.iter().any(|cli| {
                let c_lc = cli.to_ascii_lowercase();
                c_lc.len() >= 3 && (p.comm_lc == c_lc || p.exe_lc.ends_with(&format!("/{}", c_lc)))
            });
        if matched {
            pids.push(p.pid);
        }
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}

fn match_tray_entry<'a>(
    rec: &RawDesktopRecord,
    matched_adapter_id: Option<&str>,
    tray_apps: &'a [LiveTrayApp],
) -> Option<&'a LiveTrayApp> {
    let stem_lc = rec.stem_id.to_ascii_lowercase();
    let bin_base = Path::new(&rec.exec_binary)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&rec.exec_binary)
        .to_ascii_lowercase();
    let name_lc = rec.name.to_ascii_lowercase();
    let zh = rec.name_zh.as_deref().unwrap_or("");

    tray_apps.iter().find(|t| {
        let t_id = t.id.to_ascii_lowercase();
        let t_title = t.title.to_ascii_lowercase();
        let t_proc = t.comm.as_deref().unwrap_or("").to_ascii_lowercase();

        if let Some(aid) = matched_adapter_id {
            let aid_lc = aid.to_ascii_lowercase();
            if !aid_lc.is_empty() && (t_id == aid_lc || t_proc == aid_lc) {
                return true;
            }
        }

        (!stem_lc.is_empty() && stem_lc.len() >= 2 && (t_id == stem_lc || t_proc == stem_lc))
            || (!bin_base.is_empty()
                && bin_base.len() >= 2
                && (t_proc == bin_base || t_id.contains(&bin_base)))
            || (!zh.is_empty() && t.title.contains(zh))
            || (!name_lc.is_empty() && name_lc.len() >= 3 && t_title.contains(&name_lc))
            || (stem_lc.starts_with("wps-office") && t_proc == "wpscloudsvr")
    })
}

fn match_mpris_service(
    rec: &RawDesktopRecord,
    matched_mpris_names: &[String],
    active_mpris: &[String],
) -> Option<String> {
    let stem_lc = rec.stem_id.to_ascii_lowercase();
    let bin_base = Path::new(&rec.exec_binary)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&rec.exec_binary)
        .to_ascii_lowercase();

    for svc in active_mpris {
        let svc_lc = svc.to_ascii_lowercase();
        if matched_mpris_names
            .iter()
            .any(|m| svc_lc.contains(&m.to_ascii_lowercase()))
            || (!stem_lc.is_empty() && stem_lc.len() >= 3 && svc_lc.contains(&stem_lc))
            || (!bin_base.is_empty() && bin_base.len() >= 3 && svc_lc.contains(&bin_base))
        {
            return Some(svc.clone());
        }
    }
    None
}

fn find_matching_adapter_profile<'a>(
    rec: &RawDesktopRecord,
    registry: &'a AdapterRegistry,
) -> Option<&'a AppAdapterProfile> {
    let desktop_id_lc = rec.desktop_id.to_ascii_lowercase();
    let stem_lc = rec.stem_id.to_ascii_lowercase();
    let bin_base = Path::new(&rec.exec_binary)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&rec.exec_binary)
        .to_ascii_lowercase();

    let all_profiles = registry.all_profiles();

    // 1. Exact `desktop_ids` match
    if let Some(p) = all_profiles.iter().copied().find(|p| {
        p.desktop_ids.iter().any(|d| {
            let dlc = d.to_ascii_lowercase();
            dlc == desktop_id_lc || dlc.trim_end_matches(".desktop") == stem_lc
        })
    }) {
        return Some(p);
    }

    // 2. Profile `id` or `cli_executables` match (skipping generic `google-chrome` on PWAs)
    if !desktop_id_lc.starts_with("chrome-") {
        if let Some(p) = all_profiles.iter().copied().find(|p| {
            p.id.eq_ignore_ascii_case(&stem_lc)
                || (!bin_base.is_empty()
                    && p.cli_executables
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(&bin_base)))
        }) {
            return Some(p);
        }
    } else if let Some(ref zh) = rec.name_zh {
        if let Some(p) = all_profiles.iter().copied().find(|p| {
            p.name.eq_ignore_ascii_case(zh) || p.aliases.iter().any(|a| a.eq_ignore_ascii_case(zh))
        }) {
            return Some(p);
        }
    } else if let Some(p) = all_profiles.iter().copied().find(|p| {
        p.name.eq_ignore_ascii_case(&rec.name)
            || p.aliases.iter().any(|a| a.eq_ignore_ascii_case(&rec.name))
    }) {
        return Some(p);
    }

    None
}

fn synthesize_actions_and_channels(
    rec: &RawDesktopRecord,
    matched_profile: Option<&AppAdapterProfile>,
    tray_entry: Option<&LiveTrayApp>,
    mpris_service: Option<&str>,
) -> (Vec<String>, Vec<SynthesizedActionSpec>) {
    let mut channel_set = Vec::new();
    let mut push_chan = |ch: &str| {
        if !channel_set.iter().any(|c| c == ch) {
            channel_set.push(ch.to_string());
        }
    };

    let mut specs: Vec<SynthesizedActionSpec> = Vec::new();
    let mut seen_actions = BTreeSet::new();
    let mut push_spec = |spec: SynthesizedActionSpec| {
        if seen_actions.insert(spec.action.clone()) {
            specs.push(spec);
        }
    };

    // 1. Merge curated adapter profile channels & rich semantic actions first
    if let Some(prof) = matched_profile {
        for ch in &prof.channels {
            push_chan(ch.as_str());
        }
        for sa in &prof.supported_actions {
            push_spec(SynthesizedActionSpec {
                action: sa.action.clone(),
                label: sa.summary.clone(),
                channel: sa.channel.as_str().to_string(),
                description: sa.summary.clone(),
                requires_approval: sa.requires_approval,
                source: format!("curated_profile:{}", prof.id),
            });
        }
    }

    // 2. Universal `.desktop` launch / focus / quit capabilities on EVERY discovered app
    push_chan("cli_wrapper");
    push_chan("gui_atspi");

    push_spec(SynthesizedActionSpec {
        action: "launch_app".into(),
        label: "启动应用".into(),
        channel: "cli_wrapper".into(),
        description: format!(
            "使用纯净桌面环境启动「{}」",
            rec.name_zh.as_deref().unwrap_or(&rec.name)
        ),
        requires_approval: false,
        source: "desktop_entry".into(),
    });
    push_spec(SynthesizedActionSpec {
        action: "focus_window".into(),
        label: "唤起/置顶主窗口".into(),
        channel: if tray_entry.is_some() {
            "sni_dbusmenu".into()
        } else {
            "gui_atspi".into()
        },
        description: "优先从托盘或窗口管理器激活主窗口，未运行时自动启动".into(),
        requires_approval: false,
        source: "desktop_entry".into(),
    });
    push_spec(SynthesizedActionSpec {
        action: "quit".into(),
        label: "优雅关闭应用".into(),
        channel: "process_lifecycle".into(),
        description: "多阶段安全关闭应用并回读 /proc 验证退出".into(),
        requires_approval: false,
        source: "desktop_entry".into(),
    });

    // 3. Auto-synthesize from `[Desktop Action <sec_id>]`
    if !rec.desktop_actions.is_empty() {
        push_chan("desktop_action");
        for da in &rec.desktop_actions {
            push_spec(SynthesizedActionSpec {
                action: format!("desktop_action:{}", da.action_id),
                label: da.display_name.clone(),
                channel: "desktop_action".into(),
                description: format!(
                    "执行 .desktop 快捷动作 [{}]: {}",
                    da.action_id, da.display_name
                ),
                requires_approval: false,
                source: format!("desktop_action:{}", da.action_id),
            });
        }
    }

    // 4. Auto-synthesize from `x-scheme-handler/<scheme>`
    if !rec.uri_schemes.is_empty() {
        push_chan("uri_scheme");
        for scheme in &rec.uri_schemes {
            push_spec(SynthesizedActionSpec {
                action: format!("open_{}_uri", scheme.replace(['.', '-', '+'], "_")),
                label: format!("打开 {}:// 协议链接", scheme),
                channel: "uri_scheme".into(),
                description: format!("通过安全校验后调起 `{}://` 深度链接", scheme),
                requires_approval: false,
                source: format!("mime_scheme:{}", scheme),
            });
        }
        push_spec(SynthesizedActionSpec {
            action: "open_uri".into(),
            label: "打开深度链接 URI".into(),
            channel: "uri_scheme".into(),
            description: format!("支持协议: {}", rec.uri_schemes.join(", ")),
            requires_approval: false,
            source: "mime_scheme".into(),
        });
    }

    // 5. Auto-synthesize `open_file` when MIME types are declared
    if !rec.supported_mime_types.is_empty() {
        push_spec(SynthesizedActionSpec {
            action: "open_file".into(),
            label: "打开本地文件".into(),
            channel: "cli_wrapper".into(),
            description: format!(
                "使用该应用打开受支持文件（共声明 {} 种 MIME 类型）",
                rec.supported_mime_types.len()
            ),
            requires_approval: false,
            source: "mime_types".into(),
        });
    }

    // 6. Live SNI tray capabilities
    if tray_entry.is_some() {
        push_chan("sni_dbusmenu");
        push_spec(SynthesizedActionSpec {
            action: "click_tray_menu".into(),
            label: "触发系统托盘菜单项".into(),
            channel: "sni_dbusmenu".into(),
            description: "读取并点击 StatusNotifierItem / dbusmenu 实时托盘菜单项".into(),
            requires_approval: false,
            source: "live_sni_dbusmenu".into(),
        });
        push_spec(SynthesizedActionSpec {
            action: "list_tray_menus".into(),
            label: "列出实时托盘菜单".into(),
            channel: "sni_dbusmenu".into(),
            description: "内省当前驻留托盘菜单树".into(),
            requires_approval: false,
            source: "live_sni_dbusmenu".into(),
        });
    }

    // 7. Live MPRIS media player capabilities
    if mpris_service.is_some() {
        push_chan("dbus_mpris");
        for (act, lbl) in [
            ("play_pause", "播放/暂停"),
            ("next", "下一首"),
            ("previous", "上一首"),
            ("get_now_playing", "查询当前播放曲目"),
        ] {
            push_spec(SynthesizedActionSpec {
                action: act.into(),
                label: lbl.into(),
                channel: "dbus_mpris".into(),
                description: format!("通过实时 MPRIS2 总线执行「{}」", lbl),
                requires_approval: false,
                source: "live_mpris2".into(),
            });
        }
    }

    (channel_set, specs)
}

fn collect_scan_directories(
    config_dir: Option<&Path>,
    options: &LocalScanOptions,
) -> Vec<(PathBuf, &'static str)> {
    if !options.scan_dirs.is_empty() {
        return options
            .scan_dirs
            .iter()
            .map(|p| {
                let s = p.to_string_lossy();
                let kind = if s.contains("snapd") {
                    "snap"
                } else if s.contains("flatpak") {
                    "flatpak"
                } else if s.contains(".local") || s.contains("user") {
                    "user_local"
                } else {
                    "system_apt"
                };
                (p.clone(), kind)
            })
            .collect();
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    // Ordered from lowest priority to highest priority so `~/.local/share/applications` overrides `/usr/share/applications`!
    let mut dirs = vec![
        (
            PathBuf::from("/var/lib/flatpak/exports/share/applications"),
            "flatpak",
        ),
        (
            PathBuf::from(&home).join(".local/share/flatpak/exports/share/applications"),
            "flatpak",
        ),
        (PathBuf::from("/var/lib/snapd/desktop/applications"), "snap"),
        (PathBuf::from("/usr/share/applications"), "system_apt"),
        (PathBuf::from("/usr/local/share/applications"), "system_apt"),
        (
            PathBuf::from(&home).join(".local/share/applications"),
            "user_local",
        ),
    ];

    if let Some(cfg) = config_dir {
        let cfg_apps = cfg.join("applications");
        if cfg_apps.is_dir() {
            dirs.push((cfg_apps, "user_local"));
        }
        if let Some(parent) = cfg.parent() {
            let parent_apps = parent.join("applications");
            if parent_apps.is_dir() {
                dirs.push((parent_apps, "user_local"));
            }
        }
    }

    for extra in &options.extra_dirs {
        dirs.push((extra.clone(), "user_local"));
    }

    dirs
}

fn filter_catalog(
    mut catalog: DeepScanCatalog,
    options: &LocalScanOptions,
    cached: bool,
) -> DeepScanCatalog {
    catalog.cached = cached;

    let cat_filter = options
        .category
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all") && *s != "全部");
    let query_lc = options
        .query
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase);

    if cat_filter.is_some() || query_lc.is_some() || options.only_running {
        catalog.apps.retain(|app| {
            if options.only_running && !app.is_running {
                return false;
            }
            if let Some(cf) = cat_filter
                && !categories_match(&app.category_id, cf)
            {
                return false;
            }
            if let Some(ref q) = query_lc {
                let matched = app.display_name.to_ascii_lowercase().contains(q)
                    || app.name.to_ascii_lowercase().contains(q)
                    || app
                        .name_zh
                        .as_deref()
                        .is_some_and(|z| z.to_ascii_lowercase().contains(q))
                    || app.desktop_id.to_ascii_lowercase().contains(q)
                    || app.exec_binary.to_ascii_lowercase().contains(q)
                    || app.category_zh.to_ascii_lowercase().contains(q)
                    || app
                        .comment
                        .as_deref()
                        .is_some_and(|c| c.to_ascii_lowercase().contains(q))
                    || app
                        .aliases
                        .iter()
                        .any(|a| a.to_ascii_lowercase().contains(q))
                    || app
                        .actions
                        .iter()
                        .any(|a| a.to_ascii_lowercase().contains(q))
                    || app
                        .synthesized_actions
                        .iter()
                        .any(|sa| sa.label.to_ascii_lowercase().contains(q));
                if !matched {
                    return false;
                }
            }
            true
        });
    }

    catalog.filtered_count = catalog.apps.len();
    catalog
}

/// Clear the global 120s deep-scan cache (useful in tests or when custom adapters change).
pub fn clear_deep_scan_cache() {
    if let Ok(mut g) = deep_scan_cache().lock() {
        g.clear();
    }
}

/// Perform a deep multi-source scan of all local software, classify into the 9 AIOS categories,
/// correlate live runtime state (SNI + MPRIS + `/proc`), and synthesize rich executable interfaces.
///
/// Uses a directory-mtime + `120s` TTL cache and an async single-flight coalescing mutex (`H09.3`)
/// so repeated or concurrent calls never launch duplicate full `/usr/share/applications` + Snap + Flatpak scans.
pub async fn deep_scan_local_software(
    config_dir: Option<&Path>,
    registry: &AdapterRegistry,
    options: &LocalScanOptions,
) -> DeepScanCatalog {
    let request_started_at = Instant::now();
    let scan_dirs = collect_scan_directories(config_dir, options);
    let cache_key = ScanCacheKey {
        dirs_list: scan_dirs.clone(),
        include_hidden: options.include_hidden,
    };

    if !options.force_refresh {
        let fast_fp = compute_scan_dirs_fingerprint(&scan_dirs, registry);
        if let Ok(guard) = deep_scan_cache().lock()
            && let Some(state) = guard.get(&cache_key)
            && state.dirs_fingerprint == fast_fp
            && state.created_at.elapsed() < SCAN_CACHE_TTL
        {
            return filter_catalog(state.catalog.clone(), options, true);
        }
    }

    // Single-flight coalescing guard: serialize full scans so concurrent callers coalesce onto one pass.
    let _singleflight_guard = deep_scan_singleflight().lock().await;
    let dirs_fingerprint = compute_scan_dirs_fingerprint(&scan_dirs, registry);
    if let Ok(guard) = deep_scan_cache().lock()
        && let Some(state) = guard.get(&cache_key)
        && state.dirs_fingerprint == dirs_fingerprint
        && ((!options.force_refresh && state.created_at.elapsed() < SCAN_CACHE_TTL)
            || state.created_at >= request_started_at)
    {
        return filter_catalog(state.catalog.clone(), options, true);
    }

    DEEP_SCAN_EXECUTION_COUNT.fetch_add(1, Ordering::AcqRel);

    // 1. Read & parse `.desktop` entries across all configured sources; higher-priority dirs override lower-priority dirs while merging metadata.
    let mut merged_by_id: BTreeMap<String, RawDesktopRecord> = BTreeMap::new();
    for (dir, kind) in &scan_dirs {
        let Ok(rd) = fs::read_dir(dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if p.extension().and_then(|s| s.to_str()) != Some("desktop") {
                continue;
            }
            let Some(rec) = parse_raw_desktop_file(&p, kind) else {
                continue;
            };
            let key = rec.desktop_id.clone();
            if let Some(existing) = merged_by_id.get(&key) {
                let combined = merge_user_override(rec, existing);
                merged_by_id.insert(key, combined);
            } else {
                merged_by_id.insert(key, rec);
            }
        }
    }

    // 2. Harvest `x-scheme-handler/*` from hidden URL-handler companion `.desktop` files onto their visible parent apps.
    let mut harvested_schemes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rec in merged_by_id.values() {
        if !rec.uri_schemes.is_empty() {
            for parent_stem in url_handler_parent_candidates(&rec.stem_id) {
                let entry = harvested_schemes.entry(parent_stem).or_default();
                for s in &rec.uri_schemes {
                    if !entry.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                        entry.push(s.clone());
                    }
                }
            }
        }
    }
    for rec in merged_by_id.values_mut() {
        let stem_lc = rec.stem_id.to_ascii_lowercase();
        if let Some(extra_schemes) = harvested_schemes.get(&stem_lc) {
            for s in extra_schemes {
                if !rec.uri_schemes.iter().any(|x| x.eq_ignore_ascii_case(s)) {
                    rec.uri_schemes.push(s.clone());
                }
            }
        }
    }

    // 3. Gather live runtime state cleanly
    let tray_apps = if options.scan_dirs.is_empty() {
        discover_live_tray_apps().await
    } else {
        Vec::new()
    };
    let active_mpris = if options.scan_dirs.is_empty() {
        discover_active_mpris_services().await.services
    } else {
        Vec::new()
    };
    let running_procs = snapshot_user_running_processes();
    let companion_cli_tools = detect_companion_cli_tools();

    // 4. Filter visible entries, classify into 9 categories, correlate runtime & synthesize actions
    let mut apps = Vec::new();
    let mut total_interfaces = 0usize;
    let mut total_adapted = 0usize;
    let mut running_count = 0usize;
    let mut cat_counts: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
    for cat in ALL_SOFTWARE_CATEGORIES {
        cat_counts.insert(cat.id, (0, 0));
    }

    for rec in merged_by_id.into_values() {
        let _ = &rec.entry_type;
        if is_pure_uninstaller_entry(&rec) && !options.include_hidden {
            continue;
        }
        if !options.include_hidden && (rec.no_display || rec.hidden) {
            continue;
        }

        let (install_source, source_badge) = determine_install_source(&rec);
        let cat_meta = classify_software_category(
            &rec.desktop_id,
            &rec.exec_binary,
            &rec.name,
            rec.name_zh.as_deref(),
            rec.startup_wm_class.as_deref(),
            &rec.uri_schemes,
            &rec.supported_mime_types,
            &rec.freedesktop_categories,
        );

        let matched_profile = find_matching_adapter_profile(&rec, registry);
        let matched_adapter_id = matched_profile.map(|p| p.id.clone());
        let matched_cli_list = matched_profile
            .map(|p| p.cli_executables.clone())
            .unwrap_or_default();
        let matched_mpris_list = matched_profile
            .map(|p| p.mpris_bus_hints.clone())
            .unwrap_or_default();

        let tray_hit = match_tray_entry(&rec, matched_adapter_id.as_deref(), &tray_apps);
        let mpris_hit = match_mpris_service(&rec, &matched_mpris_list, &active_mpris);
        let running_pids = match_running_pids(&rec, &running_procs, &matched_cli_list);
        let is_running = tray_hit.is_some() || mpris_hit.is_some() || !running_pids.is_empty();

        let (channels, synthesized_actions) =
            synthesize_actions_and_channels(&rec, matched_profile, tray_hit, mpris_hit.as_deref());

        let actions: Vec<String> = synthesized_actions
            .iter()
            .map(|s| s.action.clone())
            .collect();
        let capabilities = synthesized_actions.clone();
        let translatable_actions = synthesized_actions.clone();

        let mut aliases: Vec<String> = Vec::new();
        let mut push_alias = |cand: &str| {
            let t = cand.trim();
            if !t.is_empty() && !aliases.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                aliases.push(t.to_string());
            }
        };
        if let Some(prof) = matched_profile {
            for a in &prof.aliases {
                push_alias(a);
            }
        }
        push_alias(&rec.name);
        if let Some(ref zh) = rec.name_zh {
            push_alias(zh);
        }
        push_alias(&rec.stem_id);

        let display_name = match &rec.name_zh {
            Some(zh) if !zh.trim().is_empty() => zh.clone(),
            _ => rec.name.clone(),
        };

        let companion_clis: Vec<String> = matched_cli_list
            .iter()
            .filter(|c| resolve_desktop_binary(c).is_some())
            .cloned()
            .collect();

        total_interfaces += synthesized_actions.len();
        if !synthesized_actions.is_empty() {
            total_adapted += 1;
        }
        if is_running {
            running_count += 1;
        }
        if let Some(entry_counts) = cat_counts.get_mut(cat_meta.id) {
            entry_counts.0 += 1;
            if is_running {
                entry_counts.1 += 1;
            }
        }

        apps.push(ScannedSoftwareEntry {
            id: matched_adapter_id
                .clone()
                .unwrap_or_else(|| rec.stem_id.clone()),
            desktop_id: rec.desktop_id,
            desktop_path: rec.desktop_path.to_string_lossy().to_string(),
            install_source: install_source.to_string(),
            source_badge: source_badge.to_string(),
            name: rec.name,
            name_zh: rec.name_zh,
            display_name,
            comment: rec.comment_zh.or(rec.comment),
            exec_raw: rec.exec_raw,
            exec_binary: rec.exec_binary,
            env_overrides: rec.env_overrides,
            icon: rec.icon,
            startup_wm_class: rec.startup_wm_class,
            dbus_activatable: rec.dbus_activatable,
            category_id: cat_meta.id.to_string(),
            category: cat_meta.id.to_string(),
            category_zh: cat_meta.category_zh.to_string(),
            category_icon: cat_meta.icon.to_string(),
            desktop_actions: rec.desktop_actions,
            uri_schemes: rec.uri_schemes,
            supported_mime_types: rec.supported_mime_types,
            freedesktop_categories: rec.freedesktop_categories,
            matched_adapter_id,
            aliases,
            channels,
            capabilities,
            actions,
            synthesized_actions,
            translatable_actions,
            is_running,
            running: is_running,
            running_pids,
            tray_service: tray_hit.map(|t| t.service.clone()),
            tray_title: tray_hit.map(|t| t.title.clone()),
            tray_menu_items: tray_hit.map(|t| t.menu_items.clone()).unwrap_or_default(),
            mpris_service: mpris_hit,
            companion_clis,
        });
    }

    // Sort running apps first, then curated apps, then alphabetically by display_name
    apps.sort_by(|a, b| {
        b.is_running
            .cmp(&a.is_running)
            .then_with(|| {
                b.matched_adapter_id
                    .is_some()
                    .cmp(&a.matched_adapter_id.is_some())
            })
            .then_with(|| {
                a.display_name
                    .to_lowercase()
                    .cmp(&b.display_name.to_lowercase())
            })
    });

    let categories: Vec<CategoryScanSummary> = ALL_SOFTWARE_CATEGORIES
        .iter()
        .map(|c| {
            let (count, run_cnt) = cat_counts.get(c.id).copied().unwrap_or((0, 0));
            CategoryScanSummary {
                id: c.id.to_string(),
                category_id: c.id.to_string(),
                name_zh: c.category_zh.to_string(),
                category_zh: c.category_zh.to_string(),
                short_zh: c.short_zh.to_string(),
                icon: c.icon.to_string(),
                category_icon: c.icon.to_string(),
                count,
                running_count: run_cnt,
            }
        })
        .collect();

    let total_scanned = apps.len();
    let full_catalog = DeepScanCatalog {
        total_scanned,
        total_apps: total_scanned,
        total_adapted,
        total_interfaces,
        total_actions_count: total_interfaces,
        translatable_actions_total: total_interfaces,
        running_count,
        running_apps: running_count,
        filtered_count: total_scanned,
        categories,
        apps,
        companion_cli_tools,
        scanned_at: Utc::now().to_rfc3339(),
        cached: false,
    };

    if let Ok(mut guard) = deep_scan_cache().lock() {
        if guard.len() >= 16
            && !guard.contains_key(&cache_key)
            && let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(k, _)| k.clone())
        {
            guard.remove(&oldest_key);
        }
        guard.insert(
            cache_key,
            CachedScanState {
                created_at: Instant::now(),
                dirs_fingerprint,
                catalog: full_catalog.clone(),
            },
        );
    }

    filter_catalog(full_catalog, options, false)
}

// ============================================================================
// Rich Interface Translation & Execution Engine
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn make_outcome(
    app_id: &str,
    app_name: &str,
    action: &str,
    channel: AdaptationChannel,
    ok: bool,
    requires_approval: bool,
    approval_scope: Option<GuiApprovalScope>,
    translated_command: String,
    summary: String,
    data: Value,
    simulated: bool,
    verification: VerificationReport,
) -> AdapterExecutionOutcome {
    let trace_dot = if requires_approval {
        AdapterTraceDot {
            kind: "approval".into(),
            color: "orange".into(),
            title: format!("待审批: {} · {}", app_name, action),
            detail: summary.clone(),
        }
    } else if ok {
        AdapterTraceDot {
            kind: "adapter".into(),
            color: "cyan".into(),
            title: format!("转译层 ({}): {} · {}", channel.as_str(), app_name, action),
            detail: format!("{}\n`{}`", summary, translated_command),
        }
    } else {
        AdapterTraceDot {
            kind: "tool_err".into(),
            color: "red".into(),
            title: format!("转译失败: {} · {}", app_name, action),
            detail: summary.clone(),
        }
    };

    AdapterExecutionOutcome {
        ok,
        requires_approval,
        approval_scope,
        channel_used: channel.as_str().to_string(),
        app_id: app_id.to_string(),
        app_name: app_name.to_string(),
        intent_action: action.to_string(),
        translated_command,
        summary,
        data,
        simulated,
        verification,
        trace_dot,
        changeset_id: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_approval_outcome(
    app_id: &str,
    app_name: &str,
    action: &str,
    channel: AdaptationChannel,
    target_detail: &str,
    translated_command: String,
    reason: String,
    data: Value,
) -> AdapterExecutionOutcome {
    let scope = GuiApprovalScope {
        scope_id: format!("app_adapter:{}:{}", app_id, action),
        app_id: app_id.to_string(),
        app_name: app_name.to_string(),
        action: action.to_string(),
        target_detail: target_detail.to_string(),
        risk_badge: "sensitive_approval".into(),
        description: reason.clone(),
    };
    make_outcome(
        app_id,
        app_name,
        action,
        channel,
        false,
        true,
        Some(scope),
        translated_command,
        reason.clone(),
        data,
        false,
        VerificationReport {
            state: VerificationState::Skipped,
            method: "rich_adapter_approval_gate".into(),
            checks: vec!["sensitive_app_operation_requires_user_approval".into()],
            details: Some(reason),
        },
    )
}

fn build_error_outcome(
    app_id: &str,
    app_name: &str,
    action: &str,
    channel: AdaptationChannel,
    msg: impl Into<String>,
) -> AdapterExecutionOutcome {
    let m = msg.into();
    make_outcome(
        app_id,
        app_name,
        action,
        channel,
        false,
        false,
        None,
        String::new(),
        m.clone(),
        json!({ "error": m }),
        false,
        VerificationReport {
            state: VerificationState::VerificationFailed,
            method: "rich_local_adapter_validation".into(),
            checks: vec!["input_and_policy_check".into()],
            details: Some(m),
        },
    )
}

fn is_dry_run(params: &Value) -> bool {
    params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn spawn_or_preview_gui_command(
    app_id: &str,
    app_name: &str,
    action: &str,
    channel: AdaptationChannel,
    bin_candidates: &[&str],
    args: &[String],
    env_pairs: &[(String, String)],
    dry_run: bool,
    extra_data: Value,
) -> AdapterExecutionOutcome {
    let primary_bin = bin_candidates.first().copied().unwrap_or(app_id);
    let env_prefix = if env_pairs.is_empty() {
        String::new()
    } else {
        let kv: Vec<String> = env_pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        format!("env {} ", kv.join(" "))
    };
    let translated_command = if args.is_empty() {
        format!("{}{}", env_prefix, primary_bin)
    } else {
        format!("{}{} {}", env_prefix, primary_bin, args.join(" "))
    };

    let resolved = bin_candidates
        .iter()
        .find_map(|c| resolve_desktop_binary(c));

    if !dry_run
        && has_gui_session()
        && let Some(ref resolved_bin) = resolved
    {
        let mut cmd = StdCommand::new(resolved_bin);
        apply_clean_desktop_env_std(&mut cmd);
        for (k, v) in env_pairs {
            cmd.env(k, v);
        }
        if cmd.args(args).spawn().is_ok() {
            return make_outcome(
                app_id,
                app_name,
                action,
                channel,
                true,
                false,
                None,
                translated_command,
                format!("已为「{}」执行动作 `{}`", app_name, action),
                json!({
                    "executable": resolved_bin,
                    "args": args,
                    "env": env_pairs.iter().cloned().collect::<BTreeMap<_, _>>(),
                    "context": extra_data,
                }),
                false,
                VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "clean_desktop_spawn".into(),
                    checks: vec![
                        "non_shell_discrete_argv".into(),
                        "clean_desktop_env_applied".into(),
                    ],
                    details: Some("桌面应用指令已异步派发".into()),
                },
            );
        }
    }

    make_outcome(
        app_id,
        app_name,
        action,
        channel,
        true,
        false,
        None,
        translated_command,
        format!(
            "已完成「{}」动作 `{}` 的参数转译与安全校验（预演模式）",
            app_name, action
        ),
        json!({
            "executable": resolved.map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| primary_bin.to_string()),
            "args": args,
            "env": env_pairs.iter().cloned().collect::<BTreeMap<_, _>>(),
            "context": extra_data,
        }),
        true,
        VerificationReport {
            state: VerificationState::RequestedUnverified,
            method: "simulated_clean_desktop_spawn".into(),
            checks: vec![
                "non_shell_discrete_argv".into(),
                "clean_desktop_env_applied".into(),
            ],
            details: Some("无头环境或显式 dry_run，已生成非 Shell 安全指令".into()),
        },
    )
}

fn validate_non_forbidden_path(core: &IntentOsCore, raw: &str) -> anyhow::Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        anyhow::bail!("文件路径不能为空或包含非法字符");
    }
    let expanded = if let Some(rest) = trimmed.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(trimmed)
    };
    if core.fs_engine.is_forbidden(&expanded) {
        anyhow::bail!("安全内核拦截：禁止访问敏感路径 `{}`", expanded.display());
    }
    Ok(expanded)
}

/// Find a scanned software entry by `desktop_id`, `id`, `name_zh`, `name`, or `exec_binary`.
pub async fn find_scanned_app(
    core: &IntentOsCore,
    registry: &AdapterRegistry,
    target_app: &str,
) -> Option<ScannedSoftwareEntry> {
    let q = target_app.trim();
    if q.is_empty() {
        return None;
    }
    let catalog = deep_scan_local_software(
        Some(&core.paths.config_dir),
        registry,
        &LocalScanOptions::default(),
    )
    .await;

    let q_lc = q.to_ascii_lowercase();
    let q_stem = q_lc.trim_end_matches(".desktop");

    catalog
        .apps
        .iter()
        .find(|a| {
            a.desktop_id.eq_ignore_ascii_case(q)
                || a.desktop_id
                    .trim_end_matches(".desktop")
                    .eq_ignore_ascii_case(q_stem)
                || a.id.eq_ignore_ascii_case(q_stem)
                || a.display_name.eq_ignore_ascii_case(q)
                || a.name.eq_ignore_ascii_case(q)
                || a.name_zh
                    .as_deref()
                    .is_some_and(|z| z.eq_ignore_ascii_case(q))
        })
        .or_else(|| {
            catalog.apps.iter().find(|a| {
                a.display_name.to_ascii_lowercase().contains(&q_lc)
                    || a.name.to_ascii_lowercase().contains(&q_lc)
                    || a.desktop_id.to_ascii_lowercase().contains(&q_lc)
            })
        })
        .cloned()
}

/// Execute a specific `.desktop` action (`[Desktop Action <action_id>]` or `"launch_app"`) by `desktop_id`.
pub async fn execute_desktop_action_by_id(
    core: &IntentOsCore,
    registry: &AdapterRegistry,
    desktop_id: &str,
    action_id: &str,
    params: &Value,
    extra_scan_dirs: &[PathBuf],
) -> AdapterExecutionOutcome {
    let mut scan_opts = LocalScanOptions::default();
    if !extra_scan_dirs.is_empty() {
        scan_opts.extra_dirs = extra_scan_dirs.to_vec();
        scan_opts.force_refresh = true;
    }
    let catalog =
        deep_scan_local_software(Some(&core.paths.config_dir), registry, &scan_opts).await;

    let q_lc = desktop_id.trim().to_ascii_lowercase();
    let q_stem = q_lc.trim_end_matches(".desktop");
    let Some(entry) = catalog.apps.into_iter().find(|a| {
        a.desktop_id.eq_ignore_ascii_case(desktop_id.trim())
            || a.desktop_id
                .trim_end_matches(".desktop")
                .eq_ignore_ascii_case(q_stem)
            || a.id.eq_ignore_ascii_case(q_stem)
    }) else {
        return build_error_outcome(
            desktop_id,
            desktop_id,
            action_id,
            AdaptationChannel::DesktopAction,
            format!("未在本机软件目录中找到 `{}`", desktop_id),
        );
    };

    let clean_act_id = action_id
        .trim()
        .strip_prefix("desktop_action:")
        .unwrap_or(action_id.trim());

    let optional_target = if let Some(u) = params
        .get("url")
        .or_else(|| params.get("uri"))
        .and_then(|v| v.as_str())
    {
        match validate_uri_safety(u, &entry.uri_schemes) {
            Ok(valid) => Some(valid),
            Err(e) => {
                return build_error_outcome(
                    &entry.id,
                    &entry.display_name,
                    clean_act_id,
                    AdaptationChannel::DesktopAction,
                    e.to_string(),
                );
            }
        }
    } else if let Some(p) = params.get("path").and_then(|v| v.as_str()) {
        match validate_non_forbidden_path(core, p) {
            Ok(pb) => Some(pb.to_string_lossy().to_string()),
            Err(e) => {
                return build_error_outcome(
                    &entry.id,
                    &entry.display_name,
                    clean_act_id,
                    AdaptationChannel::DesktopAction,
                    e.to_string(),
                );
            }
        }
    } else {
        None
    };

    if matches!(clean_act_id, "" | "launch" | "launch_app" | "open_app") {
        let (bin, args, env_vec) =
            match tokenize_desktop_exec_with_env(&entry.exec_raw, optional_target.as_deref()) {
                Ok(t) => t,
                Err(e) => {
                    return build_error_outcome(
                        &entry.id,
                        &entry.display_name,
                        "launch_app",
                        AdaptationChannel::CliWrapper,
                        e.to_string(),
                    );
                }
            };
        return spawn_or_preview_gui_command(
            &entry.id,
            &entry.display_name,
            "launch_app",
            AdaptationChannel::CliWrapper,
            &[bin.as_str()],
            &args,
            &env_vec,
            is_dry_run(params),
            json!({ "desktop_id": entry.desktop_id, "desktop_path": entry.desktop_path }),
        );
    }

    let matched_sec = entry
        .desktop_actions
        .iter()
        .find(|s| s.action_id.eq_ignore_ascii_case(clean_act_id))
        .or_else(|| {
            let needle = clean_act_id.to_ascii_lowercase();
            entry
                .desktop_actions
                .iter()
                .find(|s| s.action_id.to_ascii_lowercase().contains(&needle))
        });

    let Some(sec) = matched_sec else {
        return build_error_outcome(
            &entry.id,
            &entry.display_name,
            clean_act_id,
            AdaptationChannel::DesktopAction,
            format!(
                "「{}」的 .desktop 文件未声明快捷动作 `{}`",
                entry.display_name, clean_act_id
            ),
        );
    };

    let (bin, mut args, env_vec) =
        match tokenize_desktop_exec_with_env(&sec.exec, optional_target.as_deref()) {
            Ok(t) => t,
            Err(e) => {
                return build_error_outcome(
                    &entry.id,
                    &entry.display_name,
                    clean_act_id,
                    AdaptationChannel::DesktopAction,
                    e.to_string(),
                );
            }
        };
    if let Some(ref extra) = optional_target
        && !args.contains(extra)
    {
        args.push(extra.clone());
    }

    spawn_or_preview_gui_command(
        &entry.id,
        &entry.display_name,
        clean_act_id,
        AdaptationChannel::DesktopAction,
        &[bin.as_str()],
        &args,
        &env_vec,
        is_dry_run(params),
        json!({
            "desktop_id": entry.desktop_id,
            "desktop_action": sec.action_id,
            "action_label": sec.display_name,
        }),
    )
}

// ============================================================================
// Specialized Rich Execution Handlers
// ============================================================================

async fn exec_libreoffice_convert(
    core: &IntentOsCore,
    app_id: &str,
    app_name: &str,
    action: &str,
    params: &Value,
) -> AdapterExecutionOutcome {
    let Some(raw_in) = params
        .get("input_path")
        .or_else(|| params.get("input"))
        .or_else(|| params.get("path"))
        .or_else(|| params.get("file"))
        .and_then(|v| v.as_str())
    else {
        return build_error_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::HeadlessCli,
            "LibreOffice 文档转换缺少 `input_path` / `path` 参数",
        );
    };

    let in_path = match validate_non_forbidden_path(core, raw_in) {
        Ok(p) => p,
        Err(e) => {
            return build_error_outcome(
                app_id,
                app_name,
                action,
                AdaptationChannel::HeadlessCli,
                e.to_string(),
            );
        }
    };
    if let Err(e) = ensure_authorized_path(&core.fs_engine, &in_path) {
        return build_error_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::HeadlessCli,
            e.to_string(),
        );
    }
    if !in_path.is_file() {
        return build_error_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::HeadlessCli,
            format!("待转换源文档不存在: {}", in_path.display()),
        );
    }

    let fmt = params
        .get("format")
        .or_else(|| params.get("to"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pdf".to_string());

    if !matches!(
        fmt.as_str(),
        "pdf" | "docx" | "doc" | "odt" | "xlsx" | "ods" | "pptx" | "odp" | "txt" | "html" | "csv"
    ) {
        return build_error_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::HeadlessCli,
            format!("不支持的目标文档转换格式: `{}`", fmt),
        );
    }

    let out_dir = if let Some(raw_out) = params
        .get("out_dir")
        .or_else(|| params.get("outdir"))
        .or_else(|| params.get("output_dir"))
        .and_then(|v| v.as_str())
    {
        match validate_non_forbidden_path(core, raw_out) {
            Ok(p) => p,
            Err(e) => {
                return build_error_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::HeadlessCli,
                    e.to_string(),
                );
            }
        }
    } else if let Some(raw_out_file) = params.get("output").and_then(|v| v.as_str()) {
        match validate_non_forbidden_path(core, raw_out_file) {
            Ok(p) => p
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/tmp")),
            Err(e) => {
                return build_error_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::HeadlessCli,
                    e.to_string(),
                );
            }
        }
    } else {
        in_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
    };

    if let Err(e) = ensure_authorized_path(&core.fs_engine, &out_dir) {
        return build_error_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::HeadlessCli,
            format!("输出目录未授权: {}", e),
        );
    }
    let _ = fs::create_dir_all(&out_dir);

    let stem = in_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("converted");
    let expected_output = out_dir.join(format!("{}.{}", stem, fmt));

    let lo_bin = resolve_desktop_binary("/snap/bin/libreoffice")
        .or_else(|| resolve_desktop_binary("libreoffice"))
        .or_else(|| resolve_desktop_binary("soffice"));

    let translated_command = format!(
        "libreoffice --headless --convert-to {} --outdir {} {}",
        fmt,
        out_dir.display(),
        in_path.display()
    );

    if is_dry_run(params) || lo_bin.is_none() {
        return make_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::HeadlessCli,
            true,
            false,
            None,
            translated_command,
            format!(
                "已预演 LibreOffice 无头转换 `{}` -> `{}`",
                in_path.display(),
                expected_output.display()
            ),
            json!({
                "input_path": in_path,
                "output_path": expected_output,
                "format": fmt,
            }),
            true,
            VerificationReport {
                state: VerificationState::RequestedUnverified,
                method: "libreoffice_headless_preview".into(),
                checks: vec!["authorized_output_dir_verified".into()],
                details: Some("预演模式或本机未安装 LibreOffice".into()),
            },
        );
    }

    let bin = lo_bin.unwrap_or_else(|| PathBuf::from("libreoffice"));
    let profile_dir = std::env::temp_dir().join(format!(
        "intentos-lo-headless-{}-{}",
        std::process::id(),
        Utc::now().timestamp_millis()
    ));
    let user_install_arg = format!(
        "-env:UserInstallation=file://{}",
        profile_dir.to_string_lossy()
    );

    let mut cmd = TokioCommand::new(&bin);
    apply_clean_desktop_env(&mut cmd);
    cmd.args([
        user_install_arg.as_str(),
        "--headless",
        "--nologo",
        "--nofirststartwizard",
        "--convert-to",
        fmt.as_str(),
        "--outdir",
        &out_dir.to_string_lossy(),
        &in_path.to_string_lossy(),
    ]);

    let run_res = timeout(Duration::from_secs(45), cmd.output()).await;
    let _ = fs::remove_dir_all(&profile_dir);

    match run_res {
        Ok(Ok(output)) => {
            let meta_ok = fs::metadata(&expected_output)
                .map(|m| m.is_file() && m.len() > 0)
                .unwrap_or(false);
            let file_bytes = fs::metadata(&expected_output).map(|m| m.len()).unwrap_or(0);
            if output.status.success() && meta_ok {
                make_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::HeadlessCli,
                    true,
                    false,
                    None,
                    translated_command,
                    format!(
                        "已通过 LibreOffice 无头转换生成 `{}`（{} 字节）",
                        expected_output.display(),
                        file_bytes
                    ),
                    json!({
                        "input_path": in_path,
                        "output_path": expected_output,
                        "format": fmt,
                        "size_bytes": file_bytes,
                    }),
                    false,
                    VerificationReport {
                        state: VerificationState::Passed,
                        method: "disk_output_file_stat_verified".into(),
                        checks: vec![
                            "libreoffice_exit_zero".into(),
                            "output_file_exists_non_empty".into(),
                        ],
                        details: Some(format!(
                            "已核验输出文件存在且非空: {}",
                            expected_output.display()
                        )),
                    },
                )
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                build_error_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::HeadlessCli,
                    format!(
                        "LibreOffice 转换未生成目标文件 `{}`: {}",
                        expected_output.display(),
                        stderr
                    ),
                )
            }
        }
        Ok(Err(e)) => build_error_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::HeadlessCli,
            format!("启动 LibreOffice 失败: {}", e),
        ),
        Err(_) => build_error_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::HeadlessCli,
            "LibreOffice 无头转换超时（>45s）",
        ),
    }
}

async fn exec_drawio_export(
    core: &IntentOsCore,
    app_id: &str,
    app_name: &str,
    params: &Value,
) -> AdapterExecutionOutcome {
    let Some(raw_in) = params
        .get("input_path")
        .or_else(|| params.get("path"))
        .or_else(|| params.get("file"))
        .and_then(|v| v.as_str())
    else {
        return build_error_outcome(
            app_id,
            app_name,
            "export_diagram",
            AdaptationChannel::HeadlessCli,
            "draw.io 导出缺少 `input_path` / `path` 参数",
        );
    };
    let in_path = match validate_non_forbidden_path(core, raw_in) {
        Ok(p) => p,
        Err(e) => {
            return build_error_outcome(
                app_id,
                app_name,
                "export_diagram",
                AdaptationChannel::HeadlessCli,
                e.to_string(),
            );
        }
    };
    let fmt = params
        .get("format")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pdf".to_string());
    if !matches!(fmt.as_str(), "pdf" | "png" | "svg" | "jpg" | "xml") {
        return build_error_outcome(
            app_id,
            app_name,
            "export_diagram",
            AdaptationChannel::HeadlessCli,
            format!(
                "draw.io 不支持的导出格式: `{}`（支持 pdf/png/svg/jpg）",
                fmt
            ),
        );
    }

    let out_path = if let Some(raw_out) = params
        .get("output_path")
        .or_else(|| params.get("out_path"))
        .and_then(|v| v.as_str())
    {
        match validate_non_forbidden_path(core, raw_out) {
            Ok(p) => p,
            Err(e) => {
                return build_error_outcome(
                    app_id,
                    app_name,
                    "export_diagram",
                    AdaptationChannel::HeadlessCli,
                    e.to_string(),
                );
            }
        }
    } else {
        let stem = in_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("diagram");
        in_path
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join(format!("{}.{}", stem, fmt))
    };

    if let Some(parent) = out_path.parent()
        && let Err(e) = ensure_authorized_path(&core.fs_engine, parent)
    {
        return build_error_outcome(
            app_id,
            app_name,
            "export_diagram",
            AdaptationChannel::HeadlessCli,
            format!("导出目录未授权: {}", e),
        );
    }

    let drawio_bin =
        resolve_desktop_binary("/opt/drawio/drawio").or_else(|| resolve_desktop_binary("drawio"));
    let translated_command = format!(
        "/opt/drawio/drawio -x -f {} -o {} {}",
        fmt,
        out_path.display(),
        in_path.display()
    );

    if is_dry_run(params) || drawio_bin.is_none() || !in_path.is_file() || !has_gui_session() {
        return make_outcome(
            app_id,
            app_name,
            "export_diagram",
            AdaptationChannel::HeadlessCli,
            true,
            false,
            None,
            translated_command,
            format!(
                "已生成 draw.io 流程图导出指令 `{}` -> `{}`（预演模式）",
                in_path.display(),
                out_path.display()
            ),
            json!({
                "input_path": in_path,
                "output_path": out_path,
                "format": fmt,
            }),
            true,
            VerificationReport {
                state: VerificationState::RequestedUnverified,
                method: "drawio_export_preview".into(),
                checks: vec!["authorized_output_path_verified".into()],
                details: Some("无头环境或预演模式，已核验导出参数".into()),
            },
        );
    }

    let bin = drawio_bin.unwrap_or_else(|| PathBuf::from("/opt/drawio/drawio"));
    let mut cmd = TokioCommand::new(&bin);
    apply_clean_desktop_env(&mut cmd);
    cmd.args([
        "--no-sandbox",
        "-x",
        "-f",
        fmt.as_str(),
        "-o",
        &out_path.to_string_lossy(),
        &in_path.to_string_lossy(),
    ]);

    match timeout(Duration::from_secs(30), cmd.output()).await {
        Ok(Ok(out)) => {
            let exists_non_empty = fs::metadata(&out_path)
                .map(|m| m.is_file() && m.len() > 0)
                .unwrap_or(false);
            if out.status.success() && exists_non_empty {
                let bytes = fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
                make_outcome(
                    app_id,
                    app_name,
                    "export_diagram",
                    AdaptationChannel::HeadlessCli,
                    true,
                    false,
                    None,
                    translated_command,
                    format!(
                        "已通过 draw.io 导出 `{}`（{} 字节）",
                        out_path.display(),
                        bytes
                    ),
                    json!({
                        "input_path": in_path,
                        "output_path": out_path,
                        "format": fmt,
                        "size_bytes": bytes,
                    }),
                    false,
                    VerificationReport {
                        state: VerificationState::Passed,
                        method: "drawio_output_file_verified".into(),
                        checks: vec![
                            "drawio_exit_zero".into(),
                            "output_file_exists_non_empty".into(),
                        ],
                        details: Some(format!("已核验导出文件: {}", out_path.display())),
                    },
                )
            } else {
                build_error_outcome(
                    app_id,
                    app_name,
                    "export_diagram",
                    AdaptationChannel::HeadlessCli,
                    format!(
                        "draw.io 导出未生成文件: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                )
            }
        }
        Ok(Err(e)) => build_error_outcome(
            app_id,
            app_name,
            "export_diagram",
            AdaptationChannel::HeadlessCli,
            format!("执行 draw.io 失败: {}", e),
        ),
        Err(_) => build_error_outcome(
            app_id,
            app_name,
            "export_diagram",
            AdaptationChannel::HeadlessCli,
            "draw.io 导出超时（>30s）",
        ),
    }
}

async fn exec_flclash_probe_status(app_id: &str, app_name: &str) -> AdapterExecutionOutcome {
    let procs = snapshot_user_running_processes();
    let pids: Vec<u32> = procs
        .iter()
        .filter(|p| p.comm_lc.contains("flclash") || p.exe_lc.contains("flclash"))
        .map(|p| p.pid)
        .collect();

    let candidate_ports: &[u16] = &[7890, 7897, 7891, 7892, 9090];
    let mut open_ports = Vec::new();
    for &port in candidate_ports {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        if TcpStream::connect_timeout(&addr, Duration::from_millis(120)).is_ok() {
            open_ports.push(port);
        }
    }

    let tray_apps = discover_live_tray_apps().await;
    let tray_hit = tray_apps.iter().find(|t| {
        t.id.to_ascii_lowercase().contains("flclash")
            || t.title.to_ascii_lowercase().contains("flclash")
            || t.comm
                .as_deref()
                .is_some_and(|p| p.to_ascii_lowercase().contains("flclash"))
    });

    let running = !pids.is_empty() || tray_hit.is_some() || !open_ports.is_empty();
    let proxy_port = open_ports.iter().copied().find(|&p| p != 9090);

    make_outcome(
        app_id,
        app_name,
        "probe_proxy_status",
        AdaptationChannel::CliWrapper,
        true,
        false,
        None,
        "probe FlClash (/proc + TCP 127.0.0.1:7890/7897 + SNI tray)".into(),
        if running {
            format!(
                "FlClash 运行中（PID {:?}，监听端口 {:?}，托盘在线: {}）",
                pids,
                open_ports,
                tray_hit.is_some()
            )
        } else {
            "FlClash 当前未运行，本地代理端口 7890/7897 未监听".into()
        },
        json!({
            "running": running,
            "pids": pids,
            "open_ports": open_ports,
            "active_proxy_port": proxy_port,
            "controller_online": open_ports.contains(&9090),
            "tray_online": tray_hit.is_some(),
            "tray_menu_items": tray_hit.map(|t| &t.menu_items),
        }),
        false,
        VerificationReport {
            state: VerificationState::Passed,
            method: "proc_tcp_sni_live_probe".into(),
            checks: vec![
                "proc_uid_pid_checked".into(),
                "localhost_proxy_ports_probed".into(),
                "sni_tray_checked".into(),
            ],
            details: Some("已完成进程、本地代理端口与托盘状态联合探针核验".into()),
        },
    )
}

async fn exec_tailscale_status(
    app_id: &str,
    app_name: &str,
    params: &Value,
) -> AdapterExecutionOutcome {
    if let Some(ts_bin) = resolve_desktop_binary("tailscale")
        && !is_dry_run(params)
    {
        let mut cmd = TokioCommand::new(&ts_bin);
        apply_clean_desktop_env(&mut cmd);
        cmd.args(["status", "--json"]);
        if let Ok(Ok(out)) = timeout(Duration::from_secs(4), cmd.output()).await {
            let raw = String::from_utf8_lossy(&out.stdout);
            if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
                let backend_state = parsed
                    .get("BackendState")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let self_ips = parsed
                    .pointer("/Self/TailscaleIPs")
                    .cloned()
                    .unwrap_or_else(|| json!([]));
                let peer_count = parsed
                    .get("Peer")
                    .and_then(|v| v.as_object())
                    .map(|m| m.len())
                    .unwrap_or(0);
                return make_outcome(
                    app_id,
                    app_name,
                    "tailscale_status",
                    AdaptationChannel::CliWrapper,
                    true,
                    false,
                    None,
                    "tailscale status --json".into(),
                    format!(
                        "Tailscale 状态: {}（本机虚拟 IP: {}，已知节点: {} 个）",
                        backend_state, self_ips, peer_count
                    ),
                    json!({
                        "backend_state": backend_state,
                        "tailscale_ips": self_ips,
                        "peer_count": peer_count,
                    }),
                    false,
                    VerificationReport {
                        state: VerificationState::Passed,
                        method: "tailscale_cli_json_status".into(),
                        checks: vec!["tailscale_status_parsed".into()],
                        details: None,
                    },
                );
            }
        }
    }

    spawn_or_preview_gui_command(
        app_id,
        app_name,
        "tailscale_status",
        AdaptationChannel::CliWrapper,
        &["google-chrome", "brave-browser", "xdg-open"],
        &["--app=https://login.tailscale.com/admin/machines".to_string()],
        &[],
        is_dry_run(params),
        json!({ "fallback": "tailscale_web_console" }),
    )
}

async fn exec_virtualbox_action(
    app_id: &str,
    app_name: &str,
    action: &str,
    params: &Value,
    approved: bool,
) -> AdapterExecutionOutcome {
    match action {
        "list_vms" => {
            let Some(vbox_bin) = resolve_desktop_binary("VBoxManage") else {
                return make_outcome(
                    app_id,
                    app_name,
                    "list_vms",
                    AdaptationChannel::CliWrapper,
                    true,
                    false,
                    None,
                    "VBoxManage list vms".into(),
                    "本机未检测到 VBoxManage CLI（返回空虚拟机列表预演）".into(),
                    json!({ "vms": [], "running_vms": [], "total_count": 0, "running_count": 0 }),
                    true,
                    VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "vboxmanage_not_installed".into(),
                        checks: Vec::new(),
                        details: None,
                    },
                );
            };

            let parse_vbox_lines = |raw: &str| -> Vec<Value> {
                raw.lines()
                    .filter_map(|line| {
                        let trim = line.trim();
                        if !trim.starts_with('"') {
                            return None;
                        }
                        let end_quote = trim[1..].find('"')? + 1;
                        let vm_name = &trim[1..end_quote];
                        let uuid = trim[end_quote + 1..]
                            .trim()
                            .trim_start_matches('{')
                            .trim_end_matches('}');
                        Some(json!({ "name": vm_name, "uuid": uuid }))
                    })
                    .collect()
            };

            let mut cmd_all = TokioCommand::new(&vbox_bin);
            apply_clean_desktop_env(&mut cmd_all);
            cmd_all.args(["list", "vms"]);

            let mut cmd_run = TokioCommand::new(&vbox_bin);
            apply_clean_desktop_env(&mut cmd_run);
            cmd_run.args(["list", "runningvms"]);

            let all_out = timeout(Duration::from_secs(5), cmd_all.output()).await;
            let run_out = timeout(Duration::from_secs(5), cmd_run.output()).await;

            let vms = all_out
                .ok()
                .and_then(Result::ok)
                .map(|o| parse_vbox_lines(&String::from_utf8_lossy(&o.stdout)))
                .unwrap_or_default();
            let running_vms = run_out
                .ok()
                .and_then(Result::ok)
                .map(|o| parse_vbox_lines(&String::from_utf8_lossy(&o.stdout)))
                .unwrap_or_default();

            make_outcome(
                app_id,
                app_name,
                "list_vms",
                AdaptationChannel::CliWrapper,
                true,
                false,
                None,
                "VBoxManage list vms && VBoxManage list runningvms".into(),
                format!(
                    "已读取 VirtualBox 虚拟机列表：共 {} 台，运行中 {} 台",
                    vms.len(),
                    running_vms.len()
                ),
                json!({
                    "vms": vms,
                    "running_vms": running_vms,
                    "total_count": vms.len(),
                    "running_count": running_vms.len(),
                }),
                false,
                VerificationReport {
                    state: VerificationState::Passed,
                    method: "vboxmanage_list_vms".into(),
                    checks: vec!["vboxmanage_queried".into()],
                    details: None,
                },
            )
        }
        "start_vm" | "savestate_vm" => {
            let Some(vm) = params
                .get("vm")
                .or_else(|| params.get("vm_name"))
                .or_else(|| params.get("name"))
                .or_else(|| params.get("uuid"))
                .or_else(|| params.get("target"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return build_error_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::CliWrapper,
                    "VirtualBox 虚拟机控制缺少 `vm`（名称或 UUID）参数",
                );
            };
            if vm.starts_with('-') || vm.chars().any(|c| c.is_control()) {
                return build_error_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::CliWrapper,
                    format!("安全拦截：非法的虚拟机标识符 `{}`", vm),
                );
            }
            let vm_type = params
                .get("type")
                .and_then(|v| v.as_str())
                .filter(|t| matches!(*t, "gui" | "headless" | "separate"))
                .unwrap_or("gui");
            let translated = if action == "start_vm" {
                format!("VBoxManage startvm {} --type {}", vm, vm_type)
            } else {
                format!("VBoxManage controlvm {} savestate", vm)
            };

            if !approved {
                return build_approval_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::CliWrapper,
                    vm,
                    translated,
                    format!(
                        "虚拟机电源/状态变更操作（{} -> `{}`）属于高资源敏感动作，需确认授权后执行",
                        action, vm
                    ),
                    json!({ "vm": vm, "action": action, "type": vm_type, "requires_approval": true }),
                );
            }

            if is_dry_run(params) || resolve_desktop_binary("VBoxManage").is_none() {
                let vbox_args: Vec<String> = if action == "start_vm" {
                    vec![
                        "startvm".to_string(),
                        vm.to_string(),
                        "--type".to_string(),
                        vm_type.to_string(),
                    ]
                } else {
                    vec![
                        "controlvm".to_string(),
                        vm.to_string(),
                        "savestate".to_string(),
                    ]
                };
                return spawn_or_preview_gui_command(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::CliWrapper,
                    &["VBoxManage"],
                    &vbox_args,
                    &[],
                    true,
                    json!({ "vm": vm, "approved": true }),
                );
            }

            let vbox_bin =
                resolve_desktop_binary("VBoxManage").unwrap_or_else(|| PathBuf::from("VBoxManage"));
            let mut cmd = TokioCommand::new(&vbox_bin);
            apply_clean_desktop_env(&mut cmd);
            if action == "start_vm" {
                cmd.args(["startvm", vm, "--type", vm_type]);
            } else {
                cmd.args(["controlvm", vm, "savestate"]);
            }
            match timeout(Duration::from_secs(20), cmd.output()).await {
                Ok(Ok(out)) if out.status.success() => make_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::CliWrapper,
                    true,
                    false,
                    None,
                    translated,
                    format!("已对虚拟机 `{}` 成功执行 `{}`", vm, action),
                    json!({
                        "vm": vm,
                        "stdout": String::from_utf8_lossy(&out.stdout).trim(),
                    }),
                    false,
                    VerificationReport {
                        state: VerificationState::Passed,
                        method: "vboxmanage_exit_zero".into(),
                        checks: vec!["user_approved".into(), "vboxmanage_succeeded".into()],
                        details: None,
                    },
                ),
                Ok(Ok(out)) => build_error_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::CliWrapper,
                    format!(
                        "VBoxManage 执行失败: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                ),
                Ok(Err(e)) => build_error_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::CliWrapper,
                    format!("调用 VBoxManage 失败: {}", e),
                ),
                Err(_) => build_error_outcome(
                    app_id,
                    app_name,
                    action,
                    AdaptationChannel::CliWrapper,
                    "VBoxManage 操作超时（>20s）",
                ),
            }
        }
        _ => spawn_or_preview_gui_command(
            app_id,
            app_name,
            action,
            AdaptationChannel::CliWrapper,
            &["virtualbox"],
            &[],
            &[],
            is_dry_run(params),
            json!({}),
        ),
    }
}

async fn exec_rustdesk_action(
    app_id: &str,
    app_name: &str,
    action: &str,
    params: &Value,
    approved: bool,
) -> AdapterExecutionOutcome {
    match action {
        "get_device_id" => {
            if let Some(rd_bin) = resolve_desktop_binary("rustdesk")
                && !is_dry_run(params)
            {
                let mut cmd = TokioCommand::new(&rd_bin);
                apply_clean_desktop_env(&mut cmd);
                cmd.arg("--get-id");
                if let Ok(Ok(out)) = timeout(Duration::from_secs(4), cmd.output()).await {
                    let id_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !id_str.is_empty() && out.status.success() {
                        return make_outcome(
                            app_id,
                            app_name,
                            "get_device_id",
                            AdaptationChannel::CliWrapper,
                            true,
                            false,
                            None,
                            "rustdesk --get-id".into(),
                            format!("本机 RustDesk 设备 ID: `{}`", id_str),
                            json!({ "device_id": id_str }),
                            false,
                            VerificationReport {
                                state: VerificationState::Passed,
                                method: "rustdesk_cli_get_id".into(),
                                checks: vec!["device_id_non_empty".into()],
                                details: None,
                            },
                        );
                    }
                }
            }
            spawn_or_preview_gui_command(
                app_id,
                app_name,
                "get_device_id",
                AdaptationChannel::CliWrapper,
                &["rustdesk"],
                &["--get-id".to_string()],
                &[],
                true,
                json!({}),
            )
        }
        "connect_peer" => {
            let Some(peer_id) = params
                .get("peer_id")
                .or_else(|| params.get("id"))
                .or_else(|| params.get("target"))
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                })
                .map(|s| s.replace(' ', ""))
                .filter(|s| !s.is_empty())
            else {
                return build_error_outcome(
                    app_id,
                    app_name,
                    "connect_peer",
                    AdaptationChannel::CliWrapper,
                    "RustDesk 远控连接缺少 `peer_id` 参数",
                );
            };

            if peer_id.starts_with('-')
                || !peer_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@'))
            {
                return build_error_outcome(
                    app_id,
                    app_name,
                    "connect_peer",
                    AdaptationChannel::CliWrapper,
                    format!("安全拦截：非法的远控设备号 `{}`", peer_id),
                );
            }

            let translated = format!("rustdesk --connect {}", peer_id);
            if !approved {
                return build_approval_outcome(
                    app_id,
                    app_name,
                    "connect_peer",
                    AdaptationChannel::CliWrapper,
                    &peer_id,
                    translated,
                    format!(
                        "发起外部远程桌面控制连接（目标设备 `{}`）需要您的明确授权",
                        peer_id
                    ),
                    json!({ "peer_id": peer_id, "requires_approval": true }),
                );
            }

            spawn_or_preview_gui_command(
                app_id,
                app_name,
                "connect_peer",
                AdaptationChannel::CliWrapper,
                &["rustdesk"],
                &["--connect".to_string(), peer_id.clone()],
                &[],
                is_dry_run(params),
                json!({ "peer_id": peer_id, "approved": true }),
            )
        }
        _ => spawn_or_preview_gui_command(
            app_id,
            app_name,
            action,
            AdaptationChannel::CliWrapper,
            &["rustdesk"],
            &[],
            &[],
            is_dry_run(params),
            json!({}),
        ),
    }
}

async fn exec_fcitx5_action(
    app_id: &str,
    app_name: &str,
    action: &str,
    params: &Value,
) -> AdapterExecutionOutcome {
    if action == "open_fcitx_config" {
        return spawn_or_preview_gui_command(
            app_id,
            app_name,
            action,
            AdaptationChannel::CliWrapper,
            &["fcitx5-configtool", "fcitx5-config-qt"],
            &[],
            &[],
            is_dry_run(params),
            json!({}),
        );
    }

    let Some(remote_bin) = resolve_desktop_binary("fcitx5-remote") else {
        let fcitx_args: Vec<String> = match action {
            "activate_chinese" => vec!["-o".to_string()],
            "deactivate_chinese" => vec!["-c".to_string()],
            _ => Vec::new(),
        };
        return spawn_or_preview_gui_command(
            app_id,
            app_name,
            action,
            AdaptationChannel::CliWrapper,
            &["fcitx5-remote"],
            &fcitx_args,
            &[],
            true,
            json!({}),
        );
    };

    if !is_dry_run(params) && matches!(action, "activate_chinese" | "deactivate_chinese") {
        let mut toggle_cmd = TokioCommand::new(&remote_bin);
        apply_clean_desktop_env(&mut toggle_cmd);
        toggle_cmd.arg(if action == "activate_chinese" {
            "-o"
        } else {
            "-c"
        });
        let _ = timeout(Duration::from_secs(3), toggle_cmd.output()).await;
    }

    let mut status_cmd = TokioCommand::new(&remote_bin);
    apply_clean_desktop_env(&mut status_cmd);
    let mut name_cmd = TokioCommand::new(&remote_bin);
    apply_clean_desktop_env(&mut name_cmd);
    name_cmd.arg("-n");

    let code_str = timeout(Duration::from_secs(3), status_cmd.output())
        .await
        .ok()
        .and_then(Result::ok)
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "0".into());
    let addon_name = timeout(Duration::from_secs(3), name_cmd.output())
        .await
        .ok()
        .and_then(Result::ok)
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let state_code = code_str.parse::<i32>().unwrap_or(0);
    let chinese_active = state_code == 2;

    make_outcome(
        app_id,
        app_name,
        action,
        AdaptationChannel::CliWrapper,
        true,
        false,
        None,
        match action {
            "activate_chinese" => "fcitx5-remote -o".into(),
            "deactivate_chinese" => "fcitx5-remote -c".into(),
            _ => "fcitx5-remote && fcitx5-remote -n".into(),
        },
        format!(
            "Fcitx5 输入法当前状态: {}（引擎: `{}`，state={}）",
            if chinese_active {
                "中文输入激活"
            } else if state_code == 1 {
                "英文/键盘直接输入"
            } else {
                "未激活"
            },
            if addon_name.is_empty() {
                "unknown"
            } else {
                &addon_name
            },
            state_code
        ),
        json!({
            "state_code": state_code,
            "chinese_active": chinese_active,
            "current_im": addon_name,
        }),
        is_dry_run(params),
        VerificationReport {
            state: if is_dry_run(params) {
                VerificationState::RequestedUnverified
            } else {
                VerificationState::Passed
            },
            method: "fcitx5_remote_readback".into(),
            checks: vec!["fcitx5_state_queried".into()],
            details: None,
        },
    )
}

async fn exec_nvidia_telemetry(
    app_id: &str,
    app_name: &str,
    action: &str,
    params: &Value,
) -> AdapterExecutionOutcome {
    if action == "open_nvidia_settings" {
        return spawn_or_preview_gui_command(
            app_id,
            app_name,
            action,
            AdaptationChannel::CliWrapper,
            &["nvidia-settings"],
            &[],
            &[],
            is_dry_run(params),
            json!({}),
        );
    }

    let query_args = [
        "--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total",
        "--format=csv,noheader,nounits",
    ];
    let translated = format!("nvidia-smi {}", query_args.join(" "));

    if let Some(smi_bin) = resolve_desktop_binary("nvidia-smi")
        && !is_dry_run(params)
    {
        let mut cmd = TokioCommand::new(&smi_bin);
        apply_clean_desktop_env(&mut cmd);
        cmd.args(query_args);
        if let Ok(Ok(out)) = timeout(Duration::from_secs(4), cmd.output()).await
            && out.status.success()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let gpus: Vec<Value> = stdout
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|line| {
                    let cols: Vec<&str> = line.split(',').map(str::trim).collect();
                    json!({
                        "name": cols.first().copied().unwrap_or("NVIDIA GPU"),
                        "temperature_c": cols.get(1).and_then(|s| s.parse::<u32>().ok()),
                        "utilization_gpu_pct": cols.get(2).and_then(|s| s.parse::<u32>().ok()),
                        "memory_used_mib": cols.get(3).and_then(|s| s.parse::<u64>().ok()),
                        "memory_total_mib": cols.get(4).and_then(|s| s.parse::<u64>().ok()),
                    })
                })
                .collect();

            let first_summary = gpus
                .first()
                .map(|g| {
                    format!(
                        "{} · 温度 {}°C · 利用率 {}% · 显存 {}/{} MiB",
                        g["name"].as_str().unwrap_or("GPU"),
                        g["temperature_c"].as_u64().unwrap_or(0),
                        g["utilization_gpu_pct"].as_u64().unwrap_or(0),
                        g["memory_used_mib"].as_u64().unwrap_or(0),
                        g["memory_total_mib"].as_u64().unwrap_or(0)
                    )
                })
                .unwrap_or_else(|| "未检测到独立 NVIDIA GPU".into());

            return make_outcome(
                app_id,
                app_name,
                "query_gpu_telemetry",
                AdaptationChannel::CliWrapper,
                true,
                false,
                None,
                translated,
                format!("NVIDIA GPU 实时遥测: {}", first_summary),
                json!({ "gpus": gpus, "count": gpus.len() }),
                false,
                VerificationReport {
                    state: VerificationState::Passed,
                    method: "nvidia_smi_csv_telemetry".into(),
                    checks: vec!["nvidia_smi_exit_zero".into()],
                    details: None,
                },
            );
        }
    }

    spawn_or_preview_gui_command(
        app_id,
        app_name,
        "query_gpu_telemetry",
        AdaptationChannel::CliWrapper,
        &["nvidia-smi"],
        &query_args
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
        &[],
        true,
        json!({}),
    )
}

#[allow(clippy::too_many_arguments)]
async fn try_wake_via_sni_or_launch(
    app_id: &str,
    app_name: &str,
    action: &str,
    sni_hint: &str,
    launch_bins: &[&str],
    launch_args: &[String],
    env_pairs: &[(String, String)],
    dry_run: bool,
) -> AdapterExecutionOutcome {
    if !dry_run && let Ok(Some(tray_val)) = activate_or_show_tray_app(sni_hint).await {
        return make_outcome(
            app_id,
            app_name,
            action,
            AdaptationChannel::SniDbusMenu,
            true,
            false,
            None,
            format!("sni_dbusmenu::activate_or_show_tray_app({})", sni_hint),
            format!("已通过系统托盘唤醒「{}」主窗口", app_name),
            tray_val,
            false,
            VerificationReport {
                state: VerificationState::Passed,
                method: "sni_dbusmenu_activate".into(),
                checks: vec!["sni_tray_matched".into()],
                details: None,
            },
        );
    }

    spawn_or_preview_gui_command(
        app_id,
        app_name,
        action,
        AdaptationChannel::CliWrapper,
        launch_bins,
        launch_args,
        env_pairs,
        dry_run,
        json!({ "sni_probed": sni_hint }),
    )
}

fn dbus_result_to_outcome(
    app_id: &str,
    app_name: &str,
    action: &str,
    m: DbusDispatchResult,
) -> AdapterExecutionOutcome {
    make_outcome(
        app_id,
        app_name,
        action,
        m.channel_used,
        m.ok,
        false,
        None,
        m.translated_command,
        m.summary,
        m.data,
        m.simulated,
        m.verification,
    )
}

/// Primary rich execution interceptor invoked by `translate_and_execute`.
/// Returns `Some(outcome)` when handled by a rich domain translator or universal `.desktop` auto-synthesis,
/// or `None` to fall back to the existing 5-channel `mod.rs` dispatcher.
pub async fn try_execute_rich_local_action(
    core: &IntentOsCore,
    registry: &AdapterRegistry,
    target_app: &str,
    canonical_action: &str,
    raw_action: &str,
    params: &Value,
    approved: bool,
) -> Option<AdapterExecutionOutcome> {
    let resolved_prof = registry.resolve_app(target_app);
    let app_id = resolved_prof
        .as_ref()
        .map(|p| p.id.clone())
        .unwrap_or_else(|| {
            target_app
                .trim()
                .trim_end_matches(".desktop")
                .to_ascii_lowercase()
        });
    let app_name = resolved_prof
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| target_app.trim().to_string());

    // Direct `desktop_action:<sec_id>` invocation on any app
    if let Some(sec_id) = raw_action
        .trim()
        .strip_prefix("desktop_action:")
        .or_else(|| canonical_action.strip_prefix("desktop_action:"))
    {
        return Some(
            execute_desktop_action_by_id(core, registry, target_app, sec_id, params, &[]).await,
        );
    }

    // ------------------------------------------------------------------------
    // 1. Office, PDF & Notes Rich Translators
    // ------------------------------------------------------------------------
    if matches!(canonical_action, "convert_to_pdf" | "convert_document")
        && (app_id.contains("libreoffice")
            || app_id.contains("wps")
            || app_id.contains("yozo")
            || app_id.contains("onlyoffice"))
    {
        // Note: if `/snap/bin/libreoffice` or `libreoffice` is requested directly, our Snap-aware converter handles it!
        return Some(
            exec_libreoffice_convert(core, &app_id, &app_name, canonical_action, params).await,
        );
    }

    if matches!(canonical_action, "open_pdf_page" | "find_in_pdf")
        && (app_id.contains("evince") || app_id.contains("papers") || app_id.contains("pdf"))
    {
        let Some(raw_p) = params
            .get("path")
            .or_else(|| params.get("file"))
            .and_then(|v| v.as_str())
        else {
            return Some(build_error_outcome(
                &app_id,
                &app_name,
                canonical_action,
                AdaptationChannel::CliWrapper,
                "打开 PDF 缺少 `path` 参数",
            ));
        };
        let pb = match validate_non_forbidden_path(core, raw_p) {
            Ok(p) => p,
            Err(e) => {
                return Some(build_error_outcome(
                    &app_id,
                    &app_name,
                    canonical_action,
                    AdaptationChannel::CliWrapper,
                    e.to_string(),
                ));
            }
        };
        let mut args = Vec::new();
        if canonical_action == "open_pdf_page" {
            let page = params
                .get("page")
                .or_else(|| params.get("page_index"))
                .and_then(|v| v.as_u64())
                .unwrap_or(1)
                .max(1);
            if resolve_desktop_binary("evince").is_some() || !app_id.contains("papers") {
                args.push(format!("--page-index={}", page));
            }
        } else if let Some(kw) = params
            .get("keyword")
            .or_else(|| params.get("query"))
            .or_else(|| params.get("find"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            && (resolve_desktop_binary("evince").is_some() || !app_id.contains("papers"))
        {
            args.push(format!("--find={}", kw.trim()));
        }
        args.push(pb.to_string_lossy().to_string());
        let bins: &[&str] = if app_id.contains("papers") {
            &["papers", "evince"]
        } else {
            &["evince", "papers"]
        };
        return Some(spawn_or_preview_gui_command(
            &app_id,
            &app_name,
            canonical_action,
            AdaptationChannel::CliWrapper,
            bins,
            &args,
            &[],
            is_dry_run(params),
            json!({ "pdf_path": pb }),
        ));
    }

    if (app_id.contains("pdfarranger") || canonical_action == "open_pdf_arranger")
        && matches!(
            canonical_action,
            "open_pdf_arranger" | "open_file" | "open_document" | "launch_app"
        )
    {
        let mut args = Vec::new();
        if let Some(arr) = params.get("paths").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    match validate_non_forbidden_path(core, s) {
                        Ok(p) => args.push(p.to_string_lossy().to_string()),
                        Err(e) => {
                            return Some(build_error_outcome(
                                &app_id,
                                &app_name,
                                canonical_action,
                                AdaptationChannel::CliWrapper,
                                e.to_string(),
                            ));
                        }
                    }
                }
            }
        } else if let Some(s) = params.get("path").and_then(|v| v.as_str()) {
            match validate_non_forbidden_path(core, s) {
                Ok(p) => args.push(p.to_string_lossy().to_string()),
                Err(e) => {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        canonical_action,
                        AdaptationChannel::CliWrapper,
                        e.to_string(),
                    ));
                }
            }
        }
        return Some(spawn_or_preview_gui_command(
            &app_id,
            &app_name,
            canonical_action,
            AdaptationChannel::CliWrapper,
            &["pdfarranger"],
            &args,
            &[],
            is_dry_run(params),
            json!({ "file_count": args.len() }),
        ));
    }

    if (app_id.contains("wps")
        || app_id.contains("yozo")
        || app_id.contains("onlyoffice")
        || app_id.contains("typora")
        || app_id.contains("betternotes")
        || app_id.contains("libreoffice"))
        && matches!(
            canonical_action,
            "new_document"
                | "new_spreadsheet"
                | "new_presentation"
                | "wake_cloud_tray"
                | "wake_notes"
        )
    {
        if canonical_action == "wake_cloud_tray" {
            return Some(
                try_wake_via_sni_or_launch(
                    &app_id,
                    &app_name,
                    canonical_action,
                    "wpscloudsvr",
                    &["wps"],
                    &[],
                    &[],
                    is_dry_run(params),
                )
                .await,
            );
        }
        if canonical_action == "wake_notes" {
            return Some(
                try_wake_via_sni_or_launch(
                    &app_id,
                    &app_name,
                    canonical_action,
                    "betternotes",
                    &["betternotes", "typora"],
                    &[],
                    &[],
                    is_dry_run(params),
                )
                .await,
            );
        }
        let (bins, args): (&[&str], Vec<String>) = if app_id.contains("wps") {
            match canonical_action {
                "new_spreadsheet" => (&["et", "wps"], Vec::new()),
                "new_presentation" => (&["wpp", "wps"], Vec::new()),
                _ => (&["wps"], Vec::new()),
            }
        } else if app_id.contains("yozo") {
            match canonical_action {
                "new_spreadsheet" => (&["yozoc", "yozo-office"], Vec::new()),
                "new_presentation" => (&["yozoi", "yozo-office"], Vec::new()),
                _ => (&["yozow", "yozo-office"], Vec::new()),
            }
        } else if app_id.contains("libreoffice") {
            let flag = match canonical_action {
                "new_spreadsheet" => "--calc",
                "new_presentation" => "--impress",
                _ => "--writer",
            };
            (
                &["/snap/bin/libreoffice", "libreoffice", "soffice"],
                vec![flag.to_string()],
            )
        } else if app_id.contains("typora") {
            (&["typora"], Vec::new())
        } else {
            (&["onlyoffice-desktopeditors"], Vec::new())
        };
        return Some(spawn_or_preview_gui_command(
            &app_id,
            &app_name,
            canonical_action,
            AdaptationChannel::CliWrapper,
            bins,
            &args,
            &[],
            is_dry_run(params),
            json!({}),
        ));
    }

    // ------------------------------------------------------------------------
    // 2. Social, Collaboration & Video Conferencing (`wemeet`, `feishu`, `qq`, `wechat`)
    // ------------------------------------------------------------------------
    if canonical_action == "join_meeting"
        && (app_id.contains("wemeet") || target_app.contains("腾讯会议"))
    {
        let raw_code = params
            .get("meeting_code")
            .or_else(|| params.get("code"))
            .or_else(|| params.get("room"))
            .or_else(|| params.get("confno"))
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let code = match normalize_meeting_code(&raw_code) {
            Ok(c) => c,
            Err(e) => {
                return Some(build_error_outcome(
                    &app_id,
                    &app_name,
                    "join_meeting",
                    AdaptationChannel::UriScheme,
                    e.to_string(),
                ));
            }
        };
        let uri = format!("wemeet://page/inmeeting?meeting_code={}", code);
        let dry = is_dry_run(params);
        if !dry
            && has_gui_session()
            && let Some(gio_bin) = resolve_desktop_binary("gio")
        {
            let mut cmd = StdCommand::new(gio_bin);
            apply_clean_desktop_env_std(&mut cmd);
            if cmd.args(["open", &uri]).spawn().is_ok() {
                return Some(make_outcome(
                    &app_id,
                    &app_name,
                    "join_meeting",
                    AdaptationChannel::UriScheme,
                    true,
                    false,
                    None,
                    format!("gio open {}", uri),
                    format!("已通过腾讯会议深度链接加入会议 `{}`", code),
                    json!({ "meeting_code": code, "uri": uri }),
                    false,
                    VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "wemeet_uri_deeplink".into(),
                        checks: vec!["meeting_code_normalized".into(), "uri_dispatched".into()],
                        details: None,
                    },
                ));
            }
        }
        return Some(make_outcome(
            &app_id,
            &app_name,
            "join_meeting",
            AdaptationChannel::UriScheme,
            true,
            false,
            None,
            format!("gio open {}", uri),
            format!("已构建腾讯会议入会深度链接 `{}`（预演模式）", uri),
            json!({ "meeting_code": code, "uri": uri }),
            true,
            VerificationReport {
                state: VerificationState::RequestedUnverified,
                method: "wemeet_uri_preview".into(),
                checks: vec!["meeting_code_normalized".into()],
                details: None,
            },
        ));
    }

    if canonical_action == "open_feishu_uri"
        || (app_id.contains("feishu") && canonical_action == "open_uri")
    {
        let raw_u = params
            .get("uri")
            .or_else(|| params.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or("feishu://client/open");
        let allowed = vec![
            "feishu".to_string(),
            "lark".to_string(),
            "applink.feishu".to_string(),
            "feishu-open".to_string(),
        ];
        let valid_uri = match validate_uri_safety(raw_u, &allowed) {
            Ok(u) => u,
            Err(e) => {
                return Some(build_error_outcome(
                    &app_id,
                    &app_name,
                    canonical_action,
                    AdaptationChannel::UriScheme,
                    e.to_string(),
                ));
            }
        };
        return Some(spawn_or_preview_gui_command(
            &app_id,
            &app_name,
            canonical_action,
            AdaptationChannel::UriScheme,
            &["gio", "xdg-open", "/opt/bytedance/feishu/bytedance-feishu"],
            &["open".to_string(), valid_uri.clone()],
            &[],
            is_dry_run(params),
            json!({ "uri": valid_uri }),
        ));
    }

    if canonical_action == "wake_main_window"
        && matches!(
            app_id.as_str(),
            "qq" | "wechat" | "bytedance-feishu" | "feishu" | "wemeetapp" | "wemeet" | "dingtalk"
        )
    {
        let launch_bins: &[&str] = match app_id.as_str() {
            "qq" => &["/opt/QQ/qq", "qq", "linuxqq"],
            "wechat" => &["wechat", "wechat-universal", "weixin"],
            "bytedance-feishu" | "feishu" => {
                &["/opt/bytedance/feishu/bytedance-feishu", "bytedance-feishu"]
            }
            "wemeetapp" | "wemeet" => &["/opt/wemeet/wemeetapp.sh", "wemeetapp"],
            _ => &["dingtalk"],
        };
        let sni_hint = match app_id.as_str() {
            "bytedance-feishu" => "feishu",
            "wemeetapp" => "wemeet",
            other => other,
        };
        return Some(
            try_wake_via_sni_or_launch(
                &app_id,
                &app_name,
                canonical_action,
                sni_hint,
                launch_bins,
                &[],
                &[],
                is_dry_run(params),
            )
            .await,
        );
    }

    // ------------------------------------------------------------------------
    // 3. Media & Audio Rich Translators (`qqmusic` LIBGL_ALWAYS_SOFTWARE=1, `sodam`, `vlc`, `douyin`)
    // ------------------------------------------------------------------------
    if app_id == "qqmusic"
        && matches!(
            canonical_action,
            "launch_app" | "focus_window" | "wake_window" | "open_media"
        )
    {
        let mut args = vec![
            "--use-gl=swiftshader".to_string(),
            "--disable-gpu-sandbox".to_string(),
        ];
        if let Some(p) = params
            .get("path")
            .or_else(|| params.get("media"))
            .and_then(|v| v.as_str())
        {
            match validate_non_forbidden_path(core, p) {
                Ok(pb) => args.push(pb.to_string_lossy().to_string()),
                Err(e) => {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        canonical_action,
                        AdaptationChannel::CliWrapper,
                        e.to_string(),
                    ));
                }
            }
        }
        let env_pairs = vec![("LIBGL_ALWAYS_SOFTWARE".to_string(), "1".to_string())];
        return Some(
            try_wake_via_sni_or_launch(
                &app_id,
                &app_name,
                canonical_action,
                "qqmusic",
                &["/opt/qqmusic/qqmusic", "qqmusic"],
                &args,
                &env_pairs,
                is_dry_run(params),
            )
            .await,
        );
    }

    if matches!(app_id.as_str(), "sodam" | "qqmusic" | "vlc" | "douyin")
        && matches!(
            canonical_action,
            "play_pause"
                | "next"
                | "previous"
                | "next_track"
                | "prev_track"
                | "get_now_playing"
                | "now_playing"
                | "open_media"
        )
    {
        if canonical_action == "open_media" {
            let Some(raw_m) = params
                .get("path")
                .or_else(|| params.get("url"))
                .or_else(|| params.get("uri"))
                .and_then(|v| v.as_str())
            else {
                return Some(build_error_outcome(
                    &app_id,
                    &app_name,
                    "open_media",
                    AdaptationChannel::CliWrapper,
                    "打开媒体缺少 `path` 或 `url` 参数",
                ));
            };
            let arg = if raw_m.contains("://") {
                match validate_uri_safety(raw_m, &[]) {
                    Ok(u) => u,
                    Err(e) => {
                        return Some(build_error_outcome(
                            &app_id,
                            &app_name,
                            "open_media",
                            AdaptationChannel::CliWrapper,
                            e.to_string(),
                        ));
                    }
                }
            } else {
                match validate_non_forbidden_path(core, raw_m) {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(e) => {
                        return Some(build_error_outcome(
                            &app_id,
                            &app_name,
                            "open_media",
                            AdaptationChannel::CliWrapper,
                            e.to_string(),
                        ));
                    }
                }
            };
            let (bins, envs): (&[&str], Vec<(String, String)>) = match app_id.as_str() {
                "sodam" => (
                    &["/opt/SodaM/sodam", "/opt/BaicaiMusic/sodam", "sodam"],
                    Vec::new(),
                ),
                "qqmusic" => (
                    &["/opt/qqmusic/qqmusic", "qqmusic"],
                    vec![("LIBGL_ALWAYS_SOFTWARE".into(), "1".into())],
                ),
                _ => (&["vlc", "mpv"], Vec::new()),
            };
            return Some(spawn_or_preview_gui_command(
                &app_id,
                &app_name,
                "open_media",
                AdaptationChannel::CliWrapper,
                bins,
                &[arg],
                &envs,
                is_dry_run(params),
                json!({}),
            ));
        }

        // Try MPRIS first, then SNI tray fallback for tray-resident domestic music apps
        let mpris_action = match canonical_action {
            "next_track" => "next",
            "prev_track" => "previous",
            "now_playing" => "get_now_playing",
            other => other,
        };
        if mpris_action == "get_now_playing" {
            let players = query_all_now_playing(
                Some(&app_id),
                core.app_config.allow_simulated_hardware_fallback,
            )
            .await;
            if let Some(np) = players.first() {
                return Some(make_outcome(
                    &app_id,
                    &app_name,
                    canonical_action,
                    AdaptationChannel::DbusMpris,
                    true,
                    false,
                    None,
                    format!("dbus-mpris Get(Metadata, PlaybackStatus) [{}]", np.bus_name),
                    format!(
                        "当前播放 ({})：{} - {}",
                        np.playback_status,
                        np.title.as_deref().unwrap_or("未知曲目"),
                        np.artists.join(", ")
                    ),
                    serde_json::to_value(np).unwrap_or_else(|_| json!({})),
                    np.simulated,
                    VerificationReport {
                        state: if np.simulated {
                            VerificationState::RequestedUnverified
                        } else {
                            VerificationState::Passed
                        },
                        method: "mpris_metadata_readback".into(),
                        checks: vec!["mpris_properties_queried".into()],
                        details: None,
                    },
                ));
            }
        }
        if !is_dry_run(params)
            && let Ok(Some(tray_val)) = invoke_tray_menu_action(&app_id, mpris_action).await
        {
            return Some(make_outcome(
                &app_id,
                &app_name,
                canonical_action,
                AdaptationChannel::SniDbusMenu,
                true,
                false,
                None,
                format!(
                    "sni_dbusmenu::invoke_tray_menu_action({}, {})",
                    app_id, mpris_action
                ),
                format!("已通过系统托盘对「{}」执行 `{}`", app_name, mpris_action),
                tray_val,
                false,
                VerificationReport {
                    state: VerificationState::Passed,
                    method: "sni_dbusmenu_media_action".into(),
                    checks: vec!["tray_media_menu_clicked".into()],
                    details: None,
                },
            ));
        }
        if let Some(ref prof) = resolved_prof
            && let Ok(m) = execute_mpris_action(
                prof,
                mpris_action,
                params,
                core.app_config.allow_simulated_hardware_fallback,
            )
            .await
        {
            return Some(dbus_result_to_outcome(
                &app_id,
                &app_name,
                canonical_action,
                m,
            ));
        }
    }

    // ------------------------------------------------------------------------
    // 4. Cloud Sync, LAN Transfer & Network Proxy
    // ------------------------------------------------------------------------
    if app_id.contains("localsend") && matches!(canonical_action, "send_file" | "wake_receiver") {
        if canonical_action == "send_file" {
            let Some(raw_p) = params
                .get("path")
                .or_else(|| params.get("file"))
                .and_then(|v| v.as_str())
            else {
                return Some(build_error_outcome(
                    &app_id,
                    &app_name,
                    "send_file",
                    AdaptationChannel::CliWrapper,
                    "LocalSend 发送文件缺少 `path` 参数",
                ));
            };
            let pb = match validate_non_forbidden_path(core, raw_p) {
                Ok(p) => p,
                Err(e) => {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        "send_file",
                        AdaptationChannel::CliWrapper,
                        e.to_string(),
                    ));
                }
            };
            return Some(spawn_or_preview_gui_command(
                &app_id,
                &app_name,
                "send_file",
                AdaptationChannel::CliWrapper,
                &["localsend_app", "localsend"],
                &[pb.to_string_lossy().to_string()],
                &[],
                is_dry_run(params),
                json!({ "file": pb }),
            ));
        }
        return Some(
            try_wake_via_sni_or_launch(
                &app_id,
                &app_name,
                "wake_receiver",
                "localsend",
                &["localsend_app", "localsend"],
                &[],
                &[],
                is_dry_run(params),
            )
            .await,
        );
    }

    if (app_id.contains("baidunetdisk") || app_id.contains("mcloud"))
        && matches!(
            canonical_action,
            "wake_cloud_drive" | "open_download_folder"
        )
    {
        if canonical_action == "wake_cloud_drive" {
            let bins: &[&str] = if app_id.contains("baidunetdisk") {
                &["/opt/baidunetdisk/baidunetdisk", "baidunetdisk"]
            } else {
                &["/opt/apps/com.cmic.mcloud/files/mcloud", "mcloud"]
            };
            return Some(
                try_wake_via_sni_or_launch(
                    &app_id,
                    &app_name,
                    "wake_cloud_drive",
                    &app_id,
                    bins,
                    &[],
                    &[],
                    is_dry_run(params),
                )
                .await,
            );
        }

        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
        let candidates = [
            PathBuf::from(&home).join("baidunetdiskdownload"),
            PathBuf::from(&home).join("Downloads"),
            PathBuf::from(&home),
        ];
        let folder = candidates
            .into_iter()
            .find(|p| p.is_dir() && !core.fs_engine.is_forbidden(p))
            .unwrap_or_else(|| PathBuf::from(&home).join("Downloads"));
        let item_count = fs::read_dir(&folder).map(|rd| rd.count()).unwrap_or(0);
        return Some(spawn_or_preview_gui_command(
            &app_id,
            &app_name,
            "open_download_folder",
            AdaptationChannel::CliWrapper,
            &["nautilus", "gio"],
            &[folder.to_string_lossy().to_string()],
            &[],
            is_dry_run(params),
            json!({ "download_folder": folder, "entry_count": item_count }),
        ));
    }

    if app_id.contains("flclash") || app_id == "clash-verge" {
        if canonical_action == "probe_proxy_status" {
            return Some(exec_flclash_probe_status(&app_id, &app_name).await);
        }
        if canonical_action == "wake_dashboard" {
            return Some(
                try_wake_via_sni_or_launch(
                    &app_id,
                    &app_name,
                    "wake_dashboard",
                    "flclash",
                    &["/opt/FlClash/FlClash", "FlClash", "clash-verge"],
                    &[],
                    &[],
                    is_dry_run(params),
                )
                .await,
            );
        }
    }

    if app_id.contains("tailscale") && canonical_action == "tailscale_status" {
        return Some(exec_tailscale_status(&app_id, &app_name, params).await);
    }

    if matches!(
        app_id.as_str(),
        "google-chrome" | "brave" | "firefox" | "microsoft-edge"
    ) && matches!(
        canonical_action,
        "open_url" | "open_incognito" | "open_new_window" | "open_app_mode"
    ) {
        let bins: &[&str] = match app_id.as_str() {
            "brave" => &["brave-browser", "/opt/brave.com/brave/brave-browser"],
            "firefox" => &["firefox", "/snap/bin/firefox"],
            "microsoft-edge" => &["microsoft-edge"],
            _ => &[
                "google-chrome",
                "/opt/google/chrome/google-chrome",
                "chromium",
            ],
        };
        let opt_url = if let Some(u) = params
            .get("url")
            .or_else(|| params.get("uri"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
        {
            match validate_uri_safety(u, &[]) {
                Ok(valid) => Some(valid),
                Err(e) => {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        canonical_action,
                        AdaptationChannel::CliWrapper,
                        e.to_string(),
                    ));
                }
            }
        } else {
            None
        };

        let mut args = Vec::new();
        match canonical_action {
            "open_incognito" => {
                args.push(if app_id == "firefox" {
                    "--private-window".into()
                } else {
                    "--incognito".into()
                });
                if let Some(u) = opt_url {
                    args.push(u);
                }
            }
            "open_new_window" => {
                args.push("--new-window".into());
                if let Some(u) = opt_url {
                    args.push(u);
                }
            }
            "open_app_mode" => {
                let Some(u) = opt_url else {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        "open_app_mode",
                        AdaptationChannel::CliWrapper,
                        "浏览器独立应用模式缺少 `url` 参数",
                    ));
                };
                args.push(format!("--app={}", u));
            }
            _ => {
                let Some(u) = opt_url else {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        "open_url",
                        AdaptationChannel::CliWrapper,
                        "打开网页缺少 `url` 参数",
                    ));
                };
                args.push(u);
            }
        }
        return Some(spawn_or_preview_gui_command(
            &app_id,
            &app_name,
            canonical_action,
            AdaptationChannel::CliWrapper,
            bins,
            &args,
            &[],
            is_dry_run(params),
            json!({}),
        ));
    }

    // ------------------------------------------------------------------------
    // 5. AI Coding IDEs, Diagramming, VirtualBox, RustDesk & Hardware Tools
    // ------------------------------------------------------------------------
    if matches!(
        app_id.as_str(),
        "vscode" | "zcode" | "cursor" | "trae-cn" | "antigravity-ide" | "workbuddy"
    ) && matches!(
        canonical_action,
        "open_project" | "goto_file_line" | "diff_two_files"
    ) {
        let bins: &[&str] = match app_id.as_str() {
            "zcode" => &["zcode", "code"],
            "cursor" => &["cursor", "code"],
            "trae-cn" => &["/opt/Trae CN/trae-cn", "trae-cn", "code"],
            "antigravity-ide" => &["agy", "antigravity", "code"],
            "workbuddy" => &["/opt/WorkBuddy/workbuddy", "workbuddy", "code"],
            _ => &["code", "/usr/share/code/code"],
        };

        match canonical_action {
            "open_project" => {
                let Some(raw_dir) = params
                    .get("path")
                    .or_else(|| params.get("dir"))
                    .or_else(|| params.get("workspace"))
                    .and_then(|v| v.as_str())
                else {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        "open_project",
                        AdaptationChannel::CliWrapper,
                        "IDE 打开工程缺少 `path` 参数",
                    ));
                };
                let pb = match validate_non_forbidden_path(core, raw_dir) {
                    Ok(p) => p,
                    Err(e) => {
                        return Some(build_error_outcome(
                            &app_id,
                            &app_name,
                            "open_project",
                            AdaptationChannel::CliWrapper,
                            e.to_string(),
                        ));
                    }
                };
                return Some(spawn_or_preview_gui_command(
                    &app_id,
                    &app_name,
                    "open_project",
                    AdaptationChannel::CliWrapper,
                    bins,
                    &[pb.to_string_lossy().to_string()],
                    &[],
                    is_dry_run(params),
                    json!({ "project_dir": pb }),
                ));
            }
            "goto_file_line" => {
                let Some(raw_f) = params
                    .get("path")
                    .or_else(|| params.get("file"))
                    .and_then(|v| v.as_str())
                else {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        "goto_file_line",
                        AdaptationChannel::CliWrapper,
                        "IDE 跳转文件行号缺少 `path` 参数",
                    ));
                };
                let pb = match validate_non_forbidden_path(core, raw_f) {
                    Ok(p) => p,
                    Err(e) => {
                        return Some(build_error_outcome(
                            &app_id,
                            &app_name,
                            "goto_file_line",
                            AdaptationChannel::CliWrapper,
                            e.to_string(),
                        ));
                    }
                };
                let line = params
                    .get("line")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1)
                    .max(1);
                let col = params
                    .get("column")
                    .or_else(|| params.get("col"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1)
                    .max(1);
                let target = format!("{}:{}:{}", pb.display(), line, col);
                return Some(spawn_or_preview_gui_command(
                    &app_id,
                    &app_name,
                    "goto_file_line",
                    AdaptationChannel::CliWrapper,
                    bins,
                    &["--goto".to_string(), target],
                    &[],
                    is_dry_run(params),
                    json!({ "file": pb, "line": line, "column": col }),
                ));
            }
            _ => {
                let raw_a = params
                    .get("left")
                    .or_else(|| params.get("file_a"))
                    .and_then(|v| v.as_str());
                let raw_b = params
                    .get("right")
                    .or_else(|| params.get("file_b"))
                    .and_then(|v| v.as_str());
                let (Some(a), Some(b)) = (raw_a, raw_b) else {
                    return Some(build_error_outcome(
                        &app_id,
                        &app_name,
                        canonical_action,
                        AdaptationChannel::CliWrapper,
                        "IDE 双文件对比缺少 `left`/`file_a` 与 `right`/`file_b` 参数",
                    ));
                };
                let pa = match validate_non_forbidden_path(core, a) {
                    Ok(p) => p,
                    Err(e) => {
                        return Some(build_error_outcome(
                            &app_id,
                            &app_name,
                            canonical_action,
                            AdaptationChannel::CliWrapper,
                            e.to_string(),
                        ));
                    }
                };
                let pb = match validate_non_forbidden_path(core, b) {
                    Ok(p) => p,
                    Err(e) => {
                        return Some(build_error_outcome(
                            &app_id,
                            &app_name,
                            canonical_action,
                            AdaptationChannel::CliWrapper,
                            e.to_string(),
                        ));
                    }
                };
                return Some(spawn_or_preview_gui_command(
                    &app_id,
                    &app_name,
                    canonical_action,
                    AdaptationChannel::CliWrapper,
                    bins,
                    &[
                        "--diff".to_string(),
                        pa.to_string_lossy().to_string(),
                        pb.to_string_lossy().to_string(),
                    ],
                    &[],
                    is_dry_run(params),
                    json!({ "left": pa, "right": pb }),
                ));
            }
        }
    }

    if app_id == "drawio" {
        if canonical_action == "export_diagram" {
            return Some(exec_drawio_export(core, &app_id, &app_name, params).await);
        }
        if canonical_action == "open_diagram" {
            let mut args = Vec::new();
            if let Some(p) = params.get("path").and_then(|v| v.as_str()) {
                match validate_non_forbidden_path(core, p) {
                    Ok(pb) => args.push(pb.to_string_lossy().to_string()),
                    Err(e) => {
                        return Some(build_error_outcome(
                            &app_id,
                            &app_name,
                            "open_diagram",
                            AdaptationChannel::CliWrapper,
                            e.to_string(),
                        ));
                    }
                }
            }
            return Some(spawn_or_preview_gui_command(
                &app_id,
                &app_name,
                "open_diagram",
                AdaptationChannel::CliWrapper,
                &["/opt/drawio/drawio", "drawio"],
                &args,
                &[],
                is_dry_run(params),
                json!({}),
            ));
        }
    }

    if app_id == "virtualbox"
        && matches!(canonical_action, "list_vms" | "start_vm" | "savestate_vm")
    {
        return Some(
            exec_virtualbox_action(&app_id, &app_name, canonical_action, params, approved).await,
        );
    }

    if app_id == "rustdesk" && matches!(canonical_action, "get_device_id" | "connect_peer") {
        return Some(
            exec_rustdesk_action(&app_id, &app_name, canonical_action, params, approved).await,
        );
    }

    if app_id == "fcitx5"
        && matches!(
            canonical_action,
            "input_method_status" | "activate_chinese" | "deactivate_chinese" | "open_fcitx_config"
        )
    {
        return Some(exec_fcitx5_action(&app_id, &app_name, canonical_action, params).await);
    }

    if (app_id == "nvidia-settings" || app_id == "nvidia")
        && matches!(
            canonical_action,
            "query_gpu_telemetry" | "open_nvidia_settings"
        )
    {
        return Some(exec_nvidia_telemetry(&app_id, &app_name, canonical_action, params).await);
    }

    if app_id == "nautilus" && canonical_action == "select_in_folder" {
        let Some(raw_p) = params.get("path").and_then(|v| v.as_str()) else {
            return Some(build_error_outcome(
                &app_id,
                &app_name,
                canonical_action,
                AdaptationChannel::CliWrapper,
                "文件管理器高亮定位缺少 `path` 参数",
            ));
        };
        let pb = match validate_non_forbidden_path(core, raw_p) {
            Ok(p) => p,
            Err(e) => {
                return Some(build_error_outcome(
                    &app_id,
                    &app_name,
                    canonical_action,
                    AdaptationChannel::CliWrapper,
                    e.to_string(),
                ));
            }
        };
        return Some(spawn_or_preview_gui_command(
            &app_id,
            &app_name,
            canonical_action,
            AdaptationChannel::CliWrapper,
            &["nautilus"],
            &["--select".to_string(), pb.to_string_lossy().to_string()],
            &[],
            is_dry_run(params),
            json!({ "selected_path": pb }),
        ));
    }

    // Universal `launch_app` & `open_file` on any scanned app
    if matches!(canonical_action, "launch_app" | "open_file")
        && let Some(scanned) = find_scanned_app(core, registry, target_app).await
    {
        if canonical_action == "open_file" {
            let Some(raw_p) = params.get("path").and_then(|v| v.as_str()) else {
                return Some(build_error_outcome(
                    &scanned.id,
                    &scanned.display_name,
                    "open_file",
                    AdaptationChannel::CliWrapper,
                    "打开文件缺少 `path` 参数",
                ));
            };
            if let Err(e) = validate_non_forbidden_path(core, raw_p) {
                return Some(build_error_outcome(
                    &scanned.id,
                    &scanned.display_name,
                    "open_file",
                    AdaptationChannel::CliWrapper,
                    e.to_string(),
                ));
            }
        }
        return Some(
            execute_desktop_action_by_id(
                core,
                registry,
                &scanned.desktop_id,
                "launch_app",
                params,
                &[],
            )
            .await,
        );
    }

    // Universal uncurated `.desktop` app dispatcher
    if resolved_prof.is_none()
        && let Some(scanned) = find_scanned_app(core, registry, target_app).await
    {
        if scanned
            .desktop_actions
            .iter()
            .any(|da| da.action_id.eq_ignore_ascii_case(raw_action.trim()))
        {
            return Some(
                execute_desktop_action_by_id(
                    core,
                    registry,
                    &scanned.desktop_id,
                    raw_action.trim(),
                    params,
                    &[],
                )
                .await,
            );
        }

        match canonical_action {
            "focus_window" => {
                let env_vec: Vec<(String, String)> = scanned
                    .env_overrides
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let (_, base_args, _) = tokenize_desktop_exec_with_env(&scanned.exec_raw, None)
                    .unwrap_or_else(|_| (scanned.exec_binary.clone(), Vec::new(), Vec::new()));
                return Some(
                    try_wake_via_sni_or_launch(
                        &scanned.id,
                        &scanned.display_name,
                        "focus_window",
                        &scanned.id,
                        &[scanned.exec_binary.as_str()],
                        &base_args,
                        &env_vec,
                        is_dry_run(params),
                    )
                    .await,
                );
            }
            "open_uri" => {
                let Some(raw_u) = params
                    .get("uri")
                    .or_else(|| params.get("url"))
                    .and_then(|v| v.as_str())
                else {
                    return Some(build_error_outcome(
                        &scanned.id,
                        &scanned.display_name,
                        "open_uri",
                        AdaptationChannel::UriScheme,
                        "缺少 `uri` 参数",
                    ));
                };
                let valid = match validate_uri_safety(raw_u, &scanned.uri_schemes) {
                    Ok(u) => u,
                    Err(e) => {
                        return Some(build_error_outcome(
                            &scanned.id,
                            &scanned.display_name,
                            "open_uri",
                            AdaptationChannel::UriScheme,
                            e.to_string(),
                        ));
                    }
                };
                return Some(spawn_or_preview_gui_command(
                    &scanned.id,
                    &scanned.display_name,
                    "open_uri",
                    AdaptationChannel::UriScheme,
                    &["gio", "xdg-open"],
                    &["open".to_string(), valid.clone()],
                    &[],
                    is_dry_run(params),
                    json!({ "uri": valid }),
                ));
            }
            _ => {}
        }
    }

    None
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_nine_categories_and_normalization() {
        assert_eq!(all_software_categories().len(), 9);
        assert_eq!(
            normalize_software_category("media"),
            Some("media_entertainment")
        );
        assert_eq!(
            normalize_software_category("💬 社交通讯与视频会议"),
            Some("social_collab")
        );
        assert_eq!(
            normalize_software_category("office"),
            Some("office_notes_doc")
        );
        assert_eq!(
            normalize_software_category("browser"),
            Some("network_browser")
        );
        assert_eq!(normalize_software_category("ide"), Some("dev_ai_ide"));
        assert!(categories_match("media_entertainment", "media"));
        assert!(categories_match("office_notes_doc", "notes"));
        assert!(categories_match("dev_ai_ide", "all"));
    }

    #[test]
    fn test_classifier_covers_all_nine_categories_accurately() {
        let cases = [
            (
                "qqmusic.desktop",
                "/opt/qqmusic/qqmusic",
                "qqmusic",
                Some("QQ音乐"),
                "media_entertainment",
            ),
            (
                "sodam.desktop",
                "/opt/SodaM/sodam",
                "SodaM",
                Some("汽水音乐"),
                "media_entertainment",
            ),
            (
                "chrome-ibcfedatapddnfdnbjfkamdhbiepdbke-Default.desktop",
                "/opt/google/chrome/google-chrome",
                "抖音",
                Some("抖音"),
                "media_entertainment",
            ),
            (
                "qq.desktop",
                "/opt/QQ/qq",
                "QQ",
                Some("QQ"),
                "social_collab",
            ),
            (
                "wemeetapp.desktop",
                "/opt/wemeet/wemeetapp.sh",
                "Tencent Meeting",
                Some("腾讯会议"),
                "social_collab",
            ),
            (
                "bytedance-feishu.desktop",
                "/opt/bytedance/feishu/bytedance-feishu",
                "Feishu",
                Some("飞书"),
                "social_collab",
            ),
            (
                "wps-office-wps.desktop",
                "/usr/bin/wps",
                "WPS Writer",
                Some("WPS 文字"),
                "office_notes_doc",
            ),
            (
                "yozo-office-word.desktop",
                "/opt/apps/Yozo_Office/yozow",
                "Yozo Writer",
                Some("永中文字"),
                "office_notes_doc",
            ),
            (
                "com.github.paperhead.BetterNotes.desktop",
                "/usr/bin/betternotes",
                "BetterNotes",
                Some("轻笺"),
                "office_notes_doc",
            ),
            (
                "baidunetdisk.desktop",
                "/opt/baidunetdisk/baidunetdisk",
                "baidunetdisk",
                Some("百度网盘"),
                "cloud_transfer",
            ),
            (
                "localsend_app.desktop",
                "/usr/bin/localsend_app",
                "LocalSend",
                None,
                "cloud_transfer",
            ),
            (
                "FlClash.desktop",
                "/opt/FlClash/FlClash",
                "FlClash",
                None,
                "network_browser",
            ),
            (
                "trae-cn.desktop",
                "/opt/Trae CN/trae-cn",
                "Trae CN",
                None,
                "dev_ai_ide",
            ),
            (
                "antigravity-ide.desktop",
                "/usr/bin/agy",
                "Antigravity IDE",
                None,
                "dev_ai_ide",
            ),
            (
                "crypticapps-com.hopperapp.Hopper.desktop",
                "/opt/hopper/bin/Hopper",
                "Hopper",
                None,
                "dev_ai_ide",
            ),
            (
                "drawio.desktop",
                "/opt/drawio/drawio",
                "draw.io",
                None,
                "creative_disc",
            ),
            (
                "io.github.discforge.native.desktop",
                "/usr/bin/discforge",
                "DiscForge",
                Some("光铸"),
                "creative_disc",
            ),
            (
                "rustdesk.desktop",
                "/usr/bin/rustdesk",
                "RustDesk",
                None,
                "remote_vm",
            ),
            (
                "virtualbox.desktop",
                "/usr/bin/virtualbox",
                "Oracle VirtualBox",
                None,
                "remote_vm",
            ),
            (
                "omni-mouse-studio.desktop",
                "/opt/OmniMouseStudio/omni-mouse-studio",
                "Omni Mouse",
                Some("多功能鼠标智控中心"),
                "hardware_system",
            ),
            (
                "org.fcitx.Fcitx5.desktop",
                "/usr/bin/fcitx5",
                "Fcitx 5",
                None,
                "hardware_system",
            ),
        ];

        for (did, bin, name, zh, expected_cat) in cases {
            let meta = classify_software_category(did, bin, name, zh, None, &[], &[], &[]);
            assert_eq!(
                meta.id, expected_cat,
                "Expected {} ({}) to classify as {}, got {}",
                did, name, expected_cat, meta.id
            );
        }
    }

    #[tokio::test]
    async fn test_user_override_url_handler_harvesting_and_uninstall_filtering() {
        let tmp = tempdir().expect("tempdir");
        let sys_dir = tmp.path().join("sys_apps");
        let user_dir = tmp.path().join("user_apps");
        fs::create_dir_all(&sys_dir).unwrap();
        fs::create_dir_all(&user_dir).unwrap();

        fs::write(
            sys_dir.join("qqmusic.desktop"),
            "[Desktop Entry]\nType=Application\nName=qqmusic\nName[zh_CN]=QQ音乐\nExec=/opt/qqmusic/qqmusic %U\nIcon=qqmusic\n",
        )
        .unwrap();

        fs::write(
            user_dir.join("qqmusic.desktop"),
            "[Desktop Entry]\nType=Application\nName=QQMusic\nExec=env LIBGL_ALWAYS_SOFTWARE=1 /opt/qqmusic/qqmusic --use-gl=swiftshader %U\n",
        )
        .unwrap();

        fs::write(
            sys_dir.join("wemeetapp.desktop"),
            "[Desktop Entry]\nType=Application\nName=WeMeet\nName[zh_CN]=腾讯会议\nExec=/opt/wemeet/wemeetapp.sh %u\nMimeType=x-scheme-handler/wemeet;\nActions=JoinQuick;\n\n[Desktop Action JoinQuick]\nName=Quick Join\nName[zh_CN]=快速入会\nExec=/opt/wemeet/wemeetapp.sh --quick\n",
        )
        .unwrap();

        fs::write(
            sys_dir.join("trae-cn.desktop"),
            "[Desktop Entry]\nType=Application\nName=Trae CN\nExec=\"/opt/Trae CN/trae-cn\" %F\n",
        )
        .unwrap();
        fs::write(
            sys_dir.join("trae-cn-url-handler.desktop"),
            "[Desktop Entry]\nType=Application\nName=Trae CN URL Handler\nNoDisplay=true\nExec=\"/opt/Trae CN/trae-cn\" --open-url %U\nMimeType=x-scheme-handler/trae-cn;\n",
        )
        .unwrap();

        fs::write(
            sys_dir.join("yozo-uninstall.desktop"),
            "[Desktop Entry]\nType=Application\nName=Remove Yozo Office\nName[zh_CN]=卸载永中Office\nExec=/opt/apps/Yozo_Office/uninstall/uninstall\n",
        )
        .unwrap();

        let reg = AdapterRegistry::builtin_only();
        let catalog = deep_scan_local_software(
            None,
            &reg,
            &LocalScanOptions {
                force_refresh: true,
                scan_dirs: vec![sys_dir, user_dir],
                ..Default::default()
            },
        )
        .await;

        assert_eq!(catalog.total_scanned, 3);
        assert_eq!(catalog.categories.len(), 9);

        let qm = catalog
            .apps
            .iter()
            .find(|a| a.desktop_id == "qqmusic.desktop")
            .expect("qqmusic present");
        assert_eq!(qm.display_name, "QQ音乐");
        assert_eq!(
            qm.env_overrides
                .get("LIBGL_ALWAYS_SOFTWARE")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(qm.category_id, "media_entertainment");

        let wm = catalog
            .apps
            .iter()
            .find(|a| a.desktop_id == "wemeetapp.desktop")
            .expect("wemeet present");
        assert!(wm.uri_schemes.contains(&"wemeet".to_string()));
        assert_eq!(wm.desktop_actions.len(), 1);
        assert_eq!(wm.desktop_actions[0].display_name, "快速入会");

        let trae = catalog
            .apps
            .iter()
            .find(|a| a.desktop_id == "trae-cn.desktop")
            .expect("trae-cn present");
        assert!(trae.uri_schemes.contains(&"trae-cn".to_string()));
    }

    #[tokio::test]
    async fn test_host_deep_scan_discovers_rich_apps_if_present() {
        if !Path::new("/usr/share/applications").is_dir() {
            return;
        }
        let reg = AdapterRegistry::builtin_only();
        let catalog = deep_scan_local_software(
            None,
            &reg,
            &LocalScanOptions {
                force_refresh: true,
                ..Default::default()
            },
        )
        .await;
        println!(
            "[host_deep_scan] total_scanned={} total_adapted={} total_interfaces={} running_count={} companion_clis={} builtins={}",
            catalog.total_scanned,
            catalog.total_adapted,
            catalog.total_interfaces,
            catalog.running_count,
            catalog.companion_cli_tools.len(),
            reg.builtin_count()
        );
        for c in &catalog.categories {
            println!(
                "  [cat] {} ({}) -> count={} running={}",
                c.id, c.category_zh, c.count, c.running_count
            );
        }
        assert!(catalog.total_scanned >= 10);
        assert_eq!(catalog.categories.len(), 9);
        assert!(catalog.total_interfaces >= catalog.total_scanned * 3);
    }

    #[tokio::test]
    async fn h09_local_scanner_mtime_120s_ttl_singleflight_and_invalidation() {
        use std::sync::Arc;

        assert_eq!(SCAN_CACHE_TTL, Duration::from_secs(120));
        clear_deep_scan_cache();

        let tmp = tempdir().expect("tempdir");
        let apps_dir = tmp.path().join("applications");
        fs::create_dir_all(&apps_dir).unwrap();
        fs::write(
            apps_dir.join("code.desktop"),
            "[Desktop Entry]\nType=Application\nName=VS Code\nExec=/usr/bin/code %F\n",
        )
        .unwrap();

        let reg = Arc::new(AdapterRegistry::builtin_only());
        let opts = LocalScanOptions {
            force_refresh: false,
            scan_dirs: vec![apps_dir.clone()],
            ..Default::default()
        };

        let before_scans = deep_scan_execution_count();

        // 1. 10 concurrent cold callers coalesce via the single-flight mutex into 1 scan pass.
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let r = Arc::clone(&reg);
            let o = opts.clone();
            tasks.push(tokio::spawn(async move {
                deep_scan_local_software(None, &r, &o).await
            }));
        }
        for t in tasks {
            let cat = t.await.expect("join concurrent scan");
            assert_eq!(cat.total_scanned, 1);
        }
        assert_eq!(
            deep_scan_execution_count() - before_scans,
            1,
            "10 concurrent scans must coalesce into exactly 1 execution"
        );

        // 2. Warm 120s TTL hit returns `cached == true` in < 1 ms with zero extra scans.
        let warm_start = Instant::now();
        let warm_cat = deep_scan_local_software(None, &reg, &opts).await;
        let warm_elapsed = warm_start.elapsed();
        assert!(warm_cat.cached);
        assert_eq!(warm_cat.total_scanned, 1);
        assert!(
            warm_elapsed < Duration::from_millis(2),
            "warm deep_scan_local_software hit took {:?}",
            warm_elapsed
        );
        assert_eq!(deep_scan_execution_count() - before_scans, 1);

        // 3. Adding a new `.desktop` file invalidates directory fingerprint immediately without force_refresh!
        fs::write(
            apps_dir.join("vlc.desktop"),
            "[Desktop Entry]\nType=Application\nName=VLC\nExec=/usr/bin/vlc %U\n",
        )
        .unwrap();

        let invalidated_cat = deep_scan_local_software(None, &reg, &opts).await;
        assert!(!invalidated_cat.cached);
        assert_eq!(invalidated_cat.total_scanned, 2);
        assert_eq!(deep_scan_execution_count() - before_scans, 2);
    }
}
