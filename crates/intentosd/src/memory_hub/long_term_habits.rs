#![forbid(unsafe_code)]

//! Long-Term File Habits (`recently-used.xbel` + Frecency) & Full Ubuntu Software Inventory
//! (`long_term_habits.rs`).
//!
//! 1. Parses Ubuntu's `~/.local/share/recently-used.xbel` (with XML entity unescaping and UTF-8
//!    percent-decoding for Chinese paths), merges `core.resources` indexed files and IntentOS
//!    tool counts, and ranks Long-Term / Frequently Used Files by Frecency (`frequency * recency_decay`).
//! 2. Scans `/usr/share/applications`, `/usr/local/share/applications`, `~/.local/share/applications`,
//!    `/var/lib/snapd/desktop/applications`, and Flatpak `.desktop` directories to build a complete
//!    Ubuntu software catalog + frequently used app profile (`Name[zh_CN]`, `Name`, `GenericName`,
//!    `Comment`, `Exec`, `Categories`, `MimeType`, `DBusActivatable`, `x-scheme-handler/*` URI schemes).

use crate::core::IntentOsCore;
use crate::memory_hub::schema_and_db::{
    CategoryCount, InstalledAppsSummary, LongTermFileHabit, MemoryHubDb, SoftwareProfile,
    is_hermetic_test_core, is_sensitive_credential_path,
};
use crate::resource::to_pinyin_pair;
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::WalkDir;

/// Parsed `<bookmark:application .../>` record inside an XBEL `<bookmark>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XbelAppUsage {
    pub name: String,
    pub exec: String,
    pub count: u64,
    pub modified: Option<String>,
}

/// Parsed `<bookmark href="file://...">` entry from `recently-used.xbel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XbelBookmark {
    pub path: String,
    pub visited: Option<String>,
    pub modified: Option<String>,
    pub added: Option<String>,
    pub last_used_at: String,
    pub last_used_epoch: i64,
    pub mime_type: String,
    pub total_open_count: u64,
    pub preferred_apps: Vec<String>,
    pub applications: Vec<XbelAppUsage>,
}

/// Summary returned after `sync_system_usage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSummary {
    pub synced_xbel_bookmarks: usize,
    pub total_frequent_files: usize,
    pub total_installed_apps: usize,
    pub frequent_apps_count: usize,
    pub synced_at: String,
}

const PORTAL_HELPER_APPS: &[&str] = &[
    "xdg-desktop-portal-gtk",
    "xdg-desktop-portal-gnome",
    "xdg-desktop-portal-kde",
    "xdg-desktop-portal",
    "xdg-open",
    "gio",
    "gvfsd-metadata",
    "tracker-extract",
];

/// Compute Frecency score = `frequency * recency_decay` (with disk-existence factor).
pub fn compute_frecency_score(
    count: u64,
    last_used_epoch: i64,
    now_epoch: i64,
    exists_on_disk: bool,
) -> f64 {
    let effective_count = count.max(1) as f64;
    let frequency = effective_count.powf(0.85) * 10.0;
    let age_days = if last_used_epoch > 0 {
        ((now_epoch - last_used_epoch).max(0) as f64) / 86_400.0
    } else {
        60.0
    };
    // Smooth 30-day half-life decay: preserves multi-month long-term habits while rewarding recent activity
    let recency_decay = 1.0 / (1.0 + age_days / 30.0);
    let disk_factor = if exists_on_disk { 1.0 } else { 0.35 };
    ((frequency * recency_decay * disk_factor) * 100.0).round() / 100.0
}

/// Parse an XBEL XML string (`~/.local/share/recently-used.xbel`) into decoded `XbelBookmark` items.
pub fn parse_xbel_content(xml: &str) -> Vec<XbelBookmark> {
    static BOOKMARK_BLOCK_RE: OnceLock<Regex> = OnceLock::new();
    static MIME_RE: OnceLock<Regex> = OnceLock::new();
    static APP_TAG_RE: OnceLock<Regex> = OnceLock::new();

    let bookmark_re = BOOKMARK_BLOCK_RE.get_or_init(|| {
        Regex::new(r"(?s)<bookmark\b([^>]*)>(.*?)</bookmark>").expect("valid bookmark regex")
    });
    let mime_re = MIME_RE.get_or_init(|| {
        Regex::new(r#"<mime:mime-type\b[^>]*\btype\s*=\s*["']([^"']+)["']"#)
            .expect("valid mime regex")
    });
    let app_re = APP_TAG_RE.get_or_init(|| {
        Regex::new(r"(?s)<bookmark:application\b([^>]*)/?>").expect("valid bookmark app regex")
    });

    let mut by_path: HashMap<String, XbelBookmark> = HashMap::new();

    for caps in bookmark_re.captures_iter(xml) {
        let header_attrs = &caps[1];
        let body = &caps[2];

        let Some(raw_href) = extract_xml_attr(header_attrs, "href") else {
            continue;
        };
        let Some(decoded_path) = decode_file_uri(&raw_href) else {
            continue;
        };
        if decoded_path.is_empty() || is_sensitive_credential_path(&decoded_path) {
            continue;
        }

        let visited = extract_xml_attr(header_attrs, "visited");
        let modified = extract_xml_attr(header_attrs, "modified");
        let added = extract_xml_attr(header_attrs, "added");

        let mime_type = mime_re
            .captures(body)
            .and_then(|c| c.get(1))
            .map(|m| unescape_xml_entities(m.as_str()))
            .unwrap_or_default();

        let mut applications = Vec::new();
        let mut latest_app_epoch: i64 = 0;
        let mut latest_app_ts: Option<String> = None;

        for app_caps in app_re.captures_iter(body) {
            let app_attrs = &app_caps[1];
            let name = extract_xml_attr(app_attrs, "name").unwrap_or_default();
            let raw_exec = extract_xml_attr(app_attrs, "exec").unwrap_or_default();
            let clean_exec = clean_xbel_exec(&raw_exec);
            let count = extract_xml_attr(app_attrs, "count")
                .and_then(|c| c.trim().parse::<u64>().ok())
                .unwrap_or(1)
                .max(1);
            let app_mod = extract_xml_attr(app_attrs, "modified");
            if let Some(ref ts) = app_mod {
                let ep = parse_timestamp_epoch(ts);
                if ep > latest_app_epoch {
                    latest_app_epoch = ep;
                    latest_app_ts = Some(ts.clone());
                }
            }
            if !name.is_empty() || !clean_exec.is_empty() {
                applications.push(XbelAppUsage {
                    name,
                    exec: clean_exec,
                    count,
                    modified: app_mod,
                });
            }
        }

        // Determine best last_used timestamp across visited, modified, app.modified, added
        let mut best_epoch = 0i64;
        let mut best_ts = String::new();
        for cand in [
            visited.as_deref(),
            modified.as_deref(),
            latest_app_ts.as_deref(),
            added.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let ep = parse_timestamp_epoch(cand);
            if ep >= best_epoch {
                best_epoch = ep;
                best_ts = cand.to_string();
            }
        }
        if best_ts.is_empty() {
            best_ts = Utc::now().to_rfc3339();
            best_epoch = Utc::now().timestamp();
        }

        // Compute open_count & preferred_apps (deprioritizing portal plumbing wrappers)
        let non_portal_sum: u64 = applications
            .iter()
            .filter(|a| !is_portal_helper_app(&a.name, &a.exec))
            .map(|a| a.count)
            .sum();
        let all_sum: u64 = applications.iter().map(|a| a.count).sum();
        let total_open_count = if non_portal_sum > 0 {
            non_portal_sum
        } else {
            all_sum.max(1)
        };

        let mut ranked_apps: Vec<&XbelAppUsage> = applications.iter().collect();
        ranked_apps.sort_by(|a, b| {
            let a_portal = is_portal_helper_app(&a.name, &a.exec);
            let b_portal = is_portal_helper_app(&b.name, &b.exec);
            a_portal.cmp(&b_portal).then_with(|| b.count.cmp(&a.count))
        });
        let mut preferred_apps = Vec::new();
        for a in ranked_apps {
            if is_portal_helper_app(&a.name, &a.exec) && non_portal_sum > 0 {
                continue;
            }
            let label = if !a.name.is_empty() {
                a.name.clone()
            } else {
                a.exec.clone()
            };
            if !label.is_empty() && !preferred_apps.contains(&label) {
                preferred_apps.push(label);
            }
        }

        if let Some(existing) = by_path.get_mut(&decoded_path) {
            existing.total_open_count += total_open_count;
            if best_epoch > existing.last_used_epoch {
                existing.last_used_epoch = best_epoch;
                existing.last_used_at = best_ts;
            }
            for p in preferred_apps {
                if !existing.preferred_apps.contains(&p) {
                    existing.preferred_apps.push(p);
                }
            }
            existing.applications.extend(applications);
        } else {
            by_path.insert(
                decoded_path.clone(),
                XbelBookmark {
                    path: decoded_path,
                    visited,
                    modified,
                    added,
                    last_used_at: best_ts,
                    last_used_epoch: best_epoch,
                    mime_type,
                    total_open_count,
                    preferred_apps,
                    applications,
                },
            );
        }
    }

    let mut out: Vec<XbelBookmark> = by_path.into_values().collect();
    out.sort_by(|a, b| {
        b.total_open_count
            .cmp(&a.total_open_count)
            .then_with(|| b.last_used_epoch.cmp(&a.last_used_epoch))
    });
    out
}

/// Read and parse an XBEL file from disk (returns empty Vec cleanly if file does not exist).
pub fn parse_xbel_file(path: &Path) -> Vec<XbelBookmark> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_xbel_content(&raw)
}

fn decode_file_uri(raw_href: &str) -> Option<String> {
    let unescaped = unescape_xml_entities(raw_href.trim());
    let encoded_path = if let Some(rest) = unescaped.strip_prefix("file://localhost/") {
        format!("/{}", rest)
    } else if let Some(rest) = unescaped.strip_prefix("file:///") {
        format!("/{}", rest)
    } else if let Some(rest) = unescaped.strip_prefix("file://~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        format!("{}/{}", home.trim_end_matches('/'), rest)
    } else if let Some(rest) = unescaped.strip_prefix("file://") {
        if rest.starts_with('/') {
            rest.to_string()
        } else {
            return None;
        }
    } else {
        return None;
    };

    Some(percent_decode_utf8_lossy(&encoded_path))
}

/// Byte-level forgiving UTF-8 percent-decoder that decodes Chinese XDG paths
/// (e.g. `/home/.../%E6%A1%8C%E9%9D%A2/paper_main.docx` -> `/home/.../桌面/paper_main.docx`)
/// even when filenames contain literal `%` or `+` characters.
fn percent_decode_utf8_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn extract_xml_attr(attrs: &str, attr_name: &str) -> Option<String> {
    for (idx, _) in attrs.match_indices(attr_name) {
        let prev_ok = attrs[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| c.is_whitespace());
        if !prev_ok {
            continue;
        }
        let rest = attrs[idx + attr_name.len()..].trim_start();
        let Some(after_eq) = rest.strip_prefix('=') else {
            continue;
        };
        let after_eq = after_eq.trim_start();
        let Some(quote) = after_eq.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            continue;
        };
        let inner = &after_eq[quote.len_utf8()..];
        let end = inner.find(quote)?;
        return Some(unescape_xml_entities(&inner[..end]));
    }
    None
}

/// Unescape standard XML character & numeric entities (`&apos;`, `&quot;`, `&amp;`, `&lt;`, `&gt;`, `&#...;`).
pub fn unescape_xml_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    static NUM_ENTITY_RE: OnceLock<Regex> = OnceLock::new();
    let num_re = NUM_ENTITY_RE
        .get_or_init(|| Regex::new(r"&#(x[0-9A-Fa-f]+|[0-9]+);").expect("valid entity regex"));

    let numeric_decoded = num_re.replace_all(input, |caps: &regex::Captures<'_>| {
        let code_str = &caps[1];
        let parsed = if let Some(hex_part) = code_str.strip_prefix('x') {
            u32::from_str_radix(hex_part, 16).ok()
        } else {
            code_str.parse::<u32>().ok()
        };
        parsed
            .and_then(char::from_u32)
            .map(|c| c.to_string())
            .unwrap_or_else(|| caps[0].to_string())
    });

    numeric_decoded
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn clean_xbel_exec(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('\'').trim_matches('"').trim();
    let mut parts = Vec::new();
    for tok in trimmed.split_whitespace() {
        if tok.starts_with('%') && tok.len() == 2 {
            continue;
        }
        parts.push(tok);
    }
    parts.join(" ")
}

fn is_portal_helper_app(name: &str, exec: &str) -> bool {
    let nl = name.trim().to_ascii_lowercase();
    if !nl.is_empty() {
        return PORTAL_HELPER_APPS
            .iter()
            .any(|p| nl == *p || nl.starts_with("xdg-desktop-portal"));
    }
    let el = exec
        .split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    PORTAL_HELPER_APPS.iter().any(|p| el == *p)
}

fn parse_timestamp_epoch(raw: &str) -> i64 {
    let t = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return dt.timestamp();
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S") {
        return ndt.and_utc().timestamp();
    }
    0
}

pub fn classify_file_category(path: &str, mime_type: &str) -> &'static str {
    let lower_path = path.to_ascii_lowercase();
    if lower_path.ends_with(".pkg.tar.zst") || lower_path.ends_with(".tar.zst") {
        return "package";
    }
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "pdf",
        "doc" | "docx" | "odt" | "rtf" | "tex" | "typ" => "word",
        "xls" | "xlsx" | "csv" | "tsv" | "ods" => "spreadsheet",
        "ppt" | "pptx" | "odp" => "presentation",
        "md" | "markdown" | "txt" | "rst" => "markdown",
        "rs" | "py" | "js" | "ts" | "tsx" | "jsx" | "go" | "c" | "cpp" | "h" | "java" | "toml"
        | "yaml" | "yml" | "json" | "sh" | "sql" | "html" | "css" => "code",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "bmp" => "image",
        "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" => "audio",
        "mp4" | "mkv" | "mov" | "webm" | "avi" => "video",
        "zip" | "tar" | "gz" | "xz" | "bz2" | "7z" | "rar" | "zst" => "archive",
        "deb" | "rpm" | "appimage" | "iso" => "package",
        _ => {
            let ml = mime_type.to_ascii_lowercase();
            if ml.contains("pdf") {
                "pdf"
            } else if ml.contains("word") || ml.contains("opendocument.text") {
                "word"
            } else if ml.contains("spreadsheet") || ml.contains("excel") || ml.contains("csv") {
                "spreadsheet"
            } else if ml.contains("presentation") || ml.contains("powerpoint") {
                "presentation"
            } else if ml.starts_with("text/") {
                "markdown"
            } else if ml.starts_with("image/") {
                "image"
            } else if ml.starts_with("audio/") {
                "audio"
            } else if ml.starts_with("video/") {
                "video"
            } else {
                "other"
            }
        }
    }
}

/// Scan `.desktop` application descriptors from given directories (or standard Ubuntu dirs).
pub fn scan_desktop_directories(dirs: &[(PathBuf, &'static str)]) -> Vec<SoftwareProfile> {
    let mut by_id: HashMap<String, SoftwareProfile> = HashMap::new();

    for (dir, packaging) in dirs {
        if !dir.exists() {
            continue;
        }
        for entry in WalkDir::new(dir)
            .max_depth(2)
            .follow_links(true)
            .into_iter()
            .flatten()
        {
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("desktop") {
                continue;
            }
            if let Some(profile) = parse_desktop_file_full(path, packaging) {
                by_id.insert(profile.app_id.clone(), profile);
            }
        }
    }

    let mut list: Vec<SoftwareProfile> = by_id.into_values().collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    list
}

/// Parse a single `.desktop` file into a rich `SoftwareProfile` (`Name[zh_CN]`, `Name`,
/// `GenericName`, `Comment`, `Exec`, `Categories`, `MimeType`, `DBusActivatable`, `x-scheme-handler/*`).
pub fn parse_desktop_file_full(path: &Path, packaging: &str) -> Option<SoftwareProfile> {
    let content = std::fs::read_to_string(path).ok()?;
    let app_id = path.file_name()?.to_string_lossy().to_string();

    let mut in_desktop_entry = false;
    let mut entry_type: Option<String> = None;
    let mut no_display = false;
    let mut name_zh: Option<String> = None;
    let mut name_en: Option<String> = None;
    let mut generic_zh: Option<String> = None;
    let mut generic_en: Option<String> = None;
    let mut comment_zh: Option<String> = None;
    let mut comment_en: Option<String> = None;
    let mut keywords_list: Vec<String> = Vec::new();
    let mut exec_raw = String::new();
    let mut icon = String::new();
    let mut categories: Vec<String> = Vec::new();
    let mut mime_types: Vec<String> = Vec::new();
    let mut uri_schemes: Vec<String> = Vec::new();
    let mut dbus_activatable = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_desktop_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k_raw, v_raw)) = line.split_once('=') else {
            continue;
        };
        let key = k_raw.trim();
        let val = v_raw.trim();

        match key {
            "Type" => entry_type = Some(val.to_string()),
            "NoDisplay" | "Hidden" if val.eq_ignore_ascii_case("true") => {
                no_display = true;
            }
            "Name[zh_CN]" => name_zh = Some(val.to_string()),
            "Name[zh_SG]" | "Name[zh_TW]" | "Name[zh]" if name_zh.is_none() => {
                name_zh = Some(val.to_string());
            }
            "Name" if name_en.is_none() => name_en = Some(val.to_string()),
            "GenericName[zh_CN]" | "GenericName[zh]" => generic_zh = Some(val.to_string()),
            "GenericName" if generic_en.is_none() => generic_en = Some(val.to_string()),
            "Comment[zh_CN]" | "Comment[zh]" => comment_zh = Some(val.to_string()),
            "Comment" if comment_en.is_none() => comment_en = Some(val.to_string()),
            "Keywords" | "Keywords[zh_CN]" | "Keywords[zh]" => {
                for kw in val.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                    if !keywords_list.iter().any(|x| x.eq_ignore_ascii_case(kw)) {
                        keywords_list.push(kw.to_string());
                    }
                }
            }
            "Exec" if exec_raw.is_empty() => exec_raw = val.to_string(),
            "Icon" if icon.is_empty() => icon = val.to_string(),
            "DBusActivatable" => {
                dbus_activatable = val.eq_ignore_ascii_case("true");
            }
            "Categories" => {
                for c in val.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                    if !categories.iter().any(|x| x == c) {
                        categories.push(c.to_string());
                    }
                }
            }
            "MimeType" => {
                for m in val.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                    if let Some(scheme) = m.strip_prefix("x-scheme-handler/") {
                        let clean_scheme = scheme.trim().to_ascii_lowercase();
                        if !clean_scheme.is_empty() && !uri_schemes.contains(&clean_scheme) {
                            uri_schemes.push(clean_scheme);
                        }
                    }
                    if !mime_types.iter().any(|x| x == m) {
                        mime_types.push(m.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    if no_display {
        return None;
    }
    if let Some(ref t) = entry_type
        && !t.eq_ignore_ascii_case("Application")
    {
        return None;
    }

    let resolved_en = name_en.clone().or_else(|| name_zh.clone())?;
    let display_name = name_zh.clone().unwrap_or_else(|| resolved_en.clone());
    let generic_name = generic_zh.or(generic_en).unwrap_or_default();
    let base_comment = comment_zh.or(comment_en).unwrap_or_default();
    let comment = if keywords_list.is_empty() {
        base_comment
    } else if base_comment.is_empty() {
        keywords_list.join("; ")
    } else {
        format!("{} ({})", base_comment, keywords_list.join("; "))
    };
    let executable = extract_primary_executable(&exec_raw);

    Some(SoftwareProfile {
        app_id,
        name: display_name,
        name_zh,
        name_en: resolved_en,
        generic_name,
        comment,
        exec: exec_raw,
        executable,
        icon,
        categories,
        mime_types,
        dbus_activatable,
        uri_schemes,
        packaging: packaging.to_string(),
        desktop_file_path: path.to_string_lossy().to_string(),
        xbel_launch_count: 0,
        intentos_launch_count: 0,
        launch_count: 0,
        last_used_at: None,
        last_used_epoch: 0,
        frecency_score: 0.0,
    })
}

fn extract_primary_executable(exec_raw: &str) -> String {
    let tokens: Vec<&str> = exec_raw
        .split_whitespace()
        .map(|t| t.trim_matches('"').trim_matches('\''))
        .filter(|t| !t.is_empty())
        .collect();
    let mut idx = 0;
    while idx < tokens.len() {
        let tok = tokens[idx];
        if tok == "env" || (tok.contains('=') && !tok.starts_with('/')) {
            idx += 1;
            continue;
        }
        if (tok.ends_with("/flatpak") || tok == "flatpak") && idx + 2 < tokens.len() {
            for sub in &tokens[idx + 1..] {
                if !sub.starts_with('-')
                    && *sub != "run"
                    && !sub.starts_with("@@")
                    && !sub.starts_with('%')
                {
                    return sub.to_string();
                }
            }
        }
        return tok.rsplit('/').next().unwrap_or(tok).to_string();
    }
    String::new()
}

pub fn default_ubuntu_desktop_dirs() -> Vec<(PathBuf, &'static str)> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    vec![
        (PathBuf::from("/usr/share/applications"), "deb_system"),
        (PathBuf::from("/usr/local/share/applications"), "deb_system"),
        (PathBuf::from("/var/lib/snapd/desktop/applications"), "snap"),
        (
            PathBuf::from("/var/lib/flatpak/exports/share/applications"),
            "flatpak",
        ),
        (
            PathBuf::from(&home).join(".local/share/flatpak/exports/share/applications"),
            "flatpak",
        ),
        // User local scanned last so user customizations win on conflict
        (
            PathBuf::from(&home).join(".local/share/applications"),
            "user_local",
        ),
    ]
}

pub fn default_xbel_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    PathBuf::from(home).join(".local/share/recently-used.xbel")
}

/// Ensure `memory_hub.db` has performed an initial sync of XBEL + `.desktop` inventory.
pub fn ensure_lazy_synced(core: &IntentOsCore, db: &MemoryHubDb) {
    let now_epoch = Utc::now().timestamp();
    if let Some(last_str) = db.get_meta("last_sync_epoch")
        && let Ok(last_ep) = last_str.parse::<i64>()
        && (now_epoch - last_ep) < 180
    {
        return;
    }
    let _ = sync_system_usage_with_options(core, db, None, None);
}

/// Full idempotent sync of Ubuntu `recently-used.xbel`, `core.resources` indexed files/frecency,
/// and `.desktop` software catalog + launch profiles.
pub fn sync_system_usage_with_options(
    core: &IntentOsCore,
    db: &MemoryHubDb,
    custom_xbel: Option<&Path>,
    custom_desktop_dirs: Option<&[PathBuf]>,
) -> anyhow::Result<SyncSummary> {
    let now = Utc::now();
    let now_rfc = now.to_rfc3339();
    let now_epoch = now.timestamp();

    let xbel_path = match custom_xbel {
        Some(p) => p.to_path_buf(),
        None if is_hermetic_test_core(core) => core
            .paths
            .data_dir
            .parent()
            .map(|b| b.join("recently-used.xbel"))
            .unwrap_or_else(default_xbel_path),
        None => default_xbel_path(),
    };
    let bookmarks = parse_xbel_file(&xbel_path);
    let synced_xbel_bookmarks = bookmarks.len();

    // Aggregate per-app counts & last-used timestamps from XBEL
    let mut xbel_app_stats: Vec<(String, String, u64, i64, String)> = Vec::new();
    let mut xbel_app_map: HashMap<String, usize> = HashMap::new();
    for bm in &bookmarks {
        for app in &bm.applications {
            if is_portal_helper_app(&app.name, &app.exec) {
                continue;
            }
            let key = format!(
                "{}|{}",
                app.name.to_ascii_lowercase(),
                app.exec.to_ascii_lowercase()
            );
            let app_ep = app
                .modified
                .as_deref()
                .map(parse_timestamp_epoch)
                .filter(|e| *e > 0)
                .unwrap_or(bm.last_used_epoch);
            let app_ts = app
                .modified
                .clone()
                .unwrap_or_else(|| bm.last_used_at.clone());
            if let Some(&idx) = xbel_app_map.get(&key) {
                xbel_app_stats[idx].2 += app.count;
                if app_ep > xbel_app_stats[idx].3 {
                    xbel_app_stats[idx].3 = app_ep;
                    xbel_app_stats[idx].4 = app_ts;
                }
            } else {
                xbel_app_map.insert(key, xbel_app_stats.len());
                xbel_app_stats.push((
                    app.name.clone(),
                    app.exec.clone(),
                    app.count,
                    app_ep,
                    app_ts,
                ));
            }
        }
    }

    // Gather core.index_db file frecency & indexed files
    let mut index_file_frecency: HashMap<String, (u64, i64)> = HashMap::new();
    let mut index_app_frecency: HashMap<String, (u64, i64)> = HashMap::new();
    let mut indexed_files: Vec<(String, String, String, i64)> = Vec::new();

    if let Ok(idx_conn) = core.index_db.conn.lock() {
        if let Ok(mut stmt) =
            idx_conn.prepare("SELECT item_key, hits, last_used_secs FROM frecency")
            && let Ok(rows) = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?.max(0) as u64,
                    r.get::<_, i64>(2)?,
                ))
            })
        {
            for (k, hits, last_s) in rows.flatten() {
                if let Some(fp) = k.strip_prefix("file:") {
                    index_file_frecency.insert(fp.to_string(), (hits, last_s));
                } else if let Some(aid) = k.strip_prefix("app:") {
                    index_app_frecency.insert(aid.to_string(), (hits, last_s));
                }
            }
        }

        if let Ok(mut stmt) = idx_conn.prepare(
            "SELECT path, name, category, mtime_secs FROM files ORDER BY mtime_secs DESC LIMIT 500",
        ) && let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        }) {
            for item in rows.flatten() {
                indexed_files.push(item);
            }
        }
    }

    // Scan desktop applications
    let dir_pairs: Vec<(PathBuf, &'static str)> = match custom_desktop_dirs {
        Some(custom) => custom.iter().map(|p| (p.clone(), "custom")).collect(),
        None if is_hermetic_test_core(core) => core
            .paths
            .data_dir
            .parent()
            .map(|b| vec![(b.join("mock_applications"), "custom")])
            .unwrap_or_default(),
        None => default_ubuntu_desktop_dirs(),
    };
    let mut apps = scan_desktop_directories(&dir_pairs);
    if apps.is_empty()
        && custom_desktop_dirs.is_none()
        && core.app_config.allow_simulated_hardware_fallback
    {
        apps = fallback_software_catalog();
    }

    // Read existing intentos_count & intentos_launch_count from memory_hub.db so we never lose IntentOS history
    let mut existing_file_intentos: HashMap<String, (u64, i64, String, Vec<String>)> =
        HashMap::new();
    let mut existing_app_intentos: HashMap<String, (u64, i64, Option<String>)> = HashMap::new();
    {
        let conn = db.conn.lock().unwrap();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT path, intentos_count, last_used_epoch, last_used_at, preferred_apps_json FROM long_term_files",
        ) && let Ok(rows) = stmt.query_map([], |r| {
            let p_json: String = r.get(4)?;
            let pref: Vec<String> = serde_json::from_str(&p_json).unwrap_or_default();
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?.max(0) as u64,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                pref,
            ))
        }) {
            for (p, ic, ep, ts, pref) in rows.flatten() {
                existing_file_intentos.insert(p, (ic, ep, ts, pref));
            }
        }

        if let Ok(mut stmt) = conn.prepare(
            "SELECT app_id, intentos_launch_count, last_used_epoch, last_used_at FROM software_inventory",
        ) && let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?.max(0) as u64,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        }) {
            for (aid, ilc, ep, ts) in rows.flatten() {
                existing_app_intentos.insert(aid, (ilc, ep, ts));
            }
        }
    }

    // Build merged LongTermFileHabit map
    let mut merged_files: HashMap<String, LongTermFileHabit> = HashMap::new();

    for bm in &bookmarks {
        if core.fs_engine.is_forbidden(Path::new(&bm.path))
            || is_sensitive_credential_path(&bm.path)
        {
            continue;
        }
        let title = Path::new(&bm.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&bm.path)
            .to_string();
        let exists_on_disk = Path::new(&bm.path).exists();
        let category = classify_file_category(&bm.path, &bm.mime_type).to_string();

        let (prev_ic, prev_ep, prev_ts, prev_apps) = existing_file_intentos
            .remove(&bm.path)
            .unwrap_or_else(|| (0, 0, String::new(), Vec::new()));
        let (idx_hits, idx_ep) = index_file_frecency.remove(&bm.path).unwrap_or((0, 0));

        let intentos_count = prev_ic.max(idx_hits);
        let xbel_count = bm.total_open_count;
        let open_count = (xbel_count + intentos_count).max(1);

        let mut last_ep = bm.last_used_epoch;
        let mut last_ts = bm.last_used_at.clone();
        if prev_ep > last_ep && !prev_ts.is_empty() {
            last_ep = prev_ep;
            last_ts = prev_ts;
        }
        if idx_ep > last_ep {
            last_ep = idx_ep;
            last_ts = DateTime::from_timestamp(idx_ep, 0)
                .unwrap_or(now)
                .to_rfc3339();
        }

        let mut preferred_apps = bm.preferred_apps.clone();
        for pa in prev_apps {
            if !preferred_apps.contains(&pa) {
                preferred_apps.push(pa);
            }
        }
        let frecency_score = compute_frecency_score(open_count, last_ep, now_epoch, exists_on_disk);

        merged_files.insert(
            bm.path.clone(),
            LongTermFileHabit {
                path: bm.path.clone(),
                title,
                open_count,
                xbel_count,
                intentos_count,
                last_used_at: last_ts,
                last_used_epoch: last_ep,
                preferred_apps,
                category,
                mime_type: bm.mime_type.clone(),
                exists_on_disk,
                frecency_score,
            },
        );
    }

    // Merge indexed authorized files from core.resources
    for (fpath, fname, fcat, mtime_secs) in indexed_files {
        if merged_files.contains_key(&fpath)
            || core.fs_engine.is_forbidden(Path::new(&fpath))
            || is_sensitive_credential_path(&fpath)
        {
            continue;
        }
        let (prev_ic, prev_ep, prev_ts, prev_apps) = existing_file_intentos
            .remove(&fpath)
            .unwrap_or_else(|| (0, 0, String::new(), Vec::new()));
        let (idx_hits, idx_ep) = index_file_frecency.remove(&fpath).unwrap_or((0, 0));
        let intentos_count = prev_ic.max(idx_hits);
        let open_count = intentos_count.max(1);
        let last_ep = mtime_secs.max(prev_ep).max(idx_ep);
        let last_ts = if prev_ep >= mtime_secs && !prev_ts.is_empty() {
            prev_ts
        } else {
            DateTime::from_timestamp(last_ep, 0)
                .unwrap_or(now)
                .to_rfc3339()
        };
        let cat = if fcat.is_empty() || fcat == "other" {
            classify_file_category(&fpath, "").to_string()
        } else {
            fcat
        };
        let frecency_score = compute_frecency_score(open_count, last_ep, now_epoch, true);
        merged_files.insert(
            fpath.clone(),
            LongTermFileHabit {
                path: fpath,
                title: fname,
                open_count,
                xbel_count: 0,
                intentos_count,
                last_used_at: last_ts,
                last_used_epoch: last_ep,
                preferred_apps: prev_apps,
                category: cat,
                mime_type: String::new(),
                exists_on_disk: true,
                frecency_score,
            },
        );
    }

    // Preserve any remaining IntentOS-recorded files not in XBEL or current index
    for (fpath, (prev_ic, prev_ep, prev_ts, prev_apps)) in existing_file_intentos {
        if prev_ic == 0 || is_sensitive_credential_path(&fpath) {
            continue;
        }
        let exists_on_disk = Path::new(&fpath).exists();
        let title = Path::new(&fpath)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&fpath)
            .to_string();
        let category = classify_file_category(&fpath, "").to_string();
        let frecency_score = compute_frecency_score(prev_ic, prev_ep, now_epoch, exists_on_disk);
        merged_files.insert(
            fpath.clone(),
            LongTermFileHabit {
                path: fpath,
                title,
                open_count: prev_ic,
                xbel_count: 0,
                intentos_count: prev_ic,
                last_used_at: prev_ts,
                last_used_epoch: prev_ep,
                preferred_apps: prev_apps,
                category,
                mime_type: String::new(),
                exists_on_disk,
                frecency_score,
            },
        );
    }

    // Match XBEL app usage + IntentOS launches onto software_inventory
    let mut frequent_apps_count = 0usize;
    for app in &mut apps {
        let mut xbel_cnt = 0u64;
        let mut best_ep = 0i64;
        let mut best_ts: Option<String> = None;

        for (x_name, x_exec, x_count, x_ep, x_ts) in &xbel_app_stats {
            if matches_xbel_app(app, x_name, x_exec) {
                xbel_cnt += *x_count;
                if *x_ep > best_ep {
                    best_ep = *x_ep;
                    best_ts = Some(x_ts.clone());
                }
            }
        }

        let (prev_ilc, prev_ep, prev_ts) = existing_app_intentos
            .get(&app.app_id)
            .cloned()
            .unwrap_or((0, 0, None));
        let (idx_hits, idx_ep) = index_app_frecency
            .get(&app.app_id)
            .copied()
            .unwrap_or((0, 0));

        let intentos_cnt = prev_ilc.max(idx_hits);
        if prev_ep > best_ep {
            best_ep = prev_ep;
            best_ts = prev_ts;
        }
        if idx_ep > best_ep {
            best_ep = idx_ep;
            best_ts = Some(
                DateTime::from_timestamp(idx_ep, 0)
                    .unwrap_or(now)
                    .to_rfc3339(),
            );
        }

        app.xbel_launch_count = xbel_cnt;
        app.intentos_launch_count = intentos_cnt;
        app.launch_count = xbel_cnt + intentos_cnt;
        app.last_used_epoch = best_ep;
        app.last_used_at = best_ts;
        app.frecency_score = if app.launch_count > 0 {
            frequent_apps_count += 1;
            compute_frecency_score(app.launch_count, best_ep, now_epoch, true)
        } else {
            0.0
        };
    }

    let total_frequent_files = merged_files.len();
    let total_installed_apps = apps.len();

    // Commit atomically to memory_hub.db
    {
        let mut conn = db.conn.lock().unwrap();
        let tx = conn.transaction()?;

        tx.execute("DELETE FROM long_term_files", [])?;
        {
            let mut ins_file = tx.prepare(
                "INSERT INTO long_term_files (
                    path, title, open_count, xbel_count, intentos_count, last_used_at,
                    last_used_epoch, preferred_apps_json, category, mime_type, exists_on_disk, frecency_score
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            for item in merged_files.values() {
                ins_file.execute(params![
                    item.path,
                    item.title,
                    item.open_count as i64,
                    item.xbel_count as i64,
                    item.intentos_count as i64,
                    item.last_used_at,
                    item.last_used_epoch,
                    serde_json::to_string(&item.preferred_apps)?,
                    item.category,
                    item.mime_type,
                    i32::from(item.exists_on_disk),
                    item.frecency_score,
                ])?;
            }
        }

        tx.execute("DELETE FROM software_inventory", [])?;
        {
            let mut ins_app = tx.prepare(
                "INSERT INTO software_inventory (
                    app_id, name, name_zh, name_en, generic_name, comment, exec, executable, icon,
                    categories_json, mime_types_json, dbus_activatable, uri_schemes_json, packaging,
                    desktop_file_path, xbel_launch_count, intentos_launch_count, launch_count,
                    last_used_at, last_used_epoch, frecency_score, pinyin_full, pinyin_init
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    ?10, ?11, ?12, ?13, ?14,
                    ?15, ?16, ?17, ?18,
                    ?19, ?20, ?21, ?22, ?23
                 )",
            )?;
            for app in &apps {
                let (py_full, py_init) = to_pinyin_pair(&format!(
                    "{} {} {}",
                    app.name, app.name_en, app.generic_name
                ));
                ins_app.execute(params![
                    app.app_id,
                    app.name,
                    app.name_zh,
                    app.name_en,
                    app.generic_name,
                    app.comment,
                    app.exec,
                    app.executable,
                    app.icon,
                    serde_json::to_string(&app.categories)?,
                    serde_json::to_string(&app.mime_types)?,
                    i32::from(app.dbus_activatable),
                    serde_json::to_string(&app.uri_schemes)?,
                    app.packaging,
                    app.desktop_file_path,
                    app.xbel_launch_count as i64,
                    app.intentos_launch_count as i64,
                    app.launch_count as i64,
                    app.last_used_at,
                    app.last_used_epoch,
                    app.frecency_score,
                    py_full,
                    py_init,
                ])?;
            }
        }

        tx.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('last_sync_at', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![now_rfc],
        )?;
        tx.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('last_sync_epoch', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![now_epoch.to_string()],
        )?;
        tx.commit()?;
    }

    // Lazily index newly discovered XBEL documents & user XDG document directories into `document_outlines`
    let xbel_doc_paths: Vec<PathBuf> = bookmarks
        .iter()
        .map(|bm| PathBuf::from(&bm.path))
        .filter(|p| crate::memory_hub::document_outline::is_supported_document_path(p))
        .collect();
    let _ = crate::memory_hub::document_outline::sync_document_outlines_with_extra_paths(
        core,
        db,
        &xbel_doc_paths,
    );

    Ok(SyncSummary {
        synced_xbel_bookmarks,
        total_frequent_files,
        total_installed_apps,
        frequent_apps_count,
        synced_at: now_rfc,
    })
}

fn matches_xbel_app(app: &SoftwareProfile, x_name: &str, x_exec: &str) -> bool {
    let xn = x_name.trim().to_ascii_lowercase();
    let xe = x_exec
        .split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    let stem = app.app_id.trim_end_matches(".desktop").to_ascii_lowercase();
    let stem_tail = stem.rsplit('.').next().unwrap_or(&stem);
    let app_exec_lc = app.executable.to_ascii_lowercase();
    let name_en_lc = app.name_en.to_ascii_lowercase();
    let name_disp_lc = app.name.to_ascii_lowercase();

    if !xn.is_empty() {
        if xn == stem || xn == name_en_lc || xn == name_disp_lc || xn == app_exec_lc {
            return true;
        }
        let xn_tail = xn.rsplit('.').next().unwrap_or(&xn);
        if xn_tail.len() >= 4
            && (xn_tail == stem_tail
                || xn_tail == app_exec_lc
                || (xn_tail == "chrome" && stem.contains("chrome")))
        {
            return true;
        }
    }
    if !xe.is_empty() && xe != "gio" && xe != "sh" && xe != "bash" && xe == app_exec_lc {
        return true;
    }
    false
}

/// Increment IntentOS usage count for a file path in `long_term_files` and recompute Frecency.
pub fn record_file_usage(
    db: &MemoryHubDb,
    path: &str,
    app_used: Option<&str>,
    delta: u64,
) -> anyhow::Result<()> {
    let clean = path.trim();
    if clean.is_empty() || !clean.starts_with('/') || is_sensitive_credential_path(clean) {
        return Ok(());
    }
    let now = Utc::now();
    let now_rfc = now.to_rfc3339();
    let now_epoch = now.timestamp();
    let exists_on_disk = Path::new(clean).exists();
    let title = Path::new(clean)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(clean)
        .to_string();
    let category = classify_file_category(clean, "").to_string();

    let conn = db.conn.lock().unwrap();
    let existing: Option<(u64, u64, String)> = conn
        .query_row(
            "SELECT xbel_count, intentos_count, preferred_apps_json FROM long_term_files WHERE path = ?1",
            params![clean],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?.max(0) as u64,
                    r.get::<_, i64>(1)?.max(0) as u64,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .ok();

    let (xbel_cnt, prev_ic, prev_json) = existing.unwrap_or_else(|| (0, 0, "[]".to_string()));
    let new_ic = prev_ic + delta.max(1);
    let open_count = xbel_cnt + new_ic;
    let mut pref_apps: Vec<String> = serde_json::from_str(&prev_json).unwrap_or_default();
    if let Some(a) = app_used.map(str::trim).filter(|s| !s.is_empty())
        && !pref_apps.iter().any(|p| p.eq_ignore_ascii_case(a))
    {
        pref_apps.insert(0, a.to_string());
    }
    let frecency = compute_frecency_score(open_count, now_epoch, now_epoch, exists_on_disk);

    conn.execute(
        "INSERT INTO long_term_files (
            path, title, open_count, xbel_count, intentos_count, last_used_at,
            last_used_epoch, preferred_apps_json, category, mime_type, exists_on_disk, frecency_score
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, '', ?10, ?11)
         ON CONFLICT(path) DO UPDATE SET
            open_count = excluded.open_count,
            intentos_count = excluded.intentos_count,
            last_used_at = excluded.last_used_at,
            last_used_epoch = excluded.last_used_epoch,
            preferred_apps_json = excluded.preferred_apps_json,
            exists_on_disk = excluded.exists_on_disk,
            frecency_score = excluded.frecency_score",
        params![
            clean,
            title,
            open_count as i64,
            xbel_cnt as i64,
            new_ic as i64,
            now_rfc,
            now_epoch,
            serde_json::to_string(&pref_apps)?,
            category,
            i32::from(exists_on_disk),
            frecency,
        ],
    )?;
    Ok(())
}

/// Increment IntentOS launch count for a desktop application in `software_inventory`.
pub fn record_app_launch(db: &MemoryHubDb, app_hint: &str, delta: u64) -> anyhow::Result<bool> {
    let hint = app_hint.trim();
    if hint.is_empty() {
        return Ok(false);
    }
    let hint_lc = hint.to_ascii_lowercase();
    let stem_lc = hint_lc.trim_end_matches(".desktop");
    let now = Utc::now();
    let now_rfc = now.to_rfc3339();
    let now_epoch = now.timestamp();

    let conn = db.conn.lock().unwrap();
    let matched: Option<(String, u64, u64)> = conn
        .query_row(
            "SELECT app_id, xbel_launch_count, intentos_launch_count
             FROM software_inventory
             WHERE LOWER(app_id) = ?1
                OR LOWER(REPLACE(app_id, '.desktop', '')) = ?2
                OR LOWER(executable) = ?2
                OR LOWER(name) = ?2
                OR LOWER(name_en) = ?2
             ORDER BY launch_count DESC LIMIT 1",
            params![format!("{}.desktop", stem_lc), stem_lc],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?.max(0) as u64,
                    r.get::<_, i64>(2)?.max(0) as u64,
                ))
            },
        )
        .ok();

    let Some((app_id, xbel_cnt, prev_ilc)) = matched else {
        return Ok(false);
    };
    let new_ilc = prev_ilc + delta.max(1);
    let total = xbel_cnt + new_ilc;
    let frecency = compute_frecency_score(total, now_epoch, now_epoch, true);

    conn.execute(
        "UPDATE software_inventory
         SET intentos_launch_count = ?1,
             launch_count = ?2,
             last_used_at = ?3,
             last_used_epoch = ?4,
             frecency_score = ?5
         WHERE app_id = ?6",
        params![
            new_ilc as i64,
            total as i64,
            now_rfc,
            now_epoch,
            frecency,
            app_id
        ],
    )?;
    Ok(true)
}

/// Query Long-Term / Frequently Used Files ranked by Frecency.
pub fn query_frequent_files(
    db: &MemoryHubDb,
    query: Option<&str>,
    category: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<LongTermFileHabit>> {
    let cap = limit.clamp(1, 200);
    let q_clean = query
        .map(str::trim)
        .filter(|s| !s.is_empty() && !is_generic_frequent_file_query(s));
    let cat_clean = category
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "all");

    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT path, title, open_count, xbel_count, intentos_count, last_used_at,
                last_used_epoch, preferred_apps_json, category, mime_type, exists_on_disk, frecency_score
         FROM long_term_files
         ORDER BY frecency_score DESC, open_count DESC, last_used_epoch DESC
         LIMIT 400",
    )?;
    let rows = stmt.query_map([], |r| {
        let p_json: String = r.get(7)?;
        Ok(LongTermFileHabit {
            path: r.get(0)?,
            title: r.get(1)?,
            open_count: r.get::<_, i64>(2)?.max(0) as u64,
            xbel_count: r.get::<_, i64>(3)?.max(0) as u64,
            intentos_count: r.get::<_, i64>(4)?.max(0) as u64,
            last_used_at: r.get(5)?,
            last_used_epoch: r.get(6)?,
            preferred_apps: serde_json::from_str(&p_json).unwrap_or_default(),
            category: r.get(8)?,
            mime_type: r.get(9)?,
            exists_on_disk: r.get::<_, i32>(10)? != 0,
            frecency_score: r.get(11)?,
        })
    })?;

    let mut out = Vec::new();
    for item in rows {
        let habit = item?;
        if let Some(c) = cat_clean
            && !habit.category.eq_ignore_ascii_case(c)
        {
            continue;
        }
        if let Some(q) = q_clean {
            let ql = q.to_ascii_lowercase();
            let (py_full, py_init) = to_pinyin_pair(&habit.title);
            let matched = habit.title.to_ascii_lowercase().contains(&ql)
                || habit.path.to_ascii_lowercase().contains(&ql)
                || habit.category.to_ascii_lowercase().contains(&ql)
                || py_full.contains(&ql)
                || py_init.contains(&ql)
                || habit
                    .preferred_apps
                    .iter()
                    .any(|a| a.to_ascii_lowercase().contains(&ql));
            if !matched {
                continue;
            }
        }
        out.push(habit);
        if out.len() >= cap {
            break;
        }
    }
    Ok(out)
}

fn is_generic_frequent_file_query(q: &str) -> bool {
    let mut s = q.to_string();
    for phrase in [
        "我长期使用的文件有哪些",
        "长期使用的文件",
        "长期高频使用的文件",
        "长期高频文件",
        "常用的文件",
        "我常用的文件",
        "经常打开的文件",
        "最近常用的文件",
        "高频文件",
        "有哪些",
        "是什么",
        "我",
        "的",
        "文件",
        "？",
        "?",
    ] {
        s = s.replace(phrase, "");
    }
    s.trim().is_empty()
}

/// Query Ubuntu Software Catalog & Usage Profile ranked by relevance + Frecency.
pub fn query_software_catalog(
    db: &MemoryHubDb,
    query: Option<&str>,
    only_frequent: bool,
    limit: usize,
) -> anyhow::Result<Vec<SoftwareProfile>> {
    let cap = limit.clamp(1, 300);
    let q_clean = query
        .map(str::trim)
        .filter(|s| !s.is_empty() && !is_generic_software_query(s));

    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT app_id, name, name_zh, name_en, generic_name, comment, exec, executable, icon,
                categories_json, mime_types_json, dbus_activatable, uri_schemes_json, packaging,
                desktop_file_path, xbel_launch_count, intentos_launch_count, launch_count,
                last_used_at, last_used_epoch, frecency_score, pinyin_full, pinyin_init
         FROM software_inventory
         ORDER BY frecency_score DESC, launch_count DESC, name ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let cat_s: String = r.get(9)?;
        let mime_s: String = r.get(10)?;
        let uri_s: String = r.get(12)?;
        Ok((
            SoftwareProfile {
                app_id: r.get(0)?,
                name: r.get(1)?,
                name_zh: r.get(2)?,
                name_en: r.get(3)?,
                generic_name: r.get(4)?,
                comment: r.get(5)?,
                exec: r.get(6)?,
                executable: r.get(7)?,
                icon: r.get(8)?,
                categories: serde_json::from_str(&cat_s).unwrap_or_default(),
                mime_types: serde_json::from_str(&mime_s).unwrap_or_default(),
                dbus_activatable: r.get::<_, i32>(11)? != 0,
                uri_schemes: serde_json::from_str(&uri_s).unwrap_or_default(),
                packaging: r.get(13)?,
                desktop_file_path: r.get(14)?,
                xbel_launch_count: r.get::<_, i64>(15)?.max(0) as u64,
                intentos_launch_count: r.get::<_, i64>(16)?.max(0) as u64,
                launch_count: r.get::<_, i64>(17)?.max(0) as u64,
                last_used_at: r.get(18)?,
                last_used_epoch: r.get(19)?,
                frecency_score: r.get(20)?,
            },
            r.get::<_, String>(21)?,
            r.get::<_, String>(22)?,
        ))
    })?;

    let mut scored: Vec<(SoftwareProfile, f64)> = Vec::new();
    for item in rows {
        let (app, py_full, py_init) = item?;
        if only_frequent && app.launch_count == 0 {
            continue;
        }
        if let Some(q) = q_clean {
            let ql = q.to_ascii_lowercase();
            let cat_synonyms = map_chinese_category_keyword(&ql);
            let mut match_score = 0.0;
            if app.name.to_ascii_lowercase() == ql
                || app.name_en.to_ascii_lowercase() == ql
                || app.executable.to_ascii_lowercase() == ql
                || app
                    .app_id
                    .trim_end_matches(".desktop")
                    .eq_ignore_ascii_case(&ql)
            {
                match_score += 120.0;
            } else if app.name.to_ascii_lowercase().contains(&ql)
                || app.name_en.to_ascii_lowercase().contains(&ql)
                || app.executable.to_ascii_lowercase().contains(&ql)
            {
                match_score += 85.0;
            } else if py_full.contains(&ql) || py_init.contains(&ql) {
                match_score += 70.0;
            } else if app.generic_name.to_ascii_lowercase().contains(&ql)
                || app.comment.to_ascii_lowercase().contains(&ql)
                || app.uri_schemes.iter().any(|u| u.contains(&ql))
                || app
                    .mime_types
                    .iter()
                    .any(|m| m.to_ascii_lowercase().contains(&ql))
                || app.categories.iter().any(|c| {
                    let cl = c.to_ascii_lowercase();
                    cl.contains(&ql) || cat_synonyms.iter().any(|syn| cl.contains(syn))
                })
            {
                match_score += 60.0;
            }

            if match_score > 0.0 {
                scored.push((app.clone(), match_score + app.frecency_score * 0.5));
            }
        } else {
            let base = app.frecency_score;
            scored.push((app, base));
        }
    }

    if q_clean.is_some() {
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    }
    Ok(scored.into_iter().take(cap).map(|(a, _)| a).collect())
}

/// Query Ubuntu Software Catalog returning `(SoftwareProfile, relevance_score)` pairs for selective gating.
pub fn query_software_catalog_scored(
    db: &MemoryHubDb,
    query: &str,
    limit: usize,
) -> anyhow::Result<Vec<(SoftwareProfile, f64)>> {
    let cap = limit.clamp(1, 50);
    let q = query.trim();
    if q.is_empty() || is_generic_software_query(q) {
        return Ok(Vec::new());
    }
    let ql = q.to_ascii_lowercase();
    let cat_synonyms = map_chinese_category_keyword(&ql);

    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT app_id, name, name_zh, name_en, generic_name, comment, exec, executable, icon,
                categories_json, mime_types_json, dbus_activatable, uri_schemes_json, packaging,
                desktop_file_path, xbel_launch_count, intentos_launch_count, launch_count,
                last_used_at, last_used_epoch, frecency_score, pinyin_full, pinyin_init
         FROM software_inventory
         ORDER BY frecency_score DESC, launch_count DESC, name ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let cat_s: String = r.get(9)?;
        let mime_s: String = r.get(10)?;
        let uri_s: String = r.get(12)?;
        Ok((
            SoftwareProfile {
                app_id: r.get(0)?,
                name: r.get(1)?,
                name_zh: r.get(2)?,
                name_en: r.get(3)?,
                generic_name: r.get(4)?,
                comment: r.get(5)?,
                exec: r.get(6)?,
                executable: r.get(7)?,
                icon: r.get(8)?,
                categories: serde_json::from_str(&cat_s).unwrap_or_default(),
                mime_types: serde_json::from_str(&mime_s).unwrap_or_default(),
                dbus_activatable: r.get::<_, i32>(11)? != 0,
                uri_schemes: serde_json::from_str(&uri_s).unwrap_or_default(),
                packaging: r.get(13)?,
                desktop_file_path: r.get(14)?,
                xbel_launch_count: r.get::<_, i64>(15)?.max(0) as u64,
                intentos_launch_count: r.get::<_, i64>(16)?.max(0) as u64,
                launch_count: r.get::<_, i64>(17)?.max(0) as u64,
                last_used_at: r.get(18)?,
                last_used_epoch: r.get(19)?,
                frecency_score: r.get(20)?,
            },
            r.get::<_, String>(21)?,
            r.get::<_, String>(22)?,
        ))
    })?;

    let mut scored: Vec<(SoftwareProfile, f64)> = Vec::new();
    for item in rows {
        let (app, py_full, py_init) = item?;
        let stem = app.app_id.trim_end_matches(".desktop").to_ascii_lowercase();
        let mut match_score = 0.0;
        if app.name.to_ascii_lowercase() == ql
            || app.name_en.to_ascii_lowercase() == ql
            || app.executable.to_ascii_lowercase() == ql
            || stem == ql
        {
            match_score += 120.0;
        } else if ql.chars().count() >= 2
            && (app.name.to_ascii_lowercase().contains(&ql)
                || app.name_en.to_ascii_lowercase().contains(&ql)
                || app.executable.to_ascii_lowercase().contains(&ql)
                || stem.contains(&ql))
        {
            match_score += 88.0;
        } else if ql.chars().count() >= 3 && (py_full.contains(&ql) || py_init == ql) {
            match_score += 72.0;
        } else if ql.chars().count() >= 2
            && (app.comment.to_ascii_lowercase().contains(&ql)
                || app.generic_name.to_ascii_lowercase().contains(&ql)
                || app.uri_schemes.iter().any(|u| u == &ql))
        {
            match_score += 68.0;
        } else if !cat_synonyms.is_empty()
            && app.categories.iter().any(|c| {
                let cl = c.to_ascii_lowercase();
                cat_synonyms.iter().any(|syn| cl.contains(syn))
            })
        {
            match_score += 60.0;
        }

        if match_score > 0.0 {
            scored.push((app.clone(), match_score + app.frecency_score * 0.4));
        }
    }

    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(cap);
    Ok(scored)
}

fn is_generic_software_query(q: &str) -> bool {
    let mut s = q.to_string();
    for phrase in [
        "我电脑上有哪些软件",
        "我电脑上装了哪些软件",
        "电脑上有哪些软件",
        "本机有哪些软件",
        "本机安装了哪些软件",
        "安装了哪些软件",
        "装了哪些软件",
        "装了什么软件",
        "常用软件有哪些",
        "我常用的软件有哪些",
        "长期常用软件",
        "常用软件",
        "常用应用",
        "有哪些软件",
        "软件列表",
        "全部软件",
        "所有软件",
        "？",
        "?",
    ] {
        s = s.replace(phrase, "");
    }
    s.trim().is_empty()
}

fn map_chinese_category_keyword(ql: &str) -> &'static [&'static str] {
    if ql.contains("音乐") || ql.contains("音频") || ql.contains("播放") || ql.contains("媒体")
    {
        &["audio", "music", "player", "audiovideo", "video"]
    } else if ql.contains("视频") || ql.contains("电影") {
        &["video", "player", "audiovideo"]
    } else if ql.contains("浏览器") || ql.contains("上网") {
        &["webbrowser", "network"]
    } else if ql.contains("编程")
        || ql.contains("开发")
        || ql.contains("编辑器")
        || ql.contains("代码")
    {
        &["development", "ide", "texteditor"]
    } else if ql.contains("办公") || ql.contains("文档") || ql.contains("表格") {
        &["office", "wordprocessor", "spreadsheet", "viewer"]
    } else if ql.contains("图片") || ql.contains("设计") || ql.contains("画图") {
        &["graphics", "photography"]
    } else if ql.contains("聊天") || ql.contains("社交") || ql.contains("通讯") {
        &["instantmessaging", "chat", "network"]
    } else {
        &[]
    }
}

/// Build an aggregated summary of installed desktop software (`total`, `dbus_activatable`, `uri_schemes`, packaging, categories).
pub fn get_installed_apps_summary(db: &MemoryHubDb) -> anyhow::Result<InstalledAppsSummary> {
    let all = query_software_catalog(db, None, false, 300)?;
    let total_installed = all.len();
    let mut frequent_apps_count = 0usize;
    let mut dbus_activatable_count = 0usize;
    let mut uri_scheme_apps_count = 0usize;
    let mut by_packaging: BTreeMap<String, usize> = BTreeMap::new();
    let mut cat_counts: HashMap<String, usize> = HashMap::new();

    for app in &all {
        if app.launch_count > 0 {
            frequent_apps_count += 1;
        }
        if app.dbus_activatable {
            dbus_activatable_count += 1;
        }
        if !app.uri_schemes.is_empty() {
            uri_scheme_apps_count += 1;
        }
        *by_packaging.entry(app.packaging.clone()).or_insert(0) += 1;
        for cat in &app.categories {
            *cat_counts.entry(cat.clone()).or_insert(0) += 1;
        }
    }

    let mut top_categories: Vec<CategoryCount> = cat_counts
        .into_iter()
        .map(|(category, count)| CategoryCount { category, count })
        .collect();
    top_categories.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.category.cmp(&b.category))
    });
    top_categories.truncate(10);

    Ok(InstalledAppsSummary {
        total_installed,
        frequent_apps_count,
        dbus_activatable_count,
        uri_scheme_apps_count,
        by_packaging,
        top_categories,
    })
}

fn fallback_software_catalog() -> Vec<SoftwareProfile> {
    let seeds = [
        (
            "code.desktop",
            "Visual Studio Code",
            Some("VS Code 编辑器"),
            "Code Editor",
            "code",
            &["Development", "IDE"][..],
            &["vscode"][..],
            false,
        ),
        (
            "firefox.desktop",
            "Firefox 浏览器",
            Some("Firefox 浏览器"),
            "Web Browser",
            "firefox",
            &["Network", "WebBrowser"][..],
            &["http", "https"][..],
            false,
        ),
        (
            "org.gnome.Nautilus.desktop",
            "文件管理器",
            Some("文件管理器"),
            "Files",
            "nautilus",
            &["System", "FileManager"][..],
            &[][..],
            true,
        ),
        (
            "org.gnome.Evince.desktop",
            "文档查看器",
            Some("文档查看器"),
            "Document Viewer",
            "evince",
            &["Office", "Viewer"][..],
            &[][..],
            true,
        ),
        (
            "libreoffice-writer.desktop",
            "LibreOffice Writer",
            Some("LibreOffice 文字"),
            "Word Processor",
            "libreoffice",
            &["Office", "WordProcessor"][..],
            &[][..],
            false,
        ),
        (
            "org.gnome.Terminal.desktop",
            "终端",
            Some("终端"),
            "Terminal Emulator",
            "gnome-terminal",
            &["System", "TerminalEmulator"][..],
            &[][..],
            true,
        ),
    ];
    seeds
        .into_iter()
        .map(
            |(id, name, zh, gname, exec, cats, schemes, dbus)| SoftwareProfile {
                app_id: id.to_string(),
                name: name.to_string(),
                name_zh: zh.map(String::from),
                name_en: name.to_string(),
                generic_name: gname.to_string(),
                comment: gname.to_string(),
                exec: exec.to_string(),
                executable: exec.to_string(),
                icon: exec.to_string(),
                categories: cats.iter().map(|s| (*s).to_string()).collect(),
                mime_types: Vec::new(),
                dbus_activatable: dbus,
                uri_schemes: schemes.iter().map(|s| (*s).to_string()).collect(),
                packaging: "catalog".to_string(),
                desktop_file_path: format!("/usr/share/applications/{}", id),
                xbel_launch_count: 0,
                intentos_launch_count: 0,
                launch_count: 0,
                last_used_at: None,
                last_used_epoch: 0,
                frecency_score: 0.0,
            },
        )
        .collect()
}
