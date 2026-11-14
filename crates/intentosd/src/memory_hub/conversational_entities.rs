#![forbid(unsafe_code)]

//! Conversational Entity Extraction & Natural Reference Recall (`conversational_entities.rs`).
//!
//! Automatically extracts and persists mentioned files, directories, quoted document titles
//! (`《周报》`), URLs, and desktop applications across user prompts, assistant replies, and
//! tool execution steps, and resolves natural queries such as:
//! - "我之前说的那个文件"
//! - "上次提到的文档"
//! - "刚才改的配置"

use crate::memory_hub::schema_and_db::{
    EntityMention, MemoryHubDb, compute_entity_id, is_installer_or_package_artifact,
    is_sensitive_credential_path, scrub_sensitive_text,
};
use crate::resource::to_pinyin_pair;
use chrono::Utc;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

/// Candidate entity extracted from a single turn before DB persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedEntity {
    pub entity_kind: String,
    pub canonical_value: String,
    pub display_name: String,
    pub action_verb: String,
    pub context_snippet: String,
}

const KNOWN_FILE_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "csv", "tsv",
    "md", "markdown", "txt", "rst", "log", "py", "rs", "toml", "json", "yaml", "yml", "js", "mjs",
    "cjs", "ts", "tsx", "jsx", "html", "css", "scss", "sh", "bash", "zsh", "fish", "sql", "c",
    "cpp", "h", "hpp", "go", "java", "kt", "swift", "rb", "php", "lua", "png", "jpg", "jpeg",
    "gif", "webp", "svg", "ico", "mp3", "wav", "flac", "ogg", "m4a", "mp4", "mkv", "mov", "webm",
    "avi", "zip", "tar", "gz", "xz", "bz2", "7z", "rar", "deb", "rpm", "appimage", "iso", "conf",
    "ini", "cfg", "xml", "xbel", "desktop", "service", "lock",
];

const BUILTIN_APP_PATTERNS: &[(&str, &str, &[&str])] = &[
    ("code.desktop", "Visual Studio Code", &["vscode", "vs code", "visual studio code"]),
    ("zcode.desktop", "ZCode", &["zcode"]),
    ("google-chrome.desktop", "Google Chrome", &["google chrome", "chrome", "谷歌浏览器"]),
    ("firefox.desktop", "Firefox", &["firefox", "火狐浏览器", "火狐"]),
    ("wps-office-prometheus.desktop", "WPS Office", &["wps office", "wps文字", "wps表格", "wps"]),
    ("libreoffice-writer.desktop", "LibreOffice", &["libreoffice"]),
    ("obsidian.desktop", "Obsidian", &["obsidian"]),
    ("org.gnome.Nautilus.desktop", "文件管理器 (Nautilus)", &["nautilus", "文件管理器"]),
    ("org.gnome.Evince.desktop", "文档查看器 (Evince)", &["evince", "文档查看器"]),
    ("org.kde.okular.desktop", "Okular", &["okular"]),
    ("org.gnome.TextEditor.desktop", "文本编辑器", &["gnome-text-editor", "gedit"]),
    ("org.gnome.Terminal.desktop", "GNOME 终端", &["gnome-terminal"]),
    ("org.telegram.desktop.desktop", "Telegram", &["telegram", "电报"]),
    ("wechat.desktop", "微信", &["wechat", "微信"]),
    ("qq.desktop", "QQ", &["linuxqq", "腾讯qq", "qq"]),
    ("feishu.desktop", "飞书", &["feishu", "lark", "飞书"]),
    ("sodam.desktop", "SodaM 音乐", &["sodam", "sodam音乐", "汽水音乐"]),
    ("qqmusic.desktop", "QQ音乐", &["qqmusic", "qq音乐"]),
    ("netease-cloud-music.desktop", "网易云音乐", &["netease-cloud-music", "网易云音乐", "网易云"]),
    ("spotify.desktop", "Spotify", &["spotify"]),
    ("vlc.desktop", "VLC 媒体播放器", &["vlc"]),
    ("gimp.desktop", "GIMP", &["gimp"]),
];

/// Extract all mentioned entities from a turn (`user_text`, `assistant_text`, `tool_steps`).
///
/// `known_files` maps lowercase filename (e.g. `"report.pdf"` or stem `"周报"`) to full path so bare
/// file names upgrade cleanly to canonical paths when unambiguous.
/// `known_apps` maps lowercase alias/name to `(app_id, display_name)`.
pub fn extract_entities_from_turn(
    user_text: &str,
    assistant_text: &str,
    tool_steps: &[Value],
    known_files: &HashMap<String, String>,
    known_apps: &HashMap<String, (String, String)>,
    home_override: Option<&Path>,
) -> Vec<ExtractedEntity> {
    let home_str = home_override
        .map(|p| p.to_string_lossy().to_string())
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_else(|| "/home/user".to_string());

    let mut collected: Vec<ExtractedEntity> = Vec::new();
    let mut seen_keys: HashSet<(String, String)> = HashSet::new();
    let mut turn_path_by_filename: HashMap<String, String> = HashMap::new();
    let mut turn_path_by_stem: HashMap<String, String> = HashMap::new();

    let default_user_verb = infer_action_verb_from_text(user_text);

    // 1. First extract structured paths & apps from tool_steps (highest precision!)
    for step in tool_steps {
        extract_from_tool_step(
            step,
            &home_str,
            &mut collected,
            &mut seen_keys,
            &mut turn_path_by_filename,
            &mut turn_path_by_stem,
        );
    }

    // 2. Extract explicit file/dir paths & URLs from user_text and assistant_text
    for (source_text, is_user) in [(user_text, true), (assistant_text, false)] {
        if source_text.trim().is_empty() {
            continue;
        }
        extract_urls_and_paths_from_text(
            source_text,
            is_user,
            default_user_verb,
            &home_str,
            &mut collected,
            &mut seen_keys,
            &mut turn_path_by_filename,
            &mut turn_path_by_stem,
        );
    }

    // 3. Extract bare file names (`*.pdf`, `*.toml`, etc.) and quoted titles (`《周报》`)
    for (source_text, is_user) in [(user_text, true), (assistant_text, false)] {
        if source_text.trim().is_empty() {
            continue;
        }
        extract_bare_filenames_and_titles(
            source_text,
            is_user,
            default_user_verb,
            known_files,
            &turn_path_by_filename,
            &turn_path_by_stem,
            &mut collected,
            &mut seen_keys,
        );
    }

    // 4. Extract mentioned desktop software names
    for (source_text, is_user) in [(user_text, true), (assistant_text, false)] {
        if source_text.trim().is_empty() {
            continue;
        }
        extract_app_mentions(
            source_text,
            is_user,
            known_apps,
            &mut collected,
            &mut seen_keys,
        );
    }

    collected
}

fn push_unique_entity(
    collected: &mut Vec<ExtractedEntity>,
    seen_keys: &mut HashSet<(String, String)>,
    entity: ExtractedEntity,
) {
    if entity.canonical_value.trim().is_empty() || is_sensitive_credential_path(&entity.canonical_value) {
        return;
    }
    let key = (
        entity.entity_kind.clone(),
        entity.canonical_value.to_ascii_lowercase(),
    );
    if seen_keys.insert(key) {
        collected.push(entity);
    } else if entity.action_verb != "mention"
        && let Some(existing) = collected.iter_mut().find(|e| {
            e.entity_kind == entity.entity_kind
                && e.canonical_value
                    .eq_ignore_ascii_case(&entity.canonical_value)
        })
        && existing.action_verb == "mention"
    {
        existing.action_verb = entity.action_verb;
    }
}

fn register_path_lookup(
    full_path: &str,
    by_filename: &mut HashMap<String, String>,
    by_stem: &mut HashMap<String, String>,
) {
    let p = Path::new(full_path);
    if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
        by_filename.insert(fname.to_ascii_lowercase(), full_path.to_string());
    }
    if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
        by_stem.insert(stem.to_ascii_lowercase(), full_path.to_string());
    }
}

fn extract_from_tool_step(
    step: &Value,
    home_str: &str,
    collected: &mut Vec<ExtractedEntity>,
    seen_keys: &mut HashSet<(String, String)>,
    by_filename: &mut HashMap<String, String>,
    by_stem: &mut HashMap<String, String>,
) {
    let cap_id = step
        .get("capability_id")
        .or_else(|| step.get("tool_name"))
        .or_else(|| step.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let verb = verb_from_capability(cap_id);
    let summary_msg = step
        .get("message")
        .or_else(|| step.get("arguments_summary"))
        .and_then(|v| v.as_str())
        .unwrap_or(cap_id);
    let snippet = build_snippet(summary_msg, 120);

    let mut candidate_strings = Vec::new();
    for field in ["arguments", "args", "params", "data"] {
        if let Some(val) = step.get(field) {
            collect_path_like_values(val, &mut candidate_strings);
        }
    }
    if let Some(arg_sum) = step.get("arguments_summary").and_then(|v| v.as_str())
        && let Ok(parsed) = serde_json::from_str::<Value>(arg_sum)
    {
        collect_path_like_values(&parsed, &mut candidate_strings);
    }

    for raw_val in candidate_strings {
        let trimmed = raw_val.trim();
        if trimmed.starts_with('/') || trimmed.starts_with("~/") {
            let expanded = expand_home_prefix(trimmed, home_str);
            let (kind, clean_path, disp) = classify_path_entity(&expanded, summary_msg);
            if kind == "file" {
                register_path_lookup(&clean_path, by_filename, by_stem);
            }
            push_unique_entity(
                collected,
                seen_keys,
                ExtractedEntity {
                    entity_kind: kind,
                    canonical_value: clean_path,
                    display_name: disp,
                    action_verb: verb.to_string(),
                    context_snippet: snippet.clone(),
                },
            );
        } else if cap_id.contains("app")
            && !trimmed.is_empty()
            && trimmed.len() <= 80
            && !trimmed.contains('/')
        {
            push_unique_entity(
                collected,
                seen_keys,
                ExtractedEntity {
                    entity_kind: "app".to_string(),
                    canonical_value: trimmed.to_string(),
                    display_name: trimmed.trim_end_matches(".desktop").to_string(),
                    action_verb: "launch".to_string(),
                    context_snippet: snippet.clone(),
                },
            );
        }
    }
}

fn collect_path_like_values(val: &Value, out: &mut Vec<String>) {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let kl = k.to_ascii_lowercase();
                if matches!(
                    kl.as_str(),
                    "path"
                        | "file"
                        | "filepath"
                        | "file_path"
                        | "from"
                        | "to"
                        | "source"
                        | "src"
                        | "dest"
                        | "destination"
                        | "target"
                        | "dir"
                        | "directory"
                        | "cwd"
                        | "repo_dir"
                        | "app"
                        | "app_id"
                        | "app_hint"
                ) {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                    }
                } else {
                    collect_path_like_values(v, out);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter().take(12) {
                if let Some(s) = item.as_str() {
                    if s.starts_with('/') || s.starts_with("~/") {
                        out.push(s.to_string());
                    }
                } else {
                    collect_path_like_values(item, out);
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_urls_and_paths_from_text(
    text: &str,
    is_user: bool,
    default_user_verb: &str,
    home_str: &str,
    collected: &mut Vec<ExtractedEntity>,
    seen_keys: &mut HashSet<(String, String)>,
    by_filename: &mut HashMap<String, String>,
    by_stem: &mut HashMap<String, String>,
) {
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    static QUOTED_PATH_RE: OnceLock<Regex> = OnceLock::new();
    static BARE_PATH_RE: OnceLock<Regex> = OnceLock::new();

    let url_re = URL_RE.get_or_init(|| {
        Regex::new(r#"https?://[^\s<>'"`），。；！？\]\)]+"#).expect("valid url regex")
    });
    let quoted_path_re = QUOTED_PATH_RE.get_or_init(|| {
        Regex::new(r#"[`"']((?:~/|/(?:home|tmp|opt|etc|var|usr|mnt|media|srv|data|root)/)[^`"'\n]{1,240})[`"']"#)
            .expect("valid quoted path regex")
    });
    let bare_path_re = BARE_PATH_RE.get_or_init(|| {
        Regex::new(
            r#"(?:^|[\s:：(\[（，,《「])((?:~/|/(?:home|tmp|opt|etc|var|usr|mnt|media|srv|data)/)[^\s`"<>'"，,。；;！!？?）)\]》」]{1,220})"#,
        )
        .expect("valid bare path regex")
    });

    let snippet = build_snippet(text, 140);
    let verb = if is_user {
        default_user_verb
    } else {
        infer_action_verb_from_text(text)
    };

    for m in url_re.find_iter(text) {
        let clean_url = m
            .as_str()
            .trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}']);
        if clean_url.len() > 8 {
            push_unique_entity(
                collected,
                seen_keys,
                ExtractedEntity {
                    entity_kind: "url".to_string(),
                    canonical_value: clean_url.to_string(),
                    display_name: clean_url.to_string(),
                    action_verb: if verb == "mention" {
                        "open".to_string()
                    } else {
                        verb.to_string()
                    },
                    context_snippet: snippet.clone(),
                },
            );
        }
    }

    // Quoted paths first (preserves spaces inside paths)
    for caps in quoted_path_re.captures_iter(text) {
        let raw_p = caps[1].trim();
        let expanded = expand_home_prefix(raw_p, home_str);
        let (kind, clean_path, disp) = classify_path_entity(&expanded, text);
        if kind == "file" {
            register_path_lookup(&clean_path, by_filename, by_stem);
        }
        push_unique_entity(
            collected,
            seen_keys,
            ExtractedEntity {
                entity_kind: kind,
                canonical_value: clean_path,
                display_name: disp,
                action_verb: verb.to_string(),
                context_snippet: snippet.clone(),
            },
        );
    }

    // Unquoted paths
    for caps in bare_path_re.captures_iter(text) {
        let raw_p = caps[1]
            .trim()
            .trim_end_matches(['.', ',', ';', ':', '!', '?']);
        let expanded = expand_home_prefix(raw_p, home_str);
        let (kind, clean_path, disp) = classify_path_entity(&expanded, text);
        if kind == "file" {
            register_path_lookup(&clean_path, by_filename, by_stem);
        }
        push_unique_entity(
            collected,
            seen_keys,
            ExtractedEntity {
                entity_kind: kind,
                canonical_value: clean_path,
                display_name: disp,
                action_verb: verb.to_string(),
                context_snippet: snippet.clone(),
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_bare_filenames_and_titles(
    text: &str,
    is_user: bool,
    default_user_verb: &str,
    known_files: &HashMap<String, String>,
    turn_path_by_filename: &HashMap<String, String>,
    turn_path_by_stem: &HashMap<String, String>,
    collected: &mut Vec<ExtractedEntity>,
    seen_keys: &mut HashSet<(String, String)>,
) {
    static URL_STRIP_RE: OnceLock<Regex> = OnceLock::new();
    static FILENAME_RE: OnceLock<Regex> = OnceLock::new();
    static GUILLEMET_RE: OnceLock<Regex> = OnceLock::new();
    static DOC_QUOTED_RE: OnceLock<Regex> = OnceLock::new();

    let url_strip = URL_STRIP_RE
        .get_or_init(|| Regex::new(r#"https?://[^\s]+"#).expect("valid url strip regex"));
    let filename_re = FILENAME_RE.get_or_init(|| {
        Regex::new(
            r#"(?:^|[^A-Za-z0-9_/\-\.])([A-Za-z0-9\u{4e00}-\u{9fa5}][A-Za-z0-9_\-\.\u{4e00}-\u{9fa5}]{0,80}\.([A-Za-z0-9]{1,10}))"#,
        )
        .expect("valid filename regex")
    });
    let guillemet_re = GUILLEMET_RE
        .get_or_init(|| Regex::new(r#"《([^《》\n]{1,64})》"#).expect("valid guillemet regex"));
    let doc_quoted_re = DOC_QUOTED_RE.get_or_init(|| {
        Regex::new(
            r#"[「"“]([^」"”\n]{1,48})[」"”]\s*(?:文件|文档|报告|周报|表格|方案|配置|脚本|笔记)"#,
        )
        .expect("valid doc quoted regex")
    });

    let scrubbed_urls = url_strip.replace_all(text, " ");
    let snippet = build_snippet(text, 140);
    let verb = if is_user {
        default_user_verb
    } else {
        infer_action_verb_from_text(text)
    };

    // Bare filenames with known extensions
    for caps in filename_re.captures_iter(&scrubbed_urls) {
        let fname = caps[1].trim();
        let ext = caps[2].to_ascii_lowercase();
        if !KNOWN_FILE_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        // Guard against web domains like docs.rs or deno.sh
        let fname_lc = fname.to_ascii_lowercase();
        if matches!(
            fname_lc.as_str(),
            "docs.rs" | "crates.io" | "lib.rs" | "deno.sh" | "bun.sh" | "brew.sh" | "rustup.rs"
        ) && !text.contains("crates/")
            && !text.contains("src/")
        {
            continue;
        }

        // If a full path with this exact filename was already extracted in this turn, skip duplicate!
        if turn_path_by_filename.contains_key(&fname_lc) {
            continue;
        }

        // Upgrade to known full path from index/XBEL if available
        let canonical = known_files
            .get(&fname_lc)
            .cloned()
            .unwrap_or_else(|| fname.to_string());

        push_unique_entity(
            collected,
            seen_keys,
            ExtractedEntity {
                entity_kind: "file".to_string(),
                canonical_value: canonical,
                display_name: fname.to_string(),
                action_verb: verb.to_string(),
                context_snippet: snippet.clone(),
            },
        );
    }

    // Quoted titles like 《周报》 or 「季度总结」文档
    for raw_title in guillemet_re
        .captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim()))
        .chain(
            doc_quoted_re
                .captures_iter(text)
                .filter_map(|c| c.get(1).map(|m| m.as_str().trim())),
        )
    {
        if raw_title.is_empty() {
            continue;
        }
        let title_lc = raw_title.to_ascii_lowercase();
        if turn_path_by_filename.contains_key(&title_lc)
            || turn_path_by_stem.contains_key(&title_lc)
        {
            continue;
        }

        if let Some(full_path) = known_files.get(&title_lc) {
            let disp = Path::new(full_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(raw_title)
                .to_string();
            push_unique_entity(
                collected,
                seen_keys,
                ExtractedEntity {
                    entity_kind: "file".to_string(),
                    canonical_value: full_path.clone(),
                    display_name: disp,
                    action_verb: verb.to_string(),
                    context_snippet: snippet.clone(),
                },
            );
        } else {
            let has_ext = Path::new(raw_title)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| KNOWN_FILE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()));
            let kind = if has_ext { "file" } else { "document_ref" };
            push_unique_entity(
                collected,
                seen_keys,
                ExtractedEntity {
                    entity_kind: kind.to_string(),
                    canonical_value: raw_title.to_string(),
                    display_name: if has_ext {
                        raw_title.to_string()
                    } else {
                        format!("《{}》", raw_title)
                    },
                    action_verb: verb.to_string(),
                    context_snippet: snippet.clone(),
                },
            );
        }
    }
}

fn extract_app_mentions(
    text: &str,
    is_user: bool,
    known_apps: &HashMap<String, (String, String)>,
    collected: &mut Vec<ExtractedEntity>,
    seen_keys: &mut HashSet<(String, String)>,
) {
    let lower = text.to_ascii_lowercase();
    let snippet = build_snippet(text, 120);
    let verb = if is_user
        && (text.contains("打开")
            || text.contains("启动")
            || text.contains("用")
            || lower.contains("open")
            || lower.contains("launch"))
    {
        "launch"
    } else {
        "mention"
    };

    for (app_id, disp_name, aliases) in BUILTIN_APP_PATTERNS {
        if aliases.iter().any(|al| contains_word_or_cjk(&lower, al)) {
            push_unique_entity(
                collected,
                seen_keys,
                ExtractedEntity {
                    entity_kind: "app".to_string(),
                    canonical_value: (*app_id).to_string(),
                    display_name: (*disp_name).to_string(),
                    action_verb: verb.to_string(),
                    context_snippet: snippet.clone(),
                },
            );
        }
    }

    for (alias_lc, (app_id, disp_name)) in known_apps {
        if alias_lc.chars().count() >= 3 && contains_word_or_cjk(&lower, alias_lc) {
            push_unique_entity(
                collected,
                seen_keys,
                ExtractedEntity {
                    entity_kind: "app".to_string(),
                    canonical_value: app_id.clone(),
                    display_name: disp_name.clone(),
                    action_verb: verb.to_string(),
                    context_snippet: snippet.clone(),
                },
            );
        }
    }
}

fn contains_word_or_cjk(haystack_lower: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return false;
    }
    if !needle_lower.is_ascii() {
        return haystack_lower.contains(needle_lower);
    }
    for (idx, _) in haystack_lower.match_indices(needle_lower) {
        let before_ok = haystack_lower[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        let after_idx = idx + needle_lower.len();
        let after_ok = haystack_lower[after_idx..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

fn expand_home_prefix(raw: &str, home_str: &str) -> String {
    if let Some(rest) = raw.strip_prefix("~/") {
        format!("{}/{}", home_str.trim_end_matches('/'), rest)
    } else if raw == "~" {
        home_str.to_string()
    } else {
        raw.to_string()
    }
}

fn classify_path_entity(expanded_path: &str, surrounding_text: &str) -> (String, String, String) {
    let had_trailing_slash = expanded_path.len() > 1 && expanded_path.ends_with('/');
    let clean = if expanded_path.len() > 1 {
        expanded_path.trim_end_matches('/').to_string()
    } else {
        expanded_path.to_string()
    };
    let p = Path::new(&clean);
    let disp = p
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&clean)
        .to_string();

    if let Ok(meta) = std::fs::metadata(p) {
        if meta.is_dir() {
            return ("directory".to_string(), clean, disp);
        }
        return ("file".to_string(), clean, disp);
    }

    if had_trailing_slash {
        return ("directory".to_string(), clean, disp);
    }

    let has_ext = p
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| !e.is_empty() && e.len() <= 10);
    if has_ext {
        return ("file".to_string(), clean, disp);
    }

    let disp_lc = disp.to_ascii_lowercase();
    if matches!(
        disp_lc.as_str(),
        "downloads"
            | "documents"
            | "desktop"
            | "pictures"
            | "music"
            | "videos"
            | "workspace"
            | "projects"
            | "code"
            | "src"
            | "docs"
            | "config"
            | "下载"
            | "文档"
            | "桌面"
            | "图片"
            | "音乐"
            | "视频"
    ) || surrounding_text.contains("目录")
        || surrounding_text.contains("文件夹")
    {
        ("directory".to_string(), clean, disp)
    } else {
        ("file".to_string(), clean, disp)
    }
}

/// Infer semantic action verb from Chinese/English user utterance.
pub fn infer_action_verb_from_text(text: &str) -> &'static str {
    let lc = text.to_ascii_lowercase();
    if text.contains("修改")
        || text.contains("改了")
        || text.contains("改一下")
        || text.contains("编辑")
        || text.contains("更新")
        || text.contains("写入")
        || lc.contains("edit")
        || lc.contains("modify")
        || lc.contains("update")
    {
        "edit"
    } else if text.contains("新建")
        || text.contains("创建")
        || text.contains("生成")
        || lc.contains("create")
    {
        "create"
    } else if text.contains("移动")
        || text.contains("挪到")
        || text.contains("移到")
        || lc.contains("move")
    {
        "move"
    } else if text.contains("复制") || text.contains("备份") || lc.contains("copy") {
        "copy"
    } else if text.contains("转换") || text.contains("导出") || lc.contains("convert") {
        "convert"
    } else if text.contains("删除")
        || text.contains("回收站")
        || lc.contains("trash")
        || lc.contains("delete")
    {
        "trash"
    } else if text.contains("搜索")
        || text.contains("查找")
        || text.contains("找一下")
        || lc.contains("search")
        || lc.contains("find")
    {
        "search"
    } else if text.contains("打开")
        || text.contains("查看")
        || text.contains("看看")
        || text.contains("阅读")
        || lc.contains("open")
        || lc.contains("view")
    {
        "open"
    } else {
        "mention"
    }
}

fn verb_from_capability(cap_id: &str) -> &'static str {
    let lc = cap_id.to_ascii_lowercase();
    if lc.contains("move") {
        "move"
    } else if lc.contains("copy") {
        "copy"
    } else if lc.contains("rename") {
        "rename"
    } else if lc.contains("trash") || lc.contains("delete") {
        "trash"
    } else if lc.contains("edit") || lc.contains("write") || lc.contains("overwrite") {
        "edit"
    } else if lc.contains("convert") {
        "convert"
    } else if lc.contains("search") || lc.contains("recent") {
        "search"
    } else if lc.contains("launch") || lc.contains("app") {
        "launch"
    } else if lc.contains("open") {
        "open"
    } else {
        "use"
    }
}

fn build_snippet(raw: &str, max_chars: usize) -> String {
    let scrubbed = scrub_sensitive_text(raw);
    let single_line = scrubbed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if single_line.chars().count() <= max_chars {
        single_line
    } else {
        let mut s: String = single_line.chars().take(max_chars).collect();
        s.push('…');
        s
    }
}

/// Persist extracted entity mentions into `memory_hub.db` and return the updated records.
pub fn upsert_entity_mentions(
    db: &MemoryHubDb,
    entities: &[ExtractedEntity],
    session_id: &str,
) -> anyhow::Result<Vec<EntityMention>> {
    if entities.is_empty() {
        return Ok(Vec::new());
    }
    let now = Utc::now();
    let now_rfc = now.to_rfc3339();
    let now_epoch = now.timestamp();

    let mut conn = db.conn.lock().unwrap();
    let tx = conn.transaction()?;
    let mut ids = Vec::with_capacity(entities.len());

    for ent in entities {
        let id = compute_entity_id(&ent.entity_kind, &ent.canonical_value);
        let clean_snippet = scrub_sensitive_text(&ent.context_snippet);
        tx.execute(
            "INSERT INTO entity_mentions (
                id, entity_kind, canonical_value, display_name, action_verb,
                context_snippet, session_id, mention_count, first_seen_at, last_seen_at, last_seen_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?8, ?9)
             ON CONFLICT(entity_kind, canonical_value) DO UPDATE SET
                display_name = excluded.display_name,
                action_verb = CASE
                    WHEN excluded.action_verb != 'mention' THEN excluded.action_verb
                    ELSE entity_mentions.action_verb
                END,
                context_snippet = CASE
                    WHEN excluded.context_snippet != '' THEN excluded.context_snippet
                    ELSE entity_mentions.context_snippet
                END,
                session_id = CASE
                    WHEN excluded.session_id != '' THEN excluded.session_id
                    ELSE entity_mentions.session_id
                END,
                mention_count = entity_mentions.mention_count + 1,
                last_seen_at = excluded.last_seen_at,
                last_seen_epoch = excluded.last_seen_epoch",
            params![
                id,
                ent.entity_kind,
                ent.canonical_value,
                ent.display_name,
                ent.action_verb,
                clean_snippet,
                session_id,
                now_rfc,
                now_epoch,
            ],
        )?;
        ids.push((ent.entity_kind.clone(), ent.canonical_value.clone()));
    }
    tx.commit()?;

    let mut out = Vec::with_capacity(ids.len());
    for (kind, canon) in ids {
        let mut stmt = conn.prepare(
            "SELECT id, entity_kind, canonical_value, display_name, action_verb,
                    context_snippet, session_id, mention_count, first_seen_at, last_seen_at, last_seen_epoch
             FROM entity_mentions WHERE entity_kind = ?1 AND canonical_value = ?2",
        )?;
        if let Ok(rec) = stmt.query_row(params![kind, canon], row_to_entity_mention) {
            out.push(rec);
        }
    }
    Ok(out)
}

pub(crate) fn row_to_entity_mention(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntityMention> {
    let kind: String = row.get(1)?;
    let canon: String = row.get(2)?;
    let path = if kind == "file" || kind == "directory" {
        Some(canon.clone())
    } else {
        None
    };
    Ok(EntityMention {
        id: row.get(0)?,
        entity_kind: kind,
        canonical_value: canon,
        path,
        display_name: row.get(3)?,
        action_verb: row.get(4)?,
        context_snippet: row.get(5)?,
        session_id: row.get(6)?,
        mention_count: row.get::<_, i64>(7)?.max(0) as u64,
        first_seen_at: row.get(8)?,
        last_seen_at: row.get(9)?,
        last_seen_epoch: row.get(10)?,
    })
}

/// List recent entity mentions optionally filtered by `entity_kind` or `session_id`.
pub fn list_recent_mentions(
    db: &MemoryHubDb,
    only_files_and_docs: bool,
    session_id: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<EntityMention>> {
    let cap = limit.clamp(1, 200) as i64;
    let conn = db.conn.lock().unwrap();
    let mut out = Vec::new();

    match (only_files_and_docs, session_id.filter(|s| !s.is_empty())) {
        (true, Some(sid)) => {
            let mut stmt = conn.prepare(
                "SELECT id, entity_kind, canonical_value, display_name, action_verb,
                        context_snippet, session_id, mention_count, first_seen_at, last_seen_at, last_seen_epoch
                 FROM entity_mentions
                 WHERE entity_kind IN ('file', 'directory', 'document_ref') AND session_id = ?1
                 ORDER BY last_seen_epoch DESC, rowid DESC LIMIT ?2",
            )?;
            for row in stmt.query_map(params![sid, cap], row_to_entity_mention)? {
                out.push(row?);
            }
        }
        (true, None) => {
            let mut stmt = conn.prepare(
                "SELECT id, entity_kind, canonical_value, display_name, action_verb,
                        context_snippet, session_id, mention_count, first_seen_at, last_seen_at, last_seen_epoch
                 FROM entity_mentions
                 WHERE entity_kind IN ('file', 'directory', 'document_ref')
                 ORDER BY last_seen_epoch DESC, rowid DESC LIMIT ?1",
            )?;
            for row in stmt.query_map(params![cap], row_to_entity_mention)? {
                out.push(row?);
            }
        }
        (false, Some(sid)) => {
            let mut stmt = conn.prepare(
                "SELECT id, entity_kind, canonical_value, display_name, action_verb,
                        context_snippet, session_id, mention_count, first_seen_at, last_seen_at, last_seen_epoch
                 FROM entity_mentions
                 WHERE session_id = ?1
                 ORDER BY last_seen_epoch DESC, rowid DESC LIMIT ?2",
            )?;
            for row in stmt.query_map(params![sid, cap], row_to_entity_mention)? {
                out.push(row?);
            }
        }
        (false, None) => {
            let mut stmt = conn.prepare(
                "SELECT id, entity_kind, canonical_value, display_name, action_verb,
                        context_snippet, session_id, mention_count, first_seen_at, last_seen_at, last_seen_epoch
                 FROM entity_mentions
                 ORDER BY last_seen_epoch DESC, rowid DESC LIMIT ?1",
            )?;
            for row in stmt.query_map(params![cap], row_to_entity_mention)? {
                out.push(row?);
            }
        }
    }
    Ok(out)
}

/// Recall and rank previously mentioned entities for natural queries like:
/// - "我之前说的那个文件"
/// - "上次提到的文档"
/// - "刚才改的配置"
/// - "周报"
pub fn recall_mentioned_entities(
    db: &MemoryHubDb,
    query: &str,
    entity_kind_filter: Option<&str>,
    session_id: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<(EntityMention, f64)>> {
    let cap = limit.clamp(1, 100);
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, entity_kind, canonical_value, display_name, action_verb,
                context_snippet, session_id, mention_count, first_seen_at, last_seen_at, last_seen_epoch
         FROM entity_mentions
         ORDER BY last_seen_epoch DESC, rowid DESC LIMIT 300",
    )?;
    let mut all = Vec::new();
    for row in stmt.query_map([], row_to_entity_mention)? {
        all.push(row?);
    }
    drop(stmt);
    drop(conn);

    if let Some(kf) = entity_kind_filter
        .map(str::trim)
        .filter(|k| !k.is_empty() && *k != "all")
    {
        if kf == "mentioned_files" || kf == "file_like" {
            all.retain(|e| matches!(e.entity_kind.as_str(), "file" | "directory" | "document_ref"));
        } else {
            all.retain(|e| e.entity_kind == kf);
        }
    }

    let q_trim = query.trim();
    let q_lc = q_trim.to_ascii_lowercase();
    let now_epoch = Utc::now().timestamp();

    // Semantic cues from natural Chinese/English reference expressions
    let wants_config = q_trim.contains("配置")
        || q_lc.contains("config")
        || q_lc.contains("toml")
        || q_lc.contains("yaml")
        || q_lc.contains("json")
        || q_trim.contains("设置文件");
    let wants_doc = q_trim.contains("文档")
        || q_trim.contains("报告")
        || q_trim.contains("文章")
        || q_trim.contains("方案")
        || q_trim.contains("笔记")
        || q_lc.contains("doc")
        || q_lc.contains("pdf");
    let wants_code = q_trim.contains("代码")
        || q_trim.contains("脚本")
        || q_trim.contains("源码")
        || q_lc.contains("script")
        || q_lc.contains("code");
    let wants_sheet = q_trim.contains("表格")
        || q_trim.contains("数据表")
        || q_lc.contains("excel")
        || q_lc.contains("xlsx")
        || q_lc.contains("csv");
    let wants_dir = q_trim.contains("目录") || q_trim.contains("文件夹") || q_lc.contains("folder");
    let wants_app = (q_trim.contains("软件") || q_trim.contains("应用") || q_trim.contains("程序"))
        && !q_trim.contains("文件");
    let wants_url = q_trim.contains("网址") || q_trim.contains("链接") || q_lc.contains("url");
    let wants_file_broad = q_trim.contains("文件") || wants_config || wants_doc || wants_code || wants_sheet;

    let wants_edit_verb =
        q_trim.contains("改") || q_trim.contains("修改") || q_trim.contains("编辑") || q_lc.contains("edit");
    let wants_open_verb = q_trim.contains("打开") || q_trim.contains("看过") || q_trim.contains("查看");
    let wants_move_verb = q_trim.contains("移动") || q_trim.contains("挪");
    let wants_create_verb = q_trim.contains("新建") || q_trim.contains("创建") || q_trim.contains("生成");
    let prefers_current_session = q_trim.contains("刚才") || q_trim.contains("刚刚") || q_trim.contains("这轮");

    let content_keywords = extract_specific_keywords(q_trim);

    let mut scored: Vec<(EntityMention, f64)> = Vec::new();
    let total_len = all.len();

    for (rank_idx, item) in all.into_iter().enumerate() {
        let mut score = 20.0;
        let canon_lc = item.canonical_value.to_ascii_lowercase();
        let disp_lc = item.display_name.to_ascii_lowercase();
        let snip_lc = item.context_snippet.to_ascii_lowercase();
        let ext = Path::new(&item.canonical_value)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // 1. Entity kind / category alignment
        if wants_config {
            if matches!(ext.as_str(), "toml" | "json" | "yaml" | "yml" | "conf" | "ini" | "cfg")
                || disp_lc.contains("config")
                || item.display_name.contains("配置")
                || item.context_snippet.contains("配置")
            {
                score += 65.0;
            } else {
                score -= 25.0;
            }
        }
        if wants_doc {
            if item.entity_kind == "document_ref"
                || matches!(
                    ext.as_str(),
                    "pdf" | "doc" | "docx" | "md" | "markdown" | "txt" | "odt" | "ppt" | "pptx" | "rtf"
                )
            {
                score += 55.0;
            } else {
                score -= 20.0;
            }
        }
        if wants_code {
            if matches!(
                ext.as_str(),
                "rs" | "py" | "js" | "ts" | "tsx" | "sh" | "go" | "c" | "cpp" | "java" | "sql"
            ) {
                score += 55.0;
            } else {
                score -= 20.0;
            }
        }
        if wants_sheet {
            if matches!(ext.as_str(), "xls" | "xlsx" | "csv" | "tsv" | "ods") {
                score += 55.0;
            } else {
                score -= 20.0;
            }
        }
        if wants_dir {
            if item.entity_kind == "directory" {
                score += 60.0;
            } else {
                score -= 30.0;
            }
        } else if wants_app {
            if item.entity_kind == "app" {
                score += 65.0;
            } else {
                score -= 35.0;
            }
        } else if wants_url {
            if item.entity_kind == "url" {
                score += 65.0;
            } else {
                score -= 35.0;
            }
        } else if wants_file_broad {
            if matches!(item.entity_kind.as_str(), "file" | "document_ref") {
                score += 30.0;
            } else if item.entity_kind == "directory" {
                score += 10.0;
            } else {
                score -= 35.0;
            }
        }

        // 2. Action verb alignment ("刚才改的配置", "上次打开的文档")
        if wants_edit_verb {
            if item.action_verb == "edit" {
                score += 55.0;
            } else if item.context_snippet.contains("改")
                || item.context_snippet.contains("修改")
                || item.context_snippet.contains("编辑")
            {
                score += 30.0;
            }
        }
        if wants_open_verb && item.action_verb == "open" {
            score += 30.0;
        }
        if wants_move_verb && (item.action_verb == "move" || item.action_verb == "rename") {
            score += 40.0;
        }
        if wants_create_verb && item.action_verb == "create" {
            score += 40.0;
        }

        // 3. Explicit keyword matching (including Pinyin)
        if !content_keywords.is_empty() {
            let (py_full, py_init) = to_pinyin_pair(&item.display_name);
            let mut matched_kw = 0usize;
            for kw in &content_keywords {
                let kw_lc = kw.to_ascii_lowercase();
                if disp_lc == kw_lc || canon_lc == kw_lc {
                    score += 95.0;
                    matched_kw += 1;
                } else if disp_lc.contains(&kw_lc) || canon_lc.contains(&kw_lc) {
                    score += 75.0;
                    matched_kw += 1;
                } else if py_full.contains(&kw_lc) || py_init.contains(&kw_lc) {
                    score += 55.0;
                    matched_kw += 1;
                } else if snip_lc.contains(&kw_lc) {
                    score += 45.0;
                    matched_kw += 1;
                }
            }
            if matched_kw == 0
                && (!is_conversational_entity_reference(q_trim)
                    || (!wants_config && !wants_doc && !wants_code && !wants_sheet))
            {
                continue;
            }
        }

        // Deprioritize OS installer/package artifacts unless explicitly requested
        let asks_pkg = q_trim.contains("安装包")
            || q_lc.contains("deb")
            || q_lc.contains("rpm")
            || q_lc.contains("zst")
            || q_lc.contains("appimage")
            || q_lc.contains("iso")
            || q_lc.contains("package");
        if !asks_pkg && is_installer_or_package_artifact(&item.canonical_value) {
            score -= 65.0;
        }

        // 4. Session affinity + recency + frequency
        if let Some(sid) = session_id.filter(|s| !s.is_empty())
            && item.session_id == sid
        {
            score += if prefers_current_session { 25.0 } else { 10.0 };
        }
        let age_hours = ((now_epoch - item.last_seen_epoch).max(0) as f64) / 3600.0;
        score += 18.0 / (1.0 + age_hours / 12.0);
        score += (item.mention_count as f64).ln_1p() * 6.0;
        // Preserve insertion/recency order tie-breaker
        score += ((total_len.saturating_sub(rank_idx)) as f64) * 0.05;

        if score > 0.0 {
            scored.push((item, score));
        }
    }

    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(cap);
    Ok(scored)
}

/// Check if a user prompt contains a conversational memory reference like "我之前说的那个文件", "上次提到的文档", "刚才改的配置".
pub fn is_conversational_entity_reference(query: &str) -> bool {
    let q = query.trim();
    let has_temporal = q.contains("之前")
        || q.contains("上次")
        || q.contains("刚才")
        || q.contains("刚刚")
        || q.contains("前面")
        || q.contains("历史")
        || q.contains("提到")
        || q.contains("提过")
        || q.contains("说过")
        || q.contains("聊过");
    let has_target = q.contains("文件")
        || q.contains("文档")
        || q.contains("配置")
        || q.contains("报告")
        || q.contains("周报")
        || q.contains("脚本")
        || q.contains("代码")
        || q.contains("目录")
        || q.contains("文件夹")
        || q.contains("表格")
        || q.contains("那个")
        || q.contains("那份");
    has_temporal && has_target
}

fn extract_specific_keywords(query: &str) -> Vec<String> {
    let mut cleaned = query.to_string();
    for phrase in [
        "我之前说的那个文件",
        "我之前说的文件",
        "之前说的那个文件",
        "之前提到的那个文件",
        "之前提到的文件",
        "上次提到的文档",
        "上次提到的文件",
        "刚才改的配置文件",
        "刚才改的配置",
        "之前修改的配置",
        "我之前说的",
        "之前说的",
        "上次说的",
        "上次提到的",
        "之前提到的",
        "刚才提到的",
        "刚才说的",
        "刚才改的",
        "刚刚改的",
        "上次改的",
        "之前改的",
        "那个文件",
        "那些文件",
        "那份文件",
        "这个文件",
        "那个文档",
        "那份文档",
        "那个配置",
        "配置文件",
        "长期高频使用的",
        "长期高频常用",
        "长期使用的",
        "长期常用",
        "高频使用的",
        "经常使用的",
        "常用的",
        "有哪些",
        "是什么",
        "在哪里",
        "帮我看看",
        "帮我看一下",
        "帮我查看",
        "帮我打开",
        "帮我找一下",
        "帮我找",
        "帮我看",
        "看看",
        "查看",
        "打开",
        "请问",
        "文件",
        "文档",
        "配置",
        "目录",
        "文件夹",
        "软件",
        "应用",
    ] {
        cleaned = cleaned.replace(phrase, " ");
    }

    cleaned
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '，' | ',' | '。' | '？' | '?' | '！' | '!' | '：' | ':' | '；' | ';' | '《'
                        | '》' | '「' | '」' | '"' | '\'' | '(' | ')' | '（' | '）' | '@'
                )
        })
        .map(str::trim)
        .filter(|tok| !tok.is_empty() && tok.chars().count() >= 2)
        .map(String::from)
        .collect()
}
