#![forbid(unsafe_code)]

//! URI Deep-Link & `.desktop` Desktop Actions Driver (`uri_desktop.rs`):
//! - Parses `[Desktop Entry]` and `[Desktop Action ...]` sections from Freedesktop `.desktop` files
//! - Safely tokenizes `Exec=` lines into discrete non-shell `Command` arguments (stripping `%u`/`%U`/`%f`/`%F` field codes)
//! - Builds and percent-encodes deep-link URIs (`vscode://file/...`, `obsidian://open?...`, `mailto:...`, `tg://...`)
//! - Strictly blocks dangerous URI schemes (`javascript:`, `data:`, `vbscript:`, `blob:`, `file:` raw injection)

use crate::app_adapter::mpris_dbus::has_gui_session;
use crate::app_adapter::registry::{AdaptationChannel, AppAdapterProfile, SemanticAppAction};
use crate::app_adapter::sni_dbusmenu::apply_clean_desktop_env_std;
use crate::core::IntentOsCore;
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_protocol::{VerificationReport, VerificationState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Dangerous URI schemes that MUST never be dispatched via `gio open` / `xdg-open` or browser actions.
const BLOCKED_URI_SCHEMES: &[&str] = &[
    "javascript",
    "data",
    "vbscript",
    "blob",
    "jar",
    "view-source",
    "about",
    "chrome",
    "chrome-extension",
    "moz-extension",
    "filesystem",
    "file",
    "fd",
    "bash",
    "sh",
];

/// Default allowlist of safe URI schemes supported by built-in adapters.
const SAFE_BUILTIN_SCHEMES: &[&str] = &[
    "http",
    "https",
    "vscode",
    "vscode-insiders",
    "zcode",
    "cursor",
    "trae-cn",
    "workbuddy",
    "antigravity",
    "obsidian",
    "tg",
    "mailto",
    "spotify",
    "orpheus",
    "ksowebstartupwps",
    "applink.feishu",
    "feishu",
    "feishu-open",
    "lark",
    "wemeet",
    "tencent",
    "weixin",
    "baiduyunguanjia",
    "rustdesk",
    "zoommtg",
    "zoomus",
    "magnet",
    "gnome-extensions",
    "codex",
    "clash",
    "clashmeta",
    "flclash",
];

/// Environment variable names that MUST NEVER be injected from a `.desktop` `Exec=env ...` line.
const BLOCKED_DESKTOP_ENV_KEYS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "BASH_ENV",
    "ENV",
    "PATH",
    "IFS",
];

/// Normalize a meeting room code (e.g. `"123 456 789"` or `"987-654-3210"`) into clean 8–13 ASCII digits.
pub fn normalize_meeting_code(raw: &str) -> anyhow::Result<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '_' | '–' | '—' | '#'))
        .collect();
    if cleaned.len() < 8 || cleaned.len() > 13 || !cleaned.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!(
            "无效的会议号 `{}`（需为 8~13 位数字会议号，支持自动去除空格与连字符）",
            raw.trim()
        );
    }
    Ok(cleaned)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopActionSection {
    pub action_id: String,
    pub name: String,
    pub localized_name: Option<String>,
    pub exec: String,
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedDesktopFile {
    pub desktop_id: String,
    pub name: String,
    pub exec: Option<String>,
    pub dbus_activatable: bool,
    pub declared_actions: Vec<String>,
    pub actions: BTreeMap<String, DesktopActionSection>,
}

#[derive(Debug, Clone)]
pub struct UriDesktopDispatchResult {
    pub ok: bool,
    pub channel_used: AdaptationChannel,
    pub translated_command: String,
    pub summary: String,
    pub data: Value,
    pub simulated: bool,
    pub verification: VerificationReport,
}

/// Strictly validate a URI against dangerous schemes (`javascript:`, `data:`, `vbscript:`, etc.) and control bytes.
pub fn validate_uri_safety(
    raw_uri: &str,
    extra_allowed_schemes: &[String],
) -> anyhow::Result<String> {
    let trimmed = raw_uri.trim();
    if trimmed.is_empty() {
        anyhow::bail!("URI 不能为空");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        anyhow::bail!("安全拦截：URI 包含非法控制字符");
    }

    let Some(colon_idx) = trimmed.find(':') else {
        anyhow::bail!("无效的 URI 格式（缺少协议头）: {}", trimmed);
    };
    let scheme = trimmed[..colon_idx].trim().to_ascii_lowercase();
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        anyhow::bail!("安全拦截：非法的 URI 协议头 '{}'", scheme);
    }

    if BLOCKED_URI_SCHEMES.contains(&scheme.as_str()) {
        anyhow::bail!("安全拦截：严禁打开高危或受限 URI 协议 `{}:`", scheme);
    }

    let is_allowed = SAFE_BUILTIN_SCHEMES.contains(&scheme.as_str())
        || extra_allowed_schemes.iter().any(|s| {
            s.eq_ignore_ascii_case(&scheme)
                && !BLOCKED_URI_SCHEMES.contains(&s.to_ascii_lowercase().as_str())
        });

    if !is_allowed {
        anyhow::bail!("安全拦截：未在适配器白名单中的 URI 协议 `{}:`", scheme);
    }

    Ok(trimmed.to_string())
}

/// Percent-encode an absolute filesystem path for IDE deep-links (`vscode://file/path/to/file`).
fn encode_ide_file_path(path: &Path) -> anyhow::Result<String> {
    if !path.is_absolute() {
        anyhow::bail!("IDE 深度链接文件路径必须为绝对路径: {}", path.display());
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            anyhow::bail!("安全拦截：路径禁止包含 '..' 父目录跳转: {}", path.display());
        }
    }
    let mut encoded = String::new();
    for seg in path.to_string_lossy().split('/') {
        if seg.is_empty() {
            continue;
        }
        encoded.push('/');
        encoded.push_str(&urlencoding::encode(seg));
    }
    if encoded.is_empty() {
        encoded.push('/');
    }
    Ok(encoded)
}

/// Build a safe, RFC-encoded deep-link URI for the given adapter profile, semantic action, and parameters.
pub fn build_uri_deeplink(
    core: Option<&IntentOsCore>,
    profile: &AppAdapterProfile,
    semantic_action: &SemanticAppAction,
    params: &Value,
) -> anyhow::Result<String> {
    let canonical = semantic_action.action.as_str();
    let primary_scheme = profile
        .uri_schemes
        .first()
        .map(String::as_str)
        .unwrap_or("https");

    // Direct explicit URI if provided in `params.uri` or `params.url` for `open_uri`
    if canonical == "open_uri"
        && let Some(explicit) = params
            .get("uri")
            .or_else(|| params.get("url"))
            .and_then(|v| v.as_str())
    {
        return validate_uri_safety(explicit, &profile.uri_schemes);
    }

    let constructed = match (primary_scheme, canonical) {
        (
            "vscode" | "vscode-insiders" | "zcode" | "cursor" | "trae-cn" | "workbuddy"
            | "antigravity",
            "open_file_at_line" | "goto_file_line" | "open_workspace" | "open_project",
        ) => {
            let raw_path = params
                .get("path")
                .or_else(|| params.get("file"))
                .or_else(|| params.get("workspace"))
                .or_else(|| params.get("dir"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("IDE 跳转缺少 `path` 参数"))?;
            let path = Path::new(raw_path);
            if let Some(c) = core
                && c.fs_engine.is_forbidden(path)
            {
                anyhow::bail!("安全内核拦截：禁止通过 URI 协议打开敏感路径 {}", raw_path);
            }
            let enc_path = encode_ide_file_path(path)?;
            let line = params.get("line").and_then(|v| v.as_u64());
            let col = params
                .get("column")
                .or_else(|| params.get("col"))
                .and_then(|v| v.as_u64());
            match (canonical, line, col) {
                ("open_file_at_line" | "goto_file_line", Some(l), Some(c)) if l >= 1 && c >= 1 => {
                    format!("{}://file{}:{}:{}", primary_scheme, enc_path, l, c)
                }
                ("open_file_at_line" | "goto_file_line", Some(l), None) if l >= 1 => {
                    format!("{}://file{}:{}", primary_scheme, enc_path, l)
                }
                _ => format!("{}://file{}", primary_scheme, enc_path),
            }
        }
        ("wemeet", "join_meeting") | (_, "join_meeting")
            if primary_scheme == "wemeet"
                || profile.id.contains("wemeet")
                || profile.uri_schemes.iter().any(|s| s == "wemeet") =>
        {
            let raw_code = params
                .get("meeting_code")
                .or_else(|| params.get("code"))
                .or_else(|| params.get("room"))
                .or_else(|| params.get("confno"))
                .or_else(|| params.get("meeting_id"))
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                })
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("腾讯会议入会缺少 `meeting_code` 参数（如 9~11 位数字会议号）")
                })?;
            let code = normalize_meeting_code(&raw_code)?;
            if let Some(pwd) = params
                .get("password")
                .or_else(|| params.get("passcode"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                format!(
                    "wemeet://page/inmeeting?meeting_code={}&password={}",
                    code,
                    urlencoding::encode(pwd)
                )
            } else {
                format!("wemeet://page/inmeeting?meeting_code={}", code)
            }
        }
        ("zoommtg" | "zoomus", "join_meeting") | (_, "join_meeting") => {
            let raw_code = params
                .get("meeting_code")
                .or_else(|| params.get("confno"))
                .or_else(|| params.get("code"))
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                })
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("视频会议入会缺少 `meeting_code` 参数"))?;
            let code = normalize_meeting_code(&raw_code)?;
            if let Some(pwd) = params.get("password").and_then(|v| v.as_str())
                && !pwd.trim().is_empty()
            {
                format!(
                    "zoommtg://zoom.us/join?confno={}&pwd={}",
                    code,
                    urlencoding::encode(pwd.trim())
                )
            } else {
                format!("zoommtg://zoom.us/join?confno={}", code)
            }
        }
        ("feishu" | "lark" | "applink.feishu", _) | (_, "open_feishu_uri") => {
            if let Some(raw_u) = params
                .get("uri")
                .or_else(|| params.get("url"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                raw_u.to_string()
            } else if let Some(chat_id) = params
                .get("chat_id")
                .or_else(|| params.get("target"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                format!(
                    "feishu://client/chat/open?id={}",
                    urlencoding::encode(chat_id)
                )
            } else {
                "feishu://client/open".to_string()
            }
        }
        ("tencent", _) => {
            if let Some(uin) = params
                .get("uin")
                .or_else(|| params.get("qq"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
            {
                format!("tencent://message/?uin={}", uin)
            } else {
                "tencent://".to_string()
            }
        }
        ("weixin", _) => {
            if let Some(u) = params.get("uri").and_then(|v| v.as_str())
                && !u.trim().is_empty()
            {
                u.trim().to_string()
            } else {
                "weixin://".to_string()
            }
        }
        ("obsidian", "open_note") => {
            if let Some(raw_path) = params.get("path").and_then(|v| v.as_str())
                && raw_path.starts_with('/')
            {
                let p = Path::new(raw_path);
                if let Some(c) = core
                    && c.fs_engine.is_forbidden(p)
                {
                    anyhow::bail!("安全内核拦截：禁止通过 Obsidian 打开敏感路径 {}", raw_path);
                }
                format!("obsidian://open?path={}", urlencoding::encode(raw_path))
            } else {
                let vault = params
                    .get("vault")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Main");
                let file = params
                    .get("file")
                    .or_else(|| params.get("note"))
                    .or_else(|| params.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if file.is_empty() {
                    format!("obsidian://open?vault={}", urlencoding::encode(vault))
                } else {
                    format!(
                        "obsidian://open?vault={}&file={}",
                        urlencoding::encode(vault),
                        urlencoding::encode(file)
                    )
                }
            }
        }
        ("obsidian", "new_note") => {
            let vault = params
                .get("vault")
                .and_then(|v| v.as_str())
                .unwrap_or("Main");
            let name = params
                .get("name")
                .or_else(|| params.get("title"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("新建 Obsidian 笔记缺少 `name` 参数"))?;
            let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
            format!(
                "obsidian://new?vault={}&name={}&content={}",
                urlencoding::encode(vault),
                urlencoding::encode(name),
                urlencoding::encode(content)
            )
        }
        ("obsidian", "search_notes") => {
            let vault = params
                .get("vault")
                .and_then(|v| v.as_str())
                .unwrap_or("Main");
            let query = params
                .get("query")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Obsidian 搜索缺少 `query` 参数"))?;
            format!(
                "obsidian://search?vault={}&query={}",
                urlencoding::encode(vault),
                urlencoding::encode(query)
            )
        }
        ("mailto", _) | (_, "compose_email") => {
            let to = params
                .get("to")
                .or_else(|| params.get("recipient"))
                .or_else(|| params.get("email"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if to
                .chars()
                .any(|c| c.is_control() || matches!(c, '?' | '&' | '\n' | '\r'))
            {
                anyhow::bail!("安全拦截：收件人地址包含非法字符");
            }
            let mut query_pairs = Vec::new();
            if let Some(subj) = params.get("subject").and_then(|v| v.as_str())
                && !subj.is_empty()
            {
                query_pairs.push(format!("subject={}", urlencoding::encode(subj)));
            }
            if let Some(body) = params.get("body").and_then(|v| v.as_str())
                && !body.is_empty()
            {
                query_pairs.push(format!("body={}", urlencoding::encode(body)));
            }
            if let Some(cc) = params.get("cc").and_then(|v| v.as_str())
                && !cc.is_empty()
            {
                query_pairs.push(format!("cc={}", urlencoding::encode(cc)));
            }
            if query_pairs.is_empty() {
                format!("mailto:{}", to.trim())
            } else {
                format!("mailto:{}?{}", to.trim(), query_pairs.join("&"))
            }
        }
        ("tg", _) | (_, "open_chat") => {
            let domain = params
                .get("domain")
                .or_else(|| params.get("username"))
                .or_else(|| params.get("contact"))
                .or_else(|| params.get("chat"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("Telegram 会话跳转缺少 `domain` / `username` 参数")
                })?;
            let clean = domain.trim().trim_start_matches('@');
            format!("tg://resolve?domain={}", urlencoding::encode(clean))
        }
        ("spotify", _) => {
            if let Some(q) = params.get("query").and_then(|v| v.as_str()) {
                format!("spotify:search:{}", urlencoding::encode(q.trim()))
            } else if let Some(uri) = params.get("uri").and_then(|v| v.as_str()) {
                uri.to_string()
            } else {
                "spotify:app".to_string()
            }
        }
        _ => {
            if let Some(ref tpl) = semantic_action.target_template {
                render_uri_template(tpl, params)?
            } else if let Some(u) = params
                .get("uri")
                .or_else(|| params.get("url"))
                .and_then(|v| v.as_str())
            {
                u.to_string()
            } else {
                anyhow::bail!(
                    "应用 {} 的动作 `{}` 未提供可转译的 URI 参数或模板",
                    profile.name,
                    canonical
                );
            }
        }
    };

    validate_uri_safety(&constructed, &profile.uri_schemes)
}

fn render_uri_template(template: &str, params: &Value) -> anyhow::Result<String> {
    let mut out = String::with_capacity(template.len() + 32);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            out.push('{');
            rest = after_open;
            continue;
        };
        let key = &after_open[..close];
        let raw_val = params
            .get(key)
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default();

        if key == "url" || key == "uri" {
            out.push_str(&raw_val);
        } else {
            out.push_str(&urlencoding::encode(&raw_val));
        }
        rest = &after_open[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Parse a Freedesktop `.desktop` file's `[Desktop Entry]` and `[Desktop Action <id>]` sections.
pub fn parse_desktop_file_content(desktop_id: &str, content: &str) -> ParsedDesktopFile {
    let mut name = desktop_id.trim_end_matches(".desktop").to_string();
    let mut zh_name: Option<String> = None;
    let mut exec: Option<String> = None;
    let mut dbus_activatable = false;
    let mut declared_actions = Vec::new();
    let mut actions: BTreeMap<String, DesktopActionSection> = BTreeMap::new();

    #[derive(Clone)]
    enum Section {
        None,
        DesktopEntry,
        DesktopAction(String),
    }

    let mut current = Section::None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let header = &line[1..line.len() - 1].trim();
            if *header == "Desktop Entry" {
                current = Section::DesktopEntry;
            } else if let Some(act_id) = header.strip_prefix("Desktop Action ") {
                let id = act_id.trim().to_string();
                actions
                    .entry(id.clone())
                    .or_insert_with(|| DesktopActionSection {
                        action_id: id.clone(),
                        name: id.clone(),
                        localized_name: None,
                        exec: String::new(),
                        icon: None,
                    });
                current = Section::DesktopAction(id);
            } else {
                current = Section::None;
            }
            continue;
        }

        let Some(eq_idx) = line.find('=') else {
            continue;
        };
        let key = line[..eq_idx].trim();
        let val = line[eq_idx + 1..].trim();

        match &current {
            Section::DesktopEntry => match key {
                "Name" => name = val.to_string(),
                "Name[zh_CN]" | "Name[zh]" => zh_name = Some(val.to_string()),
                "Exec" => exec = Some(val.to_string()),
                "DBusActivatable" => dbus_activatable = val.eq_ignore_ascii_case("true"),
                "Actions" => {
                    declared_actions = val
                        .split(';')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                }
                _ => {}
            },
            Section::DesktopAction(act_id) => {
                if let Some(sec) = actions.get_mut(act_id) {
                    match key {
                        "Name" => sec.name = val.to_string(),
                        "Name[zh_CN]" | "Name[zh]" => sec.localized_name = Some(val.to_string()),
                        "Exec" => sec.exec = val.to_string(),
                        "Icon" => sec.icon = Some(val.to_string()),
                        _ => {}
                    }
                }
            }
            Section::None => {}
        }
    }

    if let Some(zh) = zh_name {
        name = zh;
    }
    actions.retain(|_, v| !v.exec.is_empty());

    ParsedDesktopFile {
        desktop_id: desktop_id.to_string(),
        name,
        exec,
        dbus_activatable,
        declared_actions,
        actions,
    }
}

/// Tokenized `.desktop` `Exec=` result: `(executable, discrete_args, safe_env_pairs)`.
pub type TokenizedDesktopExec = (String, Vec<String>, Vec<(String, String)>);

/// Tokenize a `.desktop` `Exec=` line into `(executable, discrete_args, safe_env_pairs)` WITHOUT invoking a shell.
/// Preserves benign vendor env overrides (such as `LIBGL_ALWAYS_SOFTWARE=1` for QQ Music) while blocking
/// dangerous loader/interpreter overrides (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PATH`, etc.).
pub fn tokenize_desktop_exec_with_env(
    exec_line: &str,
    target_arg: Option<&str>,
) -> anyhow::Result<TokenizedDesktopExec> {
    let mut raw_tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = exec_line.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                cur.push(ch);
            }
        } else if in_double {
            if ch == '"' {
                in_double = false;
            } else if ch == '\\' {
                if let Some(next_ch) = chars.next() {
                    cur.push(next_ch);
                }
            } else {
                cur.push(ch);
            }
        } else {
            match ch {
                '\'' => in_single = true,
                '"' => in_double = true,
                '\\' => {
                    if let Some(next_ch) = chars.next() {
                        cur.push(next_ch);
                    }
                }
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        raw_tokens.push(std::mem::take(&mut cur));
                    }
                }
                _ => cur.push(ch),
            }
        }
    }
    if !cur.is_empty() {
        raw_tokens.push(cur);
    }

    // Parse leading `env KEY=VAL ...` wrapper if present in Flatpak/Snap/vendor desktop files
    let mut env_pairs: Vec<(String, String)> = Vec::new();
    let mut idx = 0usize;
    if raw_tokens
        .first()
        .map(String::as_str)
        .is_some_and(|t| t == "env" || t == "/usr/bin/env")
    {
        idx += 1;
        while idx < raw_tokens.len() {
            let tok = &raw_tokens[idx];
            if tok == "--" {
                idx += 1;
                break;
            }
            if tok.starts_with('-') {
                idx += 1;
                continue;
            }
            if let Some(eq_pos) = tok.find('=') {
                let k = tok[..eq_pos].trim();
                let v = &tok[eq_pos + 1..];
                let valid_key = !k.is_empty()
                    && k.chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !BLOCKED_DESKTOP_ENV_KEYS
                        .iter()
                        .any(|b| b.eq_ignore_ascii_case(k));
                let valid_val = !v.chars().any(|c| c == '\0' || c == '\n' || c == '\r');
                if valid_key && valid_val {
                    env_pairs.push((k.to_string(), v.to_string()));
                }
                idx += 1;
            } else {
                break;
            }
        }
    }
    if idx >= raw_tokens.len() {
        anyhow::bail!("无效的 .desktop Exec 行: {}", exec_line);
    }

    let executable = raw_tokens[idx].clone();
    let exec_base = Path::new(&executable)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&executable);
    if matches!(exec_base, "sh" | "bash" | "dash" | "zsh") {
        anyhow::bail!(
            "安全拦截：拒绝执行包含 Shell 解释器的 .desktop 动作 ({})",
            executable
        );
    }

    // Preserve software rendering flag for `/opt/qqmusic/qqmusic` even when launched via system `.desktop`
    if executable.to_ascii_lowercase().contains("qqmusic")
        && !env_pairs
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("LIBGL_ALWAYS_SOFTWARE"))
    {
        env_pairs.push(("LIBGL_ALWAYS_SOFTWARE".into(), "1".into()));
    }

    let mut args = Vec::new();
    for tok in &raw_tokens[idx + 1..] {
        match tok.as_str() {
            "%u" | "%U" | "%f" | "%F" => {
                if let Some(t) = target_arg
                    && !t.trim().is_empty()
                {
                    args.push(t.trim().to_string());
                }
            }
            "@@u" | "@@f" | "@@" => {
                // Flatpak document portal markers omitted when spawning cleanly
            }
            "%i" | "%c" | "%k" | "%d" | "%D" | "%n" | "%N" | "%v" | "%m" => {
                // Deprecated or metadata field codes omitted
            }
            other => {
                let replaced = other.replace("%%", "%");
                if (replaced.contains("%u")
                    || replaced.contains("%U")
                    || replaced.contains("%f")
                    || replaced.contains("%F"))
                    && let Some(t) = target_arg
                {
                    args.push(
                        replaced
                            .replace("%u", t)
                            .replace("%U", t)
                            .replace("%f", t)
                            .replace("%F", t),
                    );
                } else if !replaced.starts_with('%') {
                    args.push(replaced);
                }
            }
        }
    }

    Ok((executable, args, env_pairs))
}

/// Tokenize a `.desktop` `Exec=` line into `(executable, discrete_args)` WITHOUT invoking a shell.
/// Handles quoting and Freedesktop `%u`/`%U`/`%f`/`%F` field codes safely.
pub fn tokenize_desktop_exec(
    exec_line: &str,
    target_arg: Option<&str>,
) -> anyhow::Result<(String, Vec<String>)> {
    let (executable, args, _) = tokenize_desktop_exec_with_env(exec_line, target_arg)?;
    Ok((executable, args))
}

/// Locate a `.desktop` file across optional test/config directories plus standard XDG, Snap, and Flatpak dirs.
pub fn find_desktop_file_on_disk_with_config(
    desktop_ids: &[String],
    config_dir: Option<&Path>,
) -> Option<(PathBuf, String)> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    let mut search_dirs = Vec::with_capacity(8);
    if let Some(cfg) = config_dir {
        search_dirs.push(cfg.join("applications"));
        if let Some(parent) = cfg.parent() {
            search_dirs.push(parent.join("applications"));
        }
    }
    search_dirs.extend([
        PathBuf::from(&home).join(".local/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/var/lib/snapd/desktop/applications"),
        PathBuf::from("/var/lib/flatpak/exports/share/applications"),
    ]);

    for id in desktop_ids {
        let filename = if id.ends_with(".desktop") {
            id.clone()
        } else {
            format!("{}.desktop", id)
        };
        for dir in &search_dirs {
            let candidate = dir.join(&filename);
            if candidate.is_file()
                && let Ok(raw) = fs::read_to_string(&candidate)
            {
                return Some((candidate, raw));
            }
        }
    }
    None
}

/// Locate a `.desktop` file across standard XDG, Snap, and Flatpak application directories.
pub fn find_desktop_file_on_disk(desktop_ids: &[String]) -> Option<(PathBuf, String)> {
    find_desktop_file_on_disk_with_config(desktop_ids, None)
}

fn builtin_fallback_desktop_action(
    profile: &AppAdapterProfile,
    canonical_action: &str,
) -> Option<(String, Vec<String>, String)> {
    match (profile.id.as_str(), canonical_action) {
        ("google-chrome", "new_private_window" | "open_incognito") => Some((
            "google-chrome".into(),
            vec!["--incognito".into()],
            "New Incognito Window".into(),
        )),
        ("google-chrome", "new_window" | "open_new_window") => Some((
            "google-chrome".into(),
            vec!["--new-window".into()],
            "New Window".into(),
        )),
        ("firefox", "new_private_window" | "open_incognito") => Some((
            "firefox".into(),
            vec!["--private-window".into()],
            "Open a New Private Window".into(),
        )),
        ("firefox", "new_window" | "open_new_window") => Some((
            "firefox".into(),
            vec!["--new-window".into()],
            "Open a New Window".into(),
        )),
        ("brave", "new_private_window" | "open_incognito") => Some((
            "brave-browser".into(),
            vec!["--incognito".into()],
            "New Incognito Window".into(),
        )),
        ("brave", "new_window" | "open_new_window") => Some((
            "brave-browser".into(),
            vec!["--new-window".into()],
            "New Window".into(),
        )),
        (
            "vscode" | "zcode" | "cursor" | "trae-cn" | "antigravity-ide" | "workbuddy",
            "new_window" | "open_new_window",
        ) => {
            let bin = profile
                .cli_executables
                .first()
                .cloned()
                .unwrap_or_else(|| "code".into());
            Some((bin, vec!["--new-window".into()], "New Empty Window".into()))
        }
        ("nautilus", "new_window") => Some((
            "nautilus".into(),
            vec!["--new-window".into()],
            "New Window".into(),
        )),
        ("dolphin", "new_window") => Some((
            "dolphin".into(),
            vec!["--new-window".into()],
            "New Window".into(),
        )),
        ("libreoffice", "new_window" | "new_document") => Some((
            "libreoffice".into(),
            vec!["--writer".into()],
            "LibreOffice Writer".into(),
        )),
        ("wps-office", "new_window" | "new_document") => {
            Some(("wps".into(), Vec::new(), "WPS 文字".into()))
        }
        ("yozo-office", "new_window" | "new_document") => {
            Some(("yozow".into(), Vec::new(), "永中文字".into()))
        }
        ("onlyoffice", "new_window" | "new_document") => Some((
            "onlyoffice-desktopeditors".into(),
            Vec::new(),
            "ONLYOFFICE".into(),
        )),
        ("mail-client", "new_window") => Some((
            "thunderbird".into(),
            vec!["-compose".into()],
            "Write New Message".into(),
        )),
        _ => None,
    }
}

/// Resolve a desktop binary across system PATH, `/snap/bin`, `/opt` vendor directories, Flatpak exports, and `~/.local/bin`.
pub fn resolve_desktop_binary(executable: &str) -> Option<PathBuf> {
    if executable.trim().is_empty() || executable.contains("..") || executable.contains('\0') {
        return None;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    if executable.starts_with('/') {
        let user_local_bin = format!("{}/.local/", home);
        let user_apps = format!("{}/Applications/", home);
        let allowed_prefixes = [
            "/usr/",
            "/bin/",
            "/sbin/",
            "/snap/",
            "/var/lib/flatpak/",
            "/opt/",
            user_local_bin.as_str(),
            user_apps.as_str(),
        ];
        if allowed_prefixes.iter().any(|p| executable.starts_with(p)) {
            let pb = PathBuf::from(executable);
            if pb.is_file() {
                return Some(pb);
            }
        }
        return None;
    }

    if let Some(pb) = resolve_trusted_executable(executable) {
        return Some(pb);
    }

    let extra_dirs = [
        PathBuf::from("/snap/bin"),
        PathBuf::from("/var/lib/flatpak/exports/bin"),
        PathBuf::from(&home).join(".local/bin"),
        PathBuf::from(&home).join("Applications"),
        PathBuf::from("/opt/drawio"),
        PathBuf::from("/opt/qqmusic"),
        PathBuf::from("/opt/SodaM"),
        PathBuf::from("/opt/BaicaiMusic"),
        PathBuf::from("/opt/FlClash"),
        PathBuf::from("/opt/wemeet"),
        PathBuf::from("/opt/bytedance/feishu"),
        PathBuf::from("/opt/QQ"),
        PathBuf::from("/opt/baidunetdisk"),
        PathBuf::from("/opt/Trae CN"),
        PathBuf::from("/opt/WorkBuddy"),
        PathBuf::from("/opt/OmniMouseStudio"),
        PathBuf::from("/opt/hopper/bin"),
        PathBuf::from("/opt/google/chrome"),
        PathBuf::from("/opt/brave.com/brave"),
    ];
    for dir in &extra_dirs {
        let candidate = dir.join(executable);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Build and dispatch a URI deep-link (`vscode://`, `obsidian://`, `mailto:`, `tg://`, `https://`).
pub fn execute_uri_deeplink(
    core: &IntentOsCore,
    profile: &AppAdapterProfile,
    semantic_action: &SemanticAppAction,
    params: &Value,
) -> anyhow::Result<UriDesktopDispatchResult> {
    let uri = build_uri_deeplink(Some(core), profile, semantic_action, params)?;
    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let translated_command = format!("gio open {}", uri);

    if !force_dry_run && has_gui_session() {
        let opener = resolve_trusted_executable("gio")
            .map(|b| (b, vec!["open".to_string(), uri.clone()]))
            .or_else(|| resolve_trusted_executable("xdg-open").map(|b| (b, vec![uri.clone()])));

        if let Some((bin, args)) = opener {
            let mut cmd = Command::new(&bin);
            apply_clean_desktop_env_std(&mut cmd);
            if cmd.args(&args).spawn().is_ok() {
                return Ok(UriDesktopDispatchResult {
                    ok: true,
                    channel_used: AdaptationChannel::UriScheme,
                    translated_command,
                    summary: format!(
                        "已通过 URI Deep-Link 协议请求唤起「{}」: `{}`",
                        profile.name, uri
                    ),
                    data: json!({
                        "uri": uri,
                        "action": semantic_action.action,
                    }),
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "gio_open_uri".into(),
                        checks: vec![
                            "uri_scheme_whitelisted".into(),
                            "dangerous_schemes_blocked".into(),
                        ],
                        details: Some("桌面 URI 协议请求已发出".into()),
                    },
                });
            }
        }
    }

    Ok(UriDesktopDispatchResult {
        ok: true,
        channel_used: AdaptationChannel::UriScheme,
        translated_command,
        summary: format!(
            "已将「{}」动作转译为安全 URI 深度链接 `{}`（无头环境预演）",
            profile.name, uri
        ),
        data: json!({
            "uri": uri,
            "action": semantic_action.action,
        }),
        simulated: true,
        verification: VerificationReport {
            state: VerificationState::RequestedUnverified,
            method: "simulated_headless_uri".into(),
            checks: vec![
                "uri_scheme_whitelisted".into(),
                "dangerous_schemes_blocked".into(),
            ],
            details: Some("无活跃桌面会话，已完成安全 URI 编码与协议校验".into()),
        },
    })
}

/// Parse `.desktop` `[Desktop Action ...]` (or built-in fallback) and dispatch safely without a shell.
pub fn execute_desktop_action(
    core: &IntentOsCore,
    profile: &AppAdapterProfile,
    semantic_action: &SemanticAppAction,
    params: &Value,
) -> anyhow::Result<UriDesktopDispatchResult> {
    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Optional URL or file argument passed alongside a desktop action (e.g. open URL in private window)
    let optional_target = if let Some(u) = params.get("url").and_then(|v| v.as_str()) {
        Some(validate_uri_safety(u, &profile.uri_schemes)?)
    } else if let Some(p) = params.get("path").and_then(|v| v.as_str()) {
        if core.fs_engine.is_forbidden(Path::new(p)) {
            anyhow::bail!("安全内核拦截：禁止向 .desktop 动作传入敏感路径 {}", p);
        }
        Some(p.to_string())
    } else {
        None
    };

    let requested_action_id = params
        .get("desktop_action")
        .or_else(|| params.get("action_id"))
        .and_then(|v| v.as_str())
        .or(semantic_action.target_template.as_deref())
        .unwrap_or(&semantic_action.action);

    type MatchedDesktopExec = (String, Vec<String>, Vec<(String, String)>, String, String);
    let mut matched_exec: Option<MatchedDesktopExec> = None;

    if let Some((path, raw)) =
        find_desktop_file_on_disk_with_config(&profile.desktop_ids, Some(&core.paths.config_dir))
    {
        let desktop_id = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("app.desktop");
        let parsed = parse_desktop_file_content(desktop_id, &raw);
        let found_sec = parsed.actions.get(requested_action_id).or_else(|| {
            let req_lc = requested_action_id.to_ascii_lowercase();
            parsed.actions.values().find(|sec| {
                sec.action_id.to_ascii_lowercase().contains(&req_lc)
                    || (matches!(
                        semantic_action.action.as_str(),
                        "new_private_window" | "open_incognito"
                    ) && (sec.action_id.to_ascii_lowercase().contains("private")
                        || sec.action_id.to_ascii_lowercase().contains("incognito")))
                    || (matches!(
                        semantic_action.action.as_str(),
                        "new_window" | "open_new_window"
                    ) && sec.action_id.to_ascii_lowercase().contains("window")
                        && !sec.action_id.to_ascii_lowercase().contains("private")
                        && !sec.action_id.to_ascii_lowercase().contains("incognito"))
            })
        });

        if let Some(sec) = found_sec {
            let (bin, mut args, env_pairs) =
                tokenize_desktop_exec_with_env(&sec.exec, optional_target.as_deref())?;
            if let Some(ref extra) = optional_target
                && !args.contains(extra)
            {
                args.push(extra.clone());
            }
            let label = sec
                .localized_name
                .clone()
                .unwrap_or_else(|| sec.name.clone());
            matched_exec = Some((
                bin,
                args,
                env_pairs,
                label,
                format!("desktop_file:{}", desktop_id),
            ));
        }
    }

    if matched_exec.is_none()
        && let Some((bin, mut args, label)) =
            builtin_fallback_desktop_action(profile, &semantic_action.action)
    {
        if let Some(ref extra) = optional_target {
            args.push(extra.clone());
        }
        let mut env_pairs = Vec::new();
        if bin.to_ascii_lowercase().contains("qqmusic") {
            env_pairs.push(("LIBGL_ALWAYS_SOFTWARE".into(), "1".into()));
        }
        matched_exec = Some((
            bin,
            args,
            env_pairs,
            label,
            "builtin_desktop_action_spec".into(),
        ));
    }

    let Some((bin, args, env_pairs, action_label, source_tag)) = matched_exec else {
        anyhow::bail!(
            "未能在「{}」的 .desktop 描述中找到匹配的桌面动作 `{}`",
            profile.name,
            requested_action_id
        );
    };

    let env_prefix = if env_pairs.is_empty() {
        String::new()
    } else {
        let joined: Vec<String> = env_pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        format!("env {} ", joined.join(" "))
    };
    let translated_command = if args.is_empty() {
        format!("{}{}", env_prefix, bin)
    } else {
        format!("{}{} {}", env_prefix, bin, args.join(" "))
    };
    let env_json: BTreeMap<String, String> = env_pairs.iter().cloned().collect();

    if !force_dry_run
        && has_gui_session()
        && let Some(resolved_bin) = resolve_desktop_binary(&bin)
    {
        let mut cmd = Command::new(&resolved_bin);
        apply_clean_desktop_env_std(&mut cmd);
        for (k, v) in &env_pairs {
            cmd.env(k, v);
        }
        if cmd.args(&args).spawn().is_ok() {
            return Ok(UriDesktopDispatchResult {
                ok: true,
                channel_used: AdaptationChannel::DesktopAction,
                translated_command,
                summary: format!(
                    "已触发「{}」的桌面快捷动作「{}」",
                    profile.name, action_label
                ),
                data: json!({
                    "desktop_action": requested_action_id,
                    "action_label": action_label,
                    "executable": resolved_bin,
                    "args": args,
                    "env": env_json,
                    "source": source_tag,
                }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "desktop_action_spawn".into(),
                    checks: vec!["desktop_action_parsed".into(), "non_shell_argv".into()],
                    details: Some("桌面应用快捷动作已发出（异步启动）".into()),
                },
            });
        }
    }

    Ok(UriDesktopDispatchResult {
        ok: true,
        channel_used: AdaptationChannel::DesktopAction,
        translated_command,
        summary: format!(
            "已解析「{}」的 `.desktop` 快捷动作「{}」（无头环境安全预演）",
            profile.name, action_label
        ),
        data: json!({
            "desktop_action": requested_action_id,
            "action_label": action_label,
            "executable": bin,
            "args": args,
            "env": env_json,
            "source": source_tag,
        }),
        simulated: true,
        verification: VerificationReport {
            state: VerificationState::RequestedUnverified,
            method: "simulated_headless_desktop_action".into(),
            checks: vec!["desktop_action_parsed".into(), "non_shell_argv".into()],
            details: Some("无活跃桌面会话或目标二进制未安装，返回解析后的非 Shell 参数".into()),
        },
    })
}
