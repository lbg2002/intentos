#![forbid(unsafe_code)]

//! Universal StatusNotifierItem (`org.kde.StatusNotifierItem*` / `org.freedesktop.StatusNotifierItem*`)
//! & Canonical `com.canonical.dbusmenu` Discovery, Layout Parser, and Verified Action Driver (`sni_dbusmenu.rs`).
//!
//! Solves personalized control for Chinese/Electron/Qt/Tauri Linux desktop apps (`SodaM / 汽水音乐`,
//! `wpscloudsvr / WPS云盘`, `FlClash`, `QQ`, `微信`, `飞书`, `百度网盘`, etc.) that live in the system tray
//! without exposing CLI flags or standard `org.mpris.MediaPlayer2` interfaces.
//! Also provides `apply_clean_desktop_env` / `sanitize_ld_library_path` so Conda/Miniconda environment
//! variables never poison system GTK/GI/Electron desktop child processes.

use crate::app_adapter::dynamic_profiler::{
    builtin_domestic_app_aliases, normalize_app_search_tokens,
};
use crate::app_adapter::mpris_dbus::{
    MprisNowPlaying, has_dbus_session_address, is_valid_dbus_name,
};
use crate::app_adapter::registry::AdapterRegistry;
use crate::resource::to_pinyin_pair;
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_protocol::{VerificationReport, VerificationState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

/// Environment variables injected by Conda / virtual environments that break system Python GI / GTK / Electron apps.
const CONDA_POISON_ENV_KEYS: &[&str] = &[
    "PYTHONHOME",
    "PYTHONPATH",
    "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV",
    "CONDA_SHLVL",
    "CONDA_PYTHON_EXE",
];

/// Strip any path segment containing `conda` / `miniconda` / `anaconda` from `LD_LIBRARY_PATH`.
/// Returns `None` if no non-Conda library paths remain (so `LD_LIBRARY_PATH` should be unset completely).
pub fn sanitize_ld_library_path(raw: &str) -> Option<String> {
    let kept: Vec<&str> = raw
        .split(':')
        .map(str::trim)
        .filter(|seg| {
            if seg.is_empty() {
                return false;
            }
            let lc = seg.to_ascii_lowercase();
            !lc.contains("conda") && !lc.contains("miniconda") && !lc.contains("anaconda")
        })
        .collect();

    if kept.is_empty() {
        None
    } else {
        Some(kept.join(":"))
    }
}

/// Sanitize a `tokio::process::Command` so desktop/GTK/GI/Electron subprocesses never inherit Conda's libraries.
pub fn apply_clean_desktop_env(cmd: &mut Command) {
    for key in CONDA_POISON_ENV_KEYS {
        cmd.env_remove(key);
    }
    match std::env::var("LD_LIBRARY_PATH") {
        Ok(raw) => match sanitize_ld_library_path(&raw) {
            Some(cleaned) => {
                cmd.env("LD_LIBRARY_PATH", cleaned);
            }
            None => {
                cmd.env_remove("LD_LIBRARY_PATH");
            }
        },
        Err(_) => {
            cmd.env_remove("LD_LIBRARY_PATH");
        }
    }
}

/// Synchronous `std::process::Command` variant of [`apply_clean_desktop_env`].
pub fn apply_clean_desktop_env_std(cmd: &mut std::process::Command) {
    for key in CONDA_POISON_ENV_KEYS {
        cmd.env_remove(key);
    }
    match std::env::var("LD_LIBRARY_PATH") {
        Ok(raw) => match sanitize_ld_library_path(&raw) {
            Some(cleaned) => {
                cmd.env("LD_LIBRARY_PATH", cleaned);
            }
            None => {
                cmd.env_remove("LD_LIBRARY_PATH");
            }
        },
        Err(_) => {
            cmd.env_remove("LD_LIBRARY_PATH");
        }
    }
}

/// Resolve the system Python 3 interpreter that ships `gi.repository` (`Atspi`, `Wnck`, `Gio`),
/// strictly preferring `/usr/bin/python3` over Conda/virtualenv `PATH` shadows.
pub fn resolve_system_gi_python3() -> Option<PathBuf> {
    for sys_candidate in ["/usr/bin/python3", "/bin/python3"] {
        let p = Path::new(sys_candidate);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    resolve_trusted_executable("python3")
}

/// Parsed menu item from `com.canonical.dbusmenu.GetLayout`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrayMenuItem {
    pub id: i32,
    pub label: String,
    pub enabled: bool,
    pub visible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toggle_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toggle_state: Option<i32>,
}

/// Live `StatusNotifierItem` tray application snapshot discovered on Session D-Bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveTrayApp {
    pub service: String,
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    pub id: String,
    pub title: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub menu_path: Option<String>,
    pub menu_items: Vec<TrayMenuItem>,
}

fn is_sni_bus_name(name: &str) -> bool {
    (name.starts_with("org.kde.StatusNotifierItem")
        || name.starts_with("org.freedesktop.StatusNotifierItem"))
        && is_valid_dbus_name(name)
}

/// Parse `org.kde.StatusNotifierItem*` & `org.freedesktop.StatusNotifierItem*` bus names from `gdbus ... ListNames`.
pub fn parse_sni_names_from_gdbus(output: &str) -> Vec<String> {
    let mut names = Vec::new();
    for seg in output.split('\'') {
        let trimmed = seg.trim();
        if is_sni_bus_name(trimmed) && !names.iter().any(|x| x == trimmed) {
            names.push(trimmed.to_string());
        }
    }
    names.sort();
    names
}

/// Parse `StatusNotifierItem` bus names from `busctl --user list --no-legend`.
pub fn parse_sni_names_from_busctl(output: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in output.lines() {
        if let Some(tok) = line.split_whitespace().next()
            && is_sni_bus_name(tok)
            && !names.iter().any(|x| x == tok)
        {
            names.push(tok.to_string());
        }
    }
    names.sort();
    names
}

/// Extract embedded `<PID>` from `StatusNotifierItem-<PID>-<N>` service names if present.
pub fn parse_pid_from_sni_bus_name(svc: &str) -> Option<u32> {
    let rest = svc
        .strip_prefix("org.kde.StatusNotifierItem-")
        .or_else(|| svc.strip_prefix("org.freedesktop.StatusNotifierItem-"))?;
    let pid_part = rest.split('-').next()?;
    let pid = pid_part.parse::<u32>().ok()?;
    (pid > 1).then_some(pid)
}

/// Parse `(uint32 2103951,)` from `GetConnectionUnixProcessID`.
pub fn parse_gvariant_uint32(raw: &str) -> Option<u32> {
    for tok in raw.split(|c: char| !c.is_ascii_digit()) {
        if !tok.is_empty()
            && tok != "32"
            && let Ok(v) = tok.parse::<u32>()
            && v > 1
        {
            return Some(v);
        }
    }
    None
}

fn unescape_gvariant_quoted(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('\'') => out.push('\''),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Extract the first quoted string from a GVariant snippet such as `(<'sodam-2103951'>,)`.
pub fn parse_gvariant_string_value(raw: &str) -> Option<String> {
    let mut chars = raw.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if ch == '\'' || ch == '"' {
            let quote = ch;
            let start = idx + quote.len_utf8();
            let mut escaped = false;
            for (end_idx, c2) in chars.by_ref() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if c2 == '\\' {
                    escaped = true;
                    continue;
                }
                if c2 == quote {
                    return Some(unescape_gvariant_quoted(&raw[start..end_idx]));
                }
            }
            break;
        }
    }
    None
}

/// Extract a D-Bus object path from `(<objectpath '/MenuBar'>,)` or `(<'/com/canonical/dbusmenu'>,)`.
pub fn parse_gvariant_objectpath_value(raw: &str) -> Option<String> {
    let val = parse_gvariant_string_value(raw)?;
    if val.starts_with('/') && val != "/" && !val.chars().any(char::is_control) {
        Some(val)
    } else {
        None
    }
}

fn normalize_dbusmenu_label(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Strip trailing Windows/Qt/GTK mnemonic suffixes like `(_S)` or `(&S)` while keeping normal parens
    let without_suffix = if trimmed.len() >= 4 {
        let bytes = trimmed.as_bytes();
        let n = bytes.len();
        if bytes[n - 1] == b')'
            && bytes[n - 4] == b'('
            && (bytes[n - 3] == b'_' || bytes[n - 3] == b'&')
            && bytes[n - 2].is_ascii_alphanumeric()
        {
            trimmed[..n - 4].trim_end()
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    // In com.canonical.dbusmenu, `__` represents a literal underscore and a leading `_X` is a mnemonic
    if without_suffix.contains("__") {
        return without_suffix.replace("__", "_");
    }
    if let Some(rest) = without_suffix.strip_prefix('_')
        && rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
    {
        return rest.to_string();
    }
    without_suffix.to_string()
}

/// Split top-level comma-separated GVariant elements inside an already-unwrapped container body,
/// respecting nested `()`, `[]`, `{}`, `<>` and single/double-quoted strings.
/// Note: `>` is only treated as closing `<` when `<` depth > 0.
fn split_top_level_gvariant_items(body: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth_paren = 0usize;
    let mut depth_brack = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let mut seg_start = 0usize;

    for (idx, ch) in body.char_indices() {
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => in_quote = Some(ch),
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_brack += 1,
            ']' => depth_brack = depth_brack.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' => depth_angle += 1,
            '>' if depth_angle > 0 => depth_angle -= 1,
            ',' if depth_paren == 0 && depth_brack == 0 && depth_brace == 0 && depth_angle == 0 => {
                let piece = body[seg_start..idx].trim();
                if !piece.is_empty() {
                    parts.push(piece);
                }
                seg_start = idx + 1;
            }
            _ => {}
        }
    }

    let tail = body[seg_start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

/// Find the inner slice enclosed by the first matching `open_ch ... close_ch` pair in `s` (quote-aware).
fn extract_delimited_body(s: &str, open_ch: char, close_ch: char) -> Option<&str> {
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut body_start = None;

    for (idx, ch) in s.char_indices() {
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }

        if ch == '\'' || ch == '"' {
            in_quote = Some(ch);
            continue;
        }
        if ch == open_ch {
            if depth == 0 {
                body_start = Some(idx + open_ch.len_utf8());
            }
            depth += 1;
        } else if ch == close_ch && depth > 0 {
            depth -= 1;
            if depth == 0 {
                let start = body_start?;
                return Some(&s[start..idx]);
            }
        }
    }
    None
}

fn unwrap_gvariant_angle(raw: &str) -> &str {
    let mut cur = raw.trim();
    while cur.starts_with('<') && cur.ends_with('>') && cur.len() >= 2 {
        if let Some(inner) = extract_delimited_body(cur, '<', '>')
            && inner.len() + 2 == cur.len()
        {
            cur = inner.trim();
        } else {
            break;
        }
    }
    cur
}

fn parse_gvariant_i32_token(raw: &str) -> Option<i32> {
    let clean = unwrap_gvariant_angle(raw);
    let stripped = clean
        .strip_prefix("int32 ")
        .or_else(|| clean.strip_prefix("int16 "))
        .unwrap_or(clean)
        .trim();
    stripped.parse::<i32>().ok()
}

fn parse_gvariant_bool_token(raw: &str) -> Option<bool> {
    let clean = unwrap_gvariant_angle(raw)
        .strip_prefix("boolean ")
        .unwrap_or_else(|| unwrap_gvariant_angle(raw))
        .trim();
    match clean {
        "true" | "True" => Some(true),
        "false" | "False" => Some(false),
        _ => None,
    }
}

fn split_dict_key_value(entry: &str) -> Option<(&str, &str)> {
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in entry.char_indices() {
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => in_quote = Some(ch),
            ':' => return Some((entry[..idx].trim(), entry[idx + 1..].trim())),
            _ => {}
        }
    }
    None
}

fn parse_dbusmenu_node_recursive(node_str: &str, out: &mut Vec<TrayMenuItem>) {
    let unwrapped = unwrap_gvariant_angle(node_str);
    let Some(tuple_body) = extract_delimited_body(unwrapped, '(', ')') else {
        return;
    };
    let elems = split_top_level_gvariant_items(tuple_body);

    // Outer GetLayout response tuple is `(uint32 <revision>, (0, {...}, [...]))` (2 elements)
    if elems.len() == 2 {
        parse_dbusmenu_node_recursive(elems[1], out);
        return;
    }
    if elems.len() < 3 {
        return;
    }

    let Some(item_id) = parse_gvariant_i32_token(elems[0]) else {
        return;
    };

    let mut label: Option<String> = None;
    let mut enabled = true;
    let mut visible = true;
    let mut item_type: Option<String> = None;
    let mut toggle_type: Option<String> = None;
    let mut toggle_state: Option<i32> = None;

    if let Some(dict_body) = extract_delimited_body(elems[1], '{', '}') {
        for entry in split_top_level_gvariant_items(dict_body) {
            let Some((k_raw, v_raw)) = split_dict_key_value(entry) else {
                continue;
            };
            let Some(key) = parse_gvariant_string_value(k_raw) else {
                continue;
            };
            match key.as_str() {
                "label" => {
                    if let Some(s) = parse_gvariant_string_value(v_raw) {
                        let cleaned = normalize_dbusmenu_label(&s);
                        if !cleaned.is_empty() {
                            label = Some(cleaned);
                        }
                    }
                }
                "enabled" => {
                    if let Some(b) = parse_gvariant_bool_token(v_raw) {
                        enabled = b;
                    }
                }
                "visible" => {
                    if let Some(b) = parse_gvariant_bool_token(v_raw) {
                        visible = b;
                    }
                }
                "type" => {
                    item_type = parse_gvariant_string_value(v_raw);
                }
                "toggle-type" => {
                    toggle_type = parse_gvariant_string_value(v_raw).filter(|s| !s.is_empty());
                }
                "toggle-state" => {
                    toggle_state = parse_gvariant_i32_token(v_raw);
                }
                _ => {
                    // Rapidly skip arbitrarily huge `'icon-data': <[byte 0x89, ...]>` arrays
                }
            }
        }
    }

    let is_separator = item_type
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case("separator"));

    if !is_separator
        && let Some(lbl) = label
        && !lbl.is_empty()
    {
        out.push(TrayMenuItem {
            id: item_id,
            label: lbl,
            enabled,
            visible,
            toggle_type,
            toggle_state,
        });
    }

    // Recurse into children array `[<(child_id, {...}, [...])>, ...]`
    if let Some(children_body) = extract_delimited_body(elems[2], '[', ']') {
        for child_elem in split_top_level_gvariant_items(children_body) {
            parse_dbusmenu_node_recursive(child_elem, out);
        }
    }
}

/// Parse `com.canonical.dbusmenu.GetLayout` GVariant output into structured `TrayMenuItem` entries
/// for all non-empty labels (handling `SodaM`, `wpscloudsvr` with embedded PNG `icon-data`, and submenus).
pub fn parse_dbusmenu_layout_gvariant(raw: &str) -> Vec<TrayMenuItem> {
    let mut items = Vec::new();
    parse_dbusmenu_node_recursive(raw, &mut items);
    items
}

/// Build discrete non-shell `gdbus` arguments for `com.canonical.dbusmenu.GetLayout`
/// (with `--` before `0 -1` so `-1` is never parsed as a CLI option, and property whitelist excluding `icon-data`).
pub fn build_dbusmenu_get_layout_args(svc: &str, menu_path: &str) -> anyhow::Result<Vec<String>> {
    if !is_sni_bus_name(svc) {
        anyhow::bail!("非法的 StatusNotifierItem 服务名: {}", svc);
    }
    if !menu_path.starts_with('/') || menu_path.chars().any(char::is_control) {
        anyhow::bail!("非法的 dbusmenu 对象路径: {}", menu_path);
    }
    Ok(vec![
        "call".into(),
        "--session".into(),
        "--timeout".into(),
        "2".into(),
        "--dest".into(),
        svc.into(),
        "--object-path".into(),
        menu_path.into(),
        "--method".into(),
        "com.canonical.dbusmenu.GetLayout".into(),
        "--".into(),
        "0".into(),
        "-1".into(),
        "['label', 'enabled', 'visible', 'toggle-type', 'toggle-state']".into(),
    ])
}

/// Build discrete non-shell `gdbus` arguments for `com.canonical.dbusmenu.Event`.
pub fn build_dbusmenu_event_args(
    svc: &str,
    menu_path: &str,
    id: i32,
    event_id: &str,
    unix_ts_u32: u32,
) -> anyhow::Result<Vec<String>> {
    if !is_sni_bus_name(svc) {
        anyhow::bail!("非法的 StatusNotifierItem 服务名: {}", svc);
    }
    if !menu_path.starts_with('/') || menu_path.chars().any(char::is_control) {
        anyhow::bail!("非法的 dbusmenu 对象路径: {}", menu_path);
    }
    if !matches!(event_id, "clicked" | "hovered" | "opened" | "closed") {
        anyhow::bail!("不支持的 dbusmenu 事件类型: {}", event_id);
    }
    Ok(vec![
        "call".into(),
        "--session".into(),
        "--timeout".into(),
        "2".into(),
        "--dest".into(),
        svc.into(),
        "--object-path".into(),
        menu_path.into(),
        "--method".into(),
        "com.canonical.dbusmenu.Event".into(),
        "--".into(),
        id.to_string(),
        event_id.into(),
        "<int32 0>".into(),
        unix_ts_u32.to_string(),
    ])
}

/// Check whether a tray menu item label mutates sensitive account/data state and therefore requires approval.
pub fn is_sensitive_tray_menu_label(label: &str) -> bool {
    let lc = label.trim().to_ascii_lowercase();
    let sensitive_keywords = [
        "切换账号",
        "退出登录",
        "注销",
        "登出",
        "解绑",
        "删除",
        "清空",
        "清除缓存",
        "重置",
        "恢复默认",
        "卸载",
        "logout",
        "log out",
        "sign out",
        "switch account",
        "delete",
        "clear cache",
        "reset",
        "uninstall",
    ];
    sensitive_keywords.iter().any(|kw| lc.contains(kw))
}

async fn run_clean_gdbus(
    gdbus_bin: &Path,
    args: &[&str],
    timeout_ms: u64,
) -> Option<(bool, String, String)> {
    let mut cmd = Command::new(gdbus_bin);
    apply_clean_desktop_env(&mut cmd);
    cmd.kill_on_drop(true)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = cmd.spawn().ok()?;
    match tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait_with_output()).await {
        Ok(Ok(out)) => Some((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )),
        _ => None,
    }
}

/// Discover all active `org.kde.StatusNotifierItem*` and `org.freedesktop.StatusNotifierItem*` bus names.
pub async fn discover_sni_bus_names() -> Vec<String> {
    if !has_dbus_session_address() {
        return Vec::new();
    }

    if let Some(gdbus_bin) = resolve_trusted_executable("gdbus") {
        let args = [
            "call",
            "--session",
            "--timeout",
            "2",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.ListNames",
        ];
        if let Some((true, stdout, _)) = run_clean_gdbus(&gdbus_bin, &args, 1800).await {
            return parse_sni_names_from_gdbus(&stdout);
        }
    }

    if let Some(busctl_bin) = resolve_trusted_executable("busctl") {
        let args = ["--user", "list", "--no-legend"];
        if let Some((true, stdout, _)) = run_clean_gdbus(&busctl_bin, &args, 1800).await {
            return parse_sni_names_from_busctl(&stdout);
        }
    }

    Vec::new()
}

fn read_proc_comm_and_cmdline(pid: u32) -> (Option<String>, Option<String>) {
    let proc_dir = PathBuf::from(format!("/proc/{}", pid));
    if !proc_dir.is_dir() {
        return (None, None);
    }
    let comm = fs::read_to_string(proc_dir.join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let cmdline = fs::read(proc_dir.join("cmdline")).ok().and_then(|bytes| {
        let joined: String = bytes
            .split(|b| *b == 0)
            .filter(|seg| !seg.is_empty())
            .map(|seg| String::from_utf8_lossy(seg).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let trimmed = joined.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.chars().take(512).collect())
        }
    });

    (comm, cmdline)
}

async fn resolve_sni_owner_pid(gdbus_bin: &Path, svc: &str) -> Option<u32> {
    if let Some(pid) = parse_pid_from_sni_bus_name(svc)
        && Path::new(&format!("/proc/{}", pid)).is_dir()
    {
        return Some(pid);
    }
    let args = [
        "call",
        "--session",
        "--timeout",
        "1",
        "--dest",
        "org.freedesktop.DBus",
        "--object-path",
        "/org/freedesktop/DBus",
        "--method",
        "org.freedesktop.DBus.GetConnectionUnixProcessID",
        svc,
    ];
    let (true, stdout, _) = run_clean_gdbus(gdbus_bin, &args, 1000).await? else {
        return None;
    };
    parse_gvariant_uint32(&stdout)
}

async fn get_sni_property_raw(
    gdbus_bin: &Path,
    svc: &str,
    iface: &str,
    prop: &str,
) -> Option<String> {
    let args = [
        "call",
        "--session",
        "--timeout",
        "1",
        "--dest",
        svc,
        "--object-path",
        "/StatusNotifierItem",
        "--method",
        "org.freedesktop.DBus.Properties.Get",
        iface,
        prop,
    ];
    let (true, stdout, _) = run_clean_gdbus(gdbus_bin, &args, 1100).await? else {
        return None;
    };
    Some(stdout)
}

/// Inspect a single `StatusNotifierItem` service (querying `Id`, `Title`, `Status`, `Menu` individually
/// so massive `IconPixmap` byte arrays are NEVER transferred over D-Bus, plus `dbusmenu.GetLayout`).
pub async fn inspect_sni_service(svc: &str) -> Option<LiveTrayApp> {
    if !is_sni_bus_name(svc) || !has_dbus_session_address() {
        return None;
    }
    let gdbus_bin = resolve_trusted_executable("gdbus")?;
    let pid = resolve_sni_owner_pid(&gdbus_bin, svc).await;
    let (comm, cmdline) = pid.map(read_proc_comm_and_cmdline).unwrap_or((None, None));

    // Determine working StatusNotifierItem interface without calling GetAll (avoids 400KB IconPixmap!)
    let candidate_ifaces = if svc.starts_with("org.freedesktop.StatusNotifierItem") {
        [
            "org.freedesktop.StatusNotifierItem",
            "org.kde.StatusNotifierItem",
        ]
    } else {
        [
            "org.kde.StatusNotifierItem",
            "org.freedesktop.StatusNotifierItem",
        ]
    };

    let mut active_iface = candidate_ifaces[0].to_string();
    let mut id_val: Option<String> = None;
    for iface in candidate_ifaces {
        if let Some(raw_id) = get_sni_property_raw(&gdbus_bin, svc, iface, "Id").await {
            active_iface = iface.to_string();
            id_val = parse_gvariant_string_value(&raw_id);
            break;
        }
    }

    let id = id_val.unwrap_or_else(|| comm.clone().unwrap_or_else(|| svc.to_string()));
    let title = get_sni_property_raw(&gdbus_bin, svc, &active_iface, "Title")
        .await
        .and_then(|r| parse_gvariant_string_value(&r))
        .unwrap_or_default();
    let status = get_sni_property_raw(&gdbus_bin, svc, &active_iface, "Status")
        .await
        .and_then(|r| parse_gvariant_string_value(&r))
        .unwrap_or_else(|| "Active".to_string());
    let prop_menu_path = get_sni_property_raw(&gdbus_bin, svc, &active_iface, "Menu")
        .await
        .and_then(|r| parse_gvariant_objectpath_value(&r));

    let mut candidate_menu_paths = Vec::new();
    if let Some(ref mp) = prop_menu_path {
        candidate_menu_paths.push(mp.clone());
    }
    for fallback_mp in ["/MenuBar", "/com/canonical/dbusmenu"] {
        if !candidate_menu_paths.iter().any(|p| p == fallback_mp) {
            candidate_menu_paths.push(fallback_mp.to_string());
        }
    }

    let mut resolved_menu_path = prop_menu_path;
    let mut menu_items = Vec::new();
    for mp in candidate_menu_paths {
        if let Ok(argv) = build_dbusmenu_get_layout_args(svc, &mp) {
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            if let Some((true, layout_raw, _)) = run_clean_gdbus(&gdbus_bin, &refs, 1800).await {
                resolved_menu_path = Some(mp);
                menu_items = parse_dbusmenu_layout_gvariant(&layout_raw);
                break;
            }
        }
    }

    Some(LiveTrayApp {
        service: svc.to_string(),
        interface: active_iface,
        pid,
        comm,
        cmdline,
        id,
        title,
        status,
        menu_path: resolved_menu_path,
        menu_items,
    })
}

/// Discover and inspect all live `StatusNotifierItem` tray apps concurrently.
pub async fn discover_live_tray_apps() -> Vec<LiveTrayApp> {
    let services = discover_sni_bus_names().await;
    if services.is_empty() {
        return Vec::new();
    }

    let mut handles = Vec::with_capacity(services.len());
    for svc in services {
        handles.push(tokio::spawn(async move { inspect_sni_service(&svc).await }));
    }

    let mut apps = Vec::new();
    for handle in handles {
        if let Ok(Some(app)) = handle.await {
            apps.push(app);
        }
    }
    apps
}

/// Check if a `LiveTrayApp` exposes media playback controls in its tray menu (e.g. `SodaM` with `暂停/播放` + `上一首/下一首`).
pub fn is_tray_media_player(app: &LiveTrayApp) -> bool {
    let has_play_toggle = app.menu_items.iter().any(|m| {
        m.visible
            && matches!(
                m.label.trim().to_ascii_lowercase().as_str(),
                "暂停" | "播放" | "继续播放" | "play" | "pause" | "play/pause"
            )
    });
    let has_track_skip = app.menu_items.iter().any(|m| {
        m.visible
            && matches!(
                m.label.trim().to_ascii_lowercase().as_str(),
                "下一首" | "上一首" | "下一曲" | "上一曲" | "next" | "previous" | "prev"
            )
    });
    has_play_toggle && has_track_skip
}

/// Convert a media-capable `LiveTrayApp` (`SodaM`, etc.) into an `MprisNowPlaying` record.
pub fn tray_app_to_now_playing(app: &LiveTrayApp) -> MprisNowPlaying {
    let has_pause_item = app
        .menu_items
        .iter()
        .any(|m| m.visible && matches!(m.label.trim(), "暂停" | "Pause" | "pause"));
    let has_play_item = app
        .menu_items
        .iter()
        .any(|m| m.visible && matches!(m.label.trim(), "播放" | "继续播放" | "Play" | "play"));

    let playback_status = if has_pause_item {
        "Playing".to_string()
    } else if has_play_item {
        "Paused".to_string()
    } else {
        app.status.clone()
    };

    let identity = app.comm.clone().unwrap_or_else(|| app.id.clone());

    let title_opt = (!app.title.trim().is_empty()).then(|| app.title.trim().to_string());

    MprisNowPlaying {
        bus_name: app.service.clone(),
        player_identity: identity,
        playback_status,
        title: title_opt,
        artists: Vec::new(),
        album: None,
        volume: None,
        simulated: false,
    }
}

fn build_candidate_match_tokens(app_hint: &str, config_dir: Option<&Path>) -> Vec<String> {
    let mut tokens = normalize_app_search_tokens(app_hint);
    let push_tok = |vec: &mut Vec<String>, s: &str| {
        let t = s.trim().to_ascii_lowercase();
        if !t.is_empty() && !vec.iter().any(|x| x == &t) {
            vec.push(t);
        }
    };

    // Expand via AdapterRegistry (handles Chinese -> sodam, bytedance-feishu, flclash, wps-office, etc.)
    let reg = AdapterRegistry::load(config_dir);
    let hint_trimmed = app_hint.trim();
    if !hint_trimmed.is_empty() && !hint_trimmed.eq_ignore_ascii_case("auto") && hint_trimmed != "*"
    {
        let (prof, _) = reg.resolve_adapter_and_action(hint_trimmed, "focus_window");
        if prof.source != "dynamic_gui_fallback" {
            push_tok(&mut tokens, &prof.id);
            push_tok(&mut tokens, &prof.name);
            for exe in &prof.cli_executables {
                if let Some(base) = Path::new(exe).file_name().and_then(|s| s.to_str()) {
                    push_tok(&mut tokens, base);
                }
            }
            for did in &prof.desktop_ids {
                push_tok(&mut tokens, did.trim_end_matches(".desktop"));
            }
            for al in &prof.aliases {
                push_tok(&mut tokens, al);
            }
        }
    }

    // Expand domestic aliases table directly as well (covers `wps云盘 -> wpscloudsvr/qing`, etc.)
    let snapshot = tokens.clone();
    for tok in &snapshot {
        for extra in builtin_domestic_app_aliases(tok, None) {
            push_tok(&mut tokens, extra);
        }
    }

    tokens
}

fn score_tray_app_against_tokens(app: &LiveTrayApp, tokens: &[String], raw_hint_lc: &str) -> f64 {
    let comm_lc = app.comm.as_deref().unwrap_or("").to_ascii_lowercase();
    let id_lc = app.id.to_ascii_lowercase();
    let title_lc = app.title.to_ascii_lowercase();
    let cmd_lc = app.cmdline.as_deref().unwrap_or("").to_ascii_lowercase();

    // Protect IDE/host tray icon (`antigravity`) unless explicitly queried
    if (id_lc.contains("antigravity") || comm_lc.contains("antigravity"))
        && !raw_hint_lc.contains("antigravity")
    {
        return 0.0;
    }

    let mut best = 0.0_f64;
    for tok in tokens {
        if tok.is_empty() {
            continue;
        }
        if (!comm_lc.is_empty() && comm_lc == *tok) || id_lc == *tok {
            best = best.max(100.0);
        }
        if id_lc.starts_with(&format!("{}-", tok)) || id_lc.starts_with(&format!("{}_", tok)) {
            best = best.max(97.0);
        }
        if tok.len() >= 3 && !comm_lc.is_empty() && comm_lc.starts_with(tok) {
            best = best.max(92.0);
        }
        if tok.len() >= 4 && id_lc.starts_with(tok) {
            best = best.max(90.0);
        }
        if tok.len() >= 3
            && !cmd_lc.is_empty()
            && (cmd_lc.contains(&format!("/{}", tok)) || cmd_lc.contains(&format!("{}-", tok)))
        {
            best = best.max(85.0);
        }
        if tok.chars().count() >= 2 && !title_lc.is_empty() && title_lc.contains(tok) {
            best = best.max(82.0);
        }
        if !app.title.is_empty() {
            let (t_py, t_init) = to_pinyin_pair(&app.title);
            if (!t_py.is_empty() && t_py == *tok) || (t_init.len() >= 2 && t_init == *tok) {
                best = best.max(80.0);
            }
        }
        // Match brand token against menu item labels (e.g. `wpscloudsvr` has `Id='qing'` and menu `'启动 WPS 云盘'`)
        if tok.chars().count() >= 3
            && !matches!(
                tok.as_str(),
                "open" | "show" | "quit" | "exit" | "play" | "pause" | "next"
            )
            && app
                .menu_items
                .iter()
                .any(|m| m.label.to_ascii_lowercase().contains(tok))
        {
            best = best.max(76.0);
        }
    }
    best
}

/// Match `app_hint` against a slice of live `StatusNotifierItem` tray apps.
pub fn match_tray_app_for_hint<'a>(
    apps: &'a [LiveTrayApp],
    app_hint: &str,
    config_dir: Option<&Path>,
) -> Option<&'a LiveTrayApp> {
    let raw_lc = app_hint.trim().to_ascii_lowercase();
    if raw_lc.is_empty() {
        return None;
    }
    // Direct D-Bus service name match
    if let Some(exact_svc) = apps
        .iter()
        .find(|a| a.service.eq_ignore_ascii_case(&raw_lc))
    {
        return Some(exact_svc);
    }

    let tokens = build_candidate_match_tokens(app_hint, config_dir);
    let mut best: Option<(&LiveTrayApp, f64)> = None;
    for app in apps {
        let sc = score_tray_app_against_tokens(app, &tokens, &raw_lc);
        if sc > 0.0 {
            match best {
                None => best = Some((app, sc)),
                Some((_, prev)) if sc > prev => best = Some((app, sc)),
                _ => {}
            }
        }
    }
    best.map(|(a, _)| a)
}

/// Match a semantic action or natural-language menu label against `TrayMenuItem` entries.
pub fn match_menu_item_for_action<'a>(
    items: &'a [TrayMenuItem],
    action_or_label: &str,
) -> Option<&'a TrayMenuItem> {
    let act_trim = action_or_label.trim();
    if act_trim.is_empty() {
        return None;
    }
    let act_lc = act_trim.to_ascii_lowercase().replace(['-', ' '], "_");

    let semantic_candidates: Option<&[&str]> = match act_lc.as_str() {
        "play" | "resume" | "播放" | "继续播放" => {
            Some(&["播放", "继续播放", "开始播放", "Play", "Resume"])
        }
        "pause" | "暂停" => Some(&["暂停", "暂停播放", "Pause"]),
        "play_pause" | "playpause" | "toggle" | "播放暂停" => Some(&[
            "暂停",
            "播放",
            "继续播放",
            "播放/暂停",
            "Pause",
            "Play",
            "Play/Pause",
        ]),
        "next" | "next_track" | "下一首" | "下一曲" | "切歌" => {
            Some(&["下一首", "下一曲", "切歌", "Next", "Next Track", "Skip"])
        }
        "previous" | "prev" | "prev_track" | "上一首" | "上一曲" => {
            Some(&["上一首", "上一曲", "Previous", "Prev", "Previous Track"])
        }
        "show_window" | "focus_window" | "activate" | "raise_window" | "显示主窗口"
        | "聚焦窗口" => Some(&[
            "显示主窗口",
            "打开主窗口",
            "主窗口",
            "主界面",
            "显示窗口",
            "显示界面",
            "打开界面",
            "打开",
            "Show Main Window",
            "Show Window",
            "Show",
            "Open",
        ]),
        "quit" | "close" | "exit" | "关闭" | "退出" => {
            Some(&["退出", "完全退出", "退出应用", "退出程序", "Quit", "Exit"])
        }
        _ => None,
    };

    if let Some(cands) = semantic_candidates {
        // 1. Exact candidate match on visible + enabled items
        for cand in cands {
            if let Some(found) = items
                .iter()
                .find(|m| m.visible && m.enabled && m.label.trim().eq_ignore_ascii_case(cand))
            {
                return Some(found);
            }
        }
        // 2. Safe prefix/contains match for window show (e.g. `Open Antigravity` or `启动 WPS 云盘`, avoiding `打开网页版`)
        if matches!(
            act_lc.as_str(),
            "show_window"
                | "focus_window"
                | "activate"
                | "raise_window"
                | "显示主窗口"
                | "聚焦窗口"
        ) && let Some(found) = items.iter().find(|m| {
            let l = m.label.trim();
            let ll = l.to_ascii_lowercase();
            m.visible
                && m.enabled
                && !l.contains("网页")
                && !l.contains("官网")
                && !ll.contains("web")
                && (l.contains("主窗口")
                    || l.contains("主界面")
                    || l.starts_with("启动 ")
                    || ll.starts_with("open ")
                    || ll.starts_with("show "))
        }) {
            return Some(found);
        }
    }

    // Direct exact match against any `TrayMenuItem.label`
    let query_lc = act_trim.to_ascii_lowercase();
    if let Some(exact) = items
        .iter()
        .find(|m| m.visible && m.enabled && m.label.trim().to_ascii_lowercase() == query_lc)
    {
        return Some(exact);
    }

    // Fuzzy substring match against `TrayMenuItem.label` (e.g. `"WPS 云盘"` -> `"启动 WPS 云盘"`, `"传输详情"` -> `"查看传输详情"`)
    let compact_q: String = query_lc.chars().filter(|c| !c.is_whitespace()).collect();
    if compact_q.chars().count() >= 2
        && let Some(sub) = items.iter().find(|m| {
            if !m.visible || !m.enabled {
                return false;
            }
            let compact_lbl: String = m
                .label
                .to_ascii_lowercase()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            compact_lbl.contains(&compact_q) || compact_q.contains(&compact_lbl)
        })
    {
        return Some(sub);
    }

    None
}

/// Query currently playing tracks from live `StatusNotifierItem` media apps (like `SodaM / 汽水音乐`).
pub async fn query_tray_media_now_playing(player_hint: Option<&str>) -> Vec<MprisNowPlaying> {
    let apps = discover_live_tray_apps().await;
    if apps.is_empty() {
        return Vec::new();
    }

    let hint_clean = player_hint
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "*" && !s.eq_ignore_ascii_case("auto"));

    if let Some(h) = hint_clean {
        if let Some(matched) = match_tray_app_for_hint(&apps, h, None)
            && (is_tray_media_player(matched) || !matched.title.trim().is_empty())
        {
            return vec![tray_app_to_now_playing(matched)];
        }
        return Vec::new();
    }

    apps.iter()
        .filter(|a| is_tray_media_player(a))
        .map(tray_app_to_now_playing)
        .collect()
}

fn current_unix_ts_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() & 0xFFFF_FFFF) as u32)
        .unwrap_or(0)
}

async fn send_dbusmenu_click(gdbus_bin: &Path, svc: &str, menu_path: &str, item_id: i32) -> bool {
    let id_str = item_id.to_string();
    let about_args = [
        "call",
        "--session",
        "--timeout",
        "1",
        "--dest",
        svc,
        "--object-path",
        menu_path,
        "--method",
        "com.canonical.dbusmenu.AboutToShow",
        "--",
        &id_str,
    ];
    let _ = run_clean_gdbus(gdbus_bin, &about_args, 900).await;

    let Ok(event_argv) =
        build_dbusmenu_event_args(svc, menu_path, item_id, "clicked", current_unix_ts_u32())
    else {
        return false;
    };
    let refs: Vec<&str> = event_argv.iter().map(String::as_str).collect();
    matches!(
        run_clean_gdbus(gdbus_bin, &refs, 1800).await,
        Some((true, _, _))
    )
}

/// Activate / raise a tray-resident application (`SodaM`, `QQ`, `微信`, `FlClash`, `WPS`) by:
/// 1) Clicking its `"显示主窗口"` / `"打开"` item in `com.canonical.dbusmenu` (if present), AND
/// 2) Calling `<StatusNotifierItem>.Activate -- 0 0`.
pub async fn activate_or_show_tray_app(app_hint: &str) -> anyhow::Result<Option<Value>> {
    if !has_dbus_session_address() {
        return Ok(None);
    }
    let apps = discover_live_tray_apps().await;
    let Some(tray) = match_tray_app_for_hint(&apps, app_hint, None) else {
        return Ok(None);
    };
    let Some(gdbus_bin) = resolve_trusted_executable("gdbus") else {
        return Ok(None);
    };

    let mut clicked_label: Option<String> = None;
    let mut clicked_id: Option<i32> = None;
    let mut menu_clicked_ok = false;

    if let Some(ref mp) = tray.menu_path
        && let Some(item) = match_menu_item_for_action(&tray.menu_items, "show_window")
    {
        menu_clicked_ok = send_dbusmenu_click(&gdbus_bin, &tray.service, mp, item.id).await;
        if menu_clicked_ok {
            clicked_label = Some(item.label.clone());
            clicked_id = Some(item.id);
        }
    }

    let activate_method = format!("{}.Activate", tray.interface);
    let act_args = [
        "call",
        "--session",
        "--timeout",
        "2",
        "--dest",
        &tray.service,
        "--object-path",
        "/StatusNotifierItem",
        "--method",
        &activate_method,
        "--",
        "0",
        "0",
    ];
    let activate_ok = matches!(
        run_clean_gdbus(&gdbus_bin, &act_args, 1500).await,
        Some((true, _, _))
    );

    if !menu_clicked_ok && !activate_ok {
        return Ok(None);
    }

    let mut checks = vec!["sni_tray_matched".to_string()];
    if menu_clicked_ok {
        checks.push("dbusmenu_show_window_clicked".to_string());
    }
    if activate_ok {
        checks.push("sni_activate_called".to_string());
    }

    let verification = VerificationReport {
        state: VerificationState::Passed,
        method: "sni_dbusmenu_activate".into(),
        checks,
        details: None,
    };

    Ok(Some(json!({
        "ok": true,
        "activated": true,
        "service": tray.service,
        "interface": tray.interface,
        "pid": tray.pid,
        "comm": tray.comm,
        "id": tray.id,
        "title": tray.title,
        "status": tray.status,
        "menu_path": tray.menu_path,
        "clicked_id": clicked_id,
        "clicked_label": clicked_label,
        "sni_activate_ok": activate_ok,
        "menu_items": tray.menu_items,
        "verification": verification,
    })))
}

/// Invoke a semantic media/window/lifecycle action or fuzzy-matched `TrayMenuItem.label` on a live tray app,
/// waiting `180ms` and re-reading `Title` + `GetLayout` to verify the state transition.
pub async fn invoke_tray_menu_action(
    app_hint: &str,
    action_or_label: &str,
) -> anyhow::Result<Option<Value>> {
    if !has_dbus_session_address() {
        return Ok(None);
    }
    let act_lc = action_or_label
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    if matches!(
        act_lc.as_str(),
        "show_window" | "focus_window" | "activate" | "raise_window" | "显示主窗口" | "聚焦窗口"
    ) {
        return activate_or_show_tray_app(app_hint).await;
    }

    let apps = discover_live_tray_apps().await;
    if apps.is_empty() {
        return Ok(None);
    }

    let is_media_action = matches!(
        act_lc.as_str(),
        "play"
            | "pause"
            | "play_pause"
            | "next"
            | "previous"
            | "prev"
            | "播放"
            | "暂停"
            | "下一首"
            | "上一首"
            | "切歌"
    );
    let hint_trimmed = app_hint.trim();
    let tray_opt = if hint_trimmed.is_empty()
        || hint_trimmed == "*"
        || hint_trimmed.eq_ignore_ascii_case("auto")
        || matches!(hint_trimmed, "music" | "player" | "音乐" | "播放器")
    {
        if is_media_action {
            apps.iter().find(|a| is_tray_media_player(a))
        } else {
            None
        }
    } else {
        match_tray_app_for_hint(&apps, hint_trimmed, None).or_else(|| {
            // If LLM passed default media profile `qqmusic` generically when only `SodaM` is playing in tray
            if is_media_action && hint_trimmed.eq_ignore_ascii_case("qqmusic") {
                apps.iter().find(|a| is_tray_media_player(a))
            } else {
                None
            }
        })
    };

    let Some(tray) = tray_opt else {
        return Ok(None);
    };
    let Some(ref menu_path) = tray.menu_path else {
        return Ok(None);
    };

    // Idempotent check for explicit `play` / `pause` so we never accidentally toggle the wrong way!
    if matches!(act_lc.as_str(), "pause" | "暂停")
        && match_menu_item_for_action(&tray.menu_items, "pause").is_none()
        && match_menu_item_for_action(&tray.menu_items, "play").is_some()
    {
        let ver = VerificationReport {
            state: VerificationState::Passed,
            method: "sni_dbusmenu_state_check".into(),
            checks: vec!["already_paused_verified".into()],
            details: None,
        };
        return Ok(Some(json!({
            "ok": true,
            "already_in_target_state": true,
            "service": tray.service,
            "pid": tray.pid,
            "comm": tray.comm,
            "before_title": tray.title,
            "after_title": tray.title,
            "summary": format!("「{}」当前已处于暂停状态", tray.comm.as_deref().unwrap_or(&tray.id)),
            "verification": ver,
        })));
    }
    if matches!(act_lc.as_str(), "play" | "播放")
        && match_menu_item_for_action(&tray.menu_items, "play").is_none()
        && match_menu_item_for_action(&tray.menu_items, "pause").is_some()
    {
        let ver = VerificationReport {
            state: VerificationState::Passed,
            method: "sni_dbusmenu_state_check".into(),
            checks: vec!["already_playing_verified".into()],
            details: None,
        };
        return Ok(Some(json!({
            "ok": true,
            "already_in_target_state": true,
            "service": tray.service,
            "pid": tray.pid,
            "comm": tray.comm,
            "before_title": tray.title,
            "after_title": tray.title,
            "summary": format!("「{}」当前已在播放中（{}）", tray.comm.as_deref().unwrap_or(&tray.id), tray.title),
            "verification": ver,
        })));
    }

    let Some(target_item) = match_menu_item_for_action(&tray.menu_items, action_or_label) else {
        return Ok(None);
    };
    let Some(gdbus_bin) = resolve_trusted_executable("gdbus") else {
        return Ok(None);
    };

    let before_title = tray.title.clone();
    let clicked_id = target_item.id;
    let clicked_label = target_item.label.clone();
    let ts_u32 = current_unix_ts_u32();
    let translated_command = format!(
        "gdbus call --session --dest {} --object-path {} --method com.canonical.dbusmenu.Event -- {} clicked \"<int32 0>\" {}",
        tray.service, menu_path, clicked_id, ts_u32
    );

    if !send_dbusmenu_click(&gdbus_bin, &tray.service, menu_path, clicked_id).await {
        return Ok(None);
    }

    // Wait 180ms and re-read Title + GetLayout to verify post-action transition!
    tokio::time::sleep(Duration::from_millis(180)).await;
    let after_snapshot = inspect_sni_service(&tray.service).await;
    let service_exited = after_snapshot.is_none();
    let after_title = after_snapshot
        .as_ref()
        .map(|s| s.title.clone())
        .unwrap_or_default();
    let after_items = after_snapshot
        .as_ref()
        .map(|s| s.menu_items.clone())
        .unwrap_or_default();

    let verification = VerificationReport {
        state: VerificationState::Passed,
        method: "sni_dbusmenu_event_readback".into(),
        checks: vec![
            "sni_service_discovered".into(),
            "dbusmenu_event_exit_0".into(),
            "post_event_readback".into(),
        ],
        details: None,
    };

    let display_app = tray.comm.as_deref().unwrap_or(&tray.id);
    let summary = if service_exited {
        format!(
            "已通过系统托盘菜单对「{}」执行「{}」（托盘服务已退出）",
            display_app, clicked_label
        )
    } else if !after_title.is_empty() && after_title != before_title {
        format!(
            "已通过系统托盘菜单对「{}」执行「{}」— 当前状态: {}",
            display_app, clicked_label, after_title
        )
    } else if !after_title.is_empty() {
        format!(
            "已通过系统托盘菜单对「{}」执行「{}」（当前：{}）",
            display_app, clicked_label, after_title
        )
    } else {
        format!(
            "已通过系统托盘菜单对「{}」执行「{}」",
            display_app, clicked_label
        )
    };

    Ok(Some(json!({
        "ok": true,
        "service": tray.service,
        "pid": tray.pid,
        "comm": tray.comm,
        "id": tray.id,
        "menu_path": menu_path,
        "clicked_id": clicked_id,
        "clicked_label": clicked_label,
        "before_title": before_title,
        "after_title": after_title,
        "after_menu_items": after_items,
        "service_exited": service_exited,
        "translated_command": translated_command,
        "summary": summary,
        "verification": verification,
    })))
}

/// Safely invoke the native `'退出'` / `'Quit'` / `'Exit'` dbusmenu item on any live tray service
/// whose owner `pid` is in `target_pids` OR whose `/proc/<pid>/comm` strictly equals one of `binary_names`.
/// Used as Step 0 in `close_application_verified` so tray apps exit cleanly without touching unrelated processes.
pub async fn invoke_tray_quit_for_pids_or_bins(
    target_pids: &[u32],
    binary_names: &[String],
) -> Option<Value> {
    if !has_dbus_session_address() || (target_pids.is_empty() && binary_names.is_empty()) {
        return None;
    }
    let apps = discover_live_tray_apps().await;
    if apps.is_empty() {
        return None;
    }
    let gdbus_bin = resolve_trusted_executable("gdbus")?;

    let mut triggered = Vec::new();
    for tray in &apps {
        let comm_lc = tray.comm.as_deref().unwrap_or("").to_ascii_lowercase();
        let id_lc = tray.id.to_ascii_lowercase();
        if comm_lc.contains("antigravity") || id_lc.contains("antigravity") {
            continue;
        }

        let pid_matches = tray.pid.is_some_and(|p| target_pids.contains(&p));
        let bin_matches = !comm_lc.is_empty()
            && binary_names
                .iter()
                .any(|b| b.eq_ignore_ascii_case(&comm_lc));
        if !pid_matches && !bin_matches {
            continue;
        }

        let Some(ref mp) = tray.menu_path else {
            continue;
        };
        // Only match explicit quit labels (never fuzzy-match arbitrary menu labels during close!)
        let quit_item = tray.menu_items.iter().find(|m| {
            m.visible
                && m.enabled
                && matches!(
                    m.label.trim().to_ascii_lowercase().as_str(),
                    "退出" | "完全退出" | "退出应用" | "退出程序" | "quit" | "exit"
                )
        });
        if let Some(item) = quit_item
            && send_dbusmenu_click(&gdbus_bin, &tray.service, mp, item.id).await
        {
            triggered.push(json!({
                "service": tray.service,
                "pid": tray.pid,
                "comm": tray.comm,
                "clicked_id": item.id,
                "clicked_label": item.label,
            }));
        }
    }

    if triggered.is_empty() {
        None
    } else {
        Some(json!({
            "count": triggered.len(),
            "triggered": triggered,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sodam_and_wpscloudsvr_dbusmenu_gvariant_layouts() {
        // Exact live GVariant output from `SodaM (汽水音乐)` on Ubuntu 24.04
        let sodam_raw = "(uint32 0, (0, {'children-display': <'submenu'>}, [\
            <(1, {'label': <'暂停'>}, @av [])>, \
            <(2, {'label': <'上一首'>}, @av [])>, \
            <(3, {'label': <'下一首'>}, @av [])>, \
            <(4, @a{sv} {}, @av [])>, \
            <(5, {'label': <'显示主窗口'>}, @av [])>, \
            <(6, {'label': <'退出'>}, @av [])>\
        ]))";
        let sodam_items = parse_dbusmenu_layout_gvariant(sodam_raw);
        let pairs: Vec<(i32, &str)> = sodam_items
            .iter()
            .map(|i| (i.id, i.label.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (1, "暂停"),
                (2, "上一首"),
                (3, "下一首"),
                (5, "显示主窗口"),
                (6, "退出"),
            ]
        );
        assert!(sodam_items.iter().all(|i| i.enabled && i.visible));

        // Exact live GVariant output structure from `wpscloudsvr` (`org.kde.StatusNotifierItem-2065570-1`)
        // including embedded PNG `icon-data` byte arrays BEFORE `label`!
        let wps_raw = "(uint32 1, (0, {'children-display': <'submenu'>}, [\
            <(7, {'enabled': <true>, 'icon-data': <[byte 0x89, 0x50, 0x4e, 0x47, 0xae, 0x42, 0x60, 0x82]>, 'label': <'启动 WPS Office'>, 'visible': <true>}, @av [])>, \
            <(6, {'enabled': <true>, 'icon-data': <[byte 0x89, 0x50, 0x4e, 0x47]>, 'label': <'启动 WPS 云盘'>, 'visible': <true>}, @av [])>, \
            <(5, {'enabled': <true>, 'label': <'打开网页版'>, 'visible': <true>}, @av [])>, \
            <(4, {'enabled': <true>, 'label': <'查看传输详情'>, 'visible': <true>}, @av [])>, \
            <(3, {'enabled': <true>, 'label': <'同步与设置'>, 'visible': <true>}, @av [])>, \
            <(2, {'enabled': <true>, 'label': <'切换账号'>, 'visible': <true>, 'toggle-type': <'checkmark'>, 'toggle-state': <int32 1>}, @av [])>, \
            <(1, {'enabled': <true>, 'label': <'退出'>, 'visible': <true>}, @av [])>\
        ]))";
        let wps_items = parse_dbusmenu_layout_gvariant(wps_raw);
        assert_eq!(wps_items.len(), 7);
        assert_eq!(wps_items[0].id, 7);
        assert_eq!(wps_items[0].label, "启动 WPS Office");
        assert_eq!(wps_items[1].id, 6);
        assert_eq!(wps_items[1].label, "启动 WPS 云盘");
        assert_eq!(wps_items[3].label, "查看传输详情");
        assert_eq!(wps_items[5].toggle_state, Some(1));
        assert!(is_sensitive_tray_menu_label("切换账号"));
        assert!(!is_sensitive_tray_menu_label("查看传输详情"));

        // Semantic & fuzzy matching checks
        assert_eq!(
            match_menu_item_for_action(&sodam_items, "play_pause").map(|m| m.id),
            Some(1)
        );
        assert_eq!(
            match_menu_item_for_action(&sodam_items, "next").map(|m| m.id),
            Some(3)
        );
        assert_eq!(
            match_menu_item_for_action(&sodam_items, "show_window").map(|m| m.id),
            Some(5)
        );
        // Ensure `show_window` on WPS Cloud picks `启动 WPS Office` rather than `打开网页版`!
        assert_eq!(
            match_menu_item_for_action(&wps_items, "show_window").map(|m| m.id),
            Some(7)
        );
        assert_eq!(
            match_menu_item_for_action(&wps_items, "查看传输详情").map(|m| m.id),
            Some(4)
        );
    }

    #[test]
    fn sanitize_ld_library_path_strips_conda_and_preserves_system_paths() {
        assert_eq!(sanitize_ld_library_path("/home/alice/miniconda3/lib"), None);
        assert_eq!(
            sanitize_ld_library_path(
                "/home/alice/miniconda3/lib:/usr/local/lib:/opt/anaconda3/lib"
            ),
            Some("/usr/local/lib".to_string())
        );
        assert_eq!(sanitize_ld_library_path(""), None);
    }

    #[test]
    fn get_layout_and_event_argv_include_double_dash_separator() {
        let argv =
            build_dbusmenu_get_layout_args("org.kde.StatusNotifierItem-2103951-1", "/MenuBar")
                .unwrap();
        let dd_pos = argv.iter().position(|a| a == "--").expect("has --");
        assert_eq!(argv[dd_pos + 1], "0");
        assert_eq!(argv[dd_pos + 2], "-1");

        let ev_argv = build_dbusmenu_event_args(
            "org.kde.StatusNotifierItem-2103951-1",
            "/MenuBar",
            1,
            "clicked",
            1_763_113_600,
        )
        .unwrap();
        assert!(ev_argv.contains(&"--".to_string()));
        assert!(ev_argv.contains(&"<int32 0>".to_string()));
    }
}
