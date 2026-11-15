#![forbid(unsafe_code)]

//! Window Focus & AT-SPI2 / Wnck / SNI Accessibility Inspection & Action Bridge (`gui_bridge.rs`):
//! - Enumerates desktop windows via `wmctrl -lx` OR system `/usr/bin/python3` (`Wnck 3.0` + `Atspi 2.0`)
//!   + `StatusNotifierItem` live tray items (with Conda `LD_LIBRARY_PATH` stripped!)
//! - Focuses / raises windows via (1) `sni_dbusmenu::activate_or_show_tray_app`, (2) `Wnck 3.0`
//!   `.activate(ts)` / `Atspi` focus, (3) `wmctrl -a`, and (4) `/proc` liveness verification
//! - NEVER claims headless simulation (`"无头/仿真环境预演"`) when `has_gui_session()` is true and `!force_dry_run`
//! - Strictly gates ALL synthetic UI clicks, shortcuts, and text injection behind `approved == true`

use crate::app_adapter::dynamic_profiler::find_running_pids_for_profile_or_hint;
use crate::app_adapter::mpris_dbus::{has_dbus_session_address, has_gui_session};
use crate::app_adapter::registry::{AdaptationChannel, AppAdapterProfile};
use crate::app_adapter::sni_dbusmenu::{
    apply_clean_desktop_env, discover_live_tray_apps, resolve_system_gi_python3,
};
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_protocol::{VerificationReport, VerificationState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Fixed read-only Python3 helper enumerating X11/XWayland (`Wnck 3.0`) and Wayland (`Atspi 2.0`) windows.
const GI_ENUM_WINDOWS_PY_SCRIPT: &str = r#"
import json, sys

windows = []
seen = set()

try:
    import gi
    gi.require_version("Wnck", "3.0")
    from gi.repository import Wnck
    screen = Wnck.Screen.get_default()
    if screen is not None:
        screen.force_update()
        for w in screen.get_windows():
            if w.is_skip_tasklist():
                continue
            title = (w.get_name() or "").strip()
            cls = (w.get_class_group_name() or w.get_class_instance_name() or "x11").strip()
            if not title:
                continue
            key = (cls.lower(), title.lower())
            if key not in seen:
                seen.add(key)
                windows.append({
                    "window_id": hex(w.get_xid()),
                    "desktop_index": 0,
                    "wm_class": cls,
                    "host": "x11",
                    "title": title,
                })
except Exception:
    pass

try:
    import gi
    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi
    desktop = Atspi.get_desktop(0)
    if desktop is not None:
        for i in range(desktop.get_child_count()):
            app = desktop.get_child_at_index(i)
            if app is None:
                continue
            app_name = (app.get_name() or "").strip()
            if app_name in ("gnome-shell", "mutter-x11-frames"):
                continue
            for j in range(min(app.get_child_count(), 20)):
                win = app.get_child_at_index(j)
                if win is None:
                    continue
                role = (win.get_role_name() or "").lower()
                wname = (win.get_name() or "").strip()
                if app_name == "gjs" and wname == "Desktop Icons":
                    continue
                if role in ("frame", "window", "dialog", "application") and wname:
                    key = (app_name.lower(), wname.lower())
                    if key not in seen and not any(wname.lower() == x["title"].lower() for x in windows):
                        seen.add(key)
                        windows.append({
                            "window_id": f"atspi:{i}:{j}",
                            "desktop_index": 0,
                            "wm_class": app_name or "wayland",
                            "host": "wayland",
                            "title": wname,
                        })
except Exception:
    pass

print(json.dumps(windows))
"#;

/// Fixed Python3 helper activating a matching window via `Wnck 3.0` (`_NET_ACTIVE_WINDOW`)
/// or checking `Atspi 2.0` component focus on Wayland.
/// `sys.argv[1]` is a JSON list of lowercase hint strings.
const GI_FOCUS_WINDOW_PY_SCRIPT: &str = r#"
import json, sys, time

hints = []
if len(sys.argv) > 1:
    try:
        hints = [str(x).strip().lower() for x in json.loads(sys.argv[1]) if str(x).strip()]
    except Exception:
        hints = [sys.argv[1].strip().lower()]

def matches_any(texts):
    for t in texts:
        tl = (t or "").strip().lower()
        if not tl:
            continue
        for h in hints:
            if h and (tl == h or (len(h) >= 2 and h in tl)):
                return True
    return False

try:
    import gi
    gi.require_version("Wnck", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Wnck, Gdk
    screen = Wnck.Screen.get_default()
    if screen is not None:
        screen.force_update()
        for w in screen.get_windows():
            if w.is_skip_tasklist():
                continue
            w_name = w.get_name() or ""
            w_cls = w.get_class_group_name() or ""
            w_inst = w.get_class_instance_name() or ""
            app_name = w.get_application().get_name() if w.get_application() else ""
            if matches_any([w_name, w_cls, w_inst, app_name]):
                if w.is_minimized():
                    w.unminimize(int(time.time()))
                w.activate(int(time.time()))
                Gdk.flush()
                print(json.dumps({
                    "ok": True,
                    "activated": True,
                    "method": "wnck_activate",
                    "title": w_name,
                    "wm_class": w_cls,
                }))
                sys.exit(0)
except Exception:
    pass

try:
    import gi
    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi
    desktop = Atspi.get_desktop(0)
    if desktop is not None:
        for i in range(desktop.get_child_count()):
            app = desktop.get_child_at_index(i)
            if app is None:
                continue
            aname = (app.get_name() or "").strip()
            if aname in ("gnome-shell", "gjs"):
                continue
            for j in range(min(app.get_child_count(), 20)):
                win = app.get_child_at_index(j)
                if win is None:
                    continue
                wname = (win.get_name() or "").strip()
                if matches_any([aname, wname]):
                    grabbed = False
                    try:
                        comp = win.get_component_iface()
                        if comp is not None:
                            grabbed = bool(comp.grab_focus())
                    except Exception:
                        pass
                    print(json.dumps({
                        "ok": True,
                        "activated": grabbed,
                        "wayland_window_found": True,
                        "method": "atspi_window_focus",
                        "title": wname or aname,
                        "wm_class": aname,
                    }))
                    sys.exit(0)
except Exception:
    pass

print(json.dumps({"ok": False, "reason": "window_not_found"}))
sys.exit(2)
"#;

/// Fixed read-only Python3 helper querying AT-SPI2 accessible controls.
/// Security invariant: `app_hint` is passed strictly via `sys.argv[1]`, never interpolated into code.
const ATSPI_INSPECT_PY_SCRIPT: &str = r#"
import json, sys
target = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
try:
    import gi
    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi
except Exception as e:
    print(json.dumps({"available": False, "reason": str(e), "controls": []}))
    sys.exit(0)

desktop = Atspi.get_desktop(0)
apps = []
controls = []
def walk(node, depth):
    if node is None or depth > 5 or len(controls) >= 40:
        return
    try:
        role = node.get_role_name() or ""
        name = node.get_name() or ""
        if role in ("push button", "toggle button", "menu item", "text", "entry", "page tab", "check box", "combo box") and name:
            controls.append({"role": role, "name": name})
        count = node.get_child_count()
        for i in range(min(count, 35)):
            walk(node.get_child_at_index(i), depth + 1)
    except Exception:
        pass

if desktop is not None:
    for i in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(i)
        if app is None:
            continue
        aname = (app.get_name() or "")
        apps.append(aname)
        if not target or target in aname.lower():
            walk(app, 0)

print(json.dumps({"available": True, "apps": apps, "controls": controls}))
"#;

/// Fixed Python3 helper invoking a named AT-SPI2 control's default `Action` (`do_action(0)`).
/// Only ever invoked AFTER `approved == true` has passed policy check.
const ATSPI_CLICK_PY_SCRIPT: &str = r#"
import json, sys
app_hint = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
ctrl_name = (sys.argv[2] if len(sys.argv) > 2 else "").lower()
try:
    import gi
    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi
except Exception as e:
    print(json.dumps({"ok": False, "reason": str(e)}))
    sys.exit(1)

def find_and_invoke(node, depth):
    if node is None or depth > 6:
        return False
    try:
        name = (node.get_name() or "")
        if ctrl_name and ctrl_name in name.lower():
            act_iface = node.get_action_iface()
            if act_iface is not None and act_iface.get_n_actions() > 0:
                ok = act_iface.do_action(0)
                return bool(ok)
        for i in range(min(node.get_child_count(), 40)):
            if find_and_invoke(node.get_child_at_index(i), depth + 1):
                return True
    except Exception:
        pass
    return False

desktop = Atspi.get_desktop(0)
if desktop is not None:
    for i in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(i)
        if app is not None and (not app_hint or app_hint in (app.get_name() or "").lower()):
            if find_and_invoke(app, 0):
                print(json.dumps({"ok": True}))
                sys.exit(0)

print(json.dumps({"ok": False, "reason": "control_not_found"}))
sys.exit(2)
"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopWindowInfo {
    pub window_id: String,
    pub desktop_index: i32,
    pub wm_class: String,
    pub host: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiApprovalScope {
    pub scope_id: String,
    pub app_id: String,
    pub app_name: String,
    pub action: String,
    pub target_detail: String,
    pub risk_badge: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct GuiDispatchResult {
    pub ok: bool,
    pub requires_approval: bool,
    pub approval_scope: Option<GuiApprovalScope>,
    pub channel_used: AdaptationChannel,
    pub translated_command: String,
    pub summary: String,
    pub data: Value,
    pub simulated: bool,
    pub verification: VerificationReport,
}

/// Pure predicate deciding whether `gui_bridge` is allowed to enter headless/dry-run simulation.
/// Invariant: When a live GUI session (`DISPLAY` or `WAYLAND_DISPLAY`) is present and `!force_dry_run`,
/// `gui_bridge` MUST NEVER claim headless simulation (`"无头/仿真环境预演"`).
pub fn should_use_headless_simulation(gui_session_present: bool, force_dry_run: bool) -> bool {
    force_dry_run || !gui_session_present
}

/// Parse `wmctrl -lx` output lines into structured `DesktopWindowInfo` items.
/// Example line: `0x02400003  0 code.Code             ubuntu-host main.rs - Visual Studio Code`
pub fn parse_wmctrl_lx_output(raw: &str) -> Vec<DesktopWindowInfo> {
    let mut windows = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 4 {
            continue;
        }
        let window_id = tokens[0].to_string();
        let desktop_index = tokens[1].parse::<i32>().unwrap_or(0);
        let wm_class = tokens[2].to_string();
        let host = tokens[3].to_string();
        let title = if tokens.len() > 4 {
            tokens[4..].join(" ")
        } else {
            wm_class.clone()
        };
        windows.push(DesktopWindowInfo {
            window_id,
            desktop_index,
            wm_class,
            host,
            title,
        });
    }
    windows
}

/// Validate a synthetic keyboard shortcut string, rejecting shell/control characters and system-escape combos.
pub fn validate_shortcut_safety(raw_shortcut: &str) -> anyhow::Result<String> {
    let clean = raw_shortcut.trim();
    if clean.is_empty() || clean.len() > 64 {
        anyhow::bail!("快捷键格式无效或为空");
    }
    if clean.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                ';' | '|' | '&' | '$' | '`' | '\\' | '\'' | '"' | '<' | '>'
            )
    }) {
        anyhow::bail!("安全拦截：快捷键包含非法特殊字符: {}", clean);
    }

    let norm = clean.to_ascii_lowercase().replace(' ', "");
    let forbidden_combos = [
        "ctrl+alt+del",
        "ctrl+alt+delete",
        "ctrl+alt+backspace",
        "alt+sysrq",
        "super+l",
        "ctrl+alt+t",
        "ctrl+alt+f1",
        "ctrl+alt+f2",
        "ctrl+alt+f3",
        "ctrl+alt+f4",
        "ctrl+alt+f5",
        "ctrl+alt+f6",
        "alt+f4",
    ];
    if forbidden_combos.contains(&norm.as_str()) {
        anyhow::bail!(
            "安全拦截：禁止通过应用无障碍转译层注入系统级/退出级全局快捷键 `{}`",
            clean
        );
    }

    Ok(clean.to_string())
}

/// Enumerate currently open desktop windows & active tray instances (read-only).
/// Uses `wmctrl -lx` if installed; otherwise falls back to `/usr/bin/python3` (`Wnck 3.0` + `Atspi 2.0`)
/// with sanitized desktop environment + `sni_dbusmenu` live tray items!
pub async fn enumerate_desktop_windows() -> Vec<DesktopWindowInfo> {
    if !has_gui_session() {
        return Vec::new();
    }

    let mut windows = Vec::new();

    if let Some(wmctrl_bin) = resolve_trusted_executable("wmctrl")
        && let Some((true, stdout, _)) = run_gui_helper(&wmctrl_bin, &["-lx"], 1500).await
    {
        windows = parse_wmctrl_lx_output(&stdout);
    }

    if windows.is_empty()
        && let Some((true, stdout, _)) =
            run_gi_python_helper(GI_ENUM_WINDOWS_PY_SCRIPT, &[], 2200, true).await
        && let Ok(gi_wins) = serde_json::from_str::<Vec<DesktopWindowInfo>>(stdout.trim())
    {
        windows = gi_wins;
    }

    // Merge live `StatusNotifierItem` tray apps so tray-minimized apps (`SodaM`, `wpscloudsvr`, etc.) are visible
    if has_dbus_session_address() {
        for tray in discover_live_tray_apps().await {
            let wm_cls = tray.comm.clone().unwrap_or_else(|| tray.id.clone());
            let already_listed = windows.iter().any(|w| {
                w.wm_class.eq_ignore_ascii_case(&wm_cls)
                    || (!tray.title.is_empty() && w.title.eq_ignore_ascii_case(&tray.title))
            });
            if !already_listed {
                let title = if tray.title.trim().is_empty() {
                    format!("{} (托盘驻留)", wm_cls)
                } else {
                    tray.title.clone()
                };
                windows.push(DesktopWindowInfo {
                    window_id: format!("sni:{}", tray.service),
                    desktop_index: 0,
                    wm_class: wm_cls,
                    host: "sni_tray".into(),
                    title,
                });
            }
        }
    }

    windows
}

/// Read-only AT-SPI2 accessible control probe for `inspect_live_app` (using `/usr/bin/python3` with clean env).
pub async fn probe_atspi_controls_readonly(app_hint: &str) -> Vec<Value> {
    if !has_gui_session() || !has_dbus_session_address() {
        return Vec::new();
    }
    if let Some((true, stdout, _)) =
        run_gi_python_helper(ATSPI_INSPECT_PY_SCRIPT, &[app_hint], 1600, false).await
        && let Ok(parsed) = serde_json::from_str::<Value>(stdout.trim())
        && let Some(arr) = parsed.get("controls").and_then(|c| c.as_array())
    {
        return arr.clone();
    }
    Vec::new()
}

/// Determine whether a `GuiAtspi` action synthesizes input/clicks and therefore MUST require `approved == true`.
pub fn action_requires_gui_approval(canonical_action: &str) -> bool {
    !matches!(
        canonical_action,
        "list_windows" | "focus_window" | "inspect_ui_tree"
    )
}

/// Build the explicit scoped approval descriptor returned when `approved != true`.
pub fn build_gui_approval_scope(
    profile: &AppAdapterProfile,
    canonical_action: &str,
    params: &Value,
) -> GuiApprovalScope {
    let detail = match canonical_action {
        "click_control" => params
            .get("control")
            .or_else(|| params.get("name"))
            .or_else(|| params.get("label"))
            .and_then(|v| v.as_str())
            .unwrap_or("未命名无障碍控件")
            .to_string(),
        "trigger_shortcut" => params
            .get("shortcut")
            .or_else(|| params.get("keys"))
            .and_then(|v| v.as_str())
            .unwrap_or("未指定快捷键")
            .to_string(),
        "type_text" => {
            let txt = params.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let preview: String = txt.chars().take(24).collect();
            format!("文本输入 ({} 字符: \"{}\")", txt.chars().count(), preview)
        }
        other => other.to_string(),
    };

    let scope_id = format!("gui_atspi:{}:{}", profile.id, canonical_action);
    let description = format!(
        "向纯 GUI 软件「{}」注入受控界面动作 `{}`（目标: {}），权限严格限定于该应用窗口范围",
        profile.name, canonical_action, detail
    );

    GuiApprovalScope {
        scope_id,
        app_id: profile.id.clone(),
        app_name: profile.name.clone(),
        action: canonical_action.to_string(),
        target_detail: detail,
        risk_badge: "R2".into(),
        description,
    }
}

fn build_window_match_hints(profile: &AppAdapterProfile, target: &str) -> Vec<String> {
    let mut hints = Vec::new();
    let push_h = |vec: &mut Vec<String>, s: &str| {
        let trimmed = s.trim().to_ascii_lowercase();
        if !trimmed.is_empty()
            && trimmed != "generic-gui-window"
            && !vec.iter().any(|x| x == &trimmed)
        {
            vec.push(trimmed);
        }
    };
    push_h(&mut hints, target);
    push_h(&mut hints, &profile.id);
    push_h(&mut hints, &profile.name);
    for exe in &profile.cli_executables {
        if let Some(base) = Path::new(exe).file_name().and_then(|s| s.to_str()) {
            push_h(&mut hints, base);
        }
    }
    for did in &profile.desktop_ids {
        push_h(&mut hints, did.trim_end_matches(".desktop"));
    }
    for al in &profile.aliases {
        if al.chars().count() >= 2 {
            push_h(&mut hints, al);
        }
    }
    hints
}

/// Execute a `GuiAtspi` inspection, window focus, or approval-gated synthetic UI action.
pub async fn execute_gui_bridge_action(
    profile: &AppAdapterProfile,
    canonical_action: &str,
    params: &Value,
    approved: bool,
) -> anyhow::Result<GuiDispatchResult> {
    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let gui_present = has_gui_session();
    let use_headless_sim = should_use_headless_simulation(gui_present, force_dry_run);

    // 1. Pre-validate shortcut safety BEFORE approval gate so dangerous shortcuts are rejected outright
    if canonical_action == "trigger_shortcut" {
        let raw_sc = params
            .get("shortcut")
            .or_else(|| params.get("keys"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        validate_shortcut_safety(raw_sc)?;
    }

    // 2. Enforce strict approval gate for any synthetic click / shortcut / text injection!
    if action_requires_gui_approval(canonical_action) && !approved {
        let scope = build_gui_approval_scope(profile, canonical_action, params);
        return Ok(GuiDispatchResult {
            ok: false,
            requires_approval: true,
            summary: format!("待确认分级范围权限：{}", scope.description),
            translated_command: format!(
                "atspi-bridge --app {} --action {} --target {}",
                profile.id, canonical_action, scope.target_detail
            ),
            data: json!({
                "requires_approval": true,
                "approval_scope": scope,
            }),
            approval_scope: Some(scope),
            channel_used: AdaptationChannel::GuiAtspi,
            simulated: false,
            verification: VerificationReport {
                state: VerificationState::Skipped,
                method: "approval_gate_blocked".into(),
                checks: vec!["approved_flag_false".into()],
                details: Some("未获用户显式批准 (approved != true)，已阻断合成 UI 注入".into()),
            },
        });
    }

    // 3. Read-only / low-risk inspection & focus actions
    match canonical_action {
        "list_windows" => {
            if use_headless_sim {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command: "enumerate_desktop_windows (dry_run)".into(),
                    summary: "已完成桌面活动窗口枚举预演（无头/仿真环境预演）".into(),
                    data: json!({ "windows": [] }),
                    simulated: true,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "simulated_headless_windows".into(),
                        checks: vec!["readonly_window_enumeration".into()],
                        details: None,
                    },
                });
            }

            let windows = enumerate_desktop_windows().await;
            Ok(GuiDispatchResult {
                ok: true,
                requires_approval: false,
                approval_scope: None,
                channel_used: AdaptationChannel::GuiAtspi,
                translated_command: "/usr/bin/python3 <wnck_atspi_sni_enum>".into(),
                summary: format!("枚举到当前桌面 {} 个活动窗口与托盘实例", windows.len()),
                data: json!({ "windows": windows }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::Passed,
                    method: "desktop_window_and_sni_enum".into(),
                    checks: vec!["readonly_window_enumeration".into()],
                    details: None,
                },
            })
        }
        "focus_window" => {
            let target = params
                .get("window_title")
                .or_else(|| params.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or(&profile.id);

            if use_headless_sim {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command: format!("focus_window({})", target),
                    summary: format!("已请求聚焦窗口「{}」（无头/仿真环境预演）", profile.name),
                    data: json!({ "target": target }),
                    simulated: true,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "simulated_headless_focus".into(),
                        checks: vec!["window_focus_translated".into()],
                        details: None,
                    },
                });
            }

            // Real GUI session path (`has_gui_session() == true && !force_dry_run`):
            // Step (1): `sni_dbusmenu::activate_or_show_tray_app` (`SodaM`, `WPS`, `QQ`, `微信`, `FlClash`, etc.)
            let mut tray_activated =
                crate::app_adapter::sni_dbusmenu::activate_or_show_tray_app(target).await?;
            if tray_activated.is_none() && !target.eq_ignore_ascii_case(&profile.id) {
                tray_activated =
                    crate::app_adapter::sni_dbusmenu::activate_or_show_tray_app(&profile.id)
                        .await?;
            }
            if let Some(tray_val) = tray_activated {
                let svc = tray_val
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or(target);
                let clicked_lbl = tray_val.get("clicked_label").and_then(|v| v.as_str());
                let summary = if let Some(lbl) = clicked_lbl {
                    format!(
                        "已通过系统托盘菜单「{}」唤醒并前置「{}」主窗口",
                        lbl, profile.name
                    )
                } else {
                    format!(
                        "已通过系统托盘 StatusNotifierItem 唤醒「{}」窗口",
                        profile.name
                    )
                };
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::SniDbusMenu,
                    translated_command: format!("sni_dbusmenu::activate_or_show_tray_app({})", svc),
                    summary,
                    data: tray_val,
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "sni_dbusmenu_activate".into(),
                        checks: vec![
                            "sni_tray_matched".into(),
                            "dbusmenu_or_activate_dispatched".into(),
                        ],
                        details: None,
                    },
                });
            }

            // Step (2): `Wnck 3.0` window `.activate(int(time.time()))` / `Atspi 2.0` via `/usr/bin/python3`
            let hints = build_window_match_hints(profile, target);
            let hints_json = serde_json::to_string(&hints).unwrap_or_else(|_| "[]".into());
            if let Some((true, stdout, _)) =
                run_gi_python_helper(GI_FOCUS_WINDOW_PY_SCRIPT, &[&hints_json], 1800, true).await
                && let Ok(py_res) = serde_json::from_str::<Value>(stdout.trim())
                && py_res.get("ok").and_then(|v| v.as_bool()) == Some(true)
            {
                let method_used = py_res
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("wnck_activate")
                    .to_string();
                let win_title = py_res
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&profile.name)
                    .to_string();
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command: format!("/usr/bin/python3 <{}> {}", method_used, target),
                    summary: format!(
                        "已将「{}」窗口（{}）切换至前台焦点",
                        profile.name, win_title
                    ),
                    data: py_res,
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: method_used,
                        checks: vec![
                            "desktop_window_matched".into(),
                            "window_activate_called".into(),
                        ],
                        details: None,
                    },
                });
            }

            // Step (3): `wmctrl -a` if installed on the system
            if let Some(wmctrl_bin) = resolve_trusted_executable("wmctrl")
                && let Some((true, _, _)) = run_gui_helper(&wmctrl_bin, &["-a", target], 1500).await
            {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command: format!("wmctrl -a {}", target),
                    summary: format!("已将「{}」窗口切换至前台焦点", profile.name),
                    data: json!({ "target": target }),
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "wmctrl_activate".into(),
                        checks: vec!["wmctrl_exit_0".into()],
                        details: None,
                    },
                });
            }

            // Step (4): Check `/proc` if the app is even running!
            let running_pids = find_running_pids_for_profile_or_hint(Some(profile), target, None);
            if running_pids.is_empty() {
                return Ok(GuiDispatchResult {
                    ok: false,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command: format!("focus_window({})", target),
                    summary: format!(
                        "当前未检测到「{}」在运行（无活动进程或托盘实例），请先启动该应用",
                        profile.name
                    ),
                    data: json!({
                        "target": target,
                        "is_running": false,
                        "running_pids": [],
                    }),
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::VerificationFailed,
                        method: "procfs_and_sni_liveness_check".into(),
                        checks: vec!["no_sni_tray_instance".into(), "no_running_pid".into()],
                        details: Some("application is not running".into()),
                    },
                });
            }

            Ok(GuiDispatchResult {
                ok: false,
                requires_approval: false,
                approval_scope: None,
                channel_used: AdaptationChannel::GuiAtspi,
                translated_command: format!("focus_window({})", target),
                summary: format!(
                    "检测到「{}」进程 (PID {:?}) 正在后台运行，但当前桌面未暴露可激活的顶层窗口或托盘菜单",
                    profile.name, running_pids
                ),
                data: json!({
                    "target": target,
                    "is_running": true,
                    "running_pids": running_pids,
                }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "window_surface_lookup".into(),
                    checks: vec!["pid_running".into(), "no_activatable_surface".into()],
                    details: None,
                },
            })
        }
        "inspect_ui_tree" => {
            let hint = params
                .get("app_hint")
                .and_then(|v| v.as_str())
                .unwrap_or(&profile.id);
            let translated_command = format!("/usr/bin/python3 -I -c <atspi_inspect> {}", hint);

            if use_headless_sim {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command,
                    summary: format!(
                        "已完成「{}」AT-SPI2 无障碍树探测请求（无头/仿真环境预演）",
                        profile.name
                    ),
                    data: json!({
                        "available": false,
                        "simulated": true,
                        "controls": [
                            { "role": "push button", "name": "Menu" },
                            { "role": "entry", "name": "Search" }
                        ]
                    }),
                    simulated: true,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "simulated_headless_atspi".into(),
                        checks: vec!["readonly_atspi_fallback".into()],
                        details: None,
                    },
                });
            }

            if has_dbus_session_address()
                && let Some((true, stdout, _)) =
                    run_gi_python_helper(ATSPI_INSPECT_PY_SCRIPT, &[hint], 2200, false).await
                && let Ok(parsed) = serde_json::from_str::<Value>(stdout.trim())
                && parsed.get("available").and_then(|v| v.as_bool()) == Some(true)
            {
                let count = parsed
                    .get("controls")
                    .and_then(|c| c.as_array())
                    .map(Vec::len)
                    .unwrap_or(0);
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command,
                    summary: format!(
                        "已通过 AT-SPI2 无障碍树探测「{}」界面（发现 {} 个可交互控件）",
                        profile.name, count
                    ),
                    data: parsed,
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "atspi2_tree_inspect".into(),
                        checks: vec!["readonly_atspi_query".into()],
                        details: None,
                    },
                });
            }

            Ok(GuiDispatchResult {
                ok: false,
                requires_approval: false,
                approval_scope: None,
                channel_used: AdaptationChannel::GuiAtspi,
                translated_command,
                summary: format!(
                    "当前桌面未能读取「{}」的 AT-SPI2 无障碍树（请确认应用已启动且开启桌面无障碍支持）",
                    profile.name
                ),
                data: json!({ "available": false, "controls": [] }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "atspi2_tree_inspect".into(),
                    checks: vec![],
                    details: Some("AT-SPI2 bus or Python GI unavailable".into()),
                },
            })
        }
        "click_control" => {
            // Reachable ONLY when `approved == true`
            let ctrl = params
                .get("control")
                .or_else(|| params.get("name"))
                .or_else(|| params.get("label"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("`click_control` 缺少目标控件名参数 `control`"))?;
            if ctrl.chars().any(char::is_control) {
                anyhow::bail!("安全拦截：控件名称包含非法控制字符");
            }
            let translated_command = format!(
                "/usr/bin/python3 -I -c <atspi_do_action> {} {}",
                profile.id, ctrl
            );

            if use_headless_sim {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command,
                    summary: format!(
                        "已在用户授权下完成「{}」控件 `{}` 动作转译（无头/仿真环境预演）",
                        profile.name, ctrl
                    ),
                    data: json!({ "control": ctrl, "approved": true }),
                    simulated: true,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "simulated_approved_atspi_click".into(),
                        checks: vec!["user_approved_true".into()],
                        details: None,
                    },
                });
            }

            if has_dbus_session_address()
                && let Some((true, stdout, _)) =
                    run_gi_python_helper(ATSPI_CLICK_PY_SCRIPT, &[&profile.id, ctrl], 2500, false)
                        .await
            {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command,
                    summary: format!(
                        "已在用户授权下通过 AT-SPI2 触发「{}」控件 `{}`",
                        profile.name, ctrl
                    ),
                    data: json!({
                        "control": ctrl,
                        "approved": true,
                        "output": stdout.trim(),
                    }),
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "atspi2_do_action".into(),
                        checks: vec!["user_approved_true".into(), "atspi_do_action_ok".into()],
                        details: None,
                    },
                });
            }

            Ok(GuiDispatchResult {
                ok: false,
                requires_approval: false,
                approval_scope: None,
                channel_used: AdaptationChannel::GuiAtspi,
                translated_command,
                summary: format!(
                    "在当前桌面未找到「{}」的可交互无障碍控件 `{}`",
                    profile.name, ctrl
                ),
                data: json!({ "control": ctrl, "approved": true }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "atspi2_do_action".into(),
                    checks: vec!["user_approved_true".into()],
                    details: Some("control_not_found_or_app_not_accessible".into()),
                },
            })
        }
        "trigger_shortcut" => {
            // Reachable ONLY when `approved == true` and `validate_shortcut_safety` succeeded
            let raw_sc = params
                .get("shortcut")
                .or_else(|| params.get("keys"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let valid_sc = validate_shortcut_safety(raw_sc)?;
            let xdo_key = valid_sc
                .replace("Ctrl", "ctrl")
                .replace("Shift", "shift")
                .replace("Alt", "alt");
            let translated_command = format!(
                "xdotool search --onlyvisible --class {} windowactivate --sync key --clearmodifiers {}",
                profile.id, xdo_key
            );

            if use_headless_sim {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command,
                    summary: format!(
                        "已在用户授权下完成「{}」应用内快捷键 `{}` 转译（无头/仿真环境预演）",
                        profile.name, valid_sc
                    ),
                    data: json!({ "shortcut": valid_sc, "approved": true }),
                    simulated: true,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "simulated_approved_shortcut".into(),
                        checks: vec![
                            "user_approved_true".into(),
                            "shortcut_safety_validated".into(),
                        ],
                        details: None,
                    },
                });
            }

            if let Some(xdo_bin) = resolve_trusted_executable("xdotool")
                && let Some((true, _, _)) = run_gui_helper(
                    &xdo_bin,
                    &[
                        "search",
                        "--onlyvisible",
                        "--class",
                        &profile.id,
                        "windowactivate",
                        "--sync",
                        "key",
                        "--clearmodifiers",
                        &xdo_key,
                    ],
                    2000,
                )
                .await
            {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command,
                    summary: format!(
                        "已在用户授权下向「{}」窗口发送受限快捷键 `{}`",
                        profile.name, valid_sc
                    ),
                    data: json!({ "shortcut": valid_sc, "approved": true }),
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "xdotool_scoped_key".into(),
                        checks: vec![
                            "user_approved_true".into(),
                            "shortcut_safety_validated".into(),
                        ],
                        details: None,
                    },
                });
            }

            Ok(GuiDispatchResult {
                ok: false,
                requires_approval: false,
                approval_scope: None,
                channel_used: AdaptationChannel::GuiAtspi,
                translated_command,
                summary: format!(
                    "当前图形会话未能向「{}」注入快捷键 `{}`（缺少 `xdotool` 或目标 X11 窗口未运行）",
                    profile.name, valid_sc
                ),
                data: json!({ "shortcut": valid_sc, "approved": true }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "xdotool_scoped_key".into(),
                    checks: vec!["user_approved_true".into()],
                    details: Some("xdotool missing or target window unavailable".into()),
                },
            })
        }
        other => {
            let translated_command =
                format!("atspi-bridge --app {} --action {}", profile.id, other);
            if use_headless_sim {
                return Ok(GuiDispatchResult {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    channel_used: AdaptationChannel::GuiAtspi,
                    translated_command,
                    summary: format!(
                        "已在用户授权下完成「{}」GUI 桥接动作 `{}`（无头/仿真环境预演）",
                        profile.name, other
                    ),
                    data: json!({ "action": other, "approved": true }),
                    simulated: true,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "simulated_approved_gui_action".into(),
                        checks: vec!["user_approved_true".into()],
                        details: None,
                    },
                });
            }

            Ok(GuiDispatchResult {
                ok: false,
                requires_approval: false,
                approval_scope: None,
                channel_used: AdaptationChannel::GuiAtspi,
                translated_command,
                summary: format!(
                    "当前图形会话不支持对「{}」直接执行未映射的 GUI 动作 `{}`",
                    profile.name, other
                ),
                data: json!({ "action": other, "approved": true }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "unsupported_gui_action".into(),
                    checks: vec![],
                    details: None,
                },
            })
        }
    }
}

async fn run_gui_helper(
    bin: &Path,
    args: &[&str],
    timeout_ms: u64,
) -> Option<(bool, String, String)> {
    let mut cmd = Command::new(bin);
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

async fn run_gi_python_helper(
    script: &str,
    extra_args: &[&str],
    timeout_ms: u64,
    force_x11_gdk: bool,
) -> Option<(bool, String, String)> {
    let py_bin = resolve_system_gi_python3()?;
    let mut cmd = Command::new(py_bin);
    apply_clean_desktop_env(&mut cmd);
    if force_x11_gdk {
        cmd.env("GDK_BACKEND", "x11");
    }
    cmd.kill_on_drop(true)
        .args(["-I", "-c", script])
        .args(extra_args)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_adapter::registry::AdapterRegistry;

    #[test]
    fn headless_simulation_predicate_never_triggers_on_live_gui_session() {
        assert!(!should_use_headless_simulation(true, false));
        assert!(should_use_headless_simulation(true, true));
        assert!(should_use_headless_simulation(false, false));
    }

    #[tokio::test]
    async fn focus_window_never_claims_headless_simulation_when_gui_env_is_present() {
        if !has_gui_session() {
            return;
        }
        let reg = AdapterRegistry::load(None);
        let (phantom, _) =
            reg.resolve_adapter_and_action("nonexistent-phantom-gui-app-998877", "focus_window");
        let res = execute_gui_bridge_action(&phantom, "focus_window", &json!({}), false)
            .await
            .unwrap();
        assert!(!res.simulated, "must never simulate on real GUI desktop");
        assert!(!res.ok, "non-running app focus must fail honestly");
        assert_eq!(
            res.verification.state,
            VerificationState::VerificationFailed
        );
        assert!(
            res.summary.contains("当前未检测到") && !res.summary.contains("无头/仿真环境预演"),
            "unexpected summary: {}",
            res.summary
        );
    }
}
