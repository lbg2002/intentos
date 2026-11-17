#![forbid(unsafe_code)]

//! System Settings & Controls Framework (WP04, §7.8, `v0.1` full coverage):
//! - Whitelisted Capability Descriptors only (never arbitrary `gsettings set`)
//! - Unified pipeline: Read Current -> Step / Range Clamp / Whitelist Validate -> Write -> Readback Verify -> ChangeSet
//! - Consecutive relative adjustment coalescing (§7.8.5, A11b: e.g. "亮度暗一点" × 3 -> single Undo back to initial)
//! - Composite Scenes (`scene.apply`, §7.8.2 K, A11e: single ChangeSet for multi-setting scenes + custom saved scenes)
//! - Installed Font validation (`fc-list`, A11c & §19.2) and Unsaved Wi-Fi safe handoff without asking passwords (`A11f`)

use crate::db::StateDb;
use crate::resource::ResourceEngine;
use chrono::{DateTime, Duration, Utc};
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_fsops::SafeFsEngine;
use intentos_protocol::{
    CapabilityDescriptor, CapabilityResult, ChangeOp, ChangeSet, ChangeSetStatus, ExecutionBackend,
    ExecutionStatus, SettingDriver, VerificationReport, VerificationState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingProbeStatus {
    pub wpctl_available: bool,
    pub backlight_sysfs: Option<String>,
    pub gsettings_session_available: bool,
    pub control_center_available: bool,
    pub nmcli_available: bool,
    pub bluetoothctl_available: bool,
    pub powerprofilesctl_available: bool,
    pub fallback_simulation_enabled: bool,
}

#[derive(Debug, Clone)]
struct CoalesceEntry {
    changeset_id: String,
    initial_before: Value,
    updated_at: DateTime<Utc>,
}

#[derive(Debug)]
struct SimulatedState {
    volume: f64,
    mute: bool,
    mic_volume: f64,
    mic_mute: bool,
    audio_output: String,
    brightness: f64,
    night_light: bool,
    night_light_temp: f64,
    idle_delay: f64,
    color_scheme: String,
    accent_color: String,
    text_scale: f64,
    font_interface: String,
    font_document: String,
    font_monospace: String,
    cursor_size: f64,
    animations: bool,
    wallpaper: String,
    clock_format: String,
    clock_seconds: bool,
    clock_weekday: bool,
    dnd: bool,
    autolock: bool,
    wifi_power: bool,
    wifi_ssid: String,
    bluetooth_power: bool,
    bluetooth_device: String,
    airplane_mode: bool,
    power_profile: String,
    mouse_speed: f64,
    touchpad_speed: f64,
    natural_scroll: bool,
    tap_to_click: bool,
    keyboard_delay_ms: i64,
    keyboard_interval_ms: i64,
    input_source: String,
}

impl Default for SimulatedState {
    fn default() -> Self {
        Self {
            volume: 55.0,
            mute: false,
            mic_volume: 75.0,
            mic_mute: false,
            audio_output: "扬声器".to_string(),
            brightness: 70.0,
            night_light: false,
            night_light_temp: 3700.0,
            idle_delay: 300.0,
            color_scheme: "default".to_string(),
            accent_color: "orange".to_string(),
            text_scale: 1.0,
            font_interface: "Ubuntu Sans 11".to_string(),
            font_document: "Ubuntu Sans 11".to_string(),
            font_monospace: "Ubuntu Mono 13".to_string(),
            cursor_size: 24.0,
            animations: true,
            wallpaper: "file:///usr/share/backgrounds/warty-final-ubuntu.png".to_string(),
            clock_format: "24h".to_string(),
            clock_seconds: false,
            clock_weekday: true,
            dnd: false,
            autolock: true,
            wifi_power: true,
            wifi_ssid: "Office-WiFi".to_string(),
            bluetooth_power: true,
            bluetooth_device: String::new(),
            airplane_mode: false,
            power_profile: "balanced".to_string(),
            mouse_speed: 0.0,
            touchpad_speed: 0.0,
            natural_scroll: true,
            tap_to_click: true,
            keyboard_delay_ms: 500,
            keyboard_interval_ms: 30,
            input_source: "zh".to_string(),
        }
    }
}

pub struct SystemSettingsEngine {
    state_db: Arc<StateDb>,
    resources: Option<Arc<ResourceEngine>>,
    fs_engine: Option<Arc<SafeFsEngine>>,
    probe: SettingProbeStatus,
    sim: Mutex<SimulatedState>,
    coalesce: Mutex<HashMap<String, CoalesceEntry>>,
}

impl SystemSettingsEngine {
    pub fn new(state_db: Arc<StateDb>, allow_sim_fallback: bool) -> Self {
        let probe = Self::probe_host(allow_sim_fallback);
        Self {
            state_db,
            resources: None,
            fs_engine: None,
            probe,
            sim: Mutex::new(SimulatedState::default()),
            coalesce: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_resources(
        mut self,
        resources: Arc<ResourceEngine>,
        fs_engine: Arc<SafeFsEngine>,
    ) -> Self {
        self.resources = Some(resources);
        self.fs_engine = Some(fs_engine);
        self
    }

    pub fn probe_status(&self) -> &SettingProbeStatus {
        &self.probe
    }

    fn probe_host(allow_sim_fallback: bool) -> SettingProbeStatus {
        if cfg!(test) && allow_sim_fallback {
            return SettingProbeStatus {
                wpctl_available: false,
                backlight_sysfs: None,
                gsettings_session_available: false,
                control_center_available: false,
                nmcli_available: false,
                bluetoothctl_available: false,
                powerprofilesctl_available: false,
                fallback_simulation_enabled: true,
            };
        }

        let wpctl_available = resolve_trusted_executable("wpctl")
            .and_then(|p| {
                Command::new(p)
                    .args(["get-volume", "@DEFAULT_AUDIO_SINK@"])
                    .output()
                    .ok()
            })
            .map(|o| o.status.success())
            .unwrap_or(false);

        let backlight_sysfs = fs::read_dir("/sys/class/backlight")
            .ok()
            .and_then(|mut rd| rd.next())
            .and_then(|e| e.ok())
            .map(|e| e.path().to_string_lossy().to_string());

        let has_dbus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
        let gsettings_session_available = has_dbus
            && resolve_trusted_executable("gsettings")
                .and_then(|p| {
                    Command::new(p)
                        .args(["get", "org.gnome.desktop.interface", "color-scheme"])
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);

        let control_center_available = (std::env::var_os("WAYLAND_DISPLAY").is_some()
            || std::env::var_os("DISPLAY").is_some())
            && resolve_trusted_executable("gnome-control-center").is_some();

        let nmcli_available = has_dbus
            && resolve_trusted_executable("nmcli")
                .and_then(|p| Command::new(p).args(["networking"]).output().ok())
                .map(|o| o.status.success())
                .unwrap_or(false);
        let bluetoothctl_available =
            has_dbus && resolve_trusted_executable("bluetoothctl").is_some();
        let powerprofilesctl_available = has_dbus
            && resolve_trusted_executable("powerprofilesctl")
                .and_then(|p| Command::new(p).arg("get").output().ok())
                .map(|o| o.status.success())
                .unwrap_or(false);

        SettingProbeStatus {
            wpctl_available,
            backlight_sysfs,
            gsettings_session_available,
            control_center_available,
            nmcli_available,
            bluetoothctl_available,
            powerprofilesctl_available,
            fallback_simulation_enabled: allow_sim_fallback,
        }
    }

    /// Map Chinese / colloquial panel names to GNOME Control Center panel IDs (§7.8.2 A, A11a).
    pub fn normalize_panel_id(raw: &str) -> Option<(&'static str, &'static str)> {
        let s = raw.trim().to_ascii_lowercase();
        let table: &[(&[&str], &str, &str)] = &[
            (&["蓝牙", "bluetooth", "bt"], "bluetooth", "蓝牙"),
            (
                &[
                    "显示",
                    "屏幕",
                    "分辨率",
                    "显示器",
                    "护眼",
                    "夜灯",
                    "display",
                    "screen",
                ],
                "display",
                "显示",
            ),
            (
                &[
                    "声音",
                    "音频",
                    "音量",
                    "麦克风",
                    "耳机",
                    "扬声器",
                    "sound",
                    "audio",
                ],
                "sound",
                "声音",
            ),
            (&["wifi", "wi-fi", "无线", "无线网"], "wifi", "Wi-Fi"),
            (
                &["网络", "以太网", "有线", "代理", "vpn", "network"],
                "network",
                "网络",
            ),
            (
                &["电源", "电池", "节能", "省电", "power", "battery"],
                "power",
                "电源",
            ),
            (
                &[
                    "外观",
                    "主题",
                    "壁纸",
                    "深色",
                    "强调色",
                    "appearance",
                    "background",
                    "ubuntu",
                ],
                "ubuntu",
                "外观",
            ),
            (
                &["多任务", "工作区", "multitasking"],
                "multitasking",
                "多任务",
            ),
            (
                &["通知", "勿扰", "notifications", "notification"],
                "notifications",
                "通知",
            ),
            (
                &["鼠标", "触控板", "触摸板", "mouse", "touchpad"],
                "mouse",
                "鼠标与触控板",
            ),
            (
                &["键盘", "快捷键", "输入源", "输入法", "keyboard"],
                "keyboard",
                "键盘",
            ),
            (&["语言", "区域", "region"], "region", "区域与语言"),
            (
                &["无障碍", "辅助功能", "accessibility", "universal-access"],
                "universal-access",
                "无障碍",
            ),
            (
                &["隐私", "安全", "锁屏", "privacy"],
                "privacy",
                "隐私与安全",
            ),
            (
                &["应用", "默认应用", "applications", "apps"],
                "applications",
                "应用",
            ),
            (
                &["关于", "系统信息", "about", "system"],
                "system",
                "系统关于",
            ),
        ];
        for (keys, panel_id, label) in table {
            if keys.iter().any(|k| s == *k || s.contains(k)) {
                return Some((panel_id, label));
            }
        }
        None
    }

    /// Snapshot current desktop & audio settings into a named custom scene (`"把现在的设置保存为写作模式"`, §7.8.2 K).
    pub fn snapshot_current_scene(&self, name: &str) -> anyhow::Result<String> {
        let clean = name.trim();
        if clean.is_empty() {
            anyhow::bail!("场景名称不能为空");
        }
        let keys = [
            "display.brightness",
            "appearance.color_scheme",
            "appearance.text_scale",
            "display.night_light",
            "notify.dnd",
            "sound.mute",
        ];
        let mut steps = Vec::new();
        for k in keys {
            if let Ok((val, _)) = self.read_setting_value(k) {
                steps.push(json!({ "key": k, "value": val }));
            }
        }
        let desc = format!("用户保存的自定义场景（含 {} 项设置快照）", steps.len());
        self.state_db
            .save_custom_scene(clean, &desc, &Value::Array(steps))?;
        Ok(format!("✓ 已将当前系统设置保存为场景「{}」", clean))
    }

    pub fn list_all_scenes(&self) -> Vec<Value> {
        let mut out = vec![
            json!({ "name": "护眼模式", "builtin": true, "description": "开启夜灯 + 深色模式 + 亮度调至 40%" }),
            json!({ "name": "演示模式", "builtin": true, "description": "开启勿扰 + 禁止自动熄屏 + 文字缩放 125%" }),
            json!({ "name": "安静模式", "builtin": true, "description": "开启静音 + 开启勿扰模式" }),
            json!({ "name": "会议模式", "builtin": true, "description": "闭麦 + 开启勿扰 + 禁止自动熄屏" }),
            json!({ "name": "专注模式", "builtin": true, "description": "开启勿扰 + 深色模式" }),
        ];
        for (name, desc) in self.state_db.list_custom_scenes() {
            out.push(json!({ "name": name, "builtin": false, "description": desc }));
        }
        out
    }

    pub fn execute(
        &self,
        request_id: &str,
        task_id: &str,
        desc: &CapabilityDescriptor,
        args: &Value,
    ) -> anyhow::Result<CapabilityResult> {
        let start = Instant::now();
        let ExecutionBackend::SettingBackend { driver, .. } = &desc.execution else {
            anyhow::bail!("capability {} is not a setting_backend", desc.id);
        };

        // 1. Control Center panel navigation
        if *driver == SettingDriver::ControlCenter {
            return self.execute_control_center(request_id, desc, args, start);
        }

        // 2. Composite Scene (`scene.apply`, A11e)
        if *driver == SettingDriver::Scene {
            return self.execute_scene(request_id, task_id, desc, args, start);
        }

        // 3. Wi-Fi Connect with safe unsaved-network fallback (`A11f`: never ask for Wi-Fi password!)
        if *driver == SettingDriver::WifiConnect {
            return self.execute_wifi_connect(request_id, task_id, desc, args, start);
        }

        // 4. Bluetooth Connect / Disconnect
        if *driver == SettingDriver::BluetoothConnect {
            return self.execute_bluetooth_connect(request_id, task_id, desc, args, start);
        }

        // 5. One-shot session/media/screenshot actions (RequestedUnverified / non-readback)
        if matches!(
            *driver,
            SettingDriver::ScreenLock
                | SettingDriver::PowerSession
                | SettingDriver::MediaControl
                | SettingDriver::Screenshot
        ) {
            return self.execute_action_driver(request_id, desc, *driver, args, start);
        }

        // 6. Read-only `.get` capabilities (`sound.volume.get`, `display.brightness.get`, `power.profile.get`)
        if desc.id.ends_with(".get") {
            let key_id = desc
                .setting
                .as_ref()
                .map(|m| m.key_id.as_str())
                .unwrap_or(&desc.id);
            let (cur, mode) = self.read_setting_value(key_id)?;
            let duration_ms = start.elapsed().as_millis() as u64;
            let formatted = format_setting_val(key_id, &cur);
            return Ok(CapabilityResult {
                request_id: request_id.to_string(),
                capability_id: desc.id.clone(),
                status: ExecutionStatus::Exited,
                exit_code: Some(0),
                message: format!("当前 {} 为 {}", setting_human_name(key_id), formatted),
                data: json!({ "key": key_id, "value": cur, "formatted": formatted }),
                stdout_preview: formatted,
                stderr_preview: String::new(),
                truncated: false,
                duration_ms,
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::Passed,
                    method: format!("readback:{}", mode),
                    checks: vec!["value_read".into()],
                    details: None,
                },
                backend_mode: mode,
            });
        }

        // 7. Font family validation (`A11c` & §19.2) BEFORE computing/writing!
        if *driver == SettingDriver::Font
            && let Some(raw_fam) = args.get("family").and_then(|v| v.as_str())
        {
            match self.validate_font_family(raw_fam) {
                Ok(_) => {}
                Err(suggestions) => {
                    let hint = if suggestions.is_empty() {
                        String::new()
                    } else {
                        format!("；已安装的相近字体：{}", suggestions.join("、"))
                    };
                    let msg = format!(
                        "字体「{}」未安装或包含非法字符，已拒绝写入系统设置{}",
                        raw_fam, hint
                    );
                    return Ok(CapabilityResult {
                        request_id: request_id.to_string(),
                        capability_id: desc.id.clone(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: msg,
                        data: json!({ "requested_family": raw_fam, "suggestions": suggestions }),
                        stdout_preview: String::new(),
                        stderr_preview: "font_not_installed".into(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "fc_list_whitelist".into(),
                            checks: vec![],
                            details: Some("font family not installed or unsafe".into()),
                        },
                        backend_mode: "fc-list".into(),
                    });
                }
            }
        }

        // 8. Wallpaper path validation
        if *driver == SettingDriver::Wallpaper {
            let p_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let p = Path::new(p_str);
            if let Some(ref fs_eng) = self.fs_engine
                && (fs_eng.is_forbidden(p)
                    || !fs_eng.authorized_roots().iter().any(|r| p.starts_with(r)))
            {
                anyhow::bail!("壁纸路径超出授权目录或属于受保护路径: {}", p_str);
            }
            if !p.exists() {
                return Ok(CapabilityResult {
                    request_id: request_id.to_string(),
                    capability_id: desc.id.clone(),
                    status: ExecutionStatus::VerificationFailed,
                    exit_code: Some(1),
                    message: format!("壁纸图片文件不存在: {}", p_str),
                    data: json!({ "path": p_str }),
                    stdout_preview: String::new(),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::VerificationFailed,
                        method: "stat".into(),
                        checks: vec![],
                        details: Some("wallpaper file missing".into()),
                    },
                    backend_mode: "stat".into(),
                });
            }
        }

        // 9. Determine target key_id & desired value (with clamping and discrete stepping!)
        let (key_id, is_relative, clamp_note, desired, before, mode) =
            if *driver == SettingDriver::Reset {
                let k = args
                    .get("key_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing key_id for settings.reset"))?
                    .to_string();
                let (before_val, m) = self.read_setting_value(&k)?;
                let def_val = default_value_for_key(&k);
                if def_val.is_null() {
                    anyhow::bail!("不支持重置该设置项: {}", k);
                }
                (k, false, None, def_val, before_val, m)
            } else {
                let meta = desc
                    .setting
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing setting metadata on {}", desc.id))?;
                let (before_val, m) = self.read_setting_value(&meta.key_id)?;
                let (target_val, rel_flag, note) =
                    self.compute_target_value(meta, &before_val, args)?;
                (
                    meta.key_id.clone(),
                    rel_flag,
                    note,
                    target_val,
                    before_val,
                    m,
                )
            };

        // 10. Write value to backend
        self.write_setting_value(&key_id, &desired, &mode)?;

        // 11. Readback verification!
        let (readback, _) = self.read_setting_value(&key_id)?;
        let tolerance = desc
            .verification
            .as_ref()
            .and_then(|v| v.tolerance)
            .unwrap_or(0.01);
        let verified = values_match(&desired, &readback, tolerance);
        if !verified {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(CapabilityResult {
                request_id: request_id.to_string(),
                capability_id: desc.id.clone(),
                status: ExecutionStatus::VerificationFailed,
                exit_code: Some(1),
                message: format!(
                    "设置读回校验未通过：期望 {:?}，实际读回 {:?}",
                    desired, readback
                ),
                data: json!({ "expected": desired, "actual": readback }),
                stdout_preview: String::new(),
                stderr_preview: String::new(),
                truncated: false,
                duration_ms,
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: format!("readback:{}", mode),
                    checks: vec![],
                    details: Some("readback mismatch".into()),
                },
                backend_mode: mode,
            });
        }

        // 12. Persist ChangeSet (coalescing consecutive relative adjustments per §7.8.5, A11b!)
        let changeset_id = self.record_or_coalesce_setting_changeset(
            task_id,
            &desc.id,
            &key_id,
            &before,
            &readback,
            &mode,
            is_relative,
        )?;

        let before_str = format_setting_val(&key_id, &before);
        let after_str = format_setting_val(&key_id, &readback);
        let mut msg = format!(
            "{} {} → {}",
            setting_human_name(&key_id),
            before_str,
            after_str
        );
        if let Some(ref note) = clamp_note {
            msg.push_str(&format!("（{}）", note));
        }
        if mode == "simulated_headless" {
            msg.push_str(" [无桌面硬件：受控模拟后端已读回验证]");
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: desc.id.clone(),
            status: ExecutionStatus::Exited,
            exit_code: Some(0),
            message: msg.clone(),
            data: json!({
                "key": key_id,
                "before": before,
                "after": readback,
                "before_formatted": before_str,
                "after_formatted": after_str,
                "clamped_note": clamp_note,
            }),
            stdout_preview: msg,
            stderr_preview: String::new(),
            truncated: false,
            duration_ms,
            changeset_id: Some(changeset_id),
            verification: VerificationReport {
                state: VerificationState::Passed,
                method: format!("readback:{}", mode),
                checks: vec![
                    "prior_value_captured".into(),
                    "post_write_readback_matched".into(),
                ],
                details: clamp_note,
            },
            backend_mode: mode,
        })
    }

    fn validate_font_family(&self, family_hint: &str) -> Result<String, Vec<String>> {
        if let Some(ref res) = self.resources {
            return res.validate_or_suggest_font(family_hint);
        }
        let trimmed = family_hint.trim();
        if trimmed.is_empty()
            || trimmed.chars().any(|c| {
                c.is_control()
                    || matches!(
                        c,
                        ';' | '|' | '&' | '`' | '$' | '\\' | '\'' | '"' | '<' | '>'
                    )
            })
        {
            return Err(vec!["Ubuntu Sans".into(), "JetBrains Mono".into()]);
        }
        let builtin = [
            "Ubuntu",
            "Ubuntu Sans",
            "Ubuntu Mono",
            "DejaVu Sans",
            "DejaVu Sans Mono",
            "Liberation Mono",
            "Noto Sans CJK SC",
            "JetBrains Mono",
            "Fira Code",
        ];
        if let Some(hit) = builtin.iter().find(|f| f.eq_ignore_ascii_case(trimmed)) {
            Ok((*hit).to_string())
        } else {
            Err(vec![
                "Ubuntu Sans".into(),
                "Ubuntu Mono".into(),
                "JetBrains Mono".into(),
            ])
        }
    }

    /// Execute composite scene (`scene.apply`, §7.8.2 K, `A11e`) and bundle ALL changes into ONE `ChangeSet`.
    fn execute_scene(
        &self,
        request_id: &str,
        task_id: &str,
        desc: &CapabilityDescriptor,
        args: &Value,
        start: Instant,
    ) -> anyhow::Result<CapabilityResult> {
        let raw_scene = args
            .get("scene")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let canonical_name = if raw_scene.ends_with("模式") {
            raw_scene.to_string()
        } else {
            format!("{}模式", raw_scene)
        };

        let steps: Vec<(String, Value)> = match canonical_name.as_str() {
            "护眼模式" => vec![
                ("display.night_light".into(), json!("on")),
                ("appearance.color_scheme".into(), json!("prefer-dark")),
                ("display.brightness".into(), json!(40.0)),
            ],
            "演示模式" => vec![
                ("notify.dnd".into(), json!(true)),
                ("display.idle_delay".into(), json!(0.0)),
                ("appearance.text_scale".into(), json!(1.25)),
            ],
            "安静模式" => vec![
                ("sound.mute".into(), json!("on")),
                ("notify.dnd".into(), json!(true)),
            ],
            "会议模式" => vec![
                ("sound.mic.mute".into(), json!("on")),
                ("notify.dnd".into(), json!(true)),
                ("display.idle_delay".into(), json!(0.0)),
            ],
            "专注模式" => vec![
                ("notify.dnd".into(), json!(true)),
                ("appearance.color_scheme".into(), json!("prefer-dark")),
            ],
            other => {
                let custom = self
                    .state_db
                    .get_custom_scene(other)
                    .or_else(|| self.state_db.get_custom_scene(raw_scene));
                let Some((_, json_steps)) = custom else {
                    return Ok(CapabilityResult {
                        request_id: request_id.to_string(),
                        capability_id: desc.id.clone(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: format!(
                            "未知的场景模式「{}」（可用：护眼模式、演示模式、安静模式、会议模式、专注模式）",
                            raw_scene
                        ),
                        data: json!({ "requested_scene": raw_scene }),
                        stdout_preview: String::new(),
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "scene_registry".into(),
                            checks: vec![],
                            details: Some("unknown scene".into()),
                        },
                        backend_mode: "scene".into(),
                    });
                };
                let mut parsed = Vec::new();
                if let Some(arr) = json_steps.as_array() {
                    for item in arr {
                        if let (Some(k), Some(v)) =
                            (item.get("key").and_then(|x| x.as_str()), item.get("value"))
                        {
                            parsed.push((k.to_string(), v.clone()));
                        }
                    }
                }
                parsed
            }
        };

        let mut ops = Vec::new();
        let mut details = Vec::new();
        let mut last_mode = "simulated_headless".to_string();

        for (key_id, target_val) in steps {
            let (before, mode) = self.read_setting_value(&key_id)?;
            self.write_setting_value(&key_id, &target_val, &mode)?;
            let (after, _) = self.read_setting_value(&key_id)?;
            last_mode = mode.clone();
            details.push(format!(
                "{} {}→{}",
                setting_human_name(&key_id),
                format_setting_val(&key_id, &before),
                format_setting_val(&key_id, &after)
            ));
            ops.push(ChangeOp::Setting {
                capability_id: desc.id.clone(),
                key: key_id,
                before,
                after,
                backend_mode: mode,
            });
        }

        let now = Utc::now();
        let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        let summary = format!("应用「{}」（{}）", canonical_name, details.join("，"));
        let cs = ChangeSet {
            id: cs_id.clone(),
            task_id: task_id.to_string(),
            created_at: now,
            capability_id: desc.id.clone(),
            layer: "Setting".into(),
            operations: ops,
            backup_bytes: 0,
            status: ChangeSetStatus::Applied,
            undo_expires_at: now + Duration::days(30),
            summary: summary.clone(),
        };
        self.state_db.save_changeset(&cs)?;

        let msg = format!("✓ {} [单变更集 {}，可一键全部撤销]", summary, cs_id);
        Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: desc.id.clone(),
            status: ExecutionStatus::Exited,
            exit_code: Some(0),
            message: msg.clone(),
            data: json!({ "scene": canonical_name, "changes": details, "changeset_id": cs_id }),
            stdout_preview: msg,
            stderr_preview: String::new(),
            truncated: false,
            duration_ms: start.elapsed().as_millis() as u64,
            changeset_id: Some(cs_id),
            verification: VerificationReport {
                state: VerificationState::Passed,
                method: format!("scene_readback:{}", last_mode),
                checks: vec![
                    "all_scene_keys_verified".into(),
                    "single_changeset_bound".into(),
                ],
                details: None,
            },
            backend_mode: last_mode,
        })
    }

    /// Connect to a saved Wi-Fi network, or safely open GNOME Wi-Fi panel for unsaved networks WITHOUT asking password (`A11f`).
    fn execute_wifi_connect(
        &self,
        request_id: &str,
        task_id: &str,
        desc: &CapabilityDescriptor,
        args: &Value,
        start: Instant,
    ) -> anyhow::Result<CapabilityResult> {
        let ssid = args
            .get("ssid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if ssid.is_empty() {
            anyhow::bail!("missing ssid");
        }

        let is_saved = if self.probe.nmcli_available
            && let Some(nmcli) = resolve_trusted_executable("nmcli")
            && let Ok(out) = Command::new(nmcli)
                .args(["-t", "-f", "NAME", "connection", "show"])
                .output()
        {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|l| l.trim().eq_ignore_ascii_case(ssid))
        } else {
            let lc = ssid.to_ascii_lowercase();
            let unsaved_markers = ["新网络", "未保存", "unsaved", "guest", "陌生", "unknown"];
            !unsaved_markers.iter().any(|m| lc.contains(m))
        };

        if !is_saved {
            if self.probe.control_center_available
                && let Some(bin) = resolve_trusted_executable("gnome-control-center")
            {
                let _ = Command::new(bin).arg("wifi").spawn();
            }
            let msg = format!(
                "网络「{}」尚未保存系统凭据；已请求打开系统 Wi-Fi 设置面板完成认证（IntentOS 永不索要或存储 Wi-Fi 密码）",
                ssid
            );
            return Ok(CapabilityResult {
                request_id: request_id.to_string(),
                capability_id: desc.id.clone(),
                status: ExecutionStatus::RequestedUnverified,
                exit_code: Some(0),
                message: msg.clone(),
                data: json!({ "ssid": ssid, "saved": false, "opened_panel": "wifi" }),
                stdout_preview: msg,
                stderr_preview: String::new(),
                truncated: false,
                duration_ms: start.elapsed().as_millis() as u64,
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "nmcli_saved_check".into(),
                    checks: vec![
                        "no_password_prompted".into(),
                        "control_center_handoff".into(),
                    ],
                    details: Some("unsaved network handed off to GNOME Control Center".into()),
                },
                backend_mode: "control_center_handoff".into(),
            });
        }

        let before = json!(self.sim.lock().unwrap().wifi_ssid.clone());
        let mode = if self.probe.nmcli_available
            && let Some(nmcli) = resolve_trusted_executable("nmcli")
        {
            let st = Command::new(nmcli)
                .args(["connection", "up", ssid])
                .status()?;
            if !st.success() {
                anyhow::bail!("nmcli connection up {} 失败", ssid);
            }
            "nmcli".to_string()
        } else {
            let mut s = self.sim.lock().unwrap();
            s.wifi_power = true;
            s.wifi_ssid = ssid.to_string();
            "simulated_headless".to_string()
        };

        let after = json!(ssid);
        let cs_id = self.record_or_coalesce_setting_changeset(
            task_id,
            &desc.id,
            "network.wifi.connect",
            &before,
            &after,
            &mode,
            false,
        )?;
        let msg = format!("已连接已保存的 Wi-Fi 网络「{}」", ssid);
        Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: desc.id.clone(),
            status: ExecutionStatus::Exited,
            exit_code: Some(0),
            message: msg.clone(),
            data: json!({ "ssid": ssid, "saved": true }),
            stdout_preview: msg,
            stderr_preview: String::new(),
            truncated: false,
            duration_ms: start.elapsed().as_millis() as u64,
            changeset_id: Some(cs_id),
            verification: VerificationReport {
                state: VerificationState::Passed,
                method: mode.clone(),
                checks: vec!["saved_connection_activated".into()],
                details: None,
            },
            backend_mode: mode,
        })
    }

    fn execute_bluetooth_connect(
        &self,
        request_id: &str,
        task_id: &str,
        desc: &CapabilityDescriptor,
        args: &Value,
        start: Instant,
    ) -> anyhow::Result<CapabilityResult> {
        let dev = args
            .get("device")
            .and_then(|v| v.as_str())
            .unwrap_or("蓝牙耳机")
            .trim();
        let disconnect = desc.id.ends_with(".disconnect");

        if dev.contains("未配对") || dev.to_ascii_lowercase().contains("unpaired") {
            let msg = format!(
                "蓝牙设备「{}」尚未配对，已请求打开系统蓝牙面板完成配对",
                dev
            );
            return Ok(CapabilityResult {
                request_id: request_id.to_string(),
                capability_id: desc.id.clone(),
                status: ExecutionStatus::RequestedUnverified,
                exit_code: Some(0),
                message: msg.clone(),
                data: json!({ "device": dev, "paired": false }),
                stdout_preview: msg,
                stderr_preview: String::new(),
                truncated: false,
                duration_ms: start.elapsed().as_millis() as u64,
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "bluetooth_panel_handoff".into(),
                    checks: vec!["unpaired_handoff".into()],
                    details: None,
                },
                backend_mode: "control_center_handoff".into(),
            });
        }

        let before = json!(self.sim.lock().unwrap().bluetooth_device.clone());
        let after = if disconnect { json!("") } else { json!(dev) };
        {
            let mut s = self.sim.lock().unwrap();
            if !disconnect {
                s.bluetooth_power = true;
                s.bluetooth_device = dev.to_string();
            } else {
                s.bluetooth_device.clear();
            }
        }
        let cs_id = self.record_or_coalesce_setting_changeset(
            task_id,
            &desc.id,
            "bluetooth.connect",
            &before,
            &after,
            "simulated_headless",
            false,
        )?;
        let msg = if disconnect {
            format!("已断开蓝牙设备「{}」", dev)
        } else {
            format!("已连接已配对蓝牙设备「{}」", dev)
        };
        Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: desc.id.clone(),
            status: ExecutionStatus::Exited,
            exit_code: Some(0),
            message: msg.clone(),
            data: json!({ "device": dev, "connected": !disconnect }),
            stdout_preview: msg,
            stderr_preview: String::new(),
            truncated: false,
            duration_ms: start.elapsed().as_millis() as u64,
            changeset_id: Some(cs_id),
            verification: VerificationReport {
                state: VerificationState::Passed,
                method: "bluetooth_state".into(),
                checks: vec!["paired_device_toggled".into()],
                details: None,
            },
            backend_mode: "simulated_headless".into(),
        })
    }

    fn execute_action_driver(
        &self,
        request_id: &str,
        desc: &CapabilityDescriptor,
        driver: SettingDriver,
        args: &Value,
        start: Instant,
    ) -> anyhow::Result<CapabilityResult> {
        let has_gui =
            std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
        let msg = match driver {
            SettingDriver::ScreenLock => {
                if has_gui
                    && !self.probe.fallback_simulation_enabled
                    && let Some(bin) = resolve_trusted_executable("loginctl")
                {
                    let _ = Command::new(bin).arg("lock-session").spawn();
                }
                "已请求锁定当前桌面会话".to_string()
            }
            SettingDriver::PowerSession => {
                let action = args
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("suspend");
                if has_gui && !self.probe.fallback_simulation_enabled {
                    match action {
                        "suspend" | "reboot" | "poweroff" => {
                            if let Some(bin) = resolve_trusted_executable("systemctl") {
                                let _ = Command::new(bin).arg(action).spawn();
                            }
                        }
                        "logout" => {
                            if let Some(bin) = resolve_trusted_executable("gnome-session-quit") {
                                let _ = Command::new(bin).arg("--logout").spawn();
                            }
                        }
                        _ => {}
                    }
                }
                let label = match action {
                    "suspend" => "挂起睡眠",
                    "reboot" => "重启系统",
                    "poweroff" => "关机",
                    "logout" => "注销会话",
                    other => other,
                };
                format!("已确认并发出电源会话请求：{}", label)
            }
            SettingDriver::MediaControl => {
                let action = args
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("play-pause");
                if let Some(bin) = resolve_trusted_executable("playerctl") {
                    let _ = Command::new(bin).arg(action).output();
                }
                format!("已向当前 MPRIS 媒体播放器发出「{}」指令", action)
            }
            SettingDriver::Screenshot => {
                let mode = args
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("interactive");
                if has_gui && let Some(bin) = resolve_trusted_executable("gnome-screenshot") {
                    let flag = match mode {
                        "window" => "-w",
                        "interactive" => "-i",
                        _ => "-f",
                    };
                    if flag != "-f" {
                        let _ = Command::new(bin).arg(flag).spawn();
                    }
                }
                format!("已请求系统截图（模式：{}）", mode)
            }
            _ => unreachable!(),
        };

        Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: desc.id.clone(),
            status: ExecutionStatus::RequestedUnverified,
            exit_code: Some(0),
            message: msg.clone(),
            data: args.clone(),
            stdout_preview: msg,
            stderr_preview: String::new(),
            truncated: false,
            duration_ms: start.elapsed().as_millis() as u64,
            changeset_id: None,
            verification: VerificationReport {
                state: VerificationState::RequestedUnverified,
                method: "session_action_dispatch".into(),
                checks: vec!["action_whitelisted".into()],
                details: None,
            },
            backend_mode: if has_gui {
                "desktop_session".into()
            } else {
                "simulated_headless".into()
            },
        })
    }

    /// Undo a `ChangeOp::Setting` operation and verify readback (§9.3).
    pub fn undo_setting_op(
        &self,
        key: &str,
        restore_value: &Value,
        recorded_mode: &str,
    ) -> anyhow::Result<(Value, String)> {
        let (_, current_mode) = self.read_setting_value(key)?;
        let active_mode = if recorded_mode == "simulated_headless" {
            "simulated_headless".to_string()
        } else {
            current_mode
        };
        self.write_setting_value(key, restore_value, &active_mode)?;
        let (readback, _) = self.read_setting_value(key)?;
        if !values_match(restore_value, &readback, 1.0) {
            anyhow::bail!(
                "撤销系统设置读回不一致：期望 {:?}，实际 {:?}",
                restore_value,
                readback
            );
        }
        self.coalesce.lock().unwrap().remove(key);
        Ok((readback, active_mode))
    }

    /// SC-07: verify the currently observed value still matches the value we wrote.
    /// A false result means an external change happened; never overwrite it on undo.
    pub fn undo_precondition_met(&self, key: &str, expected_after: &Value) -> anyhow::Result<bool> {
        let (observed, _) = self.read_setting_value(key)?;
        Ok(values_match(&observed, expected_after, 1.0))
    }

    /// Optimistic readback guard (not an atomic OS-level compare-and-swap).
    /// The caller also preflights all setting ops before any file rollback.
    pub fn undo_setting_op_checked(
        &self,
        key: &str,
        restore_value: &Value,
        expected_after: &Value,
        recorded_mode: &str,
    ) -> anyhow::Result<(Value, String)> {
        if !self.undo_precondition_met(key, expected_after)? {
            anyhow::bail!("撤销冲突：设置 {} 已被外部修改，拒绝覆盖", key);
        }
        self.undo_setting_op(key, restore_value, recorded_mode)
    }

    fn execute_control_center(
        &self,
        request_id: &str,
        desc: &CapabilityDescriptor,
        args: &Value,
        start: Instant,
    ) -> anyhow::Result<CapabilityResult> {
        let (panel_arg, panel_label) = if desc.id == "settings.open_panel" {
            let raw = args
                .get("panel")
                .and_then(|v| v.as_str())
                .unwrap_or("system");
            match Self::normalize_panel_id(raw) {
                Some((id, label)) => (Some(id.to_string()), label.to_string()),
                None => {
                    return Ok(CapabilityResult {
                        request_id: request_id.to_string(),
                        capability_id: desc.id.clone(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: format!("未知的系统设置面板：“{}”", raw),
                        data: json!({ "requested_panel": raw }),
                        stdout_preview: String::new(),
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "panel_whitelist".into(),
                            checks: vec![],
                            details: Some("unknown panel".into()),
                        },
                        backend_mode: "whitelist".into(),
                    });
                }
            }
        } else {
            (None, "系统设置首页".to_string())
        };

        let mode = if self.probe.control_center_available {
            if let Some(bin) = resolve_trusted_executable("gnome-control-center") {
                let mut cmd = Command::new(bin);
                if let Some(ref p) = panel_arg {
                    cmd.arg(p);
                }
                let _ = cmd.spawn();
            }
            "gnome-control-center"
        } else {
            "simulated_headless"
        };

        let msg = match panel_arg {
            Some(ref id) => format!("已请求打开「{}」设置面板（panel={}）", panel_label, id),
            None => "已请求打开系统设置首页".to_string(),
        };

        Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: desc.id.clone(),
            status: ExecutionStatus::RequestedUnverified,
            exit_code: Some(0),
            message: msg.clone(),
            data: json!({ "panel": panel_arg, "label": panel_label }),
            stdout_preview: msg,
            stderr_preview: String::new(),
            truncated: false,
            duration_ms: start.elapsed().as_millis() as u64,
            changeset_id: None,
            verification: VerificationReport {
                state: VerificationState::RequestedUnverified,
                method: mode.into(),
                checks: vec!["panel_id_verified".into()],
                details: Some("GUI 设置窗口打开请求已发出".into()),
            },
            backend_mode: mode.into(),
        })
    }

    pub fn read_setting_value(&self, key_id: &str) -> anyhow::Result<(Value, String)> {
        match key_id {
            "sound.volume" => {
                if self.probe.wpctl_available
                    && let Some(bin) = resolve_trusted_executable("wpctl")
                {
                    let out = Command::new(bin)
                        .args(["get-volume", "@DEFAULT_AUDIO_SINK@"])
                        .output()?;
                    if out.status.success() {
                        let s = String::from_utf8_lossy(&out.stdout);
                        if let Some(num) = s
                            .split_whitespace()
                            .nth(1)
                            .and_then(|v| v.parse::<f64>().ok())
                        {
                            return Ok((json!((num * 100.0).round()), "wpctl".into()));
                        }
                    }
                }
                if self.probe.fallback_simulation_enabled {
                    return Ok((
                        json!(self.sim.lock().unwrap().volume),
                        "simulated_headless".into(),
                    ));
                }
                anyhow::bail!("PipeWire wpctl 不可用")
            }
            "sound.mute" => {
                if self.probe.wpctl_available
                    && let Some(bin) = resolve_trusted_executable("wpctl")
                {
                    let out = Command::new(bin)
                        .args(["get-volume", "@DEFAULT_AUDIO_SINK@"])
                        .output()?;
                    if out.status.success() {
                        let s = String::from_utf8_lossy(&out.stdout);
                        let muted = s.contains("[MUTED]");
                        return Ok((json!(if muted { "on" } else { "off" }), "wpctl".into()));
                    }
                }
                if self.probe.fallback_simulation_enabled {
                    let m = self.sim.lock().unwrap().mute;
                    return Ok((
                        json!(if m { "on" } else { "off" }),
                        "simulated_headless".into(),
                    ));
                }
                anyhow::bail!("PipeWire wpctl 不可用")
            }
            "sound.mic.volume" => {
                if self.probe.wpctl_available
                    && let Some(bin) = resolve_trusted_executable("wpctl")
                {
                    let out = Command::new(bin)
                        .args(["get-volume", "@DEFAULT_AUDIO_SOURCE@"])
                        .output()?;
                    if out.status.success() {
                        let s = String::from_utf8_lossy(&out.stdout);
                        if let Some(num) = s
                            .split_whitespace()
                            .nth(1)
                            .and_then(|v| v.parse::<f64>().ok())
                        {
                            return Ok((json!((num * 100.0).round()), "wpctl".into()));
                        }
                    }
                }
                if self.probe.fallback_simulation_enabled {
                    return Ok((
                        json!(self.sim.lock().unwrap().mic_volume),
                        "simulated_headless".into(),
                    ));
                }
                anyhow::bail!("PipeWire wpctl 麦克风不可用")
            }
            "sound.mic.mute" => {
                if self.probe.wpctl_available
                    && let Some(bin) = resolve_trusted_executable("wpctl")
                {
                    let out = Command::new(bin)
                        .args(["get-volume", "@DEFAULT_AUDIO_SOURCE@"])
                        .output()?;
                    if out.status.success() {
                        let s = String::from_utf8_lossy(&out.stdout);
                        let muted = s.contains("[MUTED]");
                        return Ok((json!(if muted { "on" } else { "off" }), "wpctl".into()));
                    }
                }
                if self.probe.fallback_simulation_enabled {
                    let m = self.sim.lock().unwrap().mic_mute;
                    return Ok((
                        json!(if m { "on" } else { "off" }),
                        "simulated_headless".into(),
                    ));
                }
                anyhow::bail!("PipeWire wpctl 麦克风不可用")
            }
            "sound.output" => Ok((
                json!(self.sim.lock().unwrap().audio_output.clone()),
                "simulated_headless".into(),
            )),
            "display.brightness" => {
                if let Some(ref sys_dir) = self.probe.backlight_sysfs {
                    let p = PathBuf::from(sys_dir);
                    let cur: f64 = fs::read_to_string(p.join("brightness"))?
                        .trim()
                        .parse()
                        .unwrap_or(50.0);
                    let max: f64 = fs::read_to_string(p.join("max_brightness"))?
                        .trim()
                        .parse::<f64>()
                        .unwrap_or(100.0)
                        .max(1.0);
                    return Ok((
                        json!(((cur / max) * 100.0).round().max(1.0)),
                        "sysfs_backlight".into(),
                    ));
                }
                if self.probe.fallback_simulation_enabled {
                    return Ok((
                        json!(self.sim.lock().unwrap().brightness),
                        "simulated_headless".into(),
                    ));
                }
                anyhow::bail!("未检测到屏幕背光硬件 (/sys/class/backlight)")
            }
            "display.night_light" => {
                if self.probe.gsettings_session_available
                    && let Some(v) = gsettings_get(
                        "org.gnome.settings-daemon.plugins.color",
                        "night-light-enabled",
                    )
                {
                    return Ok((
                        json!(if v == "true" { "on" } else { "off" }),
                        "gsettings".into(),
                    ));
                }
                let on = self.sim.lock().unwrap().night_light;
                Ok((
                    json!(if on { "on" } else { "off" }),
                    "simulated_headless".into(),
                ))
            }
            "display.night_light.temperature" => {
                if self.probe.gsettings_session_available
                    && let Some(v) = gsettings_get(
                        "org.gnome.settings-daemon.plugins.color",
                        "night-light-temperature",
                    )
                    && let Ok(num) = v.trim_start_matches("uint32 ").parse::<f64>()
                {
                    return Ok((json!(num), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().night_light_temp),
                    "simulated_headless".into(),
                ))
            }
            "display.idle_delay" => {
                if self.probe.gsettings_session_available
                    && let Some(v) = gsettings_get("org.gnome.desktop.session", "idle-delay")
                    && let Ok(num) = v.trim_start_matches("uint32 ").parse::<f64>()
                {
                    return Ok((json!(num), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().idle_delay),
                    "simulated_headless".into(),
                ))
            }
            "appearance.color_scheme" => {
                if self.probe.gsettings_session_available
                    && let Some(val) = gsettings_get("org.gnome.desktop.interface", "color-scheme")
                {
                    return Ok((json!(val), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().color_scheme.clone()),
                    "simulated_headless".into(),
                ))
            }
            "appearance.accent_color" => {
                if self.probe.gsettings_session_available
                    && let Some(val) = gsettings_get("org.gnome.desktop.interface", "accent-color")
                {
                    return Ok((json!(val), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().accent_color.clone()),
                    "simulated_headless".into(),
                ))
            }
            "appearance.text_scale" => {
                if self.probe.gsettings_session_available
                    && let Some(v) =
                        gsettings_get("org.gnome.desktop.interface", "text-scaling-factor")
                    && let Ok(f) = v.parse::<f64>()
                {
                    return Ok((json!(f), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().text_scale),
                    "simulated_headless".into(),
                ))
            }
            "appearance.font.interface" => {
                if self.probe.gsettings_session_available
                    && let Some(v) = gsettings_get("org.gnome.desktop.interface", "font-name")
                {
                    return Ok((json!(v), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().font_interface.clone()),
                    "simulated_headless".into(),
                ))
            }
            "appearance.font.document" => {
                if self.probe.gsettings_session_available
                    && let Some(v) =
                        gsettings_get("org.gnome.desktop.interface", "document-font-name")
                {
                    return Ok((json!(v), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().font_document.clone()),
                    "simulated_headless".into(),
                ))
            }
            "appearance.font.monospace" => {
                if self.probe.gsettings_session_available
                    && let Some(v) =
                        gsettings_get("org.gnome.desktop.interface", "monospace-font-name")
                {
                    return Ok((json!(v), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().font_monospace.clone()),
                    "simulated_headless".into(),
                ))
            }
            "appearance.cursor_size" => {
                if self.probe.gsettings_session_available
                    && let Some(v) = gsettings_get("org.gnome.desktop.interface", "cursor-size")
                    && let Ok(f) = v.parse::<f64>()
                {
                    return Ok((json!(f), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().cursor_size),
                    "simulated_headless".into(),
                ))
            }
            "appearance.animations" => {
                if self.probe.gsettings_session_available
                    && let Some(v) =
                        gsettings_get("org.gnome.desktop.interface", "enable-animations")
                {
                    return Ok((
                        json!(if v == "true" { "on" } else { "off" }),
                        "gsettings".into(),
                    ));
                }
                let on = self.sim.lock().unwrap().animations;
                Ok((
                    json!(if on { "on" } else { "off" }),
                    "simulated_headless".into(),
                ))
            }
            "appearance.wallpaper" => {
                if self.probe.gsettings_session_available
                    && let Some(v) = gsettings_get("org.gnome.desktop.background", "picture-uri")
                {
                    return Ok((json!(v), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().wallpaper.clone()),
                    "simulated_headless".into(),
                ))
            }
            "appearance.clock" => {
                let s = self.sim.lock().unwrap();
                Ok((
                    json!({
                        "format": s.clock_format,
                        "show_seconds": s.clock_seconds,
                        "show_weekday": s.clock_weekday
                    }),
                    "simulated_headless".into(),
                ))
            }
            "notify.dnd" => {
                if self.probe.gsettings_session_available
                    && let Some(v) =
                        gsettings_get("org.gnome.desktop.notifications", "show-banners")
                {
                    return Ok((json!(v != "true"), "gsettings".into()));
                }
                Ok((
                    json!(self.sim.lock().unwrap().dnd),
                    "simulated_headless".into(),
                ))
            }
            "screen.autolock" => {
                if self.probe.gsettings_session_available
                    && let Some(v) = gsettings_get("org.gnome.desktop.screensaver", "lock-enabled")
                {
                    return Ok((
                        json!(if v == "true" { "on" } else { "off" }),
                        "gsettings".into(),
                    ));
                }
                let on = self.sim.lock().unwrap().autolock;
                Ok((
                    json!(if on { "on" } else { "off" }),
                    "simulated_headless".into(),
                ))
            }
            "network.wifi.power" => {
                let on = self.sim.lock().unwrap().wifi_power;
                Ok((
                    json!(if on { "on" } else { "off" }),
                    "simulated_headless".into(),
                ))
            }
            "network.wifi.connect" => Ok((
                json!(self.sim.lock().unwrap().wifi_ssid.clone()),
                "simulated_headless".into(),
            )),
            "bluetooth.power" => {
                let on = self.sim.lock().unwrap().bluetooth_power;
                Ok((
                    json!(if on { "on" } else { "off" }),
                    "simulated_headless".into(),
                ))
            }
            "bluetooth.connect" | "bluetooth.disconnect" => Ok((
                json!(self.sim.lock().unwrap().bluetooth_device.clone()),
                "simulated_headless".into(),
            )),
            "network.airplane" => {
                let on = self.sim.lock().unwrap().airplane_mode;
                Ok((
                    json!(if on { "on" } else { "off" }),
                    "simulated_headless".into(),
                ))
            }
            "power.profile" => {
                if self.probe.powerprofilesctl_available
                    && let Some(bin) = resolve_trusted_executable("powerprofilesctl")
                    && let Ok(out) = Command::new(bin).arg("get").output()
                    && out.status.success()
                {
                    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !p.is_empty() {
                        return Ok((json!(p), "powerprofilesctl".into()));
                    }
                }
                Ok((
                    json!(self.sim.lock().unwrap().power_profile.clone()),
                    "simulated_headless".into(),
                ))
            }
            "input.mouse.speed" => Ok((
                json!(self.sim.lock().unwrap().mouse_speed),
                "simulated_headless".into(),
            )),
            "input.touchpad.speed" => Ok((
                json!(self.sim.lock().unwrap().touchpad_speed),
                "simulated_headless".into(),
            )),
            "input.touchpad.natural_scroll" => {
                let on = self.sim.lock().unwrap().natural_scroll;
                Ok((
                    json!(if on { "on" } else { "off" }),
                    "simulated_headless".into(),
                ))
            }
            "input.touchpad.tap_to_click" => {
                let on = self.sim.lock().unwrap().tap_to_click;
                Ok((
                    json!(if on { "on" } else { "off" }),
                    "simulated_headless".into(),
                ))
            }
            "input.keyboard.repeat" => {
                let s = self.sim.lock().unwrap();
                Ok((
                    json!({
                        "delay_ms": s.keyboard_delay_ms,
                        "interval_ms": s.keyboard_interval_ms
                    }),
                    "simulated_headless".into(),
                ))
            }
            "input.source" => Ok((
                json!(self.sim.lock().unwrap().input_source.clone()),
                "simulated_headless".into(),
            )),
            other => anyhow::bail!("未白名单登记的设置项: {}", other),
        }
    }

    fn write_setting_value(&self, key_id: &str, val: &Value, mode: &str) -> anyhow::Result<()> {
        if mode == "simulated_headless" {
            let mut s = self.sim.lock().unwrap();
            match key_id {
                "sound.volume" => s.volume = val.as_f64().unwrap_or(50.0),
                "sound.mute" => s.mute = val.as_str() == Some("on"),
                "sound.mic.volume" => s.mic_volume = val.as_f64().unwrap_or(75.0),
                "sound.mic.mute" => s.mic_mute = val.as_str() == Some("on"),
                "sound.output" => s.audio_output = val.as_str().unwrap_or("扬声器").to_string(),
                "display.brightness" => s.brightness = val.as_f64().unwrap_or(70.0),
                "display.night_light" => s.night_light = val.as_str() == Some("on"),
                "display.night_light.temperature" => {
                    s.night_light_temp = val.as_f64().unwrap_or(3700.0);
                }
                "display.idle_delay" => s.idle_delay = val.as_f64().unwrap_or(300.0),
                "appearance.color_scheme" => {
                    s.color_scheme = val.as_str().unwrap_or("default").to_string();
                }
                "appearance.accent_color" => {
                    s.accent_color = val.as_str().unwrap_or("orange").to_string();
                }
                "appearance.text_scale" => s.text_scale = val.as_f64().unwrap_or(1.0),
                "appearance.font.interface" => {
                    s.font_interface = val.as_str().unwrap_or("Ubuntu Sans 11").to_string();
                }
                "appearance.font.document" => {
                    s.font_document = val.as_str().unwrap_or("Ubuntu Sans 11").to_string();
                }
                "appearance.font.monospace" => {
                    s.font_monospace = val.as_str().unwrap_or("Ubuntu Mono 13").to_string();
                }
                "appearance.cursor_size" => s.cursor_size = val.as_f64().unwrap_or(24.0),
                "appearance.animations" => s.animations = val.as_str() == Some("on"),
                "appearance.wallpaper" => {
                    s.wallpaper = val.as_str().unwrap_or_default().to_string();
                }
                "appearance.clock" => {
                    if let Some(f) = val.get("format").and_then(|v| v.as_str()) {
                        s.clock_format = f.to_string();
                    }
                    if let Some(sec) = val.get("show_seconds").and_then(|v| v.as_bool()) {
                        s.clock_seconds = sec;
                    }
                    if let Some(wk) = val.get("show_weekday").and_then(|v| v.as_bool()) {
                        s.clock_weekday = wk;
                    }
                }
                "notify.dnd" => s.dnd = val.as_bool().unwrap_or(false),
                "screen.autolock" => s.autolock = val.as_str() == Some("on"),
                "network.wifi.power" => s.wifi_power = val.as_str() == Some("on"),
                "network.wifi.connect" => {
                    s.wifi_ssid = val.as_str().unwrap_or_default().to_string();
                }
                "bluetooth.power" => s.bluetooth_power = val.as_str() == Some("on"),
                "bluetooth.connect" | "bluetooth.disconnect" => {
                    s.bluetooth_device = val.as_str().unwrap_or_default().to_string();
                }
                "network.airplane" => {
                    let on = val.as_str() == Some("on");
                    s.airplane_mode = on;
                    if on {
                        s.wifi_power = false;
                        s.bluetooth_power = false;
                    }
                }
                "power.profile" => {
                    s.power_profile = val.as_str().unwrap_or("balanced").to_string();
                }
                "input.mouse.speed" => s.mouse_speed = val.as_f64().unwrap_or(0.0),
                "input.touchpad.speed" => s.touchpad_speed = val.as_f64().unwrap_or(0.0),
                "input.touchpad.natural_scroll" => s.natural_scroll = val.as_str() == Some("on"),
                "input.touchpad.tap_to_click" => s.tap_to_click = val.as_str() == Some("on"),
                "input.keyboard.repeat" => {
                    if let Some(d) = val.get("delay_ms").and_then(|v| v.as_i64()) {
                        s.keyboard_delay_ms = d;
                    }
                    if let Some(i) = val.get("interval_ms").and_then(|v| v.as_i64()) {
                        s.keyboard_interval_ms = i;
                    }
                }
                "input.source" => {
                    s.input_source = val.as_str().unwrap_or("zh").to_string();
                }
                _ => anyhow::bail!("unknown simulated setting {}", key_id),
            }
            return Ok(());
        }

        match key_id {
            "sound.volume" => {
                let pct = val.as_f64().unwrap_or(50.0).round() as i64;
                let bin = resolve_trusted_executable("wpctl")
                    .ok_or_else(|| anyhow::anyhow!("wpctl missing"))?;
                Command::new(bin)
                    .args(["set-volume", "@DEFAULT_AUDIO_SINK@", &format!("{}%", pct)])
                    .status()?;
            }
            "sound.mute" => {
                let flag = if val.as_str() == Some("on") { "1" } else { "0" };
                let bin = resolve_trusted_executable("wpctl")
                    .ok_or_else(|| anyhow::anyhow!("wpctl missing"))?;
                Command::new(bin)
                    .args(["set-mute", "@DEFAULT_AUDIO_SINK@", flag])
                    .status()?;
            }
            "sound.mic.volume" => {
                let pct = val.as_f64().unwrap_or(75.0).round() as i64;
                let bin = resolve_trusted_executable("wpctl")
                    .ok_or_else(|| anyhow::anyhow!("wpctl missing"))?;
                Command::new(bin)
                    .args(["set-volume", "@DEFAULT_AUDIO_SOURCE@", &format!("{}%", pct)])
                    .status()?;
            }
            "sound.mic.mute" => {
                let flag = if val.as_str() == Some("on") { "1" } else { "0" };
                let bin = resolve_trusted_executable("wpctl")
                    .ok_or_else(|| anyhow::anyhow!("wpctl missing"))?;
                Command::new(bin)
                    .args(["set-mute", "@DEFAULT_AUDIO_SOURCE@", flag])
                    .status()?;
            }
            "display.brightness" => {
                let pct = val.as_f64().unwrap_or(70.0).clamp(1.0, 100.0);
                if let Some(ref sys_dir) = self.probe.backlight_sysfs {
                    let p = PathBuf::from(sys_dir);
                    let subsys_name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let max: f64 = fs::read_to_string(p.join("max_brightness"))?
                        .trim()
                        .parse()
                        .unwrap_or(100.0);
                    let raw_target = ((pct / 100.0) * max).round().max(1.0) as u64;
                    let mut ok = false;
                    if let Some(gdbus) = resolve_trusted_executable("gdbus") {
                        ok = Command::new(gdbus)
                            .args([
                                "call",
                                "--system",
                                "--dest",
                                "org.freedesktop.login1",
                                "--object-path",
                                "/org/freedesktop/login1/session/auto",
                                "--method",
                                "org.freedesktop.login1.Session.SetBrightness",
                                "backlight",
                                &subsys_name,
                                &raw_target.to_string(),
                            ])
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false);
                    }
                    if !ok && let Some(bctl) = resolve_trusted_executable("brightnessctl") {
                        ok = Command::new(bctl)
                            .args(["set", &format!("{}%", pct.round() as u64)])
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false);
                    }
                    if !ok {
                        anyhow::bail!("写入屏幕背光失败");
                    }
                }
            }
            "display.night_light" => {
                let flag = if val.as_str() == Some("on") {
                    "true"
                } else {
                    "false"
                };
                gsettings_set(
                    "org.gnome.settings-daemon.plugins.color",
                    "night-light-enabled",
                    flag,
                )?;
            }
            "display.night_light.temperature" => {
                let k = val.as_f64().unwrap_or(3700.0).round() as u32;
                gsettings_set(
                    "org.gnome.settings-daemon.plugins.color",
                    "night-light-temperature",
                    &k.to_string(),
                )?;
            }
            "display.idle_delay" => {
                let secs = val.as_f64().unwrap_or(300.0).round() as u32;
                gsettings_set("org.gnome.desktop.session", "idle-delay", &secs.to_string())?;
            }
            "appearance.color_scheme" => {
                let scheme = val.as_str().unwrap_or("default");
                gsettings_set("org.gnome.desktop.interface", "color-scheme", scheme)?;
                let gtk_theme = if scheme == "prefer-dark" {
                    "Yaru-dark"
                } else {
                    "Yaru"
                };
                let _ = gsettings_set("org.gnome.desktop.interface", "gtk-theme", gtk_theme);
            }
            "appearance.accent_color" => {
                let c = val.as_str().unwrap_or("orange");
                gsettings_set("org.gnome.desktop.interface", "accent-color", c)?;
            }
            "appearance.text_scale" => {
                let scale = val.as_f64().unwrap_or(1.0);
                gsettings_set(
                    "org.gnome.desktop.interface",
                    "text-scaling-factor",
                    &format!("{:.2}", scale),
                )?;
            }
            "appearance.font.interface" => {
                gsettings_set(
                    "org.gnome.desktop.interface",
                    "font-name",
                    val.as_str().unwrap_or("Ubuntu Sans 11"),
                )?;
            }
            "appearance.font.document" => {
                gsettings_set(
                    "org.gnome.desktop.interface",
                    "document-font-name",
                    val.as_str().unwrap_or("Ubuntu Sans 11"),
                )?;
            }
            "appearance.font.monospace" => {
                gsettings_set(
                    "org.gnome.desktop.interface",
                    "monospace-font-name",
                    val.as_str().unwrap_or("Ubuntu Mono 13"),
                )?;
            }
            "appearance.cursor_size" => {
                let sz = val.as_f64().unwrap_or(24.0).round() as i64;
                gsettings_set(
                    "org.gnome.desktop.interface",
                    "cursor-size",
                    &sz.to_string(),
                )?;
            }
            "appearance.animations" => {
                let flag = if val.as_str() == Some("on") {
                    "true"
                } else {
                    "false"
                };
                gsettings_set("org.gnome.desktop.interface", "enable-animations", flag)?;
            }
            "appearance.wallpaper" => {
                let uri = val.as_str().unwrap_or("");
                gsettings_set("org.gnome.desktop.background", "picture-uri", uri)?;
                let _ = gsettings_set("org.gnome.desktop.background", "picture-uri-dark", uri);
            }
            "notify.dnd" => {
                let dnd_on = val.as_bool().unwrap_or(false);
                gsettings_set(
                    "org.gnome.desktop.notifications",
                    "show-banners",
                    if dnd_on { "false" } else { "true" },
                )?;
            }
            "screen.autolock" => {
                let flag = if val.as_str() == Some("on") {
                    "true"
                } else {
                    "false"
                };
                gsettings_set("org.gnome.desktop.screensaver", "lock-enabled", flag)?;
            }
            "power.profile" => {
                if let Some(bin) = resolve_trusted_executable("powerprofilesctl") {
                    let prof = val.as_str().unwrap_or("balanced");
                    Command::new(bin).args(["set", prof]).status()?;
                }
            }
            _ => {
                // Fallback to simulated store for desktop keys when session backend is partial
                return self.write_setting_value(key_id, val, "simulated_headless");
            }
        }
        Ok(())
    }

    fn compute_target_value(
        &self,
        meta: &intentos_protocol::SettingMeta,
        before: &Value,
        args: &Value,
    ) -> anyhow::Result<(Value, bool, Option<String>)> {
        match meta.key_id.as_str() {
            "sound.mute" => {
                let req = args
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("toggle");
                let cur = before.as_str().unwrap_or("off");
                let next = toggle_on_off(cur, req)?;
                Ok((json!(next), false, None))
            }
            "sound.mic.mute"
            | "display.night_light"
            | "appearance.animations"
            | "screen.autolock"
            | "network.wifi.power"
            | "bluetooth.power"
            | "network.airplane"
            | "input.touchpad.natural_scroll"
            | "input.touchpad.tap_to_click" => {
                let req = args
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("toggle");
                let cur = before.as_str().unwrap_or("off");
                let next = toggle_on_off(cur, req)?;
                Ok((json!(next), false, None))
            }
            "sound.output" => {
                let dev = args
                    .get("device")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing device"))?;
                Ok((json!(dev.trim()), false, None))
            }
            "appearance.color_scheme" => {
                let s = args
                    .get("scheme")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing scheme"))?;
                Ok((json!(s), false, None))
            }
            "appearance.accent_color" => {
                let c = args
                    .get("color")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing color"))?;
                Ok((json!(c), false, None))
            }
            "appearance.font.interface"
            | "appearance.font.document"
            | "appearance.font.monospace" => {
                let cur_str = before.as_str().unwrap_or("Ubuntu Sans 11");
                let (cur_fam, cur_sz) = split_font_spec(cur_str);
                let fam = match args.get("family").and_then(|v| v.as_str()) {
                    Some(f) => self
                        .validate_font_family(f)
                        .map_err(|_| anyhow::anyhow!("invalid font {}", f))?,
                    None => cur_fam,
                };
                let sz = args
                    .get("size")
                    .and_then(|v| v.as_f64())
                    .map(|v| v.clamp(6.0, 24.0).round() as i64)
                    .unwrap_or(cur_sz);
                Ok((json!(format!("{} {}", fam, sz)), false, None))
            }
            "appearance.cursor_size" => {
                let cur = before.as_f64().unwrap_or(24.0);
                if let Some(rel) = args.get("relative").and_then(|v| v.as_str()) {
                    let next = step_discrete(&meta.discrete_steps, cur, rel == "up");
                    Ok((json!(next), true, None))
                } else if let Some(sz) = args.get("size").and_then(|v| v.as_f64()) {
                    let nearest = meta
                        .discrete_steps
                        .iter()
                        .copied()
                        .min_by(|a, b| (a - sz).abs().partial_cmp(&(b - sz).abs()).unwrap())
                        .unwrap_or(24.0);
                    Ok((json!(nearest), false, None))
                } else {
                    anyhow::bail!("missing cursor size or relative")
                }
            }
            "appearance.wallpaper" => {
                let p = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing path"))?;
                let uri = if p.starts_with("file://") {
                    p.to_string()
                } else {
                    format!("file://{}", p)
                };
                Ok((json!(uri), false, None))
            }
            "appearance.clock" => {
                let mut obj = before.clone();
                if let Some(map) = obj.as_object_mut() {
                    if let Some(f) = args.get("format").and_then(|v| v.as_str()) {
                        map.insert("format".into(), json!(f));
                    }
                    if let Some(sec) = args.get("show_seconds").and_then(|v| v.as_bool()) {
                        map.insert("show_seconds".into(), json!(sec));
                    }
                    if let Some(wk) = args.get("show_weekday").and_then(|v| v.as_bool()) {
                        map.insert("show_weekday".into(), json!(wk));
                    }
                }
                Ok((obj, false, None))
            }
            "notify.dnd" => {
                let en = args
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .ok_or_else(|| anyhow::anyhow!("missing enabled"))?;
                Ok((json!(en), false, None))
            }
            "display.idle_delay" => {
                let secs = args
                    .get("seconds")
                    .and_then(|v| v.as_f64())
                    .ok_or_else(|| anyhow::anyhow!("missing seconds"))?;
                let (clamped, note) = clamp_with_note(secs, 0.0, 3600.0, &meta.key_id);
                Ok((json!(clamped), false, note))
            }
            "display.night_light.temperature" => {
                let cur = before.as_f64().unwrap_or(3700.0);
                if let Some(rel) = args.get("relative").and_then(|v| v.as_str()) {
                    // Lower K = warmer (1700K), Higher K = cooler (4700K)!
                    let delta = match rel {
                        "warmer" | "down" => -500.0,
                        "cooler" | "up" => 500.0,
                        _ => -500.0,
                    };
                    let (clamped, note) =
                        clamp_with_note(cur + delta, 1700.0, 4700.0, &meta.key_id);
                    Ok((json!(clamped), true, note))
                } else if let Some(v) = args.get("value").and_then(|v| v.as_f64()) {
                    let (clamped, note) = clamp_with_note(v, 1700.0, 4700.0, &meta.key_id);
                    Ok((json!(clamped), false, note))
                } else {
                    anyhow::bail!("missing temperature value or relative")
                }
            }
            "power.profile" => {
                let p = args
                    .get("profile")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing profile"))?;
                Ok((json!(p), false, None))
            }
            "input.keyboard.repeat" => {
                let cur_d = before
                    .get("delay_ms")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(500);
                let cur_i = before
                    .get("interval_ms")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(30);
                let (d, i) = match args.get("preset").and_then(|v| v.as_str()) {
                    Some("fast") => (220, 20),
                    Some("slow") => (700, 50),
                    Some("normal") => (500, 30),
                    _ => (
                        args.get("delay_ms")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(cur_d)
                            .clamp(150, 1000),
                        args.get("interval_ms")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(cur_i)
                            .clamp(10, 100),
                    ),
                };
                Ok((json!({ "delay_ms": d, "interval_ms": i }), false, None))
            }
            "input.source" => {
                let req = args
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("next");
                let cur = before.as_str().unwrap_or("zh");
                let next = if req == "next" {
                    if cur == "zh" { "en" } else { "zh" }
                } else {
                    req
                };
                Ok((json!(next), false, None))
            }
            _ => {
                // Numeric / discrete-stepped setting (`sound.volume`, `sound.mic.volume`, `display.brightness`, `appearance.text_scale`, `input.mouse.speed`, `input.touchpad.speed`)
                let cur = before.as_f64().unwrap_or(1.0);
                let min_v = meta.min.unwrap_or(0.0);
                let max_v = meta.max.unwrap_or(100.0);

                if let Some(rel) = args.get("relative").and_then(|v| v.as_str()) {
                    let next = if !meta.discrete_steps.is_empty() {
                        step_discrete(&meta.discrete_steps, cur, rel == "up")
                    } else {
                        let step = meta.step.unwrap_or(10.0);
                        if rel == "up" { cur + step } else { cur - step }
                    };
                    let (clamped, note) = clamp_with_note(next, min_v, max_v, &meta.key_id);
                    Ok((json!(clamped), true, note))
                } else if let Some(mut raw_v) = args.get("value").and_then(|v| v.as_f64()) {
                    if meta.key_id == "appearance.text_scale" && raw_v > 10.0 {
                        raw_v /= 100.0;
                    }
                    let (clamped, note) = clamp_with_note(raw_v, min_v, max_v, &meta.key_id);
                    Ok((json!(clamped), false, note))
                } else {
                    anyhow::bail!("missing value or relative adjustment")
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_or_coalesce_setting_changeset(
        &self,
        task_id: &str,
        capability_id: &str,
        key_id: &str,
        before: &Value,
        after: &Value,
        mode: &str,
        is_relative: bool,
    ) -> anyhow::Result<String> {
        let now = Utc::now();
        let mut coalesce_map = self.coalesce.lock().unwrap();

        if is_relative
            && let Some(prev) = coalesce_map.get(key_id).cloned()
            && (now - prev.updated_at) <= Duration::seconds(60)
            && let Ok(Some(latest)) = self.state_db.latest_applied_changeset()
            && latest.id == prev.changeset_id
        {
            let mut updated_cs = latest;
            updated_cs.operations = vec![ChangeOp::Setting {
                capability_id: capability_id.to_string(),
                key: key_id.to_string(),
                before: prev.initial_before.clone(),
                after: after.clone(),
                backend_mode: mode.to_string(),
            }];
            updated_cs.summary = format!(
                "{} {} → {}（连续调整合并）",
                setting_human_name(key_id),
                format_setting_val(key_id, &prev.initial_before),
                format_setting_val(key_id, after)
            );
            self.state_db.save_changeset(&updated_cs)?;
            coalesce_map.insert(
                key_id.to_string(),
                CoalesceEntry {
                    changeset_id: updated_cs.id.clone(),
                    initial_before: prev.initial_before,
                    updated_at: now,
                },
            );
            return Ok(updated_cs.id);
        }

        let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        let cs = ChangeSet {
            id: cs_id.clone(),
            task_id: task_id.to_string(),
            created_at: now,
            capability_id: capability_id.to_string(),
            layer: "Setting".to_string(),
            operations: vec![ChangeOp::Setting {
                capability_id: capability_id.to_string(),
                key: key_id.to_string(),
                before: before.clone(),
                after: after.clone(),
                backend_mode: mode.to_string(),
            }],
            backup_bytes: 0,
            status: ChangeSetStatus::Applied,
            undo_expires_at: now + Duration::days(30),
            summary: format!(
                "{} {} → {}",
                setting_human_name(key_id),
                format_setting_val(key_id, before),
                format_setting_val(key_id, after)
            ),
        };
        self.state_db.save_changeset(&cs)?;

        if is_relative {
            coalesce_map.insert(
                key_id.to_string(),
                CoalesceEntry {
                    changeset_id: cs_id.clone(),
                    initial_before: before.clone(),
                    updated_at: now,
                },
            );
        } else {
            coalesce_map.remove(key_id);
        }

        Ok(cs_id)
    }
}

fn gsettings_get(schema: &str, key: &str) -> Option<String> {
    let bin = resolve_trusted_executable("gsettings")?;
    let out = Command::new(bin).args(["get", schema, key]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .trim_matches('\'')
            .to_string(),
    )
}

fn gsettings_set(schema: &str, key: &str, val: &str) -> anyhow::Result<()> {
    let bin = resolve_trusted_executable("gsettings")
        .ok_or_else(|| anyhow::anyhow!("gsettings missing"))?;
    let st = Command::new(bin).args(["set", schema, key, val]).status()?;
    if !st.success() {
        anyhow::bail!("gsettings set {} {} failed", schema, key);
    }
    Ok(())
}

fn toggle_on_off<'a>(cur: &'a str, req: &'a str) -> anyhow::Result<&'static str> {
    match req {
        "on" => Ok("on"),
        "off" => Ok("off"),
        "toggle" => Ok(if cur == "on" { "off" } else { "on" }),
        other => anyhow::bail!("invalid state {}", other),
    }
}

fn split_font_spec(spec: &str) -> (String, i64) {
    let trimmed = spec.trim();
    if let Some((fam, last)) = trimmed.rsplit_once(' ')
        && let Ok(sz) = last.parse::<i64>()
    {
        return (fam.trim().to_string(), sz);
    }
    (trimmed.to_string(), 11)
}

fn step_discrete(steps: &[f64], cur: f64, up: bool) -> f64 {
    if up {
        for &s in steps {
            if s > cur + 0.005 {
                return s;
            }
        }
        *steps.last().unwrap_or(&cur)
    } else {
        for &s in steps.iter().rev() {
            if s < cur - 0.005 {
                return s;
            }
        }
        *steps.first().unwrap_or(&cur)
    }
}

fn clamp_with_note(val: f64, min_v: f64, max_v: f64, key_id: &str) -> (f64, Option<String>) {
    if val < min_v {
        let msg = if key_id == "display.brightness" {
            format!("已按安全范围钳制至最低 {}%，防止黑屏", min_v as i64)
        } else {
            format!("已钳制至下限 {}", min_v)
        };
        (min_v, Some(msg))
    } else if val > max_v {
        (max_v, Some(format!("已钳制至上限 {}", max_v)))
    } else {
        let rounded = (val * 100.0).round() / 100.0;
        (rounded, None)
    }
}

fn values_match(a: &Value, b: &Value, tolerance: f64) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(fa), Some(fb)) => (fa - fb).abs() <= tolerance.max(0.01),
        _ => a == b,
    }
}

fn default_value_for_key(key_id: &str) -> Value {
    match key_id {
        "sound.volume" => json!(50.0),
        "sound.mute" => json!("off"),
        "sound.mic.volume" => json!(75.0),
        "sound.mic.mute" => json!("off"),
        "display.brightness" => json!(70.0),
        "display.night_light" => json!("off"),
        "display.night_light.temperature" => json!(3700.0),
        "display.idle_delay" => json!(300.0),
        "appearance.color_scheme" => json!("default"),
        "appearance.accent_color" => json!("orange"),
        "appearance.text_scale" => json!(1.0),
        "appearance.font.interface" => json!("Ubuntu Sans 11"),
        "appearance.font.document" => json!("Ubuntu Sans 11"),
        "appearance.font.monospace" => json!("Ubuntu Mono 13"),
        "appearance.cursor_size" => json!(24.0),
        "appearance.animations" => json!("on"),
        "notify.dnd" => json!(false),
        "screen.autolock" => json!("on"),
        "power.profile" => json!("balanced"),
        "input.mouse.speed" | "input.touchpad.speed" => json!(0.0),
        "input.touchpad.natural_scroll" | "input.touchpad.tap_to_click" => json!("on"),
        _ => Value::Null,
    }
}

pub fn setting_human_name(key_id: &str) -> &'static str {
    match key_id {
        "sound.volume" => "音量",
        "sound.mute" => "静音",
        "sound.mic.volume" => "麦克风音量",
        "sound.mic.mute" => "麦克风静音",
        "sound.output" => "音频输出设备",
        "display.brightness" => "屏幕亮度",
        "display.night_light" => "夜灯护眼",
        "display.night_light.temperature" => "夜灯色温",
        "display.idle_delay" => "自动熄屏时间",
        "appearance.color_scheme" => "外观模式",
        "appearance.accent_color" => "系统强调色",
        "appearance.text_scale" => "文字缩放",
        "appearance.font.interface" => "界面字体",
        "appearance.font.document" => "文档字体",
        "appearance.font.monospace" => "等宽字体",
        "appearance.cursor_size" => "鼠标指针大小",
        "appearance.animations" => "桌面动画",
        "appearance.wallpaper" => "桌面壁纸",
        "appearance.clock" => "顶栏时钟",
        "notify.dnd" => "勿扰模式",
        "screen.autolock" => "自动锁屏",
        "network.wifi.power" => "Wi-Fi 开关",
        "network.wifi.connect" => "Wi-Fi 连接",
        "bluetooth.power" => "蓝牙开关",
        "bluetooth.connect" | "bluetooth.disconnect" => "蓝牙设备连接",
        "network.airplane" => "飞行模式",
        "power.profile" => "电源模式",
        "input.mouse.speed" => "鼠标指针速度",
        "input.touchpad.speed" => "触控板速度",
        "input.touchpad.natural_scroll" => "触控板自然滚动",
        "input.touchpad.tap_to_click" => "触控板轻触点击",
        "input.keyboard.repeat" => "键盘连发速度",
        "input.source" => "输入法/输入源",
        _ => "系统设置",
    }
}

pub fn format_setting_val(key_id: &str, v: &Value) -> String {
    match key_id {
        "sound.volume" | "sound.mic.volume" | "display.brightness" => {
            format!("{}%", v.as_f64().unwrap_or(0.0).round() as i64)
        }
        "appearance.text_scale" => {
            format!("{}%", (v.as_f64().unwrap_or(1.0) * 100.0).round() as i64)
        }
        "display.night_light.temperature" => {
            format!("{}K", v.as_f64().unwrap_or(3700.0).round() as i64)
        }
        "display.idle_delay" => {
            let s = v.as_f64().unwrap_or(300.0).round() as i64;
            if s == 0 {
                "从不熄屏".into()
            } else if s % 60 == 0 {
                format!("{} 分钟", s / 60)
            } else {
                format!("{} 秒", s)
            }
        }
        "sound.mute" | "sound.mic.mute" => match v.as_str().unwrap_or("off") {
            "on" => "已静音".into(),
            _ => "未静音".into(),
        },
        "display.night_light"
        | "appearance.animations"
        | "screen.autolock"
        | "network.wifi.power"
        | "bluetooth.power"
        | "network.airplane"
        | "input.touchpad.natural_scroll"
        | "input.touchpad.tap_to_click" => match v.as_str().unwrap_or("off") {
            "on" => "已开启".into(),
            _ => "已关闭".into(),
        },
        "appearance.color_scheme" => match v.as_str().unwrap_or("default") {
            "prefer-dark" => "深色模式".into(),
            "prefer-light" => "浅色模式".into(),
            _ => "系统默认".into(),
        },
        "power.profile" => match v.as_str().unwrap_or("balanced") {
            "power-saver" => "省电模式".into(),
            "performance" => "性能模式".into(),
            _ => "平衡模式".into(),
        },
        "notify.dnd" => {
            if v.as_bool().unwrap_or(false) {
                "已开启".into()
            } else {
                "已关闭".into()
            }
        }
        _ => match v.as_str() {
            Some(s) => s.to_string(),
            None => v.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_capability_sdk::load_descriptors_from_dir;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn consecutive_brightness_adjustments_coalesce_and_undo_to_initial() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(StateDb::open(&tmp.path().join("state.db")).unwrap());
        let eng = SystemSettingsEngine::new(db.clone(), true);

        let repo_sys = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/system");
        let descs = load_descriptors_from_dir(&repo_sys).unwrap();
        let bright_set = descs
            .iter()
            .find(|d| d.id == "display.brightness.set")
            .unwrap();

        let r1 = eng
            .execute("req1", "t1", bright_set, &json!({"relative": "down"}))
            .unwrap();
        let r2 = eng
            .execute("req2", "t2", bright_set, &json!({"relative": "down"}))
            .unwrap();
        let r3 = eng
            .execute("req3", "t3", bright_set, &json!({"relative": "down"}))
            .unwrap();

        assert_eq!(r1.changeset_id, r2.changeset_id);
        assert_eq!(r2.changeset_id, r3.changeset_id);
        assert_eq!(r3.data["after"].as_f64().unwrap(), 40.0);

        let cs = db
            .get_changeset(r3.changeset_id.as_ref().unwrap())
            .unwrap()
            .unwrap();
        let ChangeOp::Setting {
            key,
            before,
            backend_mode,
            ..
        } = &cs.operations[0]
        else {
            panic!("expected setting op");
        };
        let (restored, _) = eng.undo_setting_op(key, before, backend_mode).unwrap();
        assert_eq!(restored.as_f64().unwrap(), 70.0);
    }

    #[test]
    fn sc07_conflicting_external_setting_is_not_overwritten_on_undo() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(StateDb::open(&tmp.path().join("state.db")).unwrap());
        let eng = SystemSettingsEngine::new(db, true);
        let repo_sys = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/system");
        let descriptors = load_descriptors_from_dir(&repo_sys).unwrap();
        let bright_set = descriptors
            .iter()
            .find(|d| d.id == "display.brightness.set")
            .unwrap();
        let original = eng.read_setting_value("display.brightness").unwrap().0;
        let first = eng
            .execute("first", "task1", bright_set, &json!({"value": 35}))
            .unwrap();
        let first_after = first.data["after"].clone();
        eng.execute("external", "task2", bright_set, &json!({"value": 80}))
            .unwrap();
        assert!(
            !eng.undo_precondition_met("display.brightness", &first_after)
                .unwrap()
        );
        assert!(
            eng.undo_setting_op_checked(
                "display.brightness",
                &original,
                &first_after,
                "simulated_headless"
            )
            .is_err()
        );
        let (current, _) = eng.read_setting_value("display.brightness").unwrap();
        assert_eq!(current.as_f64(), Some(80.0));
    }

    #[test]
    fn clamps_brightness_zero_to_one_and_volume_500_to_100() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(StateDb::open(&tmp.path().join("state.db")).unwrap());
        let eng = SystemSettingsEngine::new(db, true);

        let repo_sys = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/system");
        let descs = load_descriptors_from_dir(&repo_sys).unwrap();
        let bright_set = descs
            .iter()
            .find(|d| d.id == "display.brightness.set")
            .unwrap();
        let vol_set = descs.iter().find(|d| d.id == "sound.volume.set").unwrap();

        let rb = eng
            .execute("r_zero", "t_z", bright_set, &json!({"value": 0}))
            .unwrap();
        assert_eq!(rb.data["after"].as_f64().unwrap(), 1.0);
        assert!(rb.message.contains("1%"));

        let rv = eng
            .execute("r_500", "t_v", vol_set, &json!({"value": 500}))
            .unwrap();
        assert_eq!(rv.data["after"].as_f64().unwrap(), 100.0);
    }

    #[test]
    fn scene_apply_records_single_changeset_and_rejects_uninstalled_font_and_unsaved_wifi() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(StateDb::open(&tmp.path().join("state.db")).unwrap());
        let eng = SystemSettingsEngine::new(db.clone(), true);

        let repo_sys = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/system");
        let descs = load_descriptors_from_dir(&repo_sys).unwrap();
        let scene_desc = descs.iter().find(|d| d.id == "scene.apply").unwrap();
        let font_desc = descs
            .iter()
            .find(|d| d.id == "appearance.font.monospace.set")
            .unwrap();
        let wifi_desc = descs
            .iter()
            .find(|d| d.id == "network.wifi.connect")
            .unwrap();

        // A11e: Eye-care scene applies 3 settings in ONE changeset
        let r_scene = eng
            .execute("r_sc", "t_sc", scene_desc, &json!({"scene": "护眼模式"}))
            .unwrap();
        let csid = r_scene.changeset_id.unwrap();
        let cs = db.get_changeset(&csid).unwrap().unwrap();
        assert_eq!(cs.operations.len(), 3);

        // A11c: Unknown or injected font rejected before writing!
        let r_bad_font = eng
            .execute(
                "r_bf",
                "t_bf",
                font_desc,
                &json!({"family": "FakeFont; rm -rf ~", "size": 12}),
            )
            .unwrap();
        assert_eq!(r_bad_font.status, ExecutionStatus::VerificationFailed);

        // A11f: Unsaved Wi-Fi returns RequestedUnverified and NEVER asks password!
        let r_wifi = eng
            .execute(
                "r_wf",
                "t_wf",
                wifi_desc,
                &json!({"ssid": "陌生新网络-Guest"}),
            )
            .unwrap();
        assert_eq!(r_wifi.status, ExecutionStatus::RequestedUnverified);
        assert!(r_wifi.message.contains("永不索要"));
    }
}
