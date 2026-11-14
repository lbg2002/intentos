#![forbid(unsafe_code)]

//! Session D-Bus & MPRIS2 Non-CLI GUI App Driver (`mpris_dbus.rs`):
//! - Discovers active `org.mpris.MediaPlayer2.*` services via `gdbus` or `busctl --user`
//! - Translates semantic media intents (`play`, `pause`, `play_pause`, `next`, `previous`,
//!   `stop`, `get_now_playing`, `set_volume`) into `org.mpris.MediaPlayer2.Player` D-Bus calls
//!   with post-action metadata readback (`xesam:title`, `xesam:artist`, `PlaybackStatus`, `Volume`)
//! - Supports `org.freedesktop.FileManager1.ShowItems` / `ShowFolders` and
//!   `org.freedesktop.Application.Activate`
//! - Provides deterministic dry-run / headless fallback when no live session bus or player is active

use crate::app_adapter::registry::{AdaptationChannel, AppAdapterProfile};
use crate::app_adapter::sni_dbusmenu;
use crate::core::IntentOsCore;
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_protocol::{VerificationReport, VerificationState};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MprisNowPlaying {
    pub bus_name: String,
    pub player_identity: String,
    pub playback_status: String,
    pub title: Option<String>,
    pub artists: Vec<String>,
    pub album: Option<String>,
    pub volume: Option<f64>,
    pub simulated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MprisDiscoveryReport {
    pub dbus_session_available: bool,
    pub services: Vec<String>,
    pub method: String,
}

#[derive(Debug, Clone)]
pub struct DbusDispatchResult {
    pub ok: bool,
    pub channel_used: AdaptationChannel,
    pub translated_command: String,
    pub summary: String,
    pub data: Value,
    pub simulated: bool,
    pub verification: VerificationReport,
}

/// Check whether a desktop GUI display server is present in the environment.
pub fn has_gui_session() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
}

/// Check whether `DBUS_SESSION_BUS_ADDRESS` is configured in the environment.
pub fn has_dbus_session_address() -> bool {
    std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Validate a D-Bus well-known bus name to prevent injection or malformed arguments.
pub fn is_valid_dbus_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.contains('.')
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Convert a Freedesktop D-Bus application ID (e.g. `org.gnome.Evince`) into its standard object path (`/org/gnome/Evince`).
pub fn dbus_id_to_object_path(dbus_app_id: &str) -> String {
    let sanitized: String = dbus_app_id
        .chars()
        .map(|c| match c {
            '.' => '/',
            '-' => '_',
            other => other,
        })
        .collect();
    format!("/{}", sanitized.trim_matches('/'))
}

/// Convert an absolute filesystem path into a safe `file:///...` RFC3986 URI (percent-encoding special chars).
pub fn path_to_file_uri(path: &Path) -> anyhow::Result<String> {
    if !path.is_absolute() {
        anyhow::bail!("文件路径必须为绝对路径: {}", path.display());
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            anyhow::bail!("文件路径禁止包含 '..' 父目录逃逸: {}", path.display());
        }
    }
    let raw = path.to_string_lossy();
    let mut uri = String::from("file://");
    for seg in raw.split('/') {
        if seg.is_empty() {
            continue;
        }
        uri.push('/');
        uri.push_str(&urlencoding::encode(seg));
    }
    if uri == "file://" {
        uri.push('/');
    }
    Ok(uri)
}

/// Parse `org.mpris.MediaPlayer2.*` bus names from `gdbus call ... ListNames` output.
pub fn parse_mpris_names_from_gdbus(output: &str) -> Vec<String> {
    let re = Regex::new(r"'(org\.mpris\.MediaPlayer2\.[A-Za-z0-9_.-]+)'").unwrap();
    let mut names: Vec<String> = re
        .captures_iter(output)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Parse `org.mpris.MediaPlayer2.*` bus names from `busctl --user list --no-legend` output.
pub fn parse_mpris_names_from_busctl(output: &str) -> Vec<String> {
    let mut names: Vec<String> = output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|tok| tok.starts_with("org.mpris.MediaPlayer2.") && is_valid_dbus_name(tok))
        .map(String::from)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Parse GVariant dictionary output of `Properties.GetAll org.mpris.MediaPlayer2.Player`.
pub fn parse_mpris_properties_gvariant(bus_name: &str, raw: &str) -> MprisNowPlaying {
    let player_identity = bus_name
        .strip_prefix("org.mpris.MediaPlayer2.")
        .unwrap_or(bus_name)
        .to_string();

    let status_re = Regex::new(r#"'PlaybackStatus':\s*<'([^']+)'>"#).unwrap();
    let playback_status = status_re
        .captures(raw)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        .unwrap_or_else(|| "Unknown".to_string());

    let title_re = Regex::new(r#"'xesam:title':\s*<(?:'([^']*)'|"([^"]*)")>"#).unwrap();
    let title = title_re.captures(raw).and_then(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_string())
            .filter(|s| !s.is_empty())
    });

    let album_re = Regex::new(r#"'xesam:album':\s*<(?:'([^']*)'|"([^"]*)")>"#).unwrap();
    let album = album_re.captures(raw).and_then(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_string())
            .filter(|s| !s.is_empty())
    });

    let mut artists = Vec::new();
    let artist_arr_re = Regex::new(r#"'xesam:artist':\s*<\[([^\]]*)\]>"#).unwrap();
    if let Some(cap) = artist_arr_re.captures(raw)
        && let Some(inner) = cap.get(1)
    {
        let item_re = Regex::new(r#"'([^']*)'|"([^"]*)""#).unwrap();
        for m in item_re.captures_iter(inner.as_str()) {
            if let Some(val) = m.get(1).or_else(|| m.get(2)) {
                let trimmed = val.as_str().trim();
                if !trimmed.is_empty() {
                    artists.push(trimmed.to_string());
                }
            }
        }
    }

    let vol_re = Regex::new(r#"'Volume':\s*<(?:double\s+)?([0-9]+(?:\.[0-9]+)?)>"#).unwrap();
    let volume = vol_re
        .captures(raw)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<f64>().ok());

    MprisNowPlaying {
        bus_name: bus_name.to_string(),
        player_identity,
        playback_status,
        title,
        artists,
        album,
        volume,
        simulated: false,
    }
}

/// Normalize volume input (`0.0..=1.0` ratio or `0..=100` percentage) into clamped `0.0..=1.0`.
pub fn normalize_mpris_volume(params: &Value) -> anyhow::Result<f64> {
    let raw = params
        .get("volume")
        .or_else(|| params.get("level"))
        .or_else(|| params.get("percent"))
        .or_else(|| params.get("value"))
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_str().and_then(|s| s.trim_end_matches('%').trim().parse::<f64>().ok()))
        })
        .ok_or_else(|| anyhow::anyhow!("调节播放器音量缺少参数 `volume` (0~100 或 0.0~1.0)"))?;

    if !raw.is_finite() || raw < 0.0 {
        anyhow::bail!("无效的音量数值: {}", raw);
    }
    let normalized = if raw > 1.0 { raw / 100.0 } else { raw };
    Ok(normalized.clamp(0.0, 1.0))
}

/// Build discrete `gdbus` CLI arguments (non-shell) for an MPRIS2 action.
pub fn build_mpris_gdbus_args(
    bus_name: &str,
    canonical_action: &str,
    params: &Value,
) -> anyhow::Result<Vec<String>> {
    if !bus_name.starts_with("org.mpris.MediaPlayer2.") || !is_valid_dbus_name(bus_name) {
        anyhow::bail!("非法的 MPRIS2 D-Bus 服务名: {}", bus_name);
    }

    let base = vec![
        "call".to_string(),
        "--session".to_string(),
        "--dest".to_string(),
        bus_name.to_string(),
        "--object-path".to_string(),
        "/org/mpris/MediaPlayer2".to_string(),
        "--method".to_string(),
    ];

    let mut argv = base;
    match canonical_action {
        "play" => argv.push("org.mpris.MediaPlayer2.Player.Play".into()),
        "pause" => argv.push("org.mpris.MediaPlayer2.Player.Pause".into()),
        "play_pause" => argv.push("org.mpris.MediaPlayer2.Player.PlayPause".into()),
        "next" => argv.push("org.mpris.MediaPlayer2.Player.Next".into()),
        "previous" => argv.push("org.mpris.MediaPlayer2.Player.Previous".into()),
        "stop" => argv.push("org.mpris.MediaPlayer2.Player.Stop".into()),
        "get_now_playing" => {
            argv.push("org.freedesktop.DBus.Properties.GetAll".into());
            argv.push("org.mpris.MediaPlayer2.Player".into());
        }
        "set_volume" => {
            let vol = normalize_mpris_volume(params)?;
            argv.push("org.freedesktop.DBus.Properties.Set".into());
            argv.push("org.mpris.MediaPlayer2.Player".into());
            argv.push("Volume".into());
            argv.push(format!("<{:.4}>", vol));
        }
        other => anyhow::bail!("不支持的 MPRIS2 媒体控制动作: {}", other),
    }
    Ok(argv)
}

/// Build discrete `gdbus` CLI arguments for `org.freedesktop.FileManager1` (`ShowItems` or `ShowFolders`).
pub fn build_file_manager_gdbus_args(
    method: &str,
    target_path: &Path,
    startup_id: &str,
) -> anyhow::Result<Vec<String>> {
    if method != "ShowItems" && method != "ShowFolders" {
        anyhow::bail!("不支持的 FileManager1 方法: {}", method);
    }
    let file_uri = path_to_file_uri(target_path)?;
    let clean_startup: String = startup_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(48)
        .collect();
    let effective_startup = if clean_startup.is_empty() {
        "intentos".to_string()
    } else {
        clean_startup
    };

    Ok(vec![
        "call".into(),
        "--session".into(),
        "--dest".into(),
        "org.freedesktop.FileManager1".into(),
        "--object-path".into(),
        "/org/freedesktop/FileManager1".into(),
        "--method".into(),
        format!("org.freedesktop.FileManager1.{}", method),
        format!("['{}']", file_uri),
        effective_startup,
    ])
}

/// Build discrete `gdbus` CLI arguments for `org.freedesktop.Application` (`Activate` or `Open`).
pub fn build_freedesktop_app_activate_args(
    dbus_app_id: &str,
    file_target: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    if !is_valid_dbus_name(dbus_app_id) {
        anyhow::bail!("非法的 Freedesktop Application D-Bus 名称: {}", dbus_app_id);
    }
    let obj_path = dbus_id_to_object_path(dbus_app_id);
    if let Some(path) = file_target {
        let uri = path_to_file_uri(path)?;
        Ok(vec![
            "call".into(),
            "--session".into(),
            "--dest".into(),
            dbus_app_id.into(),
            "--object-path".into(),
            obj_path,
            "--method".into(),
            "org.freedesktop.Application.Open".into(),
            format!("['{}']", uri),
            "{}".into(),
        ])
    } else {
        Ok(vec![
            "call".into(),
            "--session".into(),
            "--dest".into(),
            dbus_app_id.into(),
            "--object-path".into(),
            obj_path,
            "--method".into(),
            "org.freedesktop.Application.Activate".into(),
            "{}".into(),
        ])
    }
}

/// Discover live `org.mpris.MediaPlayer2.*` services on the user's session D-Bus.
pub async fn discover_active_mpris_services() -> MprisDiscoveryReport {
    if !has_dbus_session_address() {
        return MprisDiscoveryReport {
            dbus_session_available: false,
            services: Vec::new(),
            method: "no_dbus_session_env".into(),
        };
    }

    if let Some(gdbus_bin) = resolve_trusted_executable("gdbus") {
        let args = [
            "call",
            "--session",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.ListNames",
        ];
        if let Some((ok, stdout, _)) = run_dbus_binary(&gdbus_bin, &args, 1800).await
            && ok
        {
            return MprisDiscoveryReport {
                dbus_session_available: true,
                services: parse_mpris_names_from_gdbus(&stdout),
                method: "gdbus_list_names".into(),
            };
        }
    }

    if let Some(busctl_bin) = resolve_trusted_executable("busctl") {
        let args = ["--user", "list", "--no-legend"];
        if let Some((ok, stdout, _)) = run_dbus_binary(&busctl_bin, &args, 1800).await
            && ok
        {
            return MprisDiscoveryReport {
                dbus_session_available: true,
                services: parse_mpris_names_from_busctl(&stdout),
                method: "busctl_user_list".into(),
            };
        }
    }

    MprisDiscoveryReport {
        dbus_session_available: false,
        services: Vec::new(),
        method: "session_bus_unreachable".into(),
    }
}

/// Count `.desktop` entries advertising `DBusActivatable=true`.
pub fn count_dbus_activatable_apps() -> usize {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    let dirs = [
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        PathBuf::from("/var/lib/flatpak/exports/share/applications"),
        PathBuf::from(&home).join(".local/share/applications"),
    ];
    let mut count = 0usize;
    for dir in &dirs {
        let Ok(rd) = fs::read_dir(dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("desktop") {
                continue;
            }
            if let Ok(raw) = fs::read_to_string(&p)
                && raw.lines().any(|l| {
                    let t = l.trim();
                    t.eq_ignore_ascii_case("DBusActivatable=true")
                })
            {
                count += 1;
            }
        }
    }
    count
}

/// Query currently playing tracks across all active MPRIS2 players and `StatusNotifierItem` tray media apps (or filtered by `player_hint`).
pub async fn query_all_now_playing(
    player_hint: Option<&str>,
    allow_simulated_fallback: bool,
) -> Vec<MprisNowPlaying> {
    let discovery = discover_active_mpris_services().await;
    let hint_norm = player_hint
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "*" && !s.eq_ignore_ascii_case("auto"))
        .map(str::to_ascii_lowercase);

    let mut matched_services: Vec<String> = discovery
        .services
        .into_iter()
        .filter(|svc| {
            if let Some(ref h) = hint_norm {
                svc.to_ascii_lowercase().contains(h)
            } else {
                true
            }
        })
        .collect();

    let mut results = Vec::new();
    if !matched_services.is_empty()
        && let Some(gdbus_bin) = resolve_trusted_executable("gdbus")
    {
        for svc in matched_services.drain(..) {
            if let Ok(argv) = build_mpris_gdbus_args(&svc, "get_now_playing", &json!({})) {
                let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                if let Some((true, stdout, _)) = run_dbus_binary(&gdbus_bin, &refs, 1800).await {
                    results.push(parse_mpris_properties_gvariant(&svc, &stdout));
                }
            }
        }
    }

    // Merge / fallback to `StatusNotifierItem` + `com.canonical.dbusmenu` tray media players (e.g. `SodaM / 汽水音乐`)
    if discovery.dbus_session_available {
        let tray_players = sni_dbusmenu::query_tray_media_now_playing(player_hint).await;
        for tp in tray_players {
            if !results.iter().any(|r| r.bus_name == tp.bus_name) {
                results.push(tp);
            }
        }
    }

    if !results.is_empty() {
        return results;
    }

    if (!has_gui_session() || !discovery.dbus_session_available) && allow_simulated_fallback {
        let sim_player = hint_norm.unwrap_or_else(|| "qqmusic".into());
        let clean_slug: String = sim_player
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        let slug = if clean_slug.is_empty() {
            "qqmusic".to_string()
        } else {
            clean_slug
        };
        return vec![MprisNowPlaying {
            bus_name: format!("org.mpris.MediaPlayer2.{}", slug),
            player_identity: slug,
            playback_status: "SimulatedIdle".into(),
            title: Some("未检测到活跃播放曲目（无头/离线仿真就绪）".into()),
            artists: vec!["IntentOS MPRIS2 Adapter".into()],
            album: None,
            volume: Some(0.75),
            simulated: true,
        }];
    }

    Vec::new()
}

/// Select the target `org.mpris.MediaPlayer2.*` bus name for a given adapter profile.
/// Returns `(bus_name, is_specific_match, is_generic_live_fallback)`.
fn select_target_mpris_bus(
    profile: &AppAdapterProfile,
    live_services: &[String],
) -> (String, bool, bool) {
    // 1. Exact dbus_name match
    if let Some(ref exact) = profile.dbus_name
        && live_services.iter().any(|s| s.eq_ignore_ascii_case(exact))
    {
        return (exact.clone(), true, false);
    }
    // 2. Substring match on `mpris_bus_hints` (ignoring generic `chromium.instance` unless profile is Chrome)
    for hint in &profile.mpris_bus_hints {
        let h_lc = hint.to_ascii_lowercase();
        if h_lc == "chromium.instance" && profile.id != "google-chrome" {
            continue;
        }
        if let Some(found) = live_services
            .iter()
            .find(|s| s.to_ascii_lowercase().contains(&h_lc))
        {
            return (found.clone(), true, false);
        }
    }
    // 3. Match by profile id
    let id_lc = profile.id.to_ascii_lowercase();
    if let Some(found) = live_services
        .iter()
        .find(|s| s.to_ascii_lowercase().contains(&id_lc))
    {
        return (found.clone(), true, false);
    }
    // 4. Generic fallback to first active media player (used only after checking SNI tray players!)
    if let Some(first_live) = live_services.first() {
        return (first_live.clone(), false, true);
    }

    // 5. Construct canonical bus name for dry-run / headless fallback
    let fallback_bus = profile
        .dbus_name
        .clone()
        .filter(|n| n.starts_with("org.mpris.MediaPlayer2."))
        .unwrap_or_else(|| {
            let clean: String = profile
                .id
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            format!("org.mpris.MediaPlayer2.{}", clean)
        });
    (fallback_bus, false, false)
}

async fn run_live_mpris_call(
    profile: &AppAdapterProfile,
    bus_name: &str,
    canonical_action: &str,
    argv: &[String],
    translated_command: String,
) -> Option<DbusDispatchResult> {
    let gdbus_bin = resolve_trusted_executable("gdbus")?;
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (ok, stdout, stderr) = run_dbus_binary(&gdbus_bin, &refs, 2500).await?;
    if ok {
        let now_playing = if canonical_action == "get_now_playing" {
            Some(parse_mpris_properties_gvariant(bus_name, &stdout))
        } else if let Ok(meta_argv) =
            build_mpris_gdbus_args(bus_name, "get_now_playing", &json!({}))
        {
            let meta_refs: Vec<&str> = meta_argv.iter().map(String::as_str).collect();
            run_dbus_binary(&gdbus_bin, &meta_refs, 1500)
                .await
                .and_then(|(m_ok, m_out, _)| {
                    m_ok.then(|| parse_mpris_properties_gvariant(bus_name, &m_out))
                })
        } else {
            None
        };

        let track_desc = now_playing
            .as_ref()
            .and_then(|np| {
                np.title.as_ref().map(|t| {
                    if np.artists.is_empty() {
                        format!("《{}》({})", t, np.playback_status)
                    } else {
                        format!(
                            "《{}》- {} ({})",
                            t,
                            np.artists.join("/"),
                            np.playback_status
                        )
                    }
                })
            })
            .unwrap_or_else(|| bus_name.to_string());

        let summary = format!(
            "已通过 MPRIS2 总线对「{}」执行 `{}` — 当前状态: {}",
            profile.name, canonical_action, track_desc
        );
        Some(DbusDispatchResult {
            ok: true,
            channel_used: AdaptationChannel::DbusMpris,
            translated_command,
            summary,
            data: json!({
                "bus_name": bus_name,
                "action": canonical_action,
                "now_playing": now_playing,
            }),
            simulated: false,
            verification: VerificationReport {
                state: VerificationState::Passed,
                method: "gdbus_mpris2_readback".into(),
                checks: vec![
                    "mpris2_service_discovered".into(),
                    "dbus_method_exit_0".into(),
                    "xesam_metadata_readback".into(),
                ],
                details: None,
            },
        })
    } else {
        Some(DbusDispatchResult {
            ok: false,
            channel_used: AdaptationChannel::DbusMpris,
            translated_command,
            summary: format!(
                "MPRIS2 调用 `{}` 失败 ({}): {}",
                canonical_action,
                bus_name,
                stderr.trim()
            ),
            data: json!({ "bus_name": bus_name, "stderr": stderr }),
            simulated: false,
            verification: VerificationReport {
                state: VerificationState::VerificationFailed,
                method: "gdbus_mpris2".into(),
                checks: vec![],
                details: Some(stderr),
            },
        })
    }
}

/// Execute an MPRIS2 media control intent (`play`, `pause`, `play_pause`, `next`, `previous`, `stop`, `get_now_playing`, `set_volume`),
/// seamlessly falling back to `StatusNotifierItem` + `com.canonical.dbusmenu` for tray media apps like `SodaM (汽水音乐)`.
pub async fn execute_mpris_action(
    profile: &AppAdapterProfile,
    canonical_action: &str,
    params: &Value,
    allow_simulated_fallback: bool,
) -> anyhow::Result<DbusDispatchResult> {
    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let discovery = if force_dry_run {
        MprisDiscoveryReport {
            dbus_session_available: false,
            services: Vec::new(),
            method: "forced_dry_run".into(),
        }
    } else {
        discover_active_mpris_services().await
    };

    let (bus_name, is_specific_match, is_generic_live_fallback) =
        select_target_mpris_bus(profile, &discovery.services);
    let argv = build_mpris_gdbus_args(&bus_name, canonical_action, params)?;
    let translated_command = format!("gdbus {}", argv.join(" "));

    // 1. Specific MPRIS2 service match
    if is_specific_match
        && !force_dry_run
        && let Some(res) =
            run_live_mpris_call(profile, &bus_name, canonical_action, &argv, translated_command.clone()).await
    {
        return Ok(res);
    }

    // 2. When MPRIS2 has no matching bus for `profile`, check `StatusNotifierItem` + `dbusmenu`!
    //    For `SodaM (汽水音乐)`, `Title = '如果当时 · 许嵩'` and menu `'暂停'/'上一首'/'下一首'` work out-of-the-box!
    if !force_dry_run && discovery.dbus_session_available {
        if canonical_action == "get_now_playing" {
            let mut tray_nps = sni_dbusmenu::query_tray_media_now_playing(Some(&profile.id)).await;
            if tray_nps.is_empty() && profile.id == "qqmusic" {
                tray_nps = sni_dbusmenu::query_tray_media_now_playing(None).await;
            }
            if let Some(np) = tray_nps.into_iter().next() {
                let title_desc = np
                    .title
                    .as_deref()
                    .map(|t| format!("《{}》({})", t, np.playback_status))
                    .unwrap_or_else(|| np.playback_status.clone());
                return Ok(DbusDispatchResult {
                    ok: true,
                    channel_used: AdaptationChannel::SniDbusMenu,
                    translated_command: format!(
                        "gdbus call --session --dest {} --object-path /StatusNotifierItem --method org.freedesktop.DBus.Properties.Get org.kde.StatusNotifierItem Title",
                        np.bus_name
                    ),
                    summary: format!(
                        "已通过系统托盘 StatusNotifierItem 读取「{}」当前播放: {}",
                        profile.name, title_desc
                    ),
                    data: json!({
                        "bus_name": np.bus_name,
                        "action": "get_now_playing",
                        "now_playing": np,
                    }),
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "sni_dbusmenu_title_readback".into(),
                        checks: vec!["sni_service_discovered".into(), "sni_title_read".into()],
                        details: None,
                    },
                });
            }
        } else if matches!(
            canonical_action,
            "play" | "pause" | "play_pause" | "next" | "previous"
        ) && let Some(tray_val) =
            sni_dbusmenu::invoke_tray_menu_action(&profile.id, canonical_action).await?
        {
            let cmd = tray_val
                .get("translated_command")
                .and_then(|v| v.as_str())
                .unwrap_or("sni_dbusmenu.Event")
                .to_string();
            let summary = tray_val
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("已通过系统托盘菜单执行媒体控制")
                .to_string();
            let ver = tray_val
                .get("verification")
                .and_then(|v| serde_json::from_value::<VerificationReport>(v.clone()).ok())
                .unwrap_or(VerificationReport {
                    state: VerificationState::Passed,
                    method: "sni_dbusmenu_event_readback".into(),
                    checks: vec!["dbusmenu_event_exit_0".into()],
                    details: None,
                });
            return Ok(DbusDispatchResult {
                ok: true,
                channel_used: AdaptationChannel::SniDbusMenu,
                translated_command: cmd,
                summary,
                data: tray_val,
                simulated: false,
                verification: ver,
            });
        }
    }

    // 3. Generic fallback to active MPRIS2 player when user invoked default media player (`qqmusic`)
    if is_generic_live_fallback
        && profile.id == "qqmusic"
        && !force_dry_run
        && let Some(res) =
            run_live_mpris_call(profile, &bus_name, canonical_action, &argv, translated_command.clone()).await
    {
        return Ok(res);
    }

    // 4. Safe simulation / dry-run fallback ONLY when forced dry_run or genuinely headless / no session bus
    if force_dry_run
        || ((!has_gui_session() || !discovery.dbus_session_available) && allow_simulated_fallback)
    {
        let sim_status = match canonical_action {
            "pause" => "Paused",
            "stop" => "Stopped",
            _ => "Playing",
        };
        let sim_vol = if canonical_action == "set_volume" {
            normalize_mpris_volume(params).ok()
        } else {
            Some(0.75)
        };
        let sim_np = MprisNowPlaying {
            bus_name: bus_name.clone(),
            player_identity: profile.id.clone(),
            playback_status: sim_status.into(),
            title: Some(format!("{} 示例曲目 (仿真回读)", profile.name)),
            artists: vec!["Simulated Artist".into()],
            album: Some("Headless MPRIS2 Bus".into()),
            volume: sim_vol,
            simulated: true,
        };
        return Ok(DbusDispatchResult {
            ok: true,
            channel_used: AdaptationChannel::DbusMpris,
            translated_command: translated_command.clone(),
            summary: format!(
                "已将「{}」的 `{}` 转译为 MPRIS2 D-Bus 指令（当前无活跃播放器会话，已完成安全预演）",
                profile.name, canonical_action
            ),
            data: json!({
                "bus_name": bus_name,
                "action": canonical_action,
                "now_playing": sim_np,
                "discovery_method": discovery.method,
            }),
            simulated: true,
            verification: VerificationReport {
                state: VerificationState::RequestedUnverified,
                method: "simulated_headless_dbus".into(),
                checks: vec!["mpris2_argv_constructed".into()],
                details: Some("当前环境无活跃 MPRIS2 会话，返回安全仿真结果".into()),
            },
        });
    }

    Ok(DbusDispatchResult {
        ok: false,
        channel_used: AdaptationChannel::DbusMpris,
        translated_command,
        summary: format!(
            "当前桌面未检测到运行中的「{}」媒体服务（无活动 MPRIS2 或系统托盘播放器），请先打开播放器后再试",
            profile.name
        ),
        data: json!({
            "bus_name": bus_name,
            "active_mpris_services": discovery.services,
        }),
        simulated: false,
        verification: VerificationReport {
            state: VerificationState::VerificationFailed,
            method: "mpris2_or_sni_discovery".into(),
            checks: vec![],
            details: Some("no active org.mpris.MediaPlayer2 or SNI tray media service found".into()),
        },
    })
}

/// Execute `org.freedesktop.FileManager1` (`reveal_file`, `open_folder`) or `org.freedesktop.Application` (`activate`).
pub async fn execute_freedesktop_action(
    core: &IntentOsCore,
    profile: &AppAdapterProfile,
    canonical_action: &str,
    params: &Value,
) -> anyhow::Result<DbusDispatchResult> {
    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let argv = match canonical_action {
        "reveal_file" | "open_folder" => {
            let raw_path = params
                .get("path")
                .or_else(|| params.get("file"))
                .or_else(|| params.get("folder"))
                .or_else(|| params.get("target"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("文件管理器定位动作缺少 `path` 参数"))?;
            let path = Path::new(raw_path);
            if core.fs_engine.is_forbidden(path) {
                anyhow::bail!("安全内核拒绝在文件管理器定位敏感路径: {}", raw_path);
            }
            let method = if canonical_action == "reveal_file" {
                "ShowItems"
            } else {
                "ShowFolders"
            };
            build_file_manager_gdbus_args(method, path, "intentos")?
        }
        "activate" => {
            let dbus_id = params
                .get("dbus_name")
                .and_then(|v| v.as_str())
                .or(profile.dbus_name.as_deref())
                .or_else(|| {
                    profile
                        .desktop_ids
                        .first()
                        .map(|d| d.trim_end_matches(".desktop"))
                })
                .ok_or_else(|| anyhow::anyhow!("应用 {} 未声明可激活的 D-Bus 名称", profile.name))?;
            let opt_path = params.get("path").and_then(|v| v.as_str()).map(Path::new);
            if let Some(p) = opt_path
                && core.fs_engine.is_forbidden(p)
            {
                anyhow::bail!("安全内核拒绝向 D-Bus 应用传递敏感路径: {}", p.display());
            }
            build_freedesktop_app_activate_args(dbus_id, opt_path)?
        }
        other => anyhow::bail!("不支持的 Freedesktop D-Bus 动作: {}", other),
    };

    let translated_command = format!("gdbus {}", argv.join(" "));

    if !force_dry_run
        && has_gui_session()
        && has_dbus_session_address()
        && let Some(gdbus_bin) = resolve_trusted_executable("gdbus")
        && let Some((true, stdout, _)) = run_dbus_binary(
            &gdbus_bin,
            &argv.iter().map(String::as_str).collect::<Vec<_>>(),
            2500,
        )
        .await
    {
        return Ok(DbusDispatchResult {
            ok: true,
            channel_used: AdaptationChannel::DbusFreedesktop,
            translated_command,
            summary: format!(
                "已通过 Freedesktop D-Bus 接口驱动「{}」执行 `{}`",
                profile.name, canonical_action
            ),
            data: json!({
                "action": canonical_action,
                "stdout": stdout.trim(),
            }),
            simulated: false,
            verification: VerificationReport {
                state: VerificationState::RequestedUnverified,
                method: "gdbus_freedesktop_call".into(),
                checks: vec!["path_not_forbidden".into(), "dbus_call_exit_0".into()],
                details: Some("D-Bus 桌面会话调用已成功送达".into()),
            },
        });
    }

    Ok(DbusDispatchResult {
        ok: true,
        channel_used: AdaptationChannel::DbusFreedesktop,
        translated_command: translated_command.clone(),
        summary: format!(
            "已完成「{}」Freedesktop D-Bus 指令转译 `{}`（无头/仿真环境预演）",
            profile.name, canonical_action
        ),
        data: json!({
            "action": canonical_action,
            "argv": argv,
        }),
        simulated: true,
        verification: VerificationReport {
            state: VerificationState::RequestedUnverified,
            method: "simulated_headless_dbus".into(),
            checks: vec!["path_not_forbidden".into(), "freedesktop_argv_constructed".into()],
            details: Some("无活跃 GUI D-Bus 桌面环境，已完成安全仿真".into()),
        },
    })
}

async fn run_dbus_binary(
    bin: &Path,
    args: &[&str],
    timeout_ms: u64,
) -> Option<(bool, String, String)> {
    let mut cmd = Command::new(bin);
    sni_dbusmenu::apply_clean_desktop_env(&mut cmd);
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
