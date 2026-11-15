#![forbid(unsafe_code)]

//! Comprehensive End-to-End Integration Test Suite for Wave 4:
//! 1) Personalized App Launch & Verification (`"打开汽水音乐"` & `"SodaM"` case-insensitive /
//!    query-to-pinyin keyword resolution `Keywords=music;qishui;soda;sodam;` -> `sodam.desktop`,
//!    zero `gtk-launch: 没有该应用程序 SodaM` failure, `gio launch` + `/proc` PID verification +
//!    already-running wake-up, and honest `VerificationFailed` on nonexistent apps).
//! 2) Universal `StatusNotifierItem` + `com.canonical.dbusmenu` Layout Parser & `sni_dbusmenu`
//!    (`SodaM` `暂停/上一首/下一首/显示主窗口/退出` + `Title='如果当时 · 许嵩'` and `wpscloudsvr`
//!    `启动 WPS Office/查看传输详情/退出` with embedded `icon-data` byte arrays) + the 9th AIOS tool
//!    `app_adapter_inspect_app` end-to-end in BOTH L2 and Quick-Chat OpenAI tool-calling loops!
//! 3) Clean Desktop Subprocess Environment (`LD_LIBRARY_PATH=/home/alice/miniconda3/lib:/usr/local/lib`
//!    strips Conda segments while keeping `/usr/local/lib`, `resolve_system_gi_python3` selects
//!    `/usr/bin/python3`, and `apply_clean_desktop_env` strips `CONDA_*`/`PYTHONPATH`).
//! 4) Honest Real GUI Session Semantics (`DISPLAY` / `WAYLAND_DISPLAY` present in `gui_bridge`
//!    never fabricates `simulated: true` or `"无头/仿真环境预演"`, plus deterministic routing for
//!    `"暂停音乐"`, `"下一首歌"`, and `"聚焦汽水音乐窗口"`).

use axum::{Json, Router, extract::State, routing::post};
use intentos_protocol::{
    CapabilityCall, ExecutionStatus, IntentRequest, InvocationOrigin, TaskStatus, VerificationState,
};
use intentosd::app_adapter::dynamic_profiler::clear_desktop_discovery_cache;
use intentosd::app_adapter::gui_bridge::{
    execute_gui_bridge_action, should_use_headless_simulation,
};
use intentosd::app_adapter::mpris_dbus::has_gui_session;
use intentosd::app_adapter::registry::AdapterRegistry;
use intentosd::app_adapter::sni_dbusmenu::{
    LiveTrayApp, apply_clean_desktop_env, build_dbusmenu_event_args,
    build_dbusmenu_get_layout_args, is_sensitive_tray_menu_label, is_tray_media_player,
    match_menu_item_for_action, match_tray_app_for_hint, parse_dbusmenu_layout_gvariant,
    resolve_system_gi_python3, sanitize_ld_library_path, tray_app_to_now_playing,
};
use intentosd::backend_bridge::{DiscoveryOptions, send_quick_chat_turn_with_options};
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use intentosd::resource::sanitize_desktop_ld_library_path;
use intentosd::router::RoutedIntent;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

fn repo_root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn init_test_core(base: &Path, ws: &Path) -> Arc<IntentOsCore> {
    let repo_root = repo_root_dir();
    let xdg = XdgPaths::resolve(Some(base), repo_root.clone());
    xdg.ensure_dirs().unwrap();
    let cfg = AppConfig {
        authorized_directories: vec![ws.to_string_lossy().to_string()],
        allow_simulated_hardware_fallback: true,
        ..AppConfig::default()
    };
    std::fs::write(
        xdg.config_dir.join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    std::fs::write(
        xdg.config_dir.join("brain.toml"),
        toml::to_string_pretty(&BrainConfig::default()).unwrap(),
    )
    .unwrap();
    IntentOsCore::initialize(Some(base), repo_root).expect("init test core")
}

fn write_executable_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

// =============================================================================
// Test 1: `"打开汽水音乐"` & `"SodaM"` Case-Insensitive / Pinyin-Keyword Resolution,
//         `gio launch` + `/proc` PID Verification, Already-Running Wake & Honest Failure
// =============================================================================

#[tokio::test]
async fn wave4_test1_sodam_pinyin_keyword_resolution_gio_launch_and_honest_missing_failure() {
    clear_desktop_discovery_cache();

    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("xdg_base");
    let ws = base.join("workspace");
    let apps_dir = base.join("applications");
    let bin_dir = base.join("bin");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&apps_dir).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();

    // Create a lightweight hermetic mock binary `sodam-wave4-testbin` so we never mutate or kill
    // any real user `SodaM` session while exercising the real `gio launch` + `/proc` PID pipeline!
    let pid_record_file = base.join("sodam_launched_pid.txt");
    let mock_bin_path = bin_dir.join("sodam-wave4-testbin");
    write_executable_file(
        &mock_bin_path,
        &format!(
            "#!/bin/sh\necho $$ > \"{}\"\nsleep 2.2\n",
            pid_record_file.display()
        ),
    );

    // Authentic `sodam.desktop` structure: lowercase filename `sodam.desktop`, mixed-case `Name=SodaM`,
    // NO `Name[zh_CN]`, and `Keywords=music;qishui;soda;sodam;`!
    let sodam_desktop_path = apps_dir.join("sodam.desktop");
    write_executable_file(
        &sodam_desktop_path,
        &format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=SodaM\n\
             GenericName=Music Player\n\
             Comment=SodaM music client\n\
             Exec={}\n\
             Icon=sodam\n\
             Terminal=false\n\
             Categories=AudioVideo;Audio;Music;Player;\n\
             Keywords=music;qishui;soda;sodam;\n\
             StartupWMClass=SodaM\n",
            mock_bin_path.display()
        ),
    );

    let core = init_test_core(&base, &ws);

    // 1. Verify `"打开汽水音乐"`, `"SodaM"`, `"sodam"`, and `"qishui"` all resolve to `sodam.desktop`
    for hint in ["汽水音乐", "SodaM", "sodam", "SODAM.DESKTOP", "qishui"] {
        let rec = core
            .resources
            .resolve_best_app(hint)
            .unwrap_or_else(|| panic!("expected '{}' to resolve to sodam.desktop", hint));
        assert_eq!(rec.app_id, "sodam.desktop");
        assert_eq!(rec.name, "SodaM");
        assert_eq!(
            rec.source,
            sodam_desktop_path.to_string_lossy().to_string(),
            "temp fixture sodam.desktop should override system entry for hermetic test"
        );
    }

    // 2. Verify L0 router routes `"打开汽水音乐"` and `"打开 SodaM"` deterministically to `app.launch` (`sodam.desktop`)
    match core.router.route_text("打开汽水音乐", false) {
        RoutedIntent::ExecuteL0 {
            capability_id,
            arguments,
            ..
        } => {
            assert_eq!(capability_id, "app.launch");
            assert_eq!(arguments["app_id"], "sodam.desktop");
            assert_eq!(arguments["query"], "汽水音乐");
        }
        other => panic!(
            "expected ExecuteL0 app.launch for 打开汽水音乐, got {:?}",
            other
        ),
    }

    // 3. Execute `"打开汽水音乐"` end-to-end: when GUI display & `gio` exist, verifies real `/proc` PID spawn
    //    and zero `gtk-launch: 没有该应用程序 SodaM` error!
    let launch_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "打开汽水音乐".into(),
                session_id: Some("ses_wave4_t1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: None,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert_eq!(launch_task.status, TaskStatus::Completed);
    let step = launch_task.steps.first().expect("app.launch step");
    assert!(!step.message.contains("没有该应用程序"));
    assert!(
        !step
            .stderr_summary_or_msg()
            .contains("SodaM: No such application")
    );

    if has_gui_session() && Path::new("/usr/bin/gio").is_file() {
        assert_eq!(step.status, ExecutionStatus::Exited);
        assert_eq!(step.verification.state, VerificationState::Passed);
        assert!(
            step.message.contains("汽水音乐 (SodaM)") && step.message.contains("PID"),
            "expected verified launch message with PID, got: {}",
            step.message
        );
        assert_eq!(step.data["already_running"], json!(false));
        let spawned_pid = step.data["pid"].as_u64().expect("verified pid") as u32;
        assert!(spawned_pid > 1);

        // Second `"打开汽水音乐"` while process is still alive in `/proc`: verifies already-running wake path!
        let second_task = core
            .submit_intent(
                IntentRequest {
                    protocol_version: 1,
                    text: "打开汽水音乐".into(),
                    session_id: Some("ses_wave4_t1".into()),
                    force_agent: false,
                    selected_candidate_id: None,
                    cwd: None,
                    incognito: false,
                    privacy_policy: None,
                },
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(second_task.status, TaskStatus::Completed);
        let second_step = second_task.steps.first().expect("second app.launch step");
        assert_eq!(second_step.status, ExecutionStatus::Exited);
        assert_eq!(second_step.verification.state, VerificationState::Passed);
        assert_eq!(second_step.data["already_running"], json!(true));
        assert!(
            second_step.message.contains("已在运行"),
            "expected already-running message, got: {}",
            second_step.message
        );

        // Cleanly close our test process via `app.quit`
        let _ = core
            .broker
            .dispatch(&CapabilityCall {
                request_id: "cleanup_sodam_testbin".into(),
                task_id: "task_cleanup".into(),
                capability_id: "app.quit".into(),
                arguments: json!({ "app": "sodam-wave4-testbin" }),
                origin: InvocationOrigin::UserExplicit,
                taints: vec![],
            })
            .await;
    }

    // 4. Nonexistent app `"打开不存在的宇宙飞船软件XYZ"` MUST return honest `VerificationFailed` (never fake success!)
    let missing_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "打开不存在的宇宙飞船软件XYZ".into(),
                session_id: Some("ses_wave4_t1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: None,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        missing_task.status,
        TaskStatus::Failed,
        "nonexistent app must fail honestly: {:?}",
        missing_task
    );
    let missing_step = missing_task.steps.first().expect("failed app.launch step");
    assert_eq!(missing_step.status, ExecutionStatus::VerificationFailed);
    assert_eq!(
        missing_step.verification.state,
        VerificationState::VerificationFailed
    );
    assert!(missing_step.message.contains("未在本机找到应用"));
}

trait StepMsgExt {
    fn stderr_summary_or_msg(&self) -> &str;
}
impl StepMsgExt for intentos_protocol::TaskStep {
    fn stderr_summary_or_msg(&self) -> &str {
        &self.message
    }
}

// =============================================================================
// Test 2: `parse_dbusmenu_layout_gvariant` & `sni_dbusmenu` (`SodaM` + `wpscloudsvr`)
//         + 9th AIOS Tool `app_adapter_inspect_app` End-to-End in L2 & Quick-Chat Loop
// =============================================================================

#[derive(Clone, Default)]
struct Wave4MockLlmState {
    captured_requests: Arc<Mutex<Vec<Value>>>,
}

async fn wave4_mock_chat_completions(
    State(st): State<Wave4MockLlmState>,
    Json(req): Json<Value>,
) -> Json<Value> {
    st.captured_requests.lock().unwrap().push(req.clone());

    let messages = req["messages"].as_array().cloned().unwrap_or_default();
    let last_role = messages
        .last()
        .and_then(|m| m["role"].as_str())
        .unwrap_or("user");

    // Round 1: LLM calls the new 9th AIOS tool `app_adapter_inspect_app`
    if last_role != "tool" {
        return Json(json!({
            "id": "chatcmpl-wave4-r1",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>用户询问个性化软件汽水音乐的状态与控制方式，我先调用 app_adapter_inspect_app 探测其 .desktop、进程与托盘菜单。</think>",
                    "tool_calls": [{
                        "id": "call_inspect_sodam_1",
                        "type": "function",
                        "function": {
                            "name": "app_adapter_inspect_app",
                            "arguments": "{\"app\":\"汽水音乐\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        }));
    }

    // Round 2: Verify tool output from `app_adapter_inspect_app` and synthesize final reply
    let tool_payload_str = messages
        .iter()
        .rev()
        .find(|m| m["role"] == "tool")
        .and_then(|m| m["content"].as_str())
        .unwrap_or("{}");
    let tool_json: Value = serde_json::from_str(tool_payload_str).unwrap_or_else(|_| json!({}));
    let data_root = tool_json.get("data").unwrap_or(&tool_json);
    let desktop_id = data_root
        .get("desktop_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let app_id = data_root
        .get("app_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    Json(json!({
        "id": "chatcmpl-wave4-r2",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": format!(
                    "<think>已拿到 app_adapter_inspect_app 返回结果：{}/{}</think>已通过实时软件探测确认「汽水音乐」对应入口 `{}` (`{}`)，可通过系统托盘菜单直接唤醒或控制播放。",
                    app_id, desktop_id, desktop_id, app_id
                )
            },
            "finish_reason": "stop"
        }]
    }))
}

#[tokio::test]
async fn wave4_test2_sni_dbusmenu_sodam_wps_parsing_and_inspect_app_tool_loop() {
    clear_desktop_discovery_cache();

    // -------------------------------------------------------------------------
    // Part A: Authentic `SodaM` & `wpscloudsvr` `com.canonical.dbusmenu` GVariant layouts
    // -------------------------------------------------------------------------
    let sodam_gvariant = r#"(uint32 7, (0, {'children-display': <'submenu'>}, [
        <(1, {'label': <'暂停'>, 'enabled': <true>, 'visible': <true>}, [])>,
        <(2, {'label': <'上一首'>, 'enabled': <true>, 'visible': <true>}, [])>,
        <(3, {'label': <'下一首'>, 'enabled': <true>, 'visible': <true>}, [])>,
        <(4, {'type': <'separator'>, 'visible': <true>}, [])>,
        <(5, {'label': <'显示主窗口'>, 'enabled': <true>, 'visible': <true>}, [])>,
        <(6, {'label': <'退出'>, 'enabled': <true>, 'visible': <true>}, [])>
    ]))"#;

    let sodam_items = parse_dbusmenu_layout_gvariant(sodam_gvariant);
    let sodam_labels: Vec<&str> = sodam_items.iter().map(|i| i.label.as_str()).collect();
    assert_eq!(
        sodam_labels,
        vec!["暂停", "上一首", "下一首", "显示主窗口", "退出"]
    );

    let sodam_tray = LiveTrayApp {
        service: "org.kde.StatusNotifierItem-48120-1".into(),
        interface: "org.kde.StatusNotifierItem".into(),
        pid: Some(48120),
        comm: Some("sodam".into()),
        cmdline: Some("/usr/bin/sodam".into()),
        id: "chrome_status_icon_1".into(),
        title: "如果当时 · 许嵩".into(),
        status: "Active".into(),
        menu_path: Some("/com/canonical/dbusmenu".into()),
        menu_items: sodam_items.clone(),
    };

    assert!(is_tray_media_player(&sodam_tray));
    let np = tray_app_to_now_playing(&sodam_tray);
    assert_eq!(np.playback_status, "Playing");
    assert_eq!(np.title.as_deref(), Some("如果当时 · 许嵩"));
    assert!(!np.simulated);

    // Verify semantic action -> tray menu item resolution on `SodaM`
    assert_eq!(
        match_menu_item_for_action(&sodam_items, "pause")
            .unwrap()
            .label,
        "暂停"
    );
    assert_eq!(
        match_menu_item_for_action(&sodam_items, "play_pause")
            .unwrap()
            .label,
        "暂停"
    );
    assert_eq!(
        match_menu_item_for_action(&sodam_items, "next")
            .unwrap()
            .label,
        "下一首"
    );
    assert_eq!(
        match_menu_item_for_action(&sodam_items, "previous")
            .unwrap()
            .label,
        "上一首"
    );
    assert_eq!(
        match_menu_item_for_action(&sodam_items, "focus_window")
            .unwrap()
            .label,
        "显示主窗口"
    );
    assert_eq!(
        match_menu_item_for_action(&sodam_items, "quit")
            .unwrap()
            .label,
        "退出"
    );
    assert!(is_sensitive_tray_menu_label("退出登录"));
    assert!(!is_sensitive_tray_menu_label("显示主窗口"));

    // Verify Chinese `"汽水音乐"` matches `sodam_tray` via `match_tray_app_for_hint`
    let tray_slice = vec![sodam_tray.clone()];
    let matched = match_tray_app_for_hint(&tray_slice, "汽水音乐", None)
        .expect("汽水音乐 should match SodaM tray app");
    assert_eq!(matched.pid, Some(48120));

    // Authentic `wpscloudsvr` layout with embedded binary PNG `icon-data` array and mnemonic `(_O)`
    let wps_gvariant = r#"(uint32 12, (0, {'children-display': <'submenu'>}, [
        <(10, {'label': <'启动 WPS Office (_O)'>, 'enabled': <true>, 'icon-data': <[byte 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]>}, [])>,
        <(11, {'label': <'查看传输详情'>, 'enabled': <true>, 'visible': <true>}, [])>,
        <(12, {'type': <'separator'>}, [])>,
        <(13, {'label': <'退出'>, 'enabled': <true>, 'visible': <true>}, [])>
    ]))"#;
    let wps_items = parse_dbusmenu_layout_gvariant(wps_gvariant);
    let wps_labels: Vec<&str> = wps_items.iter().map(|i| i.label.as_str()).collect();
    assert_eq!(wps_labels, vec!["启动 WPS Office", "查看传输详情", "退出"]);
    assert_eq!(
        match_menu_item_for_action(&wps_items, "focus_window")
            .unwrap()
            .label,
        "启动 WPS Office"
    );

    // Verify discrete non-shell `gdbus` argv builders (`--` before `0 -1`!)
    let layout_args = build_dbusmenu_get_layout_args(
        "org.kde.StatusNotifierItem-48120-1",
        "/com/canonical/dbusmenu",
    )
    .unwrap();
    assert!(layout_args.contains(&"--".to_string()));
    let event_args = build_dbusmenu_event_args(
        "org.kde.StatusNotifierItem-48120-1",
        "/com/canonical/dbusmenu",
        5,
        "clicked",
        0,
    )
    .unwrap();
    assert!(
        event_args
            .iter()
            .any(|a| a == "com.canonical.dbusmenu.Event")
    );

    // -------------------------------------------------------------------------
    // Part B: 9 AIOS Tools (`app_adapter_inspect_app`) End-to-End in BOTH L2 & Quick-Chat!
    // -------------------------------------------------------------------------
    let mock_state = Wave4MockLlmState::default();
    let app = Router::new()
        .route("/v1/chat/completions", post(wave4_mock_chat_completions))
        .with_state(mock_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("xdg_base");
    let ws = base.join("workspace");
    let apps_dir = base.join("config/applications");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&apps_dir).unwrap();

    // Seed `sodam.desktop` in `config/applications` so `app_adapter_inspect_app` discovers it on every host
    write_executable_file(
        &apps_dir.join("sodam.desktop"),
        "[Desktop Entry]\nType=Application\nName=SodaM\nExec=/usr/bin/sodam\nCategories=AudioVideo;Music;Player;\nKeywords=music;qishui;soda;sodam;\nStartupWMClass=SodaM\n",
    );

    let core = init_test_core(&base, &ws);
    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}/v1", addr)));

    // Verify `CapabilityBroker::aios_tool_specs()` exposes ALL 9 AIOS tools (5 memory_hub + 4 app_adapter)
    let aios_specs = core.broker.aios_tool_specs();
    assert_eq!(
        aios_specs.len(),
        9,
        "expected 9 AIOS tools (5 memory_hub + 4 app_adapter), got: {:?}",
        aios_specs.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
    assert!(
        aios_specs
            .iter()
            .any(|s| s.name == "app_adapter_inspect_app")
    );

    // 1) Run L2 Native Agent Loop (`force_agent: true`)
    let l2_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "帮我操作汽水音乐，看看它怎么还没有打开".into(),
                session_id: Some("ses_wave4_l2".into()),
                force_agent: true,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: None,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(l2_task.status, TaskStatus::Completed);
    assert!(
        l2_task
            .steps
            .iter()
            .any(|s| s.capability_id == "app_adapter_inspect_app"),
        "L2 loop must execute app_adapter_inspect_app"
    );
    assert!(
        l2_task
            .assistant_message
            .as_deref()
            .unwrap_or("")
            .contains("sodam.desktop")
    );

    // 2) Run Quick-Chat OpenAI Tool-Calling Loop (`send_quick_chat_turn_with_options`)
    mock_state.captured_requests.lock().unwrap().clear();
    let mock_home = temp.path().join("mock_qc_home");
    let zcode_cfg_path = mock_home.join(".zcode/v2/provider_config.json");
    std::fs::create_dir_all(zcode_cfg_path.parent().unwrap()).unwrap();
    std::fs::write(
        &zcode_cfg_path,
        serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "config": {
                "providerOrder": ["wave4_openai"],
                "providerConfigRules": {
                    "providerRules": [{
                        "providerId": "wave4_openai",
                        "templateId": "openai",
                        "providerName": "Wave4 Mock OpenAI",
                        "config": {
                            "access": { "type": "api-key", "apiKey": "sk-wave4-qc" },
                            "api": { "baseUrl": format!("http://{}/v1", addr) },
                            "modelOrder": ["gpt-wave4-qc"]
                        }
                    }]
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let mock_zcode_cjs = mock_home.join("zcode.cjs");
    std::fs::write(&mock_zcode_cjs, "// stub\n").unwrap();
    let mut disc_opts = DiscoveryOptions::isolated_for_test(mock_home);
    disc_opts.opt_zcode_cjs = Some(mock_zcode_cjs);

    let qc_resp = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_wave4_inspect_1",
            "session_id": "ses_wave4_qc",
            "text": "汽水音乐怎么还没有打开？帮我看看状态",
            "incognito": false,
        }),
        &disc_opts,
    )
    .await
    .unwrap();

    assert_eq!(qc_resp["status"], "completed");
    assert!(
        qc_resp["reply_markdown"]
            .as_str()
            .unwrap_or("")
            .contains("sodam.desktop")
    );
    let dots = qc_resp["trace_dots"].as_array().expect("trace_dots array");
    assert!(dots.iter().any(|d| d["kind"] == "thinking"));
    assert!(dots.iter().any(|d| d["kind"] == "adapter"));

    // Verify system prompt hint & all 9 AIOS tools were delivered to the LLM in Quick-Chat!
    let reqs = mock_state.captured_requests.lock().unwrap();
    assert!(reqs.len() >= 2);
    let first_req = &reqs[0];
    let sys_prompt = first_req["messages"][0]["content"].as_str().unwrap_or("");
    assert!(
        sys_prompt.contains("app_adapter_inspect_app"),
        "system prompt must guide LLM to call app_adapter_inspect_app"
    );
    assert!(sys_prompt.contains("怎么还没有打开"));
    let sent_tool_names: Vec<&str> = first_req["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["function"]["name"].as_str())
        .collect();
    for expected_tool in [
        "memory_recall_mentioned_files",
        "memory_get_frequent_files",
        "memory_get_software_catalog",
        "memory_search_past_chats",
        "memory_inspect_document",
        "app_adapter_invoke",
        "app_adapter_list",
        "app_adapter_now_playing",
        "app_adapter_inspect_app",
    ] {
        assert!(
            sent_tool_names.contains(&expected_tool),
            "Quick-Chat toolset missing '{}': {:?}",
            expected_tool,
            sent_tool_names
        );
    }
}

// =============================================================================
// Test 3: Clean Desktop Subprocess Environment (`LD_LIBRARY_PATH` Conda Stripping)
// =============================================================================

#[tokio::test]
async fn wave4_test3_clean_desktop_subprocess_environment_strips_conda_keeps_system_paths() {
    // 1. Direct unit verification on both `sni_dbusmenu` and `resource` sanitizers
    let mixed = "/home/alice/miniconda3/lib:/usr/local/lib";
    assert_eq!(
        sanitize_ld_library_path(mixed),
        Some("/usr/local/lib".to_string())
    );
    assert_eq!(
        sanitize_desktop_ld_library_path(mixed),
        Some("/usr/local/lib".to_string())
    );

    let only_conda = "/home/alice/miniconda3/lib:/opt/anaconda3/envs/base/lib";
    assert_eq!(sanitize_ld_library_path(only_conda), None);
    assert_eq!(sanitize_desktop_ld_library_path(only_conda), None);

    let multi_system =
        "/usr/lib/x86_64-linux-gnu:/home/user/conda/lib:/usr/local/lib:/opt/miniconda3/lib";
    assert_eq!(
        sanitize_ld_library_path(multi_system),
        Some("/usr/lib/x86_64-linux-gnu:/usr/local/lib".to_string())
    );

    // 2. System GI Python3 resolver strictly prefers `/usr/bin/python3` over Conda PATH shadows
    if Path::new("/usr/bin/python3").is_file() {
        assert_eq!(
            resolve_system_gi_python3(),
            Some(PathBuf::from("/usr/bin/python3"))
        );
    }

    // 3. End-to-end subprocess check: pre-seed Conda poison vars on `tokio::process::Command`
    //    and verify `apply_clean_desktop_env` strips `CONDA_PREFIX` / `PYTHONPATH` / `PYTHONHOME`!
    let mut cmd = tokio::process::Command::new("/usr/bin/env");
    cmd.env("CONDA_PREFIX", "/home/alice/miniconda3")
        .env("CONDA_DEFAULT_ENV", "base")
        .env("PYTHONPATH", "/home/alice/miniconda3/lib/python3.12")
        .env("PYTHONHOME", "/home/alice/miniconda3");
    apply_clean_desktop_env(&mut cmd);
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .await
        .expect("spawn /usr/bin/env");
    assert!(out.status.success());
    let env_text = String::from_utf8_lossy(&out.stdout);
    for line in env_text.lines() {
        assert!(!line.starts_with("CONDA_PREFIX="), "leaked CONDA_PREFIX");
        assert!(
            !line.starts_with("CONDA_DEFAULT_ENV="),
            "leaked CONDA_DEFAULT_ENV"
        );
        assert!(!line.starts_with("PYTHONPATH="), "leaked PYTHONPATH");
        assert!(!line.starts_with("PYTHONHOME="), "leaked PYTHONHOME");
        if let Some(ld_val) = line.strip_prefix("LD_LIBRARY_PATH=") {
            assert!(
                !ld_val.to_ascii_lowercase().contains("conda"),
                "child LD_LIBRARY_PATH still contained conda segment: {}",
                ld_val
            );
        }
    }
}

// =============================================================================
// Test 4: Real GUI Session (`DISPLAY` / `WAYLAND_DISPLAY`) Never Fabricates
//         `simulated: true` / `"无头/仿真环境预演"`, + Media & Window Routing
// =============================================================================

#[tokio::test]
async fn wave4_test4_real_gui_session_never_fabricates_headless_simulation_and_routes_media_window()
{
    // 1. Pure truth-table check on `should_use_headless_simulation`
    assert!(!should_use_headless_simulation(true, false));
    assert!(should_use_headless_simulation(true, true));
    assert!(should_use_headless_simulation(false, false));
    assert!(should_use_headless_simulation(false, true));

    // 2. Verify deterministic routing for `"暂停音乐"`, `"下一首歌"`, and `"聚焦汽水音乐窗口"`
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("xdg_base");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_test_core(&base, &ws);

    match core.router.route_text("暂停音乐", false) {
        RoutedIntent::ExecuteL0 {
            capability_id,
            arguments,
            ..
        } => {
            assert_eq!(capability_id, "media.control");
            assert_eq!(arguments["action"], "pause");
        }
        other => panic!("expected media.control pause for 暂停音乐, got {:?}", other),
    }

    match core.router.route_text("下一首歌", false) {
        RoutedIntent::ExecuteL0 {
            capability_id,
            arguments,
            ..
        } => {
            assert_eq!(capability_id, "media.control");
            assert_eq!(arguments["action"], "next");
        }
        other => panic!("expected media.control next for 下一首歌, got {:?}", other),
    }

    match core.router.route_text("聚焦汽水音乐窗口", false) {
        RoutedIntent::ExecuteL0 {
            capability_id,
            arguments,
            ..
        } => {
            assert_eq!(capability_id, "window.focus");
            assert_eq!(arguments["query"], "汽水音乐");
        }
        other => panic!(
            "expected window.focus for 聚焦汽水音乐窗口, got {:?}",
            other
        ),
    }

    // Verify generic `"music"` adapter resolution does NOT get hijacked by `sodam.desktop`'s `Keywords=music`
    let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
    let (generic_media_prof, _) = reg.resolve_adapter_and_action("music", "pause");
    assert_eq!(generic_media_prof.id, "qqmusic");

    // 3. On a real GUI session (`DISPLAY` or `WAYLAND_DISPLAY` set), `gui_bridge` MUST NEVER
    //    fabricate `simulated: true` or `"无头/仿真环境预演"`!
    if has_gui_session() {
        let (nonexistent_prof, _) =
            reg.resolve_adapter_and_action("NonExistentSpaceshipGuiApp999", "focus_window");

        let focus_res = execute_gui_bridge_action(
            &nonexistent_prof,
            "focus_window",
            &json!({ "target": "NonExistentSpaceshipGuiApp999" }),
            true,
        )
        .await
        .unwrap();

        assert!(
            !focus_res.simulated,
            "real GUI session must NEVER return simulated: true"
        );
        assert!(
            !focus_res.summary.contains("无头/仿真环境预演"),
            "real GUI session must NEVER claim 无头/仿真环境预演: {}",
            focus_res.summary
        );
        assert!(
            !focus_res.ok,
            "focusing a non-running app on a real GUI session must honestly return ok: false"
        );
        assert_eq!(
            focus_res.verification.state,
            VerificationState::VerificationFailed
        );

        let list_res =
            execute_gui_bridge_action(&nonexistent_prof, "list_windows", &json!({}), true)
                .await
                .unwrap();
        assert!(!list_res.simulated);
        assert!(!list_res.summary.contains("无头/仿真环境预演"));
        assert_eq!(list_res.verification.state, VerificationState::Passed);
    }

    // 4. Explicit `dry_run: true` still cleanly supports controlled simulation when requested
    let (sodam_prof, _) = reg.resolve_adapter_and_action("汽水音乐", "focus_window");
    let dry_res = execute_gui_bridge_action(
        &sodam_prof,
        "focus_window",
        &json!({ "target": "汽水音乐", "dry_run": true }),
        true,
    )
    .await
    .unwrap();
    assert!(dry_res.simulated);
    assert_eq!(
        dry_res.verification.state,
        VerificationState::RequestedUnverified
    );
}
