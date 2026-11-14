#![forbid(unsafe_code)]

//! Comprehensive End-to-End Integration Test Suite for Wave 5 (`e2e_wave5.rs`):
//! 1) `wave5_test1_approval_resumes_llm_turn_with_tool_data_and_enters_session_plus_session_grant`
//! 2) `wave5_test2_deep_local_software_scan_9_categories_and_rich_translation`
//! 3) `wave5_test3_nonlinear_time_decay_context_compression_strips_tools_and_caps_tokens`
//! 4) `wave5_test4_speech_hub_config_streaming_model_download_and_asr_runner_selftest`

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use intentos_protocol::UiRpcRequest;
use intentosd::app_adapter::dynamic_profiler::clear_desktop_discovery_cache;
use intentosd::backend_bridge::{DiscoveryOptions, send_quick_chat_turn_with_options};
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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

fn make_isolated_openai_discovery(mock_home: &Path, addr: std::net::SocketAddr) -> DiscoveryOptions {
    let zcode_cfg_path = mock_home.join(".zcode/v2/provider_config.json");
    std::fs::create_dir_all(zcode_cfg_path.parent().unwrap()).unwrap();
    std::fs::write(
        &zcode_cfg_path,
        serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "config": {
                "providerOrder": ["wave5_openai"],
                "providerConfigRules": {
                    "providerRules": [{
                        "providerId": "wave5_openai",
                        "templateId": "openai",
                        "providerName": "Wave5 Mock OpenAI",
                        "config": {
                            "access": { "type": "api-key", "apiKey": "sk-wave5-qc" },
                            "api": { "baseUrl": format!("http://{}/v1", addr) },
                            "modelOrder": ["gpt-wave5-qc"]
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
    let mut disc_opts = DiscoveryOptions::isolated_for_test(mock_home.to_path_buf());
    disc_opts.opt_zcode_cjs = Some(mock_zcode_cjs);
    disc_opts
}

async fn call_module_rpc(core: &IntentOsCore, domain: &str, action: &str, payload: Value) -> Value {
    let resp = core
        .handle_trusted_ui_rpc(
            format!("rpc_{}_{}", domain, action),
            UiRpcRequest::ModuleRpc {
                domain: domain.to_string(),
                action: action.to_string(),
                payload,
            },
        )
        .await;
    assert!(
        resp.ok,
        "ModuleRpc {}.{} failed: {:?}",
        domain, action, resp.error
    );
    resp.result.unwrap_or(Value::Null)
}

// =============================================================================
// Test 1: Sensitive Approval Resumes Suspended LLM Turn With Real Tool Data,
//         Persists Full Q&A Into Session ("进入会话"), & Grants Session Scope
// =============================================================================

#[derive(Clone)]
struct Wave5ApprovalMockState {
    captured_requests: Arc<Mutex<Vec<Value>>>,
    outside_dir_str: String,
}

async fn mock_wave5_approval_chat_completions(
    State(state): State<Wave5ApprovalMockState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.captured_requests.lock().unwrap().push(body.clone());
    let messages = body["messages"].as_array().cloned().unwrap_or_default();

    let last_tool_msg = messages
        .iter()
        .rev()
        .find(|m| m["role"].as_str() == Some("tool"));

    let last_user_text = messages
        .iter()
        .rev()
        .find(|m| m["role"].as_str() == Some("user"))
        .and_then(|m| m["content"].as_str())
        .unwrap_or("");

    let is_followup = last_user_text.contains("secret_report_appendix");

    if let Some(tmsg) = last_tool_msg {
        let tool_content = tmsg["content"].as_str().unwrap_or("");
        if is_followup {
            assert!(
                tool_content.contains("secret_report_appendix.md"),
                "Follow-up session-granted tool output must contain secret_report_appendix.md, got: {}",
                tool_content
            );
            Json(json!({
                "id": "chatcmpl_wave5_call4",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "已在会话放行目录直接找到附件 secret_report_appendix.md！"
                    },
                    "finish_reason": "stop"
                }]
            }))
        } else {
            assert!(
                tool_content.contains("secret_report_2026.md"),
                "Resumed LLM call MUST receive real discovered file path secret_report_2026.md in role=tool content, got: {}",
                tool_content
            );
            Json(json!({
                "id": "chatcmpl_wave5_call2",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "已在授权目录为您找到文件 secret_report_2026.md！"
                    },
                    "finish_reason": "stop"
                }]
            }))
        }
    } else if is_followup {
        Json(json!({
            "id": "chatcmpl_wave5_call3",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>继续在已放行的目录检索附件</think>",
                    "tool_calls": [{
                        "id": "call_wave5_search_2",
                        "type": "function",
                        "function": {
                            "name": "file_search",
                            "arguments": serde_json::to_string(&json!({
                                "directory": state.outside_dir_str,
                                "query": "secret_report_appendix"
                            })).unwrap()
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        }))
    } else {
        Json(json!({
            "id": "chatcmpl_wave5_call1",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>用户需要搜索未授权外部目录中的 secret_report</think>",
                    "tool_calls": [{
                        "id": "call_wave5_search_1",
                        "type": "function",
                        "function": {
                            "name": "file_search",
                            "arguments": serde_json::to_string(&json!({
                                "directory": state.outside_dir_str,
                                "query": "secret_report"
                            })).unwrap()
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        }))
    }
}

#[tokio::test]
async fn wave5_test1_approval_resumes_llm_turn_with_tool_data_and_enters_session_plus_session_grant()
{
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("xdg_base");
    let ws = base.join("workspace");
    let outside_dir = temp.path().join("outside_sensitive_vault");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    let secret_file = outside_dir.join("secret_report_2026.md");
    std::fs::write(
        &secret_file,
        "# 2026 年度战略报告\n核心指标已达成 128%。\n",
    )
    .unwrap();

    let core = init_test_core(&base, &ws);

    let mock_state = Wave5ApprovalMockState {
        captured_requests: Arc::new(Mutex::new(Vec::new())),
        outside_dir_str: outside_dir.to_string_lossy().to_string(),
    };
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(mock_wave5_approval_chat_completions),
        )
        .with_state(mock_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mock_home = temp.path().join("mock_qc_home");
    let disc_opts = make_isolated_openai_discovery(&mock_home, addr);

    // Step 1: Initial Quick-Chat turn hits `file.search` on outside directory -> pauses with `awaiting_approval`
    let user_prompt_1 = format!(
        "请帮我在 {} 目录下查找 secret_report 文件并汇报文件名",
        outside_dir.display()
    );
    let turn1 = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_wave5_approve_1",
            "session_id": "ses_wave5_approve",
            "text": user_prompt_1,
            "incognito": false,
        }),
        &disc_opts,
    )
    .await
    .unwrap();

    assert_eq!(turn1["status"], "awaiting_approval");
    let pa = turn1["pending_approval"]
        .as_object()
        .expect("pending_approval object");
    let approval_id = pa["approval_id"].as_str().expect("approval_id").to_string();
    let nonce = pa["nonce"].as_str().expect("nonce").to_string();
    let digest = pa["digest"].as_str().expect("digest").to_string();
    assert!(!approval_id.is_empty() && !nonce.is_empty() && !digest.is_empty());

    let dots1 = turn1["trace_dots"].as_array().expect("trace_dots array");
    assert!(
        dots1.iter().any(|d| d["kind"] == "approval"),
        "Paused turn must include an amber approval trace dot: {:?}",
        dots1
    );
    assert_eq!(mock_state.captured_requests.lock().unwrap().len(), 1);

    // Step 2: Call `backend_bridge.resume_approved_turn` over trusted `ModuleRpc` with `decision: "session"`
    let resumed = call_module_rpc(
        &core,
        "backend_bridge",
        "resume_approved_turn",
        json!({
            "approval_id": approval_id,
            "nonce": nonce,
            "digest": digest,
            "decision": "session",
            "scope_kind": "directory",
            "scope_value": outside_dir.to_string_lossy(),
            "ttl_minutes": 60,
        }),
    )
    .await;

    assert_eq!(resumed["status"], "completed");
    assert_eq!(resumed["approval_resolved"], "approved");
    assert!(
        resumed["pending_approval"].is_null(),
        "Completed resumed turn must clear pending_approval"
    );
    let reply_md = resumed["reply_markdown"].as_str().unwrap_or("");
    assert!(
        reply_md.contains("secret_report_2026.md"),
        "Final assistant reply must incorporate discovered file secret_report_2026.md, got: {}",
        reply_md
    );

    // Verify Call 2 to mock LLM happened and carried `role: "tool"` with `secret_report_2026.md`
    {
        let reqs = mock_state.captured_requests.lock().unwrap();
        assert_eq!(
            reqs.len(),
            2,
            "Expected Call 1 (tool_call) + Call 2 (resumed with tool result)"
        );
        let call2_msgs = reqs[1]["messages"].as_array().unwrap();
        let tool_msg = call2_msgs
            .iter()
            .find(|m| m["role"] == "tool")
            .expect("Call 2 must include role=tool message");
        let tool_json: Value =
            serde_json::from_str(tool_msg["content"].as_str().unwrap()).expect("valid tool JSON");
        assert_eq!(tool_json["approved_by_user"], true);
        let data_str = serde_json::to_string(&tool_json["data"]).unwrap();
        assert!(
            data_str.contains("secret_report_2026.md"),
            "Tool step.data must contain discovered file path secret_report_2026.md: {}",
            data_str
        );
    }

    // Verify the completed turn ENTERED BOTH `core.sessions` AND `memory_hub` ("进入会话")!
    let mem_session = core.sessions.get_or_create(Some("ses_wave5_approve"));
    assert!(
        mem_session.messages.len() >= 2,
        "core.sessions must record (user_text, reply_markdown) turn, got: {:?}",
        mem_session.messages
    );
    assert!(
        mem_session
            .messages
            .iter()
            .any(|m| m.role == "user" && m.content.contains("secret_report")),
        "core.sessions missing user message"
    );
    assert!(
        mem_session
            .messages
            .iter()
            .any(|m| m.role == "assistant" && m.content.contains("secret_report_2026.md")),
        "core.sessions missing resumed assistant reply"
    );
    assert!(
        mem_session
            .last_resource_path
            .as_deref()
            .unwrap_or("")
            .contains("secret_report_2026.md"),
        "session.last_resource_path should record discovered file path, got: {:?}",
        mem_session.last_resource_path
    );

    let persisted_session = call_module_rpc(
        &core,
        "memory_hub",
        "get_session",
        json!({ "session_id": "ses_wave5_approve" }),
    )
    .await;
    let persisted_msgs = persisted_session["messages"]
        .as_array()
        .expect("memory_hub session messages");
    assert!(
        persisted_msgs
            .iter()
            .any(|m| m["role"] == "user" && m["content"].as_str().unwrap_or("").contains("secret_report")),
        "memory_hub get_session missing user turn: {:?}",
        persisted_msgs
    );
    assert!(
        persisted_msgs.iter().any(|m| m["role"] == "assistant"
            && m["content"]
                .as_str()
                .unwrap_or("")
                .contains("secret_report_2026.md")),
        "memory_hub get_session missing resumed assistant reply: {:?}",
        persisted_msgs
    );

    // Step 3: Follow-up turn searching the SAME session-granted outside directory succeeds immediately WITHOUT approval!
    let appendix_file = outside_dir.join("secret_report_appendix.md");
    std::fs::write(&appendix_file, "# 补充附录\n").unwrap();

    let turn2 = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_wave5_approve_2",
            "session_id": "ses_wave5_approve",
            "text": format!("再帮我在 {} 查找 secret_report_appendix 附件", outside_dir.display()),
            "incognito": false,
        }),
        &disc_opts,
    )
    .await
    .unwrap();

    assert_eq!(
        turn2["status"], "completed",
        "Session-granted directory must NOT re-prompt for approval: {:?}",
        turn2
    );
    assert!(turn2["pending_approval"].is_null());
    assert!(
        turn2["reply_markdown"]
            .as_str()
            .unwrap_or("")
            .contains("secret_report_appendix.md"),
        "Follow-up turn reply must contain secret_report_appendix.md: {:?}",
        turn2["reply_markdown"]
    );
}

// =============================================================================
// Test 2: Deep Local Software Scan (9 Categories) & Rich Translation Layer
// =============================================================================

#[tokio::test]
async fn wave5_test2_deep_local_software_scan_9_categories_and_rich_translation() {
    clear_desktop_discovery_cache();

    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("xdg_base");
    let ws = base.join("workspace");
    let apps_dir = temp.path().join("synthetic_applications");
    let bin_dir = temp.path().join("synthetic_bin");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&apps_dir).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();

    let core = init_test_core(&base, &ws);

    // Hermetic action marker script for testing `[Desktop Action]` execution
    let wps_action_marker = temp.path().join("wps_newdoc_invoked.txt");
    let wps_mock_bin = bin_dir.join("wps-wave5-mock");
    write_executable_file(
        &wps_mock_bin,
        &format!(
            "#!/bin/sh\nprintf '%s' \"$*\" > \"{}\"\n",
            wps_action_marker.display()
        ),
    );

    // Create 9 authentic `.desktop` fixtures spanning all 9 AIOS categories
    let fixtures: &[(&str, String)] = &[
        (
            "sodam.desktop",
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=SodaM\n\
             GenericName=Music Player\n\
             Exec=/opt/SodaM/sodam %U\n\
             Categories=AudioVideo;Player;\n\
             Keywords=music;qishui;soda;sodam;\n"
                .to_string(),
        ),
        (
            "wemeetapp.desktop",
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Tencent Meeting\n\
             Name[zh_CN]=腾讯会议\n\
             Exec=/opt/wemeet/wemeetapp.sh %u\n\
             Categories=Network;VideoConference;\n\
             MimeType=x-scheme-handler/wemeet;\n\
             Actions=JoinQuick;\n\
             \n\
             [Desktop Action JoinQuick]\n\
             Name=Join Meeting Quickly\n\
             Name[zh_CN]=快速加入会议\n\
             Exec=/opt/wemeet/wemeetapp.sh --quick-join\n"
                .to_string(),
        ),
        (
            "wps-office-wps.desktop",
            format!(
                "[Desktop Entry]\n\
                 Type=Application\n\
                 Name=WPS Writer\n\
                 Name[zh_CN]=WPS 文字\n\
                 Exec={} %f\n\
                 Categories=Office;WordProcessor;\n\
                 MimeType=application/msword;application/vnd.openxmlformats-officedocument.wordprocessingml.document;\n\
                 Actions=NewDoc;\n\
                 \n\
                 [Desktop Action NewDoc]\n\
                 Name=New Blank Document\n\
                 Name[zh_CN]=新建空白文字文档\n\
                 Exec={} --new-blank-doc\n",
                wps_mock_bin.display(),
                wps_mock_bin.display()
            ),
        ),
        (
            "baidunetdisk.desktop",
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=baidunetdisk\n\
             Name[zh_CN]=百度网盘\n\
             Exec=/opt/baidunetdisk/baidunetdisk %U\n\
             Categories=Network;FileTransfer;\n"
                .to_string(),
        ),
        (
            "FlClash.desktop",
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=FlClash\n\
             Comment=Multi-platform proxy client based on ClashMeta\n\
             Exec=/opt/FlClash/FlClash %U\n\
             Categories=Network;VPN;\n"
                .to_string(),
        ),
        (
            "zcode.desktop",
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=ZCode\n\
             Name[zh_CN]=ZCode 智能开发工具\n\
             Exec=/opt/ZCode/zcode %F\n\
             Categories=Development;IDE;\n\
             Actions=NewWindow;\n\
             \n\
             [Desktop Action NewWindow]\n\
             Name=New Empty Window\n\
             Name[zh_CN]=新建空窗口\n\
             Exec=/opt/ZCode/zcode --new-window\n"
                .to_string(),
        ),
        (
            "drawio.desktop",
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=draw.io\n\
             Comment=Diagramming and flowchart design tool\n\
             Exec=/opt/drawio/drawio %U\n\
             Categories=Graphics;2DGraphics;\n"
                .to_string(),
        ),
        (
            "virtualbox.desktop",
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Oracle VM VirtualBox\n\
             Exec=VirtualBox %U\n\
             Categories=System;Emulator;\n"
                .to_string(),
        ),
        (
            "omni-mouse-studio.desktop",
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Omni Mouse Studio\n\
             Name[zh_CN]=鼠标宏与硬件驱动中心\n\
             Exec=/opt/omni-mouse-studio/omni-mouse-studio\n\
             Categories=Settings;HardwareSettings;\n"
                .to_string(),
        ),
    ];

    for (filename, content) in fixtures {
        write_executable_file(&apps_dir.join(filename), content);
    }

    // 1. Run `deep_scan_local_software` against our synthetic fixture directory
    let scan_res = call_module_rpc(
        &core,
        "app_adapter",
        "deep_scan_local_software",
        json!({
            "force_refresh": true,
            "scan_dirs": [apps_dir.to_string_lossy()],
        }),
    )
    .await;

    let categories = scan_res["categories"]
        .as_array()
        .expect("categories array");
    assert_eq!(
        categories.len(),
        9,
        "Must expose all 9 canonical AIOS software categories"
    );

    let expected_categories = [
        "media_entertainment",
        "social_collab",
        "office_notes_doc",
        "cloud_transfer",
        "network_browser",
        "dev_ai_ide",
        "creative_disc",
        "remote_vm",
        "hardware_system",
    ];
    for expected_cat in expected_categories {
        let cat_entry = categories
            .iter()
            .find(|c| c["id"].as_str() == Some(expected_cat))
            .unwrap_or_else(|| panic!("Missing category definition '{}'", expected_cat));
        assert!(
            cat_entry["count"].as_u64().unwrap_or(0) >= 1,
            "Category '{}' should have at least 1 classified fixture app: {:?}",
            expected_cat,
            cat_entry
        );
    }

    // 2. Verify accurate per-app classification, URI scheme parsing, and `[Desktop Action]` extraction
    let apps = scan_res["apps"].as_array().expect("apps array");
    assert_eq!(apps.len(), 9);

    let find_app = |desktop_id: &str| -> &Value {
        apps.iter()
            .find(|a| a["desktop_id"].as_str() == Some(desktop_id))
            .unwrap_or_else(|| panic!("Missing scanned app '{}': {:?}", desktop_id, apps))
    };

    assert_eq!(find_app("sodam.desktop")["category_id"], "media_entertainment");
    assert_eq!(find_app("wemeetapp.desktop")["category_id"], "social_collab");
    assert_eq!(
        find_app("wps-office-wps.desktop")["category_id"],
        "office_notes_doc"
    );
    assert_eq!(
        find_app("baidunetdisk.desktop")["category_id"],
        "cloud_transfer"
    );
    assert_eq!(
        find_app("FlClash.desktop")["category_id"],
        "network_browser"
    );
    assert_eq!(find_app("zcode.desktop")["category_id"], "dev_ai_ide");
    assert_eq!(find_app("drawio.desktop")["category_id"], "creative_disc");
    assert_eq!(find_app("virtualbox.desktop")["category_id"], "remote_vm");
    assert_eq!(
        find_app("omni-mouse-studio.desktop")["category_id"],
        "hardware_system"
    );

    let wemeet = find_app("wemeetapp.desktop");
    assert!(
        wemeet["uri_schemes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("wemeet")),
        "wemeetapp.desktop must extract x-scheme-handler/wemeet: {:?}",
        wemeet["uri_schemes"]
    );
    assert!(
        wemeet["desktop_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action_id"].as_str() == Some("JoinQuick")),
        "wemeetapp.desktop must parse [Desktop Action JoinQuick]: {:?}",
        wemeet["desktop_actions"]
    );
    assert!(
        !wemeet["translatable_actions"]
            .as_array()
            .unwrap()
            .is_empty(),
        "Scanned software must synthesize rich translatable_actions"
    );

    // 3. Test curated URI translation (`join_meeting` -> `wemeet://page/inmeeting?meeting_code=987654321`)
    let join_res = call_module_rpc(
        &core,
        "app_adapter",
        "translate_and_execute",
        json!({
            "app_hint": "腾讯会议",
            "intent_action": "join_meeting",
            "params": {
                "meeting_code": "987-654-321",
                "dry_run": true
            },
            "approved": false
        }),
    )
    .await;
    assert_eq!(join_res["ok"], true);
    let join_blob = serde_json::to_string(&join_res).unwrap();
    assert!(
        join_blob.contains("wemeet://page/inmeeting?meeting_code=987654321"),
        "join_meeting must construct normalized wemeet:// URI, got: {}",
        join_blob
    );

    // 4. Test `[Desktop Action]` execution (`execute_desktop_action` on synthetic `wps-office-wps.desktop`)
    let da_res = call_module_rpc(
        &core,
        "app_adapter",
        "execute_desktop_action",
        json!({
            "desktop_id": "wps-office-wps.desktop",
            "action_id": "NewDoc",
            "scan_dirs": [apps_dir.to_string_lossy()],
        }),
    )
    .await;
    assert_eq!(da_res["ok"], true, "execute_desktop_action result: {:?}", da_res);
    // Wait briefly if spawned asynchronously
    for _ in 0..20 {
        if wps_action_marker.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if wps_action_marker.exists() {
        let recorded_args = std::fs::read_to_string(&wps_action_marker).unwrap_or_default();
        assert!(
            recorded_args.contains("--new-blank-doc"),
            "Desktop Action binary must receive --new-blank-doc, got: {}",
            recorded_args
        );
    }

    // 5. Test VirtualBox `start_vm` safety gate (`requires_approval == true` when `approved == false`)
    let vm_gate = call_module_rpc(
        &core,
        "app_adapter",
        "translate_and_execute",
        json!({
            "app_hint": "virtualbox",
            "intent_action": "start_vm",
            "params": { "vm_name": "Ubuntu24_DevVM" },
            "approved": false
        }),
    )
    .await;
    assert_eq!(
        vm_gate["requires_approval"], true,
        "Starting a VM via VirtualBox must require explicit approval: {:?}",
        vm_gate
    );
}

// =============================================================================
// Test 3: Non-Linear Time-Decay Multi-Turn Context Compression
//         (Strips Tools & `<think>`, Preserves Verbatim Recent 3, Enforces Cap)
// =============================================================================

#[derive(Clone)]
struct Wave5CompressionMockState {
    captured_requests: Arc<Mutex<Vec<Value>>>,
}

async fn mock_wave5_compression_chat_completions(
    State(state): State<Wave5CompressionMockState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.captured_requests.lock().unwrap().push(body);
    Json(json!({
        "id": "chatcmpl_wave5_decay",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "已结合非线性时间衰减压缩后的多轮历史上下文完成总结。"
            },
            "finish_reason": "stop"
        }]
    }))
}

#[tokio::test]
async fn wave5_test3_nonlinear_time_decay_context_compression_strips_tools_and_caps_tokens() {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("xdg_base");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();

    let core = init_test_core(&base, &ws);
    let session_id = "ses_wave5_decay_30";
    let max_budget_tokens: usize = 2200;

    // Configure non-linear decay parameters via `memory_hub.set_context_compression_config`
    let cfg_res = call_module_rpc(
        &core,
        "memory_hub",
        "set_context_compression_config",
        json!({
            "enabled": true,
            "drop_tool_records": true,
            "max_context_tokens": max_budget_tokens,
            "verbatim_recent_turns": 3,
            "decay_lambda": 0.24,
            "decay_gamma": 1.35,
        }),
    )
    .await;
    assert_eq!(cfg_res["enabled"], true);
    assert_eq!(cfg_res["max_context_tokens"], max_budget_tokens);
    assert_eq!(cfg_res["verbatim_recent_turns"], 3);

    // Populate 30 uniform-structure turns with `<think>...</think>`, fenced code blocks, and heavy `tool_steps`
    for idx in 0..30usize {
        let user_q = format!(
            "第 {:02} 轮架构问题：请检查服务组件 `/workspace/module_{:02}/config.toml` 的连接池超时参数、重试退避策略以及监控告警阈值是否符合生产规范？",
            idx, idx
        );
        let asst_a = format!(
            "<think>SECRET_INTERNAL_COT_MARKER_{:02}: 正在逐步推导第 {:02} 轮连接池公式，这段思考内容绝不能泄露到后续轮次的上下文中！</think>\n\
             ### 第 {:02} 轮配置核验报告\n\
             - 核心配置路径：`/workspace/module_{:02}/config.toml`\n\
             - 详细分析背景说明：该微服务在高并发峰值场景下需要保持平滑的指数退避重连机制，避免雪崩效应影响上游网关吞吐。\n\
             ```rust\n\
             pub fn build_pool_config_{:02}() -> PoolOptions {{\n\
                 let max_conns = 64;\n\
                 let acquire_timeout_ms = 1500;\n\
                 PoolOptions::new(max_conns, acquire_timeout_ms)\n\
             }}\n\
             ```\n\
             最终结论：模块 {:02} 的连接池上限 64 与超时 1500ms 已核验通过。",
            idx, idx, idx, idx, idx, idx
        );
        let heavy_tool_blob = format!("RAW_TOOL_STDOUT_DUMP_NEVER_LEAK_{:02}_", idx).repeat(16);

        call_module_rpc(
            &core,
            "memory_hub",
            "record_conversation_turn",
            json!({
                "session_id": session_id,
                "user_text": user_q,
                "assistant_text": asst_a,
                "thinking": format!("DB_THINKING_COLUMN_NEVER_LEAK_{:02}", idx),
                "tool_steps": [{
                    "capability_id": "file.read",
                    "arguments": { "path": format!("/workspace/module_{:02}/config.toml", idx) },
                    "status": "exited",
                    "message": "读取配置文件完成",
                    "data": { "raw_content": heavy_tool_blob }
                }],
                "incognito": false,
            }),
        )
        .await;
    }

    // 1. Run `preview_session_compression` and verify non-linear decay invariants
    let preview = call_module_rpc(
        &core,
        "memory_hub",
        "preview_session_compression",
        json!({ "session_id": session_id }),
    )
    .await;

    assert_eq!(preview["raw_qa_turns"], 30);
    assert_eq!(preview["verbatim_turns"], 3);
    assert!(
        preview["dropped_tool_records"].as_u64().unwrap_or(0) >= 30,
        "All 30 heavy tool records must be stripped from multi-turn context: {:?}",
        preview["stats"]
    );
    assert!(
        preview["rolled_up_ancient_turns"].as_u64().unwrap_or(0) > 0,
        "Ancient turns in a 30-turn session must roll up into the summary anchor: {:?}",
        preview["stats"]
    );
    let raw_toks = preview["raw_estimated_tokens"].as_u64().unwrap() as usize;
    let comp_toks = preview["compressed_estimated_tokens"].as_u64().unwrap() as usize;
    assert!(
        comp_toks <= max_budget_tokens,
        "compressed_estimated_tokens ({}) MUST be <= max_context_tokens ({})",
        comp_toks,
        max_budget_tokens
    );
    assert!(
        comp_toks < raw_toks,
        "Compression must reduce token footprint ({} vs {})",
        comp_toks,
        raw_toks
    );

    // Verify monotonic non-linear length decay across distances: `len(d=1) >= len(d=5) >= len(d=12)`
    let tiers = preview["tiers"].as_array().expect("tiers array");
    let retained_at = |d: usize| -> usize {
        tiers
            .iter()
            .find(|t| t["distance"].as_u64() == Some(d as u64))
            .and_then(|t| t["retained_chars"].as_u64())
            .unwrap_or_else(|| panic!("Missing tier entry for distance d={}", d)) as usize
    };
    let len_d1 = retained_at(1);
    let len_d5 = retained_at(5);
    let len_d12 = retained_at(12);
    assert!(
        len_d1 >= len_d5 && len_d5 >= len_d12 && len_d1 > len_d12,
        "Non-linear decay must satisfy len(d=1) [{}] >= len(d=5) [{}] >= len(d=12) [{}]",
        len_d1,
        len_d5,
        len_d12
    );

    // 2. Run a live Quick-Chat turn against mock OpenAI and inspect the exact prompt sent upstream
    let mock_state = Wave5CompressionMockState {
        captured_requests: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(mock_wave5_compression_chat_completions),
        )
        .with_state(mock_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mock_home = temp.path().join("mock_decay_home");
    let disc_opts = make_isolated_openai_discovery(&mock_home, addr);

    let live_turn = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_wave5_decay_live",
            "session_id": session_id,
            "text": "请汇总之前检查过的服务模块关键结论",
            "incognito": false,
        }),
        &disc_opts,
    )
    .await
    .unwrap();
    assert_eq!(live_turn["status"], "completed");

    let reqs = mock_state.captured_requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let sent_messages = reqs[0]["messages"].as_array().expect("messages array");
    let full_prompt_dump = serde_json::to_string(sent_messages).unwrap();

    // ZERO `role == "tool"` messages and ZERO raw tool dumps from prior turns!
    assert!(
        !sent_messages.iter().any(|m| m["role"] == "tool"),
        "ZERO role=tool messages from prior turns may enter LLM prompt!"
    );
    assert!(
        !full_prompt_dump.contains("RAW_TOOL_STDOUT_DUMP_NEVER_LEAK_"),
        "Heavy tool output leaked into LLM prompt!"
    );

    // ZERO `<think>` blocks or thinking column text from prior turns!
    assert!(
        !full_prompt_dump.contains("<think>")
            && !full_prompt_dump.contains("SECRET_INTERNAL_COT_MARKER_")
            && !full_prompt_dump.contains("DB_THINKING_COLUMN_NEVER_LEAK_"),
        "Prior <think> reasoning leaked into multi-turn LLM prompt!"
    );

    // Last `verbatim_recent_turns` (turns 27, 28, 29) Q&A pairs MUST be preserved verbatim (including Rust code block)!
    for recent_idx in [27usize, 28, 29] {
        let expected_fn = format!("pub fn build_pool_config_{:02}()", recent_idx);
        assert!(
            full_prompt_dump.contains(&expected_fn),
            "Verbatim recent turn {} code block '{}' missing from LLM prompt!",
            recent_idx,
            expected_fn
        );
    }

    // Ancient summary anchor MUST be present!
    assert!(
        full_prompt_dump.contains("早期会话非线性时间衰减摘要"),
        "Ancient turns summary anchor must be injected into LLM history!"
    );
}

// =============================================================================
// Test 4: Speech Hub Config, Streaming HTTP Model Download, Delete & ASR Self-Test
// =============================================================================

async fn mock_sensevoice_onnx_handler() -> impl IntoResponse {
    // Deterministic 128 KB synthetic ONNX binary payload so chunked streaming & progress tracking run cleanly
    let mut payload = b"ONNX_SENSEVOICE_SYNTHETIC_HEADER_WAVE5\n".to_vec();
    payload.resize(128 * 1024, 0x5A);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        payload,
    )
}

async fn mock_sensevoice_tokens_handler() -> impl IntoResponse {
    let mut lines = String::new();
    for idx in 0..512 {
        lines.push_str(&format!("tok_{} {}\n", idx, idx));
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        lines,
    )
}

#[tokio::test]
async fn wave5_test4_speech_hub_config_streaming_model_download_and_asr_runner_selftest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("xdg_base");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();

    let core = init_test_core(&base, &ws);

    // 1. Verify `settings_overview` exposes `"speech_hub"` in `"v03_modules"` and overview payload
    let ov = core.settings_overview().expect("settings_overview");
    let v03 = ov["v03_modules"].as_array().expect("v03_modules");
    assert!(
        v03.iter().any(|m| m.as_str() == Some("speech_hub")),
        "settings_overview.v03_modules must include speech_hub: {:?}",
        v03
    );
    assert!(ov["speech_hub"]["models"].is_array());

    // 2. Spin up local HTTP model file server for `sensevoice-small-int8` (`model.int8.onnx` + `tokens.txt`)
    let model_server = Router::new()
        .route("/model.int8.onnx", get(mock_sensevoice_onnx_handler))
        .route("/tokens.txt", get(mock_sensevoice_tokens_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, model_server).await;
    });

    // 3. Test `speech_hub` `"update_speech_config"` (`enabled: true`)
    let updated_cfg = call_module_rpc(
        &core,
        "speech_hub",
        "update_speech_config",
        json!({
            "enabled": true,
            "language": "zh",
            "auto_send_after_transcribe": true,
            "audio_source": "default",
        }),
    )
    .await;
    assert_eq!(updated_cfg["config"]["enabled"], true);
    assert_eq!(updated_cfg["config"]["language"], "zh");
    assert_eq!(updated_cfg["config"]["auto_send_after_transcribe"], true);
    assert!(core.paths.config_dir.join("speech.json").is_file());

    // 4. Start streaming download with `base_url_override` pointing to our local HTTP server
    let dl_start = call_module_rpc(
        &core,
        "speech_hub",
        "download_model",
        json!({
            "model_id": "sensevoice-small-int8",
            "base_url_override": format!("http://{}", addr),
        }),
    )
    .await;
    assert_eq!(dl_start["model_id"], "sensevoice-small-int8");

    // 5. Poll `get_download_progress` until `"completed"`
    let mut final_prog = Value::Null;
    for _ in 0..100 {
        let prog = call_module_rpc(
            &core,
            "speech_hub",
            "get_download_progress",
            json!({ "model_id": "sensevoice-small-int8" }),
        )
        .await;
        let st = prog["status"].as_str().unwrap_or("");
        if st == "completed" {
            final_prog = prog;
            break;
        }
        assert_ne!(
            st, "failed",
            "Streaming model download failed unexpectedly: {:?}",
            prog
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    assert_eq!(
        final_prog["status"], "completed",
        "Download did not complete in time: {:?}",
        final_prog
    );
    assert_eq!(final_prog["installed"], true);
    assert_eq!(final_prog["progress_pct"], 100.0);
    assert_eq!(
        final_prog["downloads"]["sensevoice-small-int8"]["status"],
        "completed"
    );

    // 6. Verify downloaded model files & `manifest.json` on disk (and zero leftover `.part` files)
    let model_dir = core
        .paths
        .data_dir
        .join("speech_models")
        .join("sensevoice-small-int8");
    let onnx_file = model_dir.join("model.int8.onnx");
    let tokens_file = model_dir.join("tokens.txt");
    let manifest_file = model_dir.join("manifest.json");
    assert!(onnx_file.is_file(), "model.int8.onnx must exist on disk");
    assert_eq!(std::fs::metadata(&onnx_file).unwrap().len(), 128 * 1024);
    assert!(tokens_file.is_file(), "tokens.txt must exist on disk");
    assert!(manifest_file.is_file(), "manifest.json must exist on disk");
    assert!(!model_dir.join("model.int8.onnx.part").exists());

    // 7. Test `"delete_model"` cleans up disk directory and updates status
    let del_res = call_module_rpc(
        &core,
        "speech_hub",
        "delete_model",
        json!({ "model_id": "sensevoice-small-int8" }),
    )
    .await;
    assert_eq!(del_res["deleted"], true);
    assert!(
        !model_dir.exists(),
        "delete_model must remove model directory from disk"
    );

    // 8. Run `scripts/intentos_asr_runner.py --self-test` under clean system Python environment!
    let runner_script = repo_root_dir().join("scripts/intentos_asr_runner.py");
    assert!(
        runner_script.is_file(),
        "Missing scripts/intentos_asr_runner.py"
    );
    let out = StdCommand::new("/usr/bin/python3")
        .arg(&runner_script)
        .arg("--self-test")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("RUSTFLAGS")
        .output()
        .expect("execute intentos_asr_runner.py --self-test");
    assert!(
        out.status.success(),
        "intentos_asr_runner.py --self-test exited {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let parsed_selftest: Value = serde_json::from_str(stdout_str.trim()).unwrap_or_else(|e| {
        panic!(
            "intentos_asr_runner.py --self-test did not output valid JSON ({}): {}",
            e, stdout_str
        )
    });
    assert_eq!(
        parsed_selftest["ok"], true,
        "ASR runner self-test must report ok=true: {}",
        stdout_str
    );
}
