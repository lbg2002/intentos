#![forbid(unsafe_code)]

//! Comprehensive End-to-End Integration Test Suite for Milestone 1 (`v0.2-M1`, `e2e_v0_2_m1.rs`):
//! 1) `m1_test1_turn_engine_modularized_and_cli_broker_bridge_unifies_execution`
//! 2) `m1_test2_effect_ledger_prevents_duplicate_side_effect_on_backend_fallback`
//! 3) `m1_test3_strict_incognito_memory_isolation_and_sensitive_data_guard`
//! 4) `m1_test4_compound_splitter_never_silently_drops_unresolved_clauses`
//! 5) `m1_test5_cognitive_l1_structured_goal_recognition_and_eval_fixes`

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use intentos_protocol::{IntentRequest, PROTOCOL_VERSION, RouteLayer, TaskStatus, UiRpcRequest};
use intentosd::backend_bridge::{
    DiscoveryOptions, resume_approved_turn_with_options, send_quick_chat_turn_with_options,
    set_active_backend_with_options,
};
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use intentosd::decision::L1DecisionOutcome;
use intentosd::intent_engine::{
    CognitiveIntentKind, PatternCompiler, parse_structured_intent, split_compound_intent,
};
use intentosd::router::RoutedIntent;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

fn repo_root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn init_m1_core(base: &Path, ws: &Path, runtime: &str) -> Arc<IntentOsCore> {
    let repo_root = repo_root_dir();
    let xdg = XdgPaths::resolve(Some(base), repo_root.clone());
    xdg.ensure_dirs().unwrap();
    let cfg = AppConfig {
        authorized_directories: vec![ws.to_string_lossy().to_string()],
        allow_simulated_hardware_fallback: true,
        ..AppConfig::default()
    };
    let brain = BrainConfig {
        runtime: runtime.to_string(),
        ..BrainConfig::default()
    };
    std::fs::write(
        xdg.config_dir.join("config.toml"),
        toml::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();
    std::fs::write(
        xdg.config_dir.join("brain.toml"),
        toml::to_string_pretty(&brain).unwrap(),
    )
    .unwrap();
    IntentOsCore::initialize(Some(base), repo_root).expect("init m1 test core")
}

fn write_executable(path: &Path, content: &str) {
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

fn collect_all_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_all_files_recursive(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

// =============================================================================
// Test 1: `turn_engine.rs` Modularization (< 1,500 lines) + Unified HTTP & CLI
//         `CapabilityBroker` Execution (`trace_dots`, `changeset_ids`,
//         `execution_mode`, and `PendingApproval` suspension + resume)
// =============================================================================

#[derive(Clone)]
struct M1HttpBrokerState {
    calls: Arc<AtomicUsize>,
}

async fn mock_m1_http_broker_completions(
    State(state): State<M1HttpBrokerState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let call_idx = state.calls.fetch_add(1, Ordering::SeqCst);
    let has_tool_msg = body["messages"]
        .as_array()
        .is_some_and(|arr| arr.iter().any(|m| m["role"] == "tool"));

    if !has_tool_msg && call_idx == 0 {
        Json(json!({
            "id": "chatcmpl_m1_http_1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>通过受控 Broker 设置音量</think>",
                    "tool_calls": [{
                        "id": "call_m1_http_vol",
                        "type": "function",
                        "function": {
                            "name": "sound_volume_set",
                            "arguments": "{\"value\":45}"
                        }
                    }]
                }
            }]
        }))
    } else {
        Json(json!({
            "id": "chatcmpl_m1_http_2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "已通过 HTTP Managed Broker 将系统音量调整至 45%。"
                }
            }]
        }))
    }
}

#[tokio::test]
async fn m1_test1_turn_engine_modularized_and_cli_broker_bridge_unifies_execution() {
    // 1. Structural & safety audit of modularized `backend_bridge/` runtime files
    let bb_dir = repo_root_dir().join("crates/intentosd/src/backend_bridge");
    let turn_engine_src = std::fs::read_to_string(bb_dir.join("turn_engine.rs")).unwrap();
    let turn_engine_lines = turn_engine_src.lines().count();
    assert!(
        turn_engine_lines < 1_500,
        "turn_engine.rs MUST be refactored under 1,500 lines, got {} lines!",
        turn_engine_lines
    );
    for module_file in [
        "turn_engine.rs",
        "turn_checkpoint.rs",
        "broker_bridge.rs",
        "providers_http.rs",
        "providers_cli.rs",
    ] {
        let src = std::fs::read_to_string(bb_dir.join(module_file))
            .unwrap_or_else(|_| panic!("missing modular runtime file {}", module_file));
        assert!(
            src.starts_with("#![forbid(unsafe_code)]"),
            "{} MUST begin with `#![forbid(unsafe_code)]`",
            module_file
        );
    }

    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    let outside_vault = tmp.path().join("external_restricted_vault");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&outside_vault).unwrap();
    std::fs::write(
        outside_vault.join("architecture_audit_m1.md"),
        "# Architecture Audit\nUnified Broker verified.\n",
    )
    .unwrap();

    let core = init_m1_core(tmp.path(), &ws, "native");

    // 2. Test Managed HTTP Tool-Calling (`execution_mode == "managed_broker"`)
    let http_state = M1HttpBrokerState {
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_m1_http_broker_completions))
        .with_state(http_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mock_home_http = tmp.path().join("mock_home_http");
    std::fs::create_dir_all(&mock_home_http).unwrap();
    let opts_http = DiscoveryOptions::isolated_for_test(mock_home_http);

    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "m1-http-provider",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", http_addr),
            "api_key": "sk-m1-http-test-token-1234567890"
        }),
        &opts_http,
    )
    .await
    .unwrap();

    let http_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_m1_e2e_http",
            "text": "请帮我把音量设为 45",
        }),
        &opts_http,
    )
    .await
    .unwrap();

    assert_eq!(http_res["status"], "completed");
    assert_eq!(http_res["execution_mode"], "managed_broker");
    assert_eq!(http_res["changeset_ids"].as_array().unwrap().len(), 1);
    assert_eq!(http_res["effect_ledger"]["has_committed_side_effects"], true);
    assert!(
        http_res["trace_dots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["title"].as_str().unwrap_or("").contains("sound.volume.set")),
        "HTTP managed broker turn must produce real TraceDot for sound.volume.set"
    );
    let _ = core.undo(http_res["changeset_ids"][0].as_str());

    // 3. Test Fake CLI Binary (`codex`) emitting `<intentos_tool_call>` via `CapabilityBroker`
    let mock_home_cli = tmp.path().join("mock_home_cli");
    std::fs::create_dir_all(&mock_home_cli).unwrap();

    let cli_script = format!(
        r#"#!/bin/sh
for prompt; do :; done
case "$prompt" in
  *intentos_tool_results*architecture_audit_m1.md*)
    printf "受控目录检索完成：已定位 architecture_audit_m1.md。"
    ;;
  *intentos_tool_results*55%*)
    printf "CLI 受控桥接已完成：屏幕亮度已调整为 55%%。"
    ;;
  *CLI调节屏幕亮度*)
    printf "<think>使用受控工具调整亮度</think><intentos_tool_call>{{\"name\":\"display.brightness.set\",\"arguments\":{{\"value\":55}}}}</intentos_tool_call>"
    ;;
  *CLI受控检索外部目录*)
    printf "<intentos_tool_call>{{\"name\":\"file.search\",\"arguments\":{{\"directory\":\"{}\",\"query\":\"architecture_audit\"}}}}</intentos_tool_call>"
    ;;
  *)
    printf "CLI 默认回复"
    ;;
esac
"#,
        outside_vault.display()
    );
    write_executable(&mock_home_cli.join(".local/bin/codex"), &cli_script);
    let codex_cfg = mock_home_cli.join(".codex/config.toml");
    std::fs::create_dir_all(codex_cfg.parent().unwrap()).unwrap();
    std::fs::write(&codex_cfg, "model = \"gpt-6.1-cli-e2e\"\n").unwrap();

    let opts_cli = DiscoveryOptions::isolated_for_test(mock_home_cli);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "codex",
            "model": "gpt-6.1-cli-e2e",
        }),
        &opts_cli,
    )
    .await
    .unwrap();

    // 3a) Reversible CLI `<intentos_tool_call>` -> `trace_dots` + `changeset_ids` + `cli_broker_bridged`
    let cli_bright = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_m1_e2e_cli_bright",
            "text": "CLI调节屏幕亮度",
        }),
        &opts_cli,
    )
    .await
    .unwrap();

    assert_eq!(cli_bright["status"], "completed");
    assert_eq!(cli_bright["backend_used"], "codex");
    assert_eq!(cli_bright["execution_mode"], "cli_broker_bridged");
    assert_eq!(cli_bright["changeset_ids"].as_array().unwrap().len(), 1);
    assert_eq!(cli_bright["effect_ledger"]["has_committed_side_effects"], true);
    assert!(
        cli_bright["trace_dots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["title"].as_str().unwrap_or("").contains("display.brightness.set")),
        "CLI broker bridge must emit real TraceDot for display.brightness.set"
    );
    let _ = core.undo(cli_bright["changeset_ids"][0].as_str());

    // 3b) Sensitive CLI `<intentos_tool_call>` outside authorized dir -> `PendingApproval` suspension + resume!
    let cli_paused = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_m1_e2e_cli_approval",
            "text": "CLI受控检索外部目录",
        }),
        &opts_cli,
    )
    .await
    .unwrap();

    assert_eq!(cli_paused["status"], "awaiting_approval");
    assert_eq!(cli_paused["execution_mode"], "cli_broker_bridged");
    let pa = &cli_paused["pending_approval"];
    assert_eq!(pa["capability_id"], "file.search");

    let cli_resumed = resume_approved_turn_with_options(
        &core,
        &json!({
            "approval_id": pa["approval_id"],
            "decision": "once",
        }),
        &opts_cli,
    )
    .await
    .unwrap();

    assert_eq!(cli_resumed["status"], "completed");
    assert_eq!(cli_resumed["approval_resolved"], "approved");
    assert_eq!(cli_resumed["execution_mode"], "cli_broker_bridged");
    assert!(
        cli_resumed["reply_markdown"]
            .as_str()
            .unwrap_or("")
            .contains("architecture_audit_m1.md"),
        "Resumed CLI turn must receive approved file.search tool result, got: {}",
        cli_resumed["reply_markdown"]
    );
}

// =============================================================================
// Test 2: `TurnEffectLedger` Prevents Duplicate Side-Effect Replay When HTTP
//         Backend Commits a Mutation on Round 1 Then Fails With HTTP 502 on Round 2
// =============================================================================

#[derive(Clone)]
struct M1Round2FailState {
    rounds: Arc<AtomicUsize>,
}

async fn mock_m1_round1_mutate_round2_502(
    State(state): State<M1Round2FailState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let r = state.rounds.fetch_add(1, Ordering::SeqCst);
    let has_tool_msg = body["messages"]
        .as_array()
        .is_some_and(|arr| arr.iter().any(|m| m["role"] == "tool"));

    if !has_tool_msg && r == 0 {
        (
            StatusCode::OK,
            Json(json!({
                "id": "chatcmpl_m1_r1_mut",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "<think>调整音量为 32%</think>",
                        "tool_calls": [{
                            "id": "call_vol_r1",
                            "type": "function",
                            "function": {
                                "name": "sound_volume_set",
                                "arguments": "{\"value\":32}"
                            }
                        }]
                    }
                }]
            })),
        )
    } else {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": {
                    "message": "502 Bad Gateway upstream proxy crashed after round 1"
                }
            })),
        )
    }
}

#[tokio::test]
async fn m1_test2_effect_ledger_prevents_duplicate_side_effect_on_backend_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_m1_core(tmp.path(), &ws, "native");

    // Capture baseline volume so we can prove Undo restores it cleanly!
    let (prior_vol, _) = core.settings.read_setting_value("sound.volume").unwrap();

    let srv_state = M1Round2FailState {
        rounds: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_m1_round1_mutate_round2_502))
        .with_state(srv_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mock_home = tmp.path().join("mock_home_502");
    std::fs::create_dir_all(&mock_home).unwrap();

    // Install a fake `codex` CLI binary that touches `cli_replayed.flag` if fallback ever runs
    let cli_sentinel = tmp.path().join("cli_replayed.flag");
    write_executable(
        &mock_home.join(".local/bin/codex"),
        &format!(
            "#!/bin/sh\necho replayed > \"{}\"\necho \"illegal fallback\"\n",
            cli_sentinel.display()
        ),
    );
    let codex_toml = format!(
        "model = \"gpt-6.1-502\"\nmodel_provider = \"m1_proxy\"\n\n[model_providers.m1_proxy]\nname = \"M1 Proxy\"\nbase_url = \"http://{}/v1\"\napi_key = \"sk-m1-proxy-test-key-000011112222\"\n",
        addr
    );
    let codex_cfg = mock_home.join(".codex/config.toml");
    std::fs::create_dir_all(codex_cfg.parent().unwrap()).unwrap();
    std::fs::write(&codex_cfg, codex_toml).unwrap();

    let opts = DiscoveryOptions::isolated_for_test(mock_home);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "codex",
            "provider": "m1_proxy",
            "model": "gpt-6.1-502",
        }),
        &opts,
    )
    .await
    .unwrap();

    let changesets_before = core.state_db.list_changesets(50).unwrap().len();

    // Note: "把音量调到 32%" would ALSO match L0 `sound.volume.set` if `submit_intent` fallback ran!
    let res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_m1_e2e_502",
            "text": "把音量调到 32%",
        }),
        &opts,
    )
    .await
    .unwrap();

    assert_eq!(srv_state.rounds.load(Ordering::SeqCst), 2);
    assert_eq!(res["status"], "completed");
    assert_eq!(res["side_effect_replay_prevented"], true);
    assert_eq!(res["execution_mode"], "managed_broker");
    assert!(
        !cli_sentinel.exists(),
        "CLI fallback MUST NOT execute after round-1 side effect committed!"
    );

    // Exactly ONE changeset created (no duplicate L0 `submit_intent` execution!)
    let changesets_after = core.state_db.list_changesets(50).unwrap();
    assert_eq!(
        changesets_after.len() - changesets_before,
        1,
        "Must record exactly 1 changeset (zero duplicate replay)"
    );
    let cs_ids = res["changeset_ids"].as_array().unwrap();
    assert_eq!(cs_ids.len(), 1);
    let cs_id = cs_ids[0].as_str().unwrap();

    assert_eq!(res["effect_ledger"]["has_committed_side_effects"], true);
    assert_eq!(res["effect_ledger"]["mutated_steps"], 1);
    let (vol_after_r1, _) = core.settings.read_setting_value("sound.volume").unwrap();
    assert_eq!(vol_after_r1.as_f64().unwrap().round() as i64, 32);

    // Prove preserved `changeset_ids` allows clean atomic Undo back to `prior_vol`!
    let (undone_cs, undo_msg) = core.undo(Some(cs_id)).unwrap();
    assert_eq!(undone_cs.id, cs_id);
    assert!(!undo_msg.is_empty());
    let (vol_restored, _) = core.settings.read_setting_value("sound.volume").unwrap();
    assert_eq!(
        vol_restored.as_f64().unwrap().round() as i64,
        prior_vol.as_f64().unwrap().round() as i64
    );
}

// =============================================================================
// Test 3: Strict Incognito Memory Isolation (Quick-Chat + Core `submit_intent`)
//         AND Full-Pipeline `SensitiveDataGuard` Raw Disk Byte Scan
// =============================================================================

#[derive(Clone)]
struct M1CapturePromptState {
    captured_bodies: Arc<Mutex<Vec<String>>>,
}

async fn mock_m1_capture_completions(
    State(state): State<M1CapturePromptState>,
    body: String,
) -> Json<Value> {
    state.captured_bodies.lock().unwrap().push(body);
    Json(json!({
        "id": "chatcmpl_m1_priv",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "已在无痕隐私会话中处理您的文档写作请求。"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 64,
            "completion_tokens": 18,
            "total_tokens": 82
        }
    }))
}

#[tokio::test]
async fn m1_test3_strict_incognito_memory_isolation_and_sensitive_data_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_m1_core(tmp.path(), &ws, "native");

    // 1. Save explicit preferences: `"默认使用 WPS 打开文档"` + unique marker `"StarlightDocViewerM1"`
    core.state_db
        .save_explicit_memory("文档偏好", "默认使用 WPS 打开文档", None)
        .unwrap();
    core.state_db
        .save_explicit_memory("编辑器偏好", "默认使用 StarlightDocViewerM1 预览文稿", None)
        .unwrap();
    assert!(
        core.state_db
            .list_active_memories()
            .unwrap()
            .iter()
            .any(|(_, _, v)| v.contains("默认使用 WPS 打开文档"))
    );

    let capture_state = M1CapturePromptState {
        captured_bodies: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_m1_capture_completions))
        .route("/chat/completions", post(mock_m1_capture_completions))
        .with_state(capture_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Enable mock upstream for BOTH Quick-Chat (`set_active_backend_with_options`) AND Core L2 (`gateway`)
    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));

    let mock_home = tmp.path().join("mock_home_priv");
    std::fs::create_dir_all(&mock_home).unwrap();
    let opts = DiscoveryOptions::isolated_for_test(mock_home);

    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "m1-priv-llm",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-m1-priv-upstream-key-1122334455"
        }),
        &opts,
    )
    .await
    .unwrap();

    let tasks_before_incog = core.state_db.list_tasks(50).unwrap().len();

    // 2a. Quick-Chat turn with `incognito: true`
    let qc_incog = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "incog_qc_m1_e2e",
            "incognito": true,
            "text": "请帮我起草一份季度技术汇报提纲",
        }),
        &opts,
    )
    .await
    .unwrap();

    assert_eq!(qc_incog["status"], "completed");
    assert_eq!(qc_incog["privacy_policy"], "strict_isolated");
    assert!(qc_incog["memory_hits"].as_array().unwrap().is_empty());

    // 2b. Core `submit_intent` L2 turn with `incognito: true`
    let core_incog_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: "请帮我梳理这份技术文档的结构建议".to_string(),
                session_id: Some("incog_core_m1_e2e".to_string()),
                force_agent: true,
                selected_candidate_id: None,
                cwd: None,
                incognito: true,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert_eq!(core_incog_task.route, RouteLayer::L2);
    assert_eq!(core_incog_task.status, TaskStatus::Completed);

    // Prove BOTH outbound LLM `messages` captured ZERO explicit preference leakage!
    let outbound_payloads = capture_state.captured_bodies.lock().unwrap().clone();
    assert!(
        outbound_payloads.len() >= 2,
        "Expected >= 2 outbound LLM calls (Quick-Chat + Core L2), got {}",
        outbound_payloads.len()
    );
    for (idx, body) in outbound_payloads.iter().enumerate() {
        let parsed: Value = serde_json::from_str(body).expect("valid outbound LLM JSON");
        let messages = parsed["messages"].as_array().expect("outbound messages array");
        for msg in messages {
            let content = msg["content"].as_str().unwrap_or("");
            for forbidden in [
                "默认使用 WPS 打开文档",
                "文档偏好",
                "StarlightDocViewerM1",
                "编辑器偏好",
                "user_memories",
                "personal_os_memory",
            ] {
                assert!(
                    !content.contains(forbidden),
                    "PRIVACY LEAK on outbound call #{}: found '{}' in incognito message: {}",
                    idx,
                    forbidden,
                    content
                );
            }
            // Excluding the static system prompt example `"WPS 云盘"`, `"WPS"` must never appear in messages!
            let without_static_example = content.replace("WPS 云盘", "");
            assert!(
                !without_static_example.contains("WPS"),
                "PRIVACY LEAK on outbound call #{}: found 'WPS' in incognito message: {}",
                idx,
                content
            );
        }
    }

    // Prove ZERO task rows & ZERO session history written during incognito turns!
    assert_eq!(
        core.state_db.list_tasks(50).unwrap().len(),
        tasks_before_incog,
        "Incognito turns MUST NOT persist tasks in state.db"
    );
    for sid in ["incog_qc_m1_e2e", "incog_core_m1_e2e"] {
        let ses_resp = core
            .handle_trusted_ui_rpc(
                format!("chk_{}", sid),
                UiRpcRequest::ModuleRpc {
                    domain: "memory_hub".into(),
                    action: "get_session".into(),
                    payload: json!({ "session_id": sid }),
                },
            )
            .await;
        assert!(
            !ses_resp.ok
                || ses_resp
                    .result
                    .as_ref()
                    .and_then(|r| r["messages"].as_array())
                    .is_none_or(|m| m.is_empty()),
            "Incognito session {} MUST NOT persist messages in memory_hub.db",
            sid
        );
    }

    // 3. Submit raw secret `"记住我的 API 密钥是 sk-99887766554433221100abcdef"` in non-incognito mode
    let forbidden_secret = "sk-99887766554433221100abcdef";
    let utterance_with_secret = format!("记住我的 API 密钥是 {}", forbidden_secret);

    let secret_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: utterance_with_secret.clone(),
                session_id: Some("normal_secret_test_ses".to_string()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert!(
        !serde_json::to_string(&secret_task)
            .unwrap()
            .contains(forbidden_secret),
        "Returned Task struct must not contain plaintext secret"
    );

    // Also record through `memory_hub` (`record_conversation_turn`) to exercise `memory_hub.db` directly!
    let _ = core
        .handle_trusted_ui_rpc(
            "rec_secret_turn".into(),
            UiRpcRequest::ModuleRpc {
                domain: "memory_hub".into(),
                action: "record_conversation_turn".into(),
                payload: json!({
                    "session_id": "normal_secret_test_ses",
                    "user_text": utterance_with_secret,
                    "assistant_text": format!("已拒绝保存敏感密钥 {}", forbidden_secret),
                    "incognito": false,
                }),
            },
        )
        .await;

    // Scan raw bytes of EVERY file under `tmp.path()` (`state.db`, `state.db-wal`, `memory_hub.db`, `memory_hub.db-wal`, etc.)
    let mut disk_files = Vec::new();
    collect_all_files_recursive(tmp.path(), &mut disk_files);
    assert!(
        disk_files
            .iter()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("state.db")),
        "state.db must exist on disk for raw byte audit"
    );
    assert!(
        disk_files
            .iter()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("memory_hub.db")),
        "memory_hub.db must exist on disk for raw byte audit"
    );

    let needle = forbidden_secret.as_bytes();
    for file_path in &disk_files {
        let raw_bytes = std::fs::read(file_path).unwrap();
        assert!(
            !raw_bytes.windows(needle.len()).any(|w| w == needle),
            "SECURITY VIOLATION: raw secret '{}' found on disk inside '{}'!",
            forbidden_secret,
            file_path.display()
        );
    }
}

// =============================================================================
// Test 4: Compound Splitter Never Silently Drops Unresolved Clauses
//         (Offline `PartiallyCompleted` + Online `RouteLayer::L2` Escalation)
// =============================================================================

#[derive(Clone)]
struct M1CompoundL2State {
    captured_prompts: Arc<Mutex<Vec<String>>>,
}

async fn mock_m1_compound_l2_completions(
    State(state): State<M1CompoundL2State>,
    body: String,
) -> Json<Value> {
    state.captured_prompts.lock().unwrap().push(body);
    Json(json!({
        "id": "chatcmpl_m1_compound_l2",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "已将系统音量调至 35%，并完成了昨天实验日志报错原因的诊断分析。"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 90,
            "completion_tokens": 24,
            "total_tokens": 114
        }
    }))
}

#[tokio::test]
async fn m1_test4_compound_splitter_never_silently_drops_unresolved_clauses() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_m1_core(tmp.path(), &ws, "native");

    let utterance = "把音量调到35，然后帮我分析昨天实验日志报错原因";

    // 1. Direct `split_compound_intent` structural verification
    let compiler = PatternCompiler::compile_from_descriptors(&core.broker.descriptors());
    let plan = split_compound_intent(&core, utterance, &compiler);

    assert_eq!(plan.total_clauses, 2);
    assert_eq!(plan.steps.len(), 1);
    assert_eq!(plan.steps[0].capability_id, "sound.volume.set");
    assert_eq!(
        plan.steps[0].arguments["value"].as_f64().map(f64::round),
        Some(35.0)
    );
    assert!(!plan.all_clauses_resolved);
    assert!(plan.has_unresolved_clauses());
    assert_eq!(plan.unresolved_clauses.len(), 1);
    assert!(
        plan.unresolved_clauses[0]
            .raw_clause
            .contains("分析昨天实验日志报错原因"),
        "Unresolved clause must preserve second sub-goal, got: {:?}",
        plan.unresolved_clauses
    );

    // 2. Offline (`!has_usable_credentials()`): executes resolved step AND explicitly reports unresolved sub-goal (`PartiallyCompleted`)
    assert!(!core.gateway.has_usable_credentials());
    let offline_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: utterance.to_string(),
                session_id: Some("ses_m1_compound_offline".to_string()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert_ne!(
        offline_task.status,
        TaskStatus::Completed,
        "Offline compound intent with unresolved sub-goal MUST NOT silently claim 100% Completed!"
    );
    assert_eq!(offline_task.status, TaskStatus::PartiallyCompleted);
    let (vol_offline, _) = core.settings.read_setting_value("sound.volume").unwrap();
    assert_eq!(vol_offline.as_f64().unwrap().round() as i64, 35);
    if let Some(cs_id) = offline_task.changeset_ids.last() {
        let _ = core.undo(Some(cs_id));
    }
    let offline_msg = offline_task.assistant_message.unwrap_or_default();
    assert!(
        offline_msg.contains("分析昨天实验日志报错原因"),
        "Offline message must explicitly report unresolved sub-goal, got: {}",
        offline_msg
    );

    // 3. Online (`has_usable_credentials() == true`): escalates whole utterance to `RouteLayer::L2` Agent with injected plan hint!
    let l2_state = M1CompoundL2State {
        captured_prompts: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/chat/completions", post(mock_m1_compound_l2_completions))
        .with_state(l2_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));
    assert!(core.gateway.has_usable_credentials());

    let online_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: utterance.to_string(),
                session_id: Some("ses_m1_compound_online".to_string()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert_eq!(online_task.route, RouteLayer::L2);
    assert_eq!(online_task.status, TaskStatus::Completed);
    let prompts = l2_state.captured_prompts.lock().unwrap().clone();
    assert!(!prompts.is_empty());
    assert!(
        prompts[0].contains("sound.volume.set")
            && prompts[0].contains("分析昨天实验日志报错原因"),
        "Escalated L2 prompt must receive injected compound plan hint with both clauses! Prompt: {}",
        prompts[0]
    );
}

// =============================================================================
// Test 5: Cognitive L1 Structured Goal Recognition (`StructuredIntent`) &
//         Router / Decision Eval Blind-Spot Fixes
// =============================================================================

#[tokio::test]
async fn m1_test5_cognitive_l1_structured_goal_recognition_and_eval_fixes() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_m1_core(tmp.path(), &ws, "native");
    let descriptors_refs = core.broker.descriptors();
    let descriptors: Vec<intentos_protocol::CapabilityDescriptor> =
        descriptors_refs.iter().copied().cloned().collect();

    // 1. `"今天想专心写论文"` -> `GoalWorkspace` -> `RouteLayer::L2`
    let thesis_goal = parse_structured_intent("今天想专心写论文", &descriptors);
    assert_eq!(thesis_goal.intent_type, CognitiveIntentKind::GoalWorkspace);
    assert_eq!(thesis_goal.recommended_route, RouteLayer::L2);
    assert!(thesis_goal.requires_planning);
    assert!(thesis_goal.context.avoid_distraction);
    assert!(
        matches!(
            core.router.route_text("今天想专心写论文", false),
            RoutedIntent::EscalateL2 { .. }
        ),
        "GoalWorkspace must escalate to L2 in router"
    );
    assert!(
        matches!(
            core.decision
                .classify_colloquial_intent("今天想专心写论文", &descriptors_refs),
            L1DecisionOutcome::EscalateL2 { .. }
        ),
        "GoalWorkspace must escalate to L2 in DecisionAdapter"
    );

    // Also verify ModuleRpc `intent_engine.parse_structured_intent` exposes JSON contract
    let rpc_goal = core
        .handle_trusted_ui_rpc(
            "rpc_goal_thesis".into(),
            UiRpcRequest::ModuleRpc {
                domain: "intent_engine".into(),
                action: "parse_structured_intent".into(),
                payload: json!({ "text": "今天想专心写论文" }),
            },
        )
        .await;
    assert!(rpc_goal.ok);
    assert_eq!(
        rpc_goal.result.unwrap()["intent_type"],
        json!("goal_workspace")
    );

    // 2. `"电脑最近有点卡"` -> `SystemDiagnosis` -> `RouteLayer::L2`
    let diag_goal = parse_structured_intent("电脑最近有点卡", &descriptors);
    assert_eq!(diag_goal.intent_type, CognitiveIntentKind::SystemDiagnosis);
    assert_eq!(diag_goal.recommended_route, RouteLayer::L2);
    assert!(diag_goal.requires_planning);
    assert!(matches!(
        core.router.route_text("电脑最近有点卡", false),
        RoutedIntent::EscalateL2 { .. }
    ));

    // 3. `"帮我看下今天的天气，告诉我早上起床穿什么衣服，然后告诉我今天最应该完成哪些任务"` -> `CompoundTask` -> `L2`
    let north_star =
        "帮我看下今天的天气，告诉我早上起床穿什么衣服，然后告诉我今天最应该完成哪些任务";
    let compound_goal = parse_structured_intent(north_star, &descriptors);
    assert_eq!(compound_goal.intent_type, CognitiveIntentKind::CompoundTask);
    assert_eq!(compound_goal.recommended_route, RouteLayer::L2);
    assert!(compound_goal.requires_planning);
    assert!(compound_goal.sub_goals.len() >= 2);
    assert!(matches!(
        core.router.route_text(north_star, false),
        RoutedIntent::EscalateL2 { .. }
    ));

    // 4. `"查一下内网地址"` -> `network.ip` (`L0`), NEVER `web.search`!
    match core.router.route_text("查一下内网地址", false) {
        RoutedIntent::ExecuteL0 { capability_id, .. } => {
            assert_eq!(capability_id, "network.ip");
        }
        other => panic!("Expected ExecuteL0(network.ip) for '查一下内网地址', got {:?}", other),
    }

    // 5. `"开启省电续航"` -> `power.profile.set` (`power-saver`) cleanly on `L0`!
    match core.router.route_text("开启省电续航", false) {
        RoutedIntent::ExecuteL0 {
            capability_id,
            arguments,
            ..
        } => {
            assert_eq!(capability_id, "power.profile.set");
            assert_eq!(arguments["profile"], json!("power-saver"));
        }
        other => panic!(
            "Expected ExecuteL0(power.profile.set, power-saver) for '开启省电续航', got {:?}",
            other
        ),
    }

    // 6. `"怎么批量查找最近7天修改过的日志"` -> `ProceduralOrKnowledge` -> `EscalateL2`
    let howto_goal = parse_structured_intent("怎么批量查找最近7天修改过的日志", &descriptors);
    assert_eq!(
        howto_goal.intent_type,
        CognitiveIntentKind::ProceduralOrKnowledge
    );
    assert_eq!(howto_goal.recommended_route, RouteLayer::L2);
    assert!(matches!(
        core.router
            .route_text("怎么批量查找最近7天修改过的日志", false),
        RoutedIntent::EscalateL2 { .. }
    ));
}
