#![forbid(unsafe_code)]

//! End-to-End Integration Tests for IntentOS v0.0 PoC Core Hypotheses (Spikes S1, S2, S3, S5, S6).

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use intentos_protocol::{IntentRequest, RouteLayer, TaskStatus, UiRpcRequest};
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use intentosd::ipc::start_ui_socket_server;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone)]
struct MockLlmState {
    calls: Arc<AtomicUsize>,
    expected_src: String,
    expected_dst: String,
}

async fn mock_chat_completions(
    State(st): State<MockLlmState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // Prove ModelGateway injected the API key (Worker never possessed it)
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth != "Bearer mock-gateway-injected-key" {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("missing gateway injected bearer header, got: {}", auth),
        ));
    }

    let turn = st.calls.fetch_add(1, Ordering::SeqCst);
    let msgs = body
        .get("messages")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Check if tool result already arrived
    let has_tool_result = msgs.iter().any(|m| m.get("role") == Some(&json!("tool")));

    if !has_tool_result && turn == 0 {
        // Turn 1: Ask Broker to search for `周报`
        Ok(Json(json!({
            "id": "chatcmpl_mock_1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_search_1",
                        "type": "function",
                        "function": {
                            "name": "file_search",
                            "arguments": serde_json::to_string(&json!({ "query": "周报" })).unwrap()
                        }
                    }]
                }
            }],
            "usage": { "prompt_tokens": 120, "completion_tokens": 25 }
        })))
    } else {
        // Turn 2: Request `file_move` (which for L2AgentPlan requires user approval!)
        Ok(Json(json!({
            "id": "chatcmpl_mock_2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_move_2",
                        "type": "function",
                        "function": {
                            "name": "file_move",
                            "arguments": serde_json::to_string(&json!({
                                "source": st.expected_src,
                                "target": st.expected_dst
                            })).unwrap()
                        }
                    }]
                }
            }],
            "usage": { "prompt_tokens": 180, "completion_tokens": 30 }
        })))
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[tokio::test]
async fn e2e_sandboxed_pi_worker_gateway_approval_and_undo() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let downloads = base.join("Downloads");
    let documents = base.join("Documents");
    std::fs::create_dir_all(&downloads).unwrap();
    std::fs::create_dir_all(&documents).unwrap();

    let report_src = downloads.join("周报_第46周.docx");
    let report_dst = documents.join("周报_第46周.docx");
    std::fs::write(&report_src, b"confidential-weekly-report-v46").unwrap();

    let xdg = XdgPaths::resolve(Some(base), repo_root());
    xdg.ensure_dirs().unwrap();
    let app_cfg = AppConfig {
        hotkey: "<Super><Shift>space".into(),
        authorized_directories: vec![
            downloads.to_string_lossy().to_string(),
            documents.to_string_lossy().to_string(),
        ],
        allow_simulated_hardware_fallback: true,
        ..AppConfig::default()
    };
    let brain_cfg = BrainConfig {
        runtime: "pi".into(),
        ..BrainConfig::default()
    };
    std::fs::write(
        xdg.config_dir.join("config.toml"),
        toml::to_string_pretty(&app_cfg).unwrap(),
    )
    .unwrap();
    std::fs::write(
        xdg.config_dir.join("brain.toml"),
        toml::to_string_pretty(&brain_cfg).unwrap(),
    )
    .unwrap();

    let core = IntentOsCore::initialize(Some(base), repo_root()).unwrap();
    assert_eq!(core.agent.active_runtime_label(), "pi-adapter (sandboxed)");

    // Start Gateway Unix Socket (`gateway/gateway.sock`) & Private UI Unix Socket (`ui.sock`)
    core.gateway
        .clone()
        .spawn_unix_socket_server(&core.paths.gateway_socket_path())
        .unwrap();
    start_ui_socket_server(core.clone(), &core.paths.ui_socket_path()).unwrap();

    // Start local mock OpenAI upstream server
    let state = MockLlmState {
        calls: Arc::new(AtomicUsize::new(0)),
        expected_src: report_src.to_string_lossy().to_string(),
        expected_dst: report_dst.to_string_lossy().to_string(),
    };
    let app = Router::new()
        .route("/chat/completions", post(mock_chat_completions))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));

    // Submit complex L2 multi-step intent -> runs inside sandboxed Node `pi-adapter/dist/worker.js`!
    let task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "帮我找出下载目录里的周报并整理归档到文档目录，完成后告诉我".into(),
                session_id: Some("ses_e2e".into()),
                force_agent: true,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert_eq!(task.route, RouteLayer::L2);
    assert_eq!(task.status, TaskStatus::AwaitingApproval);
    assert_eq!(state.calls.load(Ordering::SeqCst), 2);
    assert_eq!(task.steps.len(), 1);
    assert_eq!(task.steps[0].capability_id, "file.search");
    assert!(report_src.exists(), "file must NOT move before user approval");

    let pa = task.pending_approval.expect("must have PendingApproval");
    assert_eq!(pa.capability_id, "file.move");

    // Verify token metering recorded both turns through `gateway.sock`
    let metrics = core.gateway.metrics();
    assert_eq!(metrics.total_requests, 2);
    assert_eq!(metrics.total_input_tokens, 300);

    // Approve via nonce + SHA-256 digest -> executes `openat2` move!
    let approved_task = core
        .approve_pending(&pa.approval_id, &pa.nonce, &pa.digest)
        .await
        .unwrap();
    assert_eq!(approved_task.status, TaskStatus::Completed);
    assert!(!report_src.exists());
    assert!(report_dst.exists());

    // Undo via trusted UI RPC -> 100% restored!
    let undo_resp = core
        .handle_trusted_ui_rpc("u1".into(), UiRpcRequest::Undo { target_id: None })
        .await;
    assert!(undo_resp.ok);
    assert!(report_src.exists());
    assert!(!report_dst.exists());
    assert_eq!(
        std::fs::read(&report_src).unwrap(),
        b"confidential-weekly-report-v46"
    );
}

#[tokio::test]
async fn consecutive_relative_volume_adjustments_coalesce_changeset() {
    let temp = tempfile::tempdir().unwrap();
    let core = IntentOsCore::initialize(Some(temp.path()), repo_root()).unwrap();

    // Set baseline volume to 40%
    let t0 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "把音量调到 40%".into(),
                session_id: Some("vol_s".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(t0.status, TaskStatus::Completed);

    // Two consecutive relative adjustments (+10%, +10% -> 60%) within 10s coalesce into one ChangeSet (§7.8.6)
    let t1 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "音量调大一点".into(),
                session_id: Some("vol_s".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    let t2 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "声音大一点".into(),
                session_id: Some("vol_s".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(t1.changeset_ids[0], t2.changeset_ids[0]);

    // Single undo restores straight back to 40%!
    let (_cs, msg) = core.undo(None).unwrap();
    assert!(msg.contains("40%"), "unexpected undo msg: {}", msg);
}
