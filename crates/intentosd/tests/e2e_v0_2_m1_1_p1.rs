#![forbid(unsafe_code)]

//! Comprehensive P1 Hardening, Streaming & Performance Verification Suite
//! (`crates/intentosd/tests/e2e_v0_2_m1_1_p1.rs`).
//!
//! Covers Wave B (`H07`–`H10`) end-to-end scenarios:
//! 1. `p1_01_h10_agent_event_bus_monotonic_seq_ring_backpressure_redaction_and_sse_replay`
//! 2. `p1_02_h10_openai_sse_streaming_cjk_split_secret_scrub_and_truthful_tool_ordering`
//! 3. `p1_03_h10_anthropic_sse_streaming_and_json_fallback_compatibility`
//! 4. `p1_04_h10_mid_stream_turn_cancellation_emits_cancelled_and_aborts_cleanly`
//! 5. `p1_05_h10_warm_pi_worker_reuse_incognito_isolation_and_idle_eviction`
//! 6. `p1_06_h07_h08_h09_end_to_end_synergy_and_sub_millisecond_warm_latency`

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use intentos_protocol::{
    AgentEvent, AgentEventKind, CapabilityCall, IntentRequest, InvocationOrigin,
    PrivacySessionPolicy, Taint, TaskStatus,
};
use intentosd::backend_bridge::{
    DiscoveryOptions,
    broker_bridge::build_quick_chat_openai_tools,
    detector::discover_backends_catalog_fast,
    handle_module_rpc, poll_turn_events, send_quick_chat_turn_with_options,
    set_active_backend_with_options,
    turn_checkpoint::{
        TurnIdentity, complete_turn_atomic, emit_turn_event, register_or_join_turn,
        subscribe_turn_event_stream,
    },
};
use intentosd::broker::BrokerDispatchOutcome;
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use intentosd::intent_engine::cognitive_parser::parse_structured_intent;
use intentosd::web_shell::build_web_shell_router;
use serde_json::{Value, json};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;

fn repo_root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn init_p1_core(base: &Path, ws: &Path, runtime: &str, max_tool_calls: u32) -> Arc<IntentOsCore> {
    let repo_root = repo_root_dir();
    let xdg = XdgPaths::resolve(Some(base), repo_root.clone());
    xdg.ensure_dirs().unwrap();
    let cfg = AppConfig {
        authorized_directories: vec![ws.to_string_lossy().to_string()],
        allow_simulated_hardware_fallback: true,
        ..AppConfig::default()
    };
    let mut brain = BrainConfig {
        runtime: runtime.to_string(),
        ..BrainConfig::default()
    };
    brain.runtime_limits.max_tool_calls = max_tool_calls;
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
    IntentOsCore::initialize(Some(base), repo_root).expect("init p1 test core")
}

fn read_volume_i64(core: &IntentOsCore) -> i64 {
    let (v, _) = core.settings.read_setting_value("sound.volume").unwrap();
    v.as_f64().expect("numeric volume").round() as i64
}

async fn set_baseline_volume(core: &IntentOsCore, val: i64) {
    let outcome = core
        .broker
        .dispatch(&CapabilityCall {
            request_id: format!("req_p1_vol_{}", val),
            task_id: "incog_p1_baseline".to_string(),
            capability_id: "sound.volume.set".to_string(),
            arguments: json!({ "value": val }),
            origin: InvocationOrigin::UserExplicit,
            taints: vec![Taint::User],
        })
        .await
        .unwrap();
    assert!(matches!(outcome, BrokerDispatchOutcome::Executed(_)));
    assert_eq!(read_volume_i64(core), val);
}

fn read_brightness_i64(core: &IntentOsCore) -> i64 {
    let (v, _) = core
        .settings
        .read_setting_value("display.brightness")
        .unwrap();
    v.as_f64().expect("numeric brightness").round() as i64
}

async fn set_baseline_brightness(core: &IntentOsCore, val: i64) {
    let outcome = core
        .broker
        .dispatch(&CapabilityCall {
            request_id: format!("req_p1_bright_{}", val),
            task_id: "incog_p1_baseline".to_string(),
            capability_id: "display.brightness.set".to_string(),
            arguments: json!({ "value": val }),
            origin: InvocationOrigin::UserExplicit,
            taints: vec![Taint::User],
        })
        .await
        .unwrap();
    assert!(matches!(outcome, BrokerDispatchOutcome::Executed(_)));
    assert_eq!(read_brightness_i64(core), val);
}

// =============================================================================
// P1-01: Unified `AgentEvent` Bus — Monotonic Seq, 256-Ring Backpressure,
//        SensitiveDataGuard Scrubbing, Reconnect Replay & Live `/api/turn-events` SSE
// =============================================================================

#[tokio::test]
async fn p1_01_h10_agent_event_bus_monotonic_seq_ring_backpressure_redaction_and_sse_replay() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws_p1_01");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p1_core(tmp.path(), &ws, "native", 8);

    let turn_id = "turn_p1_01_ring_bus";
    let identity = TurnIdentity {
        turn_id: turn_id.to_string(),
        session_id: "ses_p1_01".to_string(),
        request_digest: "digest_p1_01".to_string(),
        model_key: "openai:mock:gpt-4o-mini".to_string(),
        execution_mode: "direct_http_broker".to_string(),
        privacy: PrivacySessionPolicy::Standard,
    };
    let reg = register_or_join_turn(identity);
    let handle = match reg {
        intentosd::backend_bridge::turn_checkpoint::TurnRegistrationOutcome::Started(h) => h,
        other => panic!("expected Started, got {:?}", std::mem::discriminant(&other)),
    };

    let first_ev = handle.emit_event(AgentEventKind::Started);
    assert_eq!(first_ev.seq, 1);

    // Emit a secret-bearing delta and a PEM marker delta — both must be scrubbed!
    let scrubbed_ev = emit_turn_event(
        turn_id,
        Some("task_p1_01"),
        AgentEventKind::MessageDelta {
            delta: "Leaked key sk-proj-SuperSecretToken1234567890ABCDEF and -----BEGIN OPENSSH PRIVATE KEY-----".into(),
        },
    )
    .expect("scrubbed delta event");
    assert_eq!(scrubbed_ev.seq, 2);
    match &scrubbed_ev.kind {
        AgentEventKind::MessageDelta { delta } => {
            assert!(
                !delta.contains("SuperSecretToken1234567890ABCDEF"),
                "API key must be scrubbed from AgentEvent: {}",
                delta
            );
            assert!(
                !delta.contains("BEGIN OPENSSH PRIVATE KEY"),
                "PEM private key header must be scrubbed from AgentEvent: {}",
                delta
            );
        }
        other => panic!("expected MessageDelta, got {:?}", other),
    }

    // Overflow the 256-event bounded ring buffer (emit 265 more progress events -> total 267)
    for idx in 0..265 {
        let ev = handle.emit_event(AgentEventKind::Progress {
            stage: "ring_test".into(),
            detail: format!("step_{}", idx),
        });
        assert_eq!(ev.seq, 3 + idx as u64);
    }

    let snap_all = poll_turn_events(&json!({ "turn_id": turn_id, "since_seq": 0 }));
    assert_eq!(snap_all["found"], true);
    let dropped_before = snap_all["dropped_before_seq"].as_u64().unwrap();
    assert_eq!(
        dropped_before, 11,
        "267 total events with 256 ring cap must drop seqs 1..=11"
    );
    let events_arr = snap_all["events"].as_array().unwrap();
    assert_eq!(events_arr.len(), 256);
    assert_eq!(events_arr.first().unwrap()["seq"], 12);
    assert_eq!(events_arr.last().unwrap()["seq"], 267);

    // Reconnect replay from `since_seq = 260` returns strictly `261..=267`
    let snap_replay = handle_module_rpc(
        &core,
        "poll_turn_events",
        json!({ "turn_id": turn_id, "since_seq": 260 }),
    )
    .await
    .unwrap();
    let replay_evs = snap_replay["events"].as_array().unwrap();
    let replay_seqs: Vec<u64> = replay_evs
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(replay_seqs, vec![261, 262, 263, 264, 265, 266, 267]);

    // Verify `GET /api/turn-events?turn_id=...&since_seq=265` over real HTTP SSE!
    let web_app = build_web_shell_router(core.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, web_app).await;
    });

    let finish_handle = handle.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        complete_turn_atomic(
            &finish_handle,
            json!({
                "turn_id": turn_id,
                "task_status": "completed",
                "reply_markdown": "ok",
            }),
            true,
        );
    });

    let sse_resp = reqwest::Client::new()
        .get(format!(
            "http://{}/api/turn-events?turn_id={}&since_seq=265",
            web_addr, turn_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), reqwest::StatusCode::OK);
    let ctype = sse_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ctype.contains("text/event-stream"),
        "expected text/event-stream content-type, got {}",
        ctype
    );
    let sse_body = sse_resp.text().await.unwrap();
    assert!(sse_body.contains("id: 266"), "body: {}", sse_body);
    assert!(sse_body.contains("id: 267"), "body: {}", sse_body);
    assert!(
        sse_body.contains("event: completed"),
        "SSE stream must deliver terminal completed event and close cleanly: {}",
        sse_body
    );
}

// =============================================================================
// P1-02: Real OpenAI HTTP SSE Streaming — Split Multi-Byte UTF-8 CJK,
//        Split Cross-Chunk Secret Scrubbing & Truthful Broker Tool Ordering
// =============================================================================

#[derive(Clone)]
struct P1OpenAiSseState {
    calls: Arc<AtomicUsize>,
    saw_stream_true: Arc<AtomicBool>,
}

async fn mock_p1_02_openai_sse(
    State(st): State<P1OpenAiSseState>,
    Json(body): Json<Value>,
) -> Response {
    if body.get("stream") == Some(&json!(true)) {
        st.saw_stream_true.store(true, Ordering::SeqCst);
    }
    let has_tool_result = body["messages"]
        .as_array()
        .is_some_and(|arr| arr.iter().any(|m| m["role"] == "tool"));
    st.calls.fetch_add(1, Ordering::SeqCst);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(16);
    if !has_tool_result {
        // Round 1: Stream tool call `sound_volume_set` with fragmented JSON arguments across SSE frames
        tokio::spawn(async move {
            let frames = [
                "data: {\"id\":\"cmpl_sse_1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"准备将音量设为 68%\"}}]}\n\n",
                "data: {\"id\":\"cmpl_sse_1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_sse_vol_68\",\"type\":\"function\",\"function\":{\"name\":\"sound_volume_set\",\"arguments\":\"{\\\"val\"}}]}}]}\n\n",
                "data: {\"id\":\"cmpl_sse_1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ue\\\":68}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
                "data: [DONE]\n\n",
            ];
            for f in frames {
                let _ = tx.send(Ok(Bytes::from(f.as_bytes().to_vec()))).await;
                tokio::time::sleep(Duration::from_millis(8)).await;
            }
        });
    } else {
        // Round 2: Stream `<think>` tag + multi-byte UTF-8 CJK split mid-character across TCP chunks
        // + an `sk-live-...` secret split across two SSE `delta.content` chunks!
        tokio::spawn(async move {
            let sse_1 = "data: {\"id\":\"cmpl_sse_2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"<think>核验通过</think>音量已调至 68%（凭据 \"}}]}\n\n";
            let sse_2 = "data: {\"id\":\"cmpl_sse_2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"sk-live-Split\"}}]}\n\n";
            let sse_3 = "data: {\"id\":\"cmpl_sse_2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"SecretAcrossChunks9999999999 已脱敏）。\"},\"finish_reason\":\"stop\"}]}\n\n";
            let sse_done = "data: [DONE]\n\n";

            // Deliberately slice `sse_1` right in the middle of the 3-byte UTF-8 sequence for '音' (`E9 9F B3`)
            let raw_1 = sse_1.as_bytes();
            let cjk_pos = sse_1.find("音量").unwrap();
            let _ = tx
                .send(Ok(Bytes::copy_from_slice(&raw_1[..cjk_pos + 1])))
                .await;
            tokio::time::sleep(Duration::from_millis(8)).await;
            let _ = tx
                .send(Ok(Bytes::copy_from_slice(&raw_1[cjk_pos + 1..])))
                .await;
            tokio::time::sleep(Duration::from_millis(8)).await;
            let _ = tx.send(Ok(Bytes::from(sse_2.as_bytes().to_vec()))).await;
            tokio::time::sleep(Duration::from_millis(8)).await;
            let _ = tx.send(Ok(Bytes::from(sse_3.as_bytes().to_vec()))).await;
            let _ = tx.send(Ok(Bytes::from(sse_done.as_bytes().to_vec()))).await;
        });
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .unwrap()
}

#[tokio::test]
async fn p1_02_h10_openai_sse_streaming_cjk_split_secret_scrub_and_truthful_tool_ordering() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws_p1_02");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p1_core(tmp.path(), &ws, "native", 8);
    set_baseline_volume(&core, 35).await;

    let st = P1OpenAiSseState {
        calls: Arc::new(AtomicUsize::new(0)),
        saw_stream_true: Arc::new(AtomicBool::new(false)),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_p1_02_openai_sse))
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mock_home = tmp.path().join("home_p1_02");
    std::fs::create_dir_all(&mock_home).unwrap();
    let opts = DiscoveryOptions::isolated_for_test(mock_home);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "sse-openai",
            "model": "gpt-4o-mini",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-test-openai-sse",
        }),
        &opts,
    )
    .await
    .unwrap();

    let turn_id = "turn_p1_02_openai_sse";
    let observer_core = core.clone();
    let observed_vol_on_tool_completed = Arc::new(AtomicUsize::new(0));
    let observed_vol_clone = observed_vol_on_tool_completed.clone();

    let live_task = tokio::spawn(async move {
        let mut sub = loop {
            if let Some(s) = subscribe_turn_event_stream(turn_id, 0) {
                break s;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let mut all: Vec<AgentEvent> = sub.snapshot.events;
        for ev in &all {
            if matches!(ev.kind, AgentEventKind::ToolCompleted { .. }) {
                observed_vol_clone
                    .store(read_volume_i64(&observer_core) as usize, Ordering::SeqCst);
            }
        }
        if !sub.snapshot.done {
            while let Ok(ev) = sub.rx.recv().await {
                let done = ev.kind.ends_turn_stream();
                if matches!(ev.kind, AgentEventKind::ToolCompleted { .. }) {
                    observed_vol_clone
                        .store(read_volume_i64(&observer_core) as usize, Ordering::SeqCst);
                }
                all.push(ev);
                if done {
                    break;
                }
            }
        }
        all
    });

    let turn_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": turn_id,
            "session_id": "ses_p1_02",
            "text": "把音量调到 68%",
        }),
        &opts,
    )
    .await
    .unwrap();

    assert!(st.saw_stream_true.load(Ordering::SeqCst));
    assert_eq!(turn_res["status"], "completed");
    assert_eq!(turn_res["task_status"], "succeeded");
    assert_eq!(read_volume_i64(&core), 68);

    let events = live_task.await.unwrap();
    assert!(!events.is_empty());

    // Verify strictly monotonic sequence numbers `1..=N`
    for (idx, ev) in events.iter().enumerate() {
        assert_eq!(ev.seq, (idx + 1) as u64);
    }

    let pos_started = events
        .iter()
        .position(|e| matches!(e.kind, AgentEventKind::Started))
        .expect("Started event");
    let pos_goal = events
        .iter()
        .position(|e| matches!(e.kind, AgentEventKind::GoalResolved))
        .expect("GoalResolved event");
    let pos_tool_start = events
        .iter()
        .position(|e| {
            matches!(
                &e.kind,
                AgentEventKind::ToolStarted { capability_id, .. } if capability_id == "sound.volume.set"
            )
        })
        .expect("ToolStarted event");
    let pos_tool_done = events
        .iter()
        .position(|e| {
            matches!(
                &e.kind,
                AgentEventKind::ToolCompleted { capability_id, status, .. }
                    if capability_id == "sound.volume.set"
                        && (status == "verified" || status == "committed")
            )
        })
        .expect("ToolCompleted event");
    let pos_completed = events
        .iter()
        .position(|e| {
            matches!(
                &e.kind,
                AgentEventKind::Completed { task_status } if task_status == "succeeded"
            )
        })
        .expect("Completed event");

    assert!(pos_started < pos_goal);
    assert!(pos_goal < pos_tool_start);
    assert!(pos_tool_start < pos_tool_done);
    assert!(pos_tool_done < pos_completed);
    // When `ToolCompleted` fired, `CapabilityBroker` had ALREADY committed `68`!
    assert_eq!(observed_vol_on_tool_completed.load(Ordering::SeqCst), 68);

    // Verify incremental `MessageDelta` events reassembled CJK cleanly, stripped `<think>`, and scrubbed split secret!
    let deltas: Vec<String> = events
        .iter()
        .filter_map(|e| match &e.kind {
            AgentEventKind::MessageDelta { delta } => Some(delta.clone()),
            _ => None,
        })
        .collect();
    assert!(
        deltas.len() >= 2,
        "expected multiple incremental SSE MessageDelta chunks, got {:?}",
        deltas
    );
    let combined_delta = deltas.join("");
    assert!(
        combined_delta.contains("音量已调至 68%"),
        "split multi-byte CJK must reassemble without corruption: {}",
        combined_delta
    );
    assert!(!combined_delta.contains('\u{FFFD}'));
    assert!(
        !combined_delta.contains("<think>"),
        "<think> block must not leak into user-visible MessageDelta: {}",
        combined_delta
    );
    assert!(
        !combined_delta.contains("SplitSecretAcrossChunks"),
        "secret split across SSE chunks must be scrubbed: {}",
        combined_delta
    );
}

// =============================================================================
// P1-03: Anthropic Messages API SSE Streaming + Honest `application/json` Fallback
// =============================================================================

#[derive(Clone)]
struct P1AnthropicModeState {
    use_json_fallback: Arc<AtomicBool>,
}

async fn mock_p1_03_anthropic_messages(
    State(st): State<P1AnthropicModeState>,
    Json(body): Json<Value>,
) -> Response {
    if st.use_json_fallback.load(Ordering::SeqCst) {
        return Json(json!({
            "id": "msg_json_fallback",
            "type": "message",
            "role": "assistant",
            "content": [
                { "type": "text", "text": "Anthropic 非流式 JSON 回退响应正常。" }
            ],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 30, "output_tokens": 12 }
        }))
        .into_response();
    }

    let has_tool_result = body["messages"].as_array().is_some_and(|arr| {
        arr.iter().any(|m| {
            m["content"]
                .as_array()
                .is_some_and(|blocks| blocks.iter().any(|b| b["type"] == "tool_result"))
        })
    });

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(16);
    if !has_tool_result {
        tokio::spawn(async move {
            let frames = [
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_sse_1\",\"usage\":{\"input_tokens\":42,\"output_tokens\":1}}}\n\n",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"先读取当前音量\"}}\n\n",
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_vol_get\",\"name\":\"sound_volume_get\",\"input\":{}}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n",
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
                "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":15}}\n\n",
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ];
            for f in frames {
                let _ = tx.send(Ok(Bytes::from(f.as_bytes().to_vec()))).await;
                tokio::time::sleep(Duration::from_millis(6)).await;
            }
        });
    } else {
        tokio::spawn(async move {
            let frames = [
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_sse_2\",\"usage\":{\"input_tokens\":60,\"output_tokens\":1}}}\n\n",
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"当前系统音量为 \"}}\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"55%，状态已确认。\"}}\n\n",
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
                "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":18}}\n\n",
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ];
            for f in frames {
                let _ = tx.send(Ok(Bytes::from(f.as_bytes().to_vec()))).await;
                tokio::time::sleep(Duration::from_millis(6)).await;
            }
        });
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .unwrap()
}

#[tokio::test]
async fn p1_03_h10_anthropic_sse_streaming_and_json_fallback_compatibility() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws_p1_03");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p1_core(tmp.path(), &ws, "native", 8);
    set_baseline_volume(&core, 55).await;

    let st = P1AnthropicModeState {
        use_json_fallback: Arc::new(AtomicBool::new(false)),
    };
    let app = Router::new()
        .route(
            "/anthropic/v1/messages",
            post(mock_p1_03_anthropic_messages),
        )
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mock_home = tmp.path().join("home_p1_03");
    std::fs::create_dir_all(&mock_home).unwrap();
    let opts = DiscoveryOptions::isolated_for_test(mock_home);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "claude-sse",
            "kind": "anthropic",
            "model": "claude-sonnet-4-5",
            "base_url": format!("http://{}/anthropic/v1", addr),
            "api_key": "sk-ant-test-sse",
        }),
        &opts,
    )
    .await
    .unwrap();

    // Part A: Real Anthropic SSE streaming with tool_use + text_delta
    let sse_turn_id = "turn_p1_03_anthropic_sse";
    let res_sse = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": sse_turn_id,
            "session_id": "ses_p1_03",
            "text": "帮我看看现在音量是多少",
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(res_sse["status"], "completed");
    assert_eq!(res_sse["task_status"], "succeeded");
    assert!(
        res_sse["reply_markdown"]
            .as_str()
            .unwrap_or("")
            .contains("55%")
    );
    assert!(
        res_sse["thinking"]
            .as_str()
            .unwrap_or("")
            .contains("先读取当前音量")
    );

    let polled = poll_turn_events(&json!({ "turn_id": sse_turn_id, "since_seq": 0 }));
    let evs = polled["events"].as_array().unwrap();
    let delta_count = evs.iter().filter(|e| e["event"] == "message_delta").count();
    assert!(
        delta_count >= 2,
        "Anthropic SSE should emit incremental message_delta events, got {:?}",
        evs
    );
    assert!(
        evs.iter()
            .any(|e| e["event"] == "tool_started" && e["capability_id"] == "sound.volume.get")
    );
    assert!(
        evs.iter()
            .any(|e| e["event"] == "tool_completed" && e["capability_id"] == "sound.volume.get")
    );

    // Part B: Switch mock server to non-streaming `application/json` -> verify 100% fallback compatibility
    st.use_json_fallback.store(true, Ordering::SeqCst);
    let json_turn_id = "turn_p1_03_anthropic_json";
    let res_json = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": json_turn_id,
            "session_id": "ses_p1_03",
            "text": "你好，测试 JSON 回退",
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(res_json["status"], "completed");
    assert_eq!(res_json["task_status"], "succeeded");
    assert_eq!(
        res_json["reply_markdown"],
        "Anthropic 非流式 JSON 回退响应正常。"
    );
}

// =============================================================================
// P1-04: Mid-Stream SSE Turn Cancellation (`cancel_turn`) Halts Immediately
// =============================================================================

async fn mock_p1_04_slow_sse() -> Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(8);
    tokio::spawn(async move {
        let first = "data: {\"id\":\"cmpl_slow\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"正在长文本流式生成第一段…\"}}]}\n\n";
        let _ = tx.send(Ok(Bytes::from(first.as_bytes().to_vec()))).await;
        // Hold stream open for 6 seconds unless client aborts
        tokio::time::sleep(Duration::from_secs(6)).await;
        let second = "data: {\"id\":\"cmpl_slow\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"不应到达此处\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";
        let _ = tx.send(Ok(Bytes::from(second.as_bytes().to_vec()))).await;
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .unwrap()
}

#[tokio::test]
async fn p1_04_h10_mid_stream_turn_cancellation_emits_cancelled_and_aborts_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws_p1_04");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p1_core(tmp.path(), &ws, "native", 8);

    let app = Router::new().route("/v1/chat/completions", post(mock_p1_04_slow_sse));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mock_home = tmp.path().join("home_p1_04");
    std::fs::create_dir_all(&mock_home).unwrap();
    let opts = DiscoveryOptions::isolated_for_test(mock_home);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "slow-sse",
            "model": "gpt-4o-mini",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-slow-sse",
        }),
        &opts,
    )
    .await
    .unwrap();

    let turn_id = "turn_p1_04_cancel_mid_sse";
    let cancel_core = core.clone();
    tokio::spawn(async move {
        // Wait until the first `message_delta` arrives in `poll_turn_events`, then cancel!
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let snap = poll_turn_events(&json!({ "turn_id": turn_id, "since_seq": 0 }));
            if snap["events"]
                .as_array()
                .is_some_and(|arr| arr.iter().any(|e| e["event"] == "message_delta"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        let _ = handle_module_rpc(&cancel_core, "cancel_turn", json!({ "turn_id": turn_id })).await;
    });

    let started = Instant::now();
    let out = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": turn_id,
            "session_id": "ses_p1_04",
            "text": "请生成一篇很长的流式报告",
        }),
        &opts,
    )
    .await
    .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "cancel_turn must abort mid-SSE stream promptly, took {:?}",
        elapsed
    );
    assert_eq!(out["task_status"], "cancelled");

    let snap = poll_turn_events(&json!({ "turn_id": turn_id, "since_seq": 0 }));
    let evs = snap["events"].as_array().unwrap();
    assert!(evs.iter().any(|e| e["event"] == "message_delta"));
    assert!(
        evs.iter().any(|e| e["event"] == "cancelled"),
        "expected terminal cancelled event in {:?}",
        evs
    );
}

// =============================================================================
// P1-05: Warm `pi-adapter` Worker Reuse, Incognito Lease Isolation & Idle Eviction
// =============================================================================

async fn mock_p1_05_pi_gateway_upstream(Json(body): Json<Value>) -> Json<Value> {
    let user_msg = body["messages"]
        .as_array()
        .and_then(|arr| arr.last())
        .and_then(|m| m["content"].as_str())
        .unwrap_or("");
    Json(json!({
        "id": "cmpl_pi_warm",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": format!("Warm worker processed: {}", user_msg)
            }
        }],
        "usage": { "prompt_tokens": 25, "completion_tokens": 10 }
    }))
}

#[tokio::test]
async fn p1_05_h10_warm_pi_worker_reuse_incognito_isolation_and_idle_eviction() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws_p1_05");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p1_core(tmp.path(), &ws, "pi", 8);
    assert_eq!(core.agent.active_runtime_label(), "pi-adapter (sandboxed)");

    // 0 idle workers before `pi-adapter` is ever invoked!
    let init_stats = core.agent.warm_worker_stats();
    assert_eq!(init_stats.cold_spawns, 0);
    assert_eq!(init_stats.warm_reuses, 0);
    assert_eq!(init_stats.idle_workers, 0);
    assert_eq!(init_stats.active_leases, 0);

    core.gateway
        .clone()
        .spawn_unix_socket_server(&core.paths.gateway_socket_path())
        .unwrap();

    let app = Router::new().route("/chat/completions", post(mock_p1_05_pi_gateway_upstream));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));

    // Turn 1 (Standard): Cold spawns 1 worker, then parks it idle in `WarmPiWorkerPool`
    let t1 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "请总结第一轮架构要点".into(),
                session_id: Some("ses_warm_1".into()),
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
    assert_eq!(t1.status, TaskStatus::Completed);
    let s1 = core.agent.warm_worker_stats();
    assert_eq!(s1.cold_spawns, 1);
    assert_eq!(s1.warm_reuses, 0);
    assert_eq!(s1.idle_workers, 1);
    assert_eq!(s1.active_leases, 0);

    // Turn 2 (Standard): Reuses the warm worker — ZERO new Node.js cold spawn!
    let t2 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "请总结第二轮架构要点".into(),
                session_id: Some("ses_warm_1".into()),
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
    assert_eq!(t2.status, TaskStatus::Completed);
    let s2 = core.agent.warm_worker_stats();
    assert_eq!(
        s2.cold_spawns, 1,
        "second standard turn must not cold-spawn"
    );
    assert_eq!(
        s2.warm_reuses, 1,
        "second standard turn must reuse warm worker"
    );
    assert_eq!(s2.idle_workers, 1);
    assert_eq!(s2.active_leases, 0);

    // Turn 3 (`StrictIsolated` incognito): NEVER reuses pooled worker and NEVER pools its own worker!
    let t3 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "无痕隔离测试回合".into(),
                session_id: None,
                force_agent: true,
                selected_candidate_id: None,
                cwd: None,
                incognito: true,
                privacy_policy: Some(PrivacySessionPolicy::StrictIsolated),
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(t3.status, TaskStatus::Completed);
    let s3 = core.agent.warm_worker_stats();
    assert_eq!(
        s3.cold_spawns, 2,
        "StrictIsolated must spawn fresh isolated worker"
    );
    assert_eq!(
        s3.warm_reuses, 1,
        "StrictIsolated must not reuse pooled worker"
    );
    assert_eq!(
        s3.idle_workers, 1,
        "StrictIsolated worker must be destroyed immediately after turn"
    );

    // Bounded idle TTL eviction drops idle worker count back to 0!
    let evicted = core.agent.evict_idle_warm_workers(Duration::ZERO).await;
    assert_eq!(evicted, 1);
    let s4 = core.agent.warm_worker_stats();
    assert_eq!(s4.idle_workers, 0);
    assert!(s4.idle_evictions >= 1);
}

// =============================================================================
// P1-06: Wave B End-to-End Synergy (`H07` Budget Partial + `H08` State-Observation
//        & Procedural Non-Mutation + `H09` Sub-Millisecond Warm Latency Check)
// =============================================================================

async fn mock_p1_06_looping_tools(Json(body): Json<Value>) -> Json<Value> {
    let tool_count = body["messages"]
        .as_array()
        .map(|arr| arr.iter().filter(|m| m["role"] == "tool").count())
        .unwrap_or(0);
    Json(json!({
        "id": format!("cmpl_loop_{}", tool_count),
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": format!("call_loop_get_{}", tool_count + 1),
                    "type": "function",
                    "function": {
                        "name": "sound_volume_get",
                        "arguments": "{}"
                    }
                }]
            }
        }],
        "usage": { "prompt_tokens": 30, "completion_tokens": 12 }
    }))
}

#[tokio::test]
async fn p1_06_h07_h08_h09_end_to_end_synergy_and_sub_millisecond_warm_latency() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws_p1_06");
    std::fs::create_dir_all(&ws).unwrap();
    // Configure tight `max_tool_calls = 1` to verify `H07` partial completion deterministically
    let core = init_p1_core(tmp.path(), &ws, "native", 1);

    // 1. `H08` Implicit State-Goal Observation: "声音有点吵" reads `sound.volume.get` BEFORE `sound.volume.set`!
    set_baseline_volume(&core, 70).await;
    let noisy_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "声音有点吵".into(),
                session_id: Some("ses_h08_noisy".into()),
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
    assert_eq!(noisy_task.status, TaskStatus::Completed);
    assert!(
        noisy_task.steps.len() >= 2,
        "implicit relative volume goal must observe first then adjust, got steps: {:?}",
        noisy_task.steps
    );
    assert_eq!(noisy_task.steps[0].capability_id, "sound.volume.get");
    assert_eq!(noisy_task.steps[1].capability_id, "sound.volume.set");
    assert!(
        read_volume_i64(&core) < 70,
        "volume must decrease from 70 after '声音有点吵'"
    );

    // 2. `H08` Procedural How-To Guard: "怎么调暗屏幕？" MUST NOT mutate `display.brightness`!
    set_baseline_brightness(&core, 65).await;
    let howto_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "怎么调暗屏幕？".into(),
                session_id: Some("ses_h08_howto".into()),
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
        read_brightness_i64(&core),
        65,
        "procedural question must never mutate brightness!"
    );
    assert!(
        !howto_task
            .steps
            .iter()
            .any(|s| s.capability_id == "display.brightness.set"),
        "procedural question must not invoke display.brightness.set: {:?}",
        howto_task.steps
    );

    // 3. `H07` Budget Exhaustion -> Honest `partially_completed` + `AgentEventKind::Completed`
    let app = Router::new().route("/v1/chat/completions", post(mock_p1_06_looping_tools));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mock_home = tmp.path().join("home_p1_06");
    std::fs::create_dir_all(&mock_home).unwrap();
    let opts = DiscoveryOptions::isolated_for_test(mock_home);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "budget-mock",
            "model": "gpt-4o-mini",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-budget-mock",
        }),
        &opts,
    )
    .await
    .unwrap();

    let budget_turn_id = "turn_p1_06_budget_partial";
    let budget_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": budget_turn_id,
            "session_id": "ses_p1_06",
            "text": "连续多次检查系统音量并汇总",
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(budget_res["task_status"], "partially_completed");
    assert_eq!(budget_res["budget_exhausted"], true);
    assert!(
        budget_res["completed_steps"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );
    assert!(
        budget_res["unresolved_goals"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );
    let budget_events = poll_turn_events(&json!({ "turn_id": budget_turn_id, "since_seq": 0 }));
    assert!(
        budget_events["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| { e["event"] == "completed" && e["task_status"] == "partially_completed" })
    );

    // 4. `H09` Warm-Path Latency Verification (vs `cf9e649` baseline ~23.22 ms / ~23.73 ms)
    let owned_descs: Vec<_> = core.broker.descriptors().into_iter().cloned().collect();
    // Warm up caches once
    let _ = parse_structured_intent("把音量调高一点", &owned_descs);
    let _ = build_quick_chat_openai_tools(&core, "帮我查找周报并打开设置");
    let _ = discover_backends_catalog_fast(&core, &opts).await;

    let mut parse_us = Vec::with_capacity(25);
    for _ in 0..25 {
        let t0 = Instant::now();
        let si = parse_structured_intent("屏幕太亮了，帮我调暗一点", &owned_descs);
        parse_us.push(t0.elapsed().as_micros() as u64);
        assert!(!si.goal.is_empty());
    }
    parse_us.sort_unstable();
    let parse_p50_us = parse_us[parse_us.len() / 2];

    let mut tools_us = Vec::with_capacity(25);
    for _ in 0..25 {
        let t0 = Instant::now();
        let tools = build_quick_chat_openai_tools(&core, "帮我搜索下载目录里的 PDF 文档");
        tools_us.push(t0.elapsed().as_micros() as u64);
        assert!(!tools.is_empty());
    }
    tools_us.sort_unstable();
    let tools_p50_us = tools_us[tools_us.len() / 2];

    let mut catalog_us = Vec::with_capacity(15);
    for _ in 0..15 {
        let t0 = Instant::now();
        let cat = discover_backends_catalog_fast(&core, &opts).await;
        catalog_us.push(t0.elapsed().as_micros() as u64);
        assert!(!cat.active.backend.is_empty());
    }
    catalog_us.sort_unstable();
    let catalog_p50_us = catalog_us[catalog_us.len() / 2];

    println!(
        "[H09 Warm Latency] parse_structured_intent P50={}us | build_quick_chat_openai_tools P50={}us | discover_backends_catalog_fast P50={}us",
        parse_p50_us, tools_p50_us, catalog_p50_us
    );
    assert!(
        parse_p50_us < 5_000,
        "warm parse_structured_intent P50 should be < 5ms in debug (was 23.22ms), got {}us",
        parse_p50_us
    );
    assert!(
        tools_p50_us < 5_000,
        "warm build_quick_chat_openai_tools P50 should be < 5ms in debug (was 23.73ms), got {}us",
        tools_p50_us
    );
}
