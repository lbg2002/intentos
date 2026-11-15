#![forbid(unsafe_code)]

//! Comprehensive P0 Hardening & Fault-Injection Verification Suite (`crates/intentosd/tests/e2e_v0_2_m1_1_p0.rs`).
//!
//! Covers all 12 P0 scenarios from `docs/M1_1_HARDENING_AND_M2_IMPLEMENTATION.md` §5 (`H01`–`H06`):
//! 1.  `p0_01_ten_concurrent_identical_turn_id_requests_execute_side_effect_once`
//! 2.  `p0_02_same_turn_id_different_payload_or_session_rejected_with_zero_leak`
//! 3.  `p0_03_post_mutation_daemon_crash_marks_recovery_required_and_blocks_blind_replay`
//! 4.  `p0_04_read_mutate_read_within_single_turn_invalidates_read_cache_and_sees_updated_value`
//! 5.  `p0_05_two_consecutive_relative_adjustments_and_two_media_next_both_execute`
//! 6.  `p0_06_duplicate_submission_of_same_logical_step_deduplicates_and_preserves_real_error_status`
//! 7.  `p0_07_tool_mutates_then_fails_verification_marks_unknown_recovery_required_and_blocks_replay`
//! 8.  `p0_08_ephemeral_read_only_reads_authorized_memories_writes_zero_rows_and_blocks_hijack`
//! 9.  `p0_09_strict_isolated_reads_zero_memories_writes_zero_rows_and_zero_cache_or_outbound_leak`
//! 10. `p0_10_chat_only_allow_broker_tools_false_blocks_system_tools_identically_on_http_and_cli`
//! 11. `p0_11_real_cli_os_sandbox_blocks_unauthorized_write_forbidden_read_and_cmdline_leak`
//! 12. `p0_12_pi_worker_mutates_step1_crashes_step2_coordinator_halts_native_fallback_zero_replay`

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use chrono::Utc;
use intentos_protocol::{
    CapabilityCall, CapabilityResult, DataClass, ExecutionStatus, IntentRequest, InvocationOrigin,
    PROTOCOL_VERSION, PrivacySessionPolicy, RouteLayer, Taint, Task, TaskBudget, TaskStatus,
    TaskTrigger, VerificationReport, VerificationState,
};
use intentos_sandbox::probe_sandbox_support;
use intentosd::backend_bridge::{
    ActiveBackendSelection, BackendExecutionMode, DiscoveryOptions, TurnEffectLedger,
    broker_bridge::{
        QuickChatToolExecOutcome, dispatch_broker_call_transactional,
        execute_quick_chat_tool_call_with_dispatcher, execute_quick_chat_tool_call_with_step,
    },
    providers_cli::clear_cli_capability_cache,
    send_quick_chat_turn_with_options, set_active_backend_with_options,
    turn_checkpoint::StepInvocationContext,
};
use intentosd::broker::BrokerDispatchOutcome;
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use intentosd::db::StepExecState;
use intentosd::ipc::start_ui_socket_server;
use intentosd::memory_hub::{RecordTurnInput, record_conversation_turn_with_policy};
use intentosd::runtime::SessionState;
use intentosd::security_guard::UnifiedTaskStateMachine;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
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

fn init_p0_core(base: &Path, ws: &Path, runtime: &str) -> Arc<IntentOsCore> {
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
    IntentOsCore::initialize(Some(base), repo_root).expect("init p0 test core")
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

fn read_volume_i64(core: &IntentOsCore) -> i64 {
    let (v, _) = core.settings.read_setting_value("sound.volume").unwrap();
    v.as_f64().expect("numeric volume").round() as i64
}

async fn set_baseline_volume(core: &IntentOsCore, val: i64) {
    let outcome = core
        .broker
        .dispatch(&CapabilityCall {
            request_id: format!("req_base_vol_{}", val),
            task_id: "incog_baseline_setup".to_string(),
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
            request_id: format!("req_base_bright_{}", val),
            task_id: "incog_baseline_setup".to_string(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DbRowSnapshot {
    tasks: i64,
    step_execution_log: i64,
    changesets: i64,
    audit_log: i64,
    memories: i64,
    suspended_checkpoints: i64,
    chat_sessions: i64,
    chat_messages: i64,
    entity_mentions: i64,
    long_term_files: i64,
}

fn count_sqlite_table(path: &Path, table: &str) -> i64 {
    if !path.exists() {
        return 0;
    }
    let conn = Connection::open(path).expect("open sqlite for count");
    let sql = format!("SELECT COUNT(1) FROM {}", table);
    conn.query_row(&sql, [], |r| r.get::<_, i64>(0))
        .unwrap_or(0)
}

fn snapshot_all_persistence_counts(core: &IntentOsCore) -> DbRowSnapshot {
    let state_db = core.paths.data_dir.join("state.db");
    let mem_db = core.paths.data_dir.join("memory_hub.db");
    DbRowSnapshot {
        tasks: count_sqlite_table(&state_db, "tasks"),
        step_execution_log: count_sqlite_table(&state_db, "step_execution_log"),
        changesets: count_sqlite_table(&state_db, "changesets"),
        audit_log: count_sqlite_table(&state_db, "audit_log"),
        memories: count_sqlite_table(&state_db, "memories"),
        suspended_checkpoints: count_sqlite_table(&state_db, "suspended_turn_checkpoints"),
        chat_sessions: count_sqlite_table(&mem_db, "chat_sessions"),
        chat_messages: count_sqlite_table(&mem_db, "chat_messages"),
        entity_mentions: count_sqlite_table(&mem_db, "entity_mentions"),
        long_term_files: count_sqlite_table(&mem_db, "long_term_files"),
    }
}

// =============================================================================
// P0-01: 10 Concurrent Identical `turn_id` Requests -> Side Effect Executes ONCE
// =============================================================================

#[derive(Clone)]
struct P0ConcurrentState {
    upstream_calls: Arc<AtomicUsize>,
    tool_rounds: Arc<AtomicUsize>,
}

async fn mock_p0_01_completions(
    State(state): State<P0ConcurrentState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.upstream_calls.fetch_add(1, Ordering::SeqCst);
    let has_tool_msg = body["messages"]
        .as_array()
        .is_some_and(|arr| arr.iter().any(|m| m["role"] == "tool"));

    if !has_tool_msg {
        // Hold round 1 briefly so all 10 concurrent callers overlap in-flight
        tokio::time::sleep(Duration::from_millis(60)).await;
        state.tool_rounds.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "id": "chatcmpl_p0_01_r1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>将音量相对调高一次</think>",
                    "tool_calls": [{
                        "id": "call_p0_01_vol_up",
                        "type": "function",
                        "function": {
                            "name": "sound_volume_set",
                            "arguments": "{\"relative\":\"up\"}"
                        }
                    }]
                }
            }]
        }))
    } else {
        Json(json!({
            "id": "chatcmpl_p0_01_r2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "已将音量调高一格。"
                }
            }]
        }))
    }
}

#[tokio::test]
async fn p0_01_ten_concurrent_identical_turn_id_requests_execute_side_effect_once() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p0_core(tmp.path(), &ws, "native");

    // Measure single relative-up delta first, then reset to 40%
    set_baseline_volume(&core, 40).await;
    let probe_up = core
        .broker
        .dispatch(&CapabilityCall {
            request_id: "req_probe_delta".to_string(),
            task_id: "incog_probe_delta".to_string(),
            capability_id: "sound.volume.set".to_string(),
            arguments: json!({ "relative": "up" }),
            origin: InvocationOrigin::UserExplicit,
            taints: vec![Taint::User],
        })
        .await
        .unwrap();
    assert!(matches!(probe_up, BrokerDispatchOutcome::Executed(_)));
    let single_step_vol = read_volume_i64(&core);
    let step_delta = single_step_vol - 40;
    assert!(
        step_delta > 0,
        "relative up must increase volume above 40, got {}",
        single_step_vol
    );
    set_baseline_volume(&core, 40).await;

    let st = P0ConcurrentState {
        upstream_calls: Arc::new(AtomicUsize::new(0)),
        tool_rounds: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_p0_01_completions))
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mock_home = tmp.path().join("mock_home_p0_01");
    std::fs::create_dir_all(&mock_home).unwrap();
    let opts = DiscoveryOptions::isolated_for_test(mock_home);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "p0-01-openai",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-p0-01-dummy-token-123456"
        }),
        &opts,
    )
    .await
    .unwrap();

    let barrier = Arc::new(tokio::sync::Barrier::new(10));
    let mut handles = Vec::new();
    for _ in 0..10 {
        let c = core.clone();
        let o = opts.clone();
        let b = barrier.clone();
        handles.push(tokio::spawn(async move {
            b.wait().await;
            send_quick_chat_turn_with_options(
                &c,
                &json!({
                    "turn_id": "turn_p0_01_concurrent_storm",
                    "session_id": "ses_p0_01",
                    "text": "把音量调高一点"
                }),
                &o,
            )
            .await
            .unwrap()
        }));
    }

    let mut responses = Vec::new();
    for h in handles {
        responses.push(h.await.unwrap());
    }

    assert_eq!(responses.len(), 10);
    let leader_task_id = responses[0]["task_id"].as_str().unwrap().to_string();
    let leader_cs = responses[0]["changeset_ids"].clone();
    assert_eq!(leader_cs.as_array().unwrap().len(), 1);

    let mut coalesced_followers = 0usize;
    for r in &responses {
        assert_eq!(r["status"], "completed");
        assert_eq!(r["task_id"].as_str().unwrap(), leader_task_id);
        assert_eq!(r["changeset_ids"], leader_cs);
        if r.get("coalesced_in_flight").and_then(|v| v.as_bool()) == Some(true) {
            coalesced_followers += 1;
        }
    }
    assert_eq!(
        coalesced_followers, 9,
        "9 of 10 concurrent identical turn_id requests MUST join the single leader in-flight"
    );
    assert_eq!(
        st.tool_rounds.load(Ordering::SeqCst),
        1,
        "tool-calling round must run ONCE across 10 concurrent requests"
    );
    assert_eq!(
        st.upstream_calls.load(Ordering::SeqCst),
        2,
        "upstream OpenAI server must see 2 HTTP calls total (round1 + round2), never 20"
    );
    assert_eq!(
        read_volume_i64(&core),
        40 + step_delta,
        "relative volume side effect MUST execute exactly ONCE (40 + {}), never 10x!",
        step_delta
    );

    let step_rows = core
        .state_db
        .list_step_execution_logs_for_turn("turn_p0_01_concurrent_storm")
        .unwrap();
    assert_eq!(step_rows.len(), 1);
    assert_eq!(step_rows[0].exec_state, StepExecState::Verified);

    // 11th sequential replay hits completed cache with 0 extra upstream calls
    let replay_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_01_concurrent_storm",
            "session_id": "ses_p0_01",
            "text": "把音量调高一点"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(replay_res["idempotent_replay"], true);
    assert_eq!(st.upstream_calls.load(Ordering::SeqCst), 2);
}

// =============================================================================
// P0-02: Same `turn_id` + Different Payload or Session -> Rejected (`turn_conflict`),
//        Zero Private Result Leak
// =============================================================================

#[tokio::test]
async fn p0_02_same_turn_id_different_payload_or_session_rejected_with_zero_leak() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p0_core(tmp.path(), &ws, "native");

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_srv = calls.clone();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(_body): Json<Value>| {
            let c = calls_srv.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Json(json!({
                    "id": "chatcmpl_p0_02",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "私有项目代号是 ORION-VAULT-7788，严禁跨会话泄露。"
                        }
                    }]
                }))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let opts = DiscoveryOptions::isolated_for_test(tmp.path().join("mock_home_p0_02"));
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "p0-02-openai",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-p0-02-dummy-token-123456"
        }),
        &opts,
    )
    .await
    .unwrap();

    let ok_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_02_identity_bound",
            "session_id": "ses_alice",
            "text": "请告诉我私有项目代号"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(ok_res["status"], "completed");
    assert!(
        ok_res["reply_markdown"]
            .as_str()
            .unwrap()
            .contains("ORION-VAULT-7788")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // 1) Same turn_id + same session_id + DIFFERENT payload text -> `turn_conflict`, zero leak
    let payload_err = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_02_identity_bound",
            "session_id": "ses_alice",
            "text": "把系统音量调到 100%"
        }),
        &opts,
    )
    .await
    .expect_err("same turn_id with different payload MUST fail closed with turn_conflict")
    .to_string();
    assert!(payload_err.contains("turn_conflict"));
    assert!(payload_err.contains("request_digest"));
    assert!(
        !payload_err.contains("ORION-VAULT-7788"),
        "payload_mismatch error MUST NOT leak cached turn output: {}",
        payload_err
    );

    // 2) Same turn_id + DIFFERENT session_id + identical text -> `turn_conflict`, zero leak
    let session_err = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_02_identity_bound",
            "session_id": "ses_mallory",
            "text": "请告诉我私有项目代号"
        }),
        &opts,
    )
    .await
    .expect_err("same turn_id across different session_id MUST fail closed with turn_conflict")
    .to_string();
    assert!(session_err.contains("turn_conflict"));
    assert!(session_err.contains("session"));
    assert!(
        !session_err.contains("ORION-VAULT-7788"),
        "session_mismatch error MUST NOT leak Alice's private reply to Mallory: {}",
        session_err
    );

    // 3) Same turn_id + same session_id + DIFFERENT `privacy_policy` -> `turn_conflict`, zero leak
    let policy_err = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_02_identity_bound",
            "session_id": "ses_alice",
            "text": "请告诉我私有项目代号",
            "privacy_policy": "ephemeral_read_only"
        }),
        &opts,
    )
    .await
    .expect_err("same turn_id with different privacy_policy MUST fail closed with turn_conflict")
    .to_string();
    assert!(policy_err.contains("turn_conflict"));
    assert!(!policy_err.contains("ORION-VAULT-7788"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// =============================================================================
// P0-03: Post-Mutation Daemon Crash (`Executing` Row in `step_execution_log`) ->
//        `StateDb::open` Marks `recovery_required` and Prevents Blind Replay
// =============================================================================

#[tokio::test]
async fn p0_03_post_mutation_daemon_crash_marks_recovery_required_and_blocks_blind_replay() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("xdg_p0_03");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let crash_target = ws.join("crash_mid_flight.txt");

    let task_id = "task_p0_03_crash".to_string();
    let turn_id = "turn_p0_03_crash".to_string();

    {
        let core1 = init_p0_core(&base, &ws, "native");
        let now = Utc::now();
        let running_task = Task {
            id: task_id.clone(),
            goal: "写入 crash_mid_flight.txt".to_string(),
            session_id: Some("ses_p0_03".to_string()),
            project_id: None,
            trigger: TaskTrigger::User,
            route: RouteLayer::L2,
            status: TaskStatus::Running,
            steps: Vec::new(),
            changeset_ids: Vec::new(),
            pending_approval: None,
            candidates_for_disambiguation: Vec::new(),
            assistant_message: None,
            result_summary: None,
            handoff_command: None,
            taint: vec![Taint::User],
            data_class: DataClass::Personal,
            budget: TaskBudget::default(),
            created_at: now,
            updated_at: now,
        };
        core1.state_db.upsert_task(&running_task).unwrap();

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let core_in_flight = core1.clone();
        let target_in_flight = crash_target.clone();
        let tid_in_flight = task_id.clone();
        let turn_in_flight = turn_id.clone();

        let spawned = tokio::spawn(async move {
            let active = ActiveBackendSelection {
                backend: "openai".to_string(),
                provider: "local".to_string(),
                model: "gpt-5.4".to_string(),
                reasoning_effort: "default".to_string(),
                base_url: None,
                pinned: true,
                auto_selected: false,
                direct_http_capable: true,
                pill_label: "OpenAI · gpt-5.4".to_string(),
            };
            let session = SessionState {
                session_id: "ses_p0_03".to_string(),
                messages: Vec::new(),
                last_resource_path: None,
                updated_at: Utc::now(),
            };
            let mut ledger = TurnEffectLedger::new(&turn_in_flight);
            ledger.bind_persistence(
                core_in_flight.state_db.clone(),
                tid_in_flight.clone(),
                session.session_id.clone(),
                PrivacySessionPolicy::Standard,
            );

            let c_check = core_in_flight.clone();
            let tid_check = tid_in_flight.clone();
            let _ = execute_quick_chat_tool_call_with_dispatcher(
                &core_in_flight,
                &active,
                BackendExecutionMode::ManagedBrokerTools,
                &tid_in_flight,
                &session,
                "写入文档",
                false,
                &[Taint::User],
                DataClass::Personal,
                StepInvocationContext::new_call("call_crash_1"),
                "file_write",
                &json!({
                    "path": target_in_flight.to_string_lossy(),
                    "content": "INTENDED_COMPLETE_CONTENT"
                }),
                &mut ledger,
                move |_call| async move {
                    // Verify `Prepared -> Executing` is ALREADY durable in `step_execution_log`!
                    let row = c_check
                        .state_db
                        .get_step_execution_log(&tid_check, "step_1")
                        .unwrap()
                        .expect("step_1 must be journaled before OS side effect");
                    assert_eq!(row.exec_state, StepExecState::Executing);

                    // Perform partial OS side effect, then hang to simulate abrupt daemon SIGKILL
                    std::fs::write(&target_in_flight, b"PARTIAL_BYTES_BEFORE_SIGKILL").unwrap();
                    let _ = entered_tx.send(());
                    std::future::pending::<anyhow::Result<BrokerDispatchOutcome>>().await
                },
            )
            .await;
        });

        entered_rx.await.unwrap();
        spawned.abort();
        let _ = spawned.await;
        // `core1` drops here with `step_1` stranded in `Executing` and partial bytes on disk!
    }

    // Restart daemon on the same XDG directory -> `StateDb::open` runs startup reconciliation
    let core2 = IntentOsCore::initialize(Some(&base), repo_root_dir()).unwrap();

    let recovered_step = core2
        .state_db
        .get_step_execution_log(&task_id, "step_1")
        .unwrap()
        .expect("step_1 row must persist across restart");
    assert_eq!(
        recovered_step.exec_state,
        StepExecState::RecoveryRequired,
        "Executing step across crash MUST transition to recovery_required"
    );
    assert_eq!(recovered_step.verification_status, "UnknownAfterCrash");

    let recovered_task = core2
        .state_db
        .get_task(&task_id)
        .unwrap()
        .expect("task must persist across restart");
    assert_eq!(
        recovered_task.status,
        TaskStatus::RecoveryRequired,
        "Parent task MUST transition to TaskStatus::RecoveryRequired"
    );

    // Attempting blind replay on the crashed task/turn MUST fail closed without overwriting disk!
    let mut replay_ledger = TurnEffectLedger::new(&turn_id);
    replay_ledger.bind_persistence(
        core2.state_db.clone(),
        task_id.clone(),
        "ses_p0_03".to_string(),
        PrivacySessionPolicy::Standard,
    );
    let replay_attempt = dispatch_broker_call_transactional(
        &core2,
        "ses_p0_03",
        PrivacySessionPolicy::Standard,
        StepInvocationContext::new_call("call_blind_replay"),
        &CapabilityCall {
            request_id: "call_blind_replay".to_string(),
            task_id: task_id.clone(),
            capability_id: "file.write".to_string(),
            arguments: json!({
                "path": crash_target.to_string_lossy(),
                "content": "BLIND_REPLAY_OVERWRITE"
            }),
            origin: InvocationOrigin::L2AgentPlan,
            taints: vec![Taint::User],
        },
        &mut replay_ledger,
    )
    .await;
    assert!(
        replay_attempt.is_err(),
        "Blind replay after crash MUST be blocked by recovery_required guard"
    );
    assert_eq!(
        std::fs::read(&crash_target).unwrap(),
        b"PARTIAL_BYTES_BEFORE_SIGKILL",
        "Crashed target file must NOT be overwritten by blind replay"
    );
}

// =============================================================================
// P0-04: `Read -> Mutate -> Read` Within One Turn -> Second Read Sees Updated Value
//        (Verified on BOTH Quick-Chat HTTP and Core L2 `AgentCoordinator`)
// =============================================================================

#[derive(Clone)]
struct P0ReadMutateReadState {
    target_val: i64,
    observed_reads: Arc<Mutex<Vec<i64>>>,
}

async fn mock_p0_04_completions(
    State(st): State<P0ReadMutateReadState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let msgs = body["messages"].as_array().cloned().unwrap_or_default();
    let tool_msgs: Vec<&Value> = msgs.iter().filter(|m| m["role"] == "tool").collect();

    match tool_msgs.len() {
        0 => Json(json!({
            "id": "chatcmpl_p0_04_step1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_rmr_read1",
                        "type": "function",
                        "function": {
                            "name": "sound_volume_get",
                            "arguments": "{}"
                        }
                    }]
                }
            }]
        })),
        1 => {
            let content_raw = tool_msgs[0]["content"].as_str().unwrap_or("{}");
            let parsed: Value = serde_json::from_str(content_raw).unwrap_or_default();
            let v1 = parsed
                .pointer("/data/value")
                .or_else(|| parsed.get("value"))
                .and_then(|v| v.as_f64())
                .unwrap_or(-1.0)
                .round() as i64;
            st.observed_reads.lock().unwrap().push(v1);

            Json(json!({
                "id": "chatcmpl_p0_04_step2",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "call_rmr_set",
                            "type": "function",
                            "function": {
                                "name": "sound_volume_set",
                                "arguments": serde_json::to_string(&json!({ "value": st.target_val })).unwrap()
                            }
                        }]
                    }
                }]
            }))
        }
        2 => Json(json!({
            "id": "chatcmpl_p0_04_step3",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_rmr_read2",
                        "type": "function",
                        "function": {
                            "name": "sound_volume_get",
                            "arguments": "{}"
                        }
                    }]
                }
            }]
        })),
        _ => {
            let content_raw = tool_msgs
                .last()
                .and_then(|m| m["content"].as_str())
                .unwrap_or("{}");
            let parsed: Value = serde_json::from_str(content_raw).unwrap_or_default();
            let v2 = parsed
                .pointer("/data/value")
                .or_else(|| parsed.get("value"))
                .and_then(|v| v.as_f64())
                .unwrap_or(-1.0)
                .round() as i64;
            st.observed_reads.lock().unwrap().push(v2);

            Json(json!({
                "id": "chatcmpl_p0_04_done",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": format!("前后两次读取音量结果已完成，最新音量为 {}%。", v2)
                    }
                }]
            }))
        }
    }
}

#[tokio::test]
async fn p0_04_read_mutate_read_within_single_turn_invalidates_read_cache_and_sees_updated_value() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p0_core(tmp.path(), &ws, "native");

    // --- Phase A: Quick-Chat HTTP (`35 -> 75 -> 75`) ---
    set_baseline_volume(&core, 35).await;
    let qc_state = P0ReadMutateReadState {
        target_val: 75,
        observed_reads: Arc::new(Mutex::new(Vec::new())),
    };
    let app_qc = Router::new()
        .route("/v1/chat/completions", post(mock_p0_04_completions))
        .with_state(qc_state.clone());
    let l_qc = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_qc = l_qc.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(l_qc, app_qc).await.unwrap();
    });

    let opts = DiscoveryOptions::isolated_for_test(tmp.path().join("mock_home_p0_04"));
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "p0-04-openai",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr_qc),
            "api_key": "sk-p0-04-dummy-token-123456"
        }),
        &opts,
    )
    .await
    .unwrap();

    let qc_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_p0_04_qc",
            "text": "先读取当前音量，再改成 75%，然后再读一次确认"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(qc_res["status"], "completed");
    assert_eq!(
        *qc_state.observed_reads.lock().unwrap(),
        vec![35, 75],
        "Quick-Chat Read -> Mutate -> Read MUST invalidate epoch read cache and see 75 on second read"
    );

    // --- Phase B: Core L2 `submit_intent` (`25 -> 65 -> 65`) ---
    set_baseline_volume(&core, 25).await;
    core.broker
        .policy()
        .add_session_grant("capability", "sound.volume.set", 60);
    let l2_state = P0ReadMutateReadState {
        target_val: 65,
        observed_reads: Arc::new(Mutex::new(Vec::new())),
    };
    let app_l2 = Router::new()
        .route("/chat/completions", post(mock_p0_04_completions))
        .with_state(l2_state.clone());
    let l_l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_l2 = l_l2.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(l_l2, app_l2).await.unwrap();
    });
    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr_l2)));

    let l2_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: "先查看当前音量，再把音量设为 65%，然后再读取确认".to_string(),
                session_id: Some("ses_p0_04_l2".to_string()),
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
    assert_eq!(l2_task.route, RouteLayer::L2);
    assert_eq!(l2_task.status, TaskStatus::Completed);
    assert_eq!(
        *l2_state.observed_reads.lock().unwrap(),
        vec![25, 65],
        "Core L2 Read -> Mutate -> Read MUST invalidate epoch read cache and see 65 on second read"
    );
}

// =============================================================================
// P0-05: Two Consecutive Relative Adjustments + Two `media.control("next")` Steps ->
//        BOTH Execute Without False Deduplication
// =============================================================================

#[tokio::test]
async fn p0_05_two_consecutive_relative_adjustments_and_two_media_next_both_execute() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p0_core(tmp.path(), &ws, "native");

    // Measure single relative-up step delta
    set_baseline_volume(&core, 40).await;
    let _ = core
        .broker
        .dispatch(&CapabilityCall {
            request_id: "req_p0_05_delta".to_string(),
            task_id: "incog_p0_05_delta".to_string(),
            capability_id: "sound.volume.set".to_string(),
            arguments: json!({ "relative": "up" }),
            origin: InvocationOrigin::UserExplicit,
            taints: vec![Taint::User],
        })
        .await
        .unwrap();
    let step_delta = read_volume_i64(&core) - 40;
    assert!(step_delta > 0);
    set_baseline_volume(&core, 40).await;

    let app = Router::new().route(
        "/v1/chat/completions",
        post(|Json(body): Json<Value>| async move {
            let has_tool = body["messages"]
                .as_array()
                .is_some_and(|arr| arr.iter().any(|m| m["role"] == "tool"));
            if !has_tool {
                Json(json!({
                    "id": "chatcmpl_p0_05_r1",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [
                                {
                                    "id": "call_vol_up_1",
                                    "type": "function",
                                    "function": {
                                        "name": "sound_volume_set",
                                        "arguments": "{\"relative\":\"up\"}"
                                    }
                                },
                                {
                                    "id": "call_vol_up_2",
                                    "type": "function",
                                    "function": {
                                        "name": "sound_volume_set",
                                        "arguments": "{\"relative\":\"up\"}"
                                    }
                                },
                                {
                                    "id": "call_media_next_1",
                                    "type": "function",
                                    "function": {
                                        "name": "media_control",
                                        "arguments": "{\"action\":\"next\"}"
                                    }
                                },
                                {
                                    "id": "call_media_next_2",
                                    "type": "function",
                                    "function": {
                                        "name": "media_control",
                                        "arguments": "{\"action\":\"next\"}"
                                    }
                                }
                            ]
                        }
                    }]
                }))
            } else {
                Json(json!({
                    "id": "chatcmpl_p0_05_r2",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "已连续调高两次音量并切过两首歌。"
                        }
                    }]
                }))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let opts = DiscoveryOptions::isolated_for_test(tmp.path().join("mock_home_p0_05"));
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "p0-05-openai",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-p0-05-dummy-token-123456"
        }),
        &opts,
    )
    .await
    .unwrap();

    let res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_05_non_idempotent",
            "session_id": "ses_p0_05",
            "text": "把音量连续调高两次，并且切两次下一首"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(res["status"], "completed");
    assert_eq!(
        read_volume_i64(&core),
        40 + 2 * step_delta,
        "BOTH relative volume up steps must execute (expected {}, got {})",
        40 + 2 * step_delta,
        read_volume_i64(&core)
    );
    assert_eq!(res["tool_steps"].as_array().unwrap().len(), 4);

    let step_rows = core
        .state_db
        .list_step_execution_logs_for_turn("turn_p0_05_non_idempotent")
        .unwrap();
    assert_eq!(
        step_rows.len(),
        4,
        "All 4 non-idempotent steps (2 relative volume + 2 media.control next) MUST execute and log distinctly"
    );
    let vol_rows = step_rows
        .iter()
        .filter(|r| r.capability_id == "sound.volume.set")
        .count();
    let media_rows = step_rows
        .iter()
        .filter(|r| r.capability_id == "media.control")
        .count();
    assert_eq!(vol_rows, 2);
    assert_eq!(media_rows, 2);
}

// =============================================================================
// P0-06: Duplicate Submission of Same Logical Step -> Deduplicated While Preserving
//        Real `is_error` / Denial Status
// =============================================================================

#[tokio::test]
async fn p0_06_duplicate_submission_of_same_logical_step_deduplicates_and_preserves_real_error_status()
 {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p0_core(tmp.path(), &ws, "native");
    set_baseline_brightness(&core, 30).await;

    let active = ActiveBackendSelection {
        backend: "openai".to_string(),
        provider: "local".to_string(),
        model: "gpt-5.4".to_string(),
        reasoning_effort: "default".to_string(),
        base_url: None,
        pinned: true,
        auto_selected: false,
        direct_http_capable: true,
        pill_label: "OpenAI · gpt-5.4".to_string(),
    };
    let session = SessionState {
        session_id: "ses_p0_06".to_string(),
        messages: Vec::new(),
        last_resource_path: None,
        updated_at: Utc::now(),
    };
    let mut ledger = TurnEffectLedger::new("turn_p0_06");
    ledger.bind_persistence(
        core.state_db.clone(),
        "task_p0_06".to_string(),
        session.session_id.clone(),
        PrivacySessionPolicy::Standard,
    );

    // Part A: Convergent absolute setter `display.brightness.set({"value": 62})` submitted twice
    // with the same logical `step_id` / epoch -> deduplicated cleanly (`is_error == false`).
    let ok1 = execute_quick_chat_tool_call_with_step(
        &core,
        &active,
        BackendExecutionMode::ManagedBrokerTools,
        "task_p0_06",
        &session,
        "设置亮度 62%",
        false,
        &[Taint::User],
        DataClass::Personal,
        StepInvocationContext::for_trusted_step("step_bright_set", "call_b1", "attempt_1"),
        "display_brightness_set",
        &json!({ "value": 62 }),
        &mut ledger,
    )
    .await
    .unwrap();
    match ok1 {
        QuickChatToolExecOutcome::ToolMessage {
            is_error,
            duplicate_blocked,
            ..
        } => {
            assert!(!is_error);
            assert!(!duplicate_blocked);
        }
        _ => panic!("expected ToolMessage"),
    }
    assert_eq!(read_brightness_i64(&core), 62);
    assert_eq!(ledger.committed_changeset_ids().len(), 1);

    let ok2 = execute_quick_chat_tool_call_with_step(
        &core,
        &active,
        BackendExecutionMode::ManagedBrokerTools,
        "task_p0_06",
        &session,
        "设置亮度 62%",
        false,
        &[Taint::User],
        DataClass::Personal,
        StepInvocationContext::for_trusted_step("step_bright_set", "call_b2", "attempt_1"),
        "display_brightness_set",
        &json!({ "value": 62 }),
        &mut ledger,
    )
    .await
    .unwrap();
    match ok2 {
        QuickChatToolExecOutcome::ToolMessage {
            is_error,
            duplicate_blocked,
            ..
        } => {
            assert!(!is_error, "cached success must preserve is_error == false");
            assert!(
                duplicate_blocked,
                "duplicate convergent setter must hit TurnEffectLedger deduplication"
            );
        }
        _ => panic!("expected deduplicated ToolMessage"),
    }
    assert_eq!(ledger.committed_changeset_ids().len(), 1);

    // Part B: Forbidden path `file.write` submitted twice -> first is Denied (`is_error == true`),
    // second hits deduplication AND strictly preserves `is_error == true` (NEVER fabricated success!).
    let forbidden_cfg = core.paths.config_dir.join("pwned_brain.toml");
    let den1 = execute_quick_chat_tool_call_with_step(
        &core,
        &active,
        BackendExecutionMode::ManagedBrokerTools,
        "task_p0_06",
        &session,
        "写入配置",
        false,
        &[Taint::User],
        DataClass::Personal,
        StepInvocationContext::for_trusted_step("step_forbid_write", "call_d1", "attempt_1"),
        "file_write",
        &json!({
            "path": forbidden_cfg.to_string_lossy(),
            "content": "hacked = true"
        }),
        &mut ledger,
    )
    .await
    .unwrap();
    match den1 {
        QuickChatToolExecOutcome::ToolMessage {
            is_error,
            duplicate_blocked,
            ..
        } => {
            assert!(
                is_error,
                "first forbidden write must report is_error == true"
            );
            assert!(!duplicate_blocked);
        }
        _ => panic!("expected denied ToolMessage"),
    }

    let den2 = execute_quick_chat_tool_call_with_step(
        &core,
        &active,
        BackendExecutionMode::ManagedBrokerTools,
        "task_p0_06",
        &session,
        "写入配置",
        false,
        &[Taint::User],
        DataClass::Personal,
        StepInvocationContext::for_trusted_step("step_forbid_write", "call_d2", "attempt_1"),
        "file_write",
        &json!({
            "path": forbidden_cfg.to_string_lossy(),
            "content": "hacked = true"
        }),
        &mut ledger,
    )
    .await
    .unwrap();
    match den2 {
        QuickChatToolExecOutcome::ToolMessage {
            content,
            is_error,
            duplicate_blocked,
        } => {
            assert!(
                duplicate_blocked,
                "second identical denied step must be deduplicated"
            );
            assert!(
                is_error,
                "deduplicated denied step MUST preserve real is_error == true, got content={}",
                content
            );
            let v: Value = serde_json::from_str(&content).unwrap();
            assert_eq!(v["was_denied"], true);
        }
        _ => panic!("expected deduplicated denied ToolMessage"),
    }
    assert!(!forbidden_cfg.exists());

    // Also verify Core `dispatch_broker_call_transactional` preserves `BrokerDispatchOutcome::Denied` on cached hit!
    let core_dup_den = dispatch_broker_call_transactional(
        &core,
        &session.session_id,
        PrivacySessionPolicy::Standard,
        StepInvocationContext::for_trusted_step("step_forbid_write", "call_d3", "attempt_1"),
        &CapabilityCall {
            request_id: "call_d3".to_string(),
            task_id: "task_p0_06".to_string(),
            capability_id: "file.write".to_string(),
            arguments: json!({
                "path": forbidden_cfg.to_string_lossy(),
                "content": "hacked = true"
            }),
            origin: InvocationOrigin::L2AgentPlan,
            taints: vec![Taint::User],
        },
        &mut ledger,
    )
    .await
    .unwrap();
    assert!(matches!(core_dup_den, BrokerDispatchOutcome::Denied { .. }));
}

// =============================================================================
// P0-07: Tool Mutates State Then Fails Verification -> `Unknown` / `RecoveryRequired`,
//        Blocks Subsequent Mutations & Fallback Replay
// =============================================================================

#[tokio::test]
async fn p0_07_tool_mutates_then_fails_verification_marks_unknown_recovery_required_and_blocks_replay()
 {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p0_core(tmp.path(), &ws, "native");

    let mutated_file = ws.join("dirty_unverified.txt");
    let now = Utc::now();
    let mut task = Task {
        id: "task_p0_07_verif_fail".to_string(),
        goal: "写入并校验 dirty_unverified.txt".to_string(),
        session_id: Some("ses_p0_07".to_string()),
        project_id: None,
        trigger: TaskTrigger::User,
        route: RouteLayer::L2,
        status: TaskStatus::Running,
        steps: Vec::new(),
        changeset_ids: Vec::new(),
        pending_approval: None,
        candidates_for_disambiguation: Vec::new(),
        assistant_message: None,
        result_summary: None,
        handoff_command: None,
        taint: vec![Taint::User],
        data_class: DataClass::Personal,
        budget: TaskBudget::default(),
        created_at: now,
        updated_at: now,
    };
    core.state_db.upsert_task(&task).unwrap();

    let active = ActiveBackendSelection {
        backend: "openai".to_string(),
        provider: "local".to_string(),
        model: "gpt-5.4".to_string(),
        reasoning_effort: "default".to_string(),
        base_url: None,
        pinned: true,
        auto_selected: false,
        direct_http_capable: true,
        pill_label: "OpenAI · gpt-5.4".to_string(),
    };
    let session = SessionState {
        session_id: "ses_p0_07".to_string(),
        messages: Vec::new(),
        last_resource_path: None,
        updated_at: Utc::now(),
    };
    let mut ledger = TurnEffectLedger::new("turn_p0_07");
    ledger.bind_persistence(
        core.state_db.clone(),
        task.id.clone(),
        session.session_id.clone(),
        PrivacySessionPolicy::Standard,
    );

    let mf = mutated_file.clone();
    let step1_out = execute_quick_chat_tool_call_with_dispatcher(
        &core,
        &active,
        BackendExecutionMode::ManagedBrokerTools,
        &task.id,
        &session,
        "写入 dirty_unverified.txt",
        false,
        &[Taint::User],
        DataClass::Personal,
        StepInvocationContext::new_call("call_vf_1"),
        "file_write",
        &json!({
            "path": mutated_file.to_string_lossy(),
            "content": "EXPECTED_CLEAN_PAYLOAD"
        }),
        &mut ledger,
        move |call| async move {
            // Mutate disk, then fail post-condition SHA-256 verification!
            std::fs::write(&mf, b"CORRUPTED_PARTIAL_WRITE_ON_DISK").unwrap();
            Ok(BrokerDispatchOutcome::Executed(CapabilityResult {
                request_id: call.request_id,
                capability_id: call.capability_id,
                status: ExecutionStatus::VerificationFailed,
                exit_code: Some(1),
                message: "写入后 SHA-256 校验不一致".to_string(),
                data: json!({ "path": mf.to_string_lossy() }),
                stdout_preview: String::new(),
                stderr_preview: "sha256 mismatch".to_string(),
                truncated: false,
                duration_ms: 5,
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "openat2_postcondition_sha256".to_string(),
                    checks: vec!["sha256_mismatch".to_string()],
                    details: Some("expected != actual".to_string()),
                },
                backend_mode: "fault_injection".to_string(),
            }))
        },
    )
    .await
    .unwrap();

    match step1_out {
        QuickChatToolExecOutcome::ToolMessage { is_error, .. } => {
            assert!(is_error);
        }
        _ => panic!("expected error ToolMessage"),
    }
    assert!(
        ledger.has_uncertain_side_effects(),
        "Post-mutation VerificationFailed MUST set has_uncertain_side_effects() = true"
    );
    assert!(ledger.has_uncertain_or_committed_side_effects());

    let log_row = core
        .state_db
        .get_step_execution_log(&task.id, "step_1")
        .unwrap()
        .expect("step_1 row");
    assert_eq!(log_row.exec_state, StepExecState::Unknown);

    // Quick-Chat follow-up mutating call in the same turn is halted (`uncertain_side_effect_halt`)
    let halted_qc = execute_quick_chat_tool_call_with_step(
        &core,
        &active,
        BackendExecutionMode::ManagedBrokerTools,
        &task.id,
        &session,
        "重试写入",
        false,
        &[Taint::User],
        DataClass::Personal,
        StepInvocationContext::new_call("call_vf_retry"),
        "sound_volume_set",
        &json!({ "value": 80 }),
        &mut ledger,
    )
    .await
    .unwrap();
    match halted_qc {
        QuickChatToolExecOutcome::ToolMessage {
            content, is_error, ..
        } => {
            assert!(is_error);
            assert!(
                content.contains("recovery_required_halt")
                    || content.contains("uncertain_side_effect_halt"),
                "expected recovery_required_halt, got: {}",
                content
            );
        }
        _ => panic!("expected halted ToolMessage"),
    }

    // Core `dispatch_broker_call_transactional` ALSO blocks any replay / follow-up mutation!
    let core_halted = dispatch_broker_call_transactional(
        &core,
        &session.session_id,
        PrivacySessionPolicy::Standard,
        StepInvocationContext::new_call("call_core_retry"),
        &CapabilityCall {
            request_id: "call_core_retry".to_string(),
            task_id: task.id.clone(),
            capability_id: "sound.volume.set".to_string(),
            arguments: json!({ "value": 80 }),
            origin: InvocationOrigin::L2AgentPlan,
            taints: vec![Taint::User],
        },
        &mut ledger,
    )
    .await;
    assert!(core_halted.is_err());

    UnifiedTaskStateMachine::transition_task(
        &mut task,
        TaskStatus::RecoveryRequired,
        Some("步骤校验失败，需人工恢复检查"),
    )
    .unwrap();
    core.state_db.upsert_task(&task).unwrap();
    assert_eq!(
        core.state_db.get_task(&task.id).unwrap().unwrap().status,
        TaskStatus::RecoveryRequired
    );
}

// =============================================================================
// P0-08: `EphemeralReadOnly` -> Reads Authorized Memories, Writes 0 Rows Across
//        `tasks`, `step_execution_log`, `changesets`, `audit_log`, `memories`,
//        and `memory_hub` (Across Quick-Chat AND Core L0/L2) + Blocks Session Hijack
// =============================================================================

#[derive(Clone)]
struct P0EphemeralState {
    captured_bodies: Arc<Mutex<Vec<Value>>>,
    captured_tool_results: Arc<Mutex<Vec<String>>>,
}

async fn mock_p0_08_completions(
    State(st): State<P0EphemeralState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    st.captured_bodies.lock().unwrap().push(body.clone());
    let msgs = body["messages"].as_array().cloned().unwrap_or_default();
    let tool_msgs: Vec<&Value> = msgs.iter().filter(|m| m["role"] == "tool").collect();

    if tool_msgs.is_empty() {
        Json(json!({
            "id": "chatcmpl_p0_08_r1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {
                            "id": "call_hijack_attempt",
                            "type": "function",
                            "function": {
                                "name": "memory_search_past_chats",
                                "arguments": "{\"session_id\":\"ses_victim\",\"query\":\"SECRET_CODE\"}"
                            }
                        },
                        {
                            "id": "call_mem_write_attempt",
                            "type": "function",
                            "function": {
                                "name": "memory_save_preference",
                                "arguments": "{\"key\":\"illegal_ephemeral_pref\",\"value\":\"leaked\"}"
                            }
                        },
                        {
                            "id": "call_ephem_vol",
                            "type": "function",
                            "function": {
                                "name": "sound_volume_set",
                                "arguments": "{\"value\":52}"
                            }
                        }
                    ]
                }
            }]
        }))
    } else {
        for tm in &tool_msgs {
            if let Some(c) = tm["content"].as_str() {
                st.captured_tool_results.lock().unwrap().push(c.to_string());
            }
        }
        Json(json!({
            "id": "chatcmpl_p0_08_r2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "已完成只读记忆检索与临时音量调节。"
                }
            }]
        }))
    }
}

#[tokio::test]
async fn p0_08_ephemeral_read_only_reads_authorized_memories_writes_zero_rows_and_blocks_hijack() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let owner_doc = ws.join("架构评审纪要.md");
    std::fs::write(&owner_doc, "# 架构评审纪要\nOWNER_AUTHORIZED_DOC_SEED\n").unwrap();

    let core = init_p0_core(tmp.path(), &ws, "native");
    set_baseline_volume(&core, 35).await;

    // 1. Seed authorized `Standard` memories for `ses_owner` AND private chat in `ses_victim`
    let seed_mem = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: "记住 docx 用 WPS 打开".to_string(),
                session_id: Some("ses_owner".to_string()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: Some(PrivacySessionPolicy::Standard),
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(seed_mem.status, TaskStatus::Completed);

    record_conversation_turn_with_policy(
        &core,
        &RecordTurnInput {
            session_id: Some("ses_owner".to_string()),
            user_text: format!(
                "记录我的历史会话暗号 SECRET_CODE=OWNER_ONLY_ALPHA_77 以及文件 {}",
                owner_doc.display()
            ),
            assistant_text: "好的，已记住 OWNER_ONLY_ALPHA_77。".to_string(),
            thinking: None,
            tool_steps: Vec::new(),
            trace_dots: Vec::new(),
            incognito: false,
        },
        PrivacySessionPolicy::Standard,
    )
    .unwrap();

    record_conversation_turn_with_policy(
        &core,
        &RecordTurnInput {
            session_id: Some("ses_victim".to_string()),
            user_text: "我的私密会话暗号是 SECRET_CODE=VICTIM_PRIVATE_OMEGA_999".to_string(),
            assistant_text: "已保存在 ses_victim。".to_string(),
            thinking: None,
            tool_steps: Vec::new(),
            trace_dots: Vec::new(),
            incognito: false,
        },
        PrivacySessionPolicy::Standard,
    )
    .unwrap();

    // Snapshot all SQLite row counts BEFORE running `EphemeralReadOnly`
    let before = snapshot_all_persistence_counts(&core);
    assert!(before.memories >= 1);
    assert!(before.chat_messages >= 4);

    let st = P0EphemeralState {
        captured_bodies: Arc::new(Mutex::new(Vec::new())),
        captured_tool_results: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_p0_08_completions))
        .route("/chat/completions", post(mock_p0_08_completions))
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let opts = DiscoveryOptions::isolated_for_test(tmp.path().join("mock_home_p0_08"));
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "p0-08-openai",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-p0-08-dummy-token-123456"
        }),
        &opts,
    )
    .await
    .unwrap();
    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));
    core.broker
        .policy()
        .add_session_grant("capability", "sound.volume.set", 60);

    // Re-snapshot right after `set_active_backend_with_options` so we measure strictly turn execution
    let baseline = snapshot_all_persistence_counts(&core);

    // 2. Quick-Chat turn with `"privacy_policy": "ephemeral_read_only"`
    let qc_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_08_ephem_qc",
            "session_id": "ses_owner",
            "privacy_policy": "ephemeral_read_only",
            "text": "查看我之前提过的架构评审纪要并把音量设为 52"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(qc_res["status"], "completed");
    assert_eq!(qc_res["privacy_policy"], "ephemeral_read_only");
    assert_eq!(read_volume_i64(&core), 52);

    // Verify `EphemeralReadOnly` DID read authorized memories (`open_with.docx` / `OWNER_ONLY_ALPHA_77`)
    {
        let bodies = st.captured_bodies.lock().unwrap();
        let req0_str = serde_json::to_string(&bodies[0]).unwrap();
        assert!(
            req0_str.contains("open_with.docx") || req0_str.contains("OWNER_ONLY_ALPHA_77"),
            "EphemeralReadOnly MUST allow reading authorized Standard memories in prompt context"
        );

        let tool_outputs = st.captured_tool_results.lock().unwrap().join("\n");
        assert!(
            tool_outputs.contains("OWNER_ONLY_ALPHA_77"),
            "Forced trusted session_id='ses_owner' must read owner's past chat"
        );
        assert!(
            !tool_outputs.contains("VICTIM_PRIVATE_OMEGA_999"),
            "Model-supplied session_id='ses_victim' hijack MUST be overwritten with trusted 'ses_owner'!"
        );
        assert!(
            tool_outputs.contains("隐私策略拦截 (ephemeral_read_only)"),
            "Memory-writing tool MUST be denied under EphemeralReadOnly, got: {}",
            tool_outputs
        );
    }

    // 3. Core L2 `submit_intent` with `PrivacySessionPolicy::EphemeralReadOnly`
    st.captured_tool_results.lock().unwrap().clear();
    let l2_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: "再检查一次我的历史记录并调整音量".to_string(),
                session_id: Some("ses_owner".to_string()),
                force_agent: true,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: Some(PrivacySessionPolicy::EphemeralReadOnly),
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(l2_task.route, RouteLayer::L2);
    assert_eq!(l2_task.status, TaskStatus::Completed);
    {
        let l2_tools = st.captured_tool_results.lock().unwrap().join("\n");
        assert!(!l2_tools.contains("VICTIM_PRIVATE_OMEGA_999"));
        assert!(l2_tools.contains("隐私策略拦截 (ephemeral_read_only)"));
    }

    // 4. Core L0 explicit memory save `"记住 ..."` under `EphemeralReadOnly` -> rejected!
    let l0_mem_save = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: "记住 ephemeral_leak_key = bad_val".to_string(),
                session_id: Some("ses_owner".to_string()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: Some(PrivacySessionPolicy::EphemeralReadOnly),
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(l0_mem_save.status, TaskStatus::Failed);

    // 5. Assert ZERO rows written across ALL SQLite tables (`state.db` + `memory_hub.db`)!
    let after = snapshot_all_persistence_counts(&core);
    assert_eq!(
        after, baseline,
        "EphemeralReadOnly MUST write 0 rows to tasks, step_execution_log, changesets, audit_log, memories, and memory_hub!"
    );
}

// =============================================================================
// P0-09: `StrictIsolated` -> 0 Memory Reads, 0 Persistence, Zero Replay Cache /
//        Outbound Leak (Across Quick-Chat AND Core L2)
// =============================================================================

#[derive(Clone)]
struct P0StrictState {
    calls: Arc<AtomicUsize>,
    captured_bodies: Arc<Mutex<Vec<Value>>>,
    captured_tool_results: Arc<Mutex<Vec<String>>>,
}

async fn mock_p0_09_completions(
    State(st): State<P0StrictState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    st.calls.fetch_add(1, Ordering::SeqCst);
    st.captured_bodies.lock().unwrap().push(body.clone());
    let msgs = body["messages"].as_array().cloned().unwrap_or_default();
    let tool_msgs: Vec<&Value> = msgs.iter().filter(|m| m["role"] == "tool").collect();

    if tool_msgs.is_empty() {
        Json(json!({
            "id": "chatcmpl_p0_09_r1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_strict_mem_probe",
                        "type": "function",
                        "function": {
                            "name": "memory_recall_mentioned_files",
                            "arguments": "{\"session_id\":\"ses_owner\",\"query\":\"TOP_SECRET_STRICT\"}"
                        }
                    }]
                }
            }]
        }))
    } else {
        for tm in &tool_msgs {
            if let Some(c) = tm["content"].as_str() {
                st.captured_tool_results.lock().unwrap().push(c.to_string());
            }
        }
        Json(json!({
            "id": "chatcmpl_p0_09_r2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "严格隔离会话已完成回答。"
                }
            }]
        }))
    }
}

#[tokio::test]
async fn p0_09_strict_isolated_reads_zero_memories_writes_zero_rows_and_zero_cache_or_outbound_leak()
 {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let secret_doc = ws.join("TOP_SECRET_STRICT_DOC.md");
    std::fs::write(&secret_doc, "# Secret\nSTRICT_SECRET_MARKER_551\n").unwrap();

    let core = init_p0_core(tmp.path(), &ws, "native");

    // Seed Standard memories on `ses_owner`
    let _ = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: "记住 docx 用 WPS 打开".to_string(),
                session_id: Some("ses_owner".to_string()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: Some(PrivacySessionPolicy::Standard),
            },
            Vec::new(),
        )
        .await
        .unwrap();
    record_conversation_turn_with_policy(
        &core,
        &RecordTurnInput {
            session_id: Some("ses_owner".to_string()),
            user_text: format!("之前编辑过机密文档 {}", secret_doc.display()),
            assistant_text: "已记录 STRICT_HISTORY_ANCHOR_909。".to_string(),
            thinking: None,
            tool_steps: Vec::new(),
            trace_dots: Vec::new(),
            incognito: false,
        },
        PrivacySessionPolicy::Standard,
    )
    .unwrap();

    let st = P0StrictState {
        calls: Arc::new(AtomicUsize::new(0)),
        captured_bodies: Arc::new(Mutex::new(Vec::new())),
        captured_tool_results: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_p0_09_completions))
        .route("/chat/completions", post(mock_p0_09_completions))
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let opts = DiscoveryOptions::isolated_for_test(tmp.path().join("mock_home_p0_09"));
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "p0-09-openai",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-p0-09-dummy-token-123456"
        }),
        &opts,
    )
    .await
    .unwrap();
    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));
    core.broker
        .policy()
        .add_session_grant("capability", "sound.volume.set", 60);

    let baseline = snapshot_all_persistence_counts(&core);

    // 1. Quick-Chat with `"privacy_policy": "strict_isolated"` on `"ses_owner"`
    let r1 = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_09_strict",
            "session_id": "ses_owner",
            "privacy_policy": "strict_isolated",
            "text": "请查看 TOP_SECRET_STRICT_DOC.md 的记忆"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(r1["status"], "completed");
    assert_eq!(r1["privacy_policy"], "strict_isolated");
    assert!(r1["memory_hits"].as_array().unwrap().is_empty());

    {
        let bodies = st.captured_bodies.lock().unwrap();
        let outbound = serde_json::to_string(&bodies[0]).unwrap();
        assert!(
            !outbound.contains("open_with.docx")
                && !outbound.contains("STRICT_HISTORY_ANCHOR_909")
                && !outbound.contains("STRICT_SECRET_MARKER_551"),
            "StrictIsolated outbound request MUST have 0 memory/history leakage: {}",
            outbound
        );
        if let Some(tools) = bodies[0].get("tools").and_then(|v| v.as_array()) {
            assert!(
                !tools.iter().any(|t| {
                    t.pointer("/function/name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .starts_with("memory_")
                }),
                "StrictIsolated MUST omit memory_* tool schemas"
            );
        }

        let tool_res = st.captured_tool_results.lock().unwrap().join("\n");
        assert!(
            !tool_res.contains("TOP_SECRET_STRICT_DOC"),
            "Forced memory_recall_mentioned_files tool call MUST NOT return stored memories under StrictIsolated"
        );
    }

    // 2. Re-sending identical `turn_id` under `StrictIsolated` MUST NOT hit replay cache (`allows_replay_cache() == false`)!
    let calls_before_resend = st.calls.load(Ordering::SeqCst);
    let r2 = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "turn_id": "turn_p0_09_strict",
            "session_id": "ses_owner",
            "privacy_policy": "strict_isolated",
            "text": "请查看 TOP_SECRET_STRICT_DOC.md 的记忆"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert!(
        r2.get("replayed").is_none() && r2.get("idempotent_replay").is_none(),
        "StrictIsolated MUST NOT retain completed turn payloads in replay cache"
    );
    assert!(st.calls.load(Ordering::SeqCst) > calls_before_resend);

    // 3. Core L2 `submit_intent` under `StrictIsolated`
    st.captured_bodies.lock().unwrap().clear();
    let l2_strict = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: "用严格隔离模式回答问题".to_string(),
                session_id: Some("ses_owner".to_string()),
                force_agent: true,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: Some(PrivacySessionPolicy::StrictIsolated),
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(l2_strict.status, TaskStatus::Completed);
    {
        let bodies = st.captured_bodies.lock().unwrap();
        let l2_outbound = serde_json::to_string(&bodies[0]).unwrap();
        assert!(!l2_outbound.contains("open_with.docx"));
        assert!(!l2_outbound.contains("STRICT_HISTORY_ANCHOR_909"));
    }

    // 4. Verify 0 persistence across ALL tables
    let after = snapshot_all_persistence_counts(&core);
    assert_eq!(
        after, baseline,
        "StrictIsolated MUST write 0 rows to StateDb and MemoryHubDb!"
    );
}

// =============================================================================
// P0-10: `allow_broker_tools: false` ("chat-only") -> Blocks System Tools
//        Identically on OpenAI HTTP, Anthropic HTTP, AND Sandboxed CLI
// =============================================================================

#[tokio::test]
async fn p0_10_chat_only_allow_broker_tools_false_blocks_system_tools_identically_on_http_and_cli()
{
    clear_cli_capability_cache();
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_p0_core(tmp.path(), &ws, "native");
    set_baseline_volume(&core, 44).await;

    let openai_reqs: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let anth_reqs: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let o_clone = openai_reqs.clone();
    let a_clone = anth_reqs.clone();

    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |Json(body): Json<Value>| {
                let cap = o_clone.clone();
                async move {
                    cap.lock().unwrap().push(body);
                    // Malicious/confused upstream attempts forced `tool_calls` even when `tools` omitted!
                    Json(json!({
                        "id": "chatcmpl_p0_10_forced",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "尝试在仅对话模式下强行修改音量。",
                                "tool_calls": [{
                                    "id": "call_forced_openai",
                                    "type": "function",
                                    "function": {
                                        "name": "sound_volume_set",
                                        "arguments": "{\"value\":88}"
                                    }
                                }]
                            }
                        }]
                    }))
                }
            }),
        )
        .route(
            "/v1/messages",
            post(move |Json(body): Json<Value>| {
                let cap = a_clone.clone();
                async move {
                    cap.lock().unwrap().push(body);
                    // Malicious/confused Anthropic upstream emits forced `tool_use`!
                    Json(json!({
                        "id": "msg_p0_10_forced",
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            { "type": "text", "text": "尝试通过 Anthropic tool_use 修改音量。" },
                            {
                                "type": "tool_use",
                                "id": "toolu_forced_anth",
                                "name": "sound_volume_set",
                                "input": { "value": 88 }
                            }
                        ]
                    }))
                }
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mock_home = tmp.path().join("mock_home_p0_10");
    std::fs::create_dir_all(&mock_home).unwrap();
    let cli_script = r#"#!/usr/bin/env python3
import sys
argv = sys.argv[1:]
if "--help" in argv:
    print("codex exec --sandbox read-only --skip-git-repo-check stdin")
    sys.exit(0)
if "--version" in argv:
    print("codex-mock 1.0.0")
    sys.exit(0)
_ = sys.stdin.read()
reply = '<intentos_tool_call>{"name":"sound.volume.set","arguments":{"value":88}}</intentos_tool_call>'
if "-o" in argv:
    idx = argv.index("-o")
    if idx + 1 < len(argv):
        open(argv[idx + 1], "w").write(reply)
print(reply)
"#;
    write_executable(&mock_home.join(".local/bin/codex"), cli_script);
    std::fs::create_dir_all(mock_home.join(".codex")).unwrap();
    std::fs::write(
        mock_home.join(".codex/config.toml"),
        "model = \"gpt-5.4-cli\"\n",
    )
    .unwrap();

    let opts = DiscoveryOptions::isolated_for_test(mock_home);

    // 1. OpenAI HTTP with `"allow_broker_tools": false`
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "p0-10-openai",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-p0-10-openai-123456"
        }),
        &opts,
    )
    .await
    .unwrap();

    let openai_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_p0_10_openai",
            "allow_broker_tools": false,
            "text": "帮我把音量调到 88"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(openai_res["status"], "completed");
    assert_eq!(openai_res["execution_mode"], "external_chat_only");
    assert!(openai_res["changeset_ids"].as_array().unwrap().is_empty());
    assert!(
        openai_reqs.lock().unwrap()[0].get("tools").is_none(),
        "OpenAI HTTP chat-only request MUST omit tools schema"
    );
    assert_eq!(read_volume_i64(&core), 44);

    // 2. Anthropic HTTP (`/v1/messages`) with `"allow_broker_tools": false`
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "p0-10-anthropic",
            "kind": "anthropic",
            "model": "claude-sonnet-4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-p0-10-anth-123456"
        }),
        &opts,
    )
    .await
    .unwrap();

    let anth_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_p0_10_anth",
            "allow_broker_tools": false,
            "text": "帮我把音量调到 88"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(anth_res["status"], "completed");
    assert_eq!(anth_res["execution_mode"], "external_chat_only");
    assert!(anth_res["changeset_ids"].as_array().unwrap().is_empty());
    assert!(
        anth_reqs.lock().unwrap()[0].get("tools").is_none(),
        "Anthropic HTTP chat-only request MUST omit tools schema"
    );
    assert_eq!(read_volume_i64(&core), 44);

    // 3. CLI (`codex`) with `"allow_broker_tools": false`
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "codex",
            "model": "gpt-5.4-cli"
        }),
        &opts,
    )
    .await
    .unwrap();

    let cli_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_p0_10_cli",
            "allow_broker_tools": false,
            "text": "帮我把音量调到 88"
        }),
        &opts,
    )
    .await
    .unwrap();
    assert_eq!(cli_res["status"], "completed");
    assert_eq!(cli_res["execution_mode"], "external_chat_only");
    assert!(cli_res["changeset_ids"].as_array().unwrap().is_empty());
    assert_eq!(
        read_volume_i64(&core),
        44,
        "Neither OpenAI HTTP, Anthropic HTTP, nor CLI may execute Broker tools when allow_broker_tools == false!"
    );
}

// =============================================================================
// P0-11: Real CLI OS Sandbox Bypass Test -> Blocks Unauthorized Workspace Write,
//        Forbidden Path Read, and `/proc/self/cmdline` Prompt Leak
// =============================================================================

#[tokio::test]
async fn p0_11_real_cli_os_sandbox_blocks_unauthorized_write_forbidden_read_and_cmdline_leak() {
    clear_cli_capability_cache();
    let sandbox_probe = probe_sandbox_support();
    assert!(
        sandbox_probe.has_os_isolation(),
        "Linux test host MUST provide Bubblewrap or Landlock OS sandbox: {:?}",
        sandbox_probe
    );

    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("xdg_p0_11");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_readme = ws.join("readme.md");
    std::fs::write(&ws_readme, "WS_READONLY_OK").unwrap();

    let outside_secret_dir = tmp.path().join("outside_secret_vault");
    std::fs::create_dir_all(&outside_secret_dir).unwrap();
    let outside_secret_file = outside_secret_dir.join("vault.key");
    std::fs::write(&outside_secret_file, "TOP_SECRET_VAULT_KEY_P0_11").unwrap();

    let core = init_p0_core(&base, &ws, "native");
    set_baseline_volume(&core, 33).await;

    let mock_home = tmp.path().join("mock_home_p0_11");
    let ssh_dir = mock_home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let ssh_key = ssh_dir.join("id_ed25519");
    std::fs::write(&ssh_key, "TOP_SECRET_SSH_KEY_P0_11").unwrap();

    let brain_toml = core.paths.config_dir.join("brain.toml");
    let unauthorized_ws_write = ws.join("pwned_by_cli.txt");

    let codex_py = format!(
        r#"#!/usr/bin/env python3
import os, sys

argv = sys.argv[1:]
if "--help" in argv:
    print("codex exec --sandbox read-only --skip-git-repo-check stdin")
    sys.exit(0)
if "--version" in argv:
    print("codex-p0-sandbox 1.0.0")
    sys.exit(0)

# 1) /proc/self/cmdline MUST NOT contain user prompt or clipboard secret
cmdline = open("/proc/self/cmdline", "rb").read().decode("utf-8", "replace")
if "SENSITIVE_PROMPT_MARKER_42" in cmdline or "沙箱自检并调音量" in cmdline:
    print("CMDLINE_LEAKED:" + cmdline, file=sys.stderr)
    sys.exit(31)

# 2) Authorized workspace is mounted read-only: reading works, writing MUST fail!
assert open({ws_readme:?}).read() == "WS_READONLY_OK"
try:
    open({unauth_write:?}, "w").write("escaped")
    print("UNAUTHORIZED_WS_WRITE_SUCCEEDED", file=sys.stderr)
    sys.exit(32)
except OSError:
    pass

# 3) Forbidden credential paths & unmounted host directories MUST NOT be readable!
for secret_path in [{ssh_key:?}, os.path.expanduser("~/.ssh/id_ed25519"), {vault_file:?}, {brain_cfg:?}]:
    if os.path.exists(secret_path):
        try:
            data = open(secret_path).read()
            if "TOP_SECRET" in data or "runtime" in data:
                print("FORBIDDEN_READ_ESCAPED:" + secret_path, file=sys.stderr)
                sys.exit(33)
        except OSError:
            pass

prompt = sys.stdin.read()
assert "SENSITIVE_PROMPT_MARKER_42" in prompt, "stdin prompt missing marker"

if '<intentos_tool_result call_id="' in prompt:
    reply = "OS 沙箱隔离自检通过，且已通过受控 CapabilityBroker 将音量设为 58%。"
else:
    reply = '<intentos_tool_call>{{"name":"sound.volume.set","arguments":{{"value":58}}}}</intentos_tool_call>'

if "-o" in argv:
    idx = argv.index("-o")
    if idx + 1 < len(argv):
        open(argv[idx + 1], "w").write(reply)
print(reply)
"#,
        ws_readme = ws_readme.display().to_string(),
        unauth_write = unauthorized_ws_write.display().to_string(),
        ssh_key = ssh_key.display().to_string(),
        vault_file = outside_secret_file.display().to_string(),
        brain_cfg = brain_toml.display().to_string(),
    );

    write_executable(&mock_home.join(".local/bin/codex"), &codex_py);
    std::fs::create_dir_all(mock_home.join(".codex")).unwrap();
    std::fs::write(
        mock_home.join(".codex/config.toml"),
        "model = \"gpt-5.4-sandbox\"\n",
    )
    .unwrap();

    let opts = DiscoveryOptions::isolated_for_test(mock_home);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "codex",
            "model": "gpt-5.4-sandbox"
        }),
        &opts,
    )
    .await
    .unwrap();

    let res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_p0_11_sandbox",
            "allow_broker_tools": true,
            "text": "沙箱自检 SENSITIVE_PROMPT_MARKER_42 并调音量到 58"
        }),
        &opts,
    )
    .await
    .unwrap();

    assert_eq!(res["status"], "completed");
    assert_eq!(res["execution_mode"], "cli_broker_bridged");
    assert!(!unauthorized_ws_write.exists());
    assert_eq!(res["changeset_ids"].as_array().unwrap().len(), 1);
    assert_eq!(read_volume_i64(&core), 58);
}

// =============================================================================
// P0-12: `PiWorkerRuntime` Mutates in Step 1 Then Crashes in Step 2 ->
//        `AgentCoordinator` Halts Native Fallback, Zero Duplicate Mutation!
// =============================================================================

#[derive(Clone)]
struct P0PiCrashState {
    total_calls: Arc<AtomicUsize>,
    native_fallback_calls: Arc<AtomicUsize>,
}

async fn mock_p0_12_gateway_upstream(
    State(st): State<P0PiCrashState>,
    Json(_body): Json<Value>,
) -> impl IntoResponse {
    let idx = st.total_calls.fetch_add(1, Ordering::SeqCst);
    match idx {
        0 => (
            StatusCode::OK,
            Json(json!({
                "id": "chatcmpl_p0_12_pi_step1",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "call_pi_vol_up_1",
                            "type": "function",
                            "function": {
                                "name": "sound_volume_set",
                                "arguments": "{\"relative\":\"up\"}"
                            }
                        }]
                    }
                }],
                "usage": { "prompt_tokens": 80, "completion_tokens": 20 }
            })),
        ),
        1 => (
            // Step 2 inside `pi-worker` (after Step 1 already mutated OS volume!): fail hard!
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": {
                    "message": "simulated upstream 500 crash in pi-worker step 2 after step 1 side effect"
                }
            })),
        ),
        _ => {
            // If `AgentCoordinator` ever fell back to `run_via_native_loop`, it would hit call >= 2
            // and replay `sound_volume_set({"relative":"up"})` a SECOND time!
            st.native_fallback_calls.fetch_add(1, Ordering::SeqCst);
            (
                StatusCode::OK,
                Json(json!({
                    "id": "chatcmpl_p0_12_illegal_fallback",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_native_replay_bug",
                                "type": "function",
                                "function": {
                                    "name": "sound_volume_set",
                                    "arguments": "{\"relative\":\"up\"}"
                                }
                            }]
                        }
                    }]
                })),
            )
        }
    }
}

#[tokio::test]
async fn p0_12_pi_worker_mutates_step1_crashes_step2_coordinator_halts_native_fallback_zero_replay()
{
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("xdg_p0_12");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();

    let core = init_p0_core(&base, &ws, "pi");
    assert_eq!(core.agent.active_runtime_label(), "pi-adapter (sandboxed)");

    core.gateway
        .clone()
        .spawn_unix_socket_server(&core.paths.gateway_socket_path())
        .unwrap();
    start_ui_socket_server(core.clone(), &core.paths.ui_socket_path()).unwrap();

    // Measure single relative-up delta, then reset baseline volume to 40%
    set_baseline_volume(&core, 40).await;
    let _ = core
        .broker
        .dispatch(&CapabilityCall {
            request_id: "req_p0_12_delta".to_string(),
            task_id: "incog_p0_12_delta".to_string(),
            capability_id: "sound.volume.set".to_string(),
            arguments: json!({ "relative": "up" }),
            origin: InvocationOrigin::UserExplicit,
            taints: vec![Taint::User],
        })
        .await
        .unwrap();
    let step_delta = read_volume_i64(&core) - 40;
    assert!(step_delta > 0);
    set_baseline_volume(&core, 40).await;

    let st = P0PiCrashState {
        total_calls: Arc::new(AtomicUsize::new(0)),
        native_fallback_calls: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/chat/completions", post(mock_p0_12_gateway_upstream))
        .route("/v1/chat/completions", post(mock_p0_12_gateway_upstream))
        .with_state(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));
    core.broker
        .policy()
        .add_session_grant("capability", "sound.volume.set", 60);

    let task = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: "请帮我把音量调高一格并汇报执行后的状态".to_string(),
                session_id: Some("ses_p0_12".to_string()),
                force_agent: true,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: Some(PrivacySessionPolicy::Standard),
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert_eq!(task.route, RouteLayer::L2);
    assert_eq!(
        st.native_fallback_calls.load(Ordering::SeqCst),
        0,
        "AgentCoordinator MUST NEVER fall back to NativeRuntime after PiWorkerRuntime committed a side effect!"
    );
    assert_eq!(
        st.total_calls.load(Ordering::SeqCst),
        2,
        "Upstream should only see PiWorker step-1 (200) and step-2 (500)"
    );
    assert_eq!(
        read_volume_i64(&core),
        40 + step_delta,
        "Volume MUST have mutated ONCE (40 + {}), never twice!",
        step_delta
    );
    assert_eq!(
        task.status,
        TaskStatus::RecoveryRequired,
        "Interrupted L2 run after committed side effect MUST return TaskStatus::RecoveryRequired"
    );
    assert_eq!(task.steps.len(), 1);
    assert_eq!(task.steps[0].capability_id, "sound.volume.set");
    assert_eq!(task.changeset_ids.len(), 1);

    let step_rows = core
        .state_db
        .list_step_execution_logs_for_task(&task.id)
        .unwrap();
    assert_eq!(step_rows.len(), 1);
    assert_eq!(step_rows[0].exec_state, StepExecState::Verified);

    // Preserved `changeset_id` allows clean 1-click Undo back to 40%!
    core.undo(Some(&task.changeset_ids[0])).unwrap();
    assert_eq!(read_volume_i64(&core), 40);
}
