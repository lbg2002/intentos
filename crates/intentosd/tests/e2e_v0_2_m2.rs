#![forbid(unsafe_code)]

//! Comprehensive End-to-End Integration & Synthesis Test Suite for Milestone 2 (`v0.2-M2`, `e2e_v0_2_m2.rs`):
//! 1) `m2_test1_dynamic_meta_tools_mid_turn_discovery_and_50pct_schema_token_reduction`
//! 2) `m2_test2_world_state_and_resource_resolver_wayland_honesty_and_comparative_resolution`
//! 3) `m2_test3_controlled_terminal_c0_c4_sandbox_and_anti_bypass`
//! 4) `m2_test4_six_real_diagnostic_and_software_provider_scenarios`
//! 5) `m2_test5_open_ended_research_workspace_synthesis_goal` (§7 line 335 open-ended synthesis goal)

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use intentos_protocol::{
    CapabilityCall, Effect, ExecutionStatus, IntentRequest, InvocationOrigin, PROTOCOL_VERSION,
    RouteLayer, TaskStatus, UiRpcRequest, VerificationReport, VerificationState,
};
use intentos_sandbox::probe_sandbox_support;
use intentosd::app_adapter::{
    ChannelCandidate, ExecutionChannel, ProviderExecutionOutcome, build_minimal_docx_bytes,
    build_minimal_pdf_bytes, execute_channel_chain,
};
use intentosd::backend_bridge::broker_bridge::build_quick_chat_openai_tools;
use intentosd::backend_bridge::{
    DiscoveryOptions, send_quick_chat_turn_with_options, set_active_backend_with_options,
};
use intentosd::broker::BrokerDispatchOutcome;
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use intentosd::execution_hub::project_memory::discover_and_list_projects;
use intentosd::runtime::SessionState;
use intentosd::security_guard::PrivacySessionPolicy;
use intentosd::terminal_agent::{
    CommandProposal, TERMINAL_EXECUTE_CAPABILITY_ID, TerminalSafetyTier, classify_command_proposal,
};
use intentosd::world_state::{
    DesktopWindowInfo, ResourceKind, ResourceResolution, ResourceResolver, RunningAppBrief,
    StateField,
};
use serde_json::{Value, json};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

const BASELINE_CF9E649_QUICK_CHAT_OPENAI_BYTES: usize = 15_672;
const BASELINE_CF9E649_QUICK_CHAT_DIV4_TOKENS: usize = 3_918;
const BASELINE_CF9E649_CORE_L2_OPENAI_BYTES: usize = 38_351;
const BASELINE_CF9E649_CORE_L2_DIV4_TOKENS: usize = 9_588;

fn repo_root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn init_m2_core(base: &Path, auth_dirs: &[PathBuf], runtime: &str) -> Arc<IntentOsCore> {
    let repo_root = repo_root_dir();
    let xdg = XdgPaths::resolve(Some(base), repo_root.clone());
    xdg.ensure_dirs().unwrap();
    let cfg = AppConfig {
        authorized_directories: auth_dirs
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
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
    IntentOsCore::initialize(Some(base), repo_root).expect("init m2 test core")
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

fn tool_names_in_request(req: &Value) -> Vec<String> {
    req.get("tools")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    t.pointer("/function/name")
                        .or_else(|| t.get("name"))
                        .and_then(Value::as_str)
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn outcome_label(out: &BrokerDispatchOutcome) -> String {
    match out {
        BrokerDispatchOutcome::Executed(r) => {
            format!(
                "Executed({}, {:?}: {})",
                r.capability_id, r.status, r.message
            )
        }
        BrokerDispatchOutcome::RequiresApproval(pa) => {
            format!(
                "RequiresApproval({}, reversible={})",
                pa.capability_id, pa.reversible
            )
        }
        BrokerDispatchOutcome::Denied { reason } => format!("Denied({})", reason),
    }
}

// =============================================================================
// Test 1: Dynamic Meta-Tools Mid-Turn Discovery + >= 50% Initial Schema Token
//         Reduction vs `cf9e649` (`15,672 B` Quick-Chat & `38,351 B` Core L2)
// =============================================================================

#[derive(Clone)]
struct M2Test1DiscoveryState {
    calls: Arc<AtomicUsize>,
    captured_requests: Arc<Mutex<Vec<Value>>>,
    papers_dir: PathBuf,
    bib_out: PathBuf,
}

async fn mock_m2_test1_completions(
    State(state): State<M2Test1DiscoveryState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.captured_requests.lock().unwrap().push(body.clone());
    let round = state.calls.fetch_add(1, Ordering::SeqCst);

    match round {
        0 => Json(json!({
            "id": "chatcmpl_m2_t1_r0",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>先检索工作区文件，并通过 capability_search 动态发现文献综述工具</think>",
                    "tool_calls": [
                        {
                            "id": "call_t1_fsearch",
                            "type": "function",
                            "function": {
                                "name": "file_search",
                                "arguments": json!({ "query": "paper" }).to_string()
                            }
                        },
                        {
                            "id": "call_t1_csearch",
                            "type": "function",
                            "function": {
                                "name": "capability_search",
                                "arguments": json!({ "query": "bibliography 文献综述" }).to_string()
                            }
                        }
                    ]
                }
            }]
        })),
        1 => Json(json!({
            "id": "chatcmpl_m2_t1_r1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>查看 document.compile_bibliography 的完整参数 Schema 与可撤销语义</think>",
                    "tool_calls": [
                        {
                            "id": "call_t1_cdesc",
                            "type": "function",
                            "function": {
                                "name": "capability_describe",
                                "arguments": json!({
                                    "capability_ids": ["document.compile_bibliography"]
                                }).to_string()
                            }
                        }
                    ]
                }
            }]
        })),
        2 => Json(json!({
            "id": "chatcmpl_m2_t1_r2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>通过 capability_invoke 经由 CapabilityBroker 生成结构化文献综述 Markdown</think>",
                    "tool_calls": [{
                        "id": "call_t1_cinvoke",
                        "type": "function",
                        "function": {
                            "name": "capability_invoke",
                            "arguments": json!({
                                "capability_id": "document.compile_bibliography",
                                "arguments": {
                                    "directory": state.papers_dir.to_string_lossy(),
                                    "output_path": state.bib_out.to_string_lossy()
                                }
                            }).to_string()
                        }
                    }]
                }
            }]
        })),
        3 => Json(json!({
            "id": "chatcmpl_m2_t1_r3",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>调用 task_verify 校验落盘产物与 TurnEffectLedger</think>",
                    "tool_calls": [{
                        "id": "call_t1_verify",
                        "type": "function",
                        "function": {
                            "name": "task_verify",
                            "arguments": json!({
                                "goal": "从论文目录生成已验证的文献综述 Markdown 清单",
                                "expected_files": [state.bib_out.to_string_lossy()],
                                "check_ledger": true
                            }).to_string()
                        }
                    }]
                }
            }]
        })),
        _ => Json(json!({
            "id": "chatcmpl_m2_t1_r4",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "已完成工作区检索、中段动态能力解锁、文献综述清单编译及宿主机落盘校验。"
                }
            }]
        })),
    }
}

#[tokio::test]
async fn m2_test1_dynamic_meta_tools_mid_turn_discovery_and_50pct_schema_token_reduction() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    let papers_dir = ws.join("papers");
    std::fs::create_dir_all(&papers_dir).unwrap();

    // Create real multi-format papers inside `papers/`
    std::fs::write(
        papers_dir.join("paper_alpha_2025.md"),
        "# Progressive Capability Discovery in Local OS Shells\nAuthors: Alice Chen, Bob Wu\nPublished: 2025\n\n## Abstract\nProgressive tool exposure cuts initial prompt schema overhead by more than half.\n",
    )
    .unwrap();
    let docx_bytes = build_minimal_docx_bytes(
        Some("Sandboxed Execution Spines for Desktop Agents"),
        &[(
            "1 Introduction",
            1,
            &[
                "Authors: Clara Lin, David Zhao (2026)",
                "Every capability call traverses a transactional policy broker with atomic Undo.",
            ],
        )],
    );
    std::fs::write(papers_dir.join("paper_beta_2026.docx"), docx_bytes).unwrap();

    let core = init_m2_core(tmp.path(), std::slice::from_ref(&ws), "native");
    let _ = core.resources.index_authorized_files();

    // 1. Verify >= 50% initial tool Schema JSON byte & token reduction vs `cf9e649` baseline
    let qc_tools = build_quick_chat_openai_tools(&core, "帮我查找文档里的周报并把音量调到30%");
    let qc_json = serde_json::to_string(&qc_tools).unwrap();
    let qc_bytes = qc_json.len();
    let qc_div4_tokens = qc_bytes.div_ceil(4);
    assert!(
        qc_bytes * 2 <= BASELINE_CF9E649_QUICK_CHAT_OPENAI_BYTES,
        "Quick-Chat Round-0 schema bytes ({} B) MUST drop >= 50% vs cf9e649 ({} B)",
        qc_bytes,
        BASELINE_CF9E649_QUICK_CHAT_OPENAI_BYTES
    );
    assert!(
        qc_div4_tokens * 2 <= BASELINE_CF9E649_QUICK_CHAT_DIV4_TOKENS,
        "Quick-Chat Round-0 B/4 tokens ({}) MUST drop >= 50% vs cf9e649 ({})",
        qc_div4_tokens,
        BASELINE_CF9E649_QUICK_CHAT_DIV4_TOKENS
    );

    let l2_specs = core.agent.build_initial_l2_tools(
        "帮我查找文档里的周报并把音量调到30%",
        PrivacySessionPolicy::Standard,
    );
    let l2_openai: Vec<Value> = l2_specs
        .iter()
        .map(|t| {
            json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                }
            })
        })
        .collect();
    let l2_bytes = serde_json::to_string(&l2_openai).unwrap().len();
    let l2_div4_tokens = l2_bytes.div_ceil(4);
    assert!(
        l2_bytes * 2 <= BASELINE_CF9E649_CORE_L2_OPENAI_BYTES,
        "Core L2 Round-0 schema bytes ({} B) MUST drop >= 50% vs cf9e649 ({} B)",
        l2_bytes,
        BASELINE_CF9E649_CORE_L2_OPENAI_BYTES
    );
    assert!(
        l2_div4_tokens * 2 <= BASELINE_CF9E649_CORE_L2_DIV4_TOKENS,
        "Core L2 Round-0 B/4 tokens ({}) MUST drop >= 50% vs cf9e649 ({})",
        l2_div4_tokens,
        BASELINE_CF9E649_CORE_L2_DIV4_TOKENS
    );

    // 2. Run multi-round task starting with file search (no bibliography hint in prompt!)
    let bib_out = ws.join("compiled_bibliography.md");
    let state = M2Test1DiscoveryState {
        calls: Arc::new(AtomicUsize::new(0)),
        captured_requests: Arc::new(Mutex::new(Vec::new())),
        papers_dir: papers_dir.clone(),
        bib_out: bib_out.clone(),
    };
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_m2_test1_completions))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mock_home = tmp.path().join("mock_home_t1");
    std::fs::create_dir_all(&mock_home).unwrap();
    let opts = DiscoveryOptions::isolated_for_test(mock_home);

    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "m2-t1-provider",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", addr),
            "api_key": "sk-m2-t1-test-key-1234567890"
        }),
        &opts,
    )
    .await
    .unwrap();

    let res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_m2_t1",
            "text": "先查一下工作区有哪些文件，如果发现论文目录就帮我整理生成一份结构化文献清单",
        }),
        &opts,
    )
    .await
    .unwrap();

    assert_eq!(res["status"], "completed");
    assert_eq!(res["task_status"], "succeeded");
    assert_eq!(res["budget_usage"]["used_model_rounds"], 5);

    // Verify Round-0 did NOT pre-load `document_compile_bibliography`, while Round-1 dynamically unlocked it!
    {
        let reqs = state.captured_requests.lock().unwrap();
        assert_eq!(reqs.len(), 5);
        let r0_tools = tool_names_in_request(&reqs[0]);
        assert!(r0_tools.contains(&"capability_search".to_string()));
        assert!(r0_tools.contains(&"capability_describe".to_string()));
        assert!(r0_tools.contains(&"capability_invoke".to_string()));
        assert!(r0_tools.contains(&"task_verify".to_string()));
        assert!(
            !r0_tools.contains(&"document_compile_bibliography".to_string()),
            "document_compile_bibliography must NOT be pre-loaded in Round-0 tools: {:?}",
            r0_tools
        );

        let r1_tools = tool_names_in_request(&reqs[1]);
        assert!(
            r1_tools.contains(&"document_compile_bibliography".to_string()),
            "document_compile_bibliography MUST be dynamically unlocked in Round-1 after capability_search: {:?}",
            r1_tools
        );

        // Verify `task_verify` returned `verified: true` in Round-4 messages
        let r4_msgs = reqs[4]["messages"].to_string();
        assert!(
            r4_msgs.contains("\\\"verified\\\":true") && r4_msgs.contains("task.verify 校验通过"),
            "task_verify must report verified == true: {}",
            r4_msgs
        );
    }

    // Verify anti-recursion: `capability.invoke` -> `capability.invoke` (or any meta-tool) is hard-denied!
    let recursive_unwrap = intentosd::meta_tools::unwrap_capability_invoke(
        &core,
        "capability.invoke",
        &json!({
            "capability_id": "capability.invoke",
            "arguments": { "capability_id": "file.recent", "arguments": {} }
        }),
    );
    assert!(
        matches!(
            recursive_unwrap,
            intentosd::meta_tools::UnwrappedInvokeTarget::Denied { ref reason }
                if reason.contains("严禁通过 capability.invoke 递归或间接调用元工具")
        ),
        "Recursive capability.invoke MUST be hard-denied: {:?}",
        recursive_unwrap
    );

    // Verify real Markdown bibliography file on disk + ChangeSet Undo
    assert!(
        bib_out.is_file(),
        "bibliography output file must exist on disk"
    );
    let bib_md = std::fs::read_to_string(&bib_out).unwrap();
    assert!(bib_md.contains("Progressive Capability Discovery"));
    assert!(bib_md.contains("Sandboxed Execution Spines"));

    let cs_ids = res["changeset_ids"].as_array().unwrap();
    assert_eq!(
        cs_ids.len(),
        1,
        "capability.invoke -> document.compile_bibliography must record ChangeSet in TurnEffectLedger"
    );
    let cs_id = cs_ids[0].as_str().unwrap();
    core.undo(Some(cs_id)).unwrap();
    assert!(
        !bib_out.exists(),
        "Undo must atomically remove newly created bibliography output"
    );
}

// =============================================================================
// Test 2: WorldState & ResourceResolver — Wayland Honesty (`"把它关掉"`),
//         Comparative Dual-Resource Resolution (`"比较昨天与前天的实验结果"`),
//         and `StrictIsolated` Zero-Leak
// =============================================================================

#[tokio::test]
async fn m2_test2_world_state_and_resource_resolver_wayland_honesty_and_comparative_resolution() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    let exp_dir = ws.join("experiments");
    std::fs::create_dir_all(&exp_dir).unwrap();

    let fixed_now = Utc.with_ymd_and_hms(2026, 11, 15, 10, 0, 0).unwrap();
    let yesterday_file = exp_dir.join("exp_2026-11-14_metrics.json");
    let day_before_file = exp_dir.join("exp_2026-11-13_metrics.json");
    std::fs::write(
        &yesterday_file,
        r#"{"date":"2026-11-14","accuracy":0.992,"p95_ms":19.4}"#,
    )
    .unwrap();
    std::fs::write(
        &day_before_file,
        r#"{"date":"2026-11-13","accuracy":0.975,"p95_ms":28.1}"#,
    )
    .unwrap();

    // Seed a private project directory inside `ws` and scan it into `project_memory`
    let secret_proj_dir = ws.join("secret_quantum_compiler");
    std::fs::create_dir_all(&secret_proj_dir).unwrap();
    std::fs::write(
        secret_proj_dir.join("Cargo.toml"),
        "[package]\nname = \"secret_quantum_compiler\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    let core = init_m2_core(tmp.path(), std::slice::from_ref(&ws), "native");
    let _ = core.resources.index_authorized_files();
    let discovered = discover_and_list_projects(&core, true).unwrap();
    assert!(
        discovered
            .iter()
            .any(|p| p.name.contains("secret_quantum_compiler")),
        "Standard project discovery must index secret_quantum_compiler"
    );

    // 1. Wayland Focus Honesty: without verified focus hint and zero running user apps -> Unavailable (`wayland_compositor_isolated`)
    core.world_state
        .set_session_type_override(Some("wayland".to_string()));
    core.world_state.clear_desktop_focus_hint();
    core.world_state.set_running_apps_override(Some(Vec::new()));

    let snap_isolated = core.world_state.snapshot_at(
        fixed_now,
        Some(&core),
        Some(&core.resources),
        None,
        PrivacySessionPolicy::Standard,
    );
    assert_eq!(snap_isolated.desktop.session_type, "wayland");
    assert_eq!(
        snap_isolated.desktop.active_window,
        StateField::Unavailable {
            reason: "wayland_compositor_isolated".to_string()
        },
        "Wayland without GNOME extension focus hint MUST report wayland_compositor_isolated, never fake window!"
    );

    let resolver = ResourceResolver::new(&core, &core.world_state);
    let close_unavail = resolver.resolve_at(
        fixed_now,
        "把它关掉",
        None,
        None,
        PrivacySessionPolicy::Standard,
    );
    assert!(
        matches!(
            &close_unavail,
            ResourceResolution::Unavailable { reason, .. } if reason.contains("wayland")
        ),
        "Expected Unavailable with wayland reason on '把它关掉' without focus/running apps, got: {:?}",
        close_unavail
    );

    // Also verify Trusted UI RPC `"world_state"` exposes honest Wayland unavailable status
    let rpc_ws = core
        .handle_trusted_ui_rpc(
            "req_ws_1".into(),
            UiRpcRequest::ModuleRpc {
                domain: "world_state".into(),
                action: "snapshot".into(),
                payload: json!({}),
            },
        )
        .await;
    let rpc_json = serde_json::to_value(&rpc_ws).unwrap();
    let rpc_blob = rpc_json.to_string();
    assert!(
        rpc_blob.contains("wayland_compositor_isolated"),
        "world_state RPC must expose wayland_compositor_isolated: {}",
        rpc_blob
    );

    // 2. Multiple running apps on Wayland without focus hint -> Ambiguous with clarification prompt (never guessing!)
    core.world_state.set_running_apps_override(Some(vec![
        RunningAppBrief {
            app_id: "org.mozilla.firefox.desktop".into(),
            display_name: "Firefox 浏览器".into(),
            binary_name: "firefox".into(),
            pids: vec![41001],
            desktop_source: None,
        },
        RunningAppBrief {
            app_id: "org.gnome.Evince.desktop".into(),
            display_name: "Evince 文档查看器".into(),
            binary_name: "evince".into(),
            pids: vec![41002],
            desktop_source: None,
        },
    ]));
    let close_ambig = resolver.resolve_at(
        fixed_now,
        "把它关掉",
        None,
        None,
        PrivacySessionPolicy::Standard,
    );
    match &close_ambig {
        ResourceResolution::Ambiguous {
            candidates,
            clarification_prompt,
            ..
        } => {
            assert_eq!(candidates.len(), 2);
            assert!(!clarification_prompt.trim().is_empty());
        }
        other => panic!(
            "Expected Ambiguous clarification when 2 apps run on Wayland without focus, got: {:?}",
            other
        ),
    }

    // 3. Fresh verified GNOME Shell focus hint (`<= 15s` TTL) resolves exact target; `> 15s` expires cleanly!
    core.world_state.update_desktop_focus_hint_at(
        DesktopWindowInfo {
            window_id: Some("win_evince_1".into()),
            app_id: Some("org.gnome.Evince.desktop".into()),
            wm_class: Some("evince".into()),
            title: "Thesis_Draft.pdf — Evince".into(),
            pid: Some(41002),
        },
        "gnome_shell_extension",
        fixed_now,
    );
    let close_fresh = resolver.resolve_at(
        fixed_now + ChronoDuration::seconds(5),
        "把它关掉",
        None,
        None,
        PrivacySessionPolicy::Standard,
    );
    let single_win = close_fresh
        .as_single()
        .expect("fresh verified focus hint within 15s TTL must resolve Single");
    assert_eq!(single_win.kind, ResourceKind::DesktopWindow);
    assert!(
        single_win.uri.contains("win_evince_1")
            || single_win.display_name.to_lowercase().contains("evince")
    );

    let close_expired = resolver.resolve_at(
        fixed_now + ChronoDuration::seconds(20),
        "把它关掉",
        None,
        None,
        PrivacySessionPolicy::Standard,
    );
    assert!(
        close_expired.is_ambiguous(),
        "Focus hint older than 15s TTL MUST expire and fall back to Ambiguous (not stale guess), got: {:?}",
        close_expired
    );

    // 4. Comparative dual-resource resolution: `"比较昨天与前天的实验结果"`
    let comp_res = resolver.resolve_at(
        fixed_now,
        "比较昨天与前天的实验结果",
        None,
        None,
        PrivacySessionPolicy::Standard,
    );
    let pair = comp_res
        .comparative_refs()
        .expect("comparative query must return MultipleComparative");
    assert_eq!(
        pair.len(),
        2,
        "must resolve both yesterday and day-before files"
    );
    assert_eq!(pair[0].path.as_deref(), Some(yesterday_file.as_path()));
    assert_eq!(pair[1].path.as_deref(), Some(day_before_file.as_path()));
    assert_eq!(pair[0].metadata["comparison_role"], "newer");
    assert_eq!(pair[1].metadata["comparison_role"], "older");

    // 5. `StrictIsolated` privacy enforcement: zero project/memory leak & zero SQLite writes
    let incog_session = SessionState {
        session_id: "incog_m2_t2".to_string(),
        messages: Vec::new(),
        last_resource_path: Some(yesterday_file.to_string_lossy().to_string()),
        updated_at: fixed_now,
    };
    let snap_strict = core.world_state.snapshot_at(
        fixed_now,
        Some(&core),
        Some(&core.resources),
        Some(&incog_session),
        PrivacySessionPolicy::StrictIsolated,
    );
    assert!(
        snap_strict.active_project.is_none(),
        "StrictIsolated WorldState MUST NOT leak persisted active_project!"
    );

    let strict_proj_lookup = resolver.resolve_at(
        fixed_now,
        "secret_quantum_compiler",
        Some(ResourceKind::Project),
        Some(&incog_session),
        PrivacySessionPolicy::StrictIsolated,
    );
    assert!(
        strict_proj_lookup.is_not_found(),
        "StrictIsolated ResourceResolver MUST NOT read project_memory: {:?}",
        strict_proj_lookup
    );

    // Dispatch `resource.resolve` meta-tool in StrictIsolated task and verify `memory_isolated == true`
    let meta_call = CapabilityCall {
        request_id: "req_m2_t2_strict".into(),
        task_id: "incog_task_m2_t2".into(),
        capability_id: "resource.resolve".into(),
        arguments: json!({
            "query": "比较昨天与前天的实验结果",
            "session_id": "incog_m2_t2",
            "incognito": true,
            "privacy_policy": "strict_isolated"
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let meta_out = core.broker.dispatch(&meta_call).await.unwrap();
    let BrokerDispatchOutcome::Executed(cap_res) = meta_out else {
        panic!(
            "expected Executed for resource.resolve, got {}",
            outcome_label(&meta_out)
        );
    };
    assert_eq!(cap_res.data["memory_isolated"], true);
    assert_eq!(cap_res.data["status"], "multiple_comparative");
}

// =============================================================================
// Test 3: Controlled Terminal (`C0`–`C4`) Real `bwrap` Sandbox & Anti-Bypass
// =============================================================================

#[tokio::test]
async fn m2_test3_controlled_terminal_c0_c4_sandbox_and_anti_bypass() {
    let probe = probe_sandbox_support();
    assert!(
        probe.bwrap_path.is_some() && probe.bwrap_userns_ok,
        "Host has bubblewrap + userns enabled; probe_sandbox_support() must report bwrap_userns_ok"
    );

    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(
        ws.join("experiment_log.txt"),
        "epoch=10 loss=0.0421 accuracy=0.991\nepoch=20 loss=0.0189 accuracy=0.996\n",
    )
    .unwrap();

    let core = init_m2_core(tmp.path(), std::slice::from_ref(&ws), "native");

    // 1. Real `bwrap` execution of `C0ReadOnlyDiag` (`df -h` and `free -h`)
    let c0_df_call = CapabilityCall {
        request_id: "req_term_c0_df".into(),
        task_id: "task_term_c0".into(),
        capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.into(),
        arguments: json!({
            "program": "df",
            "argv": ["-h"],
            "purpose": "检查磁盘空间使用率"
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let c0_df_out = core.broker.dispatch(&c0_df_call).await.unwrap();
    let BrokerDispatchOutcome::Executed(df_res) = c0_df_out else {
        panic!(
            "C0 `df -h` must auto-execute in sandbox, got {}",
            outcome_label(&c0_df_out)
        );
    };
    assert_eq!(df_res.status, ExecutionStatus::Exited);
    assert_eq!(df_res.exit_code, Some(0));
    assert_eq!(df_res.data["tier"], "c0_read_only_diag");
    assert_eq!(df_res.data["sandbox_driver"], "bubblewrap");
    assert!(
        df_res.stdout_preview.contains("Filesystem") || df_res.stdout_preview.contains("文件系统"),
        "expected real df -h output, got: {}",
        df_res.stdout_preview
    );

    let c0_free_call = CapabilityCall {
        request_id: "req_term_c0_free".into(),
        task_id: "task_term_c0".into(),
        capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.into(),
        arguments: json!({
            "program": "free",
            "argv": ["-h"],
            "purpose": "查看本机内存使用状态"
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(free_res) =
        core.broker.dispatch(&c0_free_call).await.unwrap()
    else {
        panic!("C0 `free -h` must auto-execute in sandbox");
    };
    assert_eq!(free_res.exit_code, Some(0));
    assert!(free_res.stdout_preview.contains("Mem:"));

    // 2. Real `bwrap` execution of `C1ScopedRead` (`grep` inside authorized workspace)
    let log_path = ws.join("experiment_log.txt");
    let c1_grep_call = CapabilityCall {
        request_id: "req_term_c1_grep".into(),
        task_id: "task_term_c1".into(),
        capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.into(),
        arguments: json!({
            "program": "grep",
            "argv": ["epoch=20", log_path.to_string_lossy()],
            "cwd": ws.to_string_lossy(),
            "required_paths": [ws.to_string_lossy()],
            "purpose": "检索第 20 轮训练指标"
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(c1_res) =
        core.broker.dispatch(&c1_grep_call).await.unwrap()
    else {
        panic!("C1 scoped grep inside authorized workspace must auto-execute");
    };
    assert_eq!(c1_res.exit_code, Some(0));
    assert_eq!(c1_res.data["tier"], "c1_scoped_read");
    assert_eq!(c1_res.data["sandbox_driver"], "bubblewrap");
    assert!(c1_res.stdout_preview.contains("accuracy=0.996"));

    // 3. Hard `C4Forbidden` anti-bypass checks:
    //    (a) `bash -c`, (b) `python3 -c`, (c) executable symlink to `/bin/bash`,
    //    (d) data symlink escape outside authorized dir, (e) `~/.ssh`, (f) unauthorized write outside workspace
    let fake_bin_dir = tmp.path().join("fake_bin");
    std::fs::create_dir_all(&fake_bin_dir).unwrap();
    let fake_df_symlink = fake_bin_dir.join("df");
    symlink("/bin/bash", &fake_df_symlink).unwrap();

    let escaped_data_symlink = ws.join("escaped_passwd_link.txt");
    symlink("/etc/shadow", &escaped_data_symlink).unwrap();

    let unauth_outside_target = tmp.path().join("unauthorized_outside_write.txt");

    let forbidden_cases = vec![
        (
            "bash_dash_c",
            json!({
                "program": "bash",
                "argv": ["-c", "id"],
                "cwd": ws.to_string_lossy(),
                "purpose": "inline shell bypass attempt"
            }),
        ),
        (
            "python3_dash_c",
            json!({
                "program": "python3",
                "argv": ["-c", "import os; print(os.getuid())"],
                "cwd": ws.to_string_lossy(),
                "purpose": "inline python bypass attempt"
            }),
        ),
        (
            "executable_symlink_masquerade",
            json!({
                "program": fake_df_symlink.to_string_lossy(),
                "argv": ["-h"],
                "cwd": ws.to_string_lossy(),
                "purpose": "masqueraded symlink binary"
            }),
        ),
        (
            "data_symlink_escape",
            json!({
                "program": "head",
                "argv": ["-n", "1", escaped_data_symlink.to_string_lossy()],
                "cwd": ws.to_string_lossy(),
                "required_paths": [escaped_data_symlink.to_string_lossy()],
                "purpose": "symlink escape outside authorized workspace"
            }),
        ),
        (
            "ssh_credential_access",
            json!({
                "program": "ls",
                "argv": ["~/.ssh"],
                "cwd": ws.to_string_lossy(),
                "required_paths": ["~/.ssh"],
                "purpose": "read forbidden ssh keys"
            }),
        ),
        (
            "unauthorized_outside_write",
            json!({
                "program": "touch",
                "argv": [unauth_outside_target.to_string_lossy()],
                "cwd": ws.to_string_lossy(),
                "purpose": "write outside authorized workspace"
            }),
        ),
    ];

    for (case_name, bad_args) in forbidden_cases {
        let bad_call = CapabilityCall {
            request_id: format!("req_forbid_{}", case_name),
            task_id: "task_term_forbid".into(),
            capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.into(),
            arguments: bad_args,
            origin: InvocationOrigin::L2AgentPlan,
            taints: Vec::new(),
        };
        let bad_out = core.broker.dispatch(&bad_call).await.unwrap();
        assert!(
            matches!(bad_out, BrokerDispatchOutcome::Denied { .. }),
            "Case `{}` MUST be hard-denied before execution, got: {}",
            case_name,
            outcome_label(&bad_out)
        );
    }
    assert!(
        !unauth_outside_target.exists(),
        "Unauthorized write target MUST NOT exist on disk"
    );

    // 4. `C3SystemModify` approval + `reversible == false` + anti-downgrade (`expected_effect: "observe"` ignored!)
    let c3_args = json!({
        "program": "apt-get",
        "argv": ["install", "-y", "htop"],
        "cwd": ws.to_string_lossy(),
        "expected_effect": "observe",
        "network_access": true,
        "purpose": "安装系统监控软件包 htop"
    });
    let prop = CommandProposal::from_capability_args(&c3_args, Some(&core)).unwrap();
    let cls = classify_command_proposal(&core, &prop);
    assert_eq!(cls.tier, TerminalSafetyTier::C3SystemModify);
    assert_eq!(cls.effective_effect, Effect::SystemAdmin);
    assert!(!cls.reversible);

    let c3_call = CapabilityCall {
        request_id: "req_term_c3_apt".into(),
        task_id: "task_term_c3".into(),
        capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.into(),
        arguments: c3_args,
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let c3_out = core.broker.dispatch(&c3_call).await.unwrap();
    let BrokerDispatchOutcome::RequiresApproval(pa) = c3_out else {
        panic!(
            "C3 apt-get install MUST require explicit human approval even when model claims observe, got {}",
            outcome_label(&c3_out)
        );
    };
    assert!(
        !pa.reversible,
        "C3 package/service modification PendingApproval MUST mark reversible == false!"
    );
    assert!(pa.effects.contains(&Effect::SystemAdmin));
}

// =============================================================================
// Test 4: Six Real Diagnostic & Software Capability Provider Scenarios
// =============================================================================

#[tokio::test]
async fn m2_test4_six_real_diagnostic_and_software_provider_scenarios() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let core = init_m2_core(tmp.path(), std::slice::from_ref(&ws), "native");

    // -------------------------------------------------------------------------
    // Scenario 1: System bottleneck read-only `/proc` inspection (zero kills)
    // -------------------------------------------------------------------------
    let bn_call = CapabilityCall {
        request_id: "req_diag_s1".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "system.bottleneck".into(),
        arguments: json!({ "limit": 5 }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(bn_res) = core.broker.dispatch(&bn_call).await.unwrap()
    else {
        panic!("system.bottleneck must execute cleanly");
    };
    assert_eq!(bn_res.status, ExecutionStatus::Exited);
    assert!(
        bn_res.data["mem_total_kb"].as_u64().unwrap_or(0) > 100_000,
        "mem_total_kb must reflect real Linux /proc/meminfo: {}",
        bn_res.data
    );
    assert!(
        !bn_res.data["top_rss_processes"]
            .as_array()
            .unwrap()
            .is_empty(),
        "top_rss_processes must sample real /proc processes"
    );

    // -------------------------------------------------------------------------
    // Scenario 2: Real ELF `ldd` `dependency.inspect` + `repair.plan` + `repair.verify`
    // -------------------------------------------------------------------------
    // 2a. Probe real host ELF binary (`ls` -> `/usr/bin/ls`) with dual-environment `ldd`
    let elf_call = CapabilityCall {
        request_id: "req_diag_s2_elf".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "dependency.inspect".into(),
        arguments: json!({ "target": "ls" }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(elf_res) = core.broker.dispatch(&elf_call).await.unwrap()
    else {
        panic!("dependency.inspect on /bin/ls must succeed");
    };
    assert_eq!(elf_res.data["exists"], true);
    assert_eq!(elf_res.data["is_executable"], true);
    assert_eq!(elf_res.data["binary_kind"], "elf");
    assert_eq!(elf_res.data["healthy"], true);
    assert!(
        elf_res.data["missing_libraries_sanitized"]
            .as_array()
            .unwrap()
            .is_empty(),
        "real ldd on /bin/ls must have 0 missing libraries in sanitized desktop env: {}",
        elf_res.data
    );

    // 2b. Broken launcher permission (`0o644`) -> `dependency.inspect` -> `repair.plan` -> fix -> `repair.verify`
    let broken_tool = ws.join("research_runner.sh");
    std::fs::write(&broken_tool, "#!/bin/sh\necho ok\n").unwrap();
    std::fs::set_permissions(&broken_tool, std::fs::Permissions::from_mode(0o644)).unwrap();

    let dep_broken_call = CapabilityCall {
        request_id: "req_diag_s2_broken".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "dependency.inspect".into(),
        arguments: json!({ "target": broken_tool.to_string_lossy() }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(dep_broken) =
        core.broker.dispatch(&dep_broken_call).await.unwrap()
    else {
        panic!("dependency.inspect must execute");
    };
    assert_eq!(dep_broken.data["root_cause"], "not_executable_permission");

    let plan_call = CapabilityCall {
        request_id: "req_diag_s2_plan".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "repair.plan".into(),
        arguments: json!({ "evidence": dep_broken.data }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(plan_res) = core.broker.dispatch(&plan_call).await.unwrap()
    else {
        panic!("repair.plan must execute");
    };
    assert_eq!(plan_res.data["requires_approval"], true);
    assert!(
        !plan_res.data["proposed_steps"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Confirm `repair.plan` did NOT auto-mutate permissions!
    let mode_still_broken = std::fs::metadata(&broken_tool)
        .unwrap()
        .permissions()
        .mode()
        & 0o111;
    assert_eq!(mode_still_broken, 0, "repair.plan must never auto-mutate!");

    // Apply permission fix and run `repair.verify`
    std::fs::set_permissions(&broken_tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let verify_call = CapabilityCall {
        request_id: "req_diag_s2_verify".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "repair.verify".into(),
        arguments: json!({
            "probe": "dependency.inspect",
            "probe_args": { "target": broken_tool.to_string_lossy() },
            "before_evidence": dep_broken.data
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(verify_res) =
        core.broker.dispatch(&verify_call).await.unwrap()
    else {
        panic!("repair.verify must execute");
    };
    assert_eq!(verify_res.data["repair_succeeded"], true);

    // -------------------------------------------------------------------------
    // Scenario 3: Reversible `.docx` section edit + byte-exact `Undo` restoration
    // -------------------------------------------------------------------------
    let docx_path = ws.join("thesis_chapters.docx");
    let original_docx_bytes = build_minimal_docx_bytes(
        Some("IntentOS Architecture Thesis"),
        &[
            ("1 Introduction", 1, &["Background on intent shells."]),
            (
                "2 Methodology",
                1,
                &["Initial draft paragraph before revision."],
            ),
            ("3 Evaluation", 1, &["Latency and accuracy benchmarks."]),
        ],
    );
    std::fs::write(&docx_path, &original_docx_bytes).unwrap();

    let replace_call = CapabilityCall {
        request_id: "req_prov_s3_replace".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "document.replace_section".into(),
        arguments: json!({
            "path": docx_path.to_string_lossy(),
            "section_heading": "2 Methodology",
            "new_content": "Revised methodology: unified transactional CapabilityBroker with C0-C4 sandboxed execution."
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(replace_res) =
        core.broker.dispatch(&replace_call).await.unwrap()
    else {
        panic!("document.replace_section must execute cleanly through CapabilityBroker");
    };
    assert_eq!(replace_res.status, ExecutionStatus::Exited);
    let docx_cs_id = replace_res
        .changeset_id
        .clone()
        .expect("document.replace_section must produce a ChangeSet ID");

    // Verify updated section content while chapters 1 & 3 remain intact
    let read_sec_call = CapabilityCall {
        request_id: "req_prov_s3_read".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "document.read_section".into(),
        arguments: json!({
            "path": docx_path.to_string_lossy(),
            "section_query": "Methodology"
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(read_sec_res) =
        core.broker.dispatch(&read_sec_call).await.unwrap()
    else {
        panic!("document.read_section must execute");
    };
    let sec_blob = read_sec_res.data.to_string();
    assert!(sec_blob.contains("unified transactional CapabilityBroker"));

    // Undo and verify byte-for-byte identity with original `.docx` archive!
    core.undo(Some(&docx_cs_id)).unwrap();
    let restored_docx_bytes = std::fs::read(&docx_path).unwrap();
    assert_eq!(
        restored_docx_bytes, original_docx_bytes,
        "Atomic Undo of document.replace_section MUST restore exact original .docx bytes!"
    );

    // -------------------------------------------------------------------------
    // Scenario 4: PDF + DOCX + Markdown bibliography compilation
    // -------------------------------------------------------------------------
    let lit_dir = ws.join("literature_s4");
    std::fs::create_dir_all(&lit_dir).unwrap();
    let pdf_bytes = build_minimal_pdf_bytes(
        "Wayland Security Boundaries in Desktop AI",
        "Elena Vance",
        &[
            "Wayland Security Boundaries in Desktop AI",
            "Authors: Elena Vance",
            "Published in 2024 Systems Symposium.",
            "Abstract: Compositor isolation prevents unauthorized window spying.",
        ],
    );
    std::fs::write(lit_dir.join("vance_2024.pdf"), pdf_bytes).unwrap();
    std::fs::write(
        lit_dir.join("park_2025.md"),
        "# Verified Undo for Local File Agents\nAuthors: Minjun Park\n2025\n\nContent-addressed backups guarantee lossless rollback.\n",
    )
    .unwrap();
    std::fs::write(lit_dir.join("thesis_ref_2026.docx"), &original_docx_bytes).unwrap();

    let bib_s4_out = ws.join("s4_references.md");
    let bib_call = CapabilityCall {
        request_id: "req_prov_s4_bib".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "document.compile_bibliography".into(),
        arguments: json!({
            "directory": lit_dir.to_string_lossy(),
            "output_path": bib_s4_out.to_string_lossy()
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(bib_res) = core.broker.dispatch(&bib_call).await.unwrap()
    else {
        panic!("document.compile_bibliography must execute");
    };
    assert_eq!(bib_res.data["data"]["paper_count"], 3);
    let bib_s4_text = std::fs::read_to_string(&bib_s4_out).unwrap();
    assert!(bib_s4_text.contains("Wayland Security Boundaries"));
    assert!(bib_s4_text.contains("Verified Undo for Local File Agents"));
    assert!(bib_s4_text.contains("IntentOS Architecture Thesis"));

    // -------------------------------------------------------------------------
    // Scenario 5: Real `git.inspect_repo` on temporary Git repository
    // -------------------------------------------------------------------------
    let repo_dir = ws.join("sample_git_repo");
    std::fs::create_dir_all(&repo_dir).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(&repo_dir)
            .status()
            .unwrap()
            .success()
    );
    Command::new("git")
        .args(["config", "user.email", "test@example.local"])
        .current_dir(&repo_dir)
        .status()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "M2 Verifier"])
        .current_dir(&repo_dir)
        .status()
        .unwrap();
    std::fs::write(repo_dir.join("README.md"), "# Sample Repo\nInitial line.\n").unwrap();
    Command::new("git")
        .args(["add", "README.md"])
        .current_dir(&repo_dir)
        .status()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "initial commit"])
        .current_dir(&repo_dir)
        .status()
        .unwrap();
    // Create unstaged edit + untracked file
    std::fs::write(
        repo_dir.join("README.md"),
        "# Sample Repo\nInitial line.\nModified line.\n",
    )
    .unwrap();
    std::fs::write(repo_dir.join("notes.txt"), "untracked research note\n").unwrap();

    let git_call = CapabilityCall {
        request_id: "req_prov_s5_git".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "git.inspect_repo".into(),
        arguments: json!({ "repo_dir": repo_dir.to_string_lossy() }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(git_res) = core.broker.dispatch(&git_call).await.unwrap()
    else {
        panic!("git.inspect_repo must execute");
    };
    assert_eq!(git_res.data["data"]["branch"], "main");
    assert_eq!(git_res.data["data"]["dirty"], true);
    assert_eq!(
        git_res.data["data"]["untracked_files"],
        json!(["notes.txt"])
    );

    // -------------------------------------------------------------------------
    // Scenario 6: `network.diagnose` (real interfaces + live/stale TCP proxy probe)
    //             + `HonestGuidance` & zero blind replay on `RequestedUnverified`
    // -------------------------------------------------------------------------
    let live_proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let live_port = live_proxy.local_addr().unwrap().port();
    let dead_port = {
        let ephemeral = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ephemeral.local_addr().unwrap().port()
    };

    let net_call = CapabilityCall {
        request_id: "req_diag_s6_net".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "network.diagnose".into(),
        arguments: json!({
            "proxy_url": format!("http://127.0.0.1:{}", dead_port),
            "proxy_ports": [live_port, dead_port]
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(net_res) = core.broker.dispatch(&net_call).await.unwrap()
    else {
        panic!("network.diagnose must execute");
    };
    drop(live_proxy);
    assert_eq!(net_res.data["stale_proxy_detected"], true);
    assert_eq!(net_res.data["root_cause"], "stale_local_proxy");

    // Closed-source internal action -> Tier 5 HonestGuidance (never fakes chat send!)
    let closed_call = CapabilityCall {
        request_id: "req_prov_s6_closed".into(),
        task_id: "task_m2_t4".into(),
        capability_id: "closed_app.internal_action".into(),
        arguments: json!({
            "app_hint": "wechat",
            "requested_action": "send_message"
        }),
        origin: InvocationOrigin::L2AgentPlan,
        taints: Vec::new(),
    };
    let BrokerDispatchOutcome::Executed(closed_res) =
        core.broker.dispatch(&closed_call).await.unwrap()
    else {
        panic!("closed_app.internal_action must execute with HonestGuidance");
    };
    assert_eq!(closed_res.data["channel_used"], "honest_guidance");
    assert!(
        !closed_res.data["guidance_steps"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Zero blind replay across channels when a mutating channel returns `RequestedUnverified`
    let second_channel_runs = Arc::new(AtomicUsize::new(0));
    let second_counter = second_channel_runs.clone();
    let chain_outcome = execute_channel_chain(
        "document.convert_headless",
        Some("libreoffice".to_string()),
        Effect::WriteReversible,
        true,
        vec![
            ChannelCandidate {
                channel: ExecutionChannel::CliOrHeadless,
                available: true,
                execute_fn: Box::new(|| {
                    Ok(ProviderExecutionOutcome {
                        ok: true,
                        requires_approval: false,
                        approval_scope: None,
                        capability_id: "document.convert_headless".into(),
                        app_hint: Some("libreoffice".into()),
                        channel_used: ExecutionChannel::CliOrHeadless,
                        attempted_channels: vec![],
                        fallback_halted_due_to_side_effect: false,
                        effect: Effect::WriteReversible,
                        reversible: true,
                        summary: "已发起无头转换但输出尚未确认".into(),
                        data: json!({}),
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::RequestedUnverified,
                            method: "headless_spawn".into(),
                            checks: vec![],
                            details: None,
                        },
                        guidance_steps: None,
                    })
                }),
            },
            ChannelCandidate {
                channel: ExecutionChannel::GuiAtSpiSemantic,
                available: true,
                execute_fn: Box::new(move || {
                    second_counter.fetch_add(1, Ordering::SeqCst);
                    unreachable!(
                        "Second mutating channel MUST NEVER execute after RequestedUnverified!"
                    );
                }),
            },
        ],
    )
    .unwrap();
    assert!(chain_outcome.fallback_halted_due_to_side_effect);
    assert_eq!(second_channel_runs.load(Ordering::SeqCst), 0);
}

// =============================================================================
// Test 5: Open-Ended Research Workspace Synthesis Goal (§7 line 335)
//         — NO Hardcoded User Prompt Keywords in Production Router/Parser!
// =============================================================================

#[derive(Clone)]
struct M2Test5SynthesisState {
    calls: Arc<AtomicUsize>,
    captured_requests: Arc<Mutex<Vec<Value>>>,
    thesis_docx: PathBuf,
    downloads_dir: PathBuf,
    literature_dir: PathBuf,
    bib_summary_md: PathBuf,
    paper1_src: PathBuf,
    paper2_src: PathBuf,
}

async fn mock_m2_test5_synthesis_gateway(
    State(state): State<M2Test5SynthesisState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.captured_requests.lock().unwrap().push(body.clone());
    let round = state.calls.fetch_add(1, Ordering::SeqCst);

    match round {
        0 => {
            // Round 0: Enable DND (`notify_dnd_set`), resolve comparative experiment files via `resource_resolve`,
            // and dynamically discover document/bibliography capabilities via `capability_search`!
            Json(json!({
                "id": "chatcmpl_m2_t5_r0",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_t5_dnd",
                                "type": "function",
                                "function": {
                                    "name": "notify_dnd_set",
                                    "arguments": json!({ "enabled": true }).to_string()
                                }
                            },
                            {
                                "id": "call_t5_res_exp",
                                "type": "function",
                                "function": {
                                    "name": "resource_resolve",
                                    "arguments": json!({
                                        "query": "比较昨天与前天的实验结果",
                                        "kind": "experiment_result"
                                    }).to_string()
                                }
                            },
                            {
                                "id": "call_t5_csearch",
                                "type": "function",
                                "function": {
                                    "name": "capability_search",
                                    "arguments": json!({
                                        "query": "document read_section compile_bibliography"
                                    }).to_string()
                                }
                            }
                        ]
                    }
                }]
            }))
        }
        1 => {
            // Extract the two resolved experiment paths dynamically from Round-0 tool output!
            let mut exp_paths: Vec<String> = Vec::new();
            if let Some(msgs) = body.get("messages").and_then(Value::as_array) {
                for m in msgs {
                    if m.get("role").and_then(Value::as_str) == Some("tool")
                        && m.get("tool_call_id").and_then(Value::as_str) == Some("call_t5_res_exp")
                        && let Some(content) = m.get("content").and_then(Value::as_str)
                        && let Ok(parsed) = serde_json::from_str::<Value>(content)
                        && let Some(arr) =
                            parsed.pointer("/data/resolved").and_then(Value::as_array)
                    {
                        for item in arr {
                            if let Some(t) = item.get("target").and_then(Value::as_str) {
                                exp_paths.push(t.to_string());
                            }
                        }
                    }
                }
            }
            assert_eq!(
                exp_paths.len(),
                2,
                "resource_resolve must dynamically return both comparative experiment paths"
            );

            let p1_dst = state
                .literature_dir
                .join("2025_Speculative_Tool_Discovery.md");
            let p2_dst = state.literature_dir.join("2026_Sandboxed_OS_Agents.docx");

            Json(json!({
                "id": "chatcmpl_m2_t5_r1",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_t5_read_newer",
                                "type": "function",
                                "function": {
                                    "name": "document_read_section",
                                    "arguments": json!({ "path": exp_paths[0] }).to_string()
                                }
                            },
                            {
                                "id": "call_t5_read_older",
                                "type": "function",
                                "function": {
                                    "name": "document_read_section",
                                    "arguments": json!({ "path": exp_paths[1] }).to_string()
                                }
                            },
                            {
                                "id": "call_t5_read_thesis",
                                "type": "function",
                                "function": {
                                    "name": "document_read_section",
                                    "arguments": json!({
                                        "path": state.thesis_docx.to_string_lossy(),
                                        "section_query": "Open Bottlenecks"
                                    }).to_string()
                                }
                            },
                            {
                                "id": "call_t5_move_p1",
                                "type": "function",
                                "function": {
                                    "name": "file_move",
                                    "arguments": json!({
                                        "source": state.paper1_src.to_string_lossy(),
                                        "target": p1_dst.to_string_lossy()
                                    }).to_string()
                                }
                            },
                            {
                                "id": "call_t5_move_p2",
                                "type": "function",
                                "function": {
                                    "name": "file_move",
                                    "arguments": json!({
                                        "source": state.paper2_src.to_string_lossy(),
                                        "target": p2_dst.to_string_lossy()
                                    }).to_string()
                                }
                            }
                        ]
                    }
                }]
            }))
        }
        2 => {
            // Compile bibliography from organized `literature/` folder and verify all artifacts via `task_verify`!
            let p1_dst = state
                .literature_dir
                .join("2025_Speculative_Tool_Discovery.md");
            let p2_dst = state.literature_dir.join("2026_Sandboxed_OS_Agents.docx");
            let _ = &state.downloads_dir;
            Json(json!({
                "id": "chatcmpl_m2_t5_r2",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_t5_bib",
                                "type": "function",
                                "function": {
                                    "name": "document_compile_bibliography",
                                    "arguments": json!({
                                        "directory": state.literature_dir.to_string_lossy(),
                                        "output_path": state.bib_summary_md.to_string_lossy()
                                    }).to_string()
                                }
                            },
                            {
                                "id": "call_t5_verify",
                                "type": "function",
                                "function": {
                                    "name": "task_verify",
                                    "arguments": json!({
                                        "goal": "归档新论文并生成文献综述表且开启勿扰模式",
                                        "expected_files": [
                                            p1_dst.to_string_lossy(),
                                            p2_dst.to_string_lossy(),
                                            state.bib_summary_md.to_string_lossy()
                                        ],
                                        "check_ledger": true
                                    }).to_string()
                                }
                            }
                        ]
                    }
                }]
            }))
        }
        _ => {
            // Inspect real tool outputs in `messages` so synthesis is grounded 100% in observed evidence
            let all_msgs = body["messages"].to_string();
            assert!(all_msgs.contains("0.994") && all_msgs.contains("0.981"));
            assert!(all_msgs.contains("41.2") && all_msgs.contains("24.5"));
            assert!(all_msgs.contains("tail-latency spike under concurrent tool fanout"));

            Json(json!({
                "id": "chatcmpl_m2_t5_r3",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "## 今日研究工作区恢复与推进重点\n\n1. **专注环境已就绪**：已开启系统勿扰模式（可一键撤销），并读取论文草稿第 4 章未闭环问题（`tail-latency spike under concurrent tool fanout`）。\n2. **实验指标对比**：准确率从 `98.1%` 提升至 `99.4%`（`+1.3%`），但 P95 延迟从 `24.5 ms` 上升至 `41.2 ms`，且出现 `3` 次内存峰值重试（`oom_retries: 3`）。\n3. **新论文归档与文献表已核验**：已将下载目录新增的 2 篇论文归档至 `literature/` 并生成经宿主机核验的 `bibliography_summary.md`。\n4. **今日推进优先级**：（P1）排查并发工具调度下的 P95 尾延迟与 `oom_retries`；（P2）将 2025/2026 两篇新文献的渐进式工具暴露与沙箱校验结论补充进第 4 章。"
                    }
                }]
            }))
        }
    }
}

#[derive(Clone)]
struct M2PartialFailureState {
    calls: Arc<AtomicUsize>,
    note_file: PathBuf,
}

async fn mock_m2_partial_failure_completions(
    State(state): State<M2PartialFailureState>,
    Json(_body): Json<Value>,
) -> impl IntoResponse {
    let idx = state.calls.fetch_add(1, Ordering::SeqCst);
    if idx == 0 {
        (
            StatusCode::OK,
            Json(json!({
                "id": "chatcmpl_partial_0",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "<think>先写入第一阶段进度纪要</think>",
                        "tool_calls": [{
                            "id": "call_partial_write",
                            "type": "function",
                            "function": {
                                "name": "file_write",
                                "arguments": json!({
                                    "path": state.note_file.to_string_lossy(),
                                    "content": "Stage 1 verified checkpoint.\n"
                                }).to_string()
                            }
                        }]
                    }
                }]
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": { "message": "upstream gateway 502 mid-turn failure" } })),
        )
            .into_response()
    }
}

#[tokio::test]
async fn m2_test5_open_ended_research_workspace_synthesis_goal() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("research_workspace");
    let downloads_dir = tmp.path().join("Downloads");
    let project_dir = ws.join("thesis_multimodal_agent");
    let exp_dir = project_dir.join("experiments");
    let literature_dir = project_dir.join("literature");
    std::fs::create_dir_all(&exp_dir).unwrap();
    std::fs::create_dir_all(&literature_dir).unwrap();
    std::fs::create_dir_all(&downloads_dir).unwrap();

    // 1. Real thesis `.docx` draft with chapters
    let thesis_docx = project_dir.join("thesis_draft_v2.docx");
    let thesis_bytes = build_minimal_docx_bytes(
        Some("Controlled OS Agents for Reproducible Research"),
        &[
            (
                "1 Introduction",
                1,
                &["Bridging natural-language intent and deterministic OS execution."],
            ),
            (
                "4 Open Bottlenecks",
                1,
                &[
                    "Remaining issue: tail-latency spike under concurrent tool fanout and memory bursts.",
                ],
            ),
        ],
    );
    std::fs::write(&thesis_docx, thesis_bytes).unwrap();

    // 2. Real yesterday & day-before-yesterday experiment metrics relative to actual current UTC date
    //    so `IntentOsCore::submit_intent` (which uses live `Utc::now()`) resolves them naturally!
    let today_utc = Utc::now().date_naive();
    let yesterday_date = today_utc
        .checked_sub_days(chrono::Days::new(1))
        .unwrap()
        .to_string();
    let day_before_date = today_utc
        .checked_sub_days(chrono::Days::new(2))
        .unwrap()
        .to_string();

    let exp_yesterday = exp_dir.join(format!("exp_{}_eval.json", yesterday_date));
    let exp_day_before = exp_dir.join(format!("exp_{}_eval.json", day_before_date));
    std::fs::write(
        &exp_yesterday,
        json!({
            "run_date": yesterday_date,
            "accuracy": 0.994,
            "p95_ms": 41.2,
            "oom_retries": 3
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        &exp_day_before,
        json!({
            "run_date": day_before_date,
            "accuracy": 0.981,
            "p95_ms": 24.5,
            "oom_retries": 0
        })
        .to_string(),
    )
    .unwrap();

    // 3. Newly arrived papers in `Downloads/`
    let paper1_src = downloads_dir.join("2025_Speculative_Tool_Discovery.md");
    let paper2_src = downloads_dir.join("2026_Sandboxed_OS_Agents.docx");
    std::fs::write(
        &paper1_src,
        "# Speculative Progressive Tool Discovery for Local LLMs\nAuthors: Hannah Lin, Omar Farooq\nYear: 2025\n\n## Abstract\nDynamic mid-turn schema unlocking cuts prompt latency and context bloat.\n",
    )
    .unwrap();
    std::fs::write(
        &paper2_src,
        build_minimal_docx_bytes(
            Some("Sandboxed OS Agents with Verified Rollback"),
            &[(
                "Abstract",
                1,
                &[
                    "Authors: Kenji Sato, Mei Zhou (2026)",
                    "Bubblewrap isolation paired with content-addressed ChangeSets prevents irreversible drift.",
                ],
            )],
        ),
    )
    .unwrap();

    std::fs::write(
        project_dir.join("pyproject.toml"),
        "[project]\nname = \"thesis-multimodal-agent\"\nversion = \"0.2.0\"\n",
    )
    .unwrap();

    let auth_dirs = vec![ws.clone(), downloads_dir.clone()];
    let core = init_m2_core(tmp.path(), &auth_dirs, "native");
    let _ = core.resources.index_authorized_files();
    let _ = discover_and_list_projects(&core, true).unwrap();

    let bib_summary_md = literature_dir.join("bibliography_summary.md");
    let synth_state = M2Test5SynthesisState {
        calls: Arc::new(AtomicUsize::new(0)),
        captured_requests: Arc::new(Mutex::new(Vec::new())),
        thesis_docx: thesis_docx.clone(),
        downloads_dir: downloads_dir.clone(),
        literature_dir: literature_dir.clone(),
        bib_summary_md: bib_summary_md.clone(),
        paper1_src: paper1_src.clone(),
        paper2_src: paper2_src.clone(),
    };

    let app = Router::new()
        .route("/chat/completions", post(mock_m2_test5_synthesis_gateway))
        .route(
            "/v1/chat/completions",
            post(mock_m2_test5_synthesis_gateway),
        )
        .with_state(synth_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));

    // Record initial DND state so Undo verifies exact restoration whether running headless or with live D-Bus
    let (initial_dnd, _) = core.settings.read_setting_value("notify.dnd").unwrap();

    // Grant scoped research session permissions (`notify.dnd.set` + authorized `research_workspace` & `Downloads` roots)
    // so reversible L2 actions execute via `PolicyDecision::AllowWithUndo` while Tier-0/forbidden paths stay blocked!
    core.policy
        .add_session_grant("capability", "notify.dnd.set", 30);
    core.policy
        .add_session_grant("directory", &ws.to_string_lossy(), 30);
    core.policy
        .add_session_grant("directory", &downloads_dir.to_string_lossy(), 30);

    // Submit an open-ended natural-language research synthesis goal (NO `force_agent: true` —
    // verify progressive router routes this open-ended multi-domain synthesis goal to L2 naturally!)
    let synthesis_prompt = "恢复我昨天正在推进的论文研究工作状态并开启勿扰模式，对比昨天与前天的实验结果差异，把下载目录新收到的论文归档进课题文献目录并编译生成文献综述清单，最后结合论文草稿给出今天的具体推进重点";
    let task = core
        .submit_intent(
            IntentRequest {
                protocol_version: PROTOCOL_VERSION,
                text: synthesis_prompt.to_string(),
                session_id: Some("ses_m2_synthesis".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: Some(project_dir.to_string_lossy().to_string()),
                incognito: false,
                privacy_policy: None,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert_eq!(
        task.route,
        RouteLayer::L2,
        "Open-ended multi-domain research synthesis goal must route naturally to L2 (got {:?}, status {:?})",
        task.route,
        task.status
    );
    assert_eq!(task.status, TaskStatus::Completed);

    // Verify dynamic mid-turn schema unlocking occurred inside `AgentCoordinator::run_via_native_loop`
    {
        let reqs = synth_state.captured_requests.lock().unwrap();
        assert_eq!(reqs.len(), 4);
        let r0_tools = tool_names_in_request(&reqs[0]);
        assert!(
            !r0_tools.contains(&"document_read_section".to_string()),
            "document_read_section should not be pre-loaded in Round-0 L2 tools"
        );
        let r1_tools = tool_names_in_request(&reqs[1]);
        assert!(
            r1_tools.contains(&"document_read_section".to_string())
                && r1_tools.contains(&"document_compile_bibliography".to_string()),
            "Round-1 L2 tools MUST contain mid-turn unlocked provider capabilities: {:?}",
            r1_tools
        );
    }

    // Verify real host effects:
    // (1) DND enabled
    assert_eq!(
        core.settings.read_setting_value("notify.dnd").unwrap().0,
        json!(true)
    );
    // (2) Papers moved from `Downloads/` into `literature/`
    let p1_dst = literature_dir.join("2025_Speculative_Tool_Discovery.md");
    let p2_dst = literature_dir.join("2026_Sandboxed_OS_Agents.docx");
    assert!(!paper1_src.exists() && p1_dst.is_file());
    assert!(!paper2_src.exists() && p2_dst.is_file());
    // (3) Verified bibliography Markdown generated with both papers
    assert!(bib_summary_md.is_file());
    let bib_content = std::fs::read_to_string(&bib_summary_md).unwrap();
    assert!(bib_content.contains("Speculative Progressive Tool Discovery"));
    assert!(bib_content.contains("Sandboxed OS Agents with Verified Rollback"));
    // (4) Final synthesis grounded in real metric delta & thesis bottleneck
    let final_reply = task.assistant_message.as_deref().unwrap_or("");
    assert!(final_reply.contains("99.4%") && final_reply.contains("41.2 ms"));
    assert!(final_reply.contains("oom_retries"));

    // (5) Reversible ChangeSets recorded for DND + 2 paper moves + bibliography compilation (`>= 4`)
    assert!(
        task.changeset_ids.len() >= 4,
        "Expected >= 4 reversible ChangeSets (DND + 2 moves + bibliography), got: {:?}",
        task.changeset_ids
    );

    // Reverse-order Undo rollback of all synthesis ChangeSets -> restores exact prior workspace state!
    for cs_id in task.changeset_ids.iter().rev() {
        core.undo(Some(cs_id)).unwrap();
    }
    assert_eq!(
        core.settings.read_setting_value("notify.dnd").unwrap().0,
        initial_dnd,
        "Undo must restore DND setting back to exact initial state"
    );
    assert!(
        !bib_summary_md.exists(),
        "Undo must remove compiled bibliography_summary.md"
    );
    assert!(
        paper1_src.is_file() && !p1_dst.exists(),
        "Undo must restore paper 1 back to Downloads/"
    );
    assert!(
        paper2_src.is_file() && !p2_dst.exists(),
        "Undo must restore paper 2 back to Downloads/"
    );

    // -------------------------------------------------------------------------
    // Partial-Failure Honesty Check: step 1 commits ChangeSet, step 2 hits 502 ->
    // NEVER claims full success, preserves completed `changeset_ids`, and Undo works!
    // -------------------------------------------------------------------------
    let partial_note = project_dir.join("stage1_checkpoint.md");
    let pf_state = M2PartialFailureState {
        calls: Arc::new(AtomicUsize::new(0)),
        note_file: partial_note.clone(),
    };
    let pf_app = Router::new()
        .route(
            "/v1/chat/completions",
            post(mock_m2_partial_failure_completions),
        )
        .with_state(pf_state);
    let pf_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pf_addr = pf_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(pf_listener, pf_app).await.unwrap();
    });

    let mock_home = tmp.path().join("mock_home_pf");
    std::fs::create_dir_all(&mock_home).unwrap();
    let opts = DiscoveryOptions::isolated_for_test(mock_home);
    set_active_backend_with_options(
        &core,
        &json!({
            "backend": "openai",
            "provider": "m2-pf-provider",
            "model": "gpt-5.4",
            "base_url": format!("http://{}/v1", pf_addr),
            "api_key": "sk-m2-pf-test-key-1234567890"
        }),
        &opts,
    )
    .await
    .unwrap();

    let pf_res = send_quick_chat_turn_with_options(
        &core,
        &json!({
            "session_id": "ses_m2_partial_fail",
            "text": "先保存第一阶段进度纪要，再继续执行后续步骤",
        }),
        &opts,
    )
    .await
    .unwrap();

    // Must NOT report normal `succeeded` when round 2 failed after round 1 side effect!
    assert_ne!(
        pf_res["task_status"], "succeeded",
        "Partial mid-turn failure after committed side effect MUST NOT claim succeeded: {}",
        pf_res
    );
    assert!(partial_note.is_file());
    let pf_cs = pf_res["changeset_ids"].as_array().unwrap();
    assert_eq!(
        pf_cs.len(),
        1,
        "Completed step's ChangeSet ID must be preserved for honest rollback on partial failure"
    );
    core.undo(pf_cs[0].as_str()).unwrap();
    assert!(!partial_note.exists());

    // Sanity check: no secret tokens leaked into workspace, config, or SQLite audit/state files outside `vault/`
    let mut all_xdg_files = Vec::new();
    collect_all_files_recursive(tmp.path(), &mut all_xdg_files);
    for f in all_xdg_files {
        if f.components().any(|c| c.as_os_str() == "vault") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&f) {
            let s = String::from_utf8_lossy(&bytes);
            assert!(
                !s.contains("sk-m2-pf-test-key-1234567890"),
                "API key must never leak to disk file {}",
                f.display()
            );
        }
    }
}
