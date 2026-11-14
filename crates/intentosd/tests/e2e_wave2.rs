#![forbid(unsafe_code)]

//! Wave 2 Deep AIOS Core Integration End-to-End Tests (`e2e_wave2.rs`):
//! 1. Offline & Unreachable-API Personal Memory Hub (`memory_hub`) + Software Translation Layer (`app_adapter`) + Multi-turn Conversational Entity Resolution + Incognito Zero-Persistence.
//! 2. Live Mock OpenAI LLM Server proving BOTH `core.submit_intent` (`native-rust` L2) AND `backend_bridge::send_quick_chat_turn`:
//!    - Automatically inject `[Personal OS Memory]` (mentioned files, XBEL frequent files, Ubuntu desktop software) before LLM inference.
//!    - Expose all 7 AIOS tools (`memory_recall_mentioned_files`, `memory_get_frequent_files`, `memory_get_software_catalog`, `memory_search_past_chats`, `app_adapter_invoke`, `app_adapter_list`, `app_adapter_now_playing`).
//!    - Execute `memory_*` and `app_adapter_*` tool calls end-to-end with ordered `trace_dots` (`thinking` gray -> `memory` purple -> `adapter` cyan) and single-pass `memory_hub` turn persistence.

use axum::{Json, Router, extract::State, routing::post};
use intentos_protocol::{IntentRequest, RouteLayer, TaskStatus, UiRpcRequest};
use intentosd::backend_bridge::{DiscoveryOptions, send_quick_chat_turn_with_options};
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn setup_wave2_core(
    runtime_mode: &str,
) -> (tempfile::TempDir, Arc<IntentOsCore>, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path();
    let downloads = base.join("Downloads");
    let documents = base.join("Documents");
    std::fs::create_dir_all(&downloads).unwrap();
    std::fs::create_dir_all(&documents).unwrap();

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
        runtime: runtime_mode.into(),
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
    (temp, core, downloads, documents)
}

fn seed_xbel_and_desktop_assets(
    base: &Path,
    frequent_file: &Path,
) -> (PathBuf, Vec<PathBuf>) {
    let xbel_path = base.join("recently-used.xbel");
    // Percent-encoded UTF-8 URI for `架构白皮书_2026.pdf`
    let parent_uri = format!("file://{}", frequent_file.parent().unwrap().display());
    let encoded_uri = format!(
        "{}/%E6%9E%B6%E6%9E%84%E7%99%BD%E7%9A%AE%E4%B9%A6_2026.pdf",
        parent_uri
    );
    let xbel_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0"
      xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"
      xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">
  <bookmark href="{uri}" added="2026-11-10T09:00:00Z" modified="2026-11-14T03:00:00Z" visited="2026-11-14T03:00:00Z">
    <info>
      <metadata owner="http://freedesktop.org">
        <mime:mime-type type="application/pdf"/>
        <bookmark:applications>
          <bookmark:application name="Document Viewer" exec="&apos;evince %u&apos;" modified="2026-11-14T03:00:00Z" count="11"/>
        </bookmark:applications>
      </metadata>
    </info>
  </bookmark>
</xbel>"#,
        uri = encoded_uri
    );
    std::fs::write(&xbel_path, xbel_xml).unwrap();

    let apps_dir = base.join("mock_applications");
    std::fs::create_dir_all(&apps_dir).unwrap();
    std::fs::write(
        apps_dir.join("code.desktop"),
        "[Desktop Entry]\nType=Application\nName=Visual Studio Code\nName[zh_CN]=VS Code 编辑器\nGenericName=Text Editor\nExec=/usr/bin/code %F\nCategories=Development;IDE;\nMimeType=text/plain;x-scheme-handler/vscode;\nDBusActivatable=false\n",
    )
    .unwrap();
    std::fs::write(
        apps_dir.join("spotify.desktop"),
        "[Desktop Entry]\nType=Application\nName=Spotify\nName[zh_CN]=Spotify 音乐\nGenericName=Music Player\nExec=spotify %U\nCategories=AudioVideo;Music;Player;\nMimeType=x-scheme-handler/spotify;\n",
    )
    .unwrap();

    (xbel_path, vec![apps_dir])
}

#[tokio::test]
async fn wave2_e2e_offline_personal_memory_habit_sync_and_multi_turn_resolution() {
    let (temp, core, downloads, documents) = setup_wave2_core("native");
    let whitepaper = documents.join("架构白皮书_2026.pdf");
    std::fs::write(&whitepaper, b"%PDF-1.7-architecture-whitepaper").unwrap();
    let review_md = documents.join("季度复盘_Q4.md");
    std::fs::write(&review_md, b"# Q4 Review\nAll milestones shipped.").unwrap();
    let _ = core.resources.refresh_all().unwrap();

    // 1. Sync XBEL + .desktop into `memory_hub.db`
    let (xbel_path, desktop_dirs) = seed_xbel_and_desktop_assets(temp.path(), &whitepaper);
    let sync_resp = core
        .handle_trusted_ui_rpc(
            "sync_1".into(),
            UiRpcRequest::ModuleRpc {
                domain: "memory_hub".into(),
                action: "sync_system_usage".into(),
                payload: json!({
                    "xbel_path": xbel_path,
                    "desktop_dirs": desktop_dirs,
                }),
            },
        )
        .await;
    assert!(sync_resp.ok, "sync_system_usage failed: {:?}", sync_resp.error);

    // 2. Offline query: "我长期使用的文件有哪些" -> returns percent-decoded `架构白皮书_2026.pdf`!
    let freq_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "我长期使用的文件有哪些".into(),
                session_id: Some("ses_mem_1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(freq_task.status, TaskStatus::Completed);
    let freq_msg = freq_task.assistant_message.unwrap_or_default();
    assert!(
        freq_msg.contains("架构白皮书_2026.pdf"),
        "expected XBEL frequent file in answer, got: {}",
        freq_msg
    );

    // 3. Offline query: "我电脑上有哪些软件 / 常用软件有哪些" -> returns scanned desktop software!
    let sw_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "我电脑上有哪些软件，常用软件有哪些".into(),
                session_id: Some("ses_mem_1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(sw_task.status, TaskStatus::Completed);
    let sw_msg = sw_task.assistant_message.unwrap_or_default();
    assert!(
        sw_msg.contains("VS Code") || sw_msg.contains("Visual Studio Code"),
        "expected VS Code in software answer, got: {}",
        sw_msg
    );
    assert!(
        sw_msg.contains("Spotify"),
        "expected Spotify in software answer, got: {}",
        sw_msg
    );

    // 4. Even when a cloud API key IS configured (`set_mock_upstream_url`) but UNREACHABLE (closed port),
    //    personal memory queries MUST STILL fall back cleanly and return real data!
    core.gateway
        .set_mock_upstream_url(Some("http://127.0.0.1:9".into()));
    let unreachable_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "我长期使用的文件有哪些".into(),
                session_id: Some("ses_mem_1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(unreachable_task.status, TaskStatus::Completed);
    assert!(
        unreachable_task
            .assistant_message
            .unwrap_or_default()
            .contains("架构白皮书_2026.pdf")
    );
    core.gateway.set_mock_upstream_url(None);

    // 5. Multi-turn conversational entity memory across DIFFERENT sessions:
    //    Turn A (`ses_talk_a`): user mentions `季度复盘_Q4.md` in conversation
    let _mention_turn = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: format!("我刚才整理好了文档 {}", review_md.display()),
                session_id: Some("ses_talk_a".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    //    Turn B (`ses_talk_b` — brand new session!): user asks "我之前说的文件有哪些"
    let recall_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "我之前说的文件有哪些".into(),
                session_id: Some("ses_talk_b".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(recall_task.status, TaskStatus::Completed);
    let recall_msg = recall_task.assistant_message.unwrap_or_default();
    assert!(
        recall_msg.contains("季度复盘_Q4.md"),
        "expected recalled file 季度复盘_Q4.md across sessions, got: {}",
        recall_msg
    );

    //    Turn C (`ses_talk_b`): user says "把 我之前说的那个文件 复制到 下载" -> resolves to `季度复盘_Q4.md` and executes `file.copy`!
    let copy_recalled = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "把 我之前说的那个文件 复制到 下载".into(),
                session_id: Some("ses_talk_b".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(copy_recalled.status, TaskStatus::Completed);
    assert!(
        downloads.join("季度复盘_Q4.md").exists(),
        "conversational reference copy must create file in Downloads"
    );
    assert_eq!(copy_recalled.changeset_ids.len(), 1);

    // 6. Starter prompts #3 (Software Translation Layer) & #4 (Compound Brightness + Night Light) work offline!
    let adapter_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "用转译层查看或控制当前音乐播放".into(),
                session_id: Some("ses_starter".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(adapter_task.status, TaskStatus::Completed);
    assert!(
        adapter_task
            .assistant_message
            .unwrap_or_default()
            .contains("转译层")
    );

    let compound_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "屏幕太亮了，帮我调暗并开启护眼".into(),
                session_id: Some("ses_starter".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(compound_task.status, TaskStatus::Completed);

    // 7. Incognito privacy invariant: mentioning a secret path in incognito leaves ZERO trace in `memory_hub`!
    let _incog_turn = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: format!(
                    "我正在看隐私文件 {}",
                    downloads.join("绝密并购草案_999.pdf").display()
                ),
                session_id: Some("ses_incog_check".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: true,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    let dash_resp = core
        .handle_trusted_ui_rpc(
            "dash_1".into(),
            UiRpcRequest::ModuleRpc {
                domain: "memory_hub".into(),
                action: "get_memory_dashboard".into(),
                payload: json!({ "auto_sync": false }),
            },
        )
        .await;
    let dash_dump = serde_json::to_string(&dash_resp.result).unwrap();
    assert!(
        !dash_dump.contains("绝密并购草案_999.pdf"),
        "incognito turn must NEVER write into memory_hub.db!"
    );
}

#[derive(Clone)]
struct Wave2MockOpenAiState {
    calls: Arc<AtomicUsize>,
    captured_requests: Arc<Mutex<Vec<Value>>>,
}

async fn wave2_mock_chat_completions(
    State(st): State<Wave2MockOpenAiState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    st.captured_requests.lock().unwrap().push(body.clone());
    let _call_idx = st.calls.fetch_add(1, Ordering::SeqCst);

    let msgs = body
        .get("messages")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let tool_msg_count = msgs
        .iter()
        .filter(|m| m.get("role") == Some(&json!("tool")))
        .count();

    if tool_msg_count == 0 {
        // Round 1: Call BOTH `memory_recall_mentioned_files` AND `app_adapter_list`!
        Json(json!({
            "id": "chatcmpl_wave2_1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "reasoning_content": "先调用个人记忆工具核对之前提到的文件，再查询媒体类软件指令转译器。",
                    "content": null,
                    "tool_calls": [
                        {
                            "id": "call_mem_1",
                            "type": "function",
                            "function": {
                                "name": "memory_recall_mentioned_files",
                                "arguments": "{\"query\":\"预算\"}"
                            }
                        },
                        {
                            "id": "call_adp_1",
                            "type": "function",
                            "function": {
                                "name": "app_adapter_list",
                                "arguments": "{\"category\":\"media\"}"
                            }
                        }
                    ]
                }
            }],
            "usage": { "prompt_tokens": 220, "completion_tokens": 45 }
        }))
    } else {
        // Round 2: Synthesize final Markdown answer from tool outputs
        Json(json!({
            "id": "chatcmpl_wave2_2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "<think>工具已返回预算表路径与媒体转译器清单，整理回复。</think>已为您查到之前提到的 **年度预算_2026.xlsx**，并确认媒体软件指令转译层已就绪。"
                }
            }],
            "usage": { "prompt_tokens": 340, "completion_tokens": 38 }
        }))
    }
}

#[tokio::test]
async fn wave2_e2e_core_l2_and_quick_chat_bridge_llm_memory_injection_and_7_aios_tools() {
    let (temp, core, _downloads, documents) = setup_wave2_core("native");
    let budget_xlsx = documents.join("年度预算_2026.xlsx");
    std::fs::write(&budget_xlsx, b"xlsx-budget-2026").unwrap();
    let (xbel_path, desktop_dirs) = seed_xbel_and_desktop_assets(temp.path(), &budget_xlsx);
    let _ = core
        .handle_trusted_ui_rpc(
            "sync_w2".into(),
            UiRpcRequest::ModuleRpc {
                domain: "memory_hub".into(),
                action: "sync_system_usage".into(),
                payload: json!({
                    "xbel_path": xbel_path,
                    "desktop_dirs": desktop_dirs,
                }),
            },
        )
        .await;

    // Seed a mentioned file via `submit_intent`
    let _ = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: format!("请记一下我刚编辑了 {}", budget_xlsx.display()),
                session_id: Some("ses_llm".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    // Start local mock OpenAI HTTP server serving both `/chat/completions` and `/v1/chat/completions`
    let mock_state = Wave2MockOpenAiState {
        calls: Arc::new(AtomicUsize::new(0)),
        captured_requests: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/chat/completions", post(wave2_mock_chat_completions))
        .route("/v1/chat/completions", post(wave2_mock_chat_completions))
        .with_state(mock_state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let required_7_tools = [
        "memory_recall_mentioned_files",
        "memory_get_frequent_files",
        "memory_get_software_catalog",
        "memory_search_past_chats",
        "app_adapter_invoke",
        "app_adapter_list",
        "app_adapter_now_playing",
    ];

    // =========================================================================
    // Part A: Verify `core.submit_intent` (`native-rust` L2) injects Personal Memory + all 7 AIOS tools!
    // =========================================================================
    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}", addr)));

    let l2_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "结合我的个人记忆看看之前提到的预算文件，并列出媒体转译器".into(),
                session_id: Some("ses_llm".into()),
                force_agent: true,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    assert_eq!(l2_task.route, RouteLayer::L2);
    assert_eq!(l2_task.status, TaskStatus::Completed);
    assert!(
        l2_task
            .assistant_message
            .as_deref()
            .unwrap_or("")
            .contains("年度预算_2026.xlsx")
    );
    assert_eq!(l2_task.steps.len(), 2);
    assert_eq!(
        l2_task.steps[0].capability_id,
        "memory_recall_mentioned_files"
    );
    assert_eq!(l2_task.steps[1].capability_id, "app_adapter_list");

    {
        let reqs = mock_state.captured_requests.lock().unwrap();
        assert!(reqs.len() >= 2);
        let first_req = &reqs[0];
        let sys_content = first_req["messages"][0]["content"].as_str().unwrap_or("");
        assert!(
            sys_content.contains("[Personal OS Memory"),
            "L2 system prompt must auto-inject [Personal OS Memory], got: {}",
            sys_content
        );
        assert!(
            sys_content.contains("年度预算_2026.xlsx"),
            "L2 system prompt must include mentioned file 年度预算_2026.xlsx"
        );
        assert!(
            sys_content.contains("Spotify"),
            "L2 system prompt must include desktop software profile"
        );

        let tool_names: Vec<&str> = first_req["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["function"]["name"].as_str())
            .collect();
        for expected in required_7_tools {
            assert!(
                tool_names.contains(&expected),
                "L2 tools missing '{}'; got {:?}",
                expected,
                tool_names
            );
        }
    }

    // =========================================================================
    // Part B: Verify `backend_bridge::send_quick_chat_turn` auto-discovers ZCode OpenAI provider,
    //         injects Personal Memory + all 7 AIOS tools, executes tool calls, and builds Trace Dots!
    // =========================================================================
    mock_state.captured_requests.lock().unwrap().clear();
    let mock_home = temp.path().join("mock_qc_home");
    let zcode_cfg_path = mock_home.join(".zcode/v2/provider_config.json");
    std::fs::create_dir_all(zcode_cfg_path.parent().unwrap()).unwrap();
    std::fs::write(
        &zcode_cfg_path,
        serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "config": {
                "providerOrder": ["local_mock_openai"],
                "providerConfigRules": {
                    "providerRules": [{
                        "providerId": "local_mock_openai",
                        "templateId": "openai",
                        "providerName": "Mock OpenAI",
                        "config": {
                            "access": { "type": "api-key", "apiKey": "sk-wave2-mock-key" },
                            "api": { "baseUrl": format!("http://{}/v1", addr) },
                            "modelOrder": ["gpt-wave2-pro"]
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
            "turn_id": "turn_wave2_e2e_1",
            "session_id": "ses_qc_1",
            "text": "帮我查一下之前提到的预算文件，并看看媒体转译层状态",
            "incognito": false,
        }),
        &disc_opts,
    )
    .await
    .unwrap();

    assert_eq!(qc_resp["status"], "completed");
    assert_eq!(qc_resp["backend_used"], "zcode");
    assert_eq!(qc_resp["model_used"], "gpt-wave2-pro");
    assert!(
        qc_resp["reply_markdown"]
            .as_str()
            .unwrap_or("")
            .contains("年度预算_2026.xlsx")
    );
    assert!(
        !qc_resp["reply_markdown"]
            .as_str()
            .unwrap_or("")
            .contains("<think>"),
        "<think> tags must be cleanly stripped into thinking field"
    );
    assert!(qc_resp["thinking"].as_str().is_some());

    // Verify ordered 6-color Trace Dots: `thinking` (gray) + `memory` (purple) + `adapter` (cyan)
    let dots = qc_resp["trace_dots"].as_array().unwrap();
    let dot_kinds: Vec<&str> = dots
        .iter()
        .filter_map(|d| d["kind"].as_str())
        .collect();
    assert_eq!(dot_kinds.first().copied(), Some("thinking"));
    assert!(dot_kinds.contains(&"memory"));
    assert!(dot_kinds.contains(&"adapter"));

    // Verify Quick-Chat LLM request received `[Personal OS Memory]` AND all 7 AIOS tools
    {
        let reqs = mock_state.captured_requests.lock().unwrap();
        assert!(reqs.len() >= 2);
        let first_req = &reqs[0];
        let sys_content = first_req["messages"][0]["content"].as_str().unwrap_or("");
        assert!(sys_content.contains("[Personal OS Memory"));
        assert!(sys_content.contains("年度预算_2026.xlsx"));

        let tool_names: Vec<&str> = first_req["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["function"]["name"].as_str())
            .collect();
        for expected in required_7_tools {
            assert!(
                tool_names.contains(&expected),
                "Quick-Chat tools missing '{}'; got {:?}",
                expected,
                tool_names
            );
        }
    }

    // Verify `ses_qc_1` was persisted exactly ONCE (2 messages: 1 user + 1 assistant, no double recording!)
    let ses_detail = core
        .handle_trusted_ui_rpc(
            "ses_chk".into(),
            UiRpcRequest::ModuleRpc {
                domain: "memory_hub".into(),
                action: "get_session".into(),
                payload: json!({ "session_id": "ses_qc_1" }),
            },
        )
        .await;
    assert!(ses_detail.ok);
    let msgs = ses_detail.result.unwrap()["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        msgs.len(),
        2,
        "Quick-Chat turn must record exactly 1 user + 1 assistant message (got {})",
        msgs.len()
    );
}
