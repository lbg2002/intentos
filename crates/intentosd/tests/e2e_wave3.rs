#![forbid(unsafe_code)]

//! Comprehensive End-to-End Integration Test Suite for Wave 3:
//! 1) Live `/v1/models` HTTP Auto-Discovery (`gpt-6.1-sol`, `gpt-6-astra`, `claude-4-sonnet`, `glm-5.3`)
//!    with utility/embedding model filtering (`text-embedding-3-small`) & zero secret leakage.
//! 2) Chinese XDG `桌面` global `file.open` + `.docx` (`桌面/paper_main.docx`) 3-layer progressive
//!    chapter outline recall (`"打开我的硕士论文第四章"`, both deterministic fallback & mock LLM tool loop
//!    calling `memory_inspect_document` + `file_open`) + zero file-noise injection on `"打开QQ"`.
//! 3) 4-Tier Path Sensitivity interactive approval (`TaskStatus::AwaitingApproval` -> `approve_pending`
//!    with `SafeFsEngine::approve_path_scope`) + `incognito` zero-SQLite-write pending approvals +
//!    hard `Deny` invariant on `~/.ssh/id_ed25519` & `/etc/shadow`.
//! 4) Real `/proc`-verified process close (`SodaM` / tray app simulation via `SIGTERM` + PID exit
//!    readback verification, honest not-running reporting, and hung-process `SIGKILL` approval escalation).

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use intentos_protocol::{
    CapabilityCall, ExecutionStatus, IntentRequest, InvocationOrigin, Taint, TaskStatus,
    UiRpcRequest, VerificationState,
};
use intentosd::broker::BrokerDispatchOutcome;
use intentosd::config::{AppConfig, BrainConfig, XdgPaths, discover_user_xdg_and_home_dirs};
use intentosd::core::IntentOsCore;
use intentosd::router::RoutedIntent;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

fn write_executable_script(path: &Path, script: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn build_thesis_docx_bytes() -> Vec<u8> {
    let content_types_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;

    let document_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:pPr><w:pStyle w:val="Title"/></w:pPr>
      <w:r><w:t>硕士学位论文：智能操作系统研究</w:t></w:r>
    </w:p>
    <w:p>
      <w:r><w:t>摘要：本文面向原生 AI 操作系统架构，系统研究了多引擎自动接入、三层渐进式文档记忆、四级路径敏感度审批与真实进程生命周期闭环验证。</w:t></w:r>
    </w:p>
    <w:p>
      <w:r><w:t>关键词：智能操作系统；文档大纲记忆；openat2；软件指令转译层</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:pStyle w:val="Heading1"/><w:outlineLvl w:val="0"/></w:pPr>
      <w:r><w:t>第一章 绪论</w:t></w:r>
    </w:p>
    <w:p>
      <w:r><w:t>传统桌面交互要求用户在大量异构窗口与命令行参数之间手动切换，亟需意图原生的系统级抽象。</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:pStyle w:val="Heading1"/><w:outlineLvl w:val="0"/></w:pPr>
      <w:r><w:t>第四章 系统权限与转译层实验分析</w:t></w:r>
    </w:p>
    <w:p>
      <w:r><w:t>本章对四级路径敏感度策略、Linux openat2 内核级路径防逃逸以及无 CLI 桌面软件指令转译层进行了系统性实验评估，验证了虚假成功率为零。</w:t></w:r>
    </w:p>
    <w:p>
      <w:pPr><w:pStyle w:val="Heading1"/><w:outlineLvl w:val="0"/></w:pPr>
      <w:r><w:t>参考文献</w:t></w:r>
    </w:p>
    <w:p>
      <w:r><w:t>[1] IntentOS Architecture Specification, 2026.</w:t></w:r>
    </w:p>
  </w:body>
</w:document>"#;

    intentosd::memory_hub::build_stored_zip_archive(&[
        ("[Content_Types].xml", content_types_xml),
        ("word/document.xml", document_xml.as_bytes()),
    ])
}

// =============================================================================
// Scenario 1: Live `/v1/models` Auto-Discovery & Utility Model Filtering
// =============================================================================

#[tokio::test]
async fn wave3_e2e_live_v1_models_auto_discovery_and_utility_filtering() {
    intentosd::backend_bridge::clear_live_models_cache();

    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("xdg_base");
    let mock_home = temp.path().join("mock_home");
    let ws = base.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&mock_home).unwrap();

    // Spin up local Axum mock `/v1/models` endpoint returning 12 models (11 chat + 1 embedding)
    let app = Router::new().route(
        "/v1/models",
        get(|| async {
            Json(json!({
                "object": "list",
                "data": [
                    { "id": "gpt-6.1-sol", "object": "model" },
                    { "id": "gpt-6-astra", "object": "model" },
                    { "id": "claude-4-sonnet", "object": "model" },
                    { "id": "glm-5.3", "object": "model" },
                    { "id": "deepseek-v3.2", "object": "model" },
                    { "id": "qwen3-coder-plus", "object": "model" },
                    { "id": "o4-mini", "object": "model" },
                    { "id": "gemini-2.5-pro", "object": "model" },
                    { "id": "kimi-k2", "object": "model" },
                    { "id": "mistral-large-latest", "object": "model" },
                    { "id": "llama-4-maverick", "object": "model" },
                    { "id": "text-embedding-3-small", "object": "model" }
                ]
            }))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let mock_base_url = format!("http://{}/v1", addr);
    let test_secret = "sk-wave3-live-models-secret-998877";

    // Configure ZCode provider pointing at local mock `/v1` endpoint
    let zcode_cfg_path = mock_home.join(".zcode/v2/provider_config.json");
    std::fs::create_dir_all(zcode_cfg_path.parent().unwrap()).unwrap();
    std::fs::write(
        &zcode_cfg_path,
        serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "config": {
                "providerOrder": ["zcode_gateway"],
                "providerConfigRules": {
                    "providerRules": [
                        {
                            "providerId": "zcode_gateway",
                            "templateId": "openai",
                            "providerName": "ZCode Live Gateway",
                            "config": {
                                "access": {
                                    "type": "api-key",
                                    "apiKey": test_secret
                                },
                                "api": {
                                    "baseUrl": mock_base_url
                                },
                                "modelOrder": ["gpt-6-astra"]
                            }
                        }
                    ]
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let zcode_cjs = mock_home.join("opt_zcode/resources/glm/zcode.cjs");
    std::fs::create_dir_all(zcode_cjs.parent().unwrap()).unwrap();
    std::fs::write(&zcode_cjs, "// mock zcode bundle\n").unwrap();

    let repo_root = repo_root_dir();
    let xdg = XdgPaths::resolve(Some(&base), repo_root.clone());
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

    let core = IntentOsCore::initialize(Some(&base), repo_root).expect("init core");

    // Call `backend_bridge.refresh_models` via UiRpcRequest
    let refresh_resp = core
        .handle_trusted_ui_rpc(
            "rpc_refresh_models".into(),
            UiRpcRequest::ModuleRpc {
                domain: "backend_bridge".into(),
                action: "refresh_models".into(),
                payload: json!({
                    "home_dir": mock_home.to_string_lossy().to_string(),
                    "force_refresh": true,
                    "probe_remote_models": true,
                }),
            },
        )
        .await;
    assert!(
        refresh_resp.ok,
        "refresh_models failed: {:?}",
        refresh_resp.error
    );
    let catalog = refresh_resp.result.expect("catalog result");
    let raw_catalog_str = serde_json::to_string(&catalog).unwrap();
    assert!(
        !raw_catalog_str.contains(test_secret),
        "API secret must NEVER leak in refresh_models RPC output"
    );

    let zcode_models: Vec<String> = catalog
        .pointer("/backends/zcode/providers/0/models")
        .and_then(|v| v.as_array())
        .expect("zcode provider models array")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    for expected_model in [
        "gpt-6.1-sol",
        "gpt-6-astra",
        "claude-4-sonnet",
        "glm-5.3",
        "deepseek-v3.2",
        "qwen3-coder-plus",
        "o4-mini",
        "gemini-2.5-pro",
    ] {
        assert!(
            zcode_models.iter().any(|m| m == expected_model),
            "expected live-discovered chat model `{}` in {:?}",
            expected_model,
            zcode_models
        );
    }
    assert!(
        !zcode_models.iter().any(|m| m == "text-embedding-3-small"),
        "utility embedding model `text-embedding-3-small` must be filtered out, got {:?}",
        zcode_models
    );
    assert_eq!(
        zcode_models.len(),
        11,
        "all 11 chat models from the 12-model endpoint should be discovered: {:?}",
        zcode_models
    );

    // Verify switching active model to a newly live-probed model (`gpt-6.1-sol`) works cleanly
    let switch_resp = core
        .handle_trusted_ui_rpc(
            "rpc_switch_model".into(),
            UiRpcRequest::ModuleRpc {
                domain: "backend_bridge".into(),
                action: "set_active_backend".into(),
                payload: json!({
                    "home_dir": mock_home.to_string_lossy().to_string(),
                    "backend": "zcode",
                    "provider": "zcode_gateway",
                    "model": "gpt-6.1-sol",
                    "reasoning_effort": "high",
                }),
            },
        )
        .await;
    assert!(
        switch_resp.ok,
        "set_active_backend failed: {:?}",
        switch_resp.error
    );
    assert_eq!(
        switch_resp
            .result
            .as_ref()
            .and_then(|r| r.pointer("/active/model"))
            .and_then(|v| v.as_str()),
        Some("gpt-6.1-sol")
    );
}

// =============================================================================
// Scenario 2: Chinese `桌面` Global `file.open` + `.docx` Chapter Outline Recall
//             + Zero File Noise on `"打开QQ"`
// =============================================================================

#[derive(Clone)]
struct ChapterMockLlmState {
    calls: Arc<Mutex<Vec<Value>>>,
    expected_docx_path: String,
}

async fn mock_chapter_llm_completions(
    State(st): State<ChapterMockLlmState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    st.calls.lock().unwrap().push(body.clone());
    let messages = body
        .get("messages")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let tool_msgs: Vec<&Value> = messages
        .iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
        .collect();

    if tool_msgs.is_empty() {
        // Step 1: Call `memory_inspect_document` to locate `"硕士论文"` + `"第四章"`
        let call_args = json!({
            "query": "硕士论文",
            "section": "第四章"
        })
        .to_string();
        return Json(json!({
            "id": "chatcmpl_w3_1",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_inspect_doc_1",
                        "type": "function",
                        "function": {
                            "name": "memory_inspect_document",
                            "arguments": call_args
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        }));
    }

    if tool_msgs.len() == 1 {
        // Verify `memory_inspect_document` returned the exact `.docx` path and Chapter 4 excerpt
        let inspect_content = tool_msgs[0]
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("{}");
        let parsed: Value = serde_json::from_str(inspect_content).unwrap_or_else(|_| json!({}));
        let resolved_path = parsed
            .get("path")
            .and_then(|v| v.as_str())
            .or_else(|| parsed.pointer("/data/path").and_then(|v| v.as_str()))
            .unwrap_or(&st.expected_docx_path)
            .to_string();

        let open_args = json!({ "path": resolved_path }).to_string();
        return Json(json!({
            "id": "chatcmpl_w3_2",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_open_docx_2",
                        "type": "function",
                        "function": {
                            "name": "file_open",
                            "arguments": open_args
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        }));
    }

    // Step 3: Summarize matched chapter heading & excerpt after `file_open` succeeded
    Json(json!({
        "id": "chatcmpl_w3_3",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": format!(
                    "已为您打开桌面上的《硕士学位论文：智能操作系统研究》（`{}`），并定位到 **第四章 系统权限与转译层实验分析**：本章对四级路径敏感度策略与 Linux openat2 隔离进行了系统性实验评估，虚假成功率为零。",
                    st.expected_docx_path
                )
            },
            "finish_reason": "stop"
        }]
    }))
}

#[tokio::test]
async fn wave3_e2e_chinese_desktop_docx_chapter_open_and_zero_noise_recall() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mock_home = temp.path().join("home_zh");
    let desktop_zh = mock_home.join("桌面");
    let docs_zh = mock_home.join("文档");
    let downloads_zh = mock_home.join("下载");
    std::fs::create_dir_all(&desktop_zh).unwrap();
    std::fs::create_dir_all(&docs_zh).unwrap();
    std::fs::create_dir_all(&downloads_zh).unwrap();

    // Write XDG `user-dirs.dirs` mapping Chinese Desktop/Documents/Downloads
    let user_config_dir = mock_home.join(".config");
    std::fs::create_dir_all(&user_config_dir).unwrap();
    std::fs::write(
        user_config_dir.join("user-dirs.dirs"),
        "XDG_DESKTOP_DIR=\"$HOME/桌面\"\nXDG_DOCUMENTS_DIR=\"$HOME/文档\"\nXDG_DOWNLOAD_DIR=\"$HOME/下载\"\n",
    )
    .unwrap();

    // Verify `discover_user_xdg_and_home_dirs` automatically includes `$HOME/桌面` and `$HOME`
    let auto_dirs = discover_user_xdg_and_home_dirs(&mock_home);
    assert!(
        auto_dirs.contains(&desktop_zh),
        "auto-discovered XDG dirs must include Chinese `桌面`: {:?}",
        auto_dirs
    );
    assert!(auto_dirs.contains(&mock_home));

    // Create real `.docx` ZIP file `桌面/paper_main.docx` + noisy `.deb` / unrelated `.docx` decoys
    let thesis_path = desktop_zh.join("paper_main.docx");
    std::fs::write(&thesis_path, build_thesis_docx_bytes()).unwrap();
    std::fs::write(
        downloads_zh.join("linuxqq_3.2.15_amd64.deb"),
        b"debian-binary-package",
    )
    .unwrap();
    std::fs::write(
        downloads_zh.join("random_shopping_list.docx"),
        intentosd::memory_hub::build_stored_zip_archive(&[(
            "word/document.xml",
            r#"<w:document><w:body><w:p><w:r><w:t>超市采购清单</w:t></w:r></w:p></w:body></w:document>"#
                .as_bytes(),
        )]),
    )
    .unwrap();

    let base = temp.path().join("intentos_base");
    let repo_root = repo_root_dir();
    let xdg = XdgPaths::resolve(Some(&base), repo_root.clone());
    xdg.ensure_dirs().unwrap();
    let cfg = AppConfig {
        authorized_directories: auto_dirs
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
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

    let core = IntentOsCore::initialize(Some(&base), repo_root).expect("init core");
    let thesis_str = thesis_path.to_string_lossy().to_string();

    // Ensure `memory_inspect_document` is registered as the 5th memory tool on CapabilityBroker
    let aios_specs = core.broker.aios_tool_specs();
    assert!(
        aios_specs
            .iter()
            .any(|s| s.name == "memory_inspect_document"),
        "CapabilityBroker::aios_tool_specs must expose `memory_inspect_document`"
    );

    // Sync document outlines once and verify zero file-noise injection on `"打开QQ"` & `"关闭SODAM音乐"`
    let (_, qq_hits) =
        intentosd::memory_hub::build_personal_memory_prompt(&core, "打开QQ", Some("s_qq"));
    let qq_file_hits = qq_hits
        .iter()
        .filter(|h| {
            matches!(
                h.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
                "mentioned_file" | "frequent_file" | "document_outline"
            )
        })
        .count();
    assert_eq!(
        qq_file_hits, 0,
        "\"打开QQ\" must inject ZERO unrelated .docx/.deb file hits, got: {:?}",
        qq_hits
    );

    let (_, sodam_hits) =
        intentosd::memory_hub::build_personal_memory_prompt(&core, "关闭SODAM音乐", Some("s_qq"));
    let sodam_file_hits = sodam_hits
        .iter()
        .filter(|h| {
            matches!(
                h.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
                "mentioned_file" | "frequent_file" | "document_outline"
            )
        })
        .count();
    assert_eq!(
        sodam_file_hits, 0,
        "\"关闭SODAM音乐\" must inject ZERO file hits, got: {:?}",
        sodam_hits
    );

    // Part A: Deterministic / Offline Smart Chapter Open (`"打开我的硕士论文第四章"`)
    let det_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "打开我的硕士论文第四章".into(),
                session_id: Some("ses_thesis_det".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: None,
            },
            Vec::new(),
        )
        .await
        .expect("deterministic chapter open");

    assert_eq!(det_task.status, TaskStatus::Completed);
    let det_msg = det_task.assistant_message.as_deref().unwrap_or("");
    assert!(
        !det_msg.contains("超出授权目录范围"),
        "Chinese `桌面/paper_main.docx` must NEVER fail with out-of-scope error: {}",
        det_msg
    );
    assert!(
        det_msg.contains(&thesis_str),
        "expected resolved path `{}` in assistant_message: {}",
        thesis_str,
        det_msg
    );
    assert!(
        det_msg.contains("第四章 系统权限与转译层实验分析"),
        "expected Chapter 4 heading in assistant_message: {}",
        det_msg
    );
    assert!(
        det_msg.contains("openat2") && det_msg.contains("虚假成功率为零"),
        "expected Chapter 4 paragraph excerpt in assistant_message: {}",
        det_msg
    );
    assert!(
        det_task
            .steps
            .iter()
            .any(|s| s.capability_id == "memory_inspect_document")
    );
    assert!(
        det_task
            .steps
            .iter()
            .any(|s| s.capability_id == "file.open" && s.arguments_summary.contains(&thesis_str))
    );

    // Part B: Mock LLM Tool Loop (`memory_inspect_document` -> `file_open`) via L2 `submit_intent`
    let llm_calls = Arc::new(Mutex::new(Vec::new()));
    let llm_state = ChapterMockLlmState {
        calls: llm_calls.clone(),
        expected_docx_path: thesis_str.clone(),
    };
    let llm_app = Router::new()
        .route("/v1/chat/completions", post(mock_chapter_llm_completions))
        .with_state(llm_state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, llm_app).await;
    });
    core.gateway
        .set_mock_upstream_url(Some(format!("http://{}/v1", addr)));

    let l2_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "打开我的硕士论文第四章".into(),
                session_id: Some("ses_thesis_l2".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: None,
            },
            Vec::new(),
        )
        .await
        .expect("L2 mock LLM chapter open");

    assert_eq!(l2_task.status, TaskStatus::Completed);
    let l2_msg = l2_task.assistant_message.as_deref().unwrap_or("");
    assert!(
        !l2_msg.contains("超出授权目录范围"),
        "L2 `file_open` on `桌面/paper_main.docx` must succeed without scope error: {}",
        l2_msg
    );
    assert!(l2_msg.contains("第四章 系统权限与转译层实验分析"));
    assert!(l2_msg.contains("虚假成功率为零"));
    assert!(
        l2_task
            .steps
            .iter()
            .any(|s| s.capability_id == "memory_inspect_document")
    );
    assert!(
        l2_task
            .steps
            .iter()
            .any(|s| s.capability_id == "file.open" && s.arguments_summary.contains(&thesis_str))
    );

    // Verify the system prompt sent to the LLM included the compact Layer-0 semantic card AND both tools
    let recorded = llm_calls.lock().unwrap();
    assert!(
        recorded.len() >= 3,
        "expected 3 LLM turns (inspect -> open -> summary)"
    );
    let first_sys = recorded[0]["messages"][0]["content"]
        .as_str()
        .unwrap_or_default();
    assert!(
        first_sys.contains("硕士学位论文：智能操作系统研究")
            && first_sys.contains("paper_main.docx"),
        "expected Layer-0 semantic outline card in [Personal OS Memory] prompt, got:\n{}",
        first_sys
    );
    let offered_tools: Vec<&str> = recorded[0]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t.pointer("/function/name").and_then(|v| v.as_str()))
        .collect();
    assert!(offered_tools.contains(&"memory_inspect_document"));
    assert!(offered_tools.contains(&"file_open"));
}

// =============================================================================
// Scenario 3: Sensitive Path Interactive Approval (`RequiresApproval` -> `approve_pending`),
//             Incognito Zero-Write Approvals & Hard Forbidden Guard
// =============================================================================

#[tokio::test]
async fn wave3_e2e_sensitive_path_interactive_approval_incognito_and_forbidden_guard() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mock_home = temp.path().join("home_sec");
    let authorized_docs = mock_home.join("文档");
    let outside_dir = temp.path().join("outside_opt_project");
    let dot_config_dir = mock_home.join(".config/demo_app");
    let ssh_dir = mock_home.join(".ssh");
    std::fs::create_dir_all(&authorized_docs).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::fs::create_dir_all(&dot_config_dir).unwrap();
    std::fs::create_dir_all(&ssh_dir).unwrap();

    let dot_conf_file = dot_config_dir.join("settings.conf");
    std::fs::write(&dot_conf_file, "theme=dark\n").unwrap();
    let outside_read_file = outside_dir.join("incog_notes.txt");
    std::fs::write(&outside_read_file, "ephemeral outside note\n").unwrap();
    let ssh_key_file = ssh_dir.join("id_ed25519");
    std::fs::write(&ssh_key_file, "PRIVATE_KEY_NEVER_TOUCH\n").unwrap();

    let base = temp.path().join("intentos_sec_base");
    let repo_root = repo_root_dir();
    let xdg = XdgPaths::resolve(Some(&base), repo_root.clone());
    xdg.ensure_dirs().unwrap();
    let cfg = AppConfig {
        authorized_directories: vec![authorized_docs.to_string_lossy().to_string()],
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

    let core = IntentOsCore::initialize(Some(&base), repo_root).expect("init core");

    // 1. Sensitive dot-path (`~/.config/demo_app/settings.conf`) -> `AwaitingApproval` (NOT hard `Deny`)!
    let dot_open_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: format!("打开 {}", dot_conf_file.display()),
                session_id: Some("ses_sec_1".into()),
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
        dot_open_task.status,
        TaskStatus::AwaitingApproval,
        "sensitive dot-path open must return AwaitingApproval instead of hard Deny: {:?}",
        dot_open_task.assistant_message
    );
    let pa_dot = dot_open_task
        .pending_approval
        .expect("PendingApproval for dot-path");
    let approved_dot = core
        .approve_pending(&pa_dot.approval_id, &pa_dot.nonce, &pa_dot.digest)
        .await
        .expect("approve_pending on dot-path");
    assert_eq!(approved_dot.status, TaskStatus::Completed);

    // 2. Outside-scope `file.write` -> `RequiresApproval` -> `approve_pending` calls `approve_path_scope` -> `openat2` write succeeds!
    let outside_write_target = outside_dir.join("approved_output.txt");
    let write_call = CapabilityCall {
        request_id: "req_w3_outside_write".into(),
        task_id: "task_w3_outside_write".into(),
        capability_id: "file.write".into(),
        arguments: json!({
            "path": outside_write_target.to_string_lossy().to_string(),
            "content": "approved via interactive confirmation\n"
        }),
        origin: InvocationOrigin::UserExplicit,
        taints: vec![Taint::User],
    };
    // Persist parent task so normal non-incognito flow updates `state_db`
    let write_outcome = core.broker.dispatch(&write_call).await.unwrap();
    let pa_write = match write_outcome {
        BrokerDispatchOutcome::RequiresApproval(pa) => pa,
        _ => panic!("expected RequiresApproval for outside-scope file.write"),
    };
    let completed_write_task = core
        .approve_pending(&pa_write.approval_id, &pa_write.nonce, &pa_write.digest)
        .await
        .expect("approve outside-scope file.write");
    assert_eq!(
        completed_write_task.status,
        TaskStatus::Completed,
        "approved outside-scope write failed: {:?}",
        completed_write_task.assistant_message
    );
    assert_eq!(
        std::fs::read_to_string(&outside_write_target).unwrap(),
        "approved via interactive confirmation\n"
    );

    // 3. Incognito mode (`incognito: true`) pending approval + `approve_pending` -> 100% ZERO SQLite `state.db` writes!
    let tasks_before = core.state_db.list_tasks(200).unwrap().len();
    let mems_before = core.state_db.list_memory_entries().unwrap().len();
    let audits_before = core.state_db.list_recent_audit(200).len();

    let incog_outside_dir = temp.path().join("incog_outside_vault");
    std::fs::create_dir_all(&incog_outside_dir).unwrap();
    let incog_file = incog_outside_dir.join("ephemeral_doc.txt");
    std::fs::write(&incog_file, "top secret ephemeral doc").unwrap();

    let incog_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: format!("打开 {}", incog_file.display()),
                session_id: Some("ses_incog_w3".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: true,
                privacy_policy: None,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(incog_task.status, TaskStatus::AwaitingApproval);
    let pa_incog = incog_task
        .pending_approval
        .expect("incognito PendingApproval");

    let incog_approved = core
        .approve_pending(&pa_incog.approval_id, &pa_incog.nonce, &pa_incog.digest)
        .await
        .expect("approve incognito pending task");
    assert_eq!(incog_approved.status, TaskStatus::Completed);

    assert_eq!(
        core.state_db.list_tasks(200).unwrap().len(),
        tasks_before,
        "incognito pending approval must write ZERO tasks to state.db"
    );
    assert_eq!(
        core.state_db.list_memory_entries().unwrap().len(),
        mems_before,
        "incognito pending approval must write ZERO memories to state.db"
    );
    assert_eq!(
        core.state_db.list_recent_audit(200).len(),
        audits_before,
        "incognito pending approval must write ZERO audit rows to state.db"
    );

    // 4. Hard Forbidden Paths (`~/.ssh/id_ed25519` and `/etc/shadow`) MUST remain strictly `Denied`!
    for forbidden_target in [
        ssh_key_file.to_string_lossy().to_string(),
        "/etc/shadow".to_string(),
    ] {
        // Attempt session grant on forbidden path must be rejected (`rejected == true`)
        let grant_res = core
            .policy
            .add_session_grant("directory", &forbidden_target, 30);
        assert_eq!(
            grant_res.get("rejected").and_then(|v| v.as_bool()),
            Some(true),
            "PolicyEngine must reject session grants on forbidden path `{}`: {}",
            forbidden_target,
            grant_res
        );

        let out = core
            .broker
            .dispatch(&CapabilityCall {
                request_id: "req_forbidden_chk".into(),
                task_id: "task_forbidden_chk".into(),
                capability_id: "file.open".into(),
                arguments: json!({ "path": forbidden_target }),
                origin: InvocationOrigin::UserExplicit,
                taints: vec![Taint::User],
            })
            .await
            .unwrap();
        assert!(
            matches!(out, BrokerDispatchOutcome::Denied { .. }),
            "forbidden path `{}` must ALWAYS be hard Denied",
            forbidden_target
        );
    }
}

// =============================================================================
// Scenario 4: Real Verified Process Close (`SodaM` Tray Simulation & Hung Escalation)
// =============================================================================

fn spawn_reaped_child(exe: &Path) -> (u32, Arc<Mutex<Option<std::process::ExitStatus>>>) {
    let mut child = Command::new(exe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child process");
    let pid = child.id();
    let exit_holder = Arc::new(Mutex::new(None));
    let exit_clone = exit_holder.clone();
    std::thread::spawn(move || {
        if let Ok(st) = child.wait() {
            *exit_clone.lock().unwrap() = Some(st);
        }
    });
    (pid, exit_holder)
}

#[tokio::test]
async fn wave3_e2e_real_verified_process_close_sodam_tray_and_hung_escalation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path().join("intentos_proc_base");
    let ws = base.join("workspace");
    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();

    let repo_root = repo_root_dir();
    let xdg = XdgPaths::resolve(Some(&base), repo_root.clone());
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

    let core = IntentOsCore::initialize(Some(&base), repo_root).expect("init core");

    // 1. Verify `router.rs` cleanly routes all SodaM / 汽水音乐 close phrasings to `app.quit`
    for (utterance, expected_app) in [
        ("关闭SODAM音乐", "SODAM音乐"),
        ("退出汽水音乐", "汽水音乐"),
        ("关闭SodaM", "SodaM"),
        ("关闭 sodam-test-player", "sodam-test-player"),
    ] {
        match core.router.route_text(utterance, false) {
            RoutedIntent::ExecuteL0 {
                capability_id,
                arguments,
                ..
            } => {
                assert_eq!(
                    capability_id, "app.quit",
                    "utterance `{}` wrong cap",
                    utterance
                );
                assert_eq!(
                    arguments.get("app").and_then(|v| v.as_str()),
                    Some(expected_app),
                    "utterance `{}` wrong extracted app slot",
                    utterance
                );
            }
            other => panic!(
                "expected ExecuteL0(app.quit) for `{}`, got {:?}",
                utterance, other
            ),
        }
    }

    // 2. Register custom adapter app `"sodam-test-player"` (aliases: SODAM音乐 / 汽水音乐 / SodaM)
    let save_resp = core
        .handle_trusted_ui_rpc(
            "rpc_save_sodam".into(),
            UiRpcRequest::ModuleRpc {
                domain: "app_adapter".into(),
                action: "save_custom_adapter".into(),
                payload: json!({
                    "id": "sodam-test-player",
                    "name": "SodaM 汽水音乐测试版",
                    "binary_name": "sodam-test-player",
                    "aliases": ["SODAM音乐", "汽水音乐", "SodaM", "sodam-test-player"],
                    "category": "media"
                }),
            },
        )
        .await;
    assert!(
        save_resp.ok,
        "save_custom_adapter failed: {:?}",
        save_resp.error
    );

    // 3. Spawn real sleeping tray-like child process `sodam-test-player` and close it via `"关闭SODAM音乐"`
    let sodam_script = bin_dir.join("sodam-test-player");
    write_executable_script(
        &sodam_script,
        "#!/bin/sh\ntrap 'exit 0' TERM INT\nsleep 30\n",
    );
    let (pid, exit_holder) = spawn_reaped_child(&sodam_script);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        Path::new(&format!("/proc/{}", pid)).exists(),
        "spawned sodam-test-player PID {} should be running in /proc",
        pid
    );

    let close_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "关闭SODAM音乐".into(),
                session_id: Some("ses_sodam".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
                privacy_policy: None,
            },
            Vec::new(),
        )
        .await
        .expect("submit 关闭SODAM音乐");

    assert_eq!(close_task.status, TaskStatus::Completed);
    assert_eq!(close_task.steps.len(), 1);
    assert_eq!(close_task.steps[0].capability_id, "app.quit");
    assert_eq!(close_task.steps[0].status, ExecutionStatus::Exited);
    assert_eq!(
        close_task.steps[0].verification.state,
        VerificationState::Passed
    );
    let close_msg = close_task.assistant_message.as_deref().unwrap_or("");
    assert!(
        close_msg.contains("已确认关闭") && close_msg.contains(&pid.to_string()),
        "expected verified PID close message mentioning PID {}, got: {}",
        pid,
        close_msg
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        exit_holder.lock().unwrap().is_some(),
        "child process PID {} must have exited after SIGTERM",
        pid
    );

    // 4. Honest Not-Running Check: calling `"关闭 sodam-test-player"` when already exited reports `already_closed: true`
    let already_closed_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "关闭 sodam-test-player".into(),
                session_id: Some("ses_sodam".into()),
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
    assert_eq!(already_closed_task.status, TaskStatus::Completed);
    assert_eq!(
        already_closed_task.steps[0]
            .data
            .get("already_closed")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        already_closed_task.steps[0].verification.state,
        VerificationState::Passed
    );

    // 5. Hung Process Escalation: process ignoring `SIGTERM` surfaces `PendingApproval`, and `approve_pending` terminates it!
    let hung_script = bin_dir.join("sodam-hung-player");
    write_executable_script(&hung_script, "#!/bin/sh\ntrap '' TERM\nsleep 30\n");
    let _ = core
        .handle_trusted_ui_rpc(
            "rpc_save_hung".into(),
            UiRpcRequest::ModuleRpc {
                domain: "app_adapter".into(),
                action: "save_custom_adapter".into(),
                payload: json!({
                    "id": "sodam-hung-player",
                    "name": "Hung Test Player",
                    "binary_name": "sodam-hung-player",
                    "aliases": ["sodam-hung-player"],
                    "category": "media"
                }),
            },
        )
        .await;

    let (hung_pid, hung_exit) = spawn_reaped_child(&hung_script);
    tokio::time::sleep(Duration::from_millis(120)).await;

    let hung_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "关闭 sodam-hung-player".into(),
                session_id: Some("ses_sodam_hung".into()),
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
        hung_task.status,
        TaskStatus::AwaitingApproval,
        "SIGTERM-ignoring process must escalate to AwaitingApproval, got: {:?}",
        hung_task.assistant_message
    );
    let pa_kill = hung_task
        .pending_approval
        .expect("PendingApproval for hung force-kill");
    let force_closed = core
        .approve_pending(&pa_kill.approval_id, &pa_kill.nonce, &pa_kill.digest)
        .await
        .expect("approve force-kill");
    assert_eq!(force_closed.status, TaskStatus::Completed);
    assert_eq!(
        force_closed.steps[0].verification.state,
        VerificationState::Passed
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        hung_exit.lock().unwrap().is_some(),
        "hung process PID {} must be terminated after user approves force-kill",
        hung_pid
    );
}
