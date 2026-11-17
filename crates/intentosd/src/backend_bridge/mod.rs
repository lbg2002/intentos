#![forbid(unsafe_code)]

//! Multi-Backend AI Engine Auto-Discovery & Quick-Chat Turn Bridge (`crates/intentosd/src/backend_bridge/`).
//!
//! Brings `gnome-quick-chat`'s multi-engine switching (`ZCode | Codex | Pi | OpenAI API`) into IntentOS Core:
//! - `detector`: Read-only local CLI & config auto-discovery (`~/.zcode`, `~/.codex`, `~/.pi`, `config_center`, local Ollama)
//!   with Core-only in-memory credential handling and zero external file mutation.
//! - `turn_engine`: Active backend persistence (`quick_chat_backend.json` with zero secrets), unified Quick-Chat turn execution,
//!   `<think>` & `reasoning_content` extraction, 6-color `Trace Dots` builder, cancellation/idempotency state machine,
//!   and automatic fallback to `core.submit_intent`.

pub mod broker_bridge;
pub mod detector;
pub mod providers_cli;
pub mod providers_http;
pub mod turn_checkpoint;
pub mod turn_engine;

pub use detector::{
    ActiveBackendSelection, BackendsCatalog, CatalogBackends, DiscoveredBackend,
    DiscoveredProvider, DiscoveryOptions, clear_backends_catalog_cache, clear_live_models_cache,
    discover_backends_catalog, discover_backends_catalog_fast, is_non_chat_utility_model,
    normalize_reasoning_effort, scrub_json_secrets,
};
pub use turn_engine::{
    ActiveTurnHandle, BackendExecutionMode, PersistedQuickChatBackend, ScopedZcodeRuntimeOverride,
    StepExecutionRecord, TraceDot, TurnEffectLedger, cancel_turn, extract_thinking_and_clean_reply,
    load_persisted_backend, poll_turn_events, resolve_active_selection,
    resume_approved_turn_with_options, send_quick_chat_turn_with_options,
    set_active_backend_with_options,
};

use crate::core::IntentOsCore;
use serde_json::{Value, json};
use std::path::PathBuf;

fn build_rpc_discovery_options(
    core: &IntentOsCore,
    payload: &Value,
    default_force_refresh: bool,
) -> DiscoveryOptions {
    let force_refresh = payload
        .get("force_refresh")
        .or_else(|| payload.get("refresh_remote"))
        .and_then(|v| v.as_bool())
        .unwrap_or(default_force_refresh);
    let mut opts = DiscoveryOptions::from_core(core, force_refresh);
    if let Some(hd) = payload
        .get("home_dir")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        opts.home_dir = PathBuf::from(hd);
        opts.include_system_paths = false;
        opts.allow_env_keys = false;
    }
    if let Some(prm) = payload.get("probe_remote_models").and_then(|v| v.as_bool()) {
        opts.probe_remote_models = prm;
    }
    opts
}

pub async fn handle_module_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    match action {
        "ping" => Ok(json!({
            "module": "backend_bridge",
            "status": "ready",
            "payload": payload,
        })),

        "get_backends_catalog" => {
            let opts = build_rpc_discovery_options(core, &payload, false);
            let catalog = discover_backends_catalog_fast(core, &opts).await;
            let mut val = serde_json::to_value(catalog)?;
            scrub_json_secrets(&mut val);
            Ok(val)
        }

        "refresh_models" => {
            let opts = build_rpc_discovery_options(core, &payload, true);
            let catalog = discover_backends_catalog_fast(core, &opts).await;
            let mut val = serde_json::to_value(catalog)?;
            scrub_json_secrets(&mut val);
            Ok(val)
        }

        "set_active_backend" => {
            let opts = build_rpc_discovery_options(core, &payload, false);
            let mut res = set_active_backend_with_options(core, &payload, &opts).await?;
            scrub_json_secrets(&mut res);
            Ok(res)
        }

        "send_quick_chat_turn" => {
            let opts = build_rpc_discovery_options(core, &payload, false);
            send_quick_chat_turn_with_options(core, &payload, &opts).await
        }

        "resume_approved_turn" => {
            // Server-side guard: never trust a UI's request for a session
            // grant for terminal execution. Check both in-memory and
            // crash-restored approval metadata before resuming.
            if matches!(
                payload.get("decision").and_then(Value::as_str),
                Some("session" | "scope")
            ) {
                let approval_id = payload.get("approval_id").and_then(Value::as_str).unwrap_or("");
                let live = core.policy.peek_pending_approval(approval_id);
                let stored = core.state_db.get_suspended_checkpoint_row(approval_id)?;
                let is_terminal = live.as_ref().is_some_and(|a| a.capability_id == "terminal.execute")
                    || stored.as_ref().is_some_and(|r| r.capability_id == "terminal.execute");
                if is_terminal {
                    anyhow::bail!("terminal.execute 不允许会话范围授权；请逐次批准或拒绝");
                }
            }
            let opts = build_rpc_discovery_options(core, &payload, false);
            resume_approved_turn_with_options(core, &payload, &opts).await
        }

        "cancel_turn" => Ok(cancel_turn(core, &payload)),

        "poll_turn_events" => Ok(poll_turn_events(&payload)),

        other => anyhow::bail!("backend_bridge: unknown action '{}'", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, BrainConfig, XdgPaths};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn setup_test_core() -> (tempfile::TempDir, Arc<IntentOsCore>) {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path().join("intentos_xdg");
        let ws = base.join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

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
        (temp, core)
    }

    fn write_executable(path: &Path, script: &str) {
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

    #[tokio::test]
    async fn test_auto_discovery_zcode_codex_pi_ollama_zero_mutation_and_secret_scrubbing() {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("mock_home");
        std::fs::create_dir_all(&mock_home).unwrap();

        // 1. Mock local Ollama `/api/tags` server
        let ollama_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ollama_addr = ollama_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = ollama_listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = r#"{"models":[{"name":"qwen2.5-coder:14b"},{"name":"deepseek-r1:8b"}]}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        // 2. Populate mock binaries in `~/.nvm/versions/node/v22.12.0/bin` and `~/.local/bin`
        let nvm_bin = mock_home.join(".nvm/versions/node/v22.12.0/bin");
        write_executable(&nvm_bin.join("node"), "#!/bin/sh\nexit 0\n");
        write_executable(&nvm_bin.join("pi"), "#!/bin/sh\necho pi\n");
        write_executable(
            &mock_home.join(".local/bin/codex"),
            "#!/bin/sh\necho codex\n",
        );
        let mock_zcode_cjs = mock_home.join("opt_zcode/resources/glm/zcode.cjs");
        std::fs::create_dir_all(mock_zcode_cjs.parent().unwrap()).unwrap();
        std::fs::write(&mock_zcode_cjs, "// mock zcode.cjs bundle\n").unwrap();

        // 3. Populate `~/.zcode`, `~/.codex`, and `~/.pi` with secrets
        let zcode_secret_1 = "sk-zcode-secret-alpha-998877";
        let zcode_secret_2 = "sk-zcode-bigmodel-secret-665544";
        let codex_secret = "sk-codex-secret-beta-332211";
        let pi_secret = "sk-pi-secret-gamma-774411";

        let zcode_prov_cfg_path = mock_home.join(".zcode/v2/provider_config.json");
        std::fs::create_dir_all(zcode_prov_cfg_path.parent().unwrap()).unwrap();
        let zcode_prov_raw = serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "config": {
                "providerOrder": ["zcode_openai_gw"],
                "providerConfigRules": {
                    "providerRules": [
                        {
                            "providerId": "zcode_openai_gw",
                            "templateId": "openai",
                            "providerName": "ZCode Local Proxy",
                            "config": {
                                "access": {
                                    "type": "api-key",
                                    "apiKey": zcode_secret_1
                                },
                                "api": {
                                    "baseUrl": "https://proxy.example.com/v1?api_key=leak_me_not"
                                },
                                "modelOrder": ["gpt-6-astra", "gpt-image-disabled"]
                            }
                        }
                    ]
                },
                "modelConfigRules": {
                    "providerModelRules": [
                        {
                            "providerId": "zcode_openai_gw",
                            "modelId": "gpt-image-disabled",
                            "config": { "enabled": false }
                        }
                    ]
                }
            }
        }))
        .unwrap();
        std::fs::write(&zcode_prov_cfg_path, &zcode_prov_raw).unwrap();

        let zcode_v2_cfg_path = mock_home.join(".zcode/v2/config.json");
        let zcode_v2_raw = serde_json::to_string_pretty(&json!({
            "provider": {
                "builtin:bigmodel": {
                    "name": "BigModel Plan",
                    "kind": "anthropic",
                    "enabled": true,
                    "options": {
                        "apiKey": zcode_secret_2,
                        "baseURL": "https://open.bigmodel.cn/api/anthropic"
                    },
                    "models": {
                        "GLM-5.3": {}
                    }
                }
            }
        }))
        .unwrap();
        std::fs::write(&zcode_v2_cfg_path, &zcode_v2_raw).unwrap();

        let codex_toml_path = mock_home.join(".codex/config.toml");
        std::fs::create_dir_all(codex_toml_path.parent().unwrap()).unwrap();
        let codex_toml_raw = format!(
            "model = \"gpt-6.1-sol\"\nmodel_provider = \"corp_codex\"\nmodel_reasoning_effort = \"high\"\n\n[model_providers.corp_codex]\nname = \"Corp Codex\"\nbase_url = \"https://codex.corp.example.com/v1\"\napi_key = \"{}\"\n",
            codex_secret
        );
        std::fs::write(&codex_toml_path, &codex_toml_raw).unwrap();

        let codex_cache_path = mock_home.join(".codex/models_cache.json");
        let codex_cache_raw = serde_json::to_string_pretty(&json!({
            "models": [
                { "slug": "gpt-6.1-sol", "supported_in_api": true },
                { "slug": "gpt-6.1-terra", "supported_in_api": true },
                { "slug": "internal-hidden", "supported_in_api": false }
            ]
        }))
        .unwrap();
        std::fs::write(&codex_cache_path, &codex_cache_raw).unwrap();

        let pi_models_path = mock_home.join(".pi/agent/models.json");
        std::fs::create_dir_all(pi_models_path.parent().unwrap()).unwrap();
        let pi_models_raw = serde_json::to_string_pretty(&json!({
            "defaultProvider": "openrouter",
            "defaultModel": "anthropic/claude-sonnet-4",
            "providers": {
                "openrouter": {
                    "name": "OpenRouter",
                    "api": "openai-completions",
                    "baseUrl": "https://openrouter.ai/api/v1",
                    "apiKey": pi_secret,
                    "models": [{ "id": "anthropic/claude-sonnet-4" }]
                }
            }
        }))
        .unwrap();
        std::fs::write(&pi_models_path, &pi_models_raw).unwrap();

        // 4. Run auto-discovery
        let mut opts = DiscoveryOptions::isolated_for_test(mock_home.clone());
        opts.opt_zcode_cjs = Some(mock_zcode_cjs.clone());
        opts.ollama_tags_url = Some(format!("http://{}/api/tags", ollama_addr));

        let catalog = discover_backends_catalog(&core, &opts).await;
        let mut catalog_json = serde_json::to_value(&catalog).unwrap();
        scrub_json_secrets(&mut catalog_json);
        let dumped = serde_json::to_string(&catalog_json).unwrap();

        // Verify zero secret leakage anywhere in catalog JSON (including URL query params!)
        for secret in [
            zcode_secret_1,
            zcode_secret_2,
            codex_secret,
            pi_secret,
            "leak_me_not",
        ] {
            assert!(
                !dumped.contains(secret),
                "SECURITY VIOLATION: secret '{}' leaked in catalog JSON!",
                secret
            );
        }

        // Verify ZCode parsed providers, filtered disabled image model, and auto-selected ZCode out of the box
        assert_eq!(catalog_json["backends"]["zcode"]["available"], true);
        let zcode_models = catalog_json["backends"]["zcode"]["models"]
            .as_array()
            .unwrap();
        assert!(zcode_models.contains(&json!("gpt-6-astra")));
        assert!(zcode_models.contains(&json!("GLM-5.3")));
        assert!(!zcode_models.contains(&json!("gpt-image-disabled")));

        assert_eq!(catalog_json["active"]["backend"], "zcode");
        assert_eq!(catalog_json["active"]["provider"], "zcode_openai_gw");
        assert_eq!(catalog_json["active"]["model"], "gpt-6-astra");
        assert_eq!(catalog_json["active"]["direct_http_capable"], true);

        // Verify Codex parsed config.toml + models_cache.json
        assert_eq!(catalog_json["backends"]["codex"]["available"], true);
        assert_eq!(
            catalog_json["backends"]["codex"]["default_model"],
            "gpt-6.1-sol"
        );
        assert_eq!(
            catalog_json["backends"]["codex"]["default_reasoning_effort"],
            "high"
        );
        let codex_models = catalog_json["backends"]["codex"]["models"]
            .as_array()
            .unwrap();
        assert!(codex_models.contains(&json!("gpt-6.1-terra")));
        assert!(!codex_models.contains(&json!("internal-hidden")));

        // Verify Pi & local Ollama discovery
        assert_eq!(catalog_json["backends"]["pi"]["available"], true);
        assert_eq!(
            catalog_json["backends"]["pi"]["default_model"],
            "anthropic/claude-sonnet-4"
        );
        let openai_provs = catalog_json["backends"]["openai"]["providers"]
            .as_array()
            .unwrap();
        assert!(openai_provs.iter().any(|p| {
            p["id"] == "ollama-local"
                && p["models"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("qwen2.5-coder:14b"))
        }));

        // Verify ZERO mutation of external user config files
        assert_eq!(
            std::fs::read_to_string(&zcode_prov_cfg_path).unwrap(),
            zcode_prov_raw
        );
        assert_eq!(
            std::fs::read_to_string(&zcode_v2_cfg_path).unwrap(),
            zcode_v2_raw
        );
        assert_eq!(
            std::fs::read_to_string(&codex_toml_path).unwrap(),
            codex_toml_raw
        );
        assert_eq!(
            std::fs::read_to_string(&codex_cache_path).unwrap(),
            codex_cache_raw
        );
        assert_eq!(
            std::fs::read_to_string(&pi_models_path).unwrap(),
            pi_models_raw
        );
    }

    #[tokio::test]
    async fn test_think_tag_extraction_and_openai_tool_loop_trace_dots() {
        // 1. Unit check `<think>` & `reasoning_content` extraction edge cases
        let (t1, clean1) = extract_thinking_and_clean_reply(
            "<think>\n第一步：检查显示器接口\n第二步：设置亮度为 45%\n</think>\n\n已为您调整亮度至 **45%**。",
            Some("前置推理预算检查通过"),
        );
        let thought_str = t1.expect("should extract thinking");
        assert!(thought_str.contains("前置推理预算检查通过"));
        assert!(thought_str.contains("第一步：检查显示器接口"));
        assert_eq!(clean1, "已为您调整亮度至 **45%**。");

        // Unclosed `<think>` fallback when output is truncated
        let (t2, clean2) =
            extract_thinking_and_clean_reply("结论先行。\n<think>后续补充未闭合思考", None);
        assert_eq!(t2.as_deref(), Some("后续补充未闭合思考"));
        assert_eq!(clean2, "结论先行。");

        // 2. End-to-end Quick-Chat turn against a local mock OpenAI server with tool call + `<think>`
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("home_think");
        std::fs::create_dir_all(&mock_home).unwrap();

        let call_counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = call_counter.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let cc = counter_clone.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 32768];
                    let _ = stream.read(&mut buf).await;
                    let idx = cc.fetch_add(1, Ordering::SeqCst);
                    let body = if idx == 0 {
                        serde_json::to_string(&json!({
                            "choices": [{
                                "message": {
                                    "role": "assistant",
                                    "reasoning_content": "用户觉得屏幕刺眼，准备将亮度调至 45%。",
                                    "content": "",
                                    "tool_calls": [{
                                        "id": "call_bright_1",
                                        "type": "function",
                                        "function": {
                                            "name": "display_brightness_set",
                                            "arguments": "{\"value\": 45}"
                                        }
                                    }]
                                }
                            }]
                        }))
                        .unwrap()
                    } else {
                        serde_json::to_string(&json!({
                            "choices": [{
                                "message": {
                                    "role": "assistant",
                                    "content": "<think>工具已成功返回并生成撤销记录</think>\n已将屏幕亮度调低至 **45%**，可随时点击圆点撤销。"
                                }
                            }]
                        }))
                        .unwrap()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let opts = DiscoveryOptions::isolated_for_test(mock_home);
        let secret_key = "sk-quick-chat-inline-test-secret-5566";
        let set_res = set_active_backend_with_options(
            &core,
            &json!({
                "backend": "openai",
                "provider": "local-mock-llm",
                "model": "deepseek-reasoner",
                "reasoning_effort": "high",
                "base_url": format!("http://{}/v1", addr),
                "api_key": secret_key
            }),
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(set_res["saved"], true);

        // Verify `quick_chat_backend.json` persisted on disk with ZERO secrets
        let persisted_raw =
            std::fs::read_to_string(core.paths.config_dir.join("quick_chat_backend.json")).unwrap();
        assert!(!persisted_raw.contains(secret_key));
        assert!(persisted_raw.contains("deepseek-reasoner"));

        // Execute untainted Quick-Chat turn with memory hit -> verifies `thinking` (gray), `memory` (purple), and `tool_ok` (green + changeset_id)
        let turn_res = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "text": "屏幕太刺眼了，帮我调到 45%",
                "memory_hits": [{ "title": "偏好屏幕亮度", "value": "夜间常用 45%" }],
                "reasoning_effort": "high"
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(turn_res["backend_used"], "openai");
        assert_eq!(turn_res["model_used"], "deepseek-reasoner");
        assert_eq!(
            turn_res["reply_markdown"],
            "已将屏幕亮度调低至 **45%**，可随时点击圆点撤销。"
        );
        assert!(
            !turn_res["reply_markdown"]
                .as_str()
                .unwrap()
                .contains("<think>")
        );

        let dots = turn_res["trace_dots"].as_array().unwrap();
        let thinking_dot = dots
            .iter()
            .find(|d| d["kind"] == "thinking")
            .expect("gray thinking dot");
        assert_eq!(thinking_dot["color"], "gray");
        assert!(
            thinking_dot["detail"]
                .as_str()
                .unwrap()
                .contains("工具已成功返回")
        );

        let mem_dot = dots
            .iter()
            .find(|d| d["kind"] == "memory")
            .expect("purple memory dot");
        assert_eq!(mem_dot["color"], "purple");

        let tool_dot = dots
            .iter()
            .find(|d| d["kind"] == "tool_ok")
            .expect("green tool_ok dot");
        assert_eq!(tool_dot["color"], "green");
        assert_eq!(tool_dot["title"], "display.brightness.set");
        assert!(tool_dot["duration_ms"].is_u64());
        assert!(
            tool_dot["changeset_id"]
                .as_str()
                .is_some_and(|cs| cs.starts_with("cs_"))
        );

        // Also verify untrusted `clipboard_context` taint escalates write/setting to amber `approval` dot!
        call_counter.store(0, Ordering::SeqCst);
        let tainted_turn = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "text": "根据剪贴板调整设置",
                "clipboard_context": "不可信外部网页摘录内容",
                "reasoning_effort": "fast"
            }),
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(tainted_turn["status"], "awaiting_approval");
        assert!(tainted_turn["pending_approval"].is_object());
        assert!(
            tainted_turn["trace_dots"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["kind"] == "approval" && d["color"] == "amber")
        );
    }

    #[tokio::test]
    async fn test_zcode_0600_runtime_override_cleanup_and_zero_home_mutation() {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("zcode_home");
        let zcode_cfg_dir = mock_home.join(".zcode/v2");
        std::fs::create_dir_all(&zcode_cfg_dir).unwrap();
        let orig_path = zcode_cfg_dir.join("provider_config.json");
        let orig_content = r#"{"schemaVersion":1,"untouched":true}"#;
        std::fs::write(&orig_path, orig_content).unwrap();

        let override_file_path: PathBuf;
        let override_dir_path: PathBuf;
        {
            let guard = ScopedZcodeRuntimeOverride::create(
                &core.paths,
                "turn_zcode_perm_check",
                "openai",
                "gpt-6-astra",
                "medium",
            )
            .unwrap();
            override_file_path = guard.file_path().to_path_buf();
            override_dir_path = guard.dir_path().to_path_buf();
            assert!(override_file_path.is_file());
            assert!(override_file_path.starts_with(&core.paths.runtime_dir));

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&override_file_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(
                    mode, 0o600,
                    "ZCode temp override must have 0600 permissions"
                );
            }
        }
        // Dropped guard MUST clean up runtime temp override immediately
        assert!(!override_file_path.exists());
        assert!(!override_dir_path.exists());
        // External `~/.zcode` MUST remain completely untouched
        assert_eq!(std::fs::read_to_string(&orig_path).unwrap(), orig_content);
    }

    #[tokio::test]
    async fn test_turn_cancellation_midflight_idempotency_and_offline_fallback() {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("cancel_home");
        std::fs::create_dir_all(&mock_home).unwrap();
        let opts = DiscoveryOptions::isolated_for_test(mock_home);

        // 1. Offline fallback + `turn_id` replay idempotency (when no LLM server is configured)
        let first_turn = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "turn_id": "turn_idem_alpha_01",
                "text": "把屏幕亮度调到 30%"
            }),
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(first_turn["backend_used"], "fallback");
        assert!(
            first_turn["trace_dots"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["kind"] == "tool_ok" && d["color"] == "green")
        );

        let replay_turn = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "turn_id": "turn_idem_alpha_01",
                "text": "把屏幕亮度调到 30%"
            }),
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(replay_turn["idempotent_replay"], true);
        assert_eq!(replay_turn["task_id"], first_turn["task_id"]);

        // 2. Pre-cancellation before turn starts + repeated `cancel_turn` idempotency
        let c1 = cancel_turn(&core, &json!({ "turn_id": "turn_precancel_99" }));
        assert_eq!(c1["ok"], true);
        assert_eq!(c1["status"], "cancelled");

        let c2 = cancel_turn(&core, &json!({ "turn_id": "turn_precancel_99" }));
        assert_eq!(c2["ok"], true);
        assert_eq!(c2["idempotent"], true);
        assert_eq!(c2["status"], "already_cancelled");

        let aborted_pre = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "turn_id": "turn_precancel_99",
                "text": "这轮应当被立即中止"
            }),
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(aborted_pre["cancelled"], true);
        assert_eq!(aborted_pre["status"], "cancelled");

        // 3. Mid-flight cancellation against a slow upstream server
        let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_addr = slow_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = slow_listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "openai",
                "provider": "slow-upstream",
                "model": "gpt-4o-mini",
                "base_url": format!("http://{}/v1", slow_addr),
                "api_key": "sk-slow-test-key"
            }),
            &opts,
        )
        .await
        .unwrap();

        let core_bg = core.clone();
        let opts_bg = opts.clone();
        let started = Instant::now();
        let join = tokio::spawn(async move {
            send_quick_chat_turn_with_options(
                &core_bg,
                &json!({
                    "turn_id": "turn_midflight_cancel_01",
                    "text": "请写一篇很长的系统诊断报告"
                }),
                &opts_bg,
            )
            .await
            .unwrap()
        });

        tokio::time::sleep(Duration::from_millis(60)).await;
        let mid_cancel = cancel_turn(&core, &json!({ "turn_id": "turn_midflight_cancel_01" }));
        assert_eq!(mid_cancel["ok"], true);
        assert_eq!(mid_cancel["was_running"], true);

        let mid_res = join.await.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "Mid-flight cancel must abort promptly without waiting for 10s upstream!"
        );
        assert_eq!(mid_res["cancelled"], true);
        assert_eq!(mid_res["status"], "cancelled");
    }

    #[tokio::test]
    async fn test_live_models_discovery_force_refresh_and_utility_filtering() {
        clear_live_models_cache();
        let (_tmp, core) = setup_test_core();
        // `setup_test_core` sets `config_dir` to `<base>/config`, so `from_core` uses `<base>` as isolated `home_dir`!
        let mock_home = core.paths.config_dir.parent().unwrap().to_path_buf();

        let req_count = Arc::new(AtomicUsize::new(0));
        let req_count_bg = req_count.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let counter = req_count_bg.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let _ = stream.read(&mut buf).await;
                    let idx = counter.fetch_add(1, Ordering::SeqCst);
                    let mut data = vec![
                        json!({ "id": "gpt-5.4" }),
                        json!({ "id": "claude-sonnet-4-6" }),
                        json!({ "id": "deepseek-r1" }),
                        json!({ "id": "qwen3-coder-plus" }),
                        // Non-chat utility models that MUST be filtered out:
                        json!({ "id": "text-embedding-3-large" }),
                        json!({ "id": "bge-reranker-v2-m3" }),
                        json!({ "id": "omni-moderation-latest" }),
                        json!({ "id": "text-moderation-007" }),
                        json!({ "id": "whisper-1" }),
                        json!({ "id": "tts-1-hd" }),
                        json!({ "id": "dall-e-3" }),
                        json!({ "id": "gpt-image-1" }),
                        json!({ "id": "gpt-4o-realtime-preview" }),
                        json!({ "id": "gpt-4o-transcribe" }),
                    ];
                    if idx >= 1 {
                        data.push(json!({ "id": "glm-5.3-flash-live" }));
                    }
                    let body = serde_json::to_string(&json!({
                        "object": "list",
                        "data": data,
                    }))
                    .unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        // ZCode only lists 1 static model in `provider_config.json`, while live `/v1/models` serves 4+ chat models!
        let zcode_prov_path = mock_home.join(".zcode/v2/provider_config.json");
        std::fs::create_dir_all(zcode_prov_path.parent().unwrap()).unwrap();
        std::fs::write(
            &zcode_prov_path,
            serde_json::to_string_pretty(&json!({
                "schemaVersion": 1,
                "config": {
                    "providerOrder": ["openai"],
                    "providerConfigRules": {
                        "providerRules": [{
                            "providerId": "openai",
                            "templateId": "openai",
                            "providerName": "Local Gateway 8317",
                            "config": {
                                "access": { "apiKey": "sk-live-gw-secret-123" },
                                "api": { "baseUrl": format!("http://{}/v1", addr) },
                                "modelOrder": ["gpt-4o-mini"]
                            }
                        }]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        // Also seed a bare `.codex/config.toml` to verify Codex bridges the local OpenAI proxy!
        let codex_cfg_path = mock_home.join(".codex/config.toml");
        std::fs::create_dir_all(codex_cfg_path.parent().unwrap()).unwrap();
        std::fs::write(&codex_cfg_path, "model = \"gpt-5.4\"\n").unwrap();

        // 1. Initial `get_backends_catalog` probes `/v1/models` once and caches for 300s
        let cat1 = handle_module_rpc(&core, "get_backends_catalog", json!({}))
            .await
            .unwrap();
        assert_eq!(req_count.load(Ordering::SeqCst), 1);

        let zcode_models = cat1["backends"]["zcode"]["models"].as_array().unwrap();
        for expected in [
            "gpt-4o-mini",
            "gpt-5.4",
            "claude-sonnet-4-6",
            "deepseek-r1",
            "qwen3-coder-plus",
        ] {
            assert!(
                zcode_models.contains(&json!(expected)),
                "expected chat model {} in zcode.models: {:?}",
                expected,
                zcode_models
            );
        }
        for forbidden in [
            "text-embedding-3-large",
            "bge-reranker-v2-m3",
            "omni-moderation-latest",
            "text-moderation-007",
            "whisper-1",
            "tts-1-hd",
            "dall-e-3",
            "gpt-image-1",
            "gpt-4o-realtime-preview",
            "gpt-4o-transcribe",
        ] {
            assert!(
                !zcode_models.contains(&json!(forbidden)),
                "non-chat model {} must be filtered out!",
                forbidden
            );
        }
        assert_eq!(
            cat1["backends"]["zcode"]["providers"][0]["live_models_fetched"],
            true
        );

        // Codex should also share the local OpenAI proxy's full model list!
        let codex_models = cat1["backends"]["codex"]["models"].as_array().unwrap();
        assert!(codex_models.contains(&json!("claude-sonnet-4-6")));
        assert!(codex_models.contains(&json!("qwen3-coder-plus")));

        // 2. Second `get_backends_catalog` without `force_refresh` hits TTL cache (still 1 HTTP call)
        let cat_cached = handle_module_rpc(&core, "get_backends_catalog", json!({}))
            .await
            .unwrap();
        assert_eq!(req_count.load(Ordering::SeqCst), 1);
        assert!(
            !cat_cached["backends"]["zcode"]["models"]
                .as_array()
                .unwrap()
                .contains(&json!("glm-5.3-flash-live"))
        );

        // 3. Explicit `refresh_models` bypasses TTL cache (`force_refresh = true`) and discovers newly added model!
        let cat_refreshed = handle_module_rpc(&core, "refresh_models", json!({}))
            .await
            .unwrap();
        assert_eq!(req_count.load(Ordering::SeqCst), 2);
        assert!(
            cat_refreshed["backends"]["zcode"]["models"]
                .as_array()
                .unwrap()
                .contains(&json!("glm-5.3-flash-live"))
        );
    }

    #[tokio::test]
    async fn test_anthropic_messages_api_duplicate_loop_guard_and_broker_approval() {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("anth_home");
        std::fs::create_dir_all(&mock_home).unwrap();
        let opts = DiscoveryOptions::isolated_for_test(mock_home.clone());

        // 1. Mock Anthropic Messages API (`/api/anthropic/v1/messages`) testing:
        //    - `x-api-key` + `anthropic-version: 2023-06-01`
        //    - `thinking` + `tool_use` + `tool_result`
        //    - Duplicate tool-call loop guard (Round 2 repeats exact same tool+args -> blocked without extra dot!)
        let anth_calls = Arc::new(AtomicUsize::new(0));
        let anth_calls_bg = anth_calls.clone();
        let anth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let anth_addr = anth_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = anth_listener.accept().await else {
                    break;
                };
                let cc = anth_calls_bg.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let raw_req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let lower_req = raw_req.to_ascii_lowercase();
                    assert!(
                        raw_req.starts_with("POST /api/anthropic/v1/messages "),
                        "Expected Anthropic /v1/messages path, got: {}",
                        raw_req.lines().next().unwrap_or("")
                    );
                    assert!(lower_req.contains("anthropic-version: 2023-06-01"));
                    assert!(lower_req.contains("x-api-key: sk-anth-glm-test"));
                    assert!(raw_req.contains("\"input_schema\""));

                    let round = cc.fetch_add(1, Ordering::SeqCst);
                    let body = match round {
                        0 => serde_json::to_string(&json!({
                            "id": "msg_01",
                            "type": "message",
                            "role": "assistant",
                            "content": [
                                { "type": "thinking", "thinking": "准备通过 Anthropic 协议将亮度设为 60%" },
                                {
                                    "type": "tool_use",
                                    "id": "toolu_bright_1",
                                    "name": "display_brightness_set",
                                    "input": { "value": 60 }
                                }
                            ]
                        }))
                        .unwrap(),
                        1 => {
                            // Deliberately repeat the EXACT same tool + arguments (in different key/format) to trigger loop guard!
                            serde_json::to_string(&json!({
                                "id": "msg_02",
                                "type": "message",
                                "role": "assistant",
                                "content": [
                                    {
                                        "type": "tool_use",
                                        "id": "toolu_bright_dup",
                                        "name": "display_brightness_set",
                                        "input": { "value": 60 }
                                    }
                                ]
                            }))
                            .unwrap()
                        }
                        _ => {
                            assert!(
                                raw_req.contains("duplicate_call_blocked"),
                                "Round 3 must receive duplicate_call_blocked tool_result!"
                            );
                            serde_json::to_string(&json!({
                                "id": "msg_03",
                                "type": "message",
                                "role": "assistant",
                                "content": [
                                    { "type": "text", "text": "已通过 GLM-5.3 将屏幕亮度调至 **60%**。" }
                                ]
                            }))
                            .unwrap()
                        }
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let zcode_v2 = mock_home.join(".zcode/v2/config.json");
        std::fs::create_dir_all(zcode_v2.parent().unwrap()).unwrap();
        std::fs::write(
            &zcode_v2,
            serde_json::to_string_pretty(&json!({
                "provider": {
                    "builtin:bigmodel": {
                        "name": "BigModel Anthropic",
                        "kind": "anthropic",
                        "enabled": true,
                        "options": {
                            "apiKey": "sk-anth-glm-test",
                            "baseURL": format!("http://{}/api/anthropic", anth_addr)
                        },
                        "models": {
                            "GLM-5.3": {}
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "zcode",
                "provider": "builtin:bigmodel",
                "model": "GLM-5.3",
                "reasoning_effort": "high"
            }),
            &opts,
        )
        .await
        .unwrap();

        let anth_turn = send_quick_chat_turn_with_options(
            &core,
            &json!({ "text": "把屏幕亮度设到 60%" }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(anth_turn["backend_used"], "zcode");
        assert_eq!(anth_turn["model_used"], "GLM-5.3");
        assert_eq!(
            anth_turn["reply_markdown"],
            "已通过 GLM-5.3 将屏幕亮度调至 **60%**。"
        );
        let dots = anth_turn["trace_dots"].as_array().unwrap();
        let tool_ok_count = dots.iter().filter(|d| d["kind"] == "tool_ok").count();
        assert_eq!(
            tool_ok_count, 1,
            "Duplicate tool call MUST NOT execute a second time or emit a second tool_ok dot!"
        );
        assert!(dots.iter().any(|d| d["kind"] == "thinking"));

        // 2. Verify `app_adapter_invoke` requiring approval routes through `core.broker.dispatch`
        //    and pauses immediately with a real nonce-bound `PendingApproval`!
        let approval_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let approval_addr = approval_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = approval_listener.accept().await {
                let mut buf = vec![0u8; 32768];
                let _ = stream.read(&mut buf).await;
                let body = serde_json::to_string(&json!({
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [{
                                "id": "call_adap_gui_1",
                                "type": "function",
                                "function": {
                                    "name": "app_adapter_invoke",
                                    "arguments": "{\"app_hint\":\"legacy-erp-client\",\"intent_action\":\"click_control\",\"params\":{\"control\":\"发送按钮\",\"dry_run\":true}}"
                                }
                            }]
                        }
                    }]
                }))
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "openai",
                "provider": "local-approval-test",
                "model": "gpt-5.4",
                "base_url": format!("http://{}/v1", approval_addr),
                "api_key": "sk-local-approval-test"
            }),
            &opts,
        )
        .await
        .unwrap();

        let paused_turn = send_quick_chat_turn_with_options(
            &core,
            &json!({ "text": "通过 AT-SPI 聚焦微信窗口" }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(paused_turn["status"], "awaiting_approval");
        let pa = &paused_turn["pending_approval"];
        assert!(pa.is_object(), "Must emit real PendingApproval object!");
        assert!(
            pa["nonce"].as_str().is_some_and(|n| !n.is_empty()),
            "PendingApproval must carry cryptographic nonce from broker!"
        );
        assert_eq!(pa["capability_id"], "app_adapter_invoke");
        assert!(
            paused_turn["trace_dots"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["kind"] == "approval"
                    && d["approval_id"] == pa["approval_id"]
                    && d["pending_approval"]["nonce"] == pa["nonce"])
        );
    }

    async fn read_full_http_request_body(stream: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::with_capacity(16384);
        let mut chunk = [0u8; 4096];
        let mut header_end: Option<usize> = None;
        let mut content_len = 0usize;

        loop {
            let Ok(n) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await
            else {
                break;
            };
            let Ok(n) = n else { break };
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if header_end.is_none()
                && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
            {
                let h_end = pos + 4;
                header_end = Some(h_end);
                let headers_str = String::from_utf8_lossy(&buf[..h_end]);
                for line in headers_str.lines() {
                    if let Some((k, v)) = line.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_len = v.trim().parse::<usize>().unwrap_or(0);
                    }
                }
            }
            if let Some(h_end) = header_end
                && buf.len() >= h_end + content_len
            {
                return String::from_utf8_lossy(&buf[h_end..h_end + content_len]).to_string();
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn test_resume_approved_turn_session_grant_continuation_and_deny() {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("mock_home_resume");
        std::fs::create_dir_all(&mock_home).unwrap();

        // Sensitive directory OUTSIDE startup `authorized_directories`
        let outside_dir = tmp.path().join("outside_sensitive_docs");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let target_doc = outside_dir.join("secret_report_2026.md");
        std::fs::write(&target_doc, "# 2026 核心总结\n关键指标达标。").unwrap();
        let outside_dir_str = outside_dir.to_string_lossy().to_string();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dir_for_srv = outside_dir_str.clone();
        let call_counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = call_counter.clone();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let req_json_str = read_full_http_request_body(&mut stream).await;
                let step_no = counter_clone.fetch_add(1, Ordering::SeqCst);
                let req_val: Value =
                    serde_json::from_str(&req_json_str).unwrap_or_else(|_| json!({}));
                let msgs = req_val["messages"].as_array().cloned().unwrap_or_default();
                let has_tool_result = msgs.iter().any(|m| m["role"] == "tool");

                let body = if !has_tool_result {
                    let args_str = serde_json::to_string(&json!({
                        "directory": dir_for_srv,
                        "query": "report"
                    }))
                    .unwrap();
                    serde_json::to_string(&json!({
                        "id": format!("chatcmpl_{}", step_no),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "<think>检索受控外部目录</think>",
                                "tool_calls": [{
                                    "id": format!("call_fs_{}", step_no),
                                    "type": "function",
                                    "function": {
                                        "name": "file_search",
                                        "arguments": args_str
                                    }
                                }]
                            }
                        }]
                    }))
                    .unwrap()
                } else {
                    let tool_payload_str = msgs
                        .iter()
                        .rev()
                        .find(|m| m["role"] == "tool")
                        .and_then(|m| m["content"].as_str())
                        .unwrap_or("{}");
                    serde_json::to_string(&json!({
                        "id": format!("chatcmpl_final_{}", step_no),
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": format!("已在授权目录中找到汇报文件，工具结果摘要：{}", tool_payload_str)
                            }
                        }]
                    }))
                    .unwrap()
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let mut opts = DiscoveryOptions::from_core(&core, true);
        opts.home_dir = mock_home.clone();
        opts.include_system_paths = false;
        opts.allow_env_keys = false;
        opts.probe_remote_models = false;

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "openai",
                "provider": "mock-resume-llm",
                "model": "gpt-5.4",
                "base_url": format!("http://{}/v1", addr),
                "api_key": "sk-mock-resume-key"
            }),
            &opts,
        )
        .await
        .unwrap();

        // 1) First test DENY flow cleanly
        let sid_deny = "ses_wave5_deny";
        let turn_deny_paused = handle_module_rpc(
            &core,
            "send_quick_chat_turn",
            json!({
                "session_id": sid_deny,
                "text": "搜索受控目录汇报",
                "home_dir": mock_home.to_string_lossy(),
                "probe_remote_models": false,
            }),
        )
        .await
        .unwrap();
        assert_eq!(turn_deny_paused["status"], "awaiting_approval");
        let deny_pa = &turn_deny_paused["pending_approval"];
        let denied_res = handle_module_rpc(
            &core,
            "resume_approved_turn",
            json!({
                "approval_id": deny_pa["approval_id"],
                "decision": "deny",
                "home_dir": mock_home.to_string_lossy(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(denied_res["status"], "completed");
        assert_eq!(denied_res["approval_resolved"], "denied");
        assert!(
            denied_res["trace_dots"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["title"].as_str().unwrap_or("").contains("✕ 用户已拒绝"))
        );

        // 2) Test APPROVE (`decision: "session"`) -> LLM Continuation -> Session Persistence -> Turn 2 Zero Re-Prompt!
        let sid_ok = "ses_wave5_approve";
        let turn1_paused = handle_module_rpc(
            &core,
            "send_quick_chat_turn",
            json!({
                "session_id": sid_ok,
                "text": "帮我找一下外部目录里的 report 文档",
                "home_dir": mock_home.to_string_lossy(),
                "probe_remote_models": false,
            }),
        )
        .await
        .unwrap();
        assert_eq!(turn1_paused["status"], "awaiting_approval");
        let pa1 = &turn1_paused["pending_approval"];
        assert_eq!(pa1["capability_id"], "file.search");

        // Resume with `decision: "session"` (even omitting nonce/digest & scope_value to verify trusted auto-fallback!)
        let resumed = handle_module_rpc(
            &core,
            "resume_approved_turn",
            json!({
                "approval_id": pa1["approval_id"],
                "decision": "session",
                "ttl_minutes": 60,
                "home_dir": mock_home.to_string_lossy(),
                "probe_remote_models": false,
            }),
        )
        .await
        .unwrap();

        assert_eq!(resumed["status"], "completed");
        assert_eq!(resumed["approval_resolved"], "approved");
        assert_eq!(resumed["session_id"], sid_ok);
        assert!(resumed["pending_approval"].is_null());
        let reply_md = resumed["reply_markdown"].as_str().unwrap_or("");
        assert!(
            reply_md.contains("secret_report_2026.md"),
            "Resumed LLM reply MUST receive and summarize discovered file `secret_report_2026.md`, got: {}",
            reply_md
        );
        assert!(
            resumed["trace_dots"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["title"] == "✓ 已批准执行: file.search")
        );

        // Verify `(user_text, final_reply)` persisted in BOTH `core.sessions` AND `memory_hub.get_session`!
        let mem_ses = crate::memory_hub::handle_module_rpc(
            &core,
            "get_session",
            json!({ "session_id": sid_ok }),
        )
        .await
        .unwrap();
        let mem_msgs = mem_ses["messages"].as_array().unwrap();
        assert_eq!(mem_msgs.len(), 2);
        assert_eq!(mem_msgs[0]["role"], "user");
        assert_eq!(mem_msgs[0]["content"], "帮我找一下外部目录里的 report 文档");
        assert!(
            mem_msgs[1]["content"]
                .as_str()
                .unwrap_or("")
                .contains("secret_report_2026.md")
        );

        // 3) Turn 2 in the SAME session searches the same directory -> MUST complete immediately WITHOUT re-prompting!
        let turn2 = handle_module_rpc(
            &core,
            "send_quick_chat_turn",
            json!({
                "session_id": sid_ok,
                "text": "再确认一下那个目录里的 report 文件",
                "home_dir": mock_home.to_string_lossy(),
                "probe_remote_models": false,
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            turn2["status"], "completed",
            "Session directory grant must prevent re-prompting on subsequent turns!"
        );
        assert!(turn2["pending_approval"].is_null());
        assert!(
            turn2["reply_markdown"]
                .as_str()
                .unwrap_or("")
                .contains("secret_report_2026.md")
        );
    }

    #[tokio::test]
    async fn test_nonlinear_context_compression_strips_think_and_tools_in_quick_chat() {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("mock_home_decay");
        std::fs::create_dir_all(&mock_home).unwrap();

        let sid = "ses_wave5_decay_live";
        for i in 0..14 {
            crate::memory_hub::record_conversation_turn(
                &core,
                &crate::memory_hub::RecordTurnInput {
                    session_id: Some(sid.into()),
                    user_text: format!("历史问题 #{}：请检查 `/home/user/cfg_{}.toml` 配置", i + 1, i + 1),
                    assistant_text: format!(
                        "<think>绝密内部思考链 #{}</think>已完成检查 `/home/user/cfg_{}.toml`。\n```toml\nport = {}\n```\n一切正常。",
                        i + 1,
                        i + 1,
                        8000 + i
                    ),
                    thinking: Some("secret_cot".into()),
                    tool_steps: vec![json!({"tool": "file.read", "leak_marker": "HISTORICAL_TOOL_RECORD_LEAK"})],
                    trace_dots: vec![],
                    incognito: false,
                },
            )
            .unwrap();
        }

        let captured_req: Arc<std::sync::Mutex<Option<Value>>> =
            Arc::new(std::sync::Mutex::new(None));
        let captured_clone = captured_req.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let raw_req = read_full_http_request_body(&mut stream).await;
                if let Ok(v) = serde_json::from_str::<Value>(&raw_req) {
                    *captured_clone.lock().unwrap() = Some(v);
                }
                let body = serde_json::to_string(&json!({
                    "id": "chatcmpl_decay",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "收到，上下文压缩工作正常！"
                        }
                    }]
                }))
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let mut opts = DiscoveryOptions::from_core(&core, true);
        opts.home_dir = mock_home.clone();
        opts.include_system_paths = false;
        opts.allow_env_keys = false;
        opts.probe_remote_models = false;

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "openai",
                "provider": "mock-decay-llm",
                "model": "gpt-5.4",
                "base_url": format!("http://{}/v1", addr),
                "api_key": "sk-mock-decay"
            }),
            &opts,
        )
        .await
        .unwrap();

        let turn_res = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": sid,
                "text": "总结一下之前的配置检查",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(turn_res["status"], "completed");
        let cc = &turn_res["context_compression"];
        assert_eq!(cc["raw_qa_turns"], 14);
        assert_eq!(cc["verbatim_turns"], 3);
        assert!(cc["decayed_turns"].as_u64().unwrap() > 0);
        assert!(cc["dropped_tool_records"].as_u64().unwrap() >= 14);
        assert!(cc["saved_pct"].as_f64().unwrap() > 0.0);

        let sent = captured_req
            .lock()
            .unwrap()
            .clone()
            .expect("captured request");
        let sent_str = sent.to_string();
        assert!(
            !sent_str.contains("绝密内部思考链"),
            "Historical `<think>` blocks MUST NEVER be injected into multi-turn context!"
        );
        assert!(
            !sent_str.contains("HISTORICAL_TOOL_RECORD_LEAK"),
            "Historical tool records MUST NEVER be injected into multi-turn context!"
        );
        let msgs = sent["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "tool"));
    }

    #[tokio::test]
    async fn test_m1_effect_ledger_blocks_fallback_replay_after_mutating_tool_round1_ok_round2_500()
    {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("mock_home_m1_ledger");
        std::fs::create_dir_all(&mock_home).unwrap();

        // Unit-verify canonical SHA-256 idempotency key stability & duplicate lookup first
        let mut unit_ledger = TurnEffectLedger::new("turn_unit_canon");
        let k1 = unit_ledger.compute_idempotency_key("sound.volume.set", r#"{"b":2,"value":38}"#);
        let k2 =
            unit_ledger.compute_idempotency_key("sound.volume.set", r#"{"value": 38, "b": 2}"#);
        assert_eq!(
            k1, k2,
            "Canonical JSON idempotency_key must be key-order invariant"
        );
        assert_eq!(k1.len(), 64);
        assert!(unit_ledger.lookup_idempotent(&k2).is_none());
        let unit_sid = unit_ledger.next_step_id();
        unit_ledger.record_step(StepExecutionRecord {
            step_id: unit_sid,
            idempotency_key: k1.clone(),
            capability_id: "sound.volume.set".into(),
            canonical_args_json: r#"{"b":2,"value":38}"#.into(),
            effect: intentos_protocol::Effect::Setting,
            mutated_state: true,
            succeeded: true,
            changeset_id: Some("cs_unit_1".into()),
            verification_status: "Passed".into(),
            cached_output: json!({"volume": 38}),
        });
        assert!(unit_ledger.lookup_idempotent(&k2).is_some());
        assert!(unit_ledger.has_committed_side_effects());

        // Install a mock `codex` CLI binary that writes a sentinel flag if fallback ever invokes CLI
        let cli_sentinel = tmp.path().join("cli_fallback_must_not_run.flag");
        write_executable(
            &mock_home.join(".local/bin/codex"),
            &format!(
                "#!/bin/sh\necho invoked > \"{}\"\necho \"CLI fallback ran illegally\"\n",
                cli_sentinel.display()
            ),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let round_counter = Arc::new(AtomicUsize::new(0));
        let round_counter_srv = round_counter.clone();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let raw_req = read_full_http_request_body(&mut stream).await;
                let step_idx = round_counter_srv.fetch_add(1, Ordering::SeqCst);
                let req_val: Value = serde_json::from_str(&raw_req).unwrap_or_else(|_| json!({}));
                let has_tool_msg = req_val["messages"]
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|m| m["role"] == "tool"));

                if !has_tool_msg && step_idx == 0 {
                    // Round 1: invoke mutating capability `sound.volume.set` (`Effect::ModifyLocal > Effect::Observe`)
                    let body = serde_json::to_string(&json!({
                        "id": "chatcmpl_m1_r1",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "<think>将系统音量设为 38%</think>",
                                "tool_calls": [{
                                    "id": "call_vol_m1",
                                    "type": "function",
                                    "function": {
                                        "name": "sound_volume_set",
                                        "arguments": "{\"value\":38}"
                                    }
                                }]
                            }
                        }]
                    }))
                    .unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else {
                    // Round 2: upstream crashes with HTTP 500 AFTER mutating tool succeeded!
                    let err_body = r#"{"error":{"message":"gateway crashed upstream key sk-m1-err-leak-998811"}}"#;
                    let resp = format!(
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        err_body.len(),
                        err_body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            }
        });

        let codex_toml = format!(
            "model = \"gpt-6.1-sol\"\nmodel_provider = \"corp_codex\"\n\n[model_providers.corp_codex]\nname = \"Corp Codex\"\nbase_url = \"http://{}/v1\"\napi_key = \"sk-m1-codex-http-key\"\n",
            addr
        );
        let codex_cfg_path = mock_home.join(".codex/config.toml");
        std::fs::create_dir_all(codex_cfg_path.parent().unwrap()).unwrap();
        std::fs::write(&codex_cfg_path, codex_toml).unwrap();

        let mut opts = DiscoveryOptions::from_core(&core, true);
        opts.home_dir = mock_home.clone();
        opts.include_system_paths = false;
        opts.allow_env_keys = false;
        opts.probe_remote_models = false;

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "codex",
                "provider": "corp_codex",
                "model": "gpt-6.1-sol",
            }),
            &opts,
        )
        .await
        .unwrap();

        // Note: "把音量调到 38%" ALSO matches L0 `sound.volume.set` in `core.submit_intent`,
        // so if fallback occurred, either `cli_sentinel` would exist OR a 2nd changeset would be created!
        let res = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": "ses_m1_no_replay",
                "text": "把音量调到 38%",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(res["status"], "completed");
        assert_eq!(res["side_effect_replay_prevented"], true);
        assert_eq!(res["execution_mode"], "managed_broker");
        assert!(
            !cli_sentinel.exists(),
            "CLI fallback MUST NOT run after a mutating side-effect committed!"
        );

        let cs_ids = res["changeset_ids"].as_array().unwrap();
        assert_eq!(
            cs_ids.len(),
            1,
            "Exactly 1 changeset must exist (zero duplicate replay on `core.submit_intent`!), got: {:?}",
            cs_ids
        );

        let ledger = &res["effect_ledger"];
        assert_eq!(ledger["has_committed_side_effects"], true);
        assert_eq!(ledger["mutated_steps"], 1);
        assert_eq!(ledger["total_steps"], 1);
        assert_eq!(ledger["steps"][0]["step_id"], "step_1");
        assert_eq!(ledger["steps"][0]["capability_id"], "sound.volume.set");
        assert_eq!(ledger["steps"][0]["mutated_state"], true);

        let dots = res["trace_dots"].as_array().unwrap();
        assert!(
            dots.iter().any(|d| d["title"]
                .as_str()
                .unwrap_or("")
                .contains("sound.volume.set")),
            "Round 1 trace_dots must be preserved on safe halt, got: {:?}",
            dots
        );

        let reply_md = res["reply_markdown"].as_str().unwrap_or("");
        assert!(reply_md.contains("sound.volume.set"));
        assert!(reply_md.contains(cs_ids[0].as_str().unwrap()));
        assert!(
            !res.to_string().contains("sk-m1-err-leak-998811"),
            "Upstream HTTP 500 error message secrets must be scrubbed!"
        );
    }

    #[tokio::test]
    async fn test_m1_incognito_never_leaks_explicit_state_db_memories_to_outbound_llm() {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("mock_home_m1_incog");
        std::fs::create_dir_all(&mock_home).unwrap();

        // Populate explicit long-term user preferences in StateDb
        core.state_db
            .save_explicit_memory("文档偏好", "默认使用 WPS 打开文档", None)
            .unwrap();
        core.state_db
            .save_explicit_memory("办公地点", "常驻杭州滨江研发园区", None)
            .unwrap();
        assert_eq!(core.state_db.list_active_memories().unwrap().len(), 2);

        let captured_bodies: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_srv = captured_bodies.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let raw_req = read_full_http_request_body(&mut stream).await;
                captured_srv.lock().unwrap().push(raw_req);
                let body = serde_json::to_string(&json!({
                    "id": "chatcmpl_m1_incog",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "已为您完成纪要润色。"
                        }
                    }]
                }))
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let mut opts = DiscoveryOptions::from_core(&core, true);
        opts.home_dir = mock_home.clone();
        opts.include_system_paths = false;
        opts.allow_env_keys = false;
        opts.probe_remote_models = false;

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "openai",
                "provider": "mock-incog-llm",
                "model": "gpt-5.4",
                "base_url": format!("http://{}/v1", addr),
                "api_key": "sk-mock-incog-key"
            }),
            &opts,
        )
        .await
        .unwrap();

        // 1) Incognito turn: MUST NOT leak `StateDb::list_active_memories()` into outbound LLM request OR response!
        let incog_res = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": "incog_ses_m1_verify",
                "incognito": true,
                "text": "帮我润色一段周会纪要",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(incog_res["status"], "completed");
        assert_eq!(incog_res["execution_mode"], "managed_broker");
        assert!(
            incog_res["memory_hits"].as_array().unwrap().is_empty(),
            "Incognito turn MUST NOT return explicit StateDb memories in `memory_hits`!"
        );
        assert!(
            incog_res["trace_dots"]
                .as_array()
                .unwrap()
                .iter()
                .all(|d| d["kind"] != "memory"),
            "Incognito turn MUST NOT emit memory trace dots!"
        );

        let incog_outbound = captured_bodies.lock().unwrap()[0].clone();
        for forbidden in [
            "默认使用 WPS 打开文档",
            "文档偏好",
            "杭州滨江研发园区",
            "办公地点",
        ] {
            assert!(
                !incog_outbound.contains(forbidden),
                "PRIVACY VIOLATION: Incognito outbound LLM payload leaked explicit StateDb memory '{}'! Payload: {}",
                forbidden,
                incog_outbound
            );
        }

        // Verify zero persistence in `memory_hub` for incognito session (session does not even exist!)
        let mem_ses = crate::memory_hub::handle_module_rpc(
            &core,
            "get_session",
            json!({ "session_id": "incog_ses_m1_verify" }),
        )
        .await;
        assert!(
            mem_ses.is_err()
                || mem_ses.unwrap()["messages"]
                    .as_array()
                    .is_none_or(|arr| arr.is_empty()),
            "Incognito turn MUST NOT write conversation history!"
        );

        // 2) Normal (`incognito: false`) turn: explicit memories remain active & available
        let normal_res = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": "normal_ses_m1_verify",
                "incognito": false,
                "text": "帮我润色一段周会纪要",
            }),
            &opts,
        )
        .await
        .unwrap();
        assert!(
            !normal_res["memory_hits"].as_array().unwrap().is_empty(),
            "Non-incognito turn should still surface explicit StateDb preferences"
        );
    }

    #[tokio::test]
    async fn test_m1_cli_broker_bridge_executes_tool_call_and_suspends_on_pending_approval() {
        let (tmp, core) = setup_test_core();
        let mock_home = tmp.path().join("mock_home_m1_cli_bridge");
        std::fs::create_dir_all(&mock_home).unwrap();

        let outside_dir = tmp.path().join("controlled_external_vault");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(
            outside_dir.join("confidential_roadmap_2026.md"),
            "# Roadmap 2026\nMilestone 1 unified broker.\n",
        )
        .unwrap();

        // Mock `codex` CLI binary speaking the controlled `<intentos_tool_call>` protocol
        let mock_codex_script = format!(
            r#"#!/bin/sh
for prompt; do :; done
case "$prompt" in
  *intentos_tool_results*confidential_roadmap_2026.md*)
    printf "已完成受控目录检索，发现文件 confidential_roadmap_2026.md。"
    ;;
  *intentos_tool_results*42%*)
    printf "已通过受控 Broker 将屏幕亮度设为 42%%（调试密钥 sk-cli-leak-test-887766 已隔离）。"
    ;;
  *intentos_tool_results*)
    printf "已完成受控工具执行闭环。"
    ;;
  *调暗屏幕亮度测试*)
    printf "<think>通过 IntentOS CapabilityBroker 调整屏幕亮度</think><intentos_tool_call>{{\"name\":\"display.brightness.set\",\"arguments\":{{\"value\":42}}}}</intentos_tool_call>"
    ;;
  *检索受控外部路线图*)
    printf "<intentos_tool_call>{{\"name\":\"file.search\",\"arguments\":{{\"directory\":\"{}\",\"query\":\"roadmap\"}}}}</intentos_tool_call>"
    ;;
  *)
    printf "纯对话模式回复 <intentos_tool_call>{{broken_tag</intentos_tool_call> 完毕。"
    ;;
esac
"#,
            outside_dir.display()
        );
        write_executable(&mock_home.join(".local/bin/codex"), &mock_codex_script);

        let codex_cfg_path = mock_home.join(".codex/config.toml");
        std::fs::create_dir_all(codex_cfg_path.parent().unwrap()).unwrap();
        std::fs::write(&codex_cfg_path, "model = \"gpt-6.1-cli\"\n").unwrap();

        let mut opts = DiscoveryOptions::from_core(&core, true);
        opts.home_dir = mock_home.clone();
        opts.include_system_paths = false;
        opts.allow_env_keys = false;
        opts.probe_remote_models = false;

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "codex",
                "model": "gpt-6.1-cli",
            }),
            &opts,
        )
        .await
        .unwrap();

        // Case A: CLI emits `<intentos_tool_call>` for `display.brightness.set` -> Broker executes -> Round 2 summarizes
        let res_bright = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": "ses_m1_cli_bright",
                "text": "调暗屏幕亮度测试",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(res_bright["status"], "completed");
        assert_eq!(res_bright["backend_used"], "codex");
        assert_eq!(res_bright["execution_mode"], "cli_broker_bridged");
        assert_eq!(res_bright["changeset_ids"].as_array().unwrap().len(), 1);
        assert_eq!(
            res_bright["effect_ledger"]["has_committed_side_effects"],
            true
        );
        let bright_dots = res_bright["trace_dots"].as_array().unwrap();
        assert!(
            bright_dots.iter().any(|d| d["title"]
                .as_str()
                .unwrap_or("")
                .contains("display.brightness.set")),
            "CLI broker bridge must emit real `TraceDot` for executed capability, got: {:?}",
            bright_dots
        );
        assert!(
            !res_bright.to_string().contains("sk-cli-leak-test-887766"),
            "CLI output secrets must be scrubbed!"
        );

        // Case B: CLI emits `<intentos_tool_call>` for outside `file.search` -> suspends on `PendingApproval` -> resumes cleanly!
        let paused = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": "ses_m1_cli_approval",
                "text": "检索受控外部路线图",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(paused["status"], "awaiting_approval");
        assert_eq!(paused["execution_mode"], "cli_broker_bridged");
        let pa = &paused["pending_approval"];
        assert_eq!(pa["capability_id"], "file.search");
        assert!(!pa["nonce"].as_str().unwrap_or("").is_empty());

        let resumed = resume_approved_turn_with_options(
            &core,
            &json!({
                "approval_id": pa["approval_id"],
                "decision": "once",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(resumed["status"], "completed");
        assert_eq!(resumed["approval_resolved"], "approved");
        assert_eq!(resumed["execution_mode"], "cli_broker_bridged");
        assert!(
            resumed["reply_markdown"]
                .as_str()
                .unwrap_or("")
                .contains("confidential_roadmap_2026.md"),
            "Resumed CLI turn must receive approved file.search results, got: {}",
            resumed["reply_markdown"]
        );

        // Case C: `allow_broker_tools: false` reports `external_chat_only` and strips malformed tags
        let chat_only = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": "ses_m1_cli_chat_only",
                "allow_broker_tools": false,
                "text": "普通闲聊无需系统工具",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(chat_only["status"], "completed");
        assert_eq!(chat_only["execution_mode"], "external_chat_only");
        assert_eq!(chat_only["effect_ledger"]["total_steps"], 0);
        let cleaned = chat_only["reply_markdown"].as_str().unwrap_or("");
        assert!(!cleaned.contains("intentos_tool_call"));
        assert!(cleaned.contains("纯对话模式回复"));
    }
}
