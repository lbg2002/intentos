#![forbid(unsafe_code)]

//! Functional Module 2: Full-Element 11-Domain Config & Brain Center (`crates/intentosd/src/config_center/`)
//!
//! Implements `docs/IntentOS_设计方案_v0.3.md` (§4.7, §5.1–§5.6, §6.4, §8.7, §9.2, §10.2–§10.4, §14.2, §16.1):
//! 1. `schema.rs`: Strongly-typed structs & defaults for all 11 Settings Center domains
//! 2. `store.rs`: Persistence layer for `config.toml`, `brain.toml`, and `domains.json` (zero secrets on disk)
//! 3. `brain_manager.rs`: Multi-provider CRUD, Secret Service / `0600` credential vault, 5 Model Roles (`main`, `fast`, `decision`, `vision`, `memory`), and runtime/budget limits
//! 4. `provider_tester.rs`: Connection testing (`B-03`: `ok`, `auth_failed`, `unreachable`, `timeout`, `model_not_found`) and structured tool-calling probe (`B-04`)
//! 5. `egress_matrix.rs`: Configurable `DataClass × ProviderTrust` matrix (`forbidden` locked to `deny`), sensitive directories CRUD, and forbidden rules inspector (§5.4)
//! 6. `web_and_sites.rs`: Search engines & site shortcuts CRUD (`http://`/`https://` strictly enforced), hotkey conflict detector (`<Super>space`), and secret-free config bundle export/import (`M-08`)

pub mod brain_manager;
pub mod egress_matrix;
pub mod provider_tester;
pub mod schema;
pub mod store;
pub mod web_and_sites;

use crate::config_center::brain_manager::{
    delete_provider, update_model_profiles, upsert_provider,
};
use crate::config_center::egress_matrix::{
    classify_path_sensitivity, egress_matrix_summary_json, normalize_sensitive_directories,
};
use crate::config_center::provider_tester::{test_provider_connection, test_provider_tools};
use crate::config_center::schema::normalize_domain_key;
use crate::config_center::store::{
    get_single_domain_value, load_domains_config, reset_to_defaults, save_domains_config,
    serialize_all_domains_response, update_domain_in_store,
};
use crate::config_center::web_and_sites::{
    check_hotkey_conflict, delete_site_shortcut, export_config_bundle, import_config_bundle,
    upsert_search_engine, upsert_site_shortcut,
};
use crate::core::IntentOsCore;
use serde_json::{Value, json};

pub async fn handle_module_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    match action {
        "ping" => Ok(json!({
            "module": "config_center",
            "status": "ready",
            "payload": payload,
        })),

        "get_full_config" | "get_all_domains" => {
            let cfg = load_domains_config(core)?;
            Ok(serialize_all_domains_response(&cfg))
        }

        "get_domain" => {
            let cfg = load_domains_config(core)?;
            let raw_key = payload
                .get("domain_key")
                .or_else(|| payload.get("domain"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("get_domain 缺少 domain_key"))?;
            let canonical = normalize_domain_key(raw_key)
                .ok_or_else(|| anyhow::anyhow!("未知的配置域: {}", raw_key))?;
            Ok(json!({
                "domain_key": canonical,
                "data": get_single_domain_value(&cfg, canonical),
            }))
        }

        "update_domain" => {
            let mut cfg = load_domains_config(core)?;
            let raw_key = payload
                .get("domain_key")
                .or_else(|| payload.get("domain"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("update_domain 缺少 domain_key"))?;
            let data = payload.get("data").unwrap_or(&payload);
            let res = update_domain_in_store(core, &mut cfg, raw_key, data)?;
            let _ = core.state_db.record_audit(
                None,
                "config_center.update_domain",
                "user_explicit",
                "setting",
                "allow",
                "ok",
                &json!({ "domain_key": raw_key }),
                None,
            );
            Ok(res)
        }

        "upsert_provider" => {
            let mut cfg = load_domains_config(core)?;
            let provider = upsert_provider(&core.paths, &mut cfg, &payload)?;
            save_domains_config(core, &mut cfg)?;
            let _ = core.state_db.record_audit(
                None,
                "config_center.upsert_provider",
                "user_explicit",
                "setting",
                "allow",
                "ok",
                &json!({ "provider_id": provider.id, "kind": provider.kind, "trust": provider.trust }),
                None,
            );
            Ok(json!({
                "saved": true,
                "provider": provider,
                "providers": cfg.brain.providers,
            }))
        }

        "delete_provider" => {
            let mut cfg = load_domains_config(core)?;
            let out = delete_provider(&core.paths, &mut cfg, &payload)?;
            save_domains_config(core, &mut cfg)?;
            Ok(out)
        }

        "test_provider_connection" => {
            let cfg = load_domains_config(core)?;
            test_provider_connection(&core.paths, &cfg, &payload).await
        }

        "test_provider_tools" => {
            let cfg = load_domains_config(core)?;
            test_provider_tools(&core.paths, &cfg, &payload).await
        }

        "update_model_profiles" => {
            let mut cfg = load_domains_config(core)?;
            let out = update_model_profiles(&mut cfg, &payload)?;
            save_domains_config(core, &mut cfg)?;
            Ok(out)
        }

        "update_egress_matrix" => {
            let mut cfg = load_domains_config(core)?;
            let strict_reject = payload
                .get("strict_reject")
                .or_else(|| payload.get("strict"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let matrix_patch = payload.get("matrix").unwrap_or(&payload);
            let had_forbidden_violation = cfg
                .brain
                .egress_matrix
                .apply_patch(matrix_patch, strict_reject)?;

            if let Some(sens_arr) = payload
                .get("sensitive_directories")
                .and_then(|v| v.as_array())
            {
                let raw_dirs: Vec<String> = sens_arr
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect();
                let normalized = normalize_sensitive_directories(raw_dirs)?;
                cfg.brain.sensitive_directories = normalized.clone();
                cfg.resources_config.sensitive_directories = normalized;
            }

            cfg.brain.egress_matrix.enforce_invariants();
            save_domains_config(core, &mut cfg)?;

            let mut out = egress_matrix_summary_json(
                &cfg.brain.egress_matrix,
                &cfg.brain.sensitive_directories,
            );
            if let Some(obj) = out.as_object_mut() {
                obj.insert("saved".into(), json!(true));
                obj.insert(
                    "forbidden_relaxation_rejected".into(),
                    json!(had_forbidden_violation),
                );
            }
            Ok(out)
        }

        "inspect_path_sensitivity" => {
            let cfg = load_domains_config(core)?;
            let path_str = payload
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("inspect_path_sensitivity 缺少 path"))?;
            let dc = classify_path_sensitivity(
                std::path::Path::new(path_str),
                &cfg.brain.sensitive_directories,
            );
            Ok(json!({
                "path": path_str,
                "data_class": dc,
            }))
        }

        "upsert_site_shortcut" => {
            let mut cfg = load_domains_config(core)?;
            let site = upsert_site_shortcut(&mut cfg, &payload)?;
            save_domains_config(core, &mut cfg)?;
            Ok(json!({
                "saved": true,
                "site": site,
                "sites": cfg.web_config.sites,
            }))
        }

        "delete_site_shortcut" => {
            let mut cfg = load_domains_config(core)?;
            let out = delete_site_shortcut(&mut cfg, &payload)?;
            save_domains_config(core, &mut cfg)?;
            Ok(out)
        }

        "upsert_search_engine" => {
            let mut cfg = load_domains_config(core)?;
            let out = upsert_search_engine(&mut cfg, &payload)?;
            save_domains_config(core, &mut cfg)?;
            Ok(out)
        }

        "check_hotkey_conflict" => {
            let cfg = load_domains_config(core)?;
            check_hotkey_conflict(&cfg, &payload)
        }

        "export_config_bundle" => {
            let cfg = load_domains_config(core)?;
            export_config_bundle(&cfg, core.app_config.allow_simulated_hardware_fallback)
        }

        "import_config_bundle" => {
            let mut cfg = load_domains_config(core)?;
            let out = import_config_bundle(&mut cfg, &payload)?;
            save_domains_config(core, &mut cfg)?;
            Ok(out)
        }

        "reset_to_defaults" => {
            let mut cfg = load_domains_config(core)?;
            reset_to_defaults(core, &mut cfg, &payload)
        }

        other => anyhow::bail!("config_center: unknown action '{}'", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, BrainConfig, XdgPaths};
    use crate::config_center::schema::ALL_DOMAIN_KEYS;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn setup_test_core() -> (tempfile::TempDir, Arc<IntentOsCore>) {
        let temp = tempfile::tempdir().expect("tempdir");
        let base = temp.path();
        let ws = base.join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

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

        let core = IntentOsCore::initialize(Some(base), repo_root).expect("init core");
        (temp, core)
    }

    #[tokio::test]
    async fn test_all_11_domains_read_update_and_persistence_roundtrip() {
        let (_tmp, core) = setup_test_core();

        // 1. Read all 11 domains
        let all = handle_module_rpc(&core, "get_all_domains", json!({}))
            .await
            .unwrap();
        for key in ALL_DOMAIN_KEYS {
            assert!(
                all.get(key).is_some(),
                "Expected domain key '{}' in get_all_domains output",
                key
            );
        }

        // Verify 5 model roles exist by default
        let profiles = all["brain"]["profiles"].as_object().unwrap();
        for role in ["main", "fast", "decision", "vision", "memory"] {
            assert!(profiles.contains_key(role), "Missing default role {}", role);
        }

        // 2. Update multiple domains (`undo_config`, `interaction_config`, `automation_config`, `maintenance_config`, `permissions_config`)
        let _ = handle_module_rpc(
            &core,
            "update_domain",
            json!({
                "domain_key": "undo_config",
                "data": {
                    "quota_gb": 12,
                    "retention_days": 45,
                    "single_file_max_ratio_percent": 30
                }
            }),
        )
        .await
        .unwrap();

        let _ = handle_module_rpc(
            &core,
            "update_domain",
            json!({
                "domain_key": "interaction_config",
                "data": {
                    "theme": "dark",
                    "default_surface_mode": "workspace",
                    "ui_scale_percent": 115,
                    "voice_asr_mode": "local_cpu"
                }
            }),
        )
        .await
        .unwrap();

        let _ = handle_module_rpc(
            &core,
            "update_domain",
            json!({
                "domain_key": "automation_config",
                "data": {
                    "autonomy_level": "L1_Suggest",
                    "max_triggers_per_hour": 10
                }
            }),
        )
        .await
        .unwrap();

        let _ = handle_module_rpc(
            &core,
            "update_domain",
            json!({
                "domain_key": "maintenance_config",
                "data": {
                    "record_transcripts": true,
                    "log_level": "debug"
                }
            }),
        )
        .await
        .unwrap();

        // 3. Read back and verify persistence in `config.toml`, `brain.toml`, and `domains.json`
        let reload = handle_module_rpc(&core, "get_all_domains", json!({}))
            .await
            .unwrap();
        assert_eq!(reload["undo_config"]["quota_gb"], 12);
        assert_eq!(reload["undo_config"]["retention_days"], 45);
        assert_eq!(reload["interaction_config"]["theme"], "dark");
        assert_eq!(
            reload["interaction_config"]["default_surface_mode"],
            "workspace"
        );
        assert_eq!(reload["interaction_config"]["ui_scale_percent"], 115);
        assert_eq!(reload["automation_config"]["autonomy_level"], "L1_Suggest");
        assert_eq!(reload["maintenance_config"]["record_transcripts"], true);

        let cfg_toml_raw =
            std::fs::read_to_string(core.paths.config_dir.join("config.toml")).unwrap();
        assert!(cfg_toml_raw.contains("quota_gb = 12"));
        assert!(core.paths.config_dir.join("domains.json").exists());
    }

    #[tokio::test]
    async fn test_provider_crud_five_model_roles_and_zero_secret_leakage() {
        let (_tmp, core) = setup_test_core();
        let secret_key = "sk-super-secret-never-write-to-toml-998877";

        // 1. Upsert a new provider with an API key
        let up_res = handle_module_rpc(
            &core,
            "upsert_provider",
            json!({
                "provider": {
                    "id": "deepseek-cloud",
                    "name": "DeepSeek Official",
                    "kind": "openai-compatible",
                    "base_url": "https://api.deepseek.com/v1",
                    "trust": "standard",
                    "enabled": true,
                    "available_models": ["deepseek-chat", "deepseek-reasoner"]
                },
                "api_key": secret_key
            }),
        )
        .await
        .unwrap();

        assert_eq!(up_res["provider"]["id"], "deepseek-cloud");
        assert_eq!(up_res["provider"]["has_api_key"], true);

        // 2. Verify secret key NEVER appears in `config.toml`, `brain.toml`, or `domains.json`
        for filename in ["config.toml", "brain.toml", "domains.json"] {
            let content =
                std::fs::read_to_string(core.paths.config_dir.join(filename)).unwrap();
            assert!(
                !content.contains(secret_key),
                "SECURITY VIOLATION: API key leaked into {}!",
                filename
            );
        }

        // 3. Update 5 model roles and runtime budget limits
        let prof_res = handle_module_rpc(
            &core,
            "update_model_profiles",
            json!({
                "runtime": "native",
                "profiles": {
                    "main": {
                        "provider": "deepseek-cloud",
                        "model": "deepseek-reasoner",
                        "context_budget": 131072,
                        "max_output_tokens": 8192,
                        "thinking": "high",
                        "temperature": 0.3
                    },
                    "fast": {
                        "provider": "deepseek-cloud",
                        "model": "deepseek-chat",
                        "inherit": "main",
                        "thinking": "off",
                        "temperature": 0.1
                    },
                    "decision": {
                        "kind": "emulated",
                        "inherit": "fast",
                        "direct_threshold": 0.88,
                        "margin_threshold": 0.32,
                        "clarify_threshold": 0.52
                    },
                    "vision": {
                        "provider": "default-openai",
                        "model": "gpt-4o",
                        "thinking": "low",
                        "enabled": true
                    },
                    "memory": {
                        "inherit": "fast",
                        "thinking": "off"
                    }
                },
                "runtime_limits": {
                    "max_tool_calls": 45,
                    "max_runtime_seconds": 240,
                    "daily_cost_limit": 5.5,
                    "fallback_enabled": true
                }
            }),
        )
        .await
        .unwrap();

        assert_eq!(prof_res["profiles"]["main"]["model"], "deepseek-reasoner");
        assert_eq!(prof_res["profiles"]["main"]["thinking"], "high");
        assert_eq!(prof_res["runtime_limits"]["max_tool_calls"], 45);
        assert_eq!(prof_res["runtime_limits"]["fallback_enabled"], true);

        // 4. Deleting the provider currently referenced by `main` (`deepseek-cloud`) must be blocked
        let del_main_err = handle_module_rpc(
            &core,
            "delete_provider",
            json!({ "provider_id": "deepseek-cloud" }),
        )
        .await;
        assert!(
            del_main_err.is_err(),
            "Deleting provider referenced by main profile should be blocked"
        );

        // 5. Deleting the non-main provider (`default-openai`) succeeds
        let del_ok = handle_module_rpc(
            &core,
            "delete_provider",
            json!({ "provider_id": "default-openai" }),
        )
        .await
        .unwrap();
        assert_eq!(del_ok["deleted"], true);
    }

    #[tokio::test]
    async fn test_egress_matrix_forbidden_invariant_and_sensitive_dirs() {
        let (_tmp, core) = setup_test_core();

        // 1. Attempt to relax `forbidden` to `allow` or `confirm` -> must remain locked to `deny`
        let res = handle_module_rpc(
            &core,
            "update_egress_matrix",
            json!({
                "matrix": {
                    "trusted": {
                        "public": "allow",
                        "personal": "allow",
                        "sensitive": "allow",
                        "forbidden": "allow"
                    },
                    "standard": {
                        "public": "allow",
                        "personal": "confirm",
                        "sensitive": "deny",
                        "forbidden": "confirm"
                    },
                    "untrusted": {
                        "public": "confirm",
                        "personal": "deny",
                        "sensitive": "deny",
                        "forbidden": "allow"
                    }
                },
                "sensitive_directories": ["~/PrivateVault", "/home/user/finance"]
            }),
        )
        .await
        .unwrap();

        assert_eq!(res["matrix"]["trusted"]["sensitive"], "allow");
        assert_eq!(res["matrix"]["trusted"]["forbidden"], "deny");
        assert_eq!(res["matrix"]["standard"]["forbidden"], "deny");
        assert_eq!(res["matrix"]["untrusted"]["forbidden"], "deny");
        assert_eq!(res["forbidden_relaxation_rejected"], true);

        // 2. Strict mode explicitly errors on `forbidden != deny`
        let strict_err = handle_module_rpc(
            &core,
            "update_egress_matrix",
            json!({
                "strict": true,
                "matrix": {
                    "trusted": { "forbidden": "allow" }
                }
            }),
        )
        .await;
        assert!(strict_err.is_err());

        // 3. Verify path sensitivity classification
        let ssh_check = handle_module_rpc(
            &core,
            "inspect_path_sensitivity",
            json!({ "path": "/home/user/.ssh/id_ed25519" }),
        )
        .await
        .unwrap();
        assert_eq!(ssh_check["data_class"], "forbidden");

        let finance_check = handle_module_rpc(
            &core,
            "inspect_path_sensitivity",
            json!({ "path": "/home/user/finance/tax_2026.xlsx" }),
        )
        .await
        .unwrap();
        assert_eq!(finance_check["data_class"], "sensitive");
    }

    #[tokio::test]
    async fn test_web_sites_dangerous_url_rejection_and_search_engines() {
        let (_tmp, core) = setup_test_core();

        // 1. Reject dangerous schemes (`javascript:`, `file:`, `data:`)
        for bad_url in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
        ] {
            let err = handle_module_rpc(
                &core,
                "upsert_site_shortcut",
                json!({
                    "site": {
                        "id": "evil",
                        "names": ["Evil"],
                        "url": bad_url
                    }
                }),
            )
            .await;
            assert!(
                err.is_err(),
                "Expected dangerous URL '{}' to be rejected",
                bad_url
            );
        }

        // 2. Valid custom site shortcut + search template succeeds
        let ok_site = handle_module_rpc(
            &core,
            "upsert_site_shortcut",
            json!({
                "site": {
                    "id": "jira",
                    "names": ["Jira", "jira", "看板"],
                    "url": "https://jira.example.com",
                    "search": "https://jira.example.com/secure/QuickSearch.jspa?searchString={query}"
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(ok_site["site"]["id"], "jira");

        // 3. Delete custom site shortcut
        let del_site = handle_module_rpc(
            &core,
            "delete_site_shortcut",
            json!({ "site_id": "jira" }),
        )
        .await
        .unwrap();
        assert_eq!(del_site["deleted"], true);

        // 4. Upsert custom search engine (requires `{query}`)
        let bad_eng = handle_module_rpc(
            &core,
            "upsert_search_engine",
            json!({
                "engine": {
                    "id": "kagi",
                    "name": "Kagi",
                    "url": "https://kagi.com/search"
                }
            }),
        )
        .await;
        assert!(bad_eng.is_err(), "Search engine without {{query}} must fail");

        let ok_eng = handle_module_rpc(
            &core,
            "upsert_search_engine",
            json!({
                "engine": {
                    "id": "kagi",
                    "name": "Kagi",
                    "url": "https://kagi.com/search?q={query}"
                },
                "set_default": true
            }),
        )
        .await
        .unwrap();
        assert_eq!(ok_eng["default_search"], "kagi");
    }

    #[tokio::test]
    async fn test_hotkey_conflict_detection_and_secret_free_export_import() {
        let (_tmp, core) = setup_test_core();

        // 1. `<Super>space` triggers high-severity IBus/Fcitx5 conflict warning
        let conflict = handle_module_rpc(
            &core,
            "check_hotkey_conflict",
            json!({ "hotkey": "<Super>space" }),
        )
        .await
        .unwrap();
        assert_eq!(conflict["conflict"], true);
        assert_eq!(conflict["recommended_hotkey"], "<Super><Shift>space");

        // 2. `<Super><Shift>space` has no conflict
        let clean = handle_module_rpc(
            &core,
            "check_hotkey_conflict",
            json!({ "hotkey": "<Super><Shift>space" }),
        )
        .await
        .unwrap();
        assert_eq!(clean["conflict"], false);

        // 3. Store a provider secret and export config bundle -> verify zero secret leakage
        let leak_check_key = "sk-export-must-never-contain-this-key-12345";
        let _ = handle_module_rpc(
            &core,
            "upsert_provider",
            json!({
                "provider": {
                    "id": "corp-gw",
                    "kind": "openai-compatible",
                    "base_url": "https://llm.corp.example.com/v1",
                    "trust": "trusted"
                },
                "api_key": leak_check_key
            }),
        )
        .await
        .unwrap();

        let bundle = handle_module_rpc(&core, "export_config_bundle", json!({}))
            .await
            .unwrap();
        assert_eq!(bundle["secret_free"], true);
        let serialized_bundle = serde_json::to_string(&bundle).unwrap();
        assert!(
            !serialized_bundle.contains(leak_check_key),
            "Exported bundle must never contain API keys"
        );

        // 4. Reset to defaults, then re-import bundle
        let _ = handle_module_rpc(&core, "reset_to_defaults", json!({ "domain_key": "all" }))
            .await
            .unwrap();
        let imp = handle_module_rpc(
            &core,
            "import_config_bundle",
            json!({ "bundle": bundle }),
        )
        .await
        .unwrap();
        assert_eq!(imp["imported"], true);
    }

    #[tokio::test]
    async fn test_provider_connection_and_tools_tester_b03_b04() {
        let (_tmp, core) = setup_test_core();

        // Spawn a lightweight local mock server to deterministically verify B-03 & B-04
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]);

                    let (status_line, body) = if req_str.contains("Bearer bad-key") {
                        (
                            "HTTP/1.1 401 Unauthorized",
                            r#"{"error":{"message":"invalid api key"}}"#,
                        )
                    } else if req_str.starts_with("GET /v1/models") {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"data":[{"id":"gpt-4o-mini"},{"id":"deepseek-chat"}]}"#,
                        )
                    } else if req_str.starts_with("POST /v1/chat/completions") {
                        (
                            "HTTP/1.1 200 OK",
                            r#"{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"ping_tool","arguments":"{\"echo\":\"intentos_b04_probe\"}"}}]}}]}"#,
                        )
                    } else {
                        ("HTTP/1.1 404 Not Found", r#"{"error":"not found"}"#)
                    };

                    let resp = format!(
                        "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status_line,
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let base_url = format!("http://{}/v1", addr);

        // 1. B-03 `ok`
        let ok_conn = handle_module_rpc(
            &core,
            "test_provider_connection",
            json!({
                "provider_id": "default-openai",
                "base_url": base_url,
                "api_key": "good-key",
                "model": "gpt-4o-mini"
            }),
        )
        .await
        .unwrap();
        assert_eq!(ok_conn["status"], "ok");

        // 2. B-03 `model_not_found`
        let missing_model = handle_module_rpc(
            &core,
            "test_provider_connection",
            json!({
                "provider_id": "default-openai",
                "base_url": base_url,
                "api_key": "good-key",
                "model": "nonexistent-model-999"
            }),
        )
        .await
        .unwrap();
        assert_eq!(missing_model["status"], "model_not_found");

        // 3. B-03 `auth_failed`
        let auth_fail = handle_module_rpc(
            &core,
            "test_provider_connection",
            json!({
                "provider_id": "default-openai",
                "base_url": base_url,
                "api_key": "bad-key"
            }),
        )
        .await
        .unwrap();
        assert_eq!(auth_fail["status"], "auth_failed");

        // 4. B-03 `unreachable`
        let unreachable = handle_module_rpc(
            &core,
            "test_provider_connection",
            json!({
                "provider_id": "default-openai",
                "base_url": "http://127.0.0.1:1/v1",
                "timeout_ms": 500
            }),
        )
        .await
        .unwrap();
        assert_eq!(unreachable["status"], "unreachable");

        // 5. B-04 `test_provider_tools` -> `supported: true`
        let tools_ok = handle_module_rpc(
            &core,
            "test_provider_tools",
            json!({
                "provider_id": "default-openai",
                "base_url": base_url,
                "api_key": "good-key",
                "model": "gpt-4o-mini"
            }),
        )
        .await
        .unwrap();
        assert_eq!(tools_ok["supported"], true);
        assert_eq!(tools_ok["status"], "ok");
    }
}
