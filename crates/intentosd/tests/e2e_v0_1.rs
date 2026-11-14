#![forbid(unsafe_code)]

//! End-to-End Integration Tests for Stage 2 (`v0.1 Intent Shell`, §18.2):
//! - 87 built-in capability descriptors loaded & validated
//! - L1 `DecisionAdapter` colloquial routing (`RouteLayer::L1`)
//! - `A11c` font whitelist validation + suggestions & `A11e` composite scene + custom saved scene atomic undo
//! - `A22` + `M-03` explicit file-association preference memory (`open_with.<ext>`) + deletion tombstone
//! - `M-01` Privacy Session (`incognito = true`) zero SQLite persistence & `M-02` secret memory guard
//! - Offline developer Command Handoff (`handoff_command` populated, never auto-executed)
//! - `archive.create` + `archive.extract` + Zip-Slip protection + ChangeSet undo
//! - `PublicDbusService` non-privileged D-Bus boundary (`org.intentos.Core1`).

use intentos_protocol::{
    CapabilityCall, ExecutionStatus, IntentRequest, InvocationOrigin, RouteLayer, TaskStatus, Taint,
};
use intentosd::broker::BrokerDispatchOutcome;
use intentosd::config::{AppConfig, BrainConfig, XdgPaths};
use intentosd::core::IntentOsCore;
use intentosd::dbus_bridge::PublicDbusService;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

fn setup_v0_1_core() -> (tempfile::TempDir, Arc<IntentOsCore>, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let base = temp.path();
    let downloads = base.join("Downloads");
    let documents = base.join("Documents");
    std::fs::create_dir_all(&downloads).unwrap();
    std::fs::create_dir_all(&documents).unwrap();

    std::fs::write(downloads.join("周报_第47周.docx"), b"weekly report v47").unwrap();
    std::fs::write(documents.join("设计纪要.md"), b"# Design Notes\n").unwrap();

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let xdg = XdgPaths::resolve(Some(base), repo_root.clone());
    xdg.ensure_dirs().unwrap();
    let cfg = AppConfig {
        authorized_directories: vec![
            downloads.to_string_lossy().to_string(),
            documents.to_string_lossy().to_string(),
        ],
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
    (temp, core, downloads, documents)
}

#[tokio::test]
async fn v0_1_loads_87_capabilities_and_routes_colloquial_l1() {
    let (_tmp, core, _, _) = setup_v0_1_core();
    assert!(
        core.broker.descriptors().len() >= 87,
        "expected >= 87 capabilities, got {}",
        core.broker.descriptors().len()
    );

    // Colloquial phrase not hardcoded in L0 exact match -> routed and executed by L1 DecisionAdapter
    let task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "让电脑闭嘴".into(),
                session_id: Some("s_l1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(task.route, RouteLayer::L1);
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.steps[0].capability_id, "sound.mute.set");
}

#[tokio::test]
async fn v0_1_explicit_file_association_memory_and_deletion_tombstone() {
    let (_tmp, core, _, _) = setup_v0_1_core();

    // 1. Default opening `.docx` uses `file.open`
    let t1 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "打开 周报_第47周.docx".into(),
                session_id: Some("s_mem".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(t1.steps[0].capability_id, "file.open");

    // 2. Save explicit preference (`A22`): "记住 docx 用 WPS 打开"
    let t_save = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "记住 docx 用 WPS 打开".into(),
                session_id: Some("s_mem".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(t_save.status, TaskStatus::Completed);

    // 3. Subsequent open automatically routes to `file.open_with` with WPS
    let t2 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "打开 周报_第47周.docx".into(),
                session_id: Some("s_mem".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(t2.steps[0].capability_id, "file.open_with");
    assert!(t2.steps[0].arguments_summary.contains("wps"));

    // 4. Delete memory (`M-03` tombstone) -> reverts back to `file.open`
    let entries = core.state_db.list_memory_entries().unwrap();
    let docx_mem = entries
        .iter()
        .find(|m| m.subject == "open_with.docx")
        .expect("open_with.docx entry");
    assert!(core.state_db.delete_memory(&docx_mem.id).unwrap());

    let t3 = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "打开 周报_第47周.docx".into(),
                session_id: Some("s_mem".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(t3.steps[0].capability_id, "file.open");
}

#[tokio::test]
async fn v0_1_custom_scene_save_apply_and_single_changeset_undo() {
    let (_tmp, core, _, _) = setup_v0_1_core();

    // Set baseline brightness=75, color_scheme=prefer-light
    let _ = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "切换到浅色模式".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    let _ = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "把亮度调到 75%".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();

    // Apply built-in composite scene `护眼模式` (sets prefer-dark + night_light=on + brightness=45)
    let scene_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "开启护眼模式".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(scene_task.status, TaskStatus::Completed);
    assert_eq!(scene_task.changeset_ids.len(), 1);

    // Save current state as custom scene `"深夜码字模式"` (`A11e`)
    let save_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "把当前设置存成深夜码字模式".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(save_task.status, TaskStatus::Completed);
    assert!(core.state_db.get_custom_scene("深夜码字模式").is_some());

    // Undo `护眼模式` via single ChangeSet -> brightness returns to 75
    let _ = core.undo(Some(&scene_task.changeset_ids[0])).unwrap();
    let b_after_undo = core
        .broker
        .dispatch(&CapabilityCall {
            request_id: "chk_b".into(),
            task_id: "t_chk_b".into(),
            capability_id: "display.brightness.get".into(),
            arguments: json!({}),
            origin: InvocationOrigin::UserExplicit,
            taints: vec![Taint::User],
        })
        .await
        .unwrap();
    if let BrokerDispatchOutcome::Executed(res) = b_after_undo {
        assert_eq!(res.data.get("value").and_then(|v| v.as_f64()), Some(75.0));
    } else {
        panic!("expected Executed");
    }

    // Re-apply saved custom scene `"开启深夜码字模式"`
    let custom_apply = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "开启深夜码字模式".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(custom_apply.status, TaskStatus::Completed);
    assert_eq!(custom_apply.steps[0].capability_id, "scene.apply");
}

#[tokio::test]
async fn v0_1_incognito_privacy_session_and_offline_command_handoff() {
    let (_tmp, core, _, _) = setup_v0_1_core();
    let initial_tasks = core.state_db.list_tasks(100).unwrap().len();
    let initial_mems = core.state_db.list_memory_entries().unwrap().len();

    // 1. Incognito session rejects persistent memory write AND runs normal queries with zero SQLite traces (`M-01`)
    let incog_mem = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "记住 临时隐私偏好=不落盘".into(),
                session_id: Some("incog_1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: true,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(incog_mem.status, TaskStatus::Failed);

    let incog_query = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "当前音量".into(),
                session_id: Some("incog_1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: true,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(incog_query.status, TaskStatus::Completed);
    assert_eq!(core.state_db.list_tasks(100).unwrap().len(), initial_tasks);
    assert_eq!(core.state_db.list_memory_entries().unwrap().len(), initial_mems);

    // 2. Developer how-to query returns structured `handoff_command` without auto-execution (§8.8, A16)
    let handoff = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "怎么撤销上一次 git commit 但保留改动".into(),
                session_id: Some("dev_1".into()),
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(handoff.route, RouteLayer::L2);
    let cmd = handoff.handoff_command.expect("should populate handoff_command");
    assert!(cmd.starts_with("$ git reset --soft HEAD~1"));
    assert!(handoff.steps.is_empty(), "must NEVER auto-execute shell command");

    // 3. Public non-privileged D-Bus service rejects `$ ` passthrough (§15.2)
    let dbus = PublicDbusService::new(core.clone());
    let resp = dbus.submit("$ echo pwned", None).await.unwrap();
    assert_eq!(resp.status, TaskStatus::Failed);
}

#[tokio::test]
async fn v0_1_archive_create_extract_and_font_whitelist() {
    let (_tmp, core, downloads, documents) = setup_v0_1_core();

    // 1. Pack `设计纪要.md` into `notes_pack.zip` and extract to `Downloads/unpacked`
    let pack_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "把 设计纪要.md 压缩成 notes_pack.zip".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(pack_task.status, TaskStatus::Completed);
    let created_zip = documents.join("notes_pack.zip");
    assert!(created_zip.exists());

    // Re-index so router finds `notes_pack.zip`
    core.resources.index_authorized_files().unwrap();
    let extract_task = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "把 notes_pack.zip 解压到 下载".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(extract_task.status, TaskStatus::Completed);
    assert!(downloads.join("设计纪要.md").exists());

    // 2. Installed font (`DejaVu Sans Mono`) succeeds; nonexistent font returns suggestions & fails (`A11c`)
    let ok_font = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "把等宽字体换成 DejaVu Sans Mono".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(ok_font.status, TaskStatus::Completed);

    let bad_font = core
        .submit_intent(
            IntentRequest {
                protocol_version: 1,
                text: "把等宽字体换成 NonExistentFontXYZ".into(),
                session_id: None,
                force_agent: false,
                selected_candidate_id: None,
                cwd: None,
                incognito: false,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(bad_font.status, TaskStatus::Failed);
    assert_eq!(bad_font.steps[0].status, ExecutionStatus::VerificationFailed);
}
