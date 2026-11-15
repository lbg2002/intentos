#![forbid(unsafe_code)]

//! Functional Module 3: E2 Sandbox Staging, Grant Envelopes, Skills/Workflows & Drive Engine (`crates/intentosd/src/execution_hub/`)
//!
//! Assigned to **Agent-3** (`exec`).
//! Responsibilities (per `docs/IntentOS_设计方案_v0.3.md` §7.4–§7.6, §8.4, §10.3, §11.2–§11.5, §13.1–§13.4):
//! 1. E2 Sandboxed Staged Execution (`e2_staging.rs`: run command/script in isolated staging/overlay dir, compute file tree diff,
//!    preview & commit via `SafeFsEngine` into atomic reversible `ChangeSet`)
//! 2. Grant Envelope & Progressive Trust (`grant_envelope.rs`: multi-step task authorization envelopes, scope/effect/op-count checks,
//!    and automatic narrow long-term rule proposals after repeated approvals)
//! 3. Project Registry & Memory Candidates (`project_memory.rs`: Git repo discovery `R-05`, project-scoped memories `M-04`,
//!    session-end memory candidate extraction & confirmation `M-05`, provenance tracking `M-06`)
//! 4. Skill & Workflow Registry (`skill_workflow.rs`: Markdown + YAML frontmatter parser, workflow step learning from completed tasks `M-07`)
//! 5. Drive Engine (`drive_scheduler.rs`: scheduled tasks, filesystem event triggers with debounce & L1 Decision filter, autonomy levels L0/L1/L2)

pub mod drive_scheduler;
pub mod e2_staging;
pub mod grant_envelope;
pub mod project_memory;
pub mod skill_workflow;

use crate::core::IntentOsCore;
use intentos_protocol::{CapabilityCall, InvocationOrigin, Taint};
use serde_json::{Value, json};

pub async fn handle_module_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    match action {
        "ping" => Ok(json!({
            "module": "execution_hub",
            "status": "ready",
            "active_sessions": core.sessions.active_count(),
            "payload": payload,
        })),

        // 3.1 E2 Sandboxed Staged Execution (§8.4)
        "stage_e2_command" => {
            let command = payload
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let work_dir = payload.get("work_dir").and_then(|v| v.as_str());
            let task_id = payload.get("task_id").and_then(|v| v.as_str());
            let allow_network = payload
                .get("allow_network")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let proposal =
                e2_staging::stage_e2_command(core, command, work_dir, task_id, allow_network)
                    .await?;
            Ok(serde_json::to_value(proposal)?)
        }
        "commit_e2_proposal" => {
            let proposal_id = payload
                .get("proposal_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 proposal_id"))?;
            e2_staging::commit_e2_proposal(core, proposal_id)
        }
        "discard_e2_proposal" => {
            let proposal_id = payload
                .get("proposal_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 proposal_id"))?;
            e2_staging::discard_e2_proposal(core, proposal_id)
        }
        "list_e2_proposals" => {
            let items = e2_staging::list_e2_proposals(core);
            Ok(json!({ "proposals": items }))
        }

        // 3.2 GrantEnvelope & Progressive Trust (§10.3)
        "create_grant_envelope" => {
            let rec = grant_envelope::create_grant_envelope(core, &payload)?;
            Ok(serde_json::to_value(rec)?)
        }
        "check_within_envelope" => {
            let envelope_id = payload
                .get("envelope_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 envelope_id"))?;
            let capability_id = payload
                .get("capability_id")
                .and_then(|v| v.as_str())
                .unwrap_or("file.move")
                .to_string();
            let arguments = payload
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let effect_str = payload
                .get("effect")
                .and_then(|v| v.as_str())
                .unwrap_or("write.reversible");
            let effect = grant_envelope::parse_effect_str(effect_str);
            let op_count = payload
                .get("operation_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u32;
            let requires_network = payload
                .get("requires_network")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let taints: Vec<Taint> = payload
                .get("taints")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_else(|| vec![Taint::User]);

            let call = CapabilityCall {
                request_id: "req_check".to_string(),
                task_id: payload
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("task_check")
                    .to_string(),
                capability_id,
                arguments,
                origin: InvocationOrigin::L2AgentPlan,
                taints,
            };
            let outcome = grant_envelope::check_within_envelope(
                core,
                envelope_id,
                &call,
                effect,
                op_count,
                requires_network,
            );
            Ok(serde_json::to_value(outcome)?)
        }
        "record_approval_decision" => {
            let capability_id = payload
                .get("capability_id")
                .and_then(|v| v.as_str())
                .unwrap_or("file.move");
            let resource_scope = payload
                .get("resource_scope")
                .and_then(|v| v.as_str())
                .unwrap_or("~/Downloads");
            let effect_str = payload
                .get("effect")
                .and_then(|v| v.as_str())
                .unwrap_or("write.reversible");
            let effect = grant_envelope::parse_effect_str(effect_str);
            let approved = payload
                .get("approved")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let decision_ms = payload
                .get("decision_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(1800);
            let proposal = grant_envelope::record_approval_decision(
                core,
                capability_id,
                resource_scope,
                effect,
                approved,
                decision_ms,
            );
            Ok(json!({
                "recorded": true,
                "rule_proposal": proposal,
            }))
        }
        "list_envelopes_and_rules" => Ok(grant_envelope::list_envelopes_and_rules(core)),
        "confirm_rule_proposal" => {
            let proposal_id = payload
                .get("proposal_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 proposal_id"))?;
            let rule = grant_envelope::confirm_rule_proposal(core, proposal_id)?;
            Ok(json!({
                "confirmed": true,
                "rule": rule,
            }))
        }
        "revoke_grant_or_rule" => {
            let id = payload
                .get("id")
                .or_else(|| payload.get("envelope_id"))
                .or_else(|| payload.get("rule_id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 id"))?;
            grant_envelope::revoke_grant_or_rule(core, id)
        }

        // 3.2b Security Posture & Interactive Session Scope Grants (Wave 3)
        "get_security_posture" => Ok(grant_envelope::get_security_posture(core)),
        "set_security_mode" => {
            let mode = payload
                .get("mode")
                .or_else(|| payload.get("security_mode"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 mode"))?;
            grant_envelope::set_security_mode(core, mode)
        }
        "grant_session_scope" => {
            let scope_kind = payload
                .get("scope_kind")
                .or_else(|| payload.get("kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("directory");
            let scope_value = payload
                .get("scope_value")
                .or_else(|| payload.get("value"))
                .or_else(|| payload.get("path"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 scope_value"))?;
            let ttl_minutes = payload
                .get("ttl_minutes")
                .and_then(|v| v.as_i64())
                .unwrap_or(60);
            grant_envelope::grant_session_scope(core, scope_kind, scope_value, ttl_minutes)
        }
        "revoke_session_grant" => {
            let id = payload
                .get("id")
                .or_else(|| payload.get("grant_id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 id"))?;
            grant_envelope::revoke_session_grant(core, id)
        }

        // 3.3 Project Registry & Memory Candidates (`R-05`, `M-04`, `M-05`, `M-06`)
        "list_projects" => {
            let rescan = payload
                .get("rescan")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let projects = project_memory::discover_and_list_projects(core, rescan)?;
            Ok(json!({
                "count": projects.len(),
                "projects": projects,
            }))
        }
        "list_memory_candidates" => project_memory::list_memory_candidates(core),
        "propose_memory_candidate" => {
            let subject = payload
                .get("subject")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 subject"))?;
            let value = payload
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 value"))?;
            let scope = payload.get("scope").and_then(|v| v.as_str());
            let mem_type = payload.get("mem_type").and_then(|v| v.as_str());
            let task_id = payload.get("task_id").and_then(|v| v.as_str());
            let cand = project_memory::propose_custom_memory_candidate(
                core, subject, value, scope, mem_type, task_id,
            )?;
            Ok(json!({ "candidate": cand }))
        }
        "confirm_memory_candidate" | "reject_memory_candidate" => {
            let candidate_id = payload
                .get("candidate_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 candidate_id"))?;
            let reject = action == "reject_memory_candidate"
                || payload
                    .get("rejected")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                || payload
                    .get("action")
                    .and_then(|v| v.as_str())
                    .map(|a| a.eq_ignore_ascii_case("reject") || a.eq_ignore_ascii_case("ignore"))
                    .unwrap_or(false);
            project_memory::confirm_memory_candidate(core, candidate_id, reject)
        }

        // 3.4 Skill & Workflow Registry & Task Learning (§7.1, §11.4, `M-07`)
        "list_skills_and_workflows" => {
            let all = skill_workflow::scan_skills_and_workflows(core)?;
            let skills: Vec<&skill_workflow::SkillOrWorkflowEntry> =
                all.iter().filter(|e| e.kind == "skill").collect();
            let workflows: Vec<&skill_workflow::SkillOrWorkflowEntry> =
                all.iter().filter(|e| e.kind == "workflow").collect();
            Ok(json!({
                "skills": skills,
                "workflows": workflows,
                "items": all,
                "count": all.len(),
            }))
        }
        "learn_workflow_from_task" => {
            let task_id = payload
                .get("task_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 task_id"))?;
            let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let trigger_phrase = payload
                .get("trigger_phrase")
                .or_else(|| payload.get("trigger"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            skill_workflow::learn_workflow_from_task(core, task_id, name, trigger_phrase)
        }
        "run_workflow" => {
            let workflow_id = payload
                .get("workflow_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 workflow_id"))?;
            let params = payload.get("parameters");
            skill_workflow::run_workflow(core, workflow_id, params).await
        }

        // 3.5 Drive Engine (§13.3–§13.4)
        "list_drive_triggers" => Ok(drive_scheduler::list_drive_triggers(core)),
        "upsert_drive_trigger" => drive_scheduler::upsert_drive_trigger(core, &payload),
        "delete_drive_trigger" => {
            let rule_id = payload
                .get("rule_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少参数 rule_id"))?;
            drive_scheduler::delete_drive_trigger(core, rule_id)
        }
        "trigger_dry_run" => {
            let rule_id = payload
                .get("rule_id")
                .and_then(|v| v.as_str())
                .unwrap_or("research.pdf-arrival");
            let sample_path = payload
                .get("sample_path")
                .and_then(|v| v.as_str())
                .unwrap_or("~/Downloads/paper.pdf");
            let rapid = payload
                .get("simulate_rapid_duplicate")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            drive_scheduler::trigger_dry_run(core, rule_id, sample_path, rapid).await
        }

        other => anyhow::bail!("execution_hub: unknown action '{}'", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_or_create_configs;
    use intentos_protocol::{Effect, IntentRequest, TaskStatus};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn setup_test_core() -> (TempDir, std::sync::Arc<IntentOsCore>, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let paths = crate::config::XdgPaths::resolve(Some(tmp.path()), repo_root.clone());
        let (mut app_cfg, brain_cfg) = load_or_create_configs(&paths).unwrap();
        let work_dir = tmp.path().join("workspace");
        std::fs::create_dir_all(&work_dir).unwrap();
        app_cfg.authorized_directories = vec![work_dir.to_string_lossy().to_string()];
        std::fs::write(
            paths.config_dir.join("config.toml"),
            toml::to_string_pretty(&app_cfg).unwrap(),
        )
        .unwrap();
        std::fs::write(
            paths.config_dir.join("brain.toml"),
            toml::to_string_pretty(&brain_cfg).unwrap(),
        )
        .unwrap();

        let core = IntentOsCore::initialize(Some(tmp.path()), repo_root).unwrap();
        (tmp, core, work_dir)
    }

    #[tokio::test]
    async fn e2_staging_diff_commit_and_undo_closed_loop() {
        let (_tmp, core, work_dir) = setup_test_core();

        // Prepare initial files in authorized work_dir
        let readme = work_dir.join("README.md");
        let old_note = work_dir.join("obsolete.txt");
        std::fs::write(&readme, "# Project\nversion = 1\n").unwrap();
        std::fs::write(&old_note, "delete me").unwrap();

        // 1. Stage a multi-file command in E2 sandbox
        let stage_res = handle_module_rpc(
            &core,
            "stage_e2_command",
            json!({
                "command": "printf '# Project\\nversion = 2\\n' > README.md && printf 'new summary\\n' > summary.txt && rm obsolete.txt",
                "work_dir": work_dir.to_string_lossy(),
                "task_id": "task_e2_01"
            }),
        )
        .await
        .unwrap();

        let proposal_id = stage_res["proposal_id"].as_str().unwrap().to_string();
        assert_eq!(stage_res["status"], "staged");
        assert_eq!(stage_res["requires_approval"], true);
        assert_eq!(
            stage_res["diffs"]["added_files"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            stage_res["diffs"]["modified_files"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            stage_res["diffs"]["deleted_files"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let mod_diff = &stage_res["diffs"]["modified_files"][0]["unified_diff"]
            .as_str()
            .unwrap();
        assert!(mod_diff.contains("-version = 1"));
        assert!(mod_diff.contains("+version = 2"));

        // Verify real directory was NOT modified during staging
        assert_eq!(
            std::fs::read_to_string(&readme).unwrap(),
            "# Project\nversion = 1\n"
        );
        assert!(old_note.exists());
        assert!(!work_dir.join("summary.txt").exists());

        // 2. Commit staged proposal via SafeFsEngine
        let commit_res = handle_module_rpc(
            &core,
            "commit_e2_proposal",
            json!({ "proposal_id": proposal_id }),
        )
        .await
        .unwrap();
        assert_eq!(commit_res["committed"], true);
        let cs_id = commit_res["changeset_id"].as_str().unwrap().to_string();

        // Verify real directory now reflects all staged changes
        assert_eq!(
            std::fs::read_to_string(&readme).unwrap(),
            "# Project\nversion = 2\n"
        );
        assert_eq!(
            std::fs::read_to_string(work_dir.join("summary.txt")).unwrap(),
            "new summary\n"
        );
        assert!(!old_note.exists());

        // 3. One-click Undo of the E2 ChangeSet restores added, modified, and deleted files!
        let (undone_cs, _msg) = core.undo(Some(&cs_id)).unwrap();
        assert_eq!(undone_cs.id, cs_id);
        assert_eq!(
            std::fs::read_to_string(&readme).unwrap(),
            "# Project\nversion = 1\n"
        );
        assert_eq!(std::fs::read_to_string(&old_note).unwrap(), "delete me");
        assert!(!work_dir.join("summary.txt").exists());
    }

    #[tokio::test]
    async fn grant_envelope_bounds_and_progressive_trust_rules() {
        let (_tmp, core, work_dir) = setup_test_core();
        let scope_dir = work_dir.to_string_lossy().to_string();

        // 1. Create a GrantEnvelope with max_operations = 2, max_effect = write.reversible
        let env_res = handle_module_rpc(
            &core,
            "create_grant_envelope",
            json!({
                "task_id": "task_env_1",
                "capabilities": ["file.move", "file.search"],
                "resource_scope": [scope_dir],
                "max_effect": "write.reversible",
                "max_operations": 2,
                "network": false
            }),
        )
        .await
        .unwrap();
        let envelope_id = env_res["envelope"]["envelope_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Step 1 inside scope & capability -> Allowed (used=1, remaining=1)
        let ok1 = handle_module_rpc(
            &core,
            "check_within_envelope",
            json!({
                "envelope_id": envelope_id,
                "capability_id": "file.move",
                "arguments": {
                    "source": work_dir.join("a.txt").to_string_lossy(),
                    "target": work_dir.join("b.txt").to_string_lossy()
                },
                "effect": "write.reversible",
                "operation_count": 1
            }),
        )
        .await
        .unwrap();
        assert_eq!(ok1["status"], "allowed");
        assert_eq!(ok1["remaining_operations"], 1);

        // Out-of-scope directory -> Blocked (`scope_exceeded`)
        let out_scope = handle_module_rpc(
            &core,
            "check_within_envelope",
            json!({
                "envelope_id": envelope_id,
                "capability_id": "file.move",
                "arguments": {
                    "source": "/tmp/outside_scope/a.txt",
                    "target": work_dir.join("b.txt").to_string_lossy()
                },
                "effect": "write.reversible",
                "operation_count": 1
            }),
        )
        .await
        .unwrap();
        assert_eq!(out_scope["status"], "out_of_bounds");
        assert_eq!(out_scope["violation_kind"], "scope_exceeded");

        // Higher effect (`write.destructive` / `confirm_each`) -> Blocked
        let high_eff = handle_module_rpc(
            &core,
            "check_within_envelope",
            json!({
                "envelope_id": envelope_id,
                "capability_id": "file.move",
                "arguments": {},
                "effect": "write.destructive",
                "operation_count": 1
            }),
        )
        .await
        .unwrap();
        assert_eq!(high_eff["status"], "out_of_bounds");

        // Exceeding max_operations (already used 1, requesting 2 > max 2) -> Blocked
        let over_ops = handle_module_rpc(
            &core,
            "check_within_envelope",
            json!({
                "envelope_id": envelope_id,
                "capability_id": "file.move",
                "arguments": {},
                "effect": "write.reversible",
                "operation_count": 2
            }),
        )
        .await
        .unwrap();
        assert_eq!(over_ops["status"], "out_of_bounds");
        assert_eq!(over_ops["violation_kind"], "max_operations_exceeded");

        // 2. Progressive Trust: 3 approvals of `file.move` in `scope_dir` (1 from envelope creation + 2 more)
        let _ = grant_envelope::record_approval_decision(
            &core,
            "file.move",
            &scope_dir,
            Effect::WriteReversible,
            true,
            900,
        );
        let prop = grant_envelope::record_approval_decision(
            &core,
            "file.move",
            &scope_dir,
            Effect::WriteReversible,
            true,
            800,
        );
        assert!(
            prop.is_some(),
            "3rd consecutive approval must propose a rule"
        );
        let prop_id = prop.unwrap().proposal_id;

        // Verify confirm_each effects NEVER generate a RuleProposal even after 5 approvals
        for _ in 0..5 {
            let never = grant_envelope::record_approval_decision(
                &core,
                "process.terminate",
                &scope_dir,
                Effect::ProcessControl,
                true,
                500,
            );
            assert!(never.is_none());
        }

        // Confirm the RuleProposal into a TrustedRule
        let conf = handle_module_rpc(
            &core,
            "confirm_rule_proposal",
            json!({ "proposal_id": prop_id }),
        )
        .await
        .unwrap();
        assert_eq!(conf["confirmed"], true);
        let rule_id = conf["rule"]["rule_id"].as_str().unwrap().to_string();

        // Revoke rule
        let rev = handle_module_rpc(&core, "revoke_grant_or_rule", json!({ "id": rule_id }))
            .await
            .unwrap();
        assert_eq!(rev["revoked"], true);
    }

    #[tokio::test]
    async fn project_discovery_memory_candidates_and_workflow_learning() {
        let (_tmp, core, work_dir) = setup_test_core();

        // Create a mock Rust/Git project inside authorized work_dir
        let proj_dir = work_dir.join("demo-app");
        std::fs::create_dir_all(proj_dir.join(".git")).unwrap();
        std::fs::write(proj_dir.join(".git/HEAD"), "ref: refs/heads/feat/v03\n").unwrap();
        std::fs::write(
            proj_dir.join("Cargo.toml"),
            "[package]\nname = \"demo-app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        // 1. Discover projects (`R-05`)
        let proj_res = handle_module_rpc(&core, "list_projects", json!({ "rescan": true }))
            .await
            .unwrap();
        let projects = proj_res["projects"].as_array().unwrap();
        assert!(projects.iter().any(|p| {
            p["name"] == "demo-app"
                && p["git_branch"] == "feat/v03"
                && p["tech_stack"].as_array().unwrap().contains(&json!("Rust"))
        }));

        // 2. Run a real L0 task so we can extract both Memory Candidates and learn a Workflow (`M-05`, `M-07`)
        let sample_file = work_dir.join("note.txt");
        std::fs::write(&sample_file, "hello workflow").unwrap();
        let task = core
            .submit_intent(
                IntentRequest {
                    protocol_version: 1,
                    text: "开启护眼模式".to_string(),
                    session_id: None,
                    force_agent: false,
                    selected_candidate_id: None,
                    cwd: Some(proj_dir.to_string_lossy().to_string()),
                    incognito: false,
                    privacy_policy: None,
                },
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(task.status, TaskStatus::Completed);

        // 3. List memory candidates extracted from the completed task and confirm one (`M-05`, `M-06`)
        let mem_cands = handle_module_rpc(&core, "list_memory_candidates", json!({}))
            .await
            .unwrap();
        let cands_arr = mem_cands["candidates"].as_array().unwrap();
        assert!(!cands_arr.is_empty());
        let first_cand_id = cands_arr[0]["candidate_id"].as_str().unwrap().to_string();

        let confirmed = handle_module_rpc(
            &core,
            "confirm_memory_candidate",
            json!({ "candidate_id": first_cand_id }),
        )
        .await
        .unwrap();
        assert_eq!(confirmed["confirmed"], true);

        // 4. Learn a reusable Workflow from the completed task (`M-07`)
        let learned = handle_module_rpc(
            &core,
            "learn_workflow_from_task",
            json!({
                "task_id": task.id,
                "name": "一键开启夜间开发护眼",
                "trigger_phrase": "夜间开发护眼"
            }),
        )
        .await
        .unwrap();
        assert_eq!(learned["saved"], true);
        let wf_id = learned["workflow_id"].as_str().unwrap().to_string();
        let skill_md_path = PathBuf::from(learned["skill_md_path"].as_str().unwrap());
        assert!(skill_md_path.exists());

        // Verify `list_skills_and_workflows` includes both builtin skills and our newly learned workflow
        let listed_sw = handle_module_rpc(&core, "list_skills_and_workflows", json!({}))
            .await
            .unwrap();
        assert!(
            listed_sw["workflows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["id"] == wf_id)
        );

        // 5. Run the learned workflow (`run_workflow`)
        let run_res = handle_module_rpc(&core, "run_workflow", json!({ "workflow_id": wf_id }))
            .await
            .unwrap();
        assert_eq!(run_res["status"], "completed");
        assert_eq!(run_res["drift_detected"], false);
    }

    #[tokio::test]
    async fn drive_engine_debounce_ignore_crdownload_and_l1_filter() {
        let (_tmp, core, _work_dir) = setup_test_core();

        // 1. `.crdownload` incomplete download MUST be debounced/ignored
        let cr_res = handle_module_rpc(
            &core,
            "trigger_dry_run",
            json!({
                "rule_id": "research.pdf-arrival",
                "sample_path": "~/Downloads/attention_is_all_you_need.pdf.crdownload"
            }),
        )
        .await
        .unwrap();
        assert_eq!(cr_res["status"], "ignored_incomplete_download");
        assert_eq!(cr_res["debounced"], true);

        // 2. Non-academic PDF (`invoice_2026.pdf`) MUST be filtered out by L1 binary decision
        let inv_res = handle_module_rpc(
            &core,
            "trigger_dry_run",
            json!({
                "rule_id": "research.pdf-arrival",
                "sample_path": "~/Downloads/invoice_2026.pdf"
            }),
        )
        .await
        .unwrap();
        assert_eq!(inv_res["status"], "filtered_out_by_l1");
        assert_eq!(inv_res["l1_passed"], false);

        // 3. Academic paper PDF (`arxiv_2611_llm_agent_survey.pdf`) passes L1 and produces L1_Suggest card
        let paper_res = handle_module_rpc(
            &core,
            "trigger_dry_run",
            json!({
                "rule_id": "research.pdf-arrival",
                "sample_path": "~/Downloads/arxiv_2611_llm_agent_survey.pdf"
            }),
        )
        .await
        .unwrap();
        assert_eq!(paper_res["status"], "suggested");
        assert_eq!(paper_res["l1_passed"], true);
        assert!(paper_res["suggestion_card"].is_object());
    }

    #[tokio::test]
    async fn workflow_resource_drift_fails_safely_and_e2_discard_cleans_up() {
        let (_tmp, core, work_dir) = setup_test_core();

        // 1. Test E2 discard_e2_proposal
        let stage_res = handle_module_rpc(
            &core,
            "stage_e2_command",
            json!({
                "command": "echo 'temp' > discard_me.txt",
                "work_dir": work_dir.to_string_lossy(),
            }),
        )
        .await
        .unwrap();
        let pid = stage_res["proposal_id"].as_str().unwrap();
        let staging_dir = PathBuf::from(stage_res["staging_dir"].as_str().unwrap());
        assert!(staging_dir.exists());

        let disc = handle_module_rpc(&core, "discard_e2_proposal", json!({ "proposal_id": pid }))
            .await
            .unwrap();
        assert_eq!(disc["discarded"], true);
        assert!(!staging_dir.exists());
        assert!(!work_dir.join("discard_me.txt").exists());

        // 2. Test workflow resource drift detection (§11.4)
        let src_file = work_dir.join("report.txt");
        let dst_file = work_dir.join("archive/report.txt");
        std::fs::write(&src_file, "important content").unwrap();

        let move_task = core
            .submit_intent(
                IntentRequest {
                    protocol_version: 1,
                    text: format!("把 {} 移到 {}", src_file.display(), dst_file.display()),
                    session_id: None,
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
        assert_eq!(move_task.status, TaskStatus::Completed);

        // Learn workflow from the file move task
        let learned = handle_module_rpc(
            &core,
            "learn_workflow_from_task",
            json!({
                "task_id": move_task.id,
                "name": "归档报告工作流",
                "trigger_phrase": "归档报告"
            }),
        )
        .await
        .unwrap();
        let wf_id = learned["workflow_id"].as_str().unwrap().to_string();

        // Now `src_file` no longer exists (it was moved to `dst_file`), so re-running the workflow
        // MUST detect resource drift and fail safely without guessing!
        let drift_res = handle_module_rpc(&core, "run_workflow", json!({ "workflow_id": wf_id }))
            .await
            .unwrap();
        assert_eq!(drift_res["status"], "failed_drift");
        assert_eq!(drift_res["drift_detected"], true);
    }

    #[tokio::test]
    async fn security_posture_modes_and_session_scope_rpc_roundtrip() {
        let (tmp, core, _work_dir) = setup_test_core();
        let outside_dir = tmp.path().join("outside_opt");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let outside_file = outside_dir.join("sample.txt");
        std::fs::write(&outside_file, "hello").unwrap();

        let posture0 = handle_module_rpc(&core, "get_security_posture", json!({}))
            .await
            .unwrap();
        assert_eq!(posture0["security_mode"], "balanced");
        assert!(posture0["session_grants"].as_array().unwrap().is_empty());

        // Switch security mode
        let set_res = handle_module_rpc(&core, "set_security_mode", json!({ "mode": "strict" }))
            .await
            .unwrap();
        assert_eq!(set_res["security_mode"], "strict");

        // Forbidden path cannot be granted
        assert!(
            handle_module_rpc(
                &core,
                "grant_session_scope",
                json!({
                    "scope_kind": "directory",
                    "scope_value": "~/.ssh",
                    "ttl_minutes": 30
                }),
            )
            .await
            .is_err()
        );

        // Grant valid outside directory scope -> syncs both PolicyEngine and SafeFsEngine
        let granted = handle_module_rpc(
            &core,
            "grant_session_scope",
            json!({
                "scope_kind": "directory",
                "scope_value": outside_file.to_string_lossy(),
                "ttl_minutes": 60
            }),
        )
        .await
        .unwrap();
        assert_eq!(granted["ok"], true);
        let grant_id = granted["grant"]["id"].as_str().unwrap().to_string();
        assert_eq!(
            granted["approved_root"].as_str().unwrap(),
            outside_dir.to_string_lossy()
        );

        let posture1 = handle_module_rpc(&core, "get_security_posture", json!({}))
            .await
            .unwrap();
        assert_eq!(posture1["security_mode"], "strict");
        assert_eq!(posture1["session_grants"].as_array().unwrap().len(), 1);
        assert!(
            posture1["approved_roots"]
                .as_array()
                .unwrap()
                .contains(&json!(outside_dir.to_string_lossy().to_string()))
        );

        // Revoke session grant -> removes both grant and approved_root
        let rev = handle_module_rpc(&core, "revoke_session_grant", json!({ "id": grant_id }))
            .await
            .unwrap();
        assert_eq!(rev["revoked"], true);
        assert!(rev["session_grants"].as_array().unwrap().is_empty());
        assert!(rev["approved_roots"].as_array().unwrap().is_empty());
    }
}
