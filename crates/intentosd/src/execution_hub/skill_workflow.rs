#![forbid(unsafe_code)]

//! Skill & Workflow Registry (`SKILL.md` YAML frontmatter + Markdown parser),
//! Workflow Learning from Completed Tasks (`M-07`), and Controlled Workflow Execution
//! with Policy Engine & Resource Drift Detection (`docs/IntentOS_设计方案_v0.3.md` §7.1, §11.4).

use crate::broker::BrokerDispatchOutcome;
use crate::core::IntentOsCore;
use chrono::Utc;
use intentos_protocol::{
    CapabilityCall, DataClass, ExecutionStatus, InvocationOrigin, RouteLayer, Taint, Task,
    TaskBudget, TaskStatus, TaskStep, TaskTrigger,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStepSpec {
    pub step_index: usize,
    pub capability_id: String,
    #[serde(default = "empty_json_obj")]
    pub arguments: Value,
    #[serde(default)]
    pub expected_paths: Vec<String>,
    #[serde(default)]
    pub description: String,
}

fn empty_json_obj() -> Value {
    json!({})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillOrWorkflowEntry {
    pub id: String,
    pub kind: String, // "skill" | "workflow"
    pub name: String,
    pub summary: String,
    pub version: String,
    pub triggers: Vec<String>,
    pub trust_level: String, // "builtin" | "module" | "user_confirmed" | "untrusted"
    pub source: String,
    pub effects: Vec<String>,
    pub allowed_capabilities: Vec<String>,
    pub steps: Vec<WorkflowStepSpec>,
    pub file_path: String,
    pub sha256: String,
    pub markdown_body: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FrontmatterRaw {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    version: Option<Value>,
    #[serde(default)]
    triggers: Vec<String>,
    #[serde(default)]
    trust: Option<String>,
    #[serde(default)]
    trust_level: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    effects: Vec<String>,
    #[serde(default)]
    allowed_capabilities: Vec<String>,
    #[serde(default)]
    steps: Vec<WorkflowStepSpec>,
}

/// Scan `skills/builtin/` and `${data_dir}/skills/user/` for all `SKILL.md` files (§11.4).
pub fn scan_skills_and_workflows(core: &IntentOsCore) -> anyhow::Result<Vec<SkillOrWorkflowEntry>> {
    let mut roots: Vec<(PathBuf, &str)> = Vec::new();
    let repo_builtin = core.paths.repo_root.join("skills/builtin");
    if repo_builtin.exists() {
        roots.push((repo_builtin, "builtin"));
    }
    let sys_builtin = PathBuf::from("/usr/share/intentos/builtin-skills");
    if sys_builtin.exists() {
        roots.push((sys_builtin, "builtin"));
    }
    let user_skills = core.paths.data_dir.join("skills/user");
    let _ = std::fs::create_dir_all(&user_skills);
    roots.push((user_skills, "user_confirmed"));

    let mut entries = Vec::new();
    for (root, default_trust) in roots {
        for dir_entry in WalkDir::new(&root)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if !dir_entry.file_type().is_file() {
                continue;
            }
            let path = dir_entry.path();
            if path.file_name().and_then(|s| s.to_str()) != Some("SKILL.md") {
                continue;
            }
            if let Ok(parsed) = parse_skill_md_file(path, default_trust)
                && !entries.iter().any(|e: &SkillOrWorkflowEntry| e.id == parsed.id)
            {
                entries.push(parsed);
            }
        }
    }

    Ok(entries)
}

/// Parse a `SKILL.md` file with YAML frontmatter and Markdown body (§11.4).
pub fn parse_skill_md_file(
    path: &Path,
    default_trust: &str,
) -> anyhow::Result<SkillOrWorkflowEntry> {
    let raw_bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&raw_bytes);
    let sha256 = format!("sha256:{}", hex::encode(hasher.finalize()));

    let content = String::from_utf8_lossy(&raw_bytes).to_string();
    let (fm_raw, body) = split_yaml_frontmatter(&content);
    let fm: FrontmatterRaw = if !fm_raw.trim().is_empty() {
        serde_yaml::from_str(&fm_raw).unwrap_or_default()
    } else {
        FrontmatterRaw::default()
    };

    let folder_name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("skill")
        .to_string();

    let id = fm.id.unwrap_or_else(|| folder_name.clone());
    let mut steps = fm.steps;
    if steps.is_empty() {
        steps = parse_steps_from_markdown(&body);
    }

    let kind = fm.kind.unwrap_or_else(|| {
        if id.starts_with("workflow.") || !steps.is_empty() {
            "workflow".to_string()
        } else {
            "skill".to_string()
        }
    });

    let name = fm.name.unwrap_or_else(|| id.clone());
    let summary = fm
        .summary
        .or(fm.description)
        .unwrap_or_else(|| extract_summary_from_markdown(&body, &name));

    let version = match fm.version {
        Some(Value::String(s)) => s,
        Some(Value::Number(n)) => n.to_string(),
        _ => "1.0.0".to_string(),
    };

    let trust_level = fm
        .trust
        .or(fm.trust_level)
        .unwrap_or_else(|| default_trust.to_string());

    let source = fm.source.unwrap_or_else(|| default_trust.to_string());

    Ok(SkillOrWorkflowEntry {
        id,
        kind,
        name,
        summary,
        version,
        triggers: fm.triggers,
        trust_level,
        source,
        effects: fm.effects,
        allowed_capabilities: fm.allowed_capabilities,
        steps,
        file_path: path.to_string_lossy().to_string(),
        sha256,
        markdown_body: body.trim().to_string(),
    })
}

fn split_yaml_frontmatter(content: &str) -> (String, String) {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return (String::new(), content.to_string());
    }
    let after_first = &trimmed[3..];
    if let Some(end_idx) = after_first.find("\n---") {
        let yaml_part = &after_first[..end_idx];
        let rest = &after_first[end_idx + 4..];
        let body = rest.strip_prefix('\n').unwrap_or(rest);
        return (yaml_part.to_string(), body.to_string());
    }
    (String::new(), content.to_string())
}

fn extract_summary_from_markdown(body: &str, fallback: &str) -> String {
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let clean = l.trim_start_matches('-').trim();
        if !clean.is_empty() {
            return clean.chars().take(120).collect();
        }
    }
    fallback.to_string()
}

fn parse_steps_from_markdown(body: &str) -> Vec<WorkflowStepSpec> {
    let mut steps = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        // Match numbered list item like: 1. `cap.id` {"k": "v"}
        let Some(dot_pos) = l.find(". ") else {
            continue;
        };
        let num_part = &l[..dot_pos];
        if !num_part.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let rest = l[dot_pos + 2..].trim();
        if let Some(after_tick) = rest.strip_prefix('`')
            && let Some(end_tick) = after_tick.find('`')
        {
            let cap_id = after_tick[..end_tick].trim().to_string();
            let after_cap = after_tick[end_tick + 1..].trim();
            let args = if let Some(brace_start) = after_cap.find('{')
                && let Some(brace_end) = after_cap.rfind('}')
                && brace_end >= brace_start
            {
                let json_slice = &after_cap[brace_start..=brace_end];
                serde_json::from_str::<Value>(json_slice).unwrap_or_else(|_| json!({}))
            } else {
                json!({})
            };
            steps.push(WorkflowStepSpec {
                step_index: steps.len() + 1,
                capability_id: cap_id,
                arguments: args,
                expected_paths: Vec::new(),
                description: rest.to_string(),
            });
        }
    }
    steps
}

/// Extract steps from a completed `Task` into a parameterized reusable `Workflow` and persist to `${data_dir}/skills/user/<slug>/SKILL.md` (`M-07`).
pub fn learn_workflow_from_task(
    core: &IntentOsCore,
    task_id: &str,
    name: &str,
    trigger_phrase: &str,
) -> anyhow::Result<Value> {
    let task = core
        .state_db
        .get_task(task_id)?
        .ok_or_else(|| anyhow::anyhow!("未找到历史任务: {}", task_id))?;

    if task.steps.is_empty() {
        anyhow::bail!("任务 {} 不包含任何已执行步骤，无法提炼为工作流", task_id);
    }

    let clean_name = if name.trim().is_empty() {
        task.goal.clone()
    } else {
        name.trim().to_string()
    };
    let clean_trigger = if trigger_phrase.trim().is_empty() {
        clean_name.clone()
    } else {
        trigger_phrase.trim().to_string()
    };

    let slug = slugify_workflow_name(&clean_name, task_id);
    let workflow_id = format!("workflow.{}", slug);

    let mut wf_steps = Vec::new();
    let mut allowed_caps = Vec::new();
    for (idx, st) in task.steps.iter().enumerate() {
        let args: Value =
            serde_json::from_str(&st.arguments_summary).unwrap_or_else(|_| json!({}));
        let expected_paths = collect_existing_paths_from_args(&args);
        if !allowed_caps.contains(&st.capability_id) {
            allowed_caps.push(st.capability_id.clone());
        }
        wf_steps.push(WorkflowStepSpec {
            step_index: idx + 1,
            capability_id: st.capability_id.clone(),
            arguments: args,
            expected_paths,
            description: st.message.clone(),
        });
    }

    let frontmatter = FrontmatterRaw {
        id: Some(workflow_id.clone()),
        kind: Some("workflow".to_string()),
        name: Some(clean_name.clone()),
        summary: Some(format!(
            "从任务 `{}` 提炼的可复用工作流（共 {} 步）",
            task.goal,
            wf_steps.len()
        )),
        description: None,
        version: Some(json!("1.0.0")),
        triggers: vec![clean_trigger.clone()],
        trust: Some("user_confirmed".to_string()),
        trust_level: None,
        source: Some(format!("learned_from_task:{}", task_id)),
        effects: vec!["write.reversible".to_string()],
        allowed_capabilities: allowed_caps,
        steps: wf_steps.clone(),
    };

    let yaml_str = serde_yaml::to_string(&frontmatter)?;
    let mut md_lines = Vec::new();
    md_lines.push("---".to_string());
    md_lines.push(yaml_str.trim().to_string());
    md_lines.push("---".to_string());
    md_lines.push(String::new());
    md_lines.push(format!("# {} (`{}`)", clean_name, workflow_id));
    md_lines.push(String::new());
    md_lines.push("## 步骤".to_string());
    for st in &wf_steps {
        md_lines.push(format!(
            "{}. `{}` {}",
            st.step_index,
            st.capability_id,
            serde_json::to_string(&st.arguments).unwrap_or_else(|_| "{}".to_string())
        ));
    }
    md_lines.push(String::new());
    md_lines.push("## 说明".to_string());
    md_lines.push(format!(
        "- 来源任务：`{}`（目标：{}）",
        task_id, task.goal
    ));
    md_lines.push("- 执行时每一步均经 Policy Engine 校验；若引用的资源发生漂移则安全中止。".to_string());

    let skill_dir = core.paths.data_dir.join("skills/user").join(&slug);
    std::fs::create_dir_all(&skill_dir)?;
    let skill_md_path = skill_dir.join("SKILL.md");
    std::fs::write(&skill_md_path, md_lines.join("\n"))?;

    let entry = parse_skill_md_file(&skill_md_path, "user_confirmed")?;

    let _ = core.state_db.record_audit(
        Some(task_id),
        "workflow.learn",
        "user_explicit",
        "write.reversible",
        "allow",
        "saved",
        &json!({
            "workflow_id": workflow_id,
            "task_id": task_id,
            "skill_md_path": skill_md_path.to_string_lossy(),
        }),
        Some(&format!("已从任务 {} 学习并保存工作流 {}", task_id, clean_name)),
    );

    Ok(json!({
        "saved": true,
        "workflow": entry,
        "workflow_id": workflow_id,
        "skill_md_path": skill_md_path.to_string_lossy(),
        "message": format!("✓ 已将任务 `{}` 保存为可复用工作流 `{}` (触发短语: “{}”)", task.goal, clean_name, clean_trigger),
    }))
}

fn collect_existing_paths_from_args(args: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    let Some(obj) = args.as_object() else {
        return paths;
    };
    for key in ["source", "path", "directory", "repo_dir"] {
        if let Some(p_str) = obj.get(key).and_then(|v| v.as_str()) {
            let p = Path::new(p_str);
            if p.is_absolute() && p.exists() {
                paths.push(p_str.to_string());
            }
        }
    }
    paths
}

fn slugify_workflow_name(name: &str, task_id: &str) -> String {
    let mut s = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            s.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() {
            s.push('-');
        }
    }
    let clean = s.trim_matches('-').to_string();
    if clean.len() >= 2 {
        clean
    } else {
        let suffix = task_id.trim_start_matches("task_");
        format!("wf-{}", &suffix[..suffix.len().min(8)])
    }
}

/// Execute a registered `Workflow` step-by-step through `core.broker.dispatch`,
/// enforcing Policy checks and failing safely on resource drift (§11.4, `M-07`).
pub async fn run_workflow(
    core: &IntentOsCore,
    workflow_id_or_trigger: &str,
    param_overrides: Option<&Value>,
) -> anyhow::Result<Value> {
    let all = scan_skills_and_workflows(core)?;
    let q = workflow_id_or_trigger.trim();
    let wf = all
        .into_iter()
        .find(|entry| {
            entry.id == q
                || entry.name == q
                || entry.triggers.iter().any(|t| t == q)
                || format!("workflow.{}", q) == entry.id
        })
        .ok_or_else(|| anyhow::anyhow!("未找到工作流: {}", q))?;

    if wf.steps.is_empty() {
        anyhow::bail!("技能 `{}` 不包含可执行工作流步骤", wf.id);
    }

    let now = Utc::now();
    let task_id = format!("task_wf_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let mut taints = vec![Taint::User];
    if wf.trust_level == "untrusted" {
        taints.push(Taint::RemoteUntrusted);
    }

    let mut task = Task {
        id: task_id.clone(),
        goal: format!("执行工作流：{} ({})", wf.name, wf.id),
        session_id: None,
        project_id: None,
        trigger: TaskTrigger::Workflow,
        route: RouteLayer::L0,
        status: TaskStatus::Running,
        steps: Vec::new(),
        changeset_ids: Vec::new(),
        pending_approval: None,
        candidates_for_disambiguation: Vec::new(),
        assistant_message: None,
        result_summary: None,
        handoff_command: None,
        taint: taints.clone(),
        data_class: DataClass::Personal,
        budget: TaskBudget::default(),
        created_at: now,
        updated_at: now,
    };

    for step_spec in &wf.steps {
        // 1. Check capability availability (drift check)
        if core.broker.get_descriptor(&step_spec.capability_id).is_none() {
            let reason = format!(
                "资源/能力漂移检测拦截：工作流步骤 #{} 引用的能力 `{}` 未注册或已不可用",
                step_spec.step_index, step_spec.capability_id
            );
            task.status = TaskStatus::Failed;
            task.assistant_message = Some(reason.clone());
            task.result_summary = Some(reason.clone());
            task.updated_at = Utc::now();
            core.state_db.upsert_task(&task)?;
            return Ok(json!({
                "workflow_id": wf.id,
                "status": "failed_drift",
                "drift_detected": true,
                "reason": reason,
                "task": task,
            }));
        }

        // 2. Apply optional parameter overrides
        let mut step_args = step_spec.arguments.clone();
        if let Some(Value::Object(ov_map)) = param_overrides
            && let Some(arg_obj) = step_args.as_object_mut()
        {
            for (k, v) in ov_map {
                arg_obj.insert(k.clone(), v.clone());
            }
        }

        // 3. Check resource drift on expected input paths (§11.4: 引用的资源变化时安全失败，不猜测替代)
        if let Some(drift_err) = check_step_resource_drift(core, step_spec, &step_args) {
            task.status = TaskStatus::Failed;
            task.assistant_message = Some(drift_err.clone());
            task.result_summary = Some(drift_err.clone());
            task.updated_at = Utc::now();
            core.state_db.upsert_task(&task)?;
            return Ok(json!({
                "workflow_id": wf.id,
                "status": "failed_drift",
                "drift_detected": true,
                "reason": drift_err,
                "task": task,
            }));
        }

        // 4. Dispatch step through CapabilityBroker (Schema + PolicyEngine + Execution + Verification)
        let call_id = format!(
            "wfstep_{}_{}",
            step_spec.step_index,
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        );
        let call = CapabilityCall {
            request_id: call_id.clone(),
            task_id: task_id.clone(),
            capability_id: step_spec.capability_id.clone(),
            arguments: step_args.clone(),
            origin: InvocationOrigin::UserExplicit,
            taints: taints.clone(),
        };

        match core.broker.dispatch(&call).await? {
            BrokerDispatchOutcome::Executed(res) => {
                if let Some(ref csid) = res.changeset_id {
                    task.changeset_ids.push(csid.clone());
                }
                let ok_step = matches!(
                    res.status,
                    ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
                );
                task.steps.push(TaskStep {
                    step_id: call_id,
                    capability_id: step_spec.capability_id.clone(),
                    arguments_summary: step_args.to_string(),
                    status: res.status,
                    verification: res.verification,
                    changeset_id: res.changeset_id,
                    message: res.message.clone(),
                    data: res.data,
                    duration_ms: res.duration_ms,
                });
                if !ok_step {
                    task.status = TaskStatus::Failed;
                    task.assistant_message = Some(res.message.clone());
                    task.result_summary = Some(res.message);
                    task.updated_at = Utc::now();
                    core.state_db.upsert_task(&task)?;
                    return Ok(json!({
                        "workflow_id": wf.id,
                        "status": "failed",
                        "drift_detected": false,
                        "task": task,
                    }));
                }
            }
            BrokerDispatchOutcome::RequiresApproval(pa) => {
                task.status = TaskStatus::AwaitingApproval;
                task.assistant_message = Some(pa.summary.clone());
                task.pending_approval = Some(pa);
                task.updated_at = Utc::now();
                core.state_db.upsert_task(&task)?;
                return Ok(json!({
                    "workflow_id": wf.id,
                    "status": "awaiting_approval",
                    "drift_detected": false,
                    "task": task,
                }));
            }
            BrokerDispatchOutcome::Denied { reason } => {
                task.status = TaskStatus::Failed;
                task.assistant_message = Some(format!("策略拒绝工作流步骤：{}", reason));
                task.result_summary = Some(reason.clone());
                task.updated_at = Utc::now();
                core.state_db.upsert_task(&task)?;
                return Ok(json!({
                    "workflow_id": wf.id,
                    "status": "denied",
                    "drift_detected": false,
                    "reason": reason,
                    "task": task,
                }));
            }
        }
    }

    let summary_msg = format!(
        "✓ 工作流 `{}` 执行完成（共完成 {} 步）",
        wf.name,
        task.steps.len()
    );
    task.status = TaskStatus::Completed;
    task.assistant_message = Some(summary_msg.clone());
    task.result_summary = Some(summary_msg.clone());
    task.updated_at = Utc::now();
    core.state_db.upsert_task(&task)?;

    Ok(json!({
        "workflow_id": wf.id,
        "status": "completed",
        "drift_detected": false,
        "steps_completed": task.steps.len(),
        "message": summary_msg,
        "task": task,
    }))
}

fn check_step_resource_drift(
    core: &IntentOsCore,
    step_spec: &WorkflowStepSpec,
    step_args: &Value,
) -> Option<String> {
    // Verify expected_paths recorded at learning time still exist
    for exp in &step_spec.expected_paths {
        let p = Path::new(exp);
        if !p.exists() {
            return Some(format!(
                "资源漂移检测拦截：步骤 #{} 依赖的资源路径已不存在 `{}`（不执行猜测替代）",
                step_spec.step_index, exp
            ));
        }
    }

    // Also verify any explicit input path in step_args (`source`, `repo_dir`) exists
    if let Some(obj) = step_args.as_object() {
        for key in ["source", "repo_dir"] {
            if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
                let p = Path::new(s);
                if core.fs_engine.is_forbidden(p) {
                    return Some(format!(
                        "资源漂移检测拦截：步骤 #{} 引用了禁止访问路径 `{}`",
                        step_spec.step_index, s
                    ));
                }
                if !p.exists() {
                    return Some(format!(
                        "资源漂移检测拦截：步骤 #{} 的输入资源 `{}` 不存在或已发生漂移",
                        step_spec.step_index, s
                    ));
                }
            }
        }
    }

    None
}
