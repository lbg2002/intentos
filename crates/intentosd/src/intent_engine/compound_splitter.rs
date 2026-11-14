#![forbid(unsafe_code)]

//! Compound Intent Splitter & Multi-Step Executor (`compound_splitter.rs`, §3.1, §4.7).
//!
//! Splits multi-step compound utterances (e.g., `"把音量调到20然后开启护眼模式"`,
//! `"静音并开启勿扰模式"`, `"找昨天的周报并复制到桌面"`) into ordered `PlannedStep` items
//! with effect, risk badge (`R0`–`R3`), and undo metadata, and executes them sequentially
//! through `core.broker.dispatch` with cross-step output propagation.

use crate::broker::BrokerDispatchOutcome;
use crate::core::IntentOsCore;
use crate::intent_engine::fuzzy_scorer::rank_capabilities;
use crate::intent_engine::pattern_compiler::PatternCompiler;
use crate::intent_engine::slot_extractor::{
    extract_slots_for_descriptor, extract_universal_slots,
};
use crate::router::RoutedIntent;
use intentos_protocol::{
    CapabilityCall, Effect, ExecutionStatus, InvocationOrigin, Taint, UndoStrategy,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// A single planned step inside a `CompoundPlan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedStep {
    pub step_index: usize,
    pub raw_segment: String,
    pub capability_id: String,
    pub summary: String,
    pub arguments: Value,
    pub effect: Effect,
    pub risk_badge: String,
    pub reversible: bool,
    pub undo_strategy: UndoStrategy,
    pub depends_on_previous_output: bool,
    pub confidence: f64,
}

/// Multi-step plan produced by `split_compound_intent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundPlan {
    pub is_compound: bool,
    pub original_text: String,
    pub steps: Vec<PlannedStep>,
    pub requires_confirmation: bool,
    pub max_effect: Effect,
    pub overall_risk_badge: String,
}

/// Execution outcome of a single step during `execute_compound`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecutionOutcome {
    pub step_index: usize,
    pub capability_id: String,
    pub status: String,
    pub ok: bool,
    pub message: String,
    pub data: Value,
    pub changeset_id: Option<String>,
    pub approval_nonce: Option<String>,
}

/// Overall execution report returned by `execute_compound`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundExecutionReport {
    pub task_id: String,
    pub is_compound: bool,
    pub all_succeeded: bool,
    pub completed_steps: usize,
    pub total_steps: usize,
    pub step_results: Vec<StepExecutionOutcome>,
    pub changeset_ids: Vec<String>,
    pub summary_message: String,
}

/// Split raw text into atomic clause segments if it contains compound connectors.
pub fn split_into_clauses(raw_text: &str) -> Vec<String> {
    let trimmed = raw_text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Do not split `$ ` passthrough commands
    if trimmed.starts_with('$') {
        return vec![trimmed.to_string()];
    }

    // Replace explicit multi-step connectors with a delimiter `\n|||\n` (no look-around needed)
    let connector_re = Regex::new(
        r"(?:；|;|，然后|,\s*然后|然后|接着|随后|之后|并且|同时|顺便|再把|再去)",
    )
    .expect("valid compound connector regex");
    let verb_connector_re = Regex::new(
        r"(?:并|再)(开启|打开|启动|关闭|关掉|禁用|设置|设为|调|切|静音|复制|移动|重命名|删除|锁屏|截图|进入|启用|取消|查看|查)",
    )
    .expect("valid verb connector regex");

    let step1 = connector_re.replace_all(trimmed, "\n|||\n");
    let replaced = verb_connector_re.replace_all(&step1, "\n|||\n$1");
    let parts: Vec<String> = replaced
        .split("\n|||\n")
        .map(|s| s.trim().trim_matches(['，', ',', '。', ' ']).to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if parts.is_empty() {
        vec![trimmed.to_string()]
    } else {
        parts
    }
}

/// Analyze and split a potentially compound utterance into an ordered `CompoundPlan`.
pub fn split_compound_intent(
    core: &IntentOsCore,
    raw_text: &str,
    compiler: &PatternCompiler,
) -> CompoundPlan {
    let clauses = split_into_clauses(raw_text);
    let mut steps = Vec::new();

    for (idx, clause) in clauses.iter().enumerate() {
        let step_num = idx + 1;
        if let Some(step) = resolve_clause_to_step(core, clause, step_num, steps.last(), compiler) {
            steps.push(step);
        }
    }

    let is_compound = steps.len() > 1;
    let max_effect = steps
        .iter()
        .map(|s| s.effect)
        .max()
        .unwrap_or(Effect::Observe);
    let requires_confirmation = steps
        .iter()
        .any(|s| s.effect >= Effect::ProcessControl || !s.reversible && s.effect >= Effect::WriteReversible);

    CompoundPlan {
        is_compound,
        original_text: raw_text.trim().to_string(),
        steps,
        requires_confirmation,
        max_effect,
        overall_risk_badge: max_effect.risk_badge().to_string(),
    }
}

fn resolve_clause_to_step(
    core: &IntentOsCore,
    clause: &str,
    step_index: usize,
    prev_step: Option<&PlannedStep>,
    compiler: &PatternCompiler,
) -> Option<PlannedStep> {
    let trimmed = clause.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. Check cross-step dependent file operations (e.g., `复制到桌面`, `移动到下载`, `打开它`, `重命名为...`)
    if let Some(prev) = prev_step {
        let uni = extract_universal_slots(trimmed, &core.resources);
        if (trimmed.starts_with("复制到") || trimmed.starts_with("拷贝到") || trimmed.contains("把它复制到"))
            && let Some(dest) = uni.locations.first()
            && let Some(desc) = core.broker.get_descriptor("fs.copy")
        {
            let prev_ref = infer_previous_target_reference(prev);
            let args = json!({
                "sources": [prev_ref],
                "dest_dir": dest.resolved_path,
            });
            return Some(build_planned_step(
                step_index,
                trimmed,
                desc,
                args,
                true,
                0.92,
            ));
        }

        if (trimmed.starts_with("移动到") || trimmed.starts_with("移到") || trimmed.contains("把它移动到"))
            && let Some(dest) = uni.locations.first()
            && let Some(desc) = core.broker.get_descriptor("fs.move")
        {
            let prev_ref = infer_previous_target_reference(prev);
            let args = json!({
                "sources": [prev_ref],
                "dest_dir": dest.resolved_path,
            });
            return Some(build_planned_step(
                step_index,
                trimmed,
                desc,
                args,
                true,
                0.92,
            ));
        }

        if (trimmed == "打开" || trimmed == "打开它" || trimmed == "打开这个文件")
            && let Some(desc) = core.broker.get_descriptor("xdg.open")
        {
            let prev_ref = infer_previous_target_reference(prev);
            let args = json!({ "target": prev_ref });
            return Some(build_planned_step(
                step_index,
                trimmed,
                desc,
                args,
                true,
                0.90,
            ));
        }
    }

    // 2. Check `PatternCompiler` + `FuzzyScorer` for high-confidence non-generic capability matches
    let ranked = rank_capabilities(trimmed, compiler, Some(&core.index_db), 3);

    // 3. Try deterministic L0 router (`core.router.route_text`), unless it fell back to generic `app.launch`/`web.search`
    // when `PatternCompiler` matched a specific setting/system capability with high confidence.
    if let RoutedIntent::ExecuteL0 {
        capability_id,
        arguments,
        summary,
    } = core.router.route_text(trimmed, false)
    {
        let is_generic_fallback = matches!(capability_id.as_str(), "app.launch" | "web.search");
        let compiler_has_better = is_generic_fallback
            && ranked.first().is_some_and(|top| {
                top.confidence >= 0.85
                    && !matches!(top.capability_id.as_str(), "app.launch" | "web.search")
            });

        if !compiler_has_better
            && let Some(desc) = core.broker.get_descriptor(&capability_id)
        {
            let mut step = build_planned_step(step_index, trimmed, desc, arguments, false, 0.96);
            if !summary.is_empty() {
                step.summary = summary;
            }
            return Some(step);
        }
    }

    // 4. Use `PatternCompiler` + `FuzzyScorer` + `SlotExtractor`
    if let Some(top) = ranked.first()
        && let Some(desc) = core.broker.get_descriptor(&top.capability_id)
    {
        let args = extract_slots_for_descriptor(
            desc,
            trimmed,
            &top.captured_slots,
            &core.resources,
        );
        return Some(build_planned_step(
            step_index,
            trimmed,
            desc,
            args,
            false,
            top.confidence,
        ));
    }

    None
}

fn infer_previous_target_reference(prev: &PlannedStep) -> String {
    if let Some(dest) = prev.arguments.get("dest_dir").and_then(|v| v.as_str()) {
        return dest.to_string();
    }
    if let Some(target) = prev.arguments.get("target").and_then(|v| v.as_str()) {
        return target.to_string();
    }
    if let Some(path) = prev.arguments.get("path").and_then(|v| v.as_str()) {
        return path.to_string();
    }
    "$prev_step.first_path".to_string()
}

fn build_planned_step(
    step_index: usize,
    raw_segment: &str,
    desc: &intentos_protocol::CapabilityDescriptor,
    arguments: Value,
    depends_on_previous_output: bool,
    confidence: f64,
) -> PlannedStep {
    let effect = desc.max_effect();
    let reversible = desc.undo != UndoStrategy::None || effect.is_reversible_by_default();
    PlannedStep {
        step_index,
        raw_segment: raw_segment.to_string(),
        capability_id: desc.id.clone(),
        summary: desc.summary.clone(),
        arguments,
        effect,
        risk_badge: effect.risk_badge().to_string(),
        reversible,
        undo_strategy: desc.undo.clone(),
        depends_on_previous_output,
        confidence,
    }
}

/// Execute a compound plan sequentially through `core.broker.dispatch`, propagating
/// intermediate outputs (such as file paths discovered by `fs.search`) to dependent steps.
pub async fn execute_compound(
    core: &IntentOsCore,
    raw_text: &str,
    steps_override: Option<Vec<PlannedStep>>,
    session_id: Option<&str>,
    incognito: bool,
    compiler: &PatternCompiler,
) -> anyhow::Result<CompoundExecutionReport> {
    let steps = match steps_override {
        Some(s) if !s.is_empty() => s,
        _ => split_compound_intent(core, raw_text, compiler).steps,
    };

    let task_id = format!("task-compound-{}", Uuid::new_v4());
    let total_steps = steps.len();
    let is_compound = total_steps > 1;
    let mut step_results = Vec::with_capacity(total_steps);
    let mut changeset_ids = Vec::new();
    let mut last_discovered_paths: Vec<String> = Vec::new();
    let mut all_succeeded = !steps.is_empty();

    for step in &steps {
        let mut resolved_args = step.arguments.clone();
        if step.depends_on_previous_output && !last_discovered_paths.is_empty() {
            substitute_previous_paths(&mut resolved_args, &last_discovered_paths);
        }

        let call = CapabilityCall {
            request_id: format!("req-{}-step-{}", task_id, step.step_index),
            task_id: task_id.clone(),
            capability_id: step.capability_id.clone(),
            arguments: resolved_args,
            origin: InvocationOrigin::UserExplicit,
            taints: vec![Taint::User],
        };

        match core.broker.dispatch(&call).await? {
            BrokerDispatchOutcome::Executed(res) => {
                let ok = res.status == ExecutionStatus::Exited;
                if !ok {
                    all_succeeded = false;
                }
                if let Some(cs_id) = &res.changeset_id {
                    changeset_ids.push(cs_id.clone());
                }
                // Extract any file paths produced by this step for downstream steps
                let paths = extract_paths_from_result_data(&res.data);
                if !paths.is_empty() {
                    last_discovered_paths = paths;
                }

                step_results.push(StepExecutionOutcome {
                    step_index: step.step_index,
                    capability_id: step.capability_id.clone(),
                    status: format!("{:?}", res.status).to_ascii_lowercase(),
                    ok,
                    message: res.message,
                    data: res.data,
                    changeset_id: res.changeset_id,
                    approval_nonce: None,
                });

                if !ok {
                    break;
                }
            }
            BrokerDispatchOutcome::RequiresApproval(pending) => {
                all_succeeded = false;
                step_results.push(StepExecutionOutcome {
                    step_index: step.step_index,
                    capability_id: step.capability_id.clone(),
                    status: "requires_approval".to_string(),
                    ok: false,
                    message: format!("步骤 {} 需要用户授权确认: {}", step.step_index, pending.summary),
                    data: serde_json::to_value(&pending).unwrap_or_else(|_| json!({})),
                    changeset_id: None,
                    approval_nonce: Some(pending.nonce),
                });
                break;
            }
            BrokerDispatchOutcome::Denied { reason } => {
                all_succeeded = false;
                step_results.push(StepExecutionOutcome {
                    step_index: step.step_index,
                    capability_id: step.capability_id.clone(),
                    status: "denied".to_string(),
                    ok: false,
                    message: reason,
                    data: json!({}),
                    changeset_id: None,
                    approval_nonce: None,
                });
                break;
            }
        }
    }

    let completed_steps = step_results.iter().filter(|r| r.ok).count();
    let summary_message = if step_results.is_empty() {
        "未能解析出可执行的步骤".to_string()
    } else {
        step_results
            .iter()
            .map(|r| format!("[步骤{}] {}", r.step_index, r.message))
            .collect::<Vec<_>>()
            .join("；")
    };

    if !incognito {
        let sess = core.sessions.get_or_create(session_id);
        let last_res = last_discovered_paths.first().cloned();
        core.sessions.append_turn(
            &sess.session_id,
            raw_text,
            &summary_message,
            last_res,
        );
    }

    Ok(CompoundExecutionReport {
        task_id,
        is_compound,
        all_succeeded,
        completed_steps,
        total_steps,
        step_results,
        changeset_ids,
        summary_message,
    })
}

fn substitute_previous_paths(args: &mut Value, paths: &[String]) {
    let Some(first) = paths.first() else {
        return;
    };
    let Some(obj) = args.as_object_mut() else {
        return;
    };

    if let Some(sources) = obj.get_mut("sources")
        && let Some(arr) = sources.as_array_mut()
        && arr.iter().any(|v| {
            v.as_str()
                .is_some_and(|s| s.starts_with("$prev_step") || s.is_empty())
        })
    {
        *sources = json!([first]);
    }
    if let Some(target) = obj.get_mut("target")
        && target
            .as_str()
            .is_some_and(|s| s.starts_with("$prev_step") || s.is_empty())
    {
        *target = json!(first);
    }
    if let Some(path) = obj.get_mut("path")
        && path
            .as_str()
            .is_some_and(|s| s.starts_with("$prev_step") || s.is_empty())
    {
        *path = json!(first);
    }
}

fn extract_paths_from_result_data(data: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["items", "files", "results"] {
        if let Some(arr) = data.get(key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(p) = item.get("path").and_then(|v| v.as_str()) {
                    out.push(p.to_string());
                } else if let Some(p) = item.as_str() {
                    out.push(p.to_string());
                }
            }
        }
    }
    if let Some(p) = data.get("path").and_then(|v| v.as_str()) {
        out.push(p.to_string());
    }
    if let Some(p) = data.get("dest_path").and_then(|v| v.as_str()) {
        out.push(p.to_string());
    }
    out
}
