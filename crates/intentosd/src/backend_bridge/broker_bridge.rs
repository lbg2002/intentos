#![forbid(unsafe_code)]

//! Unified `CapabilityBroker` Bridge, Tool Spec Builder & Effect Ledger Recorder (`broker_bridge.rs`).
//!
//! Connects all external/local LLM transports (OpenAI HTTP, Anthropic HTTP, and Controlled CLI)
//! to IntentOS's single-entry `CapabilityBroker` security & undo pipeline, recording every
//! invocation into `TurnEffectLedger`.

use crate::backend_bridge::detector::ActiveBackendSelection;
use crate::backend_bridge::turn_checkpoint::{StepExecutionRecord, TurnEffectLedger};
use crate::broker::BrokerDispatchOutcome;
use crate::core::IntentOsCore;
use crate::runtime::{SessionState, build_context_blocks};
use chrono::Utc;
use intentos_capability_sdk::descriptor_to_tool_spec;
use intentos_protocol::{
    CapabilityCall, ContextBlock, DataClass, Effect, ExecutionStatus, InvocationOrigin,
    PendingApproval, RouteLayer, Taint, Task, TaskBudget, TaskStatus, TaskStep, TaskTrigger,
    ToolSpec,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// Explicit runtime execution mode reported on every Quick-Chat turn response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendExecutionMode {
    #[serde(rename = "managed_broker")]
    ManagedBrokerTools,
    #[serde(rename = "cli_broker_bridged")]
    CliBrokerBridged,
    #[serde(rename = "external_chat_only")]
    ExternalChatOnly,
    #[serde(rename = "offline_core")]
    OfflineCore,
}

impl BackendExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManagedBrokerTools => "managed_broker",
            Self::CliBrokerBridged => "cli_broker_bridged",
            Self::ExternalChatOnly => "external_chat_only",
            Self::OfflineCore => "offline_core",
        }
    }
}

/// Colored horizontal trace dot item (`20px` dot bar in Quick-Chat bubbles).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDot {
    pub kind: String,
    pub color: String,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    pub changeset_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_approval: Option<PendingApproval>,
}

impl TraceDot {
    pub fn thinking(detail: impl Into<String>) -> Self {
        Self {
            kind: "thinking".to_string(),
            color: "gray".to_string(),
            title: "深度思考".to_string(),
            detail: detail.into(),
            duration_ms: None,
            changeset_id: None,
            capability_id: None,
            approval_id: None,
            pending_approval: None,
        }
    }

    pub fn memory(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: "memory".to_string(),
            color: "purple".to_string(),
            title: title.into(),
            detail: detail.into(),
            duration_ms: None,
            changeset_id: None,
            capability_id: None,
            approval_id: None,
            pending_approval: None,
        }
    }

    pub fn adapter(
        title: impl Into<String>,
        detail: impl Into<String>,
        duration_ms: Option<u64>,
        changeset_id: Option<String>,
    ) -> Self {
        Self {
            kind: "adapter".to_string(),
            color: "cyan".to_string(),
            title: title.into(),
            detail: detail.into(),
            duration_ms,
            changeset_id,
            capability_id: None,
            approval_id: None,
            pending_approval: None,
        }
    }

    pub fn approval(pa: &PendingApproval) -> Self {
        Self {
            kind: "approval".to_string(),
            color: "amber".to_string(),
            title: format!("待确认: {}", pa.capability_id),
            detail: if pa.diff_preview.trim().is_empty() {
                pa.summary.clone()
            } else {
                format!("{}\n{}", pa.summary, pa.diff_preview)
            },
            duration_ms: None,
            changeset_id: None,
            capability_id: Some(pa.capability_id.clone()),
            approval_id: Some(pa.approval_id.clone()),
            pending_approval: Some(pa.clone()),
        }
    }

    pub fn approved_ok(
        capability_id: &str,
        detail: impl Into<String>,
        duration_ms: u64,
        changeset_id: Option<String>,
    ) -> Self {
        Self {
            kind: "tool_ok".to_string(),
            color: "green".to_string(),
            title: format!("✓ 已批准执行: {}", capability_id),
            detail: detail.into(),
            duration_ms: Some(duration_ms),
            changeset_id,
            capability_id: Some(capability_id.to_string()),
            approval_id: None,
            pending_approval: None,
        }
    }

    pub fn denied(capability_id: &str, detail: impl Into<String>) -> Self {
        Self {
            kind: "tool_err".to_string(),
            color: "red".to_string(),
            title: format!("✕ 用户已拒绝: {}", capability_id),
            detail: detail.into(),
            duration_ms: Some(0),
            changeset_id: None,
            capability_id: Some(capability_id.to_string()),
            approval_id: None,
            pending_approval: None,
        }
    }

    pub fn tool_ok(
        capability_id: &str,
        detail: impl Into<String>,
        duration_ms: u64,
        changeset_id: Option<String>,
    ) -> Self {
        Self {
            kind: "tool_ok".to_string(),
            color: "green".to_string(),
            title: capability_id.to_string(),
            detail: detail.into(),
            duration_ms: Some(duration_ms),
            changeset_id,
            capability_id: Some(capability_id.to_string()),
            approval_id: None,
            pending_approval: None,
        }
    }

    pub fn tool_unverified(
        capability_id: &str,
        detail: impl Into<String>,
        duration_ms: u64,
        changeset_id: Option<String>,
    ) -> Self {
        Self {
            kind: "tool_unverified".to_string(),
            color: "blue".to_string(),
            title: format!("{} · 已发送请求（待桌面响应）", capability_id),
            detail: detail.into(),
            duration_ms: Some(duration_ms),
            changeset_id,
            capability_id: Some(capability_id.to_string()),
            approval_id: None,
            pending_approval: None,
        }
    }

    pub fn tool_err(capability_id: &str, detail: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            kind: "tool_err".to_string(),
            color: "red".to_string(),
            title: format!("失败: {}", capability_id),
            detail: detail.into(),
            duration_ms: Some(duration_ms),
            changeset_id: None,
            capability_id: Some(capability_id.to_string()),
            approval_id: None,
            pending_approval: None,
        }
    }
}

/// Internal normalized turn outcome returned by HTTP, CLI, or offline engines.
pub struct TurnExecutionOutcome {
    pub task_id: String,
    pub backend_used: String,
    pub provider_used: String,
    pub model_used: String,
    pub execution_mode: BackendExecutionMode,
    pub side_effect_replay_prevented: bool,
    pub thinking: Option<String>,
    pub reply_markdown: String,
    pub trace_dots: Vec<TraceDot>,
    pub adapter_actions: Vec<Value>,
    pub tool_steps_json: Vec<Value>,
    pub changeset_ids: Vec<String>,
    pub handoff_command: Option<String>,
    pub pending_approval: Option<PendingApproval>,
}

/// Outcome of executing a single tool invocation via `CapabilityBroker`.
pub enum QuickChatToolExecOutcome {
    ToolMessage {
        content: String,
        is_error: bool,
        duplicate_blocked: bool,
    },
    PausedForApproval {
        outcome: Box<TurnExecutionOutcome>,
        canonical_tool: String,
    },
}

pub fn canonicalize_json_for_dedup(val: &Value) -> String {
    match val {
        Value::Object(map) => {
            let sorted: BTreeMap<&str, String> = map
                .iter()
                .map(|(k, v)| (k.as_str(), canonicalize_json_for_dedup(v)))
                .collect();
            let parts: Vec<String> = sorted
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| format!("\"{}\"", k)),
                        v
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonicalize_json_for_dedup).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".to_string()),
    }
}

pub fn resolve_tool_name_to_capability(tool_name: &str, core: &IntentOsCore) -> String {
    let trimmed = tool_name.trim();
    if crate::memory_hub::is_memory_tool(trimmed) || crate::app_adapter::is_adapter_tool(trimmed) {
        return trimmed.replace('.', "_");
    }
    if core.broker.get_descriptor(trimmed).is_some() {
        return trimmed.to_string();
    }
    for d in core.broker.descriptors() {
        if d.id.replace('.', "_") == trimmed {
            return d.id.clone();
        }
    }
    trimmed.replace('_', ".")
}

pub fn resolve_capability_effect(core: &IntentOsCore, canonical_tool: &str) -> Effect {
    if crate::memory_hub::is_memory_tool(canonical_tool) {
        return Effect::Observe;
    }
    if crate::app_adapter::is_adapter_tool(canonical_tool) {
        return if canonical_tool == "app_adapter_invoke" {
            Effect::Ui
        } else {
            Effect::Observe
        };
    }
    core.broker
        .get_descriptor(canonical_tool)
        .map(|d| d.max_effect())
        .unwrap_or(Effect::Observe)
}

/// Build the OpenAI `tools` spec array combining top ranked `broker` capabilities + `memory_hub` + `app_adapter`.
pub fn build_quick_chat_openai_tools(core: &IntentOsCore, user_text: &str) -> Vec<Value> {
    let descriptors = core.broker.descriptors();
    let all_cap_specs: Vec<ToolSpec> = descriptors
        .iter()
        .cloned()
        .map(descriptor_to_tool_spec)
        .collect();

    let selected_caps: Vec<&ToolSpec> = if all_cap_specs.len() <= 20 {
        all_cap_specs.iter().collect()
    } else {
        let compiler =
            crate::intent_engine::PatternCompiler::compile_from_descriptors(&descriptors);
        let ranked = crate::intent_engine::rank_capabilities(user_text, &compiler, None, 12);
        let mut chosen_names: Vec<String> = ranked
            .into_iter()
            .map(|r| r.capability_id.replace('.', "_"))
            .collect();
        for ess in [
            "file_open",
            "file_write",
            "app_launch",
            "app_quit",
            "window_focus",
            "window_list",
            "media_control",
            "display_brightness_set",
            "display_night_light_set",
            "sound_volume_set",
            "sound_mute_set",
            "appearance_color_scheme_set",
            "scene_apply",
            "file_search",
            "file_recent",
            "file_move",
            "file_copy",
            "file_trash",
            "disk_usage",
            "network_status",
        ] {
            if chosen_names.len() >= 25 {
                break;
            }
            if !chosen_names.iter().any(|n| n == ess) {
                chosen_names.push(ess.to_string());
            }
        }
        all_cap_specs
            .iter()
            .filter(|t| chosen_names.iter().any(|n| n == &t.name))
            .collect()
    };

    let mut tools: Vec<Value> = selected_caps
        .into_iter()
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

    for spec in crate::memory_hub::memory_tool_specs()
        .into_iter()
        .chain(crate::app_adapter::adapter_tool_specs())
    {
        tools.push(json!({
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description,
                "parameters": spec.parameters,
            }
        }));
    }

    tools
}

pub fn build_quick_chat_anthropic_tools(openai_tools: &[Value]) -> Vec<Value> {
    openai_tools
        .iter()
        .filter_map(|t| {
            let f = t.get("function")?;
            let name = f.get("name")?.as_str()?;
            let desc = f.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let schema = f
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
            Some(json!({
                "name": name,
                "description": desc,
                "input_schema": schema,
            }))
        })
        .collect()
}

/// Execute a single Quick-Chat tool call through `CapabilityBroker`, enforcing per-turn
/// idempotency deduplication and recording the execution into `effect_ledger`.
#[allow(clippy::too_many_arguments)]
pub async fn execute_quick_chat_tool_call(
    core: &IntentOsCore,
    active: &ActiveBackendSelection,
    execution_mode: BackendExecutionMode,
    task_id: &str,
    session: &SessionState,
    user_text: &str,
    incognito: bool,
    taints: &[Taint],
    data_class: DataClass,
    call_id: &str,
    fn_name: &str,
    parsed_args: &Value,
    effect_ledger: &mut TurnEffectLedger,
) -> anyhow::Result<QuickChatToolExecOutcome> {
    let canonical_tool = resolve_tool_name_to_capability(fn_name, core);
    let is_mem = crate::memory_hub::is_memory_tool(&canonical_tool);
    let is_adap = crate::app_adapter::is_adapter_tool(&canonical_tool);
    let canonical_args = canonicalize_json_for_dedup(parsed_args);
    let idempotency_key = effect_ledger.compute_idempotency_key(&canonical_tool, &canonical_args);

    // Idempotent Duplicate Tool-Call Guard via `TurnEffectLedger`
    if let Some(prev) = effect_ledger.lookup_idempotent(&idempotency_key) {
        let feedback = serde_json::to_string(&json!({
            "duplicate_call_blocked": true,
            "idempotent_dedup": true,
            "idempotency_key": prev.idempotency_key,
            "step_id": prev.step_id,
            "tool": canonical_tool,
            "changeset_id": prev.changeset_id,
            "cached_output": prev.cached_output,
            "instruction": "检测到当前回合内重复调用完全相同的工具与参数，系统已通过 TurnEffectLedger 幂等账本拦截重复执行并返回缓存输出。请不要再次调用该工具，请立即基于已有结果向用户总结并完成回复。"
        }))?;
        return Ok(QuickChatToolExecOutcome::ToolMessage {
            content: feedback,
            is_error: false,
            duplicate_blocked: true,
        });
    }

    let mut effective_args = parsed_args.clone();
    if is_mem
        && !incognito
        && let Some(obj) = effective_args.as_object_mut()
    {
        obj.entry("session_id".to_string())
            .or_insert_with(|| json!(session.session_id));
    }

    let effect = resolve_capability_effect(core, &canonical_tool);
    let is_untainted_reversible_setting = !is_mem
        && !is_adap
        && !taints.iter().any(|t| t.is_untrusted())
        && effect == Effect::Setting;
    let call_origin = if is_untainted_reversible_setting {
        InvocationOrigin::L1Inferred
    } else {
        InvocationOrigin::L2AgentPlan
    };

    let call = CapabilityCall {
        request_id: call_id.to_string(),
        task_id: task_id.to_string(),
        capability_id: canonical_tool.clone(),
        arguments: effective_args,
        origin: call_origin,
        taints: taints.to_vec(),
    };

    match core.broker.dispatch(&call).await? {
        BrokerDispatchOutcome::Executed(mut res) => {
            let step_id = effect_ledger.next_step_id();
            if canonical_tool == "file.search" {
                supplement_approved_dir_file_search(
                    core,
                    &call.arguments,
                    &mut res.message,
                    &mut res.data,
                );
            }
            if let Some(p) = parsed_args
                .get("path")
                .or_else(|| parsed_args.get("target"))
                .or_else(|| parsed_args.get("source"))
                .or_else(|| parsed_args.get("directory"))
                .and_then(|v| v.as_str())
            {
                effect_ledger.last_resource_path = Some(p.to_string());
            }

            let is_ok = matches!(
                res.status,
                ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
            );
            let mutated_state = effect > Effect::Observe && is_ok;
            let verification_status = format!("{:?}", res.verification.state);

            if is_mem {
                let summary = serde_json::to_string_pretty(&res.data)
                    .unwrap_or_else(|_| res.data.to_string());
                effect_ledger.trace_dots.push(TraceDot::memory(
                    format!("记忆查询: {}", canonical_tool),
                    summary,
                ));
                effect_ledger.tool_steps_json.push(json!({
                    "step_id": step_id,
                    "idempotency_key": idempotency_key,
                    "capability_id": canonical_tool,
                    "tool": canonical_tool,
                    "arguments": parsed_args,
                    "duration_ms": res.duration_ms,
                    "data": res.data,
                }));
                effect_ledger.task_steps.push(TaskStep {
                    step_id: step_id.clone(),
                    capability_id: canonical_tool.clone(),
                    arguments_summary: parsed_args.to_string(),
                    status: res.status,
                    verification: res.verification,
                    changeset_id: res.changeset_id.clone(),
                    message: res.message,
                    data: res.data.clone(),
                    duration_ms: res.duration_ms,
                });
                effect_ledger.record_step(StepExecutionRecord {
                    step_id,
                    idempotency_key,
                    capability_id: canonical_tool,
                    canonical_args_json: canonical_args,
                    effect,
                    mutated_state,
                    succeeded: is_ok,
                    changeset_id: res.changeset_id,
                    verification_status,
                    cached_output: res.data.clone(),
                });
                return Ok(QuickChatToolExecOutcome::ToolMessage {
                    content: serde_json::to_string(&res.data)?,
                    is_error: !is_ok,
                    duplicate_blocked: false,
                });
            }

            if is_adap {
                let channel = res
                    .data
                    .get("channel_used")
                    .and_then(|v| v.as_str())
                    .unwrap_or("adapter");
                let summary = res
                    .data
                    .get("summary")
                    .or_else(|| res.data.get("message"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| res.message.clone());
                if is_ok {
                    effect_ledger.trace_dots.push(TraceDot::adapter(
                        format!("转译层: {}", channel),
                        summary,
                        Some(res.duration_ms),
                        res.changeset_id.clone(),
                    ));
                } else {
                    effect_ledger.trace_dots.push(TraceDot::tool_err(
                        &canonical_tool,
                        summary,
                        res.duration_ms,
                    ));
                }
                effect_ledger.adapter_actions.push(res.data.clone());
                effect_ledger.tool_steps_json.push(json!({
                    "step_id": step_id,
                    "idempotency_key": idempotency_key,
                    "capability_id": canonical_tool,
                    "tool": canonical_tool,
                    "arguments": parsed_args,
                    "duration_ms": res.duration_ms,
                    "data": res.data,
                    "result": res.data,
                }));
                effect_ledger.task_steps.push(TaskStep {
                    step_id: step_id.clone(),
                    capability_id: canonical_tool.clone(),
                    arguments_summary: parsed_args.to_string(),
                    status: res.status,
                    verification: res.verification,
                    changeset_id: res.changeset_id.clone(),
                    message: res.message,
                    data: res.data.clone(),
                    duration_ms: res.duration_ms,
                });
                effect_ledger.record_step(StepExecutionRecord {
                    step_id,
                    idempotency_key,
                    capability_id: canonical_tool,
                    canonical_args_json: canonical_args,
                    effect,
                    mutated_state,
                    succeeded: is_ok,
                    changeset_id: res.changeset_id,
                    verification_status,
                    cached_output: res.data.clone(),
                });
                return Ok(QuickChatToolExecOutcome::ToolMessage {
                    content: serde_json::to_string(&res.data)?,
                    is_error: !is_ok,
                    duplicate_blocked: false,
                });
            }

            let is_unverified = res.status == ExecutionStatus::RequestedUnverified
                || res.verification.state == intentos_protocol::VerificationState::RequestedUnverified
                || res.data.get("simulated").and_then(|v| v.as_bool()) == Some(true);

            if is_ok && is_unverified {
                effect_ledger.trace_dots.push(TraceDot::tool_unverified(
                    &canonical_tool,
                    format!(
                        "{} ({}ms, 状态: 已发送请求，待桌面响应)",
                        res.message, res.duration_ms
                    ),
                    res.duration_ms,
                    res.changeset_id.clone(),
                ));
            } else if is_ok {
                effect_ledger.trace_dots.push(TraceDot::tool_ok(
                    &canonical_tool,
                    format!(
                        "{} ({}ms, 校验: {:?})",
                        res.message, res.duration_ms, res.verification.state
                    ),
                    res.duration_ms,
                    res.changeset_id.clone(),
                ));
            } else {
                effect_ledger.trace_dots.push(TraceDot::tool_err(
                    &canonical_tool,
                    res.message.clone(),
                    res.duration_ms,
                ));
            }

            let out_val = json!({
                "message": res.message,
                "data": res.data,
            });

            effect_ledger.tool_steps_json.push(json!({
                "step_id": step_id,
                "idempotency_key": idempotency_key,
                "capability_id": canonical_tool,
                "arguments": parsed_args,
                "status": res.status,
                "duration_ms": res.duration_ms,
                "changeset_id": res.changeset_id,
                "message": res.message,
                "data": res.data,
            }));
            effect_ledger.task_steps.push(TaskStep {
                step_id: step_id.clone(),
                capability_id: canonical_tool.clone(),
                arguments_summary: parsed_args.to_string(),
                status: res.status,
                verification: res.verification,
                changeset_id: res.changeset_id.clone(),
                message: res.message.clone(),
                data: res.data.clone(),
                duration_ms: res.duration_ms,
            });
            effect_ledger.record_step(StepExecutionRecord {
                step_id,
                idempotency_key,
                capability_id: canonical_tool,
                canonical_args_json: canonical_args,
                effect,
                mutated_state,
                succeeded: is_ok,
                changeset_id: res.changeset_id,
                verification_status,
                cached_output: out_val.clone(),
            });

            Ok(QuickChatToolExecOutcome::ToolMessage {
                content: serde_json::to_string(&out_val)?,
                is_error: !is_ok,
                duplicate_blocked: false,
            })
        }

        BrokerDispatchOutcome::RequiresApproval(pa) => {
            let now = Utc::now();
            let awaiting_task = Task {
                id: task_id.to_string(),
                goal: user_text.to_string(),
                session_id: Some(session.session_id.clone()),
                project_id: None,
                trigger: TaskTrigger::User,
                route: RouteLayer::L2,
                status: TaskStatus::AwaitingApproval,
                steps: effect_ledger.task_steps.clone(),
                changeset_ids: effect_ledger.committed_changeset_ids(),
                pending_approval: Some(pa.clone()),
                candidates_for_disambiguation: Vec::new(),
                assistant_message: Some(pa.summary.clone()),
                result_summary: Some(pa.summary.clone()),
                handoff_command: None,
                taint: taints.to_vec(),
                data_class,
                budget: TaskBudget::default(),
                created_at: now,
                updated_at: now,
            };
            let _ = core.persist_or_ephemeral(&awaiting_task, incognito);

            let combined_thinking = if effect_ledger.accumulated_thoughts.is_empty() {
                None
            } else {
                Some(effect_ledger.accumulated_thoughts.join("\n\n"))
            };
            let mut outcome_dots = effect_ledger.trace_dots.clone();
            outcome_dots.push(TraceDot::approval(&pa));

            Ok(QuickChatToolExecOutcome::PausedForApproval {
                outcome: Box::new(TurnExecutionOutcome {
                    task_id: task_id.to_string(),
                    backend_used: active.backend.clone(),
                    provider_used: active.provider.clone(),
                    model_used: active.model.clone(),
                    execution_mode,
                    side_effect_replay_prevented: false,
                    thinking: combined_thinking,
                    reply_markdown: format!("操作需要确认审批：{}", pa.summary),
                    trace_dots: outcome_dots,
                    adapter_actions: effect_ledger.adapter_actions.clone(),
                    tool_steps_json: effect_ledger.tool_steps_json.clone(),
                    changeset_ids: effect_ledger.committed_changeset_ids(),
                    handoff_command: None,
                    pending_approval: Some(pa),
                }),
                canonical_tool,
            })
        }

        BrokerDispatchOutcome::Denied { reason } => {
            let step_id = effect_ledger.next_step_id();
            let err_val = json!({ "error": reason });
            effect_ledger
                .trace_dots
                .push(TraceDot::tool_err(&canonical_tool, reason.clone(), 0));
            effect_ledger.record_step(StepExecutionRecord {
                step_id,
                idempotency_key,
                capability_id: canonical_tool,
                canonical_args_json: canonical_args,
                effect,
                mutated_state: false,
                succeeded: false,
                changeset_id: None,
                verification_status: "Denied".to_string(),
                cached_output: err_val.clone(),
            });
            Ok(QuickChatToolExecOutcome::ToolMessage {
                content: serde_json::to_string(&err_val)?,
                is_error: true,
                duplicate_blocked: false,
            })
        }
    }
}

/// Record a user-approved `TaskStep` into `effect_ledger` during `resume_approved_turn`.
pub fn record_approved_step_into_ledger(
    core: &IntentOsCore,
    effect_ledger: &mut TurnEffectLedger,
    step: &TaskStep,
    paused_args_val: &Value,
    task_changeset_ids: &[String],
) {
    let step_id = effect_ledger.next_step_id();
    let canonical_args = canonicalize_json_for_dedup(paused_args_val);
    let idempotency_key =
        effect_ledger.compute_idempotency_key(&step.capability_id, &canonical_args);
    let effect = resolve_capability_effect(core, &step.capability_id);
    let is_ok = matches!(
        step.status,
        ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
    );
    let mutated_state = effect > Effect::Observe && is_ok;

    for csid in task_changeset_ids {
        if !effect_ledger.changeset_ids.contains(csid) {
            effect_ledger.changeset_ids.push(csid.clone());
        }
    }

    let step_discovered_file = step
        .data
        .get("files")
        .or_else(|| step.data.get("candidates"))
        .and_then(|f| f.as_array())
        .and_then(|a| a.first())
        .and_then(|x| x.get("path").or(Some(x)))
        .and_then(|v| v.as_str())
        .map(String::from);
    if let Some(fp) = step_discovered_file {
        effect_ledger.last_resource_path = Some(fp);
    } else if let Some(p) = paused_args_val
        .get("path")
        .or_else(|| paused_args_val.get("target"))
        .or_else(|| paused_args_val.get("source"))
        .or_else(|| paused_args_val.get("directory"))
        .and_then(|v| v.as_str())
    {
        effect_ledger.last_resource_path = Some(p.to_string());
    }

    effect_ledger.trace_dots.push(TraceDot::approved_ok(
        &step.capability_id,
        format!(
            "{} ({}ms, 校验: {:?})",
            step.message, step.duration_ms, step.verification.state
        ),
        step.duration_ms,
        step.changeset_id.clone(),
    ));
    effect_ledger.tool_steps_json.push(json!({
        "step_id": step_id,
        "idempotency_key": idempotency_key,
        "capability_id": step.capability_id,
        "arguments": paused_args_val,
        "status": step.status,
        "duration_ms": step.duration_ms,
        "changeset_id": step.changeset_id,
        "message": step.message,
        "data": step.data,
        "approved_by_user": true,
    }));
    effect_ledger.task_steps.push(step.clone());
    effect_ledger.record_step(StepExecutionRecord {
        step_id,
        idempotency_key,
        capability_id: step.capability_id.clone(),
        canonical_args_json: canonical_args,
        effect,
        mutated_state,
        succeeded: is_ok,
        changeset_id: step.changeset_id.clone(),
        verification_status: format!("{:?}", step.verification.state),
        cached_output: json!({
            "approved_by_user": true,
            "message": step.message,
            "data": step.data,
        }),
    });
}

fn expand_tilde_local(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if trimmed == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    } else if let Some(rest) = trimmed.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(trimmed)
}

/// Auto-infer `(scope_kind, scope_value)` for `"session"` / `"scope"` grants when omitted by caller.
pub fn extract_approval_grant_target(
    req_kind: Option<&str>,
    req_val: Option<&str>,
    pa: Option<&PendingApproval>,
) -> Option<(String, String)> {
    if let Some(val) = req_val.map(str::trim).filter(|s| !s.is_empty()) {
        let kind = req_kind
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if val.starts_with('/') || val.starts_with("~/") || val == "~" {
                    "directory"
                } else {
                    "capability"
                }
            });
        if kind == "directory" {
            let p = expand_tilde_local(val);
            if p.is_file()
                && let Some(parent) = p.parent()
                && parent != Path::new("/")
            {
                return Some(("directory".to_string(), parent.to_string_lossy().to_string()));
            }
            return Some(("directory".to_string(), p.to_string_lossy().to_string()));
        }
        return Some((kind.to_string(), val.to_string()));
    }

    let p = pa?;
    if let Some(dir_str) = p
        .arguments
        .get("directory")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let expanded = expand_tilde_local(dir_str);
        return Some((
            "directory".to_string(),
            expanded.to_string_lossy().to_string(),
        ));
    }

    for key in ["path", "target", "source", "repo_dir", "output"] {
        if let Some(raw_p) = p
            .arguments
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let expanded = expand_tilde_local(raw_p);
            if expanded.is_dir() || raw_p.ends_with('/') {
                return Some((
                    "directory".to_string(),
                    expanded.to_string_lossy().to_string(),
                ));
            }
            if let Some(parent) = expanded.parent()
                && parent != Path::new("/")
                && !parent.as_os_str().is_empty()
            {
                return Some((
                    "directory".to_string(),
                    parent.to_string_lossy().to_string(),
                ));
            }
            return Some((
                "directory".to_string(),
                expanded.to_string_lossy().to_string(),
            ));
        }
    }

    Some(("capability".to_string(), p.capability_id.clone()))
}

/// Supplement `file.search` results on newly approved or session-granted directories outside startup `authorized_roots`.
/// Strictly enforces `follow_links(false)`, skips symlinks & `is_forbidden` paths, and validates via `SafeFsEngine`.
pub fn supplement_approved_dir_file_search(
    core: &IntentOsCore,
    args: &Value,
    message: &mut String,
    data: &mut Value,
) {
    let Some(raw_dir) = args
        .get("directory")
        .or_else(|| args.get("path"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return;
    };

    let dir_path = expand_tilde_local(raw_dir);
    if !dir_path.is_dir() || core.fs_engine.is_forbidden(&dir_path) {
        return;
    }
    if core.fs_engine.classify_path_sensitivity(&dir_path)
        != intentos_fsops::PathSensitivity::NormalUserSpace
    {
        return;
    }

    let query = args
        .get("query")
        .or_else(|| args.get("keyword"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let q_lower = query.to_lowercase();
    let q_tokens: Vec<&str> = q_lower
        .split_whitespace()
        .filter(|t| !t.is_empty())
        .collect();

    let ext_filters: Vec<String> = args
        .get("extensions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(20)
        .clamp(1, 50) as usize;

    let is_doc_category_query = matches!(
        q_lower.as_str(),
        "文档" | "文件" | "资料" | "document" | "documents" | "docs" | "doc"
    );

    let mut existing_paths: HashSet<String> = HashSet::new();
    let mut merged_files: Vec<Value> = data
        .get("files")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for item in &merged_files {
        if let Some(p) = item.get("path").and_then(|v| v.as_str()) {
            existing_paths.insert(p.to_string());
        }
    }

    let mut discovered: Vec<(f64, i64, Value)> = Vec::new();
    let mut scanned = 0usize;

    for entry in walkdir::WalkDir::new(&dir_path)
        .max_depth(6)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.path_is_symlink() || core.fs_engine.is_forbidden(e.path()) {
                return false;
            }
            if e.depth() > 0 && e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                if matches!(
                    name.as_ref(),
                    ".git"
                        | "target"
                        | "node_modules"
                        | ".cache"
                        | ".cargo"
                        | ".rustup"
                        | "__pycache__"
                        | ".venv"
                ) {
                    return false;
                }
            }
            true
        })
    {
        let Ok(entry) = entry else { continue };
        if entry.depth() == 0 || entry.path_is_symlink() {
            continue;
        }
        scanned += 1;
        if scanned > 15_000 {
            break;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let p = entry.path();
        if core.fs_engine.is_forbidden(p) {
            continue;
        }
        let p_str = p.to_string_lossy().to_string();
        if existing_paths.contains(&p_str) {
            continue;
        }

        let ext = p
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if !ext_filters.is_empty() && !ext_filters.iter().any(|ef| ef == &ext) {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();
        let name_lower = name.to_lowercase();
        let rel_lower = p
            .strip_prefix(&dir_path)
            .unwrap_or(p)
            .to_string_lossy()
            .to_lowercase();

        let score_opt =
            if q_lower.is_empty() || q_lower == "*" || q_lower == "全部" || q_lower == "all" {
                Some(80.0)
            } else if name_lower.contains(&q_lower) {
                Some(100.0)
            } else if rel_lower.contains(&q_lower) {
                Some(92.0)
            } else if q_tokens.len() > 1
                && q_tokens
                    .iter()
                    .all(|tok| name_lower.contains(tok) || rel_lower.contains(tok))
            {
                Some(88.0)
            } else if is_doc_category_query
                && matches!(
                    ext.as_str(),
                    "md" | "markdown"
                        | "txt"
                        | "pdf"
                        | "doc"
                        | "docx"
                        | "wps"
                        | "odt"
                        | "rtf"
                        | "xls"
                        | "xlsx"
                        | "csv"
                        | "ppt"
                        | "pptx"
                )
            {
                Some(76.0)
            } else {
                None
            };

        let Some(score) = score_opt else {
            continue;
        };

        let mtime_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let size_bytes = meta.len();

        discovered.push((
            score,
            mtime_secs,
            json!({
                "path": p_str,
                "name": name,
                "size_bytes": size_bytes,
                "mtime_secs": mtime_secs,
                "score": score,
            }),
        ));
    }

    if !discovered.is_empty() {
        discovered.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.cmp(&a.1))
        });
        for (_, _, item) in discovered {
            if merged_files.len() >= limit {
                break;
            }
            merged_files.push(item);
        }
        if let Some(obj) = data.as_object_mut() {
            obj.insert("files".to_string(), Value::Array(merged_files.clone()));
        } else {
            *data = json!({ "files": merged_files });
        }
        *message = format!("在授权目录中检索到 {} 个文件", merged_files.len());
    }
}

/// Synthesize a rich, conversational Markdown summary from approved `TaskStep` results when no live upstream LLM is reachable.
pub fn synthesize_rich_approved_step_markdown(user_text: &str, steps: &[TaskStep]) -> String {
    let Some(last) = steps.last() else {
        return "已完成您批准的操作。".to_string();
    };

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "已根据您的授权完成 **{}** 操作：{}",
        last.capability_id, last.message
    ));

    if let Some(files) = last.data.get("files").and_then(|v| v.as_array()) {
        if files.is_empty() {
            lines.push("\n未在该授权目录下找到符合条件的文件。".to_string());
        } else {
            lines.push(format!("\n共为您找到 **{}** 个匹配文件：", files.len()));
            for (idx, f) in files.iter().take(15).enumerate() {
                let name = f
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("未命名文件");
                let path = f.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let size = f.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                if path.is_empty() {
                    lines.push(format!("{}. **{}** ({} B)", idx + 1, name, size));
                } else {
                    lines.push(format!("{}. **{}** — `{}` ({} B)", idx + 1, name, path, size));
                }
            }
            if files.len() > 15 {
                lines.push(format!("… 以及其余 {} 个文件。", files.len() - 15));
            }
        }
    } else if let Some(content) = last
        .data
        .get("content")
        .or_else(|| last.data.get("text"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        let preview: String = content.chars().take(600).collect();
        lines.push(format!("\n**内容摘要**：\n```\n{}\n```", preview.trim()));
    } else if let Some(path) = last
        .data
        .get("path")
        .or_else(|| last.data.get("target"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        lines.push(format!("- 目标路径：`{}`", path));
    }

    if !user_text.trim().is_empty()
        && lines.len() == 1
        && !last.data.is_null()
        && last.data != json!({})
        && let Ok(pretty) = serde_json::to_string_pretty(&last.data)
    {
        let snippet: String = pretty.chars().take(450).collect();
        lines.push(format!("\n```json\n{}\n```", snippet));
    }

    lines.join("\n")
}

/// Build context blocks while strictly isolating `StateDb` explicit memories when `incognito == true`.
pub fn prepare_turn_context_blocks(
    core: &IntentOsCore,
    extra_blocks: &[ContextBlock],
    incognito: bool,
) -> (Vec<ContextBlock>, Vec<Taint>, DataClass) {
    let (mut blocks, _, _) = build_context_blocks(&core.state_db, extra_blocks.to_vec());
    if incognito {
        // Strictly remove `StateDb` explicit preferences (`user_memories`) in incognito sessions!
        blocks.retain(|b| b.id != "user_memories");
    }

    let mut taints = vec![Taint::User];
    let mut max_dc = DataClass::Public;
    for b in &blocks {
        if !taints.contains(&b.taint) {
            taints.push(b.taint);
        }
        if b.data_class > max_dc {
            max_dc = b.data_class;
        }
    }
    (blocks, taints, max_dc)
}

pub fn prepare_system_prompt_and_context(
    core: &IntentOsCore,
    active: &ActiveBackendSelection,
    extra_blocks: &[ContextBlock],
    incognito: bool,
) -> (String, Vec<Taint>, DataClass) {
    let (mut context_blocks, taints, data_class) =
        prepare_turn_context_blocks(core, extra_blocks, incognito);

    let effort_hint = match active.reasoning_effort.as_str() {
        "fast" => "思考强度：快（fast）—— 请直接切入重点，简洁高效回答。",
        "medium" => "思考强度：标准（medium）—— 平衡响应速度与推理严谨度。",
        "high" => {
            "思考强度：深入（high）—— 在复杂问题上先在 `<think>...</think>` 中充分推演多步方案，再给出清晰结论。"
        }
        _ => "",
    };
    if !effort_hint.is_empty() {
        context_blocks.push(ContextBlock {
            id: "reasoning_effort_hint".to_string(),
            label: "reasoning_mode".to_string(),
            content: effort_hint.to_string(),
            taint: Taint::System,
            data_class: DataClass::Public,
        });
    }

    let sys_text = context_blocks
        .iter()
        .map(|b| format!("[{} | taint={:?}]\n{}", b.label, b.taint, b.content))
        .collect::<Vec<_>>()
        .join("\n\n");

    (sys_text, taints, data_class)
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_completed_turn_outcome(
    core: &IntentOsCore,
    active: &ActiveBackendSelection,
    execution_mode: BackendExecutionMode,
    task_id: &str,
    session: &SessionState,
    user_text: &str,
    incognito: bool,
    taints: Vec<Taint>,
    data_class: DataClass,
    cleaned_content: String,
    effect_ledger: &mut TurnEffectLedger,
) -> TurnExecutionOutcome {
    let final_reply = if cleaned_content.is_empty() {
        if let Some(last_step) = effect_ledger.task_steps.last() {
            last_step.message.clone()
        } else if let Some(last_dot) = effect_ledger.trace_dots.last() {
            last_dot.detail.clone()
        } else {
            "已完成处理。".to_string()
        }
    } else {
        cleaned_content
    };

    let handoff_command = effect_ledger.task_steps.iter().find_map(|st| {
        st.data
            .get("handoff_command")
            .and_then(|v| v.as_str())
            .map(String::from)
    });

    let changeset_ids = effect_ledger.committed_changeset_ids();
    let task_steps = std::mem::take(&mut effect_ledger.task_steps);
    let last_resource_path = effect_ledger.last_resource_path.take();

    if !incognito {
        let now = Utc::now();
        let completed_task = Task {
            id: task_id.to_string(),
            goal: user_text.to_string(),
            session_id: Some(session.session_id.clone()),
            project_id: None,
            trigger: TaskTrigger::User,
            route: RouteLayer::L2,
            status: TaskStatus::Completed,
            steps: task_steps,
            changeset_ids: changeset_ids.clone(),
            pending_approval: None,
            candidates_for_disambiguation: Vec::new(),
            assistant_message: Some(final_reply.clone()),
            result_summary: Some(final_reply.clone()),
            handoff_command: handoff_command.clone(),
            taint: taints,
            data_class,
            budget: TaskBudget::default(),
            created_at: now,
            updated_at: now,
        };
        let _ = core.state_db.upsert_task(&completed_task);
        core.sessions.append_turn(
            &session.session_id,
            user_text,
            &final_reply,
            last_resource_path,
        );
    }

    let combined_thinking = if effect_ledger.accumulated_thoughts.is_empty() {
        None
    } else {
        Some(
            std::mem::take(&mut effect_ledger.accumulated_thoughts)
                .join("\n\n"),
        )
    };

    TurnExecutionOutcome {
        task_id: task_id.to_string(),
        backend_used: active.backend.clone(),
        provider_used: active.provider.clone(),
        model_used: active.model.clone(),
        execution_mode,
        side_effect_replay_prevented: false,
        thinking: combined_thinking,
        reply_markdown: final_reply,
        trace_dots: std::mem::take(&mut effect_ledger.trace_dots),
        adapter_actions: std::mem::take(&mut effect_ledger.adapter_actions),
        tool_steps_json: std::mem::take(&mut effect_ledger.tool_steps_json),
        changeset_ids,
        handoff_command,
        pending_approval: None,
    }
}

/// Convert a deterministic `core.submit_intent` `Task` into a `TurnExecutionOutcome`
/// and record its steps into `effect_ledger` under `BackendExecutionMode::OfflineCore`.
pub fn convert_core_task_to_turn_outcome(
    core: &IntentOsCore,
    task: Task,
    thinking: Option<String>,
    mut reply_markdown: String,
    effect_ledger: &mut TurnEffectLedger,
) -> TurnExecutionOutcome {
    if !task.candidates_for_disambiguation.is_empty() {
        let mut lines = vec![reply_markdown];
        for (idx, cand) in task
            .candidates_for_disambiguation
            .iter()
            .take(6)
            .enumerate()
        {
            lines.push(format!(
                "{}. **{}** — {}",
                idx + 1,
                cand.title,
                cand.subtitle
            ));
        }
        reply_markdown = lines.join("\n");
    }

    let mut trace_dots = Vec::new();
    let mut tool_steps_json = Vec::new();
    for step in &task.steps {
        let step_id = effect_ledger.next_step_id();
        let idempotency_key =
            effect_ledger.compute_idempotency_key(&step.capability_id, &step.arguments_summary);
        let effect = resolve_capability_effect(core, &step.capability_id);
        let ok = matches!(
            step.status,
            ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
        );
        effect_ledger.record_step(StepExecutionRecord {
            step_id: step_id.clone(),
            idempotency_key: idempotency_key.clone(),
            capability_id: step.capability_id.clone(),
            canonical_args_json: step.arguments_summary.clone(),
            effect,
            mutated_state: effect > Effect::Observe && ok,
            succeeded: ok,
            changeset_id: step.changeset_id.clone(),
            verification_status: format!("{:?}", step.verification.state),
            cached_output: step.data.clone(),
        });

        if step.capability_id == "memory_hub.query" || step.capability_id.starts_with("memory_") {
            trace_dots.push(TraceDot::memory(
                format!("记忆召回: {}", step.capability_id),
                step.message.clone(),
            ));
        } else if step.capability_id.starts_with("app_adapter") {
            trace_dots.push(TraceDot::adapter(
                format!("转译层: {}", step.capability_id),
                step.message.clone(),
                Some(step.duration_ms),
                step.changeset_id.clone(),
            ));
        } else if ok {
            let step_unverified = step.status == ExecutionStatus::RequestedUnverified
                || step.verification.state
                    == intentos_protocol::VerificationState::RequestedUnverified
                || step.data.get("simulated").and_then(|v| v.as_bool()) == Some(true);
            if step_unverified {
                trace_dots.push(TraceDot::tool_unverified(
                    &step.capability_id,
                    format!(
                        "{} ({}ms, 状态: 已发送请求，待桌面响应)",
                        step.message, step.duration_ms
                    ),
                    step.duration_ms,
                    step.changeset_id.clone(),
                ));
            } else {
                trace_dots.push(TraceDot::tool_ok(
                    &step.capability_id,
                    format!(
                        "{} ({}ms, 校验: {:?})",
                        step.message, step.duration_ms, step.verification.state
                    ),
                    step.duration_ms,
                    step.changeset_id.clone(),
                ));
            }
        } else {
            trace_dots.push(TraceDot::tool_err(
                &step.capability_id,
                step.message.clone(),
                step.duration_ms,
            ));
        }
        tool_steps_json.push(json!({
            "step_id": step_id,
            "idempotency_key": idempotency_key,
            "capability_id": step.capability_id,
            "arguments_summary": step.arguments_summary,
            "status": step.status,
            "duration_ms": step.duration_ms,
            "changeset_id": step.changeset_id,
            "message": step.message,
            "data": step.data,
        }));
    }

    if let Some(ref pa) = task.pending_approval {
        trace_dots.push(TraceDot::approval(pa));
    } else if task.status == TaskStatus::Failed && task.steps.is_empty() {
        trace_dots.push(TraceDot::tool_err(
            "intent.router",
            reply_markdown.clone(),
            0,
        ));
    }

    TurnExecutionOutcome {
        task_id: task.id,
        backend_used: "fallback".to_string(),
        provider_used: "intentos-core".to_string(),
        model_used: format!("{:?}", task.route).to_ascii_lowercase(),
        execution_mode: BackendExecutionMode::OfflineCore,
        side_effect_replay_prevented: false,
        thinking,
        reply_markdown,
        trace_dots,
        adapter_actions: Vec::new(),
        tool_steps_json,
        changeset_ids: task.changeset_ids,
        handoff_command: task.handoff_command,
        pending_approval: task.pending_approval,
    }
}

/// Build a safe halted outcome when an upstream backend fails AFTER mutating side-effects committed,
/// preventing secondary CLI / `core.submit_intent` fallback from replaying user mutations a second time!
#[allow(clippy::too_many_arguments)]
pub fn build_halted_side_effect_outcome(
    core: &IntentOsCore,
    active: &ActiveBackendSelection,
    task_id: &str,
    session: &SessionState,
    user_text: &str,
    incognito: bool,
    taints: Vec<Taint>,
    data_class: DataClass,
    effect_ledger: &mut TurnEffectLedger,
    upstream_err_msg: &str,
) -> TurnExecutionOutcome {
    let changeset_ids = effect_ledger.committed_changeset_ids();
    let mut summary_lines = vec![
        "已完成前置系统操作，但后续模型响应异常；为防止重复执行副作用，已安全中止自动回退重试：".to_string(),
    ];
    for rec in effect_ledger.records().iter().filter(|r| r.succeeded) {
        if let Some(ref csid) = rec.changeset_id {
            summary_lines.push(format!(
                "- **{}** (`{}`)：已执行成功（可撤销凭证：`{}`）",
                rec.step_id, rec.capability_id, csid
            ));
        } else {
            summary_lines.push(format!(
                "- **{}** (`{}`)：已执行成功",
                rec.step_id, rec.capability_id
            ));
        }
    }
    summary_lines.push(format!("\n中止原因：{}", upstream_err_msg));
    if !changeset_ids.is_empty() {
        summary_lines.push(format!(
            "如需回滚已执行的变更，可使用撤销记录（`{}`）一键撤销。",
            changeset_ids.join("`, `")
        ));
    }
    let honest_reply = summary_lines.join("\n");

    let handoff_command = effect_ledger.task_steps.iter().find_map(|st| {
        st.data
            .get("handoff_command")
            .and_then(|v| v.as_str())
            .map(String::from)
    });
    let task_steps = std::mem::take(&mut effect_ledger.task_steps);
    let last_resource_path = effect_ledger.last_resource_path.take();

    if !incognito {
        let now = Utc::now();
        let partial_task = Task {
            id: task_id.to_string(),
            goal: user_text.to_string(),
            session_id: Some(session.session_id.clone()),
            project_id: None,
            trigger: TaskTrigger::User,
            route: RouteLayer::L2,
            status: TaskStatus::Completed,
            steps: task_steps,
            changeset_ids: changeset_ids.clone(),
            pending_approval: None,
            candidates_for_disambiguation: Vec::new(),
            assistant_message: Some(honest_reply.clone()),
            result_summary: Some(honest_reply.clone()),
            handoff_command: handoff_command.clone(),
            taint: taints,
            data_class,
            budget: TaskBudget::default(),
            created_at: now,
            updated_at: now,
        };
        let _ = core.state_db.upsert_task(&partial_task);
        core.sessions.append_turn(
            &session.session_id,
            user_text,
            &honest_reply,
            last_resource_path,
        );
    }

    let combined_thinking = if effect_ledger.accumulated_thoughts.is_empty() {
        None
    } else {
        Some(
            std::mem::take(&mut effect_ledger.accumulated_thoughts)
                .join("\n\n"),
        )
    };

    TurnExecutionOutcome {
        task_id: task_id.to_string(),
        backend_used: active.backend.clone(),
        provider_used: active.provider.clone(),
        model_used: active.model.clone(),
        execution_mode: BackendExecutionMode::ManagedBrokerTools,
        side_effect_replay_prevented: true,
        thinking: combined_thinking,
        reply_markdown: honest_reply,
        trace_dots: std::mem::take(&mut effect_ledger.trace_dots),
        adapter_actions: std::mem::take(&mut effect_ledger.adapter_actions),
        tool_steps_json: std::mem::take(&mut effect_ledger.tool_steps_json),
        changeset_ids,
        handoff_command,
        pending_approval: None,
    }
}
