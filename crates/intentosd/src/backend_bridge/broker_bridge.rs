#![forbid(unsafe_code)]

//! Unified `CapabilityBroker` Bridge, Tool Spec Builder & Effect Ledger Recorder (`broker_bridge.rs`).
//!
//! Connects all external/local LLM transports (OpenAI HTTP, Anthropic HTTP, and Controlled CLI)
//! to IntentOS's single-entry `CapabilityBroker` security & undo pipeline, recording every
//! invocation into `TurnEffectLedger`.

use crate::backend_bridge::detector::ActiveBackendSelection;
pub use crate::backend_bridge::turn_checkpoint::{
    IdempotencyDecision, StepExecutionMeta, StepInvocationContext, ToolIdempotencyPolicy,
};
use crate::backend_bridge::turn_checkpoint::{
    StepExecutionRecord, TurnEffectLedger, canonicalize_tool_args_value,
};
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
use std::collections::HashSet;
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
    canonicalize_tool_args_value(val)
}

fn strip_untrusted_step_meta_fields(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut clean = serde_json::Map::new();
            for (k, v) in map {
                if matches!(
                    k.as_str(),
                    "step_id"
                        | "_step_id"
                        | "__step_id"
                        | "attempt_id"
                        | "_attempt_id"
                        | "idempotency_key"
                ) {
                    continue;
                }
                clean.insert(k.clone(), v.clone());
            }
            Value::Object(clean)
        }
        other => other.clone(),
    }
}

fn has_relative_or_toggle_adjustment(parsed_args: &Value) -> bool {
    let Some(obj) = parsed_args.as_object() else {
        return false;
    };
    if let Some(rel) = obj.get("relative") {
        let non_empty = match rel {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::String(s) => !s.trim().is_empty(),
            _ => true,
        };
        if non_empty {
            return true;
        }
    }
    if obj.get("delta").is_some_and(|v| !v.is_null()) {
        return true;
    }
    if obj.get("toggle").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }
    if let Some(act) = obj
        .get("action")
        .or_else(|| obj.get("mode"))
        .and_then(|v| v.as_str())
    {
        let act_norm = act.trim().to_ascii_lowercase();
        if matches!(
            act_norm.as_str(),
            "up" | "down"
                | "increase"
                | "decrease"
                | "inc"
                | "dec"
                | "toggle"
                | "next"
                | "previous"
                | "prev"
                | "play_pause"
        ) {
            return true;
        }
    }
    false
}

/// Deterministically classify `ToolIdempotencyPolicy` from trusted capability metadata and arguments.
pub fn classify_capability_idempotency(
    capability_id: &str,
    effect: Effect,
    parsed_args: &Value,
) -> ToolIdempotencyPolicy {
    let cap = capability_id.trim();

    if effect == Effect::Observe
        || cap.starts_with("memory_")
        || cap.starts_with("memory.")
        || matches!(
            cap,
            "app_adapter_inspect_app"
                | "app_adapter.inspect_app"
                | "app_adapter_list"
                | "app_adapter.list"
                | "app_adapter_now_playing"
                | "app_adapter.now_playing"
        )
    {
        if matches!(
            cap,
            "file.search"
                | "app.search"
                | "package.search"
                | "web.resolve"
                | "web.search"
                | "web.search_site"
        ) {
            return ToolIdempotencyPolicy::CacheUntilStateChanged;
        }
        return ToolIdempotencyPolicy::AlwaysRefresh;
    }

    if matches!(
        cap,
        "process.terminate"
            | "power.session"
            | "screen.lock"
            | "settings.reset"
            | "terminal.handoff"
            | "package.install"
            | "package.remove"
            | "service.control"
            | "docker.control"
    ) || (effect >= Effect::WriteDestructive && cap != "file.trash")
    {
        return ToolIdempotencyPolicy::NeverReplay;
    }

    if !has_relative_or_toggle_adjustment(parsed_args)
        && (cap.starts_with("appearance.")
            || matches!(
                cap,
                "sound.volume.set"
                    | "sound.mic.volume.set"
                    | "sound.mute.set"
                    | "sound.mic.mute.set"
                    | "sound.output.switch"
                    | "display.brightness.set"
                    | "display.night_light.set"
                    | "display.scale.set"
                    | "display.resolution.set"
                    | "display.orientation.set"
                    | "notify.dnd.set"
                    | "power.profile.set"
                    | "power.idle_timeout.set"
                    | "bluetooth.power.set"
                    | "network.wifi.set"
                    | "network.airplane.set"
                    | "network.vpn.set"
                    | "network.proxy.set"
                    | "file.mkdir"
            ))
    {
        return ToolIdempotencyPolicy::IdempotentMutation;
    }

    ToolIdempotencyPolicy::ExactlyOncePerStep
}

/// Derive `ToolIdempotencyPolicy` from `IntentOsCore`'s trusted capability registry + arguments.
pub fn derive_tool_idempotency_policy(
    core: &IntentOsCore,
    canonical_tool: &str,
    parsed_args: &Value,
) -> ToolIdempotencyPolicy {
    let effect = resolve_capability_effect(core, canonical_tool);
    classify_capability_idempotency(canonical_tool, effect, parsed_args)
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

/// Execute a single Quick-Chat tool call through `CapabilityBroker`, enforcing capability-semantic
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
    execute_quick_chat_tool_call_with_step(
        core,
        active,
        execution_mode,
        task_id,
        session,
        user_text,
        incognito,
        taints,
        data_class,
        StepInvocationContext::new_call(call_id),
        fn_name,
        parsed_args,
        effect_ledger,
    )
    .await
}

/// Execute a Quick-Chat tool call with explicit separation of trusted `step_id` (from `TurnEffectLedger`
/// or trusted orchestrator), transport `call_id`, and `attempt_id`.
#[allow(clippy::too_many_arguments)]
pub async fn execute_quick_chat_tool_call_with_step(
    core: &IntentOsCore,
    active: &ActiveBackendSelection,
    execution_mode: BackendExecutionMode,
    task_id: &str,
    session: &SessionState,
    user_text: &str,
    incognito: bool,
    taints: &[Taint],
    data_class: DataClass,
    step_ctx: StepInvocationContext,
    fn_name: &str,
    parsed_args: &Value,
    effect_ledger: &mut TurnEffectLedger,
) -> anyhow::Result<QuickChatToolExecOutcome> {
    let canonical_tool = resolve_tool_name_to_capability(fn_name, core);
    let is_mem = crate::memory_hub::is_memory_tool(&canonical_tool);
    let is_adap = crate::app_adapter::is_adapter_tool(&canonical_tool);

    // Strip untrusted model-supplied step identity fields before policy/dedup/dispatch
    let sanitized_input_args = strip_untrusted_step_meta_fields(parsed_args);
    let canonical_args = canonicalize_json_for_dedup(&sanitized_input_args);
    let effect = resolve_capability_effect(core, &canonical_tool);
    let policy = classify_capability_idempotency(&canonical_tool, effect, &sanitized_input_args);
    let attempt_id = if step_ctx.attempt_id.trim().is_empty() {
        "attempt_1".to_string()
    } else {
        step_ctx.attempt_id.trim().to_string()
    };

    // Capability-Semantic Idempotency & Step-Identity Evaluation via `TurnEffectLedger`
    match effect_ledger.evaluate_idempotency(
        policy,
        step_ctx.trusted_step_id.as_deref(),
        &attempt_id,
        &canonical_tool,
        &canonical_args,
    ) {
        IdempotencyDecision::StepIdentityConflict {
            step_id,
            existing_capability,
        } => {
            let err_payload = serde_json::to_string(&json!({
                "duplicate_call_blocked": true,
                "idempotent_dedup": false,
                "is_error": true,
                "was_denied": false,
                "dedup_reason": "step_identity_conflict",
                "step_id": step_id,
                "existing_capability": existing_capability,
                "requested_capability": canonical_tool,
                "error": format!(
                    "Trusted step_id '{}' is already bound to '{}' and cannot be reused with conflicting capability or arguments",
                    step_id, existing_capability
                ),
            }))?;
            return Ok(QuickChatToolExecOutcome::ToolMessage {
                content: err_payload,
                is_error: true,
                duplicate_blocked: true,
            });
        }

        IdempotencyDecision::CachedHit {
            record: prev,
            reason,
            ..
        } => {
            let is_err = prev.is_error();
            let was_denied = prev.was_denied();
            let feedback = serde_json::to_string(&json!({
                "duplicate_call_blocked": true,
                "idempotent_dedup": !is_err,
                "dedup_reason": reason,
                "policy": policy,
                "idempotency_key": prev.idempotency_key,
                "step_id": prev.step_id,
                "tool": canonical_tool,
                "is_error": is_err,
                "was_denied": was_denied,
                "verification_status": prev.verification_status,
                "changeset_id": prev.changeset_id,
                "cached_output": prev.cached_output,
                "instruction": if was_denied {
                    "该操作已被安全策略拒绝（Denied），重复调用同样被拦截。请不要再次尝试访问受禁路径或权限范围。"
                } else if is_err {
                    "该步骤此前执行失败，为防止未知副作用已阻止盲目重放。请向用户如实说明错误原因。"
                } else {
                    "检测到当前回合内重复调用可安全去重的工具与参数，系统已通过 TurnEffectLedger 幂等账本拦截重复执行并返回缓存输出。请不要再次调用该工具，请立即基于已有结果向用户总结并完成回复。"
                }
            }))?;
            return Ok(QuickChatToolExecOutcome::ToolMessage {
                content: feedback,
                is_error: is_err,
                duplicate_blocked: true,
            });
        }

        IdempotencyDecision::Proceed => {}
    }

    let mut effective_args = sanitized_input_args.clone();
    if is_mem
        && !incognito
        && let Some(obj) = effective_args.as_object_mut()
    {
        obj.entry("session_id".to_string())
            .or_insert_with(|| json!(session.session_id));
    }

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
        request_id: step_ctx.call_id.clone(),
        task_id: task_id.to_string(),
        capability_id: canonical_tool.clone(),
        arguments: effective_args,
        origin: call_origin,
        taints: taints.to_vec(),
    };

    match core.broker.dispatch(&call).await? {
        BrokerDispatchOutcome::Executed(mut res) => {
            let step_id = step_ctx
                .trusted_step_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| effect_ledger.next_step_id());
            let pre_epoch = effect_ledger.state_epoch();
            let post_epoch = if effect > Effect::Observe {
                effect_ledger.bump_state_epoch()
            } else {
                pre_epoch
            };
            let idempotency_key = effect_ledger.compute_step_idempotency_key(
                policy,
                &step_id,
                &attempt_id,
                &canonical_tool,
                &canonical_args,
                post_epoch,
            );

            if canonical_tool == "file.search" {
                supplement_approved_dir_file_search(
                    core,
                    &call.arguments,
                    &mut res.message,
                    &mut res.data,
                );
            }
            if let Some(p) = sanitized_input_args
                .get("path")
                .or_else(|| sanitized_input_args.get("target"))
                .or_else(|| sanitized_input_args.get("source"))
                .or_else(|| sanitized_input_args.get("directory"))
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
            let step_meta = StepExecutionMeta {
                step_id: step_id.clone(),
                call_id: step_ctx.call_id.clone(),
                attempt_id: attempt_id.clone(),
                policy,
                pre_state_epoch: pre_epoch,
                post_state_epoch: post_epoch,
                is_error: !is_ok,
                was_denied: false,
                verification_status: verification_status.clone(),
            };

            if is_mem {
                let summary = serde_json::to_string_pretty(&res.data)
                    .unwrap_or_else(|_| res.data.to_string());
                effect_ledger.trace_dots.push(TraceDot::memory(
                    format!("记忆查询: {}", canonical_tool),
                    summary,
                ));
                effect_ledger.tool_steps_json.push(json!({
                    "step_id": step_id,
                    "call_id": step_ctx.call_id,
                    "attempt_id": attempt_id,
                    "policy": policy,
                    "idempotency_key": idempotency_key,
                    "capability_id": canonical_tool,
                    "tool": canonical_tool,
                    "arguments": sanitized_input_args,
                    "duration_ms": res.duration_ms,
                    "data": res.data,
                }));
                effect_ledger.task_steps.push(TaskStep {
                    step_id: step_id.clone(),
                    capability_id: canonical_tool.clone(),
                    arguments_summary: sanitized_input_args.to_string(),
                    status: res.status,
                    verification: res.verification,
                    changeset_id: res.changeset_id.clone(),
                    message: res.message,
                    data: res.data.clone(),
                    duration_ms: res.duration_ms,
                });
                effect_ledger.record_step_with_meta(
                    StepExecutionRecord {
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
                    },
                    step_meta,
                );
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
                    "call_id": step_ctx.call_id,
                    "attempt_id": attempt_id,
                    "policy": policy,
                    "idempotency_key": idempotency_key,
                    "capability_id": canonical_tool,
                    "tool": canonical_tool,
                    "arguments": sanitized_input_args,
                    "duration_ms": res.duration_ms,
                    "data": res.data,
                    "result": res.data,
                }));
                effect_ledger.task_steps.push(TaskStep {
                    step_id: step_id.clone(),
                    capability_id: canonical_tool.clone(),
                    arguments_summary: sanitized_input_args.to_string(),
                    status: res.status,
                    verification: res.verification,
                    changeset_id: res.changeset_id.clone(),
                    message: res.message,
                    data: res.data.clone(),
                    duration_ms: res.duration_ms,
                });
                effect_ledger.record_step_with_meta(
                    StepExecutionRecord {
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
                    },
                    step_meta,
                );
                return Ok(QuickChatToolExecOutcome::ToolMessage {
                    content: serde_json::to_string(&res.data)?,
                    is_error: !is_ok,
                    duplicate_blocked: false,
                });
            }

            let is_unverified = res.status == ExecutionStatus::RequestedUnverified
                || res.verification.state
                    == intentos_protocol::VerificationState::RequestedUnverified
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
                "call_id": step_ctx.call_id,
                "attempt_id": attempt_id,
                "policy": policy,
                "idempotency_key": idempotency_key,
                "capability_id": canonical_tool,
                "arguments": sanitized_input_args,
                "status": res.status,
                "duration_ms": res.duration_ms,
                "changeset_id": res.changeset_id,
                "message": res.message,
                "data": res.data,
            }));
            effect_ledger.task_steps.push(TaskStep {
                step_id: step_id.clone(),
                capability_id: canonical_tool.clone(),
                arguments_summary: sanitized_input_args.to_string(),
                status: res.status,
                verification: res.verification,
                changeset_id: res.changeset_id.clone(),
                message: res.message.clone(),
                data: res.data.clone(),
                duration_ms: res.duration_ms,
            });
            effect_ledger.record_step_with_meta(
                StepExecutionRecord {
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
                },
                step_meta,
            );

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
            let step_id = step_ctx
                .trusted_step_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| effect_ledger.next_step_id());
            let epoch = effect_ledger.state_epoch();
            let idempotency_key = effect_ledger.compute_step_idempotency_key(
                policy,
                &step_id,
                &attempt_id,
                &canonical_tool,
                &canonical_args,
                epoch,
            );
            let err_val = json!({
                "error": reason,
                "was_denied": true,
            });
            effect_ledger
                .trace_dots
                .push(TraceDot::tool_err(&canonical_tool, reason.clone(), 0));
            let step_meta = StepExecutionMeta {
                step_id: step_id.clone(),
                call_id: step_ctx.call_id,
                attempt_id,
                policy,
                pre_state_epoch: epoch,
                post_state_epoch: epoch,
                is_error: true,
                was_denied: true,
                verification_status: "Denied".to_string(),
            };
            effect_ledger.record_step_with_meta(
                StepExecutionRecord {
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
                },
                step_meta,
            );
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
    let sanitized_args = strip_untrusted_step_meta_fields(paused_args_val);
    let canonical_args = canonicalize_json_for_dedup(&sanitized_args);
    let effect = resolve_capability_effect(core, &step.capability_id);
    let policy = classify_capability_idempotency(&step.capability_id, effect, &sanitized_args);
    // Always advance `state_epoch` on user approval (new scope/grant or state mutation)!
    let pre_epoch = effect_ledger.state_epoch();
    let post_epoch = effect_ledger.bump_state_epoch();
    let idempotency_key = effect_ledger.compute_step_idempotency_key(
        policy,
        &step_id,
        "approved_attempt_1",
        &step.capability_id,
        &canonical_args,
        post_epoch,
    );
    let is_ok = matches!(
        step.status,
        ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
    );
    let mutated_state = effect > Effect::Observe && is_ok;
    let verification_status = format!("{:?}", step.verification.state);

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
    } else if let Some(p) = sanitized_args
        .get("path")
        .or_else(|| sanitized_args.get("target"))
        .or_else(|| sanitized_args.get("source"))
        .or_else(|| sanitized_args.get("directory"))
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
        "policy": policy,
        "idempotency_key": idempotency_key,
        "capability_id": step.capability_id,
        "arguments": sanitized_args,
        "status": step.status,
        "duration_ms": step.duration_ms,
        "changeset_id": step.changeset_id,
        "message": step.message,
        "data": step.data,
        "approved_by_user": true,
    }));
    effect_ledger.task_steps.push(step.clone());
    let step_meta = StepExecutionMeta {
        step_id: step_id.clone(),
        call_id: step.step_id.clone(),
        attempt_id: "approved_attempt_1".to_string(),
        policy,
        pre_state_epoch: pre_epoch,
        post_state_epoch: post_epoch,
        is_error: !is_ok,
        was_denied: false,
        verification_status: verification_status.clone(),
    };
    effect_ledger.record_step_with_meta(
        StepExecutionRecord {
            step_id,
            idempotency_key,
            capability_id: step.capability_id.clone(),
            canonical_args_json: canonical_args,
            effect,
            mutated_state,
            succeeded: is_ok,
            changeset_id: step.changeset_id.clone(),
            verification_status,
            cached_output: json!({
                "approved_by_user": true,
                "message": step.message,
                "data": step.data,
            }),
        },
        step_meta,
    );
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
                return Some((
                    "directory".to_string(),
                    parent.to_string_lossy().to_string(),
                ));
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
                    lines.push(format!(
                        "{}. **{}** — `{}` ({} B)",
                        idx + 1,
                        name,
                        path,
                        size
                    ));
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
        Some(std::mem::take(&mut effect_ledger.accumulated_thoughts).join("\n\n"))
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
        "已完成前置系统操作，但后续模型响应异常；为防止重复执行副作用，已安全中止自动回退重试："
            .to_string(),
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
        Some(std::mem::take(&mut effect_ledger.accumulated_thoughts).join("\n\n"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, BrainConfig, XdgPaths};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn setup_bridge_test_core() -> (TempDir, PathBuf, Arc<IntentOsCore>) {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("base");
        let ws = temp.path().join("workspace");
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
        (temp, ws, core)
    }

    fn dummy_active_selection() -> ActiveBackendSelection {
        ActiveBackendSelection {
            backend: "openai".to_string(),
            provider: "test".to_string(),
            model: "gpt-4o-mini".to_string(),
            reasoning_effort: "medium".to_string(),
            base_url: None,
            pinned: false,
            auto_selected: true,
            direct_http_capable: true,
            pill_label: "OpenAI".to_string(),
        }
    }

    #[tokio::test]
    async fn h02_read_write_read_gets_updated_value_and_invalidates_search_cache() {
        let (_tmp, ws, core) = setup_bridge_test_core();
        core.policy
            .add_session_grant("directory", &ws.to_string_lossy(), 30);
        let session = core.sessions.get_or_create(Some("ses_h02_rw"));
        let active = dummy_active_selection();
        let mut ledger = TurnEffectLedger::new("turn_h02_rw");

        let note_path = ws.join("status_note.md");
        std::fs::write(&note_path, "alpha_v1").unwrap();

        // 1. Read #1 (`memory_inspect_document` -> AlwaysRefresh) gets "alpha_v1"
        let r1 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_rw",
            &session,
            "read update read",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_r1",
            "memory_inspect_document",
            &json!({ "path": note_path.to_string_lossy() }),
            &mut ledger,
        )
        .await
        .unwrap();
        match r1 {
            QuickChatToolExecOutcome::ToolMessage {
                content,
                is_error,
                duplicate_blocked,
            } => {
                assert!(!is_error);
                assert!(!duplicate_blocked);
                assert!(content.contains("alpha_v1"));
            }
            _ => panic!("expected ToolMessage"),
        }

        // 2. Search #1 (`file.search` -> CacheUntilStateChanged) finds 1 file at epoch 0
        let s1 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_rw",
            &session,
            "read update read",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_s1",
            "file_search",
            &json!({ "directory": ws.to_string_lossy(), "query": "status_note" }),
            &mut ledger,
        )
        .await
        .unwrap();
        if let QuickChatToolExecOutcome::ToolMessage {
            duplicate_blocked,
            is_error,
            ..
        } = s1
        {
            assert!(!is_error);
            assert!(!duplicate_blocked);
        } else {
            panic!("expected ToolMessage");
        }

        // 3. Search #2 before any mutation -> hits CacheUntilStateChanged!
        let s2 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_rw",
            &session,
            "read update read",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_s2",
            "file_search",
            &json!({ "query": "status_note", "directory": format!("{}/.", ws.display()) }),
            &mut ledger,
        )
        .await
        .unwrap();
        if let QuickChatToolExecOutcome::ToolMessage {
            duplicate_blocked,
            is_error,
            ..
        } = s2
        {
            assert!(!is_error);
            assert!(
                duplicate_blocked,
                "file.search must be cached within unchanged state_epoch"
            );
        } else {
            panic!("expected ToolMessage");
        }

        // 4. Mutating `file.write` updates status_note.md -> "beta_v2" and bumps state_epoch!
        let epoch_before = ledger.state_epoch();
        let w1 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_rw",
            &session,
            "read update read",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_w1",
            "file_write",
            &json!({
                "path": note_path.to_string_lossy(),
                "content": "beta_v2"
            }),
            &mut ledger,
        )
        .await
        .unwrap();
        if let QuickChatToolExecOutcome::ToolMessage {
            is_error,
            duplicate_blocked,
            ..
        } = w1
        {
            assert!(!is_error);
            assert!(!duplicate_blocked);
        } else {
            panic!("expected ToolMessage for file.write");
        }
        assert!(
            ledger.state_epoch() > epoch_before,
            "mutating tool must bump state_epoch"
        );

        let extra_note = ws.join("status_note_2.md");
        let _ = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_rw",
            &session,
            "read update read",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_w2",
            "file_write",
            &json!({
                "path": extra_note.to_string_lossy(),
                "content": "extra_file"
            }),
            &mut ledger,
        )
        .await
        .unwrap();

        // 5. Read #2 (`memory_inspect_document` -> AlwaysRefresh) gets fresh "beta_v2"!
        let r2 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_rw",
            &session,
            "read update read",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_r2",
            "memory_inspect_document",
            &json!({ "path": note_path.to_string_lossy() }),
            &mut ledger,
        )
        .await
        .unwrap();
        match r2 {
            QuickChatToolExecOutcome::ToolMessage {
                content,
                is_error,
                duplicate_blocked,
            } => {
                assert!(!is_error);
                assert!(!duplicate_blocked, "read after write must NEVER be blocked");
                assert!(
                    content.contains("beta_v2"),
                    "read after write must return updated content, got: {content}"
                );
            }
            _ => panic!("expected ToolMessage"),
        }

        // 6. Search #3 after mutation -> CacheUntilStateChanged invalidated, sees new file!
        let s3 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_rw",
            &session,
            "read update read",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_s3",
            "file_search",
            &json!({ "directory": ws.to_string_lossy(), "query": "status_note" }),
            &mut ledger,
        )
        .await
        .unwrap();
        match s3 {
            QuickChatToolExecOutcome::ToolMessage {
                content,
                is_error,
                duplicate_blocked,
            } => {
                assert!(!is_error);
                assert!(
                    !duplicate_blocked,
                    "CacheUntilStateChanged must invalidate when state_epoch advances"
                );
                assert!(content.contains("status_note_2.md"));
            }
            _ => panic!("expected ToolMessage"),
        }
    }

    #[tokio::test]
    async fn h02_consecutive_media_next_and_relative_volume_both_execute_while_same_step_replays_once()
     {
        let (_tmp, _ws, core) = setup_bridge_test_core();
        let session = core.sessions.get_or_create(Some("ses_h02_seq"));
        let active = dummy_active_selection();
        let mut ledger = TurnEffectLedger::new("turn_h02_seq");

        assert_eq!(
            derive_tool_idempotency_policy(&core, "media.control", &json!({ "action": "next" })),
            ToolIdempotencyPolicy::ExactlyOncePerStep
        );
        assert_eq!(
            derive_tool_idempotency_policy(
                &core,
                "sound.volume.set",
                &json!({ "relative": "up", "value": 5 })
            ),
            ToolIdempotencyPolicy::ExactlyOncePerStep
        );
        assert_eq!(
            derive_tool_idempotency_policy(&core, "sound.volume.set", &json!({ "value": 55 })),
            ToolIdempotencyPolicy::IdempotentMutation
        );

        // 1. Two consecutive `media.control("next")` steps -> BOTH execute!
        for call_id in ["call_next_1", "call_next_2"] {
            let out = execute_quick_chat_tool_call(
                &core,
                &active,
                BackendExecutionMode::ManagedBrokerTools,
                "task_h02_seq",
                &session,
                "skip two tracks",
                false,
                &[Taint::User],
                DataClass::Public,
                call_id,
                "media_control",
                &json!({ "action": "next" }),
                &mut ledger,
            )
            .await
            .unwrap();
            match out {
                QuickChatToolExecOutcome::ToolMessage {
                    duplicate_blocked, ..
                } => {
                    assert!(
                        !duplicate_blocked,
                        "distinct logical media.control('next') steps must both execute ({call_id})"
                    );
                }
                _ => panic!("expected ToolMessage"),
            }
        }
        assert_eq!(ledger.records().len(), 2);
        assert_eq!(ledger.records()[0].step_id, "step_1");
        assert_eq!(ledger.records()[1].step_id, "step_2");

        // 2. Duplicate replay of trusted `step_1` executes AT MOST ONCE!
        let replay_step1 = execute_quick_chat_tool_call_with_step(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_seq",
            &session,
            "skip two tracks",
            false,
            &[Taint::User],
            DataClass::Public,
            StepInvocationContext::for_trusted_step("step_1", "call_next_1_retry", "attempt_2"),
            "media_control",
            &json!({ "action": "next" }),
            &mut ledger,
        )
        .await
        .unwrap();
        match replay_step1 {
            QuickChatToolExecOutcome::ToolMessage {
                duplicate_blocked, ..
            } => {
                assert!(
                    duplicate_blocked,
                    "replaying the same trusted step_id must not execute a second time"
                );
            }
            _ => panic!("expected ToolMessage"),
        }
        assert_eq!(ledger.records().len(), 2);

        // 3. Two consecutive relative `sound.volume.set` steps -> BOTH execute!
        for call_id in ["call_rel_vol_1", "call_rel_vol_2"] {
            let out = execute_quick_chat_tool_call(
                &core,
                &active,
                BackendExecutionMode::ManagedBrokerTools,
                "task_h02_seq",
                &session,
                "raise volume twice",
                false,
                &[Taint::User],
                DataClass::Public,
                call_id,
                "sound_volume_set",
                &json!({ "relative": "up", "value": 5, "step_id": "step_1" }),
                &mut ledger,
            )
            .await
            .unwrap();
            match out {
                QuickChatToolExecOutcome::ToolMessage {
                    duplicate_blocked, ..
                } => {
                    assert!(
                        !duplicate_blocked,
                        "relative volume steps must both execute and ignore untrusted model step_id"
                    );
                }
                _ => panic!("expected ToolMessage"),
            }
        }
        assert_eq!(ledger.records().len(), 4);

        // 4. Absolute `sound.volume.set({"value": 55})` deduplicates immediate repeat even if model injects forged `step_id`
        let abs1 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_seq",
            &session,
            "set volume 55",
            false,
            &[Taint::User],
            DataClass::Public,
            "call_abs_1",
            "sound_volume_set",
            &json!({ "value": 55 }),
            &mut ledger,
        )
        .await
        .unwrap();
        assert!(matches!(
            abs1,
            QuickChatToolExecOutcome::ToolMessage {
                duplicate_blocked: false,
                is_error: false,
                ..
            }
        ));

        let abs2 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_seq",
            &session,
            "set volume 55",
            false,
            &[Taint::User],
            DataClass::Public,
            "call_abs_2",
            "sound_volume_set",
            &json!({ "value": 55, "step_id": "forged_step_999" }),
            &mut ledger,
        )
        .await
        .unwrap();
        assert!(matches!(
            abs2,
            QuickChatToolExecOutcome::ToolMessage {
                duplicate_blocked: true,
                is_error: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn h02_denied_call_stays_is_error_true_and_transient_read_allows_single_retry() {
        let (_tmp, _ws, core) = setup_bridge_test_core();
        let session = core.sessions.get_or_create(Some("ses_h02_deny"));
        let active = dummy_active_selection();
        let mut ledger = TurnEffectLedger::new("turn_h02_deny");

        // 1. Forbidden path `~/.ssh/id_ed25519` -> Denied (`is_error: true`)
        let d1 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_deny",
            &session,
            "write ssh key",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_deny_1",
            "file_write",
            &json!({ "path": "~/.ssh/id_ed25519", "content": "unauthorized" }),
            &mut ledger,
        )
        .await
        .unwrap();
        match d1 {
            QuickChatToolExecOutcome::ToolMessage {
                is_error,
                duplicate_blocked,
                ..
            } => {
                assert!(is_error, "initial policy denial must set is_error = true");
                assert!(!duplicate_blocked);
            }
            _ => panic!("expected ToolMessage on policy denial"),
        }

        // 2. Duplicate call in same turn AND replay of same `step_1` MUST stay `is_error: true`!
        let d2 = execute_quick_chat_tool_call(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_deny",
            &session,
            "write ssh key",
            false,
            &[Taint::User],
            DataClass::Personal,
            "call_deny_2",
            "file_write",
            &json!({ "content": "unauthorized", "path": "~/.ssh/./id_ed25519" }),
            &mut ledger,
        )
        .await
        .unwrap();
        match d2 {
            QuickChatToolExecOutcome::ToolMessage {
                content,
                is_error,
                duplicate_blocked,
            } => {
                assert!(duplicate_blocked);
                assert!(
                    is_error,
                    "cached policy denial must NEVER flip is_error to false!"
                );
                let parsed: Value = serde_json::from_str(&content).unwrap();
                assert_eq!(parsed["was_denied"], true);
                assert_eq!(parsed["idempotent_dedup"], false);
            }
            _ => panic!("expected ToolMessage"),
        }

        let d3 = execute_quick_chat_tool_call_with_step(
            &core,
            &active,
            BackendExecutionMode::ManagedBrokerTools,
            "task_h02_deny",
            &session,
            "write ssh key",
            false,
            &[Taint::User],
            DataClass::Personal,
            StepInvocationContext::for_trusted_step("step_1", "call_deny_retry", "attempt_2"),
            "file_write",
            &json!({ "path": "~/.ssh/id_ed25519", "content": "unauthorized" }),
            &mut ledger,
        )
        .await
        .unwrap();
        assert!(matches!(
            d3,
            QuickChatToolExecOutcome::ToolMessage {
                is_error: true,
                duplicate_blocked: true,
                ..
            }
        ));

        // 3. Transient read-only failure allows AT MOST 1 retry; failed mutation allows 0 blind retries
        let mut retry_ledger = TurnEffectLedger::new("turn_h02_retry");
        let read_args = r#"{"interface":"wlan0"}"#;
        let k_a1 = retry_ledger.compute_step_idempotency_key(
            ToolIdempotencyPolicy::AlwaysRefresh,
            "step_1",
            "attempt_1",
            "network.status",
            read_args,
            0,
        );
        retry_ledger.record_step_with_meta(
            StepExecutionRecord {
                step_id: "step_1".into(),
                idempotency_key: k_a1,
                capability_id: "network.status".into(),
                canonical_args_json: read_args.into(),
                effect: Effect::Observe,
                mutated_state: false,
                succeeded: false,
                changeset_id: None,
                verification_status: "Failed".into(),
                cached_output: json!({ "error": "transient dbus timeout" }),
            },
            StepExecutionMeta {
                step_id: "step_1".into(),
                call_id: "c1".into(),
                attempt_id: "attempt_1".into(),
                policy: ToolIdempotencyPolicy::AlwaysRefresh,
                pre_state_epoch: 0,
                post_state_epoch: 0,
                is_error: true,
                was_denied: false,
                verification_status: "Failed".into(),
            },
        );
        // Same (step_1, attempt_1) -> CachedHit with is_error = true
        assert!(matches!(
            retry_ledger.evaluate_idempotency(
                ToolIdempotencyPolicy::AlwaysRefresh,
                Some("step_1"),
                "attempt_1",
                "network.status",
                read_args
            ),
            IdempotencyDecision::CachedHit { record, .. } if record.is_error()
        ));
        // 1st retry (step_1, attempt_2) on transient read error -> Proceed!
        assert!(matches!(
            retry_ledger.evaluate_idempotency(
                ToolIdempotencyPolicy::AlwaysRefresh,
                Some("step_1"),
                "attempt_2",
                "network.status",
                read_args
            ),
            IdempotencyDecision::Proceed
        ));
        // Record 2nd failure on attempt_2 -> attempt_3 must now be blocked!
        let k_a2 = retry_ledger.compute_step_idempotency_key(
            ToolIdempotencyPolicy::AlwaysRefresh,
            "step_1",
            "attempt_2",
            "network.status",
            read_args,
            0,
        );
        retry_ledger.record_step_with_meta(
            StepExecutionRecord {
                step_id: "step_1".into(),
                idempotency_key: k_a2,
                capability_id: "network.status".into(),
                canonical_args_json: read_args.into(),
                effect: Effect::Observe,
                mutated_state: false,
                succeeded: false,
                changeset_id: None,
                verification_status: "Failed".into(),
                cached_output: json!({ "error": "transient dbus timeout 2" }),
            },
            StepExecutionMeta {
                step_id: "step_1".into(),
                call_id: "c1_r1".into(),
                attempt_id: "attempt_2".into(),
                policy: ToolIdempotencyPolicy::AlwaysRefresh,
                pre_state_epoch: 0,
                post_state_epoch: 0,
                is_error: true,
                was_denied: false,
                verification_status: "Failed".into(),
            },
        );
        assert!(matches!(
            retry_ledger.evaluate_idempotency(
                ToolIdempotencyPolicy::AlwaysRefresh,
                Some("step_1"),
                "attempt_3",
                "network.status",
                read_args
            ),
            IdempotencyDecision::CachedHit {
                record,
                reason: "read_retry_exhausted",
                ..
            } if record.is_error()
        ));
    }

    #[test]
    fn h02_json_key_order_and_path_normalization_invariance() {
        let ledger = TurnEffectLedger::new("turn_h02_canon");
        let a = json!({
            "b": 1,
            "nested": { "z": true, "a": [1, 2] },
            "path": "/tmp/ws/./sub/../notes//report.md/",
            "step_id": "untrusted_model_spoof_1"
        });
        let b = json!({
            "path": "/tmp/ws/notes/report.md",
            "nested": { "a": [1, 2], "z": true },
            "b": 1,
            "_step_id": "untrusted_model_spoof_2"
        });

        let ca = canonicalize_json_for_dedup(&a);
        let cb = canonicalize_json_for_dedup(&b);
        assert_eq!(ca, cb);
        assert!(!ca.contains("untrusted_model_spoof"));

        let ka = ledger.compute_idempotency_key("file.write", &a.to_string());
        let kb = ledger.compute_idempotency_key("file.write", &b.to_string());
        assert_eq!(ka, kb);

        // URLs must NOT have `https://` mangled by path normalization
        let url_args = json!({ "target": "https://example.com/a//b" });
        assert!(canonicalize_json_for_dedup(&url_args).contains("https://example.com/a//b"));
    }
}
