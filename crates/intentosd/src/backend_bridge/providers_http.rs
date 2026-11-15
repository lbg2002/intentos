#![forbid(unsafe_code)]

//! Managed HTTP Tool-Calling Providers (`providers_http.rs`):
//! - OpenAI-compatible (`/v1/chat/completions` & `ModelGateway` lease proxy)
//! - Anthropic Messages API (`/v1/messages`, including ZCode `builtin:bigmodel` / Claude)
//! - Seamless checkpoint continuation (`continue_resumed_openai_turn` & `continue_resumed_anthropic_turn`)
//! - Unified `allow_broker_tools` ("Chat-Only Mode") enforcement across OpenAI & Anthropic HTTP:
//!   when `allow_broker_tools == false`, tool schemas are omitted completely, `execution_mode` is
//!   `BackendExecutionMode::ExternalChatOnly`, and any forced upstream `tool_calls` / `tool_use`
//!   blocks are hard-rejected without ever invoking `CapabilityBroker`.

use crate::backend_bridge::broker_bridge::{
    BackendExecutionMode, QuickChatToolExecOutcome, TraceDot, TurnExecutionOutcome,
    build_budget_exhausted_turn_outcome, build_quick_chat_anthropic_tools,
    build_quick_chat_openai_tools_with_policy, execute_quick_chat_tool_call,
    finalize_completed_turn_outcome, prepare_system_prompt_and_context_with_policy,
    prepare_turn_context_blocks, synthesize_rich_approved_step_markdown,
};
use crate::backend_bridge::detector::{
    ActiveBackendSelection, BackendsCatalog, DiscoveryOptions, discover_backends_catalog_fast,
    is_anthropic_endpoint, lookup_ephemeral_backend_key,
};
use crate::backend_bridge::turn_checkpoint::{
    ActiveTurnHandle, SuspendedDialectState, SuspendedTurnCheckpoint, TurnBudgetTracker,
    TurnEffectLedger, emit_turn_event, save_suspended_checkpoint,
};
use crate::backend_bridge::turn_engine::extract_thinking_and_clean_reply;
use crate::config::{EgressVerdict, check_egress_matrix};
use crate::core::IntentOsCore;
use crate::runtime::SessionState;
use intentos_protocol::{AgentEventKind, ContextBlock, DataClass, ProviderTrust};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HTTP_CHAT_ONLY_PROMPT_NOTE: &str = "\n\n[chat_only_policy | taint=System]\n\
当前会话启用了仅对话模式（allow_broker_tools=false）：严禁调用任何系统工具或执行系统变更，请仅以纯文本自然语言回答。";

pub enum UpstreamTransport {
    GatewayLease {
        run_token: String,
    },
    DirectHttp {
        base_url: String,
        api_key: Option<String>,
        trust: ProviderTrust,
    },
    AnthropicHttp {
        base_url: String,
        api_key: Option<String>,
        trust: ProviderTrust,
    },
}

pub fn resolve_upstream_transport(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
    catalog: &BackendsCatalog,
    active: &ActiveBackendSelection,
    task_id: &str,
    extra_blocks: &[ContextBlock],
    incognito: bool,
) -> Option<UpstreamTransport> {
    let (_, _, data_class) = prepare_turn_context_blocks(core, extra_blocks, incognito);

    // Prefer `ModelGateway` when `openai` backend uses the configured `main` provider & gateway is ready
    if active.backend == "openai"
        && opts.allow_env_keys
        && let Ok((prof, _)) = core.gateway.resolve_profile("main")
        && prof.provider == active.provider
        && core.gateway.has_usable_credentials()
    {
        let token = core.gateway.issue_run_lease(task_id, "main", data_class);
        return Some(UpstreamTransport::GatewayLease { run_token: token });
    }

    let disc_prov = catalog
        .backends
        .get(&active.backend)
        .and_then(|b| b.providers.iter().find(|p| p.id == active.provider));

    let base_url = active
        .base_url
        .clone()
        .or_else(|| disc_prov.and_then(|p| p.base_url.clone()))?;

    let kind = disc_prov
        .map(|p| p.kind.as_str())
        .unwrap_or("openai-compatible");

    let api_key = lookup_ephemeral_backend_key(
        &core.paths,
        &active.backend,
        &active.provider,
        opts.allow_env_keys,
    );
    let is_local = base_url.contains("127.0.0.1") || base_url.contains("localhost");
    if api_key.is_none() && !is_local {
        return None;
    }
    if let Some(dp) = disc_prov
        && !dp.has_api_key
        && api_key.is_none()
    {
        return None;
    }

    let trust = if is_local {
        ProviderTrust::Trusted
    } else {
        ProviderTrust::Standard
    };

    if is_anthropic_endpoint(kind, Some(&base_url)) {
        return Some(UpstreamTransport::AnthropicHttp {
            base_url,
            api_key,
            trust,
        });
    }

    Some(UpstreamTransport::DirectHttp {
        base_url,
        api_key,
        trust,
    })
}

fn format_chat_only_tool_rejection(
    cleaned_content: &str,
    blocked_names: &[String],
    effect_ledger: &mut TurnEffectLedger,
) -> String {
    if blocked_names.is_empty() {
        effect_ledger
            .chat_only_blocked_tools
            .push("unknown_tool".to_string());
    } else {
        for name in blocked_names {
            if !effect_ledger.chat_only_blocked_tools.contains(name) {
                effect_ledger.chat_only_blocked_tools.push(name.clone());
            }
        }
    }
    let joined = if blocked_names.is_empty() {
        "unknown_tool".to_string()
    } else {
        blocked_names.join(", ")
    };
    let security_note = format!(
        "安全拦截（仅对话模式 allow_broker_tools=false）：已拒绝上游模型未授权的工具调用请求 [{}]，CapabilityBroker 未执行任何系统操作。",
        joined
    );
    effect_ledger.trace_dots.push(TraceDot::tool_err(
        "chat_only_policy",
        security_note.clone(),
        0,
    ));

    if cleaned_content.trim().is_empty() {
        format!("> {}\n", security_note)
    } else {
        format!("{}\n\n> {}", cleaned_content.trim(), security_note)
    }
}

fn record_openai_response_usage(
    resp: &Value,
    effect_ledger: &mut TurnEffectLedger,
) -> Option<String> {
    let usage = resp.get("usage")?;
    let input_tokens = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output_tokens = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cost_usd = usage
        .get("cost_usd")
        .or_else(|| usage.get("total_cost_usd"))
        .or_else(|| usage.get("cost"))
        .and_then(|v| v.as_f64());
    effect_ledger
        .budget_tracker
        .record_token_usage(input_tokens, output_tokens, cost_usd)
}

fn record_anthropic_response_usage(
    resp: &Value,
    effect_ledger: &mut TurnEffectLedger,
) -> Option<String> {
    let usage = resp.get("usage")?;
    let input_tokens = usage
        .get("input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cost_usd = usage
        .get("cost_usd")
        .or_else(|| usage.get("total_cost_usd"))
        .or_else(|| usage.get("cost"))
        .and_then(|v| v.as_f64());
    effect_ledger
        .budget_tracker
        .record_token_usage(input_tokens, output_tokens, cost_usd)
}

fn parse_remaining_openai_tool_calls(tool_calls: &[Value]) -> Vec<(String, String, Value)> {
    tool_calls
        .iter()
        .filter_map(|rem_tc| {
            let rem_id = rem_tc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("call_sib")
                .to_string();
            let rem_fn = rem_tc.get("function").unwrap_or(&Value::Null);
            let rem_name = rem_fn
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if rem_name.is_empty() {
                return None;
            }
            let rem_raw = rem_fn
                .get("arguments")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            let rem_args: Value = serde_json::from_str(rem_raw).unwrap_or_else(|_| json!({}));
            Some((rem_id, rem_name, rem_args))
        })
        .collect()
}

fn parse_anthropic_content_blocks(
    content_blocks: &[Value],
) -> (Option<String>, String, Vec<(String, String, Value)>) {
    let mut step_thinking_parts: Vec<String> = Vec::new();
    let mut step_text_parts: Vec<String> = Vec::new();
    let mut tool_uses: Vec<(String, String, Value)> = Vec::new();

    for block in content_blocks {
        match block.get("type").and_then(|v| v.as_str()).unwrap_or("") {
            "thinking" => {
                if let Some(th) = block
                    .get("thinking")
                    .or_else(|| block.get("text"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    step_thinking_parts.push(th.to_string());
                }
            }
            "text" => {
                if let Some(tx) = block.get("text").and_then(|v| v.as_str()) {
                    step_text_parts.push(tx.to_string());
                }
            }
            "tool_use" => {
                let id = block
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("toolu_0")
                    .to_string();
                let name = block
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let input = block.get("input").cloned().unwrap_or_else(|| json!({}));
                if !name.is_empty() {
                    tool_uses.push((id, name, input));
                }
            }
            _ => {}
        }
    }

    let joined_thinking = if step_thinking_parts.is_empty() {
        None
    } else {
        Some(step_thinking_parts.join("\n\n"))
    };
    let raw_text = step_text_parts.join("\n");
    let (step_thought, cleaned_content) =
        extract_thinking_and_clean_reply(&raw_text, joined_thinking.as_deref());
    (step_thought, cleaned_content, tool_uses)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_openai_tool_calling_turn(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
    transport: UpstreamTransport,
    active: &ActiveBackendSelection,
    turn_handle: &Arc<ActiveTurnHandle>,
    task_id: &str,
    session: &SessionState,
    user_text: &str,
    extra_blocks: &[ContextBlock],
    compressed_history: &crate::memory_hub::CompressedSessionHistory,
    memory_hits: &[Value],
    memory_dot: Option<&TraceDot>,
    incognito: bool,
    effect_ledger: &mut TurnEffectLedger,
) -> anyhow::Result<TurnExecutionOutcome> {
    run_openai_tool_calling_turn_with_policy(
        core,
        opts,
        transport,
        active,
        turn_handle,
        task_id,
        session,
        user_text,
        extra_blocks,
        compressed_history,
        memory_hits,
        memory_dot,
        incognito,
        true,
        effect_ledger,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_openai_tool_calling_turn_with_policy(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
    transport: UpstreamTransport,
    active: &ActiveBackendSelection,
    turn_handle: &Arc<ActiveTurnHandle>,
    task_id: &str,
    session: &SessionState,
    user_text: &str,
    extra_blocks: &[ContextBlock],
    compressed_history: &crate::memory_hub::CompressedSessionHistory,
    memory_hits: &[Value],
    memory_dot: Option<&TraceDot>,
    incognito: bool,
    allow_broker_tools: bool,
    effect_ledger: &mut TurnEffectLedger,
) -> anyhow::Result<TurnExecutionOutcome> {
    let execution_mode = if allow_broker_tools {
        BackendExecutionMode::ManagedBrokerTools
    } else {
        BackendExecutionMode::ExternalChatOnly
    };

    let effective_privacy = if incognito {
        crate::security_guard::PrivacySessionPolicy::StrictIsolated
    } else {
        effect_ledger.privacy()
    };
    let (mut sys_text, taints, data_class) = prepare_system_prompt_and_context_with_policy(
        core,
        active,
        extra_blocks,
        effective_privacy,
    );
    if !allow_broker_tools {
        sys_text.push_str(HTTP_CHAT_ONLY_PROMPT_NOTE);
    }
    if let Some(ref anchor) = compressed_history.ancient_summary_anchor
        && !anchor.trim().is_empty()
    {
        sys_text.push_str("\n\n[session_ancient_context | taint=Memory]\n");
        sys_text.push_str(anchor);
    }

    let mut messages = vec![json!({ "role": "system", "content": sys_text.clone() })];
    for (q, a) in &compressed_history.turns {
        if !q.trim().is_empty() {
            messages.push(json!({ "role": "user", "content": q }));
        }
        if !a.trim().is_empty() {
            messages.push(json!({ "role": "assistant", "content": a }));
        }
    }
    messages.push(json!({ "role": "user", "content": user_text }));

    let openai_tools = if allow_broker_tools {
        build_quick_chat_openai_tools_with_policy(core, user_text, effective_privacy)
    } else {
        Vec::new()
    };
    effect_ledger.budget_tracker.start_active_execution();

    let result: anyhow::Result<TurnExecutionOutcome> = async {
        loop {
            if turn_handle.is_cancelled() {
                anyhow::bail!("turn_cancelled");
            }

            if let Err(_dim) = effect_ledger.budget_tracker.try_begin_model_round() {
                return Ok(build_budget_exhausted_turn_outcome(
                    core,
                    active,
                    execution_mode,
                    task_id,
                    session,
                    user_text,
                    incognito,
                    taints,
                    data_class,
                    String::new(),
                    effect_ledger,
                ));
            }

            let call_res = call_openai_upstream_streaming(
                core,
                &transport,
                data_class,
                &active.model,
                &active.reasoning_effort,
                &messages,
                &openai_tools,
                Some(&mut effect_ledger.budget_tracker),
                Some(turn_handle.as_ref()),
                Some(task_id),
                &effect_ledger.turn_id,
            )
            .await;
            let (resp, streamed_sse) = match call_res {
                Ok(v) => v,
                Err(err) => {
                    if turn_handle.is_cancelled() {
                        anyhow::bail!("turn_cancelled");
                    }
                    if effect_ledger.budget_tracker.budget_exhausted {
                        return Ok(build_budget_exhausted_turn_outcome(
                            core,
                            active,
                            execution_mode,
                            task_id,
                            session,
                            user_text,
                            incognito,
                            taints,
                            data_class,
                            String::new(),
                            effect_ledger,
                        ));
                    }
                    return Err(err);
                }
            };
            record_openai_response_usage(&resp, effect_ledger);

            let choice = resp
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
                .ok_or_else(|| anyhow::anyhow!("模型返回空的 choices"))?;
            let msg = choice
                .get("message")
                .ok_or_else(|| anyhow::anyhow!("模型响应缺少 message"))?;

            let api_reasoning = msg
                .get("reasoning_content")
                .or_else(|| msg.get("reasoning"))
                .and_then(|v| v.as_str());
            let raw_content = msg.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let (step_thought, cleaned_content) =
                extract_thinking_and_clean_reply(raw_content, api_reasoning);
            if let Some(t) = step_thought {
                effect_ledger.push_thought(t);
            }
            if !streamed_sse
                && !cleaned_content.is_empty()
                && (allow_broker_tools
                    || msg
                        .get("tool_calls")
                        .and_then(|tc| tc.as_array())
                        .is_none_or(|a| a.is_empty()))
            {
                turn_handle.emit_event(AgentEventKind::MessageDelta {
                    delta: cleaned_content.clone(),
                });
            }

            if let Some(tool_calls) = msg
                .get("tool_calls")
                .and_then(|tc| tc.as_array())
                .filter(|a| !a.is_empty())
            {
                if !allow_broker_tools {
                    let blocked_names: Vec<String> = tool_calls
                        .iter()
                        .filter_map(|tc| {
                            tc.pointer("/function/name")
                                .and_then(|v| v.as_str())
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(String::from)
                        })
                        .collect();
                    let rejected_md = format_chat_only_tool_rejection(
                        &cleaned_content,
                        &blocked_names,
                        effect_ledger,
                    );
                    return Ok(finalize_completed_turn_outcome(
                        core,
                        active,
                        BackendExecutionMode::ExternalChatOnly,
                        task_id,
                        session,
                        user_text,
                        incognito,
                        taints,
                        data_class,
                        rejected_md,
                        effect_ledger,
                    ));
                }

                if effect_ledger.budget_tracker.budget_exhausted {
                    let dim = effect_ledger
                        .budget_tracker
                        .exhausted_dimension
                        .clone()
                        .unwrap_or_else(|| "token_or_cost".to_string());
                    for tc in tool_calls {
                        if let Some(n) = tc
                            .pointer("/function/name")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        {
                            effect_ledger.budget_skipped_steps.push(format!(
                                "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                                n, dim
                            ));
                        }
                    }
                    return Ok(build_budget_exhausted_turn_outcome(
                        core,
                        active,
                        execution_mode,
                        task_id,
                        session,
                        user_text,
                        incognito,
                        taints,
                        data_class,
                        cleaned_content,
                        effect_ledger,
                    ));
                }

                messages.push(msg.clone());
                for (tc_idx, tc) in tool_calls.iter().enumerate() {
                    if turn_handle.is_cancelled() {
                        anyhow::bail!("turn_cancelled");
                    }
                    let call_id = tc
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("call_0")
                        .to_string();
                    let fn_obj = tc.get("function").unwrap_or(&Value::Null);
                    let fn_name = fn_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let raw_args = fn_obj
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}");
                    let parsed_args: Value =
                        serde_json::from_str(raw_args).unwrap_or_else(|_| json!({}));

                    match execute_quick_chat_tool_call(
                        core,
                        active,
                        execution_mode,
                        task_id,
                        session,
                        user_text,
                        incognito,
                        &taints,
                        data_class,
                        &call_id,
                        fn_name,
                        &parsed_args,
                        effect_ledger,
                    )
                    .await?
                    {
                        QuickChatToolExecOutcome::PausedForApproval {
                            outcome,
                            canonical_tool,
                        } => {
                            if let Some(ref pa) = outcome.pending_approval {
                                save_suspended_checkpoint(SuspendedTurnCheckpoint {
                                    created_at_instant: Instant::now(),
                                    approval_id: pa.approval_id.clone(),
                                    pending_approval: pa.clone(),
                                    task_id: task_id.to_string(),
                                    session: session.clone(),
                                    user_text: user_text.to_string(),
                                    incognito,
                                    active: active.clone(),
                                    discovery_opts: opts.clone(),
                                    extra_blocks: extra_blocks.to_vec(),
                                    sys_text: sys_text.clone(),
                                    taints: taints.clone(),
                                    data_class,
                                    memory_hits: memory_hits.to_vec(),
                                    memory_dot: memory_dot.cloned(),
                                    context_compression: compressed_history.stats.clone(),
                                    rounds_used: effect_ledger.budget_tracker.used_model_rounds
                                        as usize,
                                    paused_call_id: call_id,
                                    paused_canonical_tool: canonical_tool,
                                    paused_parsed_args: parsed_args,
                                    remaining_tool_calls: parse_remaining_openai_tool_calls(
                                        &tool_calls[tc_idx + 1..],
                                    ),
                                    effect_ledger: effect_ledger.clone(),
                                    dialect: SuspendedDialectState::OpenAi {
                                        messages: messages.clone(),
                                        tools: openai_tools.clone(),
                                    },
                                });
                            }
                            return Ok(*outcome);
                        }
                        QuickChatToolExecOutcome::BudgetExhausted { dimension } => {
                            for rem_tc in &tool_calls[tc_idx..] {
                                if let Some(n) = rem_tc
                                    .pointer("/function/name")
                                    .and_then(|v| v.as_str())
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                {
                                    effect_ledger.budget_skipped_steps.push(format!(
                                        "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                                        n, dimension
                                    ));
                                }
                            }
                            return Ok(build_budget_exhausted_turn_outcome(
                                core,
                                active,
                                execution_mode,
                                task_id,
                                session,
                                user_text,
                                incognito,
                                taints,
                                data_class,
                                cleaned_content,
                                effect_ledger,
                            ));
                        }
                        QuickChatToolExecOutcome::ToolMessage { content, .. } => {
                            messages.push(json!({
                                "role": "tool",
                                "tool_call_id": call_id,
                                "content": content,
                            }));
                        }
                    }
                }
            } else {
                return Ok(finalize_completed_turn_outcome(
                    core,
                    active,
                    execution_mode,
                    task_id,
                    session,
                    user_text,
                    incognito,
                    taints,
                    data_class,
                    cleaned_content,
                    effect_ledger,
                ));
            }
        }
    }
    .await;

    if let UpstreamTransport::GatewayLease { ref run_token } = transport {
        core.gateway.revoke_lease(run_token);
    }

    result
}

/// Execute a full Anthropic Messages API (`POST .../v1/messages`) AIOS Tool-Calling Loop.
#[allow(clippy::too_many_arguments)]
pub async fn run_anthropic_tool_calling_turn(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
    base_url: &str,
    api_key: Option<&str>,
    trust: ProviderTrust,
    active: &ActiveBackendSelection,
    turn_handle: &Arc<ActiveTurnHandle>,
    task_id: &str,
    session: &SessionState,
    user_text: &str,
    extra_blocks: &[ContextBlock],
    compressed_history: &crate::memory_hub::CompressedSessionHistory,
    memory_hits: &[Value],
    memory_dot: Option<&TraceDot>,
    incognito: bool,
    effect_ledger: &mut TurnEffectLedger,
) -> anyhow::Result<TurnExecutionOutcome> {
    run_anthropic_tool_calling_turn_with_policy(
        core,
        opts,
        base_url,
        api_key,
        trust,
        active,
        turn_handle,
        task_id,
        session,
        user_text,
        extra_blocks,
        compressed_history,
        memory_hits,
        memory_dot,
        incognito,
        true,
        effect_ledger,
    )
    .await
}

/// Execute an Anthropic Messages API turn with explicit `allow_broker_tools` chat-only enforcement.
#[allow(clippy::too_many_arguments)]
pub async fn run_anthropic_tool_calling_turn_with_policy(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
    base_url: &str,
    api_key: Option<&str>,
    trust: ProviderTrust,
    active: &ActiveBackendSelection,
    turn_handle: &Arc<ActiveTurnHandle>,
    task_id: &str,
    session: &SessionState,
    user_text: &str,
    extra_blocks: &[ContextBlock],
    compressed_history: &crate::memory_hub::CompressedSessionHistory,
    memory_hits: &[Value],
    memory_dot: Option<&TraceDot>,
    incognito: bool,
    allow_broker_tools: bool,
    effect_ledger: &mut TurnEffectLedger,
) -> anyhow::Result<TurnExecutionOutcome> {
    let execution_mode = if allow_broker_tools {
        BackendExecutionMode::ManagedBrokerTools
    } else {
        BackendExecutionMode::ExternalChatOnly
    };

    let effective_privacy = if incognito {
        crate::security_guard::PrivacySessionPolicy::StrictIsolated
    } else {
        effect_ledger.privacy()
    };
    let (mut sys_text, taints, data_class) = prepare_system_prompt_and_context_with_policy(
        core,
        active,
        extra_blocks,
        effective_privacy,
    );
    if !allow_broker_tools {
        sys_text.push_str(HTTP_CHAT_ONLY_PROMPT_NOTE);
    }
    if let Some(ref anchor) = compressed_history.ancient_summary_anchor
        && !anchor.trim().is_empty()
    {
        sys_text.push_str("\n\n[session_ancient_context | taint=Memory]\n");
        sys_text.push_str(anchor);
    }

    let mut anthropic_messages: Vec<Value> = Vec::new();
    let push_alternating = |msgs: &mut Vec<Value>, role: &str, text_val: &str| {
        if text_val.trim().is_empty() {
            return;
        }
        let norm_role = if role == "assistant" {
            "assistant"
        } else {
            "user"
        };
        if let Some(last) = msgs.last_mut()
            && last.get("role").and_then(|v| v.as_str()) == Some(norm_role)
            && let Some(prev_str) = last
                .get("content")
                .and_then(|v| v.as_str())
                .map(String::from)
        {
            last["content"] = json!(format!("{}\n\n{}", prev_str, text_val));
            return;
        }
        msgs.push(json!({
            "role": norm_role,
            "content": text_val,
        }));
    };

    for (q, a) in &compressed_history.turns {
        push_alternating(&mut anthropic_messages, "user", q);
        push_alternating(&mut anthropic_messages, "assistant", a);
    }
    push_alternating(&mut anthropic_messages, "user", user_text);

    let anthropic_tools = if allow_broker_tools {
        let openai_tools =
            build_quick_chat_openai_tools_with_policy(core, user_text, effective_privacy);
        build_quick_chat_anthropic_tools(&openai_tools)
    } else {
        Vec::new()
    };
    effect_ledger.budget_tracker.start_active_execution();

    loop {
        if turn_handle.is_cancelled() {
            anyhow::bail!("turn_cancelled");
        }

        if let Err(_dim) = effect_ledger.budget_tracker.try_begin_model_round() {
            return Ok(build_budget_exhausted_turn_outcome(
                core,
                active,
                execution_mode,
                task_id,
                session,
                user_text,
                incognito,
                taints,
                data_class,
                String::new(),
                effect_ledger,
            ));
        }

        let (resp, streamed_sse) = call_anthropic_upstream_streaming(
            base_url,
            api_key,
            trust,
            data_class,
            &active.model,
            &sys_text,
            &anthropic_messages,
            &anthropic_tools,
            Some(&mut effect_ledger.budget_tracker),
            Some(turn_handle.as_ref()),
            Some(task_id),
            &effect_ledger.turn_id,
        )
        .await?;
        record_anthropic_response_usage(&resp, effect_ledger);

        let content_blocks = resp
            .get("content")
            .and_then(|c| c.as_array())
            .ok_or_else(|| anyhow::anyhow!("Anthropic 模型响应缺少 content 数组"))?;

        let (step_thought, cleaned_content, tool_uses) =
            parse_anthropic_content_blocks(content_blocks);
        if let Some(t) = step_thought {
            effect_ledger.push_thought(t);
        }
        if !streamed_sse
            && !cleaned_content.is_empty()
            && (allow_broker_tools || tool_uses.is_empty())
        {
            turn_handle.emit_event(AgentEventKind::MessageDelta {
                delta: cleaned_content.clone(),
            });
        }

        if !tool_uses.is_empty() {
            if !allow_broker_tools {
                let blocked_names: Vec<String> =
                    tool_uses.iter().map(|(_, n, _)| n.clone()).collect();
                let rejected_md = format_chat_only_tool_rejection(
                    &cleaned_content,
                    &blocked_names,
                    effect_ledger,
                );
                return Ok(finalize_completed_turn_outcome(
                    core,
                    active,
                    BackendExecutionMode::ExternalChatOnly,
                    task_id,
                    session,
                    user_text,
                    incognito,
                    taints,
                    data_class,
                    rejected_md,
                    effect_ledger,
                ));
            }

            if effect_ledger.budget_tracker.budget_exhausted {
                let dim = effect_ledger
                    .budget_tracker
                    .exhausted_dimension
                    .clone()
                    .unwrap_or_else(|| "token_or_cost".to_string());
                for (_, n, _) in &tool_uses {
                    effect_ledger.budget_skipped_steps.push(format!(
                        "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                        n, dim
                    ));
                }
                return Ok(build_budget_exhausted_turn_outcome(
                    core,
                    active,
                    execution_mode,
                    task_id,
                    session,
                    user_text,
                    incognito,
                    taints,
                    data_class,
                    cleaned_content,
                    effect_ledger,
                ));
            }

            anthropic_messages.push(json!({
                "role": "assistant",
                "content": content_blocks,
            }));

            let mut tool_result_blocks: Vec<Value> = Vec::new();
            for (tu_idx, (call_id, fn_name, input_args)) in tool_uses.iter().enumerate() {
                if turn_handle.is_cancelled() {
                    anyhow::bail!("turn_cancelled");
                }
                match execute_quick_chat_tool_call(
                    core,
                    active,
                    execution_mode,
                    task_id,
                    session,
                    user_text,
                    incognito,
                    &taints,
                    data_class,
                    call_id,
                    fn_name,
                    input_args,
                    effect_ledger,
                )
                .await?
                {
                    QuickChatToolExecOutcome::PausedForApproval {
                        outcome,
                        canonical_tool,
                    } => {
                        if let Some(ref pa) = outcome.pending_approval {
                            save_suspended_checkpoint(SuspendedTurnCheckpoint {
                                created_at_instant: Instant::now(),
                                approval_id: pa.approval_id.clone(),
                                pending_approval: pa.clone(),
                                task_id: task_id.to_string(),
                                session: session.clone(),
                                user_text: user_text.to_string(),
                                incognito,
                                active: active.clone(),
                                discovery_opts: opts.clone(),
                                extra_blocks: extra_blocks.to_vec(),
                                sys_text: sys_text.clone(),
                                taints: taints.clone(),
                                data_class,
                                memory_hits: memory_hits.to_vec(),
                                memory_dot: memory_dot.cloned(),
                                context_compression: compressed_history.stats.clone(),
                                rounds_used: effect_ledger.budget_tracker.used_model_rounds
                                    as usize,
                                paused_call_id: call_id.clone(),
                                paused_canonical_tool: canonical_tool,
                                paused_parsed_args: input_args.clone(),
                                remaining_tool_calls: tool_uses[tu_idx + 1..].to_vec(),
                                effect_ledger: effect_ledger.clone(),
                                dialect: SuspendedDialectState::Anthropic {
                                    base_url: base_url.to_string(),
                                    api_key: api_key.map(String::from),
                                    trust,
                                    messages: anthropic_messages.clone(),
                                    prior_tool_results: tool_result_blocks,
                                    tools: anthropic_tools.clone(),
                                },
                            });
                        }
                        return Ok(*outcome);
                    }
                    QuickChatToolExecOutcome::BudgetExhausted { dimension } => {
                        for (_, rem_name, _) in &tool_uses[tu_idx..] {
                            effect_ledger.budget_skipped_steps.push(format!(
                                "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                                rem_name, dimension
                            ));
                        }
                        return Ok(build_budget_exhausted_turn_outcome(
                            core,
                            active,
                            execution_mode,
                            task_id,
                            session,
                            user_text,
                            incognito,
                            taints,
                            data_class,
                            cleaned_content,
                            effect_ledger,
                        ));
                    }
                    QuickChatToolExecOutcome::ToolMessage {
                        content, is_error, ..
                    } => {
                        tool_result_blocks.push(json!({
                            "type": "tool_result",
                            "tool_use_id": call_id,
                            "content": content,
                            "is_error": is_error,
                        }));
                    }
                }
            }

            anthropic_messages.push(json!({
                "role": "user",
                "content": tool_result_blocks,
            }));
        } else {
            return Ok(finalize_completed_turn_outcome(
                core,
                active,
                execution_mode,
                task_id,
                session,
                user_text,
                incognito,
                taints,
                data_class,
                cleaned_content,
                effect_ledger,
            ));
        }
    }
}

pub async fn continue_resumed_openai_turn(
    core: &IntentOsCore,
    cp: &mut SuspendedTurnCheckpoint,
    eff_opts: &DiscoveryOptions,
    mut messages: Vec<Value>,
    openai_tools: Vec<Value>,
    approved_tool_content: String,
) -> anyhow::Result<TurnExecutionOutcome> {
    let allow_broker_tools = !openai_tools.is_empty();
    let execution_mode = if allow_broker_tools {
        BackendExecutionMode::ManagedBrokerTools
    } else {
        BackendExecutionMode::ExternalChatOnly
    };

    messages.push(json!({
        "role": "tool",
        "tool_call_id": cp.paused_call_id,
        "content": approved_tool_content,
    }));

    if allow_broker_tools {
        for (rem_idx, (rem_id, rem_name, rem_args)) in cp.remaining_tool_calls.iter().enumerate() {
            match execute_quick_chat_tool_call(
                core,
                &cp.active,
                execution_mode,
                &cp.task_id,
                &cp.session,
                &cp.user_text,
                cp.incognito,
                &cp.taints,
                cp.data_class,
                rem_id,
                rem_name,
                rem_args,
                &mut cp.effect_ledger,
            )
            .await?
            {
                QuickChatToolExecOutcome::PausedForApproval {
                    outcome,
                    canonical_tool,
                } => {
                    if let Some(ref next_pa) = outcome.pending_approval {
                        save_suspended_checkpoint(SuspendedTurnCheckpoint {
                            created_at_instant: Instant::now(),
                            approval_id: next_pa.approval_id.clone(),
                            pending_approval: next_pa.clone(),
                            task_id: cp.task_id.clone(),
                            session: cp.session.clone(),
                            user_text: cp.user_text.clone(),
                            incognito: cp.incognito,
                            active: cp.active.clone(),
                            discovery_opts: eff_opts.clone(),
                            extra_blocks: cp.extra_blocks.clone(),
                            sys_text: cp.sys_text.clone(),
                            taints: cp.taints.clone(),
                            data_class: cp.data_class,
                            memory_hits: cp.memory_hits.clone(),
                            memory_dot: cp.memory_dot.clone(),
                            context_compression: cp.context_compression.clone(),
                            rounds_used: cp.effect_ledger.budget_tracker.used_model_rounds as usize,
                            paused_call_id: rem_id.clone(),
                            paused_canonical_tool: canonical_tool,
                            paused_parsed_args: rem_args.clone(),
                            remaining_tool_calls: cp.remaining_tool_calls[rem_idx + 1..].to_vec(),
                            effect_ledger: cp.effect_ledger.clone(),
                            dialect: SuspendedDialectState::OpenAi {
                                messages,
                                tools: openai_tools,
                            },
                        });
                    }
                    return Ok(*outcome);
                }
                QuickChatToolExecOutcome::BudgetExhausted { dimension } => {
                    for (_, skipped_name, _) in &cp.remaining_tool_calls[rem_idx..] {
                        cp.effect_ledger.budget_skipped_steps.push(format!(
                            "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                            skipped_name, dimension
                        ));
                    }
                    let partial_md = synthesize_rich_approved_step_markdown(
                        &cp.user_text,
                        &cp.effect_ledger.task_steps,
                    );
                    return Ok(build_budget_exhausted_turn_outcome(
                        core,
                        &cp.active,
                        execution_mode,
                        &cp.task_id,
                        &cp.session,
                        &cp.user_text,
                        cp.incognito,
                        cp.taints.clone(),
                        cp.data_class,
                        partial_md,
                        &mut cp.effect_ledger,
                    ));
                }
                QuickChatToolExecOutcome::ToolMessage { content, .. } => {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": rem_id,
                        "content": content,
                    }));
                }
            }
        }
    }

    let catalog = discover_backends_catalog_fast(core, eff_opts).await;
    let maybe_transport = resolve_upstream_transport(
        core,
        eff_opts,
        &catalog,
        &cp.active,
        &cp.task_id,
        &cp.extra_blocks,
        cp.incognito,
    );

    if let Some(transport) = maybe_transport {
        let mut loop_outcome: Option<TurnExecutionOutcome> = None;
        loop {
            if let Err(_dim) = cp.effect_ledger.budget_tracker.try_begin_model_round() {
                let partial_md = synthesize_rich_approved_step_markdown(
                    &cp.user_text,
                    &cp.effect_ledger.task_steps,
                );
                loop_outcome = Some(build_budget_exhausted_turn_outcome(
                    core,
                    &cp.active,
                    execution_mode,
                    &cp.task_id,
                    &cp.session,
                    &cp.user_text,
                    cp.incognito,
                    cp.taints.clone(),
                    cp.data_class,
                    partial_md,
                    &mut cp.effect_ledger,
                ));
                break;
            }

            let call_res = call_openai_upstream_streaming(
                core,
                &transport,
                cp.data_class,
                &cp.active.model,
                &cp.active.reasoning_effort,
                &messages,
                &openai_tools,
                Some(&mut cp.effect_ledger.budget_tracker),
                None,
                Some(&cp.task_id),
                &cp.effect_ledger.turn_id,
            )
            .await;

            let (resp, streamed_sse) = match call_res {
                Ok(v) => v,
                Err(err) => {
                    if cp.effect_ledger.budget_tracker.budget_exhausted {
                        let partial_md = synthesize_rich_approved_step_markdown(
                            &cp.user_text,
                            &cp.effect_ledger.task_steps,
                        );
                        loop_outcome = Some(build_budget_exhausted_turn_outcome(
                            core,
                            &cp.active,
                            execution_mode,
                            &cp.task_id,
                            &cp.session,
                            &cp.user_text,
                            cp.incognito,
                            cp.taints.clone(),
                            cp.data_class,
                            partial_md,
                            &mut cp.effect_ledger,
                        ));
                    } else {
                        tracing::warn!(
                            "Resumed OpenAI upstream failed ({}), synthesizing rich fallback reply",
                            err
                        );
                    }
                    break;
                }
            };
            record_openai_response_usage(&resp, &mut cp.effect_ledger);

            let Some(msg) = resp
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
                .and_then(|c| c.get("message"))
            else {
                break;
            };

            let api_reasoning = msg
                .get("reasoning_content")
                .or_else(|| msg.get("reasoning"))
                .and_then(|v| v.as_str());
            let raw_content = msg.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let (step_thought, cleaned_content) =
                extract_thinking_and_clean_reply(raw_content, api_reasoning);
            if let Some(t) = step_thought {
                cp.effect_ledger.push_thought(t);
            }
            if !streamed_sse && !cleaned_content.is_empty() {
                let _ = emit_turn_event(
                    &cp.effect_ledger.turn_id,
                    Some(&cp.task_id),
                    AgentEventKind::MessageDelta {
                        delta: cleaned_content.clone(),
                    },
                );
            }

            if let Some(tool_calls) = msg
                .get("tool_calls")
                .and_then(|tc| tc.as_array())
                .filter(|a| !a.is_empty())
            {
                if !allow_broker_tools {
                    let blocked_names: Vec<String> = tool_calls
                        .iter()
                        .filter_map(|tc| {
                            tc.pointer("/function/name")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                        })
                        .collect();
                    let rejected_md = format_chat_only_tool_rejection(
                        &cleaned_content,
                        &blocked_names,
                        &mut cp.effect_ledger,
                    );
                    loop_outcome = Some(finalize_completed_turn_outcome(
                        core,
                        &cp.active,
                        BackendExecutionMode::ExternalChatOnly,
                        &cp.task_id,
                        &cp.session,
                        &cp.user_text,
                        cp.incognito,
                        cp.taints.clone(),
                        cp.data_class,
                        rejected_md,
                        &mut cp.effect_ledger,
                    ));
                    break;
                }

                if cp.effect_ledger.budget_tracker.budget_exhausted {
                    let dim = cp
                        .effect_ledger
                        .budget_tracker
                        .exhausted_dimension
                        .clone()
                        .unwrap_or_else(|| "token_or_cost".to_string());
                    for tc in tool_calls {
                        if let Some(n) = tc
                            .pointer("/function/name")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        {
                            cp.effect_ledger.budget_skipped_steps.push(format!(
                                "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                                n, dim
                            ));
                        }
                    }
                    let partial_md = if cleaned_content.trim().is_empty() {
                        synthesize_rich_approved_step_markdown(
                            &cp.user_text,
                            &cp.effect_ledger.task_steps,
                        )
                    } else {
                        cleaned_content
                    };
                    loop_outcome = Some(build_budget_exhausted_turn_outcome(
                        core,
                        &cp.active,
                        execution_mode,
                        &cp.task_id,
                        &cp.session,
                        &cp.user_text,
                        cp.incognito,
                        cp.taints.clone(),
                        cp.data_class,
                        partial_md,
                        &mut cp.effect_ledger,
                    ));
                    break;
                }

                messages.push(msg.clone());
                let mut inner_paused = false;
                for (tc_idx, tc) in tool_calls.iter().enumerate() {
                    let call_id = tc
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("call_0")
                        .to_string();
                    let fn_obj = tc.get("function").unwrap_or(&Value::Null);
                    let fn_name = fn_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let raw_args = fn_obj
                        .get("arguments")
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}");
                    let parsed_args: Value =
                        serde_json::from_str(raw_args).unwrap_or_else(|_| json!({}));

                    match execute_quick_chat_tool_call(
                        core,
                        &cp.active,
                        execution_mode,
                        &cp.task_id,
                        &cp.session,
                        &cp.user_text,
                        cp.incognito,
                        &cp.taints,
                        cp.data_class,
                        &call_id,
                        fn_name,
                        &parsed_args,
                        &mut cp.effect_ledger,
                    )
                    .await?
                    {
                        QuickChatToolExecOutcome::PausedForApproval {
                            outcome,
                            canonical_tool,
                        } => {
                            if let Some(ref next_pa) = outcome.pending_approval {
                                save_suspended_checkpoint(SuspendedTurnCheckpoint {
                                    created_at_instant: Instant::now(),
                                    approval_id: next_pa.approval_id.clone(),
                                    pending_approval: next_pa.clone(),
                                    task_id: cp.task_id.clone(),
                                    session: cp.session.clone(),
                                    user_text: cp.user_text.clone(),
                                    incognito: cp.incognito,
                                    active: cp.active.clone(),
                                    discovery_opts: eff_opts.clone(),
                                    extra_blocks: cp.extra_blocks.clone(),
                                    sys_text: cp.sys_text.clone(),
                                    taints: cp.taints.clone(),
                                    data_class: cp.data_class,
                                    memory_hits: cp.memory_hits.clone(),
                                    memory_dot: cp.memory_dot.clone(),
                                    context_compression: cp.context_compression.clone(),
                                    rounds_used: cp.effect_ledger.budget_tracker.used_model_rounds
                                        as usize,
                                    paused_call_id: call_id,
                                    paused_canonical_tool: canonical_tool,
                                    paused_parsed_args: parsed_args,
                                    remaining_tool_calls: parse_remaining_openai_tool_calls(
                                        &tool_calls[tc_idx + 1..],
                                    ),
                                    effect_ledger: cp.effect_ledger.clone(),
                                    dialect: SuspendedDialectState::OpenAi {
                                        messages: messages.clone(),
                                        tools: openai_tools.clone(),
                                    },
                                });
                            }
                            loop_outcome = Some(*outcome);
                            inner_paused = true;
                            break;
                        }
                        QuickChatToolExecOutcome::BudgetExhausted { dimension } => {
                            for rem_tc in &tool_calls[tc_idx..] {
                                if let Some(n) = rem_tc
                                    .pointer("/function/name")
                                    .and_then(|v| v.as_str())
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                {
                                    cp.effect_ledger.budget_skipped_steps.push(format!(
                                        "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                                        n, dimension
                                    ));
                                }
                            }
                            let partial_md = if cleaned_content.trim().is_empty() {
                                synthesize_rich_approved_step_markdown(
                                    &cp.user_text,
                                    &cp.effect_ledger.task_steps,
                                )
                            } else {
                                cleaned_content.clone()
                            };
                            loop_outcome = Some(build_budget_exhausted_turn_outcome(
                                core,
                                &cp.active,
                                execution_mode,
                                &cp.task_id,
                                &cp.session,
                                &cp.user_text,
                                cp.incognito,
                                cp.taints.clone(),
                                cp.data_class,
                                partial_md,
                                &mut cp.effect_ledger,
                            ));
                            inner_paused = true;
                            break;
                        }
                        QuickChatToolExecOutcome::ToolMessage { content, .. } => {
                            messages.push(json!({
                                "role": "tool",
                                "tool_call_id": call_id,
                                "content": content,
                            }));
                        }
                    }
                }
                if inner_paused {
                    break;
                }
            } else {
                let final_md = if cleaned_content.trim().is_empty() {
                    synthesize_rich_approved_step_markdown(
                        &cp.user_text,
                        &cp.effect_ledger.task_steps,
                    )
                } else {
                    cleaned_content
                };
                loop_outcome = Some(finalize_completed_turn_outcome(
                    core,
                    &cp.active,
                    execution_mode,
                    &cp.task_id,
                    &cp.session,
                    &cp.user_text,
                    cp.incognito,
                    cp.taints.clone(),
                    cp.data_class,
                    final_md,
                    &mut cp.effect_ledger,
                ));
                break;
            }
        }

        if let UpstreamTransport::GatewayLease { ref run_token } = transport {
            core.gateway.revoke_lease(run_token);
        }

        if let Some(done) = loop_outcome {
            return Ok(done);
        }
    }

    let rich_md =
        synthesize_rich_approved_step_markdown(&cp.user_text, &cp.effect_ledger.task_steps);
    Ok(finalize_completed_turn_outcome(
        core,
        &cp.active,
        execution_mode,
        &cp.task_id,
        &cp.session,
        &cp.user_text,
        cp.incognito,
        cp.taints.clone(),
        cp.data_class,
        rich_md,
        &mut cp.effect_ledger,
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn continue_resumed_anthropic_turn(
    core: &IntentOsCore,
    cp: &mut SuspendedTurnCheckpoint,
    eff_opts: &DiscoveryOptions,
    base_url: String,
    api_key: Option<String>,
    trust: ProviderTrust,
    mut messages: Vec<Value>,
    mut prior_tool_results: Vec<Value>,
    anthropic_tools: Vec<Value>,
    approved_tool_content: String,
    approved_is_err: bool,
) -> anyhow::Result<TurnExecutionOutcome> {
    let allow_broker_tools = !anthropic_tools.is_empty();
    let execution_mode = if allow_broker_tools {
        BackendExecutionMode::ManagedBrokerTools
    } else {
        BackendExecutionMode::ExternalChatOnly
    };

    prior_tool_results.push(json!({
        "type": "tool_result",
        "tool_use_id": cp.paused_call_id,
        "content": approved_tool_content,
        "is_error": approved_is_err,
    }));

    if allow_broker_tools {
        for (rem_idx, (rem_id, rem_name, rem_args)) in cp.remaining_tool_calls.iter().enumerate() {
            match execute_quick_chat_tool_call(
                core,
                &cp.active,
                execution_mode,
                &cp.task_id,
                &cp.session,
                &cp.user_text,
                cp.incognito,
                &cp.taints,
                cp.data_class,
                rem_id,
                rem_name,
                rem_args,
                &mut cp.effect_ledger,
            )
            .await?
            {
                QuickChatToolExecOutcome::PausedForApproval {
                    outcome,
                    canonical_tool,
                } => {
                    if let Some(ref next_pa) = outcome.pending_approval {
                        save_suspended_checkpoint(SuspendedTurnCheckpoint {
                            created_at_instant: Instant::now(),
                            approval_id: next_pa.approval_id.clone(),
                            pending_approval: next_pa.clone(),
                            task_id: cp.task_id.clone(),
                            session: cp.session.clone(),
                            user_text: cp.user_text.clone(),
                            incognito: cp.incognito,
                            active: cp.active.clone(),
                            discovery_opts: eff_opts.clone(),
                            extra_blocks: cp.extra_blocks.clone(),
                            sys_text: cp.sys_text.clone(),
                            taints: cp.taints.clone(),
                            data_class: cp.data_class,
                            memory_hits: cp.memory_hits.clone(),
                            memory_dot: cp.memory_dot.clone(),
                            context_compression: cp.context_compression.clone(),
                            rounds_used: cp.effect_ledger.budget_tracker.used_model_rounds as usize,
                            paused_call_id: rem_id.clone(),
                            paused_canonical_tool: canonical_tool,
                            paused_parsed_args: rem_args.clone(),
                            remaining_tool_calls: cp.remaining_tool_calls[rem_idx + 1..].to_vec(),
                            effect_ledger: cp.effect_ledger.clone(),
                            dialect: SuspendedDialectState::Anthropic {
                                base_url,
                                api_key,
                                trust,
                                messages,
                                prior_tool_results,
                                tools: anthropic_tools,
                            },
                        });
                    }
                    return Ok(*outcome);
                }
                QuickChatToolExecOutcome::BudgetExhausted { dimension } => {
                    for (_, skipped_name, _) in &cp.remaining_tool_calls[rem_idx..] {
                        cp.effect_ledger.budget_skipped_steps.push(format!(
                            "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                            skipped_name, dimension
                        ));
                    }
                    let partial_md = synthesize_rich_approved_step_markdown(
                        &cp.user_text,
                        &cp.effect_ledger.task_steps,
                    );
                    return Ok(build_budget_exhausted_turn_outcome(
                        core,
                        &cp.active,
                        execution_mode,
                        &cp.task_id,
                        &cp.session,
                        &cp.user_text,
                        cp.incognito,
                        cp.taints.clone(),
                        cp.data_class,
                        partial_md,
                        &mut cp.effect_ledger,
                    ));
                }
                QuickChatToolExecOutcome::ToolMessage {
                    content, is_error, ..
                } => {
                    prior_tool_results.push(json!({
                        "type": "tool_result",
                        "tool_use_id": rem_id,
                        "content": content,
                        "is_error": is_error,
                    }));
                }
            }
        }
    }

    messages.push(json!({
        "role": "user",
        "content": prior_tool_results,
    }));

    loop {
        if let Err(_dim) = cp.effect_ledger.budget_tracker.try_begin_model_round() {
            let partial_md =
                synthesize_rich_approved_step_markdown(&cp.user_text, &cp.effect_ledger.task_steps);
            return Ok(build_budget_exhausted_turn_outcome(
                core,
                &cp.active,
                execution_mode,
                &cp.task_id,
                &cp.session,
                &cp.user_text,
                cp.incognito,
                cp.taints.clone(),
                cp.data_class,
                partial_md,
                &mut cp.effect_ledger,
            ));
        }

        let call_res = call_anthropic_upstream_streaming(
            &base_url,
            api_key.as_deref(),
            trust,
            cp.data_class,
            &cp.active.model,
            &cp.sys_text,
            &messages,
            &anthropic_tools,
            Some(&mut cp.effect_ledger.budget_tracker),
            None,
            Some(&cp.task_id),
            &cp.effect_ledger.turn_id,
        )
        .await;

        let (resp, streamed_sse) = match call_res {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "Resumed Anthropic upstream failed ({}), synthesizing rich fallback reply",
                    err
                );
                break;
            }
        };
        record_anthropic_response_usage(&resp, &mut cp.effect_ledger);

        let Some(content_blocks) = resp.get("content").and_then(|c| c.as_array()) else {
            break;
        };

        let (step_thought, cleaned_content, tool_uses) =
            parse_anthropic_content_blocks(content_blocks);
        if let Some(t) = step_thought {
            cp.effect_ledger.push_thought(t);
        }
        if !streamed_sse && !cleaned_content.is_empty() {
            let _ = emit_turn_event(
                &cp.effect_ledger.turn_id,
                Some(&cp.task_id),
                AgentEventKind::MessageDelta {
                    delta: cleaned_content.clone(),
                },
            );
        }

        if !tool_uses.is_empty() {
            if !allow_broker_tools {
                let blocked_names: Vec<String> =
                    tool_uses.iter().map(|(_, n, _)| n.clone()).collect();
                let rejected_md = format_chat_only_tool_rejection(
                    &cleaned_content,
                    &blocked_names,
                    &mut cp.effect_ledger,
                );
                return Ok(finalize_completed_turn_outcome(
                    core,
                    &cp.active,
                    BackendExecutionMode::ExternalChatOnly,
                    &cp.task_id,
                    &cp.session,
                    &cp.user_text,
                    cp.incognito,
                    cp.taints.clone(),
                    cp.data_class,
                    rejected_md,
                    &mut cp.effect_ledger,
                ));
            }

            if cp.effect_ledger.budget_tracker.budget_exhausted {
                let dim = cp
                    .effect_ledger
                    .budget_tracker
                    .exhausted_dimension
                    .clone()
                    .unwrap_or_else(|| "token_or_cost".to_string());
                for (_, n, _) in &tool_uses {
                    cp.effect_ledger.budget_skipped_steps.push(format!(
                        "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                        n, dim
                    ));
                }
                let partial_md = if cleaned_content.trim().is_empty() {
                    synthesize_rich_approved_step_markdown(
                        &cp.user_text,
                        &cp.effect_ledger.task_steps,
                    )
                } else {
                    cleaned_content
                };
                return Ok(build_budget_exhausted_turn_outcome(
                    core,
                    &cp.active,
                    execution_mode,
                    &cp.task_id,
                    &cp.session,
                    &cp.user_text,
                    cp.incognito,
                    cp.taints.clone(),
                    cp.data_class,
                    partial_md,
                    &mut cp.effect_ledger,
                ));
            }

            messages.push(json!({
                "role": "assistant",
                "content": content_blocks,
            }));
            let mut next_results: Vec<Value> = Vec::new();
            for (tu_idx, (cid, fname, iargs)) in tool_uses.iter().enumerate() {
                match execute_quick_chat_tool_call(
                    core,
                    &cp.active,
                    execution_mode,
                    &cp.task_id,
                    &cp.session,
                    &cp.user_text,
                    cp.incognito,
                    &cp.taints,
                    cp.data_class,
                    cid,
                    fname,
                    iargs,
                    &mut cp.effect_ledger,
                )
                .await?
                {
                    QuickChatToolExecOutcome::PausedForApproval {
                        outcome,
                        canonical_tool,
                    } => {
                        if let Some(ref next_pa) = outcome.pending_approval {
                            save_suspended_checkpoint(SuspendedTurnCheckpoint {
                                created_at_instant: Instant::now(),
                                approval_id: next_pa.approval_id.clone(),
                                pending_approval: next_pa.clone(),
                                task_id: cp.task_id.clone(),
                                session: cp.session.clone(),
                                user_text: cp.user_text.clone(),
                                incognito: cp.incognito,
                                active: cp.active.clone(),
                                discovery_opts: eff_opts.clone(),
                                extra_blocks: cp.extra_blocks.clone(),
                                sys_text: cp.sys_text.clone(),
                                taints: cp.taints.clone(),
                                data_class: cp.data_class,
                                memory_hits: cp.memory_hits.clone(),
                                memory_dot: cp.memory_dot.clone(),
                                context_compression: cp.context_compression.clone(),
                                rounds_used: cp.effect_ledger.budget_tracker.used_model_rounds
                                    as usize,
                                paused_call_id: cid.clone(),
                                paused_canonical_tool: canonical_tool,
                                paused_parsed_args: iargs.clone(),
                                remaining_tool_calls: tool_uses[tu_idx + 1..].to_vec(),
                                effect_ledger: cp.effect_ledger.clone(),
                                dialect: SuspendedDialectState::Anthropic {
                                    base_url: base_url.clone(),
                                    api_key: api_key.clone(),
                                    trust,
                                    messages: messages.clone(),
                                    prior_tool_results: next_results.clone(),
                                    tools: anthropic_tools.clone(),
                                },
                            });
                        }
                        return Ok(*outcome);
                    }
                    QuickChatToolExecOutcome::BudgetExhausted { dimension } => {
                        for (_, rem_name, _) in &tool_uses[tu_idx..] {
                            cp.effect_ledger.budget_skipped_steps.push(format!(
                                "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                                rem_name, dimension
                            ));
                        }
                        let partial_md = if cleaned_content.trim().is_empty() {
                            synthesize_rich_approved_step_markdown(
                                &cp.user_text,
                                &cp.effect_ledger.task_steps,
                            )
                        } else {
                            cleaned_content
                        };
                        return Ok(build_budget_exhausted_turn_outcome(
                            core,
                            &cp.active,
                            execution_mode,
                            &cp.task_id,
                            &cp.session,
                            &cp.user_text,
                            cp.incognito,
                            cp.taints.clone(),
                            cp.data_class,
                            partial_md,
                            &mut cp.effect_ledger,
                        ));
                    }
                    QuickChatToolExecOutcome::ToolMessage {
                        content, is_error, ..
                    } => {
                        next_results.push(json!({
                            "type": "tool_result",
                            "tool_use_id": cid,
                            "content": content,
                            "is_error": is_error,
                        }));
                    }
                }
            }
            messages.push(json!({
                "role": "user",
                "content": next_results,
            }));
        } else {
            let final_md = if cleaned_content.trim().is_empty() {
                synthesize_rich_approved_step_markdown(&cp.user_text, &cp.effect_ledger.task_steps)
            } else {
                cleaned_content
            };
            return Ok(finalize_completed_turn_outcome(
                core,
                &cp.active,
                execution_mode,
                &cp.task_id,
                &cp.session,
                &cp.user_text,
                cp.incognito,
                cp.taints.clone(),
                cp.data_class,
                final_md,
                &mut cp.effect_ledger,
            ));
        }
    }

    let rich_md =
        synthesize_rich_approved_step_markdown(&cp.user_text, &cp.effect_ledger.task_steps);
    Ok(finalize_completed_turn_outcome(
        core,
        &cp.active,
        execution_mode,
        &cp.task_id,
        &cp.session,
        &cp.user_text,
        cp.incognito,
        cp.taints.clone(),
        cp.data_class,
        rich_md,
        &mut cp.effect_ledger,
    ))
}

/// Byte-buffered W3C SSE (`text/event-stream`) frame decoder (`H10`).
///
/// Decodes lines strictly at `\n` (`0x0A`) boundaries so multi-byte UTF-8 CJK characters
/// split across TCP packets are never corrupted.
#[derive(Default)]
pub struct SseFrameDecoder {
    raw_buf: Vec<u8>,
    current_event: String,
    current_data: Vec<String>,
}

impl SseFrameDecoder {
    pub fn push_bytes(&mut self, chunk: &[u8]) -> Vec<(String, String)> {
        self.raw_buf.extend_from_slice(chunk);
        let mut frames = Vec::new();
        while let Some(nl_idx) = self.raw_buf.iter().position(|&b| b == b'\n') {
            let mut line_bytes: Vec<u8> = self.raw_buf.drain(..=nl_idx).collect();
            if line_bytes.last() == Some(&b'\n') {
                line_bytes.pop();
            }
            if line_bytes.last() == Some(&b'\r') {
                line_bytes.pop();
            }
            let line = String::from_utf8(line_bytes)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
            self.process_line(&line, &mut frames);
        }
        frames
    }

    pub fn finish(&mut self) -> Vec<(String, String)> {
        let mut frames = Vec::new();
        if !self.raw_buf.is_empty() {
            let mut line_bytes = std::mem::take(&mut self.raw_buf);
            if line_bytes.last() == Some(&b'\r') {
                line_bytes.pop();
            }
            let line = String::from_utf8(line_bytes)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
            self.process_line(&line, &mut frames);
        }
        if !self.current_data.is_empty() {
            let ev = std::mem::take(&mut self.current_event);
            let data = std::mem::take(&mut self.current_data).join("\n");
            frames.push((ev, data));
        }
        frames
    }

    fn process_line(&mut self, line: &str, out: &mut Vec<(String, String)>) {
        if line.is_empty() {
            if !self.current_data.is_empty() {
                let ev = std::mem::take(&mut self.current_event);
                let data = std::mem::take(&mut self.current_data).join("\n");
                out.push((ev, data));
            } else {
                self.current_event.clear();
            }
            return;
        }
        if line.starts_with(':') {
            return;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            self.current_event = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            let val = rest.strip_prefix(' ').unwrap_or(rest);
            self.current_data.push(val.to_string());
        }
    }
}

/// Filters `<think>...</think>` / `<thinking>...</thinking>` blocks and buffers partial secret
/// token prefixes across SSE chunks so `SensitiveDataGuard` scrubs secrets even if split across chunks.
#[derive(Default)]
struct IncrementalMessageDeltaFilter {
    inside_think: bool,
    buf: String,
}

impl IncrementalMessageDeltaFilter {
    fn feed<F: FnMut(&str)>(&mut self, chunk: &str, on_delta: &mut F) {
        if chunk.is_empty() {
            return;
        }
        self.buf.push_str(chunk);
        self.drain_ready(false, on_delta);
    }

    fn flush<F: FnMut(&str)>(&mut self, on_delta: &mut F) {
        self.drain_ready(true, on_delta);
    }

    fn drain_ready<F: FnMut(&str)>(&mut self, eof: bool, on_delta: &mut F) {
        loop {
            if self.buf.is_empty() {
                return;
            }
            if self.inside_think {
                let lower = self.buf.to_ascii_lowercase();
                if let Some((close_idx, tag_len)) = lower
                    .find("</thinking>")
                    .map(|i| (i, 11usize))
                    .or_else(|| lower.find("</think>").map(|i| (i, 8usize)))
                {
                    self.buf.drain(..close_idx + tag_len);
                    self.inside_think = false;
                    continue;
                }
                if eof {
                    self.buf.clear();
                } else if self.buf.len() > 32 {
                    // Keep last 12 ASCII-safe char boundary bytes in case `</thinking>` spans chunks
                    let keep_from = self
                        .buf
                        .char_indices()
                        .rev()
                        .take(12)
                        .last()
                        .map(|(idx, _)| idx)
                        .unwrap_or(0);
                    self.buf.drain(..keep_from);
                }
                return;
            }

            let lower = self.buf.to_ascii_lowercase();
            if let Some(lt_idx) = lower.find('<') {
                let after = &lower[lt_idx..];
                if after.starts_with("<thinking>") {
                    let prefix: String = self.buf.drain(..lt_idx).collect();
                    if !prefix.is_empty() {
                        on_delta(&prefix);
                    }
                    self.buf.drain(..10);
                    self.inside_think = true;
                    continue;
                } else if after.starts_with("<think>") {
                    let prefix: String = self.buf.drain(..lt_idx).collect();
                    if !prefix.is_empty() {
                        on_delta(&prefix);
                    }
                    self.buf.drain(..7);
                    self.inside_think = true;
                    continue;
                } else if !eof && ("<thinking>".starts_with(after) || "<think>".starts_with(after))
                {
                    let prefix: String = self.buf.drain(..lt_idx).collect();
                    if !prefix.is_empty() {
                        on_delta(&prefix);
                    }
                    return;
                }
            }

            if !eof && Self::might_have_trailing_partial_secret(&self.buf) && self.buf.len() < 96 {
                return;
            }

            let out = std::mem::take(&mut self.buf);
            if !out.is_empty() {
                on_delta(&out);
            }
            return;
        }
    }

    fn might_have_trailing_partial_secret(s: &str) -> bool {
        let lower = s.to_ascii_lowercase();
        if lower.contains("-----begin") && !lower.contains("-----end") {
            return true;
        }
        let tail_token = s
            .rsplit(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | ']'))
            .next()
            .unwrap_or("");
        let tail_lower = tail_token.to_ascii_lowercase();
        tail_token.starts_with("sk-")
            || tail_token.starts_with("rk-")
            || tail_token.starts_with("ghp_")
            || tail_token.starts_with("gho_")
            || tail_token.starts_with("ghs_")
            || tail_token.starts_with("xox")
            || tail_lower == "sk"
            || tail_lower == "bearer"
            || lower.ends_with("bearer ")
    }
}

#[derive(Default)]
struct PartialOpenAiToolCall {
    id: String,
    name: String,
    arguments: String,
}

#[derive(Default)]
struct OpenAiSseAccumulator {
    stream_id: Option<String>,
    finish_reason: Option<String>,
    content_buf: String,
    reasoning_buf: String,
    tool_calls: BTreeMap<usize, PartialOpenAiToolCall>,
    usage: Option<Value>,
    saw_done: bool,
    delta_filter: IncrementalMessageDeltaFilter,
}

impl OpenAiSseAccumulator {
    fn feed_frame<F: FnMut(&str)>(&mut self, data: &str, on_delta: &mut F) -> anyhow::Result<bool> {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return Ok(false);
        }
        if trimmed == "[DONE]" {
            self.saw_done = true;
            self.delta_filter.flush(on_delta);
            return Ok(true);
        }

        let val: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if let Some(err_obj) = val.get("error") {
            let msg = err_obj
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or(trimmed);
            anyhow::bail!("OpenAI SSE error: {}", msg);
        }
        if let Some(id) = val.get("id").and_then(|v| v.as_str())
            && !id.is_empty()
        {
            self.stream_id = Some(id.to_string());
        }
        if let Some(u) = val.get("usage").filter(|u| !u.is_null()) {
            self.usage = Some(u.clone());
        }

        if let Some(choice) = val
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
        {
            if let Some(fr) = choice.get("finish_reason").and_then(|v| v.as_str()) {
                self.finish_reason = Some(fr.to_string());
            }
            let delta = choice
                .get("delta")
                .or_else(|| choice.get("message"))
                .unwrap_or(&Value::Null);

            if let Some(rc) = delta
                .get("reasoning_content")
                .or_else(|| delta.get("reasoning"))
                .and_then(|v| v.as_str())
                && !rc.is_empty()
            {
                self.reasoning_buf.push_str(rc);
            }
            if let Some(c) = delta.get("content").and_then(|v| v.as_str())
                && !c.is_empty()
            {
                self.content_buf.push_str(c);
                self.delta_filter.feed(c, on_delta);
            }
            if let Some(tc_arr) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                for (pos, tc) in tc_arr.iter().enumerate() {
                    let idx = tc
                        .get("index")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as usize)
                        .unwrap_or(pos);
                    let entry = self.tool_calls.entry(idx).or_default();
                    if let Some(id) = tc.get("id").and_then(|v| v.as_str())
                        && !id.is_empty()
                    {
                        entry.id = id.to_string();
                    }
                    if let Some(fn_obj) = tc.get("function") {
                        if let Some(n) = fn_obj.get("name").and_then(|v| v.as_str())
                            && !n.is_empty()
                        {
                            if entry.name.is_empty() {
                                entry.name = n.to_string();
                            } else if entry.name != n {
                                entry.name.push_str(n);
                            }
                        }
                        if let Some(a) = fn_obj.get("arguments").and_then(|v| v.as_str()) {
                            entry.arguments.push_str(a);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn into_response_json<F: FnMut(&str)>(mut self, on_delta: &mut F) -> Value {
        self.delta_filter.flush(on_delta);
        let mut msg = json!({
            "role": "assistant",
            "content": self.content_buf,
        });
        if !self.reasoning_buf.is_empty() {
            msg["reasoning_content"] = json!(self.reasoning_buf);
        }
        if !self.tool_calls.is_empty() {
            let tc_vec: Vec<Value> = self
                .tool_calls
                .into_iter()
                .map(|(idx, tc)| {
                    let id = if tc.id.is_empty() {
                        format!("call_sse_{}", idx)
                    } else {
                        tc.id
                    };
                    let args = if tc.arguments.trim().is_empty() {
                        "{}".to_string()
                    } else {
                        tc.arguments
                    };
                    json!({
                        "id": id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": args,
                        }
                    })
                })
                .collect();
            msg["tool_calls"] = Value::Array(tc_vec);
        }

        let mut out = json!({
            "id": self.stream_id.unwrap_or_else(|| "chatcmpl_sse".to_string()),
            "choices": [{
                "index": 0,
                "finish_reason": self.finish_reason.unwrap_or_else(|| "stop".to_string()),
                "message": msg,
            }],
        });
        if let Some(u) = self.usage {
            out["usage"] = u;
        }
        out
    }
}

enum PartialAnthropicBlock {
    Text(String),
    Thinking(String),
    ToolUse {
        id: String,
        name: String,
        initial_input: Value,
        partial_json: String,
    },
}

#[derive(Default)]
struct AnthropicSseAccumulator {
    msg_id: Option<String>,
    stop_reason: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    blocks: BTreeMap<usize, PartialAnthropicBlock>,
    delta_filter: IncrementalMessageDeltaFilter,
}

impl AnthropicSseAccumulator {
    fn feed_frame<F: FnMut(&str)>(
        &mut self,
        event_hint: &str,
        data: &str,
        on_delta: &mut F,
    ) -> anyhow::Result<bool> {
        let trimmed = data.trim();
        if trimmed.is_empty() || trimmed == "[DONE]" {
            if trimmed == "[DONE]" {
                self.delta_filter.flush(on_delta);
                return Ok(true);
            }
            return Ok(false);
        }
        let val: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let ev_type = if !event_hint.is_empty() {
            event_hint
        } else {
            val.get("type").and_then(|v| v.as_str()).unwrap_or("")
        };

        match ev_type {
            "ping" => Ok(false),
            "error" => {
                let msg = val
                    .pointer("/error/message")
                    .or_else(|| val.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(trimmed);
                anyhow::bail!("Anthropic SSE error: {}", msg);
            }
            "message_start" => {
                if let Some(m) = val.get("message") {
                    if let Some(id) = m.get("id").and_then(|v| v.as_str()) {
                        self.msg_id = Some(id.to_string());
                    }
                    if let Some(u) = m.get("usage") {
                        if let Some(it) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                            self.input_tokens = it;
                        }
                        if let Some(ot) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                            self.output_tokens = ot;
                        }
                    }
                }
                Ok(false)
            }
            "content_block_start" => {
                let idx = val.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let cb = val.get("content_block").unwrap_or(&Value::Null);
                match cb.get("type").and_then(|v| v.as_str()).unwrap_or("") {
                    "text" => {
                        let initial = cb.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        if !initial.is_empty() {
                            self.delta_filter.feed(initial, on_delta);
                        }
                        self.blocks
                            .insert(idx, PartialAnthropicBlock::Text(initial.to_string()));
                    }
                    "thinking" => {
                        let initial = cb.get("thinking").and_then(|v| v.as_str()).unwrap_or("");
                        self.blocks
                            .insert(idx, PartialAnthropicBlock::Thinking(initial.to_string()));
                    }
                    "tool_use" => {
                        let id = cb
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("toolu_sse_0")
                            .to_string();
                        let name = cb
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let initial_input = cb.get("input").cloned().unwrap_or_else(|| json!({}));
                        self.blocks.insert(
                            idx,
                            PartialAnthropicBlock::ToolUse {
                                id,
                                name,
                                initial_input,
                                partial_json: String::new(),
                            },
                        );
                    }
                    _ => {}
                }
                Ok(false)
            }
            "content_block_delta" => {
                let idx = val.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let delta = val.get("delta").unwrap_or(&Value::Null);
                let dtype = delta.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match dtype {
                    "text_delta" => {
                        let tx = delta.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        if !tx.is_empty() {
                            if let PartialAnthropicBlock::Text(buf) = self
                                .blocks
                                .entry(idx)
                                .or_insert_with(|| PartialAnthropicBlock::Text(String::new()))
                            {
                                buf.push_str(tx);
                            }
                            self.delta_filter.feed(tx, on_delta);
                        }
                    }
                    "thinking_delta" => {
                        let th = delta
                            .get("thinking")
                            .or_else(|| delta.get("text"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if !th.is_empty()
                            && let PartialAnthropicBlock::Thinking(buf) = self
                                .blocks
                                .entry(idx)
                                .or_insert_with(|| PartialAnthropicBlock::Thinking(String::new()))
                        {
                            buf.push_str(th);
                        }
                    }
                    "input_json_delta" => {
                        let pj = delta
                            .get("partial_json")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if !pj.is_empty()
                            && let Some(PartialAnthropicBlock::ToolUse { partial_json, .. }) =
                                self.blocks.get_mut(&idx)
                        {
                            partial_json.push_str(pj);
                        }
                    }
                    _ => {}
                }
                Ok(false)
            }
            "content_block_stop" => Ok(false),
            "message_delta" => {
                if let Some(sr) = val
                    .pointer("/delta/stop_reason")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    self.stop_reason = Some(sr.to_string());
                }
                if let Some(u) = val.get("usage") {
                    if let Some(it) = u.get("input_tokens").and_then(|v| v.as_u64()) {
                        self.input_tokens = it;
                    }
                    if let Some(ot) = u.get("output_tokens").and_then(|v| v.as_u64()) {
                        self.output_tokens = ot;
                    }
                }
                Ok(false)
            }
            "message_stop" => {
                self.delta_filter.flush(on_delta);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn into_response_json<F: FnMut(&str)>(mut self, on_delta: &mut F) -> Value {
        self.delta_filter.flush(on_delta);
        let content: Vec<Value> = self
            .blocks
            .into_values()
            .map(|b| match b {
                PartialAnthropicBlock::Text(text) => json!({
                    "type": "text",
                    "text": text,
                }),
                PartialAnthropicBlock::Thinking(thinking) => json!({
                    "type": "thinking",
                    "thinking": thinking,
                }),
                PartialAnthropicBlock::ToolUse {
                    id,
                    name,
                    initial_input,
                    partial_json,
                } => {
                    let parsed_input = if partial_json.trim().is_empty() {
                        initial_input
                    } else {
                        serde_json::from_str::<Value>(partial_json.trim()).unwrap_or(initial_input)
                    };
                    json!({
                        "type": "tool_use",
                        "id": id,
                        "name": name,
                        "input": parsed_input,
                    })
                }
            })
            .collect();

        json!({
            "id": self.msg_id.unwrap_or_else(|| "msg_sse".to_string()),
            "type": "message",
            "role": "assistant",
            "stop_reason": self.stop_reason.unwrap_or_else(|| "end_turn".to_string()),
            "content": content,
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            }
        })
    }
}

/// Parse an OpenAI SSE (`text/event-stream`) transcript incrementally (`H10`).
pub fn parse_openai_sse_transcript<F: FnMut(&str)>(
    raw_sse: &str,
    mut on_delta: F,
) -> anyhow::Result<Value> {
    let mut decoder = SseFrameDecoder::default();
    let mut acc = OpenAiSseAccumulator::default();
    for (_ev, data) in decoder.push_bytes(raw_sse.as_bytes()) {
        if acc.feed_frame(&data, &mut on_delta)? {
            return Ok(acc.into_response_json(&mut on_delta));
        }
    }
    for (_ev, data) in decoder.finish() {
        if acc.feed_frame(&data, &mut on_delta)? {
            return Ok(acc.into_response_json(&mut on_delta));
        }
    }
    Ok(acc.into_response_json(&mut on_delta))
}

/// Parse an Anthropic Messages SSE (`text/event-stream`) transcript incrementally (`H10`).
pub fn parse_anthropic_sse_transcript<F: FnMut(&str)>(
    raw_sse: &str,
    mut on_delta: F,
) -> anyhow::Result<Value> {
    let mut decoder = SseFrameDecoder::default();
    let mut acc = AnthropicSseAccumulator::default();
    for (ev, data) in decoder.push_bytes(raw_sse.as_bytes()) {
        if acc.feed_frame(&ev, &data, &mut on_delta)? {
            return Ok(acc.into_response_json(&mut on_delta));
        }
    }
    for (ev, data) in decoder.finish() {
        if acc.feed_frame(&ev, &data, &mut on_delta)? {
            return Ok(acc.into_response_json(&mut on_delta));
        }
    }
    Ok(acc.into_response_json(&mut on_delta))
}

fn response_has_sse_content_type(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
}

fn body_looks_like_sse(text_body: &str) -> bool {
    let t = text_body.trim_start();
    t.starts_with("data:") || t.starts_with("event:")
}

/// Decode an OpenAI HTTP `Response` either incrementally via SSE (`text/event-stream`) or via
/// non-streaming `application/json` fallback (`H10`), returning `(assembled_response, streamed_sse)`.
pub async fn decode_openai_http_or_sse_response<F>(
    mut resp: reqwest::Response,
    turn_handle: Option<&ActiveTurnHandle>,
    on_delta: &mut F,
) -> anyhow::Result<(Value, bool)>
where
    F: FnMut(&str),
{
    if response_has_sse_content_type(&resp) {
        let mut decoder = SseFrameDecoder::default();
        let mut acc = OpenAiSseAccumulator::default();
        loop {
            let next_chunk = if let Some(th) = turn_handle {
                tokio::select! {
                    _ = th.wait_cancelled() => anyhow::bail!("turn_cancelled"),
                    c = resp.chunk() => c?,
                }
            } else {
                resp.chunk().await?
            };
            let Some(bytes) = next_chunk else {
                break;
            };
            for (_ev, data) in decoder.push_bytes(&bytes) {
                if acc.feed_frame(&data, on_delta)? {
                    return Ok((acc.into_response_json(on_delta), true));
                }
            }
        }
        for (_ev, data) in decoder.finish() {
            if acc.feed_frame(&data, on_delta)? {
                return Ok((acc.into_response_json(on_delta), true));
            }
        }
        return Ok((acc.into_response_json(on_delta), true));
    }

    let text_body = if let Some(th) = turn_handle {
        tokio::select! {
            _ = th.wait_cancelled() => anyhow::bail!("turn_cancelled"),
            t = resp.text() => t?,
        }
    } else {
        resp.text().await?
    };

    if body_looks_like_sse(&text_body) {
        let val = parse_openai_sse_transcript(&text_body, |d| on_delta(d))?;
        return Ok((val, true));
    }
    Ok((serde_json::from_str(&text_body)?, false))
}

/// Decode an Anthropic HTTP `Response` either incrementally via SSE (`text/event-stream`) or via
/// non-streaming `application/json` fallback (`H10`), returning `(assembled_response, streamed_sse)`.
pub async fn decode_anthropic_http_or_sse_response<F>(
    mut resp: reqwest::Response,
    turn_handle: Option<&ActiveTurnHandle>,
    on_delta: &mut F,
) -> anyhow::Result<(Value, bool)>
where
    F: FnMut(&str),
{
    if response_has_sse_content_type(&resp) {
        let mut decoder = SseFrameDecoder::default();
        let mut acc = AnthropicSseAccumulator::default();
        loop {
            let next_chunk = if let Some(th) = turn_handle {
                tokio::select! {
                    _ = th.wait_cancelled() => anyhow::bail!("turn_cancelled"),
                    c = resp.chunk() => c?,
                }
            } else {
                resp.chunk().await?
            };
            let Some(bytes) = next_chunk else {
                break;
            };
            for (ev, data) in decoder.push_bytes(&bytes) {
                if acc.feed_frame(&ev, &data, on_delta)? {
                    return Ok((acc.into_response_json(on_delta), true));
                }
            }
        }
        for (ev, data) in decoder.finish() {
            if acc.feed_frame(&ev, &data, on_delta)? {
                return Ok((acc.into_response_json(on_delta), true));
            }
        }
        return Ok((acc.into_response_json(on_delta), true));
    }

    let text_body = if let Some(th) = turn_handle {
        tokio::select! {
            _ = th.wait_cancelled() => anyhow::bail!("turn_cancelled"),
            t = resp.text() => t?,
        }
    } else {
        resp.text().await?
    };

    if body_looks_like_sse(&text_body) {
        let val = parse_anthropic_sse_transcript(&text_body, |d| on_delta(d))?;
        return Ok((val, true));
    }
    Ok((serde_json::from_str(&text_body)?, false))
}

#[allow(clippy::too_many_arguments)]
pub async fn call_anthropic_upstream(
    base_url: &str,
    api_key: Option<&str>,
    trust: ProviderTrust,
    data_class: DataClass,
    model: &str,
    system_prompt: &str,
    messages: &[Value],
    tools: &[Value],
) -> anyhow::Result<Value> {
    let (val, _) = call_anthropic_upstream_streaming(
        base_url,
        api_key,
        trust,
        data_class,
        model,
        system_prompt,
        messages,
        tools,
        None,
        None,
        None,
        "",
    )
    .await?;
    Ok(val)
}

#[allow(clippy::too_many_arguments)]
pub async fn call_anthropic_upstream_streaming(
    base_url: &str,
    api_key: Option<&str>,
    trust: ProviderTrust,
    data_class: DataClass,
    model: &str,
    system_prompt: &str,
    messages: &[Value],
    tools: &[Value],
    mut budget_tracker: Option<&mut TurnBudgetTracker>,
    turn_handle: Option<&ActiveTurnHandle>,
    task_id: Option<&str>,
    turn_id: &str,
) -> anyhow::Result<(Value, bool)> {
    let verdict = check_egress_matrix(data_class, trust);
    if verdict == EgressVerdict::Deny {
        anyhow::bail!(
            "外发矩阵阻断：数据分级 {:?} 不允许发往 {:?} 后端",
            data_class,
            trust
        );
    }

    let build_body = |stream_flag: bool| -> Value {
        let mut body = json!({
            "model": model,
            "max_tokens": 4096,
            "messages": messages,
        });
        if stream_flag {
            body["stream"] = json!(true);
        }
        if !system_prompt.trim().is_empty() {
            body["system"] = json!(system_prompt);
        }
        if !tools.is_empty() {
            body["tools"] = json!(tools);
        }
        body
    };

    let primary_body = build_body(true);
    let raw_check = primary_body.to_string();
    if raw_check.contains("BEGIN OPENSSH PRIVATE KEY")
        || raw_check.contains("BEGIN RSA PRIVATE KEY")
    {
        anyhow::bail!("安全拦截：检测到疑似私钥内容，禁止外发");
    }

    let clean_base = base_url.trim_end_matches('/');
    let endpoints = if clean_base.ends_with("/messages") {
        vec![clean_base.to_string()]
    } else if clean_base.ends_with("/v1") {
        vec![format!("{}/messages", clean_base)]
    } else {
        vec![
            format!("{}/v1/messages", clean_base),
            format!("{}/messages", clean_base),
        ]
    };

    let is_local =
        clean_base.starts_with("http://127.0.0.1") || clean_base.starts_with("http://localhost");
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(90));
    if is_local {
        builder = builder.no_proxy();
    }
    let client = builder.build()?;

    let mut emit_delta = |delta_chunk: &str| {
        if delta_chunk.is_empty() {
            return;
        }
        let kind = AgentEventKind::MessageDelta {
            delta: delta_chunk.to_string(),
        };
        if let Some(th) = turn_handle {
            th.emit_event(kind);
        } else if !turn_id.is_empty() {
            let _ = emit_turn_event(turn_id, task_id, kind);
        }
    };

    let mut last_err = String::new();
    for (idx, endpoint) in endpoints.iter().enumerate() {
        let mut req = client
            .post(endpoint)
            .header("anthropic-version", "2023-06-01")
            .header(
                reqwest::header::ACCEPT,
                "text/event-stream, application/json",
            )
            .json(&primary_body);
        if let Some(k) = api_key {
            req = req.header("x-api-key", k).bearer_auth(k);
        }

        let resp = if let Some(th) = turn_handle {
            tokio::select! {
                _ = th.wait_cancelled() => anyhow::bail!("turn_cancelled"),
                r = req.send() => r?,
            }
        } else {
            req.send().await?
        };
        let status = resp.status();
        if status.is_success() {
            return decode_anthropic_http_or_sse_response(resp, turn_handle, &mut emit_delta).await;
        }

        let err_text = resp.text().await.unwrap_or_default();
        if status.as_u16() == 400 && err_text.to_ascii_lowercase().contains("stream") {
            if let Some(ref mut bt) = budget_tracker
                && let Err(dim) = bt.try_record_retry()
            {
                anyhow::bail!("budget_exhausted:{}", dim);
            }
            let mut retry_req = client
                .post(endpoint)
                .header("anthropic-version", "2023-06-01")
                .json(&build_body(false));
            if let Some(k) = api_key {
                retry_req = retry_req.header("x-api-key", k).bearer_auth(k);
            }
            let retry_resp = retry_req.send().await?;
            let retry_status = retry_resp.status();
            if retry_status.is_success() {
                return decode_anthropic_http_or_sse_response(
                    retry_resp,
                    turn_handle,
                    &mut emit_delta,
                )
                .await;
            }
            let retry_err = retry_resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {}: {}", retry_status, retry_err);
        }

        last_err = format!("HTTP {}: {}", status, err_text);
        if status.as_u16() == 404 && idx + 1 < endpoints.len() {
            continue;
        }
        break;
    }

    anyhow::bail!("{}", last_err)
}

pub async fn call_openai_upstream(
    core: &IntentOsCore,
    transport: &UpstreamTransport,
    data_class: DataClass,
    model: &str,
    reasoning_effort: &str,
    messages: &[Value],
    tools: &[Value],
) -> anyhow::Result<Value> {
    call_openai_upstream_with_budget(
        core,
        transport,
        data_class,
        model,
        reasoning_effort,
        messages,
        tools,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn call_openai_upstream_with_budget(
    core: &IntentOsCore,
    transport: &UpstreamTransport,
    data_class: DataClass,
    model: &str,
    reasoning_effort: &str,
    messages: &[Value],
    tools: &[Value],
    budget_tracker: Option<&mut TurnBudgetTracker>,
) -> anyhow::Result<Value> {
    let (val, _) = call_openai_upstream_streaming(
        core,
        transport,
        data_class,
        model,
        reasoning_effort,
        messages,
        tools,
        budget_tracker,
        None,
        None,
        "",
    )
    .await?;
    Ok(val)
}

#[allow(clippy::too_many_arguments)]
pub async fn call_openai_upstream_streaming(
    core: &IntentOsCore,
    transport: &UpstreamTransport,
    data_class: DataClass,
    model: &str,
    reasoning_effort: &str,
    messages: &[Value],
    tools: &[Value],
    mut budget_tracker: Option<&mut TurnBudgetTracker>,
    turn_handle: Option<&ActiveTurnHandle>,
    task_id: Option<&str>,
    turn_id: &str,
) -> anyhow::Result<(Value, bool)> {
    let mapped_effort = match reasoning_effort {
        "fast" => Some("low"),
        "medium" => Some("medium"),
        "high" => Some("high"),
        _ => None,
    };

    let build_body = |include_effort: bool, include_tools: bool, include_stream: bool| -> Value {
        let mut body = json!({
            "model": model,
            "messages": messages,
        });
        if include_stream {
            body["stream"] = json!(true);
        }
        if include_tools && !tools.is_empty() {
            body["tools"] = json!(tools);
        }
        if include_effort && let Some(eff) = mapped_effort {
            body["reasoning_effort"] = json!(eff);
        }
        body
    };

    let mut emit_delta = |delta_chunk: &str| {
        if delta_chunk.is_empty() {
            return;
        }
        let kind = AgentEventKind::MessageDelta {
            delta: delta_chunk.to_string(),
        };
        if let Some(th) = turn_handle {
            th.emit_event(kind);
        } else if !turn_id.is_empty() {
            let _ = emit_turn_event(turn_id, task_id, kind);
        }
    };

    match transport {
        UpstreamTransport::GatewayLease { run_token } => {
            let first = core
                .gateway
                .proxy_chat_completion_streaming(
                    run_token,
                    build_body(mapped_effort.is_some(), true, true),
                    true,
                    turn_handle,
                    &mut emit_delta,
                )
                .await;
            match first {
                Ok(v) => Ok(v),
                Err(err) => {
                    let es = err.to_string();
                    if es.contains("turn_cancelled") {
                        anyhow::bail!("turn_cancelled");
                    }
                    if (mapped_effort.is_some() || es.to_ascii_lowercase().contains("stream"))
                        && (es.contains("reasoning_effort")
                            || es.to_ascii_lowercase().contains("stream")
                            || es.contains("400"))
                    {
                        if let Some(ref mut bt) = budget_tracker
                            && let Err(dim) = bt.try_record_retry()
                        {
                            anyhow::bail!("budget_exhausted:{}", dim);
                        }
                        let retry_stream = !es.to_ascii_lowercase().contains("stream");
                        Ok(core
                            .gateway
                            .proxy_chat_completion_streaming(
                                run_token,
                                build_body(false, true, retry_stream),
                                retry_stream,
                                turn_handle,
                                &mut emit_delta,
                            )
                            .await?)
                    } else {
                        Err(err.into())
                    }
                }
            }
        }
        UpstreamTransport::DirectHttp {
            base_url,
            api_key,
            trust,
        }
        | UpstreamTransport::AnthropicHttp {
            base_url,
            api_key,
            trust,
        } => {
            let verdict = check_egress_matrix(data_class, *trust);
            if verdict == EgressVerdict::Deny {
                anyhow::bail!(
                    "外发矩阵阻断：数据分级 {:?} 不允许发往 {:?} 后端",
                    data_class,
                    trust
                );
            }
            let payload_with_effort = build_body(mapped_effort.is_some(), true, true);
            let raw_check = payload_with_effort.to_string();
            if raw_check.contains("BEGIN OPENSSH PRIVATE KEY")
                || raw_check.contains("BEGIN RSA PRIVATE KEY")
            {
                anyhow::bail!("安全拦截：检测到疑似私钥内容，禁止外发");
            }

            let clean_base = base_url.trim_end_matches('/');
            let endpoint = if clean_base.ends_with("/chat/completions") {
                clean_base.to_string()
            } else {
                format!("{}/chat/completions", clean_base)
            };

            let is_local = endpoint.starts_with("http://127.0.0.1")
                || endpoint.starts_with("http://localhost");
            let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(90));
            if is_local {
                builder = builder.no_proxy();
            }
            let client = builder.build()?;

            let send_once = |body_val: Value| {
                let mut req = client
                    .post(&endpoint)
                    .header(
                        reqwest::header::ACCEPT,
                        "text/event-stream, application/json",
                    )
                    .json(&body_val);
                if let Some(k) = api_key {
                    req = req.bearer_auth(k);
                }
                req.send()
            };

            let resp = if let Some(th) = turn_handle {
                tokio::select! {
                    _ = th.wait_cancelled() => anyhow::bail!("turn_cancelled"),
                    r = send_once(payload_with_effort) => r?,
                }
            } else {
                send_once(payload_with_effort).await?
            };
            let status = resp.status();
            if status.is_success() {
                return decode_openai_http_or_sse_response(resp, turn_handle, &mut emit_delta)
                    .await;
            }

            let text_body = resp.text().await.unwrap_or_default();
            if status.as_u16() == 400
                && (mapped_effort.is_some() || text_body.to_ascii_lowercase().contains("stream"))
            {
                if let Some(ref mut bt) = budget_tracker
                    && let Err(dim) = bt.try_record_retry()
                {
                    anyhow::bail!("budget_exhausted:{}", dim);
                }
                let retry_stream = !text_body.to_ascii_lowercase().contains("stream");
                let retry_resp = send_once(build_body(false, true, retry_stream)).await?;
                let retry_status = retry_resp.status();
                if retry_status.is_success() {
                    return decode_openai_http_or_sse_response(
                        retry_resp,
                        turn_handle,
                        &mut emit_delta,
                    )
                    .await;
                }
                let retry_text = retry_resp.text().await.unwrap_or_default();
                anyhow::bail!("HTTP {}: {}", retry_status, retry_text);
            }

            anyhow::bail!("HTTP {}: {}", status, retry_or_body(&text_body))
        }
    }
}

fn retry_or_body(text_body: &str) -> &str {
    text_body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend_bridge::turn_checkpoint::{TurnStartOutcome, begin_turn, complete_turn};
    use crate::config::{AppConfig, BrainConfig, XdgPaths};
    use axum::{Json, Router, extract::State, routing::post};
    use chrono::Utc;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    fn setup_http_test_core() -> (tempfile::TempDir, Arc<IntentOsCore>) {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("xdg_http_h04");
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

        let core = IntentOsCore::initialize(Some(&base), repo_root).unwrap();
        (tmp, core)
    }

    #[derive(Clone, Default)]
    struct CapturedHttpRequests {
        bodies: Arc<Mutex<Vec<Value>>>,
    }

    #[tokio::test]
    async fn openai_http_chat_only_omits_tools_and_rejects_forced_upstream_tool_calls() {
        let (tmp, core) = setup_http_test_core();
        let (prior_vol, _) = core.settings.read_setting_value("sound.volume").unwrap();
        let initial_vol = prior_vol.as_f64().unwrap().round() as i64;
        let target_vol = if initial_vol == 91 { 19 } else { 91 };

        let captured = CapturedHttpRequests::default();
        let cap_srv = captured.clone();
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                post(
                    move |State(st): State<CapturedHttpRequests>, Json(body): Json<Value>| async move {
                        st.bodies.lock().unwrap().push(body);
                        Json(json!({
                            "id": "chatcmpl_h04_forced_tc",
                            "choices": [{
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": "这是普通回答文本。",
                                    "tool_calls": [{
                                        "id": "forced_call_1",
                                        "type": "function",
                                        "function": {
                                            "name": "sound_volume_set",
                                            "arguments": format!("{{\"value\":{}}}", target_vol)
                                        }
                                    }]
                                }
                            }]
                        }))
                    },
                ),
            )
            .with_state(cap_srv);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let opts = DiscoveryOptions::isolated_for_test(tmp.path().join("mock_home"));
        let active = ActiveBackendSelection {
            backend: "openai".to_string(),
            provider: "mock-openai".to_string(),
            model: "gpt-5.4".to_string(),
            reasoning_effort: "default".to_string(),
            base_url: Some(format!("http://{}/v1", addr)),
            pinned: true,
            auto_selected: false,
            direct_http_capable: true,
            pill_label: "OpenAI · gpt-5.4".to_string(),
        };
        let session = SessionState {
            session_id: "ses_h04_openai_chat_only".to_string(),
            messages: Vec::new(),
            last_resource_path: None,
            updated_at: Utc::now(),
        };
        let compressed =
            crate::memory_hub::build_compressed_session_history(&core, &session, false);

        let turn_id = "turn_h04_openai_chat_only_1";
        let TurnStartOutcome::Started(handle) = begin_turn(turn_id, Some(&session.session_id))
        else {
            panic!("expected fresh turn start");
        };
        let mut ledger = TurnEffectLedger::new(turn_id);

        let outcome = run_openai_tool_calling_turn_with_policy(
            &core,
            &opts,
            UpstreamTransport::DirectHttp {
                base_url: format!("http://{}/v1", addr),
                api_key: Some("sk-test-local-dummy".to_string()),
                trust: ProviderTrust::Trusted,
            },
            &active,
            &handle,
            "task_h04_openai_chat_only",
            &session,
            "帮我把音量调大",
            &[],
            &compressed,
            &[],
            None,
            false,
            false, // allow_broker_tools = false!
            &mut ledger,
        )
        .await
        .unwrap();
        complete_turn(turn_id, json!({}), false);

        let reqs = captured.bodies.lock().unwrap();
        assert_eq!(
            reqs.len(),
            1,
            "must not re-enter tool loop on rejected tool_calls"
        );
        assert!(
            reqs[0].get("tools").is_none(),
            "chat-only OpenAI HTTP request MUST omit `tools` schema completely"
        );

        assert_eq!(
            outcome.execution_mode,
            BackendExecutionMode::ExternalChatOnly
        );
        assert!(outcome.changeset_ids.is_empty());
        assert!(outcome.tool_steps_json.is_empty());
        assert!(!ledger.has_committed_side_effects());
        assert!(
            outcome
                .trace_dots
                .iter()
                .any(|d| d.kind == "tool_err" && d.detail.contains("allow_broker_tools=false"))
        );
        assert!(outcome.reply_markdown.contains("allow_broker_tools=false"));

        let (after_vol, _) = core.settings.read_setting_value("sound.volume").unwrap();
        assert_eq!(
            after_vol.as_f64().unwrap().round() as i64,
            initial_vol,
            "CapabilityBroker MUST NOT execute forced tool_calls when allow_broker_tools == false!"
        );
    }

    #[tokio::test]
    async fn anthropic_http_chat_only_omits_tools_and_rejects_forced_upstream_tool_use() {
        let (tmp, core) = setup_http_test_core();
        let (prior_bright, _) = core
            .settings
            .read_setting_value("display.brightness")
            .unwrap();
        let initial_bright = prior_bright.as_f64().unwrap().round() as i64;
        let target_bright = if initial_bright == 83 { 23 } else { 83 };

        let captured = CapturedHttpRequests::default();
        let cap_srv = captured.clone();
        let app = Router::new()
            .route(
                "/v1/messages",
                post(
                    move |State(st): State<CapturedHttpRequests>, Json(body): Json<Value>| async move {
                        st.bodies.lock().unwrap().push(body);
                        Json(json!({
                            "id": "msg_h04_forced_tu",
                            "type": "message",
                            "role": "assistant",
                            "content": [
                                { "type": "text", "text": "仅对话回复内容。" },
                                {
                                    "type": "tool_use",
                                    "id": "toolu_forced_1",
                                    "name": "display_brightness_set",
                                    "input": { "value": target_bright }
                                }
                            ]
                        }))
                    },
                ),
            )
            .with_state(cap_srv);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let opts = DiscoveryOptions::isolated_for_test(tmp.path().join("mock_home_anth"));
        let active = ActiveBackendSelection {
            backend: "zcode".to_string(),
            provider: "builtin:bigmodel".to_string(),
            model: "claude-sonnet-4".to_string(),
            reasoning_effort: "default".to_string(),
            base_url: Some(format!("http://{}/v1", addr)),
            pinned: true,
            auto_selected: false,
            direct_http_capable: true,
            pill_label: "ZCode · claude-sonnet-4".to_string(),
        };
        let session = SessionState {
            session_id: "ses_h04_anth_chat_only".to_string(),
            messages: Vec::new(),
            last_resource_path: None,
            updated_at: Utc::now(),
        };
        let compressed =
            crate::memory_hub::build_compressed_session_history(&core, &session, false);

        let turn_id = "turn_h04_anth_chat_only_1";
        let TurnStartOutcome::Started(handle) = begin_turn(turn_id, Some(&session.session_id))
        else {
            panic!("expected fresh turn start");
        };
        let mut ledger = TurnEffectLedger::new(turn_id);

        let outcome = run_anthropic_tool_calling_turn_with_policy(
            &core,
            &opts,
            &format!("http://{}/v1", addr),
            Some("sk-test-anth-dummy"),
            ProviderTrust::Trusted,
            &active,
            &handle,
            "task_h04_anth_chat_only",
            &session,
            "帮我把屏幕亮度调高",
            &[],
            &compressed,
            &[],
            None,
            false,
            false, // allow_broker_tools = false!
            &mut ledger,
        )
        .await
        .unwrap();
        complete_turn(turn_id, json!({}), false);

        let reqs = captured.bodies.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(
            reqs[0].get("tools").is_none(),
            "chat-only Anthropic HTTP request MUST omit `tools` schema completely"
        );

        assert_eq!(
            outcome.execution_mode,
            BackendExecutionMode::ExternalChatOnly
        );
        assert!(outcome.changeset_ids.is_empty());
        assert!(outcome.tool_steps_json.is_empty());
        assert!(!ledger.has_committed_side_effects());
        assert!(
            outcome
                .trace_dots
                .iter()
                .any(|d| d.kind == "tool_err" && d.detail.contains("display_brightness_set"))
        );

        let (after_bright, _) = core
            .settings
            .read_setting_value("display.brightness")
            .unwrap();
        assert_eq!(
            after_bright.as_f64().unwrap().round() as i64,
            initial_bright,
            "CapabilityBroker MUST NOT execute forced tool_use when allow_broker_tools == false!"
        );
    }
}
