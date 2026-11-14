#![forbid(unsafe_code)]

//! Controlled CLI Subprocess Bridge (`providers_cli.rs`):
//! - Supports `ZCode`, `Codex`, and `Pi` CLI backends with `0600` runtime override isolation
//!   (`ScopedZcodeRuntimeOverride`) and ZERO mutation of `~/.zcode`, `~/.codex`, or `~/.pi`.
//! - Bridges CLI backends into `CapabilityBroker` via the `<intentos_tool_call>` protocol
//!   (up to 4 rounds), recording into `TurnEffectLedger`, emitting real `TraceDot`s & `changeset_id`s,
//!   and participating in the exact same `PendingApproval` checkpoint & resume workflow as HTTP!

use crate::backend_bridge::broker_bridge::{
    BackendExecutionMode, QuickChatToolExecOutcome, TraceDot, TurnExecutionOutcome,
    build_quick_chat_openai_tools, execute_quick_chat_tool_call, finalize_completed_turn_outcome,
    prepare_system_prompt_and_context, synthesize_rich_approved_step_markdown,
};
use crate::backend_bridge::detector::{
    ActiveBackendSelection, DiscoveredBackend, DiscoveryOptions,
};
use crate::backend_bridge::turn_checkpoint::{
    ActiveTurnHandle, SuspendedDialectState, SuspendedTurnCheckpoint, TurnEffectLedger,
    save_suspended_checkpoint,
};
use crate::backend_bridge::turn_engine::extract_thinking_and_clean_reply;
use crate::config::XdgPaths;
use crate::core::IntentOsCore;
use crate::runtime::SessionState;
use intentos_protocol::ContextBlock;
use regex::Regex;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::process::Command;

pub const MAX_CLI_TOOL_ROUNDS: usize = 4;

/// RAII temporary `0600` override file inside `core.paths.runtime_dir` for ZCode CLI runs.
/// Guarantees zero modification to `~/.zcode` and automatic cleanup when dropped!
pub struct ScopedZcodeRuntimeOverride {
    dir_path: PathBuf,
    file_path: PathBuf,
}

impl ScopedZcodeRuntimeOverride {
    pub fn create(
        paths: &XdgPaths,
        turn_id: &str,
        provider: &str,
        model: &str,
        reasoning_effort: &str,
    ) -> anyhow::Result<Self> {
        let safe_id: String = turn_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(48)
            .collect();
        let dir_path = paths.runtime_dir.join(format!(
            "zcode_override_{}",
            if safe_id.is_empty() { "turn" } else { &safe_id }
        ));
        std::fs::create_dir_all(&dir_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700));
        }

        let file_path = dir_path.join("provider_override.json");
        let override_doc = json!({
            "schemaVersion": 1,
            "activeProvider": provider,
            "defaultModel": model,
            "reasoningEffort": reasoning_effort,
        });
        std::fs::write(&file_path, serde_json::to_vec_pretty(&override_doc)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self {
            dir_path,
            file_path,
        })
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    pub fn dir_path(&self) -> &Path {
        &self.dir_path
    }
}

impl Drop for ScopedZcodeRuntimeOverride {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.file_path);
        let _ = std::fs::remove_dir_all(&self.dir_path);
    }
}

/// Scrub inline API keys, tokens, and PEM private keys from arbitrary CLI text output.
pub fn scrub_text_secrets(raw: &str) -> String {
    static PEM_RE: OnceLock<Regex> = OnceLock::new();
    static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    static BEARER_RE: OnceLock<Regex> = OnceLock::new();

    let pem_re = PEM_RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
            .expect("valid pem regex")
    });
    let token_re = TOKEN_RE.get_or_init(|| {
        Regex::new(r"\b(?:sk|rk)-[A-Za-z0-9_-]{12,}\b|\b(?:ghp|gho|ghs)_[A-Za-z0-9]{12,}\b|\bxox[baprs]-[A-Za-z0-9-]{12,}\b")
            .expect("valid token regex")
    });
    let bearer_re = BEARER_RE.get_or_init(|| {
        Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}").expect("valid bearer regex")
    });

    let step1 = pem_re.replace_all(raw, "[REDACTED_PRIVATE_KEY]");
    let step2 = token_re.replace_all(&step1, "[REDACTED]");
    bearer_re.replace_all(&step2, "Bearer [REDACTED]").to_string()
}

/// Build a compact IntentOS Controlled Broker Tool Protocol prompt section for CLI backends.
pub fn build_cli_broker_protocol_prompt(core: &IntentOsCore, user_text: &str) -> String {
    let openai_tools = build_quick_chat_openai_tools(core, user_text);
    let mut tool_lines: Vec<String> = Vec::with_capacity(openai_tools.len());

    for t in &openai_tools {
        let Some(f) = t.get("function") else { continue };
        let Some(name) = f.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let desc = f
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("");
        let short_desc: String = desc.chars().take(72).collect();

        let required_set: Vec<&str> = f
            .pointer("/parameters/required")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let param_hints: Vec<String> = f
            .pointer("/parameters/properties")
            .and_then(|v| v.as_object())
            .map(|props| {
                props
                    .keys()
                    .take(6)
                    .map(|k| {
                        if required_set.iter().any(|r| r == k) {
                            k.clone()
                        } else {
                            format!("{}?", k)
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        tool_lines.push(format!(
            "- {}({}): {}",
            name,
            param_hints.join(", "),
            short_desc
        ));
    }

    format!(
        "[intentos_controlled_broker_protocol]\n\
        安全与受控执行协议：\n\
        1) 严禁直接执行不受控的 Shell 修改命令。\n\
        2) 当需要读取或修改 IntentOS 系统设置、文件、窗口、桌面软件或个人记忆时，请输出如下受控工具调用标签（支持单轮输出一个或多个，内部必须是合法 JSON）：\n\
        <intentos_tool_call>{{\"name\":\"<tool_name>\",\"arguments\":{{...}}}}</intentos_tool_call>\n\
        3) 输出 `<intentos_tool_call>` 后请立即结束本轮输出，等待系统通过 `CapabilityBroker` 安全执行并回传 `<intentos_tool_result>` 后再做总结。\n\
        4) 若用户仅作日常问答且无需调用系统能力，请直接用自然语言回复，不要输出任何 `<intentos_tool_call>` 标签。\n\
        可用 Broker 工具列表：\n{}",
        tool_lines.join("\n")
    )
}

/// Parse valid `<intentos_tool_call>...</intentos_tool_call>` blocks and strip ALL
/// `<intentos_tool_call>` tags (including malformed or unclosed tags) from CLI output text.
pub fn parse_and_strip_cli_tool_calls(
    raw: &str,
) -> (Vec<(Option<String>, String, Value)>, String) {
    static TOOL_CALL_RE: OnceLock<Regex> = OnceLock::new();
    static STRAY_TAG_RE: OnceLock<Regex> = OnceLock::new();
    static EXCESS_BLANK_RE: OnceLock<Regex> = OnceLock::new();

    let call_re = TOOL_CALL_RE.get_or_init(|| {
        Regex::new(r"(?is)<intentos_tool_call>(.*?)</intentos_tool_call>")
            .expect("valid cli tool call regex")
    });
    let stray_re = STRAY_TAG_RE.get_or_init(|| {
        Regex::new(r"(?is)</?intentos_tool_call\b[^>]*>").expect("valid stray tag regex")
    });
    let blank_re =
        EXCESS_BLANK_RE.get_or_init(|| Regex::new(r"\n{3,}").expect("valid blank regex"));

    let mut calls: Vec<(Option<String>, String, Value)> = Vec::new();

    for caps in call_re.captures_iter(raw) {
        let Some(m) = caps.get(1) else { continue };
        let mut inner = m.as_str().trim();
        if let Some(rest) = inner.strip_prefix("```json") {
            inner = rest.trim().trim_end_matches("```").trim();
        } else if let Some(rest) = inner.strip_prefix("```") {
            inner = rest.trim().trim_end_matches("```").trim();
        }

        let Ok(parsed) = serde_json::from_str::<Value>(inner) else {
            continue;
        };
        let Some(name) = parsed
            .get("name")
            .or_else(|| parsed.get("tool"))
            .or_else(|| parsed.get("capability_id"))
            .or_else(|| parsed.get("capability"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };

        let opt_id = parsed
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);

        let raw_args = parsed
            .get("arguments")
            .or_else(|| parsed.get("args"))
            .or_else(|| parsed.get("input"))
            .or_else(|| parsed.get("parameters"));
        let args_val = match raw_args {
            Some(Value::String(s)) => serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!({})),
            Some(v @ Value::Object(_)) => v.clone(),
            _ => json!({}),
        };

        calls.push((opt_id, name.to_string(), args_val));
    }

    let mut stripped = call_re.replace_all(raw, "").to_string();
    // Strip unclosed trailing `<intentos_tool_call>...` if truncated
    let lower = stripped.to_ascii_lowercase();
    if let Some(open_idx) = lower.find("<intentos_tool_call") {
        stripped.truncate(open_idx);
    }
    let stripped = stray_re.replace_all(&stripped, "").to_string();
    let cleaned = blank_re
        .replace_all(stripped.trim(), "\n\n")
        .trim()
        .to_string();

    (calls, cleaned)
}

async fn invoke_cli_subprocess_once(
    core: &IntentOsCore,
    disc: &DiscoveredBackend,
    active: &ActiveBackendSelection,
    turn_handle: &Arc<ActiveTurnHandle>,
    round_seq: usize,
    full_prompt: &str,
    incognito: bool,
) -> anyhow::Result<String> {
    if full_prompt.contains("BEGIN OPENSSH PRIVATE KEY")
        || full_prompt.contains("BEGIN RSA PRIVATE KEY")
    {
        anyhow::bail!("安全拦截：检测到疑似私钥内容，拒绝外发至外部 CLI 引擎");
    }

    let bin_str = disc
        .binary_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("未找到 {} 可执行文件", active.backend))?;

    let mut zcode_override_guard: Option<ScopedZcodeRuntimeOverride> = None;
    let mut codex_msg_file: Option<PathBuf> = None;

    let mut cmd = if let Some(ref runner) = disc.runner_program {
        let mut c = Command::new(runner);
        c.arg(bin_str);
        c
    } else {
        Command::new(bin_str)
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let round_turn_tag = format!("{}_r{}", turn_handle.turn_id, round_seq);

    match active.backend.as_str() {
        "zcode" => {
            let guard = ScopedZcodeRuntimeOverride::create(
                &core.paths,
                &round_turn_tag,
                &active.provider,
                &active.model,
                &active.reasoning_effort,
            )?;
            cmd.env("ZCODE_OVERRIDE_CONFIG", guard.file_path())
                .env("ZCODE_MODEL", &active.model)
                .env("NO_COLOR", "1")
                .args([
                    "--no-color",
                    "--workflow-mode",
                    "disabled",
                    "--disallowed-tools",
                    "Bash Edit Write",
                    "-p",
                    full_prompt,
                ]);
            zcode_override_guard = Some(guard);
        }
        "codex" => {
            let out_file = core
                .paths
                .runtime_dir
                .join(format!("codex_last_msg_{}.txt", round_turn_tag));
            let _ = std::fs::write(&out_file, b"");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out_file, std::fs::Permissions::from_mode(0o600));
            }
            cmd.args(["exec", "--skip-git-repo-check", "--color", "never"]);
            if incognito {
                cmd.arg("--ephemeral");
            }
            if !active.model.trim().is_empty() {
                cmd.args(["-m", &active.model]);
            }
            let codex_effort = match active.reasoning_effort.as_str() {
                "fast" => Some("low"),
                "medium" => Some("medium"),
                "high" => Some("high"),
                _ => None,
            };
            if let Some(eff) = codex_effort {
                cmd.args(["-c", &format!("model_reasoning_effort=\"{}\"", eff)]);
            }
            cmd.arg("-o").arg(&out_file).arg(full_prompt);
            codex_msg_file = Some(out_file);
        }
        "pi" => {
            if !active.model.trim().is_empty() {
                cmd.args(["--model", &active.model]);
            }
            cmd.args(["-p", full_prompt]);
        }
        other => anyhow::bail!("未知 CLI 后端: {}", other),
    }

    let child = cmd.spawn()?;
    let output_res = tokio::select! {
        _ = turn_handle.wait_cancelled() => {
            Err(anyhow::anyhow!("turn_cancelled"))
        }
        res = tokio::time::timeout(Duration::from_secs(90), child.wait_with_output()) => {
            match res {
                Ok(Ok(out)) => Ok(out),
                Ok(Err(e)) => Err(e.into()),
                Err(_) => Err(anyhow::anyhow!("CLI 后端响应超时")),
            }
        }
    };

    let raw_reply = match output_res {
        Ok(out) => {
            let from_file = codex_msg_file
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if let Some(ref p) = codex_msg_file {
                let _ = std::fs::remove_file(p);
            }
            drop(zcode_override_guard);

            if !out.status.success() && from_file.is_none() {
                let stderr = scrub_text_secrets(&String::from_utf8_lossy(&out.stderr));
                anyhow::bail!("CLI 退出码 {:?}: {}", out.status.code(), stderr.trim());
            }
            from_file.unwrap_or_else(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Err(err) => {
            if let Some(ref p) = codex_msg_file {
                let _ = std::fs::remove_file(p);
            }
            drop(zcode_override_guard);
            return Err(err);
        }
    };

    if raw_reply.is_empty() {
        anyhow::bail!("CLI 返回空输出");
    }

    Ok(raw_reply)
}

/// Controlled CLI Broker Bridge for `zcode`, `codex`, and `pi`.
#[allow(clippy::too_many_arguments)]
pub async fn run_cli_backend_turn(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
    disc: &DiscoveredBackend,
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
    let (sys_text, taints, data_class) =
        prepare_system_prompt_and_context(core, active, extra_blocks, incognito);
    let execution_mode = if allow_broker_tools {
        BackendExecutionMode::CliBrokerBridged
    } else {
        BackendExecutionMode::ExternalChatOnly
    };

    let mut base_sections: Vec<String> = vec![sys_text.clone()];
    if allow_broker_tools {
        base_sections.push(build_cli_broker_protocol_prompt(core, user_text));
    }
    if let Some(ref anchor) = compressed_history.ancient_summary_anchor
        && !anchor.trim().is_empty()
    {
        base_sections.push(anchor.clone());
    }
    for (q, a) in &compressed_history.turns {
        if !q.trim().is_empty() {
            base_sections.push(format!("user: {}", q));
        }
        if !a.trim().is_empty() {
            base_sections.push(format!("assistant: {}", a));
        }
    }
    base_sections.push(format!("User: {}", user_text));

    let mut transcript_history: Vec<String> = Vec::new();
    let max_rounds = if allow_broker_tools {
        MAX_CLI_TOOL_ROUNDS
    } else {
        1
    };

    for round_idx in 0..max_rounds {
        if turn_handle.is_cancelled() {
            anyhow::bail!("turn_cancelled");
        }

        let mut prompt_sections = base_sections.clone();
        prompt_sections.extend(transcript_history.iter().cloned());
        let full_prompt = prompt_sections.join("\n\n");

        let raw_reply = invoke_cli_subprocess_once(
            core,
            disc,
            active,
            turn_handle,
            round_idx + 1,
            &full_prompt,
            incognito,
        )
        .await?;

        let (step_thought, after_think) = extract_thinking_and_clean_reply(&raw_reply, None);
        if let Some(t) = step_thought {
            effect_ledger.push_thought(scrub_text_secrets(&t));
        }

        let (parsed_calls, cleaned_without_tags) = parse_and_strip_cli_tool_calls(&after_think);
        let scrubbed_text = scrub_text_secrets(&cleaned_without_tags);

        if allow_broker_tools && !parsed_calls.is_empty() {
            transcript_history.push(format!("Assistant:\n{}", scrub_text_secrets(&after_think)));
            let mut round_tool_results: Vec<String> = Vec::new();
            let mut all_duplicates = true;

            for (tc_idx, (opt_id, fn_name, parsed_args)) in parsed_calls.iter().enumerate() {
                if turn_handle.is_cancelled() {
                    anyhow::bail!("turn_cancelled");
                }
                let call_id = opt_id
                    .clone()
                    .unwrap_or_else(|| format!("cli_call_{}_{}", round_idx + 1, tc_idx + 1));

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
                    parsed_args,
                    effect_ledger,
                )
                .await?
                {
                    QuickChatToolExecOutcome::PausedForApproval {
                        outcome,
                        canonical_tool,
                    } => {
                        if let Some(ref pa) = outcome.pending_approval {
                            let remaining_tool_calls: Vec<(String, String, Value)> = parsed_calls
                                [tc_idx + 1..]
                                .iter()
                                .enumerate()
                                .map(|(rem_i, (rid, rname, rargs))| {
                                    (
                                        rid.clone().unwrap_or_else(|| {
                                            format!("cli_sib_{}_{}", round_idx + 1, rem_i + 1)
                                        }),
                                        rname.clone(),
                                        rargs.clone(),
                                    )
                                })
                                .collect();
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
                                rounds_used: round_idx + 1,
                                paused_call_id: call_id,
                                paused_canonical_tool: canonical_tool,
                                paused_parsed_args: parsed_args.clone(),
                                remaining_tool_calls,
                                effect_ledger: effect_ledger.clone(),
                                dialect: SuspendedDialectState::Cli {
                                    disc: disc.clone(),
                                    transcript_history: transcript_history.clone(),
                                    prior_round_tool_results: round_tool_results,
                                    allow_broker_tools,
                                },
                            });
                        }
                        return Ok(*outcome);
                    }
                    QuickChatToolExecOutcome::ToolMessage {
                        content,
                        is_error,
                        duplicate_blocked,
                    } => {
                        if !duplicate_blocked {
                            all_duplicates = false;
                        }
                        round_tool_results.push(format!(
                            "<intentos_tool_result call_id=\"{}\" name=\"{}\" is_error=\"{}\">{}</intentos_tool_result>",
                            call_id,
                            fn_name,
                            is_error,
                            scrub_text_secrets(&content)
                        ));
                    }
                }
            }

            if all_duplicates {
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
                    scrubbed_text,
                    effect_ledger,
                ));
            }

            transcript_history.push(format!(
                "System Tool Results:\n{}\n请基于上述真实 `<intentos_tool_result>` 结果向用户给出最终总结回复（若无需进一步操作，请不要再输出 `<intentos_tool_call>`）。",
                round_tool_results.join("\n")
            ));
            continue;
        }

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
            scrubbed_text,
            effect_ledger,
        ));
    }

    Ok(finalize_completed_turn_outcome(
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
    ))
}

/// Resume a suspended CLI turn after `PendingApproval` has been approved by the user.
#[allow(clippy::too_many_arguments)]
pub async fn continue_resumed_cli_turn(
    core: &IntentOsCore,
    cp: &mut SuspendedTurnCheckpoint,
    eff_opts: &DiscoveryOptions,
    resume_handle: &Arc<ActiveTurnHandle>,
    disc: DiscoveredBackend,
    mut transcript_history: Vec<String>,
    mut prior_round_tool_results: Vec<String>,
    allow_broker_tools: bool,
    approved_tool_content: String,
    approved_is_err: bool,
) -> anyhow::Result<TurnExecutionOutcome> {
    let execution_mode = if allow_broker_tools {
        BackendExecutionMode::CliBrokerBridged
    } else {
        BackendExecutionMode::ExternalChatOnly
    };

    prior_round_tool_results.push(format!(
        "<intentos_tool_result call_id=\"{}\" name=\"{}\" is_error=\"{}\">{}</intentos_tool_result>",
        cp.paused_call_id,
        cp.paused_canonical_tool,
        approved_is_err,
        scrub_text_secrets(&approved_tool_content)
    ));

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
                        rounds_used: cp.rounds_used,
                        paused_call_id: rem_id.clone(),
                        paused_canonical_tool: canonical_tool,
                        paused_parsed_args: rem_args.clone(),
                        remaining_tool_calls: cp.remaining_tool_calls[rem_idx + 1..].to_vec(),
                        effect_ledger: cp.effect_ledger.clone(),
                        dialect: SuspendedDialectState::Cli {
                            disc,
                            transcript_history,
                            prior_round_tool_results,
                            allow_broker_tools,
                        },
                    });
                }
                return Ok(*outcome);
            }
            QuickChatToolExecOutcome::ToolMessage {
                content, is_error, ..
            } => {
                prior_round_tool_results.push(format!(
                    "<intentos_tool_result call_id=\"{}\" name=\"{}\" is_error=\"{}\">{}</intentos_tool_result>",
                    rem_id,
                    rem_name,
                    is_error,
                    scrub_text_secrets(&content)
                ));
            }
        }
    }

    transcript_history.push(format!(
        "System Tool Results:\n{}\n请基于上述已授权执行的 `<intentos_tool_result>` 结果向用户完成最终回复。",
        prior_round_tool_results.join("\n")
    ));

    let remaining_rounds = MAX_CLI_TOOL_ROUNDS.saturating_sub(cp.rounds_used).max(1);
    let mut base_sections: Vec<String> = vec![cp.sys_text.clone()];
    if allow_broker_tools {
        base_sections.push(build_cli_broker_protocol_prompt(core, &cp.user_text));
    }
    base_sections.push(format!("User: {}", cp.user_text));

    for r_offset in 0..remaining_rounds {
        let mut prompt_sections = base_sections.clone();
        prompt_sections.extend(transcript_history.iter().cloned());
        let full_prompt = prompt_sections.join("\n\n");

        let Ok(raw_reply) = invoke_cli_subprocess_once(
            core,
            &disc,
            &cp.active,
            resume_handle,
            cp.rounds_used + r_offset + 1,
            &full_prompt,
            cp.incognito,
        )
        .await
        else {
            break;
        };

        let (step_thought, after_think) = extract_thinking_and_clean_reply(&raw_reply, None);
        if let Some(t) = step_thought {
            cp.effect_ledger.push_thought(scrub_text_secrets(&t));
        }

        let (parsed_calls, cleaned_without_tags) = parse_and_strip_cli_tool_calls(&after_think);
        let scrubbed_text = scrub_text_secrets(&cleaned_without_tags);

        if allow_broker_tools && !parsed_calls.is_empty() {
            transcript_history.push(format!("Assistant:\n{}", scrub_text_secrets(&after_think)));
            let mut next_results: Vec<String> = Vec::new();
            let mut all_duplicates = true;

            for (tc_idx, (opt_id, fn_name, parsed_args)) in parsed_calls.iter().enumerate() {
                let call_id = opt_id.clone().unwrap_or_else(|| {
                    format!(
                        "cli_res_{}_{}",
                        cp.rounds_used + r_offset + 1,
                        tc_idx + 1
                    )
                });
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
                    parsed_args,
                    &mut cp.effect_ledger,
                )
                .await?
                {
                    QuickChatToolExecOutcome::PausedForApproval {
                        outcome,
                        canonical_tool,
                    } => {
                        if let Some(ref next_pa) = outcome.pending_approval {
                            let rem_calls = parsed_calls[tc_idx + 1..]
                                .iter()
                                .enumerate()
                                .map(|(ri, (rid, rname, rargs))| {
                                    (
                                        rid.clone().unwrap_or_else(|| {
                                            format!(
                                                "cli_sib_{}_{}",
                                                cp.rounds_used + r_offset + 1,
                                                ri + 1
                                            )
                                        }),
                                        rname.clone(),
                                        rargs.clone(),
                                    )
                                })
                                .collect();
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
                                rounds_used: cp.rounds_used + r_offset + 1,
                                paused_call_id: call_id,
                                paused_canonical_tool: canonical_tool,
                                paused_parsed_args: parsed_args.clone(),
                                remaining_tool_calls: rem_calls,
                                effect_ledger: cp.effect_ledger.clone(),
                                dialect: SuspendedDialectState::Cli {
                                    disc: disc.clone(),
                                    transcript_history: transcript_history.clone(),
                                    prior_round_tool_results: next_results,
                                    allow_broker_tools,
                                },
                            });
                        }
                        return Ok(*outcome);
                    }
                    QuickChatToolExecOutcome::ToolMessage {
                        content,
                        is_error,
                        duplicate_blocked,
                    } => {
                        if !duplicate_blocked {
                            all_duplicates = false;
                        }
                        next_results.push(format!(
                            "<intentos_tool_result call_id=\"{}\" name=\"{}\" is_error=\"{}\">{}</intentos_tool_result>",
                            call_id,
                            fn_name,
                            is_error,
                            scrub_text_secrets(&content)
                        ));
                    }
                }
            }

            if all_duplicates {
                break;
            }
            transcript_history.push(format!(
                "System Tool Results:\n{}\n请基于上述 `<intentos_tool_result>` 完成最终总结。",
                next_results.join("\n")
            ));
            continue;
        }

        let final_md = if scrubbed_text.trim().is_empty() {
            synthesize_rich_approved_step_markdown(&cp.user_text, &cp.effect_ledger.task_steps)
        } else {
            scrubbed_text
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
