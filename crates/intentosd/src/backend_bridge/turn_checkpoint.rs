#![forbid(unsafe_code)]

//! Turn Lifecycle Registry, Checkpoints & Side-Effect Idempotency Ledger (`turn_checkpoint.rs`).
//!
//! Responsibilities:
//! 1. `TurnEffectLedger` & `StepExecutionRecord`: Deterministic per-step `step_id` (`step_1`, `step_2`, ...)
//!    and SHA-256 `idempotency_key` (`turn_id + capability_id + canonical_args_json`), deduplicating
//!    accidental duplicate side-effecting calls within a turn and blocking backend fallback replay
//!    once any step with `effect > Effect::Observe` has committed!
//! 2. `ActiveTurnHandle` & turn registry (`ACTIVE_TURNS`, `RECENT_COMPLETED_TURNS`, `CANCELLED_TURN_IDS`):
//!    Pre-turn & mid-flight cancellation (`cancel_turn`) + explicit `turn_id` replay protection.
//! 3. `SuspendedTurnCheckpoint` (`SUSPENDED_APPROVAL_TURNS`): Seamless suspension & continuation across
//!    OpenAI HTTP, Anthropic HTTP, and Controlled CLI backends when `CapabilityBroker` issues `PendingApproval`.

use crate::backend_bridge::broker_bridge::{
    BackendExecutionMode, TraceDot, record_approved_step_into_ledger,
};
use crate::backend_bridge::detector::{
    ActiveBackendSelection, DiscoveredBackend, DiscoveryOptions, scrub_json_secrets,
};
use crate::backend_bridge::providers_cli::continue_resumed_cli_turn;
use crate::backend_bridge::providers_http::{
    continue_resumed_anthropic_turn, continue_resumed_openai_turn,
};
use crate::core::IntentOsCore;
use crate::runtime::SessionState;
use intentos_protocol::{
    ContextBlock, DataClass, Effect, ExecutionStatus, PendingApproval, ProviderTrust, Taint,
    TaskStep,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// Recursively serialize a JSON `Value` with lexicographically sorted object keys so
/// `idempotency_key` is 100% invariant to JSON field ordering (even under `preserve_order`).
pub fn canonicalize_json_value(v: &Value) -> String {
    fn write_canonical(v: &Value, out: &mut String) {
        match v {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                if let Ok(s) = serde_json::to_string(v) {
                    out.push_str(&s);
                }
            }
            Value::Array(arr) => {
                out.push('[');
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_canonical(item, out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                let mut sorted: BTreeMap<&str, &Value> = BTreeMap::new();
                for (k, val) in map {
                    sorted.insert(k.as_str(), val);
                }
                out.push('{');
                for (i, (k, val)) in sorted.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if let Ok(ks) = serde_json::to_string(k) {
                        out.push_str(&ks);
                    }
                    out.push(':');
                    write_canonical(val, out);
                }
                out.push('}');
            }
        }
    }
    let mut buf = String::new();
    write_canonical(v, &mut buf);
    buf
}

/// Canonicalize a raw JSON string if valid JSON, otherwise return trimmed raw string.
pub fn canonicalize_json_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        canonicalize_json_value(&val)
    } else {
        trimmed.to_string()
    }
}

/// Immutable execution ledger entry for a single tool step within a turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecutionRecord {
    pub step_id: String,
    pub idempotency_key: String,
    pub capability_id: String,
    pub canonical_args_json: String,
    pub effect: Effect,
    pub mutated_state: bool,
    pub succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changeset_id: Option<String>,
    pub verification_status: String,
    pub cached_output: Value,
}

/// Per-turn side-effect ledger and runtime progress buffer.
///
/// Tracks every tool invocation's `step_id` and `idempotency_key`, deduplicates duplicate
/// tool calls within the same turn, and prevents fallback side-effect replay when an upstream
/// backend fails after a mutating capability has already committed!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnEffectLedger {
    pub turn_id: String,
    next_step_seq: usize,
    records: Vec<StepExecutionRecord>,
    #[serde(skip)]
    by_idempotency_key: HashMap<String, usize>,

    // Runtime progress buffers preserved across mid-turn backend failures and checkpoints:
    #[serde(skip)]
    pub trace_dots: Vec<TraceDot>,
    #[serde(skip)]
    pub adapter_actions: Vec<Value>,
    #[serde(skip)]
    pub tool_steps_json: Vec<Value>,
    #[serde(skip)]
    pub task_steps: Vec<TaskStep>,
    #[serde(skip)]
    pub changeset_ids: Vec<String>,
    #[serde(skip)]
    pub accumulated_thoughts: Vec<String>,
    #[serde(skip)]
    pub last_resource_path: Option<String>,
}

impl TurnEffectLedger {
    pub fn new(turn_id: impl Into<String>) -> Self {
        Self {
            turn_id: turn_id.into(),
            next_step_seq: 0,
            records: Vec::new(),
            by_idempotency_key: HashMap::new(),
            trace_dots: Vec::new(),
            adapter_actions: Vec::new(),
            tool_steps_json: Vec::new(),
            task_steps: Vec::new(),
            changeset_ids: Vec::new(),
            accumulated_thoughts: Vec::new(),
            last_resource_path: None,
        }
    }

    /// Allocate the next deterministic `step_id` (`step_1`, `step_2`, ...).
    pub fn next_step_id(&mut self) -> String {
        self.next_step_seq += 1;
        format!("step_{}", self.next_step_seq)
    }

    /// Compute deterministic SHA-256 `idempotency_key` from `turn_id + capability_id + canonical_args_json`.
    pub fn compute_idempotency_key(&self, capability_id: &str, args_json: &str) -> String {
        let canonical = canonicalize_json_str(args_json);
        let mut hasher = Sha256::new();
        hasher.update(self.turn_id.as_bytes());
        hasher.update(b":");
        hasher.update(capability_id.as_bytes());
        hasher.update(b":");
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Look up an existing step execution by `idempotency_key` to block duplicate execution in the same turn.
    pub fn lookup_idempotent(&self, idempotency_key: &str) -> Option<&StepExecutionRecord> {
        if let Some(&idx) = self.by_idempotency_key.get(idempotency_key) {
            return self.records.get(idx);
        }
        self.records
            .iter()
            .find(|r| r.idempotency_key == idempotency_key)
    }

    /// Record a completed or denied tool execution step into the ledger.
    pub fn record_step(&mut self, record: StepExecutionRecord) {
        if let Some(ref csid) = record.changeset_id
            && !self.changeset_ids.contains(csid)
        {
            self.changeset_ids.push(csid.clone());
        }
        let idx = self.records.len();
        self.by_idempotency_key
            .entry(record.idempotency_key.clone())
            .or_insert(idx);
        self.records.push(record);
    }

    /// Push a unique reasoning/thinking snippet into `accumulated_thoughts`.
    pub fn push_thought(&mut self, thought: String) {
        if !thought.trim().is_empty()
            && !self
                .accumulated_thoughts
                .iter()
                .any(|existing| existing == &thought)
        {
            self.accumulated_thoughts.push(thought);
        }
    }

    /// Returns `true` if ANY step with `effect > Effect::Observe` has already executed and committed!
    pub fn has_committed_side_effects(&self) -> bool {
        self.records.iter().any(|r| r.mutated_state)
    }

    /// Returns all committed `changeset_id`s recorded in this turn (preserving execution order).
    pub fn committed_changeset_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in &self.records {
            if let Some(ref csid) = r.changeset_id
                && !out.contains(csid)
            {
                out.push(csid.clone());
            }
        }
        for csid in &self.changeset_ids {
            if !out.contains(csid) {
                out.push(csid.clone());
            }
        }
        out
    }

    pub fn records(&self) -> &[StepExecutionRecord] {
        &self.records
    }

    /// Export a structured JSON summary of this turn's effect ledger for UI & audit diagnostics.
    pub fn summary_json(&self) -> Value {
        json!({
            "turn_id": self.turn_id,
            "total_steps": self.records.len(),
            "mutated_steps": self.records.iter().filter(|r| r.mutated_state).count(),
            "has_committed_side_effects": self.has_committed_side_effects(),
            "committed_changeset_ids": self.committed_changeset_ids(),
            "steps": self.records,
        })
    }
}

/// Active turn cancellation & idempotency handle.
pub struct ActiveTurnHandle {
    pub turn_id: String,
    pub session_id: Option<String>,
    pub task_id: Mutex<Option<String>>,
    cancelled: AtomicBool,
    notify: Notify,
    pub started_at: Instant,
}

impl ActiveTurnHandle {
    pub fn new(turn_id: String, session_id: Option<String>) -> Self {
        Self {
            turn_id,
            session_id,
            task_id: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
            started_at: Instant::now(),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) -> bool {
        let was_already = self.cancelled.swap(true, Ordering::SeqCst);
        self.notify.notify_waiters();
        !was_already
    }

    pub async fn wait_cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

pub(crate) enum TurnStartOutcome {
    Started(Arc<ActiveTurnHandle>),
    IdempotentReplay(Value),
    PreCancelled,
}

pub(crate) static ACTIVE_TURNS: OnceLock<Mutex<HashMap<String, Arc<ActiveTurnHandle>>>> =
    OnceLock::new();
pub(crate) static RECENT_COMPLETED_TURNS: OnceLock<Mutex<VecDeque<(String, Value)>>> =
    OnceLock::new();
static CANCELLED_TURN_IDS: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn active_turns() -> &'static Mutex<HashMap<String, Arc<ActiveTurnHandle>>> {
    ACTIVE_TURNS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn recent_completed_turns() -> &'static Mutex<VecDeque<(String, Value)>> {
    RECENT_COMPLETED_TURNS.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn cancelled_turn_ids() -> &'static Mutex<VecDeque<String>> {
    CANCELLED_TURN_IDS.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn record_cancelled_id(turn_id: &str) {
    let mut c = cancelled_turn_ids().lock().unwrap();
    if !c.iter().any(|id| id == turn_id) {
        if c.len() >= 128 {
            c.pop_front();
        }
        c.push_back(turn_id.to_string());
    }
}

pub(crate) fn begin_turn(turn_id: &str, session_id: Option<&str>) -> TurnStartOutcome {
    if let Some((_, cached)) = recent_completed_turns()
        .lock()
        .unwrap()
        .iter()
        .find(|(id, _)| id == turn_id)
        .cloned()
    {
        return TurnStartOutcome::IdempotentReplay(cached);
    }

    if cancelled_turn_ids()
        .lock()
        .unwrap()
        .iter()
        .any(|id| id == turn_id)
    {
        return TurnStartOutcome::PreCancelled;
    }

    let mut active_map = active_turns().lock().unwrap();
    if let Some(existing) = active_map.get(turn_id)
        && existing.is_cancelled()
    {
        return TurnStartOutcome::PreCancelled;
    }

    let handle = Arc::new(ActiveTurnHandle::new(
        turn_id.to_string(),
        session_id.map(String::from),
    ));
    active_map.insert(turn_id.to_string(), handle.clone());
    TurnStartOutcome::Started(handle)
}

pub(crate) fn complete_turn(turn_id: &str, result: Value, cache_for_replay: bool) {
    active_turns().lock().unwrap().remove(turn_id);
    if cache_for_replay {
        let mut comp = recent_completed_turns().lock().unwrap();
        if !comp.iter().any(|(id, _)| id == turn_id) {
            if comp.len() >= 64 {
                comp.pop_front();
            }
            comp.push_back((turn_id.to_string(), result));
        }
    }
}

pub(crate) fn remove_active_turn(turn_id: &str) {
    active_turns().lock().unwrap().remove(turn_id);
}

pub fn cancel_turn(core: &IntentOsCore, payload: &Value) -> Value {
    let target_turn_id = payload.get("turn_id").and_then(|v| v.as_str());
    let target_session_id = payload.get("session_id").and_then(|v| v.as_str());

    if let Some(tid) = target_turn_id.map(str::trim).filter(|s| !s.is_empty()) {
        let maybe_handle = active_turns().lock().unwrap().get(tid).cloned();
        if let Some(handle) = maybe_handle {
            let first_cancel = handle.cancel();
            if let Some(ref task_id) = *handle.task_id.lock().unwrap() {
                core.gateway.cancel_task_leases(task_id);
            }
            record_cancelled_id(tid);
            return json!({
                "ok": true,
                "turn_id": tid,
                "status": if first_cancel { "cancelled" } else { "already_cancelled" },
                "was_running": first_cancel,
                "idempotent": !first_cancel,
            });
        }

        let already_cancelled = cancelled_turn_ids()
            .lock()
            .unwrap()
            .iter()
            .any(|id| id == tid);
        let already_completed = recent_completed_turns()
            .lock()
            .unwrap()
            .iter()
            .any(|(id, _)| id == tid);

        if already_completed {
            return json!({
                "ok": true,
                "turn_id": tid,
                "status": "already_completed",
                "was_running": false,
                "idempotent": true,
            });
        }

        // Pre-register cancellation so an arriving turn with this `turn_id` aborts immediately
        record_cancelled_id(tid);
        return json!({
            "ok": true,
            "turn_id": tid,
            "status": if already_cancelled { "already_cancelled" } else { "cancelled" },
            "was_running": false,
            "idempotent": already_cancelled,
        });
    }

    // Cancel by `session_id` or latest active turn
    let target_handle = {
        let map = active_turns().lock().unwrap();
        if let Some(sid) = target_session_id.map(str::trim).filter(|s| !s.is_empty()) {
            map.values()
                .find(|h| h.session_id.as_deref() == Some(sid))
                .cloned()
        } else {
            map.values().max_by_key(|h| h.started_at).cloned()
        }
    };

    if let Some(handle) = target_handle {
        let first_cancel = handle.cancel();
        if let Some(ref task_id) = *handle.task_id.lock().unwrap() {
            core.gateway.cancel_task_leases(task_id);
        }
        record_cancelled_id(&handle.turn_id);
        json!({
            "ok": true,
            "turn_id": handle.turn_id,
            "status": if first_cancel { "cancelled" } else { "already_cancelled" },
            "was_running": first_cancel,
            "idempotent": !first_cancel,
        })
    } else {
        json!({
            "ok": true,
            "turn_id": Value::Null,
            "status": "idle",
            "was_running": false,
            "idempotent": true,
        })
    }
}

pub(crate) fn build_cancelled_turn_response(
    turn_id: &str,
    session_id: &str,
    trace_dots: Vec<TraceDot>,
) -> Value {
    json!({
        "turn_id": turn_id,
        "session_id": session_id,
        "status": "cancelled",
        "cancelled": true,
        "backend_used": "cancelled",
        "model_used": "none",
        "thinking": Value::Null,
        "reply_markdown": "已中止当前对话回合。",
        "reply": "已中止当前对话回合。",
        "trace_dots": trace_dots,
        "memory_hits": [],
        "adapter_actions": [],
        "changeset_ids": [],
        "pending_approval": Value::Null,
    })
}

const MAX_SUSPENDED_CHECKPOINTS: usize = 64;
const SUSPENDED_CHECKPOINT_TTL: Duration = Duration::from_secs(7200);

#[derive(Clone)]
pub enum SuspendedDialectState {
    OpenAi {
        messages: Vec<Value>,
        tools: Vec<Value>,
    },
    Anthropic {
        base_url: String,
        api_key: Option<String>,
        trust: ProviderTrust,
        messages: Vec<Value>,
        prior_tool_results: Vec<Value>,
        tools: Vec<Value>,
    },
    Cli {
        disc: DiscoveredBackend,
        transcript_history: Vec<String>,
        prior_round_tool_results: Vec<String>,
        allow_broker_tools: bool,
    },
}

#[derive(Clone)]
pub struct SuspendedTurnCheckpoint {
    pub created_at_instant: Instant,
    #[allow(dead_code)]
    pub approval_id: String,
    pub pending_approval: PendingApproval,
    pub task_id: String,
    pub session: SessionState,
    pub user_text: String,
    pub incognito: bool,
    pub active: ActiveBackendSelection,
    pub discovery_opts: DiscoveryOptions,
    pub extra_blocks: Vec<ContextBlock>,
    pub sys_text: String,
    pub taints: Vec<Taint>,
    pub data_class: DataClass,
    pub memory_hits: Vec<Value>,
    pub memory_dot: Option<TraceDot>,
    pub context_compression: crate::memory_hub::ContextCompressionStats,
    pub rounds_used: usize,
    pub paused_call_id: String,
    #[allow(dead_code)]
    pub paused_canonical_tool: String,
    pub paused_parsed_args: Value,
    pub remaining_tool_calls: Vec<(String, String, Value)>,
    pub effect_ledger: TurnEffectLedger,
    pub dialect: SuspendedDialectState,
}

pub(crate) static SUSPENDED_APPROVAL_TURNS: OnceLock<
    Mutex<HashMap<String, SuspendedTurnCheckpoint>>,
> = OnceLock::new();

fn suspended_approval_turns() -> &'static Mutex<HashMap<String, SuspendedTurnCheckpoint>> {
    SUSPENDED_APPROVAL_TURNS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn save_suspended_checkpoint(cp: SuspendedTurnCheckpoint) {
    let mut map = suspended_approval_turns().lock().unwrap();
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(v.created_at_instant) <= SUSPENDED_CHECKPOINT_TTL);
    while map.len() >= MAX_SUSPENDED_CHECKPOINTS {
        let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, v)| v.created_at_instant)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        map.remove(&oldest_key);
    }
    map.insert(cp.pending_approval.approval_id.clone(), cp);
}

pub(crate) fn take_suspended_checkpoint(approval_id: &str) -> Option<SuspendedTurnCheckpoint> {
    let mut map = suspended_approval_turns().lock().unwrap();
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(v.created_at_instant) <= SUSPENDED_CHECKPOINT_TTL);
    map.remove(approval_id)
}

pub(crate) async fn resume_suspended_checkpoint_and_finalize(
    core: &IntentOsCore,
    mut cp: SuspendedTurnCheckpoint,
    opts: &DiscoveryOptions,
    resume_turn_id: &str,
    step: &TaskStep,
    paused_args_val: &Value,
    approved_changeset_ids: &[String],
) -> anyhow::Result<Value> {
    record_approved_step_into_ledger(
        core,
        &mut cp.effect_ledger,
        step,
        paused_args_val,
        approved_changeset_ids,
    );

    let approved_tool_content = serde_json::to_string(&json!({
        "approved_by_user": true,
        "message": step.message,
        "data": step.data,
    }))?;
    let approved_is_err = !matches!(
        step.status,
        ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
    );

    let resume_handle = Arc::new(ActiveTurnHandle::new(
        resume_turn_id.to_string(),
        Some(cp.session.session_id.clone()),
    ));
    *resume_handle.task_id.lock().unwrap() = Some(cp.task_id.clone());

    let max_rounds = core.brain_config.runtime_limits.max_tool_calls.clamp(1, 6) as usize;
    let remaining_llm_rounds = max_rounds.saturating_sub(cp.rounds_used).max(2);

    let eff_opts = if opts.include_system_paths && !cp.discovery_opts.include_system_paths {
        cp.discovery_opts.clone()
    } else {
        opts.clone()
    };

    let dialect = cp.dialect.clone();
    let outcome = match dialect {
        SuspendedDialectState::OpenAi { messages, tools } => {
            continue_resumed_openai_turn(
                core,
                &mut cp,
                &eff_opts,
                messages,
                tools,
                approved_tool_content,
                remaining_llm_rounds,
            )
            .await?
        }
        SuspendedDialectState::Anthropic {
            base_url,
            api_key,
            trust,
            messages,
            prior_tool_results,
            tools,
        } => {
            continue_resumed_anthropic_turn(
                core,
                &mut cp,
                &eff_opts,
                base_url,
                api_key,
                trust,
                messages,
                prior_tool_results,
                tools,
                approved_tool_content,
                approved_is_err,
                remaining_llm_rounds,
            )
            .await?
        }
        SuspendedDialectState::Cli {
            disc,
            transcript_history,
            prior_round_tool_results,
            allow_broker_tools,
        } => {
            continue_resumed_cli_turn(
                core,
                &mut cp,
                &eff_opts,
                &resume_handle,
                disc,
                transcript_history,
                prior_round_tool_results,
                allow_broker_tools,
                approved_tool_content,
                approved_is_err,
            )
            .await?
        }
    };

    let mut final_dots: Vec<TraceDot> = Vec::new();
    if let Some(ref think_str) = outcome.thinking
        && !think_str.trim().is_empty()
    {
        final_dots.push(TraceDot::thinking(think_str.clone()));
    }
    if let Some(mdot) = cp.memory_dot
        && !outcome.trace_dots.iter().any(|d| d.kind == "memory")
    {
        final_dots.push(mdot);
    }
    final_dots.extend(outcome.trace_dots);

    if !cp.incognito && outcome.pending_approval.is_none() {
        let dots_val = serde_json::to_value(&final_dots)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        let _ = crate::memory_hub::record_conversation_turn(
            core,
            &crate::memory_hub::RecordTurnInput {
                session_id: Some(cp.session.session_id.clone()),
                user_text: cp.user_text,
                assistant_text: outcome.reply_markdown.clone(),
                thinking: outcome.thinking.clone(),
                tool_steps: outcome.tool_steps_json.clone(),
                trace_dots: dots_val,
                incognito: false,
            },
        );
    }

    let mut response = json!({
        "turn_id": resume_turn_id,
        "task_id": outcome.task_id,
        "session_id": cp.session.session_id,
        "status": if outcome.pending_approval.is_some() { "awaiting_approval" } else { "completed" },
        "approval_resolved": "approved",
        "execution_mode": outcome.execution_mode,
        "side_effect_replay_prevented": outcome.side_effect_replay_prevented,
        "effect_ledger": cp.effect_ledger.summary_json(),
        "backend_used": outcome.backend_used,
        "provider_used": outcome.provider_used,
        "model_used": outcome.model_used,
        "reasoning_effort": cp.active.reasoning_effort,
        "thinking": outcome.thinking,
        "reply_markdown": outcome.reply_markdown,
        "reply": outcome.reply_markdown,
        "trace_dots": final_dots,
        "tool_steps": outcome.tool_steps_json,
        "memory_hits": cp.memory_hits,
        "adapter_actions": outcome.adapter_actions,
        "changeset_ids": outcome.changeset_ids,
        "handoff_command": outcome.handoff_command,
        "pending_approval": outcome.pending_approval,
        "context_compression": cp.context_compression,
    });
    scrub_json_secrets(&mut response);
    Ok(response)
}

pub(crate) fn build_denied_resume_response(
    core: &IntentOsCore,
    payload: &Value,
    approval_id: &str,
    resume_turn_id: &str,
    pa_ref: Option<PendingApproval>,
    checkpoint: Option<SuspendedTurnCheckpoint>,
) -> anyhow::Result<Value> {
    let denied_task = core.deny_pending(approval_id).ok();
    let cap_id = pa_ref
        .as_ref()
        .map(|p| p.capability_id.clone())
        .unwrap_or_else(|| "sensitive.operation".to_string());
    let denied_dot = TraceDot::denied(
        &cap_id,
        format!("用户已拒绝执行受控操作 ({})，未产生任何系统修改", cap_id),
    );
    let session_reply_text = "已按您的指令拒绝执行该敏感操作，未产生任何修改。";
    let display_reply_text = "已拒绝执行该敏感受控操作，未产生任何系统修改。";

    if let Some(cp) = checkpoint {
        let exec_mode = match cp.dialect {
            SuspendedDialectState::Cli {
                allow_broker_tools, ..
            } => {
                if allow_broker_tools {
                    BackendExecutionMode::CliBrokerBridged
                } else {
                    BackendExecutionMode::ExternalChatOnly
                }
            }
            _ => BackendExecutionMode::ManagedBrokerTools,
        };
        let thinking = if cp.effect_ledger.accumulated_thoughts.is_empty() {
            None
        } else {
            Some(cp.effect_ledger.accumulated_thoughts.join("\n\n"))
        };
        let mut final_dots: Vec<TraceDot> = Vec::new();
        if let Some(ref th) = thinking
            && !th.trim().is_empty()
        {
            final_dots.push(TraceDot::thinking(th.clone()));
        }
        if let Some(ref mdot) = cp.memory_dot
            && !cp
                .effect_ledger
                .trace_dots
                .iter()
                .any(|d| d.kind == "memory")
        {
            final_dots.push(mdot.clone());
        }
        final_dots.extend(cp.effect_ledger.trace_dots.clone());
        final_dots.push(denied_dot);

        if !cp.incognito {
            core.sessions.append_turn(
                &cp.session.session_id,
                &cp.user_text,
                session_reply_text,
                cp.effect_ledger.last_resource_path.clone(),
            );
            let dots_val = serde_json::to_value(&final_dots)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            let _ = crate::memory_hub::record_conversation_turn(
                core,
                &crate::memory_hub::RecordTurnInput {
                    session_id: Some(cp.session.session_id.clone()),
                    user_text: cp.user_text,
                    assistant_text: session_reply_text.to_string(),
                    thinking: thinking.clone(),
                    tool_steps: cp.effect_ledger.tool_steps_json.clone(),
                    trace_dots: dots_val,
                    incognito: false,
                },
            );
        }

        let mut resp = json!({
            "turn_id": resume_turn_id,
            "task_id": cp.task_id,
            "session_id": cp.session.session_id,
            "status": "completed",
            "approval_resolved": "denied",
            "execution_mode": exec_mode,
            "side_effect_replay_prevented": false,
            "effect_ledger": cp.effect_ledger.summary_json(),
            "backend_used": cp.active.backend,
            "provider_used": cp.active.provider,
            "model_used": cp.active.model,
            "reasoning_effort": cp.active.reasoning_effort,
            "thinking": thinking,
            "reply_markdown": display_reply_text,
            "reply": display_reply_text,
            "trace_dots": final_dots,
            "tool_steps": cp.effect_ledger.tool_steps_json,
            "memory_hits": cp.memory_hits,
            "adapter_actions": cp.effect_ledger.adapter_actions,
            "changeset_ids": cp.effect_ledger.committed_changeset_ids(),
            "handoff_command": Value::Null,
            "pending_approval": Value::Null,
            "context_compression": cp.context_compression,
        });
        scrub_json_secrets(&mut resp);
        return Ok(resp);
    }

    let sid = denied_task
        .as_ref()
        .and_then(|t| t.session_id.clone())
        .or_else(|| {
            payload
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .unwrap_or_else(|| core.sessions.get_or_create(None).session_id);
    let incognito = sid.starts_with("incog_")
        || denied_task
            .as_ref()
            .is_some_and(|t| t.id.starts_with("incog_"));
    let user_goal = denied_task
        .as_ref()
        .map(|t| t.goal.clone())
        .unwrap_or_default();
    let final_dots = vec![denied_dot];

    if !incognito && !user_goal.trim().is_empty() {
        core.sessions
            .append_turn(&sid, &user_goal, session_reply_text, None);
        let dots_val = serde_json::to_value(&final_dots)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        let _ = crate::memory_hub::record_conversation_turn(
            core,
            &crate::memory_hub::RecordTurnInput {
                session_id: Some(sid.clone()),
                user_text: user_goal,
                assistant_text: session_reply_text.to_string(),
                thinking: None,
                tool_steps: Vec::new(),
                trace_dots: dots_val,
                incognito: false,
            },
        );
    }

    let session_obj = core.sessions.get_or_create(Some(&sid));
    let cc_stats =
        crate::memory_hub::build_compressed_session_history(core, &session_obj, incognito).stats;
    let empty_ledger = TurnEffectLedger::new(resume_turn_id);
    let mut resp = json!({
        "turn_id": resume_turn_id,
        "task_id": denied_task.as_ref().map(|t| t.id.clone()).unwrap_or_default(),
        "session_id": sid,
        "status": "completed",
        "approval_resolved": "denied",
        "execution_mode": BackendExecutionMode::OfflineCore,
        "side_effect_replay_prevented": false,
        "effect_ledger": empty_ledger.summary_json(),
        "backend_used": "intentos-core",
        "provider_used": "intentos-core",
        "model_used": "policy",
        "reasoning_effort": "default",
        "thinking": Value::Null,
        "reply_markdown": display_reply_text,
        "reply": display_reply_text,
        "trace_dots": final_dots,
        "tool_steps": [],
        "memory_hits": [],
        "adapter_actions": [],
        "changeset_ids": [],
        "handoff_command": Value::Null,
        "pending_approval": Value::Null,
        "context_compression": cc_stats,
    });
    scrub_json_secrets(&mut resp);
    Ok(resp)
}
