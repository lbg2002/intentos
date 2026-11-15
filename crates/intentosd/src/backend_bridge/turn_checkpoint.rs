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
    BackendExecutionMode, TraceDot, extract_approval_grant_target,
    record_approved_step_into_ledger, supplement_approved_dir_file_search,
};
use crate::backend_bridge::detector::{
    ActiveBackendSelection, DiscoveredBackend, DiscoveryOptions, lookup_ephemeral_backend_key,
    scrub_json_secrets,
};
use crate::backend_bridge::providers_cli::continue_resumed_cli_turn;
use crate::backend_bridge::providers_http::{
    continue_resumed_anthropic_turn, continue_resumed_openai_turn,
};
use crate::broker::BrokerDispatchOutcome;
use crate::core::IntentOsCore;
pub use crate::db::StepExecState;
use crate::db::{StateDb, StepExecutionLogRow, SuspendedCheckpointRow};
use crate::runtime::SessionState;
use crate::security_guard::{PrivacySessionPolicy, SensitiveDataGuard, UnifiedTaskStateMachine};
use chrono::{DateTime, Utc};
use intentos_protocol::{
    CapabilityCall, ChatMessage, ContextBlock, DataClass, Effect, ExecutionStatus,
    InvocationOrigin, PendingApproval, PolicyDecision, ProviderTrust, RouteLayer, Taint, Task,
    TaskBudget, TaskStatus, TaskStep, TaskTrigger,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

fn is_untrusted_step_meta_key(key: &str) -> bool {
    matches!(
        key,
        "step_id" | "_step_id" | "__step_id" | "attempt_id" | "_attempt_id" | "idempotency_key"
    )
}

fn is_path_argument_key(key: &str) -> bool {
    matches!(
        key,
        "path"
            | "target"
            | "source"
            | "destination"
            | "dest"
            | "directory"
            | "dir"
            | "repo_dir"
            | "output"
            | "out_dir"
            | "left"
            | "right"
            | "file"
            | "file_path"
            | "input"
            | "archive_path"
    )
}

fn is_path_array_argument_key(key: &str) -> bool {
    matches!(key, "paths" | "files" | "sources")
}

/// Normalize filesystem paths (`~` expansion + lexical `.`, `..`, duplicate `/`, and trailing `/`
/// cleanup) while leaving URLs (`https://...`) and plain identifiers untouched.
pub fn normalize_path_for_dedup(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("://") {
        return trimmed.to_string();
    }
    let looks_like_path = trimmed.starts_with('/')
        || trimmed == "~"
        || trimmed.starts_with("~/")
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.contains('/');
    if !looks_like_path {
        return trimmed.to_string();
    }

    let expanded = if trimmed == "~" {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(trimmed))
    } else if let Some(rest) = trimmed.strip_prefix("~/") {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(rest))
            .unwrap_or_else(|_| PathBuf::from(trimmed))
    } else {
        PathBuf::from(trimmed)
    };

    let mut is_abs = false;
    let mut prefix: Option<String> = None;
    let mut segments: Vec<String> = Vec::new();

    for comp in Path::new(&expanded).components() {
        match comp {
            Component::Prefix(p) => {
                prefix = Some(p.as_os_str().to_string_lossy().to_string());
            }
            Component::RootDir => {
                is_abs = true;
                segments.clear();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if let Some(last) = segments.last()
                    && last != ".."
                {
                    segments.pop();
                } else if !is_abs {
                    segments.push("..".to_string());
                }
            }
            Component::Normal(seg) => {
                segments.push(seg.to_string_lossy().to_string());
            }
        }
    }

    let mut out = String::new();
    if let Some(p) = prefix {
        out.push_str(&p);
    }
    if is_abs {
        out.push('/');
    }
    out.push_str(&segments.join("/"));
    if out.is_empty() { ".".to_string() } else { out }
}

/// Strip untrusted model-supplied step identity fields and normalize path values in a JSON `Value`.
pub fn sanitize_and_normalize_tool_args(v: &Value) -> Value {
    fn normalize_inner(v: &Value, is_root: bool) -> Value {
        match v {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, val) in map {
                    if is_root && is_untrusted_step_meta_key(k.as_str()) {
                        continue;
                    }
                    let normalized_val = if is_path_argument_key(k.as_str()) {
                        if let Some(s) = val.as_str() {
                            Value::String(normalize_path_for_dedup(s))
                        } else {
                            normalize_inner(val, false)
                        }
                    } else if is_path_array_argument_key(k.as_str()) {
                        if let Some(arr) = val.as_array() {
                            Value::Array(
                                arr.iter()
                                    .map(|item| {
                                        if let Some(s) = item.as_str() {
                                            Value::String(normalize_path_for_dedup(s))
                                        } else {
                                            normalize_inner(item, false)
                                        }
                                    })
                                    .collect(),
                            )
                        } else {
                            normalize_inner(val, false)
                        }
                    } else {
                        normalize_inner(val, false)
                    };
                    out.insert(k.clone(), normalized_val);
                }
                Value::Object(out)
            }
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(|item| normalize_inner(item, false))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
    normalize_inner(v, true)
}

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

/// Canonicalize tool arguments (`Value`) with untrusted step-meta stripping, path normalization,
/// and deterministic lexicographical JSON key ordering.
pub fn canonicalize_tool_args_value(v: &Value) -> String {
    let normalized = sanitize_and_normalize_tool_args(v);
    canonicalize_json_value(&normalized)
}

/// Canonicalize a raw JSON string if valid JSON (including path normalization and meta-key stripping),
/// otherwise return trimmed raw string.
pub fn canonicalize_json_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        canonicalize_tool_args_value(&val)
    } else {
        trimmed.to_string()
    }
}

/// Capability-semantic idempotency policy derived deterministically by the trusted broker bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolIdempotencyPolicy {
    /// Live environment/status/memory/app-inspect reads (`*.get`, `*.list`, `*.status`, `*.inspect`,
    /// `network.ip`, `disk.free`, `memory_*`, `app_adapter_inspect_app`). Fresh on each logical step;
    /// deduplicates only exact retries of the same `(step_id, attempt_id)`.
    AlwaysRefresh,
    /// Deterministic search (`file.search`, `app.search`, `package.search`). Cached within the
    /// current `state_epoch`, immediately invalidated when any tool with `effect > Effect::Observe` executes.
    CacheUntilStateChanged,
    /// Absolute state setters (`sound.volume.set` without `relative`, `display.brightness.set` without
    /// `relative`, `notify.dnd.set`, `appearance.*`, `power.profile.set`). Deduplicates identical
    /// `(capability_id, canonical_args, state_epoch)` when the prior outcome succeeded.
    IdempotentMutation,
    /// Relative, stateful, or sequential actions (`sound.volume.set` with `relative`, `media.control`,
    /// `app.launch`, `app.quit`, `file.move`, `file.rename`, `file.copy`, `file.write`, `file.trash`,
    /// `archive.*`, `app_adapter_invoke`). Distinct steps both execute; replaying the same trusted
    /// `step_id` executes at most once.
    ExactlyOncePerStep,
    /// High-risk/session/destructive operations (`process.terminate`, `power.session`, `screen.lock`, etc.)
    /// that must never be automatically replayed.
    NeverReplay,
}

/// Trusted step invocation identity separating logical `step_id`, transport `call_id`, and `attempt_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepInvocationContext {
    /// Trusted `step_id` allocated by `TurnEffectLedger` (NEVER accepted from untrusted model JSON!).
    /// When `None`, `TurnEffectLedger` allocates the next sequential `step_<N>`.
    pub trusted_step_id: Option<String>,
    /// Transport protocol call identifier (`tool_call_id` / XML `call_id`).
    pub call_id: String,
    /// Execution attempt within the logical step (`attempt_1`, `attempt_2`, ...).
    pub attempt_id: String,
}

impl StepInvocationContext {
    /// Create context for a new model tool call (`trusted_step_id: None`, `attempt_id: "attempt_1"`).
    pub fn new_call(call_id: impl Into<String>) -> Self {
        Self {
            trusted_step_id: None,
            call_id: call_id.into(),
            attempt_id: "attempt_1".to_string(),
        }
    }

    /// Create context for an explicit trusted replay/retry of `step_id`.
    pub fn for_trusted_step(
        step_id: impl Into<String>,
        call_id: impl Into<String>,
        attempt_id: impl Into<String>,
    ) -> Self {
        Self {
            trusted_step_id: Some(step_id.into()),
            call_id: call_id.into(),
            attempt_id: attempt_id.into(),
        }
    }
}

fn default_step_exec_state() -> StepExecState {
    StepExecState::Verified
}

/// Rich per-step metadata tracked alongside `StepExecutionRecord` inside `TurnEffectLedger`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecutionMeta {
    pub step_id: String,
    pub call_id: String,
    pub attempt_id: String,
    pub policy: ToolIdempotencyPolicy,
    pub pre_state_epoch: u64,
    pub post_state_epoch: u64,
    #[serde(default = "default_step_exec_state")]
    pub exec_state: StepExecState,
    pub is_error: bool,
    pub was_denied: bool,
    pub verification_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_hint: Option<String>,
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

impl StepExecutionRecord {
    /// True when the recorded execution failed or was denied (`!self.succeeded`).
    pub fn is_error(&self) -> bool {
        !self.succeeded
    }

    /// True when the step was rejected by `PolicyEngine` / `SafeFsEngine` (`Denied`).
    pub fn was_denied(&self) -> bool {
        self.verification_status.eq_ignore_ascii_case("denied")
            || self
                .cached_output
                .get("was_denied")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
    }
}

/// Decision produced by `TurnEffectLedger::evaluate_idempotency`.
pub enum IdempotencyDecision<'a> {
    Proceed,
    CachedHit {
        record: &'a StepExecutionRecord,
        meta: Option<&'a StepExecutionMeta>,
        reason: &'static str,
    },
    StepIdentityConflict {
        step_id: String,
        existing_capability: String,
    },
}

/// Per-turn side-effect ledger and runtime progress buffer.
///
/// Tracks every tool invocation's trusted `step_id`, `attempt_id`, `state_epoch`, and
/// `ToolIdempotencyPolicy`, deduplicates according to capability semantics, invalidates
/// read caches upon state mutation, and prevents fallback side-effect replay!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnEffectLedger {
    pub turn_id: String,
    next_step_seq: usize,
    #[serde(default)]
    state_epoch: u64,
    records: Vec<StepExecutionRecord>,
    #[serde(default)]
    step_metadata: Vec<StepExecutionMeta>,
    #[serde(skip)]
    by_idempotency_key: HashMap<String, usize>,

    #[serde(default)]
    privacy: PrivacySessionPolicy,
    #[serde(default)]
    privacy_explicit: bool,
    #[serde(default)]
    bound_task_id: Option<String>,
    #[serde(default)]
    bound_session_id: Option<String>,
    #[serde(default)]
    pub(crate) pending_approval_step_id: Option<String>,
    #[serde(skip)]
    state_db: Option<Arc<StateDb>>,

    // Runtime progress buffers preserved across mid-turn backend failures and checkpoints:
    #[serde(default)]
    pub trace_dots: Vec<TraceDot>,
    #[serde(default)]
    pub adapter_actions: Vec<Value>,
    #[serde(default)]
    pub tool_steps_json: Vec<Value>,
    #[serde(default)]
    pub task_steps: Vec<TaskStep>,
    #[serde(default)]
    pub changeset_ids: Vec<String>,
    #[serde(default)]
    pub accumulated_thoughts: Vec<String>,
    #[serde(default)]
    pub last_resource_path: Option<String>,
}

impl TurnEffectLedger {
    pub fn new(turn_id: impl Into<String>) -> Self {
        Self {
            turn_id: turn_id.into(),
            next_step_seq: 0,
            state_epoch: 0,
            records: Vec::new(),
            step_metadata: Vec::new(),
            by_idempotency_key: HashMap::new(),
            privacy: PrivacySessionPolicy::Standard,
            privacy_explicit: false,
            bound_task_id: None,
            bound_session_id: None,
            pending_approval_step_id: None,
            state_db: None,
            trace_dots: Vec::new(),
            adapter_actions: Vec::new(),
            tool_steps_json: Vec::new(),
            task_steps: Vec::new(),
            changeset_ids: Vec::new(),
            accumulated_thoughts: Vec::new(),
            last_resource_path: None,
        }
    }

    pub fn with_privacy(mut self, privacy: PrivacySessionPolicy) -> Self {
        self.privacy = privacy;
        self.privacy_explicit = true;
        self
    }

    pub fn set_privacy(&mut self, privacy: PrivacySessionPolicy) {
        self.privacy = privacy;
        self.privacy_explicit = true;
    }

    pub fn privacy(&self) -> PrivacySessionPolicy {
        self.privacy
    }

    /// Explicitly bind SQLite `StateDb`, `task_id`, `session_id`, and `PrivacySessionPolicy`
    /// onto this ledger (`H03` / `H05` / `H06`).
    pub fn bind_persistence(
        &mut self,
        state_db: Arc<StateDb>,
        task_id: impl Into<String>,
        session_id: impl Into<String>,
        privacy: PrivacySessionPolicy,
    ) {
        self.state_db = Some(state_db);
        self.bound_task_id = Some(task_id.into());
        self.bound_session_id = Some(session_id.into());
        self.privacy = privacy;
        self.privacy_explicit = true;
    }

    /// Ensure `state_db`, `task_id`, and `session_id` are attached, applying `fallback_privacy`
    /// only when no explicit `PrivacySessionPolicy` was set via `set_privacy` / `bind_persistence`.
    pub fn ensure_persistence_context(
        &mut self,
        state_db: Arc<StateDb>,
        task_id: &str,
        session_id: &str,
        fallback_privacy: PrivacySessionPolicy,
    ) {
        self.state_db = Some(state_db);
        self.bound_task_id = Some(task_id.to_string());
        self.bound_session_id = Some(session_id.to_string());
        if !self.privacy_explicit {
            self.privacy = fallback_privacy;
        }
    }

    pub fn state_db(&self) -> Option<&Arc<StateDb>> {
        self.state_db.as_ref()
    }

    pub fn bound_task_id(&self) -> Option<&str> {
        self.bound_task_id.as_deref()
    }

    pub fn bound_session_id(&self) -> Option<&str> {
        self.bound_session_id.as_deref()
    }

    pub fn rebuild_indexes(&mut self) {
        self.by_idempotency_key.clear();
        for (idx, rec) in self.records.iter().enumerate() {
            self.by_idempotency_key
                .insert(rec.idempotency_key.clone(), idx);
        }
    }

    /// Current monotonic `state_epoch` within this turn (incremented whenever `effect > Effect::Observe` executes).
    pub fn state_epoch(&self) -> u64 {
        self.state_epoch
    }

    /// Advance `state_epoch` to invalidate `CacheUntilStateChanged` and prior `IdempotentMutation` epochs.
    pub fn bump_state_epoch(&mut self) -> u64 {
        self.state_epoch += 1;
        self.state_epoch
    }

    /// Allocate the next deterministic trusted `step_id` (`step_1`, `step_2`, ...).
    pub fn next_step_id(&mut self) -> String {
        self.next_step_seq += 1;
        format!("step_{}", self.next_step_seq)
    }

    /// Compute deterministic SHA-256 `idempotency_key` from `turn_id + capability_id + canonical_args_json`
    /// (with JSON key sorting and path normalization).
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

    /// Compute a policy-scoped SHA-256 `idempotency_key` binding `turn_id`, `policy`, and the
    /// relevant step/attempt/epoch scope.
    pub fn compute_step_idempotency_key(
        &self,
        policy: ToolIdempotencyPolicy,
        step_id: &str,
        attempt_id: &str,
        capability_id: &str,
        canonical_args_json: &str,
        epoch: u64,
    ) -> String {
        let canonical = canonicalize_json_str(canonical_args_json);
        let mut hasher = Sha256::new();
        hasher.update(self.turn_id.as_bytes());
        hasher.update(b":");
        match policy {
            ToolIdempotencyPolicy::AlwaysRefresh => {
                hasher.update(b"always_refresh:");
                hasher.update(step_id.as_bytes());
                hasher.update(b":");
                hasher.update(attempt_id.as_bytes());
            }
            ToolIdempotencyPolicy::CacheUntilStateChanged => {
                hasher.update(b"cache_epoch:");
                hasher.update(epoch.to_string().as_bytes());
            }
            ToolIdempotencyPolicy::IdempotentMutation => {
                hasher.update(b"idempotent_mutation:");
                hasher.update(epoch.to_string().as_bytes());
            }
            ToolIdempotencyPolicy::ExactlyOncePerStep => {
                hasher.update(b"once_per_step:");
                hasher.update(step_id.as_bytes());
            }
            ToolIdempotencyPolicy::NeverReplay => {
                hasher.update(b"never_replay:");
                hasher.update(step_id.as_bytes());
            }
        }
        hasher.update(b":");
        hasher.update(capability_id.as_bytes());
        hasher.update(b":");
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Evaluate whether an incoming tool invocation should execute fresh (`Proceed`), return a
    /// cached outcome (`CachedHit`), or reject a conflicting `trusted_step_id` (`StepIdentityConflict`).
    pub fn evaluate_idempotency(
        &self,
        policy: ToolIdempotencyPolicy,
        trusted_step_id: Option<&str>,
        attempt_id: &str,
        capability_id: &str,
        canonical_args_json: &str,
    ) -> IdempotencyDecision<'_> {
        let canonical = canonicalize_json_str(canonical_args_json);

        // 1. Explicit trusted `step_id` replay / retry evaluation
        if let Some(sid) = trusted_step_id.map(str::trim).filter(|s| !s.is_empty()) {
            let matching: Vec<(usize, &StepExecutionRecord, Option<&StepExecutionMeta>)> = self
                .records
                .iter()
                .enumerate()
                .filter(|(_, r)| r.step_id == sid)
                .map(|(i, r)| (i, r, self.step_metadata.get(i)))
                .collect();

            if let Some((_, first_rec, _)) = matching.first() {
                if first_rec.capability_id != capability_id
                    || canonicalize_json_str(&first_rec.canonical_args_json) != canonical
                {
                    return IdempotencyDecision::StepIdentityConflict {
                        step_id: sid.to_string(),
                        existing_capability: first_rec.capability_id.clone(),
                    };
                }

                // Exact `(step_id, attempt_id)` transport duplicate -> always return cached hit!
                if let Some((_, rec, meta)) = matching
                    .iter()
                    .rev()
                    .find(|(_, _, m)| m.is_some_and(|meta| meta.attempt_id == attempt_id))
                {
                    return IdempotencyDecision::CachedHit {
                        record: rec,
                        meta: *meta,
                        reason: "exact_step_attempt_replay",
                    };
                }

                // New attempt_id for an already-attempted trusted `step_id`:
                let (_, last_rec, last_meta) = *matching.last().unwrap();
                if last_rec.succeeded {
                    return IdempotencyDecision::CachedHit {
                        record: last_rec,
                        meta: last_meta,
                        reason: "step_already_succeeded",
                    };
                }
                if last_rec.was_denied() {
                    return IdempotencyDecision::CachedHit {
                        record: last_rec,
                        meta: last_meta,
                        reason: "step_policy_denied",
                    };
                }
                if last_meta.is_some_and(|m| m.exec_state.is_uncertain_or_recovery()) {
                    return IdempotencyDecision::CachedHit {
                        record: last_rec,
                        meta: last_meta,
                        reason: "uncertain_side_effect_halt",
                    };
                }

                return match policy {
                    ToolIdempotencyPolicy::AlwaysRefresh
                    | ToolIdempotencyPolicy::CacheUntilStateChanged => {
                        // Allow at most 1 retry (total 2 attempts) on transient read-only errors
                        if matching.len() < 2 {
                            IdempotencyDecision::Proceed
                        } else {
                            IdempotencyDecision::CachedHit {
                                record: last_rec,
                                meta: last_meta,
                                reason: "read_retry_exhausted",
                            }
                        }
                    }
                    ToolIdempotencyPolicy::IdempotentMutation
                    | ToolIdempotencyPolicy::ExactlyOncePerStep
                    | ToolIdempotencyPolicy::NeverReplay => IdempotencyDecision::CachedHit {
                        record: last_rec,
                        meta: last_meta,
                        reason: "mutation_step_no_blind_replay",
                    },
                };
            }
        }

        // 2. Policy denial cache within the current `state_epoch`: never flip a denied call to ok
        //    or allow loop-hammering a forbidden scope when no state/approval epoch changed.
        for (idx, rec) in self.records.iter().enumerate().rev() {
            let meta = self.step_metadata.get(idx);
            let epoch_matches = meta.is_none_or(|m| m.post_state_epoch == self.state_epoch);
            if epoch_matches
                && rec.capability_id == capability_id
                && canonicalize_json_str(&rec.canonical_args_json) == canonical
                && rec.was_denied()
            {
                return IdempotencyDecision::CachedHit {
                    record: rec,
                    meta,
                    reason: "cached_policy_denial",
                };
            }
        }

        // 3. Policy-semantic cross-step evaluation
        match policy {
            ToolIdempotencyPolicy::AlwaysRefresh => IdempotencyDecision::Proceed,

            ToolIdempotencyPolicy::CacheUntilStateChanged => {
                let mut transient_failures_in_epoch = 0usize;
                for (idx, rec) in self.records.iter().enumerate().rev() {
                    let meta = self.step_metadata.get(idx);
                    let in_epoch = meta.is_none_or(|m| m.post_state_epoch == self.state_epoch);
                    if !in_epoch {
                        continue;
                    }
                    if rec.capability_id == capability_id
                        && canonicalize_json_str(&rec.canonical_args_json) == canonical
                    {
                        if rec.succeeded {
                            return IdempotencyDecision::CachedHit {
                                record: rec,
                                meta,
                                reason: "cache_until_state_changed",
                            };
                        }
                        transient_failures_in_epoch += 1;
                        if transient_failures_in_epoch >= 2 {
                            return IdempotencyDecision::CachedHit {
                                record: rec,
                                meta,
                                reason: "read_retry_exhausted",
                            };
                        }
                    }
                }
                IdempotencyDecision::Proceed
            }

            ToolIdempotencyPolicy::IdempotentMutation => {
                for (idx, rec) in self.records.iter().enumerate().rev() {
                    let meta = self.step_metadata.get(idx);
                    let in_epoch = meta.is_none_or(|m| m.post_state_epoch == self.state_epoch);
                    if !in_epoch {
                        continue;
                    }
                    if rec.capability_id == capability_id
                        && canonicalize_json_str(&rec.canonical_args_json) == canonical
                    {
                        return IdempotencyDecision::CachedHit {
                            record: rec,
                            meta,
                            reason: if rec.succeeded {
                                "idempotent_mutation_dedup"
                            } else {
                                "failed_mutation_no_blind_replay"
                            },
                        };
                    }
                }
                IdempotencyDecision::Proceed
            }

            ToolIdempotencyPolicy::ExactlyOncePerStep => IdempotencyDecision::Proceed,

            ToolIdempotencyPolicy::NeverReplay => {
                for (idx, rec) in self.records.iter().enumerate().rev() {
                    if rec.capability_id == capability_id
                        && canonicalize_json_str(&rec.canonical_args_json) == canonical
                    {
                        return IdempotencyDecision::CachedHit {
                            record: rec,
                            meta: self.step_metadata.get(idx),
                            reason: "never_replay_policy",
                        };
                    }
                }
                IdempotencyDecision::Proceed
            }
        }
    }

    /// Look up an existing step execution by `idempotency_key`.
    pub fn lookup_idempotent(&self, idempotency_key: &str) -> Option<&StepExecutionRecord> {
        if let Some(&idx) = self.by_idempotency_key.get(idempotency_key) {
            return self.records.get(idx);
        }
        self.records
            .iter()
            .find(|r| r.idempotency_key == idempotency_key)
    }

    /// Look up the latest `StepExecutionRecord` for a trusted `step_id`.
    pub fn lookup_step(&self, step_id: &str) -> Option<&StepExecutionRecord> {
        self.records.iter().rev().find(|r| r.step_id == step_id)
    }

    /// Record a step alongside explicit `StepExecutionMeta`.
    pub fn record_step_with_meta(
        &mut self,
        mut record: StepExecutionRecord,
        meta: StepExecutionMeta,
    ) {
        record.canonical_args_json = canonicalize_json_str(&record.canonical_args_json);
        if let Some(ref csid) = record.changeset_id
            && !self.changeset_ids.contains(csid)
        {
            self.changeset_ids.push(csid.clone());
        }
        let idx = self.records.len();
        self.by_idempotency_key
            .insert(record.idempotency_key.clone(), idx);
        self.records.push(record);
        self.step_metadata.push(meta);
    }

    /// Record a completed or denied tool execution step into the ledger (compatibility entry point).
    pub fn record_step(&mut self, record: StepExecutionRecord) {
        let pre_epoch = self.state_epoch;
        if record.effect > Effect::Observe && record.mutated_state {
            self.bump_state_epoch();
        }
        let post_epoch = self.state_epoch;
        let default_policy = if record.effect == Effect::Observe {
            ToolIdempotencyPolicy::AlwaysRefresh
        } else {
            ToolIdempotencyPolicy::IdempotentMutation
        };
        let exec_state = if record.was_denied() {
            StepExecState::Denied
        } else if record.succeeded {
            if record
                .verification_status
                .eq_ignore_ascii_case("requestedunverified")
            {
                StepExecState::Applied
            } else {
                StepExecState::Verified
            }
        } else if record.effect > Effect::Observe
            && record
                .verification_status
                .eq_ignore_ascii_case("verificationfailed")
        {
            StepExecState::Unknown
        } else {
            StepExecState::FailedClean
        };
        let meta = StepExecutionMeta {
            step_id: record.step_id.clone(),
            call_id: record.step_id.clone(),
            attempt_id: "attempt_1".to_string(),
            policy: default_policy,
            pre_state_epoch: pre_epoch,
            post_state_epoch: post_epoch,
            exec_state,
            is_error: record.is_error(),
            was_denied: record.was_denied(),
            verification_status: record.verification_status.clone(),
            recovery_hint: None,
        };
        self.record_step_with_meta(record, meta);
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

    /// Returns `true` if ANY mutating step entered `Executing` and finished in an unconfirmed/failed
    /// side-effect state (`Executing`, `Unknown`, or `RecoveryRequired`).
    pub fn has_uncertain_side_effects(&self) -> bool {
        self.step_metadata
            .iter()
            .zip(self.records.iter())
            .any(|(m, r)| r.effect > Effect::Observe && m.exec_state.is_uncertain_or_recovery())
    }

    /// Returns `true` if ANY step with `effect > Effect::Observe` either committed (`Verified` / `Applied`)
    /// OR entered an uncertain side-effect state (`Executing` / `Unknown` / `RecoveryRequired`)!
    pub fn has_uncertain_or_committed_side_effects(&self) -> bool {
        self.records.iter().any(|r| r.mutated_state)
            || self
                .step_metadata
                .iter()
                .zip(self.records.iter())
                .any(|(m, r)| {
                    r.effect > Effect::Observe
                        && m.exec_state.has_potential_or_committed_side_effect()
                })
    }

    /// Returns `true` if ANY step with `effect > Effect::Observe` has committed OR entered an uncertain
    /// side-effect state (preventing whole-turn fallback replay across `turn_engine` and `runtime`).
    pub fn has_committed_side_effects(&self) -> bool {
        self.has_uncertain_or_committed_side_effects()
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

    pub fn step_metadata(&self) -> &[StepExecutionMeta] {
        &self.step_metadata
    }

    /// Export a structured JSON summary of this turn's effect ledger for UI & audit diagnostics.
    pub fn summary_json(&self) -> Value {
        json!({
            "turn_id": self.turn_id,
            "privacy": self.privacy,
            "state_epoch": self.state_epoch,
            "total_steps": self.records.len(),
            "mutated_steps": self.records.iter().filter(|r| r.mutated_state).count(),
            "has_uncertain_side_effects": self.has_uncertain_side_effects(),
            "has_uncertain_or_committed_side_effects": self.has_uncertain_or_committed_side_effects(),
            "has_committed_side_effects": self.has_committed_side_effects(),
            "committed_changeset_ids": self.committed_changeset_ids(),
            "steps": self.records,
            "step_metadata": self.step_metadata,
        })
    }
}

/// TTL for cached completed turn outcomes (`IdempotentReplay`).
pub const COMPLETED_TURN_CACHE_TTL: Duration = Duration::from_secs(300);
/// Maximum number of completed turn outcomes retained in memory.
pub const MAX_COMPLETED_TURN_CACHE: usize = 64;
/// TTL for cancelled turn tombstones (`PreCancelled`).
pub const CANCELLED_TURN_CACHE_TTL: Duration = Duration::from_secs(600);
/// Maximum number of cancelled turn tombstones retained in memory.
pub const MAX_CANCELLED_TURN_CACHE: usize = 128;

const LEGACY_WILDCARD_SESSION: &str = "__legacy_wildcard__";
const ANONYMOUS_SESSION_SENTINEL: &str = "__anonymous__";

/// Unified lifecycle states for a registered turn in `TurnRegistry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnLifecycleState {
    Running,
    PausedApproval,
    Finished,
    Cancelled,
}

/// Request identity bound to a `turn_id` to prevent cross-session cache mixing,
/// payload tampering on replay, or duplicate concurrent execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnIdentity {
    pub turn_id: String,
    pub session_id: String,
    pub request_digest: String,
    pub model_key: String,
    pub execution_mode: String,
    pub privacy: PrivacySessionPolicy,
}

/// Compute a deterministic SHA-256 hex digest binding normalized `user_text`,
/// optional `clipboard`, and `allow_broker_tools`.
pub fn compute_request_digest(
    user_text: &str,
    clipboard: Option<&str>,
    allow_broker_tools: bool,
) -> String {
    let norm_text = user_text.trim();
    let norm_clip = clipboard
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("");
    let canonical = canonicalize_json_value(&json!({
        "allow_broker_tools": allow_broker_tools,
        "clipboard": norm_clip,
        "user_text": norm_text,
    }));
    let mut hasher = Sha256::new();
    hasher.update(b"turn_req_v1:");
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

impl TurnIdentity {
    pub fn new(
        turn_id: impl Into<String>,
        session_id: impl Into<String>,
        request_digest: impl Into<String>,
        model_key: impl Into<String>,
        execution_mode: impl Into<String>,
        privacy: PrivacySessionPolicy,
    ) -> Self {
        Self {
            turn_id: turn_id.into(),
            session_id: session_id.into(),
            request_digest: request_digest.into(),
            model_key: model_key.into(),
            execution_mode: execution_mode.into(),
            privacy,
        }
    }

    /// Build a `TurnIdentity` from raw request parameters. When `explicit_session_id` is omitted
    /// (`None` or empty), binds to a canonical anonymous sentinel so anonymous retries of the
    /// identical payload match each other while never matching an explicit `session_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_request(
        turn_id: impl Into<String>,
        explicit_session_id: Option<&str>,
        user_text: &str,
        clipboard: Option<&str>,
        allow_broker_tools: bool,
        model_key: impl Into<String>,
        execution_mode: impl Into<String>,
        privacy: PrivacySessionPolicy,
    ) -> Self {
        let sid = explicit_session_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(ANONYMOUS_SESSION_SENTINEL)
            .to_string();
        Self {
            turn_id: turn_id.into(),
            session_id: sid,
            request_digest: compute_request_digest(user_text, clipboard, allow_broker_tools),
            model_key: model_key.into(),
            execution_mode: execution_mode.into(),
            privacy,
        }
    }

    /// Returns `Some(reason)` when `incoming` attempts to reuse `self.turn_id` with a mismatched
    /// `session_id`, `privacy`, `request_digest`, `model_key`, or `execution_mode`.
    pub fn conflict_reason(&self, incoming: &TurnIdentity) -> Option<String> {
        if self.session_id != LEGACY_WILDCARD_SESSION
            && incoming.session_id != LEGACY_WILDCARD_SESSION
            && self.session_id != incoming.session_id
        {
            return Some(format!(
                "turn_id '{}' is already bound to a different session_id",
                self.turn_id
            ));
        }
        if self.privacy != incoming.privacy {
            return Some(format!(
                "turn_id '{}' is already bound to privacy policy {:?} (got {:?})",
                self.turn_id, self.privacy, incoming.privacy
            ));
        }
        if !self.request_digest.is_empty()
            && !incoming.request_digest.is_empty()
            && self.request_digest != incoming.request_digest
        {
            return Some(format!(
                "turn_id '{}' is already bound to a different request_digest",
                self.turn_id
            ));
        }
        if !self.model_key.is_empty()
            && !incoming.model_key.is_empty()
            && self.model_key != incoming.model_key
        {
            return Some(format!(
                "turn_id '{}' is already bound to model_key '{}' (got '{}')",
                self.turn_id, self.model_key, incoming.model_key
            ));
        }
        if !self.execution_mode.is_empty()
            && !incoming.execution_mode.is_empty()
            && self.execution_mode != incoming.execution_mode
        {
            return Some(format!(
                "turn_id '{}' is already bound to execution_mode '{}' (got '{}')",
                self.turn_id, self.execution_mode, incoming.execution_mode
            ));
        }
        None
    }
}

/// Active turn ownership, cancellation & completion-coalescing handle.
pub struct ActiveTurnHandle {
    pub instance_seq: u64,
    pub identity: TurnIdentity,
    pub turn_id: String,
    pub session_id: Option<String>,
    pub task_id: Mutex<Option<String>>,
    cancelled: AtomicBool,
    aborted: AtomicBool,
    lifecycle: Mutex<TurnLifecycleState>,
    terminal_result: Mutex<Option<Value>>,
    notify: Notify,
    pub started_at: Instant,
}

impl ActiveTurnHandle {
    pub fn new(turn_id: String, session_id: Option<String>) -> Self {
        let privacy = PrivacySessionPolicy::from_session(false, session_id.as_deref());
        let identity = TurnIdentity {
            turn_id: turn_id.clone(),
            session_id: session_id
                .clone()
                .unwrap_or_else(|| ANONYMOUS_SESSION_SENTINEL.to_string()),
            request_digest: String::new(),
            model_key: String::new(),
            execution_mode: String::new(),
            privacy,
        };
        Self::new_registered(0, identity, session_id, Instant::now())
    }

    fn new_registered(
        instance_seq: u64,
        identity: TurnIdentity,
        session_override: Option<String>,
        started_at: Instant,
    ) -> Self {
        let turn_id = identity.turn_id.clone();
        let session_id = session_override.or_else(|| {
            if identity.session_id == LEGACY_WILDCARD_SESSION
                || identity.session_id == ANONYMOUS_SESSION_SENTINEL
                || identity.session_id.is_empty()
            {
                None
            } else {
                Some(identity.session_id.clone())
            }
        });
        Self {
            instance_seq,
            identity,
            turn_id,
            session_id,
            task_id: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
            lifecycle: Mutex::new(TurnLifecycleState::Running),
            terminal_result: Mutex::new(None),
            notify: Notify::new(),
            started_at,
        }
    }

    pub fn lifecycle_state(&self) -> TurnLifecycleState {
        *self.lifecycle.lock().unwrap()
    }

    pub fn terminal_result(&self) -> Option<Value> {
        self.terminal_result.lock().unwrap().clone()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) -> bool {
        let was_already = self.cancelled.swap(true, Ordering::SeqCst);
        {
            let mut st = self.lifecycle.lock().unwrap();
            *st = TurnLifecycleState::Cancelled;
        }
        self.notify.notify_waiters();
        !was_already
    }

    fn set_finished_and_notify(&self, next_state: TurnLifecycleState, result: Value) {
        {
            let mut res_guard = self.terminal_result.lock().unwrap();
            *res_guard = Some(result);
        }
        {
            let mut st_guard = self.lifecycle.lock().unwrap();
            *st_guard = next_state;
        }
        self.notify.notify_waiters();
    }

    fn mark_aborted_and_notify(&self) {
        self.aborted.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub async fn wait_cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }

    /// Await completion of an in-flight turn (`AlreadyRunning`).
    /// Returns `Some(result)` when the leader finishes (or transitions to `PausedApproval`),
    /// or `None` if the leader turn was cancelled or aborted without a completion payload.
    pub async fn wait_finished_result(&self) -> Option<Value> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if let Some(res) = self.terminal_result() {
                return Some(res);
            }
            if self.is_cancelled() || self.is_aborted() {
                return None;
            }
            notified.await;
        }
    }
}

/// Outcome of atomic turn registration in `TurnRegistry`.
pub enum TurnRegistrationOutcome {
    /// Sole active owner (`instance_seq`) authorized to execute side effects and model calls.
    Started(Arc<ActiveTurnHandle>),
    /// Identical `TurnIdentity` is already `Running`; await `handle.wait_finished_result().await`
    /// or return in-progress status without spawning a second agent or second ledger.
    AlreadyRunning(Arc<ActiveTurnHandle>),
    /// Identical `TurnIdentity` completed within TTL (`300s`, max `64`) and allows memory write.
    IdempotentReplay(Value),
    /// Same `turn_id` submitted with different `session_id`, `request_digest`, `privacy`, or mode.
    Conflict { reason: String },
    /// Turn was cancelled prior to or during execution.
    PreCancelled,
}

pub(crate) enum TurnStartOutcome {
    Started(Arc<ActiveTurnHandle>),
    IdempotentReplay(Value),
    PreCancelled,
}

struct ActiveTurnEntry {
    instance_seq: u64,
    handle: Arc<ActiveTurnHandle>,
}

#[derive(Clone)]
struct CompletedTurnEntry {
    #[allow(dead_code)]
    instance_seq: u64,
    identity: TurnIdentity,
    state: TurnLifecycleState,
    result: Value,
    completed_at: Instant,
}

#[derive(Clone)]
struct CancelledTurnEntry {
    turn_id: String,
    instance_seq: Option<u64>,
    identity: Option<TurnIdentity>,
    cancelled_at: Instant,
}

/// Single atomic state machine managing active, paused-approval, finished, and cancelled turns.
pub struct TurnRegistry {
    next_instance_seq: u64,
    active: HashMap<String, ActiveTurnEntry>,
    completed: VecDeque<CompletedTurnEntry>,
    cancelled: VecDeque<CancelledTurnEntry>,
    completed_tombstones: VecDeque<(String, Instant)>,
}

impl Default for TurnRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TurnRegistry {
    pub fn new() -> Self {
        Self {
            next_instance_seq: 0,
            active: HashMap::new(),
            completed: VecDeque::new(),
            cancelled: VecDeque::new(),
            completed_tombstones: VecDeque::new(),
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        self.completed
            .retain(|e| now.saturating_duration_since(e.completed_at) <= COMPLETED_TURN_CACHE_TTL);
        self.cancelled
            .retain(|e| now.saturating_duration_since(e.cancelled_at) <= CANCELLED_TURN_CACHE_TTL);
        self.completed_tombstones
            .retain(|(_, ts)| now.saturating_duration_since(*ts) <= COMPLETED_TURN_CACHE_TTL);
    }

    fn push_cancelled_entry(&mut self, entry: CancelledTurnEntry) {
        if let Some(existing) = self
            .cancelled
            .iter_mut()
            .find(|c| c.turn_id == entry.turn_id)
        {
            if entry.instance_seq.is_some() {
                existing.instance_seq = entry.instance_seq;
            }
            if entry.identity.is_some() {
                existing.identity = entry.identity;
            }
            existing.cancelled_at = entry.cancelled_at;
            return;
        }
        while self.cancelled.len() >= MAX_CANCELLED_TURN_CACHE {
            self.cancelled.pop_front();
        }
        self.cancelled.push_back(entry);
    }

    fn push_completed_tombstone(&mut self, turn_id: &str, now: Instant) {
        if let Some(existing) = self
            .completed_tombstones
            .iter_mut()
            .find(|(id, _)| id == turn_id)
        {
            existing.1 = now;
            return;
        }
        while self.completed_tombstones.len() >= MAX_COMPLETED_TURN_CACHE {
            self.completed_tombstones.pop_front();
        }
        self.completed_tombstones
            .push_back((turn_id.to_string(), now));
    }

    pub fn register_or_join_at(
        &mut self,
        identity: TurnIdentity,
        session_override: Option<String>,
        now: Instant,
    ) -> TurnRegistrationOutcome {
        self.evict_expired(now);

        if let Some(active_entry) = self.active.get(&identity.turn_id) {
            if let Some(reason) = active_entry.handle.identity.conflict_reason(&identity) {
                return TurnRegistrationOutcome::Conflict { reason };
            }
            if active_entry.handle.is_cancelled()
                || active_entry.handle.lifecycle_state() == TurnLifecycleState::Cancelled
            {
                return TurnRegistrationOutcome::PreCancelled;
            }
            return TurnRegistrationOutcome::AlreadyRunning(active_entry.handle.clone());
        }

        if let Some(cancel_entry) = self
            .cancelled
            .iter()
            .find(|c| c.turn_id == identity.turn_id)
        {
            if let Some(ref orig_id) = cancel_entry.identity
                && let Some(reason) = orig_id.conflict_reason(&identity)
            {
                return TurnRegistrationOutcome::Conflict { reason };
            }
            return TurnRegistrationOutcome::PreCancelled;
        }

        if let Some(comp_entry) = self
            .completed
            .iter()
            .find(|c| c.identity.turn_id == identity.turn_id)
        {
            if let Some(reason) = comp_entry.identity.conflict_reason(&identity) {
                return TurnRegistrationOutcome::Conflict { reason };
            }
            if identity.privacy.allows_memory_write()
                && comp_entry.identity.privacy.allows_memory_write()
            {
                return TurnRegistrationOutcome::IdempotentReplay(comp_entry.result.clone());
            }
        }

        self.next_instance_seq += 1;
        let seq = self.next_instance_seq;
        let handle = Arc::new(ActiveTurnHandle::new_registered(
            seq,
            identity.clone(),
            session_override,
            now,
        ));
        self.active.insert(
            identity.turn_id,
            ActiveTurnEntry {
                instance_seq: seq,
                handle: handle.clone(),
            },
        );
        TurnRegistrationOutcome::Started(handle)
    }

    pub fn complete_turn_at(
        &mut self,
        handle: &Arc<ActiveTurnHandle>,
        result: Value,
        cache_for_replay: bool,
        now: Instant,
    ) -> bool {
        self.evict_expired(now);

        let was_cancelled = handle.is_cancelled()
            || self.cancelled.iter().any(|c| {
                c.turn_id == handle.turn_id
                    && (c.instance_seq.is_none() || c.instance_seq == Some(handle.instance_seq))
            });

        if was_cancelled {
            if self
                .active
                .get(&handle.turn_id)
                .is_some_and(|e| e.instance_seq == handle.instance_seq)
            {
                self.active.remove(&handle.turn_id);
            }
            handle.cancel();
            return false;
        }

        let is_current_owner = self
            .active
            .get(&handle.turn_id)
            .is_some_and(|e| e.instance_seq == handle.instance_seq);
        if !is_current_owner {
            handle.mark_aborted_and_notify();
            return false;
        }

        self.active.remove(&handle.turn_id);

        let is_paused_approval = result.get("status").and_then(|v| v.as_str())
            == Some("awaiting_approval")
            || result.get("pending_approval").is_some_and(|v| !v.is_null());
        let next_state = if is_paused_approval {
            TurnLifecycleState::PausedApproval
        } else {
            TurnLifecycleState::Finished
        };

        handle.set_finished_and_notify(next_state, result.clone());

        if handle.identity.privacy.allows_memory_write() {
            self.push_completed_tombstone(&handle.turn_id, now);
        }

        if cache_for_replay && handle.identity.privacy.allows_memory_write() {
            self.completed
                .retain(|c| c.identity.turn_id != handle.turn_id);
            while self.completed.len() >= MAX_COMPLETED_TURN_CACHE {
                self.completed.pop_front();
            }
            self.completed.push_back(CompletedTurnEntry {
                instance_seq: handle.instance_seq,
                identity: handle.identity.clone(),
                state: next_state,
                result,
                completed_at: now,
            });
        }

        true
    }

    pub fn abort_turn(&mut self, handle: &Arc<ActiveTurnHandle>) -> bool {
        let removed = if self
            .active
            .get(&handle.turn_id)
            .is_some_and(|e| e.instance_seq == handle.instance_seq)
        {
            self.active.remove(&handle.turn_id);
            true
        } else {
            false
        };
        handle.mark_aborted_and_notify();
        removed
    }

    pub fn lifecycle_state(&mut self, turn_id: &str, now: Instant) -> Option<TurnLifecycleState> {
        self.evict_expired(now);
        if let Some(active) = self.active.get(turn_id) {
            return Some(active.handle.lifecycle_state());
        }
        if self.cancelled.iter().any(|c| c.turn_id == turn_id) {
            return Some(TurnLifecycleState::Cancelled);
        }
        if let Some(comp) = self
            .completed
            .iter()
            .find(|c| c.identity.turn_id == turn_id)
        {
            return Some(comp.state);
        }
        if self
            .completed_tombstones
            .iter()
            .any(|(id, _)| id == turn_id)
        {
            return Some(TurnLifecycleState::Finished);
        }
        None
    }
}

static TURN_REGISTRY: OnceLock<Mutex<TurnRegistry>> = OnceLock::new();

fn turn_registry() -> &'static Mutex<TurnRegistry> {
    TURN_REGISTRY.get_or_init(|| Mutex::new(TurnRegistry::new()))
}

/// Atomically register a new turn or coalesce/reject concurrent and replayed requests
/// according to `TurnIdentity` (`session_id`, `request_digest`, `model_key`, `execution_mode`, `privacy`).
pub fn register_or_join_turn(identity: TurnIdentity) -> TurnRegistrationOutcome {
    turn_registry()
        .lock()
        .unwrap()
        .register_or_join_at(identity, None, Instant::now())
}

/// Atomically transition an active turn owned by `handle` (`instance_seq` verified) from
/// `Running` -> `Finished` (or `PausedApproval`), notify any `AlreadyRunning` waiters, and
/// optionally insert into the TTL-bounded replay cache when `privacy.allows_memory_write()`.
pub fn complete_turn_atomic(
    handle: &Arc<ActiveTurnHandle>,
    result: Value,
    cache_for_replay: bool,
) -> bool {
    turn_registry().lock().unwrap().complete_turn_at(
        handle,
        result,
        cache_for_replay,
        Instant::now(),
    )
}

/// Safely release an active turn slot owned by `handle` (`instance_seq` verified) without
/// caching a replay outcome, waking any `AlreadyRunning` waiters so they never hang.
pub fn abort_turn_atomic(handle: &Arc<ActiveTurnHandle>) -> bool {
    turn_registry().lock().unwrap().abort_turn(handle)
}

/// Inspect the current `TurnLifecycleState` of `turn_id` in `TurnRegistry`.
pub fn turn_lifecycle_state(turn_id: &str) -> Option<TurnLifecycleState> {
    turn_registry()
        .lock()
        .unwrap()
        .lifecycle_state(turn_id, Instant::now())
}

pub(crate) fn begin_turn(turn_id: &str, session_id: Option<&str>) -> TurnStartOutcome {
    let privacy = PrivacySessionPolicy::from_session(false, session_id);
    let identity = TurnIdentity {
        turn_id: turn_id.to_string(),
        session_id: LEGACY_WILDCARD_SESSION.to_string(),
        request_digest: String::new(),
        model_key: String::new(),
        execution_mode: String::new(),
        privacy,
    };
    let outcome = turn_registry().lock().unwrap().register_or_join_at(
        identity,
        session_id.map(String::from),
        Instant::now(),
    );
    match outcome {
        TurnRegistrationOutcome::Started(h) | TurnRegistrationOutcome::AlreadyRunning(h) => {
            TurnStartOutcome::Started(h)
        }
        TurnRegistrationOutcome::IdempotentReplay(cached) => {
            TurnStartOutcome::IdempotentReplay(cached)
        }
        TurnRegistrationOutcome::PreCancelled | TurnRegistrationOutcome::Conflict { .. } => {
            TurnStartOutcome::PreCancelled
        }
    }
}

pub(crate) fn complete_turn(turn_id: &str, result: Value, cache_for_replay: bool) {
    let mut reg = turn_registry().lock().unwrap();
    if let Some(handle) = reg.active.get(turn_id).map(|e| e.handle.clone()) {
        reg.complete_turn_at(&handle, result, cache_for_replay, Instant::now());
    }
}

pub(crate) fn remove_active_turn(turn_id: &str) {
    let mut reg = turn_registry().lock().unwrap();
    if let Some(handle) = reg.active.get(turn_id).map(|e| e.handle.clone()) {
        reg.abort_turn(&handle);
    }
}

pub fn cancel_turn(core: &IntentOsCore, payload: &Value) -> Value {
    let target_turn_id = payload.get("turn_id").and_then(|v| v.as_str());
    let target_session_id = payload.get("session_id").and_then(|v| v.as_str());
    let now = Instant::now();

    if let Some(tid) = target_turn_id.map(str::trim).filter(|s| !s.is_empty()) {
        let mut task_to_cancel: Option<String> = None;
        let response = {
            let mut reg = turn_registry().lock().unwrap();
            reg.evict_expired(now);

            if let Some(active_entry) = reg.active.remove(tid) {
                let first_cancel = active_entry.handle.cancel();
                task_to_cancel = active_entry.handle.task_id.lock().unwrap().clone();
                reg.push_cancelled_entry(CancelledTurnEntry {
                    turn_id: tid.to_string(),
                    instance_seq: Some(active_entry.instance_seq),
                    identity: Some(active_entry.handle.identity.clone()),
                    cancelled_at: now,
                });
                json!({
                    "ok": true,
                    "turn_id": tid,
                    "status": if first_cancel { "cancelled" } else { "already_cancelled" },
                    "was_running": first_cancel,
                    "idempotent": !first_cancel,
                })
            } else if reg.cancelled.iter().any(|c| c.turn_id == tid) {
                json!({
                    "ok": true,
                    "turn_id": tid,
                    "status": "already_cancelled",
                    "was_running": false,
                    "idempotent": true,
                })
            } else if reg.completed.iter().any(|c| c.identity.turn_id == tid)
                || reg.completed_tombstones.iter().any(|(id, _)| id == tid)
            {
                json!({
                    "ok": true,
                    "turn_id": tid,
                    "status": "already_completed",
                    "was_running": false,
                    "idempotent": true,
                })
            } else {
                reg.push_cancelled_entry(CancelledTurnEntry {
                    turn_id: tid.to_string(),
                    instance_seq: None,
                    identity: None,
                    cancelled_at: now,
                });
                json!({
                    "ok": true,
                    "turn_id": tid,
                    "status": "cancelled",
                    "was_running": false,
                    "idempotent": false,
                })
            }
        };

        if let Some(ref task_id) = task_to_cancel {
            core.gateway.cancel_task_leases(task_id);
        }
        return response;
    }

    // Cancel by `session_id` or latest active turn
    let mut task_to_cancel: Option<String> = None;
    let cancelled_info = {
        let mut reg = turn_registry().lock().unwrap();
        reg.evict_expired(now);
        let target_key =
            if let Some(sid) = target_session_id.map(str::trim).filter(|s| !s.is_empty()) {
                reg.active
                    .iter()
                    .find(|(_, e)| {
                        e.handle.session_id.as_deref() == Some(sid)
                            || e.handle.identity.session_id == sid
                    })
                    .map(|(k, _)| k.clone())
            } else {
                reg.active
                    .iter()
                    .max_by_key(|(_, e)| e.handle.started_at)
                    .map(|(k, _)| k.clone())
            };

        if let Some(tid) = target_key
            && let Some(active_entry) = reg.active.remove(&tid)
        {
            let first_cancel = active_entry.handle.cancel();
            task_to_cancel = active_entry.handle.task_id.lock().unwrap().clone();
            reg.push_cancelled_entry(CancelledTurnEntry {
                turn_id: tid.clone(),
                instance_seq: Some(active_entry.instance_seq),
                identity: Some(active_entry.handle.identity.clone()),
                cancelled_at: now,
            });
            Some((tid, first_cancel))
        } else {
            None
        }
    };

    if let Some(ref task_id) = task_to_cancel {
        core.gateway.cancel_task_leases(task_id);
    }

    if let Some((tid, first_cancel)) = cancelled_info {
        json!({
            "ok": true,
            "turn_id": tid,
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

#[derive(Serialize, Deserialize)]
struct PersistedSessionStateDto {
    session_id: String,
    messages: Vec<ChatMessage>,
    last_resource_path: Option<String>,
    updated_at: DateTime<Utc>,
}

impl From<&SessionState> for PersistedSessionStateDto {
    fn from(s: &SessionState) -> Self {
        Self {
            session_id: s.session_id.clone(),
            messages: s.messages.clone(),
            last_resource_path: s.last_resource_path.clone(),
            updated_at: s.updated_at,
        }
    }
}

impl From<PersistedSessionStateDto> for SessionState {
    fn from(dto: PersistedSessionStateDto) -> Self {
        Self {
            session_id: dto.session_id,
            messages: dto.messages,
            last_resource_path: dto.last_resource_path,
            updated_at: dto.updated_at,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedDiscoveryOptionsDto {
    home_dir: PathBuf,
    extra_bin_dirs: Vec<PathBuf>,
    include_system_paths: bool,
    opt_zcode_cjs: Option<PathBuf>,
    ollama_tags_url: Option<String>,
    ollama_timeout_ms: u64,
    allow_env_keys: bool,
    probe_remote_models: bool,
    force_refresh_models: bool,
}

impl From<&DiscoveryOptions> for PersistedDiscoveryOptionsDto {
    fn from(o: &DiscoveryOptions) -> Self {
        Self {
            home_dir: o.home_dir.clone(),
            extra_bin_dirs: o.extra_bin_dirs.clone(),
            include_system_paths: o.include_system_paths,
            opt_zcode_cjs: o.opt_zcode_cjs.clone(),
            ollama_tags_url: o.ollama_tags_url.clone(),
            ollama_timeout_ms: o.ollama_timeout_ms,
            allow_env_keys: o.allow_env_keys,
            probe_remote_models: o.probe_remote_models,
            force_refresh_models: o.force_refresh_models,
        }
    }
}

impl From<PersistedDiscoveryOptionsDto> for DiscoveryOptions {
    fn from(dto: PersistedDiscoveryOptionsDto) -> Self {
        Self {
            home_dir: dto.home_dir,
            extra_bin_dirs: dto.extra_bin_dirs,
            include_system_paths: dto.include_system_paths,
            opt_zcode_cjs: dto.opt_zcode_cjs,
            ollama_tags_url: dto.ollama_tags_url,
            ollama_timeout_ms: dto.ollama_timeout_ms,
            allow_env_keys: dto.allow_env_keys,
            probe_remote_models: dto.probe_remote_models,
            force_refresh_models: dto.force_refresh_models,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PersistedDialectStateDto {
    OpenAi {
        messages: Vec<Value>,
        tools: Vec<Value>,
    },
    Anthropic {
        base_url: String,
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

impl From<&SuspendedDialectState> for PersistedDialectStateDto {
    fn from(d: &SuspendedDialectState) -> Self {
        match d {
            SuspendedDialectState::OpenAi { messages, tools } => Self::OpenAi {
                messages: messages.clone(),
                tools: tools.clone(),
            },
            SuspendedDialectState::Anthropic {
                base_url,
                trust,
                messages,
                prior_tool_results,
                tools,
                ..
            } => Self::Anthropic {
                base_url: base_url.clone(),
                trust: *trust,
                messages: messages.clone(),
                prior_tool_results: prior_tool_results.clone(),
                tools: tools.clone(),
            },
            SuspendedDialectState::Cli {
                disc,
                transcript_history,
                prior_round_tool_results,
                allow_broker_tools,
            } => Self::Cli {
                disc: disc.clone(),
                transcript_history: transcript_history.clone(),
                prior_round_tool_results: prior_round_tool_results.clone(),
                allow_broker_tools: *allow_broker_tools,
            },
        }
    }
}

impl From<PersistedDialectStateDto> for SuspendedDialectState {
    fn from(dto: PersistedDialectStateDto) -> Self {
        match dto {
            PersistedDialectStateDto::OpenAi { messages, tools } => {
                Self::OpenAi { messages, tools }
            }
            PersistedDialectStateDto::Anthropic {
                base_url,
                trust,
                messages,
                prior_tool_results,
                tools,
            } => Self::Anthropic {
                base_url,
                api_key: None,
                trust,
                messages,
                prior_tool_results,
                tools,
            },
            PersistedDialectStateDto::Cli {
                disc,
                transcript_history,
                prior_round_tool_results,
                allow_broker_tools,
            } => Self::Cli {
                disc,
                transcript_history,
                prior_round_tool_results,
                allow_broker_tools,
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedCheckpointDto {
    approval_id: String,
    pending_approval: PendingApproval,
    task_id: String,
    session: PersistedSessionStateDto,
    user_text: String,
    incognito: bool,
    active: ActiveBackendSelection,
    discovery_opts: PersistedDiscoveryOptionsDto,
    extra_blocks: Vec<ContextBlock>,
    sys_text: String,
    taints: Vec<Taint>,
    data_class: DataClass,
    memory_hits: Vec<Value>,
    memory_dot: Option<TraceDot>,
    context_compression: crate::memory_hub::ContextCompressionStats,
    rounds_used: usize,
    paused_call_id: String,
    paused_canonical_tool: String,
    paused_parsed_args: Value,
    remaining_tool_calls: Vec<(String, String, Value)>,
    effect_ledger: TurnEffectLedger,
    dialect: PersistedDialectStateDto,
}

impl PersistedCheckpointDto {
    fn from_checkpoint(cp: &SuspendedTurnCheckpoint) -> Self {
        Self {
            approval_id: cp.approval_id.clone(),
            pending_approval: cp.pending_approval.clone(),
            task_id: cp.task_id.clone(),
            session: PersistedSessionStateDto::from(&cp.session),
            user_text: cp.user_text.clone(),
            incognito: cp.incognito,
            active: cp.active.clone(),
            discovery_opts: PersistedDiscoveryOptionsDto::from(&cp.discovery_opts),
            extra_blocks: cp.extra_blocks.clone(),
            sys_text: cp.sys_text.clone(),
            taints: cp.taints.clone(),
            data_class: cp.data_class,
            memory_hits: cp.memory_hits.clone(),
            memory_dot: cp.memory_dot.clone(),
            context_compression: cp.context_compression.clone(),
            rounds_used: cp.rounds_used,
            paused_call_id: cp.paused_call_id.clone(),
            paused_canonical_tool: cp.paused_canonical_tool.clone(),
            paused_parsed_args: cp.paused_parsed_args.clone(),
            remaining_tool_calls: cp.remaining_tool_calls.clone(),
            effect_ledger: cp.effect_ledger.clone(),
            dialect: PersistedDialectStateDto::from(&cp.dialect),
        }
    }

    fn into_checkpoint(mut self) -> SuspendedTurnCheckpoint {
        self.effect_ledger.rebuild_indexes();
        SuspendedTurnCheckpoint {
            created_at_instant: Instant::now(),
            approval_id: self.approval_id,
            pending_approval: self.pending_approval,
            task_id: self.task_id,
            session: SessionState::from(self.session),
            user_text: self.user_text,
            incognito: self.incognito,
            active: self.active,
            discovery_opts: DiscoveryOptions::from(self.discovery_opts),
            extra_blocks: self.extra_blocks,
            sys_text: self.sys_text,
            taints: self.taints,
            data_class: self.data_class,
            memory_hits: self.memory_hits,
            memory_dot: self.memory_dot,
            context_compression: self.context_compression,
            rounds_used: self.rounds_used,
            paused_call_id: self.paused_call_id,
            paused_canonical_tool: self.paused_canonical_tool,
            paused_parsed_args: self.paused_parsed_args,
            remaining_tool_calls: self.remaining_tool_calls,
            effect_ledger: self.effect_ledger,
            dialect: SuspendedDialectState::from(self.dialect),
        }
    }
}

/// Derive canonical `scope_kind:scope_value` bound to a `PendingApproval` for checkpoint verification.
pub fn compute_checkpoint_target_scope(pa: &PendingApproval) -> String {
    if let Some((kind, val)) = extract_approval_grant_target(None, None, Some(pa)) {
        format!("{}:{}", kind, val)
    } else {
        format!("capability:{}", pa.capability_id)
    }
}

fn persist_checkpoint_to_db(
    state_db: &StateDb,
    cp: &SuspendedTurnCheckpoint,
    privacy: PrivacySessionPolicy,
) -> anyhow::Result<bool> {
    if !privacy.allows_task_persistence() || cp.incognito {
        return Ok(false);
    }
    let dto = PersistedCheckpointDto::from_checkpoint(cp);
    let mut dto_val = serde_json::to_value(&dto)?;
    SensitiveDataGuard::redact_json(&mut dto_val);
    let checkpoint_json = serde_json::to_string(&dto_val)?;

    let row = SuspendedCheckpointRow {
        approval_id: cp.pending_approval.approval_id.clone(),
        turn_id: cp.effect_ledger.turn_id.clone(),
        task_id: cp.task_id.clone(),
        session_id: cp.session.session_id.clone(),
        approval_digest: cp.pending_approval.digest.clone(),
        capability_id: cp.pending_approval.capability_id.clone(),
        target_scope: compute_checkpoint_target_scope(&cp.pending_approval),
        checkpoint_json,
        expires_at: cp.pending_approval.expires_at,
        created_at: cp.pending_approval.created_at,
    };
    state_db.save_suspended_checkpoint_row(&row, privacy)
}

pub(crate) static SUSPENDED_APPROVAL_TURNS: OnceLock<
    Mutex<HashMap<String, SuspendedTurnCheckpoint>>,
> = OnceLock::new();

fn suspended_approval_turns() -> &'static Mutex<HashMap<String, SuspendedTurnCheckpoint>> {
    SUSPENDED_APPROVAL_TURNS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn insert_in_memory_suspended_checkpoint(cp: SuspendedTurnCheckpoint) {
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

/// Explicitly save a `SuspendedTurnCheckpoint` to both in-memory registry and (when `privacy == Standard`)
/// `StateDb` (`suspended_turn_checkpoints`), returning `Ok(true)` if persisted to SQLite or `Ok(false)`
/// when `EphemeralReadOnly` / `StrictIsolated` kept it strictly in-memory.
pub fn save_suspended_checkpoint_with_db(
    state_db: &StateDb,
    mut cp: SuspendedTurnCheckpoint,
    privacy: PrivacySessionPolicy,
) -> anyhow::Result<bool> {
    cp.effect_ledger.set_privacy(privacy);
    let persisted = persist_checkpoint_to_db(state_db, &cp, privacy)?;
    insert_in_memory_suspended_checkpoint(cp);
    Ok(persisted)
}

pub fn save_suspended_checkpoint(cp: SuspendedTurnCheckpoint) {
    let effective_privacy = if cp.incognito {
        PrivacySessionPolicy::StrictIsolated
    } else if cp.effect_ledger.privacy_explicit {
        cp.effect_ledger.privacy()
    } else {
        PrivacySessionPolicy::from_session(cp.incognito, Some(&cp.session.session_id))
    };
    if let Some(db) = cp.effect_ledger.state_db().cloned() {
        let _ = persist_checkpoint_to_db(&db, &cp, effective_privacy);
    }
    insert_in_memory_suspended_checkpoint(cp);
}

pub fn take_suspended_checkpoint(approval_id: &str) -> Option<SuspendedTurnCheckpoint> {
    let removed = {
        let mut map = suspended_approval_turns().lock().unwrap();
        let now = Instant::now();
        map.retain(|_, v| now.duration_since(v.created_at_instant) <= SUSPENDED_CHECKPOINT_TTL);
        map.remove(approval_id)
    };
    if let Some(ref cp) = removed
        && let Some(db) = cp.effect_ledger.state_db()
    {
        let _ = db.delete_suspended_checkpoint_row(approval_id);
    }
    removed
}

/// Clear in-memory suspended approval checkpoints (used in daemon restart simulation tests).
pub fn clear_in_memory_suspended_checkpoints() {
    suspended_approval_turns().lock().unwrap().clear();
}

fn expand_tilde_checkpoint_path(raw: &str) -> PathBuf {
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

fn collect_json_path_candidates(args: &Value) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Some(obj) = args.as_object() else {
        return out;
    };
    for (k, v) in obj {
        if is_path_argument_key(k)
            && let Some(s) = v.as_str()
            && !s.trim().is_empty()
        {
            out.push(expand_tilde_checkpoint_path(s));
        } else if is_path_array_argument_key(k)
            && let Some(arr) = v.as_array()
        {
            for item in arr {
                if let Some(s) = item.as_str()
                    && !s.trim().is_empty()
                {
                    out.push(expand_tilde_checkpoint_path(s));
                }
            }
        } else if k == "params"
            && let Some(pobj) = v.as_object()
        {
            for (pk, pv) in pobj {
                if is_path_argument_key(pk)
                    && let Some(s) = pv.as_str()
                    && !s.trim().is_empty()
                {
                    out.push(expand_tilde_checkpoint_path(s));
                }
            }
        }
    }
    out
}

fn approve_non_forbidden_paths_for_resume(core: &IntentOsCore, args: &Value) {
    for expanded in collect_json_path_candidates(args) {
        if !expanded
            .components()
            .any(|c| matches!(c, Component::ParentDir))
            && !core.fs_engine.is_forbidden(&expanded)
        {
            let _ = core.fs_engine.approve_path_scope(&expanded);
        }
    }
}

/// Strictly re-verify `SafeFsEngine` forbidden/traversal invariants and `PolicyEngine::evaluate`
/// scope rules on a reloaded `SuspendedTurnCheckpoint` before resuming across a restart (`H03`).
pub fn verify_checkpoint_policy_scope(
    core: &IntentOsCore,
    cp: &SuspendedTurnCheckpoint,
) -> anyhow::Result<()> {
    for candidate in collect_json_path_candidates(&cp.pending_approval.arguments)
        .into_iter()
        .chain(collect_json_path_candidates(&cp.paused_parsed_args))
    {
        if candidate
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            anyhow::bail!(
                "拒绝恢复包含路径穿越 ('..') 的持久化审批检查点: {}",
                candidate.display()
            );
        }
        if core.fs_engine.is_forbidden(&candidate) {
            anyhow::bail!(
                "拒绝恢复指向受禁路径 (forbidden path) 的审批检查点: {}",
                candidate.display()
            );
        }
    }

    if !crate::app_adapter::is_adapter_tool(&cp.pending_approval.capability_id) {
        let desc = core
            .broker
            .get_descriptor(&cp.pending_approval.capability_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "无法恢复未知或已移除的能力: {}",
                    cp.pending_approval.capability_id
                )
            })?;
        if let PolicyDecision::Deny { reason } = core.policy.evaluate(
            desc,
            &cp.pending_approval.arguments,
            InvocationOrigin::L2AgentPlan,
            &cp.taints,
            1,
            true,
        ) {
            anyhow::bail!("重启后安全策略重校验拒绝恢复: {}", reason);
        }
    }
    Ok(())
}

fn canonical_args_without_injected_session(cap_id: &str, v: &Value) -> String {
    if crate::memory_hub::is_memory_tool(cap_id)
        && let Some(obj) = v.as_object()
    {
        let mut copy = obj.clone();
        copy.remove("session_id");
        return canonicalize_tool_args_value(&Value::Object(copy));
    }
    canonicalize_tool_args_value(v)
}

/// Reload a `SuspendedTurnCheckpoint` from `StateDb` across daemon restart, strictly re-verifying:
/// 1. Non-expired `expires_at` timestamp;
/// 2. Exact `session_id` match;
/// 3. Exact `approval_digest` match AND cryptographic recomputation of `PendingApproval::compute_digest`;
/// 4. Consistency between `paused_parsed_args`, `pending_approval.arguments`, and `target_scope`
///    (plus optional caller-supplied `(scope_kind, scope_value)` match);
/// 5. Current `PolicyEngine` + `SafeFsEngine` scope rules (`verify_checkpoint_policy_scope`).
///
/// Consumes (deletes) the persisted row upon successful verification so it can never be replayed.
pub fn load_and_verify_persisted_checkpoint(
    core: &IntentOsCore,
    approval_id: &str,
    expected_session_id: &str,
    expected_digest: &str,
    requested_scope: Option<(&str, &str)>,
) -> anyhow::Result<SuspendedTurnCheckpoint> {
    let row = core
        .state_db
        .get_suspended_checkpoint_row(approval_id)?
        .ok_or_else(|| anyhow::anyhow!("持久化审批检查点不存在或已被消费（拒绝重放）"))?;

    if Utc::now() > row.expires_at {
        let _ = core.state_db.delete_suspended_checkpoint_row(approval_id);
        anyhow::bail!("持久化审批检查点已过期");
    }

    let clean_expected_sid = expected_session_id.trim();
    if clean_expected_sid.is_empty() || row.session_id != clean_expected_sid {
        anyhow::bail!("持久化审批检查点会话校验失败：session_id 不匹配（拒绝跨会话恢复）");
    }

    let clean_expected_digest = expected_digest.trim();
    if clean_expected_digest.is_empty() || row.approval_digest != clean_expected_digest {
        anyhow::bail!("持久化审批检查点摘要校验失败：approval_digest 不匹配");
    }

    let dto: PersistedCheckpointDto = serde_json::from_str(&row.checkpoint_json)
        .map_err(|e| anyhow::anyhow!("反序列化持久化审批检查点失败: {}", e))?;
    let mut cp = dto.into_checkpoint();

    if cp.pending_approval.approval_id != approval_id
        || cp.session.session_id != row.session_id
        || cp.task_id != row.task_id
        || cp.pending_approval.capability_id != row.capability_id
        || cp.pending_approval.digest != row.approval_digest
    {
        let _ = core.state_db.delete_suspended_checkpoint_row(approval_id);
        anyhow::bail!("持久化审批检查点元数据绑定不一致（检测到篡改）");
    }

    let recomputed_digest = PendingApproval::compute_digest(
        &cp.pending_approval.capability_id,
        &cp.pending_approval.arguments,
    );
    if recomputed_digest != row.approval_digest {
        let _ = core.state_db.delete_suspended_checkpoint_row(approval_id);
        anyhow::bail!("持久化审批检查点参数摘要重算不一致（参数已被脱敏改写或篡改）");
    }

    let canon_pa_args = canonical_args_without_injected_session(
        &cp.pending_approval.capability_id,
        &cp.pending_approval.arguments,
    );
    let canon_paused_args = canonical_args_without_injected_session(
        &cp.pending_approval.capability_id,
        &cp.paused_parsed_args,
    );
    if canon_pa_args != canon_paused_args {
        let _ = core.state_db.delete_suspended_checkpoint_row(approval_id);
        anyhow::bail!("持久化审批检查点 paused_parsed_args 与授权参数不一致");
    }

    let recomputed_scope = compute_checkpoint_target_scope(&cp.pending_approval);
    if recomputed_scope != row.target_scope {
        let _ = core.state_db.delete_suspended_checkpoint_row(approval_id);
        anyhow::bail!(
            "持久化审批检查点 target_scope 校验失败（期望 '{}', 实际 '{}'）",
            recomputed_scope,
            row.target_scope
        );
    }

    if let Some((req_kind, req_val)) = requested_scope {
        let normalized_req = extract_approval_grant_target(
            Some(req_kind),
            Some(req_val),
            Some(&cp.pending_approval),
        )
        .map(|(k, v)| format!("{}:{}", k, v))
        .unwrap_or_default();
        if normalized_req != row.target_scope {
            anyhow::bail!(
                "请求的授权作用域 '{}' 与持久化检查点绑定作用域 '{}' 不一致（拒绝越权恢复）",
                normalized_req,
                row.target_scope
            );
        }
    }

    if let Err(policy_err) = verify_checkpoint_policy_scope(core, &cp) {
        let _ = core.state_db.delete_suspended_checkpoint_row(approval_id);
        return Err(policy_err);
    }

    cp.effect_ledger.bind_persistence(
        core.state_db.clone(),
        cp.task_id.clone(),
        cp.session.session_id.clone(),
        PrivacySessionPolicy::Standard,
    );

    core.state_db.delete_suspended_checkpoint_row(approval_id)?;
    Ok(cp)
}

/// Resume (or deny) a persisted `SuspendedTurnCheckpoint` across a daemon restart (`H03`).
///
/// Strictly re-verifies `session_id`, `approval_digest` (`digest`), optional `nonce`,
/// non-expired `expires_at`, `target_scope`, and `PolicyEngine` scope before executing!
pub async fn resume_persisted_checkpoint_across_restart(
    core: &IntentOsCore,
    payload: &Value,
    opts: &DiscoveryOptions,
) -> anyhow::Result<Value> {
    let approval_id = payload
        .get("approval_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("resume_persisted_checkpoint 缺少 approval_id"))?
        .to_string();

    let raw_decision = payload
        .get("decision")
        .or_else(|| payload.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("once")
        .trim()
        .to_ascii_lowercase();
    let decision = match raw_decision.as_str() {
        "approve" | "once" => "once",
        "session" => "session",
        "scope" => "scope",
        "deny" | "reject" | "cancel" => "deny",
        other => anyhow::bail!(
            "不支持的审批决策 '{}'（仅支持 once / session / scope / deny）",
            other
        ),
    };

    let req_session_id = payload
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    let req_digest = payload
        .get("digest")
        .or_else(|| payload.get("approval_digest"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    let req_nonce = payload
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let req_scope_kind = payload
        .get("scope_kind")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let req_scope_value = payload
        .get("scope_value")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let ttl_minutes = payload
        .get("ttl_minutes")
        .and_then(|v| v.as_i64())
        .unwrap_or(60)
        .clamp(1, 24 * 60);

    let resume_turn_id = format!(
        "resume_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );

    if decision == "deny" {
        let row = core
            .state_db
            .get_suspended_checkpoint_row(&approval_id)?
            .ok_or_else(|| anyhow::anyhow!("持久化审批检查点不存在或已被消费"))?;
        if !req_session_id.is_empty() && row.session_id != req_session_id {
            anyhow::bail!("拒绝操作会话标识不匹配");
        }
        let dto: Option<PersistedCheckpointDto> = serde_json::from_str(&row.checkpoint_json).ok();
        let cp = dto.map(|d| d.into_checkpoint());
        let pa_ref = cp.as_ref().map(|c| c.pending_approval.clone());
        let _ = core.state_db.delete_suspended_checkpoint_row(&approval_id);
        if let Some(ref c) = cp
            && let Some(ref prep_step_id) = c.effect_ledger.pending_approval_step_id
            && let Ok(Some(mut step_row)) = core
                .state_db
                .get_step_execution_log(&c.task_id, prep_step_id)
        {
            step_row.exec_state = StepExecState::Denied;
            step_row.verification_status = "Denied".to_string();
            step_row.updated_at = Utc::now();
            let _ = core
                .state_db
                .upsert_step_execution_log(&step_row, PrivacySessionPolicy::Standard);
        }
        if let Ok(Some(mut task)) = core.state_db.get_task(&row.task_id) {
            task.pending_approval = None;
            task.status = TaskStatus::Cancelled;
            task.updated_at = Utc::now();
            let _ = core.state_db.upsert_task(&task);
        }
        return build_denied_resume_response(
            core,
            payload,
            &approval_id,
            &resume_turn_id,
            pa_ref,
            cp,
        );
    }

    let requested_scope = match (req_scope_kind, req_scope_value) {
        (Some(k), Some(v)) => Some((k, v)),
        (None, Some(v)) => Some(("", v)),
        _ => None,
    };

    let cp = load_and_verify_persisted_checkpoint(
        core,
        &approval_id,
        req_session_id,
        req_digest,
        requested_scope,
    )?;

    if let Some(nonce) = req_nonce
        && nonce != cp.pending_approval.nonce
    {
        anyhow::bail!("持久化审批检查点 nonce 校验失败（拒绝伪造）");
    }

    if core
        .state_db
        .task_has_uncertain_or_recovery_steps(&cp.task_id)?
    {
        anyhow::bail!(
            "任务 '{}' 存在未确认副作用或处于 recovery_required 状态，已阻止自动恢复执行",
            cp.task_id
        );
    }

    if matches!(decision, "session" | "scope")
        && let Some((sk, sv)) = extract_approval_grant_target(
            req_scope_kind,
            req_scope_value,
            Some(&cp.pending_approval),
        )
    {
        let grant_out = core.policy.add_session_grant(&sk, &sv, ttl_minutes);
        if grant_out.get("rejected").and_then(|v| v.as_bool()) == Some(true) {
            anyhow::bail!("会话授权作用域被安全策略拒绝: {}", sv);
        }
    }

    // Transition step `Prepared -> Executing` in SQLite before running the approved OS action
    let pa = cp.pending_approval.clone();
    let cap_effect = core
        .broker
        .get_descriptor(&pa.capability_id)
        .map(|d| d.max_effect())
        .unwrap_or(Effect::WriteReversible);
    let tracked_step_id = cp
        .effect_ledger
        .pending_approval_step_id
        .clone()
        .unwrap_or_else(|| format!("step_{}", cp.effect_ledger.next_step_seq + 1));
    let now_exec = Utc::now();
    if cap_effect > Effect::Observe {
        let exec_row = StepExecutionLogRow {
            task_id: cp.task_id.clone(),
            turn_id: cp.effect_ledger.turn_id.clone(),
            session_id: cp.session.session_id.clone(),
            step_id: tracked_step_id.clone(),
            attempt_id: "approved_attempt_1".to_string(),
            idempotency_key: cp
                .effect_ledger
                .compute_idempotency_key(&pa.capability_id, &pa.arguments.to_string()),
            capability_id: pa.capability_id.clone(),
            effect: cap_effect.as_str().to_string(),
            exec_state: StepExecState::Executing,
            expected_summary: pa.summary.clone(),
            changeset_id: None,
            verification_status: "Executing".to_string(),
            recovery_hint: None,
            created_at: now_exec,
            updated_at: now_exec,
        };
        core.state_db
            .upsert_step_execution_log(&exec_row, PrivacySessionPolicy::Standard)?;
    }

    approve_non_forbidden_paths_for_resume(core, &pa.arguments);

    let exec_res = if crate::app_adapter::is_adapter_tool(&pa.capability_id) {
        let call = CapabilityCall {
            request_id: pa.approval_id.clone(),
            task_id: cp.task_id.clone(),
            capability_id: pa.capability_id.clone(),
            arguments: pa.arguments.clone(),
            origin: InvocationOrigin::UserExplicit,
            taints: vec![Taint::User],
        };
        match core.broker.dispatch(&call).await {
            Ok(BrokerDispatchOutcome::Executed(r)) => Ok(r),
            Ok(BrokerDispatchOutcome::Denied { reason }) => {
                Err(anyhow::anyhow!("转译层执行被拒绝: {}", reason))
            }
            Ok(BrokerDispatchOutcome::RequiresApproval(_)) => {
                Err(anyhow::anyhow!("转译层在已确认状态下仍请求重复确认"))
            }
            Err(e) => Err(e),
        }
    } else {
        let desc = core
            .broker
            .get_descriptor(&pa.capability_id)
            .ok_or_else(|| anyhow::anyhow!("未找到能力: {}", pa.capability_id))?;
        core.broker
            .execute_approved(&pa.approval_id, &cp.task_id, desc, &pa.arguments)
            .await
    };

    let res = match exec_res {
        Ok(r) => r,
        Err(err) => {
            if cap_effect > Effect::Observe {
                let rec_row = StepExecutionLogRow {
                    task_id: cp.task_id.clone(),
                    turn_id: cp.effect_ledger.turn_id.clone(),
                    session_id: cp.session.session_id.clone(),
                    step_id: tracked_step_id,
                    attempt_id: "approved_attempt_1".to_string(),
                    idempotency_key: cp
                        .effect_ledger
                        .compute_idempotency_key(&pa.capability_id, &pa.arguments.to_string()),
                    capability_id: pa.capability_id.clone(),
                    effect: cap_effect.as_str().to_string(),
                    exec_state: StepExecState::RecoveryRequired,
                    expected_summary: pa.summary.clone(),
                    changeset_id: None,
                    verification_status: "ErrorDuringExecution".to_string(),
                    recovery_hint: Some(format!(
                        "已授权步骤执行期间返回错误 ({})，实际副作用未知；已标记为 recovery_required 并阻止盲目重放。",
                        err
                    )),
                    created_at: now_exec,
                    updated_at: Utc::now(),
                };
                let _ = core
                    .state_db
                    .upsert_step_execution_log(&rec_row, PrivacySessionPolicy::Standard);
                if let Ok(Some(mut t)) = core.state_db.get_task(&cp.task_id) {
                    t.pending_approval = None;
                    t.status = TaskStatus::RecoveryRequired;
                    t.updated_at = Utc::now();
                    let _ = core.state_db.upsert_task(&t);
                }
            }
            return Err(err);
        }
    };

    let mut approved_changeset_ids = cp.effect_ledger.committed_changeset_ids();
    if let Some(ref csid) = res.changeset_id
        && !approved_changeset_ids.contains(csid)
    {
        approved_changeset_ids.push(csid.clone());
    }

    let mut step = TaskStep {
        step_id: pa.approval_id.clone(),
        capability_id: pa.capability_id.clone(),
        arguments_summary: pa.arguments.to_string(),
        status: res.status,
        verification: res.verification,
        changeset_id: res.changeset_id.clone(),
        message: res.message.clone(),
        data: res.data,
        duration_ms: res.duration_ms,
    };

    if step.capability_id == "file.search" {
        supplement_approved_dir_file_search(core, &pa.arguments, &mut step.message, &mut step.data);
    }

    // Update persisted Task in `StateDb` before continuing resumed model turn
    let mut task_record = core
        .state_db
        .get_task(&cp.task_id)?
        .unwrap_or_else(|| Task {
            id: cp.task_id.clone(),
            goal: cp.user_text.clone(),
            session_id: Some(cp.session.session_id.clone()),
            project_id: None,
            trigger: TaskTrigger::Resume,
            route: RouteLayer::L2,
            status: TaskStatus::AwaitingApproval,
            steps: Vec::new(),
            changeset_ids: Vec::new(),
            pending_approval: None,
            candidates_for_disambiguation: Vec::new(),
            assistant_message: None,
            result_summary: None,
            handoff_command: None,
            taint: cp.taints.clone(),
            data_class: cp.data_class,
            budget: TaskBudget::default(),
            created_at: now_exec,
            updated_at: now_exec,
        });
    task_record.pending_approval = None;
    let step_ok = matches!(
        step.status,
        ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
    );
    let next_task_status = if step_ok {
        TaskStatus::Completed
    } else if cap_effect > Effect::Observe {
        TaskStatus::RecoveryRequired
    } else {
        TaskStatus::Failed
    };
    if UnifiedTaskStateMachine::can_transition(task_record.status, next_task_status) {
        let _ = UnifiedTaskStateMachine::transition_task(&mut task_record, next_task_status, None);
    } else {
        task_record.status = next_task_status;
    }
    task_record.changeset_ids = approved_changeset_ids.clone();
    task_record.steps.push(step.clone());
    task_record.updated_at = Utc::now();
    core.state_db.upsert_task(&task_record)?;

    // Restore session context into in-memory `SessionBuffer` after daemon restart
    for msg in &cp.session.messages {
        if msg.role == "user" {
            let _ = core.sessions.get_or_create(Some(&cp.session.session_id));
        }
    }
    if let Some(ref rp) = cp.session.last_resource_path {
        core.sessions
            .set_last_resource_path(&cp.session.session_id, rp.clone());
    }

    resume_suspended_checkpoint_and_finalize(
        core,
        cp,
        opts,
        &resume_turn_id,
        &step,
        &pa.arguments,
        &approved_changeset_ids,
    )
    .await
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
    let fallback_privacy =
        PrivacySessionPolicy::from_session(cp.incognito, Some(&cp.session.session_id));
    cp.effect_ledger.ensure_persistence_context(
        core.state_db.clone(),
        &cp.task_id,
        &cp.session.session_id,
        fallback_privacy,
    );

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
            let resolved_key = api_key.or_else(|| {
                lookup_ephemeral_backend_key(
                    &core.paths,
                    &cp.active.backend,
                    &cp.active.provider,
                    eff_opts.allow_env_keys,
                )
            });
            continue_resumed_anthropic_turn(
                core,
                &mut cp,
                &eff_opts,
                base_url,
                resolved_key,
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

    if !cp.incognito
        && cp.effect_ledger.privacy().allows_memory_write()
        && outcome.pending_approval.is_none()
    {
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
    let _ = core.state_db.delete_suspended_checkpoint_row(approval_id);
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

        if !cp.incognito && cp.effect_ledger.privacy().allows_memory_write() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn h01_ten_concurrent_identical_turn_requests_execute_side_effect_once() {
        let turn_id = format!("h01_conc_{}", uuid::Uuid::new_v4().simple());
        let base_identity = TurnIdentity::from_request(
            &turn_id,
            Some("ses_h01_alpha"),
            "set volume to 35%",
            None,
            true,
            "openai:gpt-4o-mini",
            "managed_broker_tools",
            PrivacySessionPolicy::Standard,
        );

        let barrier = Arc::new(Barrier::new(10));
        let side_effect_runs = Arc::new(AtomicUsize::new(0));
        let started_count = Arc::new(AtomicUsize::new(0));
        let joined_count = Arc::new(AtomicUsize::new(0));

        let mut joins = Vec::with_capacity(10);
        for _ in 0..10 {
            let b = barrier.clone();
            let id = base_identity.clone();
            let se = side_effect_runs.clone();
            let sc = started_count.clone();
            let jc = joined_count.clone();
            joins.push(tokio::spawn(async move {
                b.wait().await;
                match register_or_join_turn(id) {
                    TurnRegistrationOutcome::Started(handle) => {
                        sc.fetch_add(1, Ordering::SeqCst);
                        // Hold active ownership briefly while sibling tasks hit AlreadyRunning
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        se.fetch_add(1, Ordering::SeqCst);
                        let res = json!({
                            "turn_id": handle.turn_id,
                            "task_id": "task_sole_owner_01",
                            "session_id": "ses_h01_alpha",
                            "status": "completed",
                            "reply": "Volume set to 35%",
                        });
                        assert!(complete_turn_atomic(&handle, res.clone(), true));
                        res
                    }
                    TurnRegistrationOutcome::AlreadyRunning(handle) => {
                        jc.fetch_add(1, Ordering::SeqCst);
                        handle
                            .wait_finished_result()
                            .await
                            .expect("AlreadyRunning follower must receive finished result")
                    }
                    TurnRegistrationOutcome::IdempotentReplay(cached) => {
                        jc.fetch_add(1, Ordering::SeqCst);
                        cached
                    }
                    TurnRegistrationOutcome::Conflict { reason } => {
                        panic!("unexpected Conflict for identical TurnIdentity: {reason}")
                    }
                    TurnRegistrationOutcome::PreCancelled => {
                        panic!("unexpected PreCancelled")
                    }
                }
            }));
        }

        let mut results = Vec::with_capacity(10);
        for j in joins {
            results.push(j.await.unwrap());
        }

        assert_eq!(
            side_effect_runs.load(Ordering::SeqCst),
            1,
            "side effect closure must execute strictly once across 10 concurrent callers"
        );
        assert_eq!(started_count.load(Ordering::SeqCst), 1);
        assert_eq!(joined_count.load(Ordering::SeqCst), 9);
        for r in &results {
            assert_eq!(r["task_id"], "task_sole_owner_01");
            assert_eq!(r["reply"], "Volume set to 35%");
            assert_eq!(r["status"], "completed");
        }

        // Subsequent identical request within TTL gets IdempotentReplay
        match register_or_join_turn(base_identity) {
            TurnRegistrationOutcome::IdempotentReplay(replayed) => {
                assert_eq!(replayed["task_id"], "task_sole_owner_01");
            }
            _ => panic!("expected IdempotentReplay on sequential retry within TTL"),
        }
    }

    #[test]
    fn h01_conflict_on_mismatched_session_payload_privacy_and_ephemeral_isolation() {
        let turn_id = format!("h01_conflict_{}", uuid::Uuid::new_v4().simple());
        let id_owner = TurnIdentity::from_request(
            &turn_id,
            Some("ses_owner"),
            "summarize ~/notes/work.md",
            Some("clip_a"),
            true,
            "openai:gpt-4o",
            "managed_broker_tools",
            PrivacySessionPolicy::Standard,
        );

        let handle = match register_or_join_turn(id_owner.clone()) {
            TurnRegistrationOutcome::Started(h) => h,
            _ => panic!("expected Started"),
        };

        // 1. Different session_id while Running -> Conflict
        let diff_session = TurnIdentity::from_request(
            &turn_id,
            Some("ses_attacker"),
            "summarize ~/notes/work.md",
            Some("clip_a"),
            true,
            "openai:gpt-4o",
            "managed_broker_tools",
            PrivacySessionPolicy::Standard,
        );
        assert!(matches!(
            register_or_join_turn(diff_session.clone()),
            TurnRegistrationOutcome::Conflict { .. }
        ));

        // 2. Different request payload (user_text or allow_broker_tools) while Running -> Conflict
        let diff_payload = TurnIdentity::from_request(
            &turn_id,
            Some("ses_owner"),
            "delete ~/notes/work.md",
            Some("clip_a"),
            true,
            "openai:gpt-4o",
            "managed_broker_tools",
            PrivacySessionPolicy::Standard,
        );
        assert!(matches!(
            register_or_join_turn(diff_payload.clone()),
            TurnRegistrationOutcome::Conflict { .. }
        ));

        // 3. Different privacy policy while Running -> Conflict
        let diff_privacy = TurnIdentity::from_request(
            &turn_id,
            Some("ses_owner"),
            "summarize ~/notes/work.md",
            Some("clip_a"),
            true,
            "openai:gpt-4o",
            "managed_broker_tools",
            PrivacySessionPolicy::StrictIsolated,
        );
        assert!(matches!(
            register_or_join_turn(diff_privacy.clone()),
            TurnRegistrationOutcome::Conflict { .. }
        ));

        assert!(complete_turn_atomic(
            &handle,
            json!({ "turn_id": turn_id, "reply": "private_owner_summary", "status": "completed" }),
            true
        ));

        // 4. After completion, cross-session / tampered payload / privacy mismatch STILL Conflict (never leaks cache!)
        assert!(matches!(
            register_or_join_turn(diff_session),
            TurnRegistrationOutcome::Conflict { .. }
        ));
        assert!(matches!(
            register_or_join_turn(diff_payload),
            TurnRegistrationOutcome::Conflict { .. }
        ));
        assert!(matches!(
            register_or_join_turn(diff_privacy),
            TurnRegistrationOutcome::Conflict { .. }
        ));

        // 5. StrictIsolated & EphemeralReadOnly never cache finished payload for replay
        for priv_policy in [
            PrivacySessionPolicy::EphemeralReadOnly,
            PrivacySessionPolicy::StrictIsolated,
        ] {
            let p_turn = format!("h01_priv_{}", uuid::Uuid::new_v4().simple());
            let pid = TurnIdentity::from_request(
                &p_turn,
                Some("ses_priv"),
                "inspect system status",
                None,
                true,
                "openai:gpt-4o-mini",
                "managed_broker_tools",
                priv_policy,
            );
            let ph = match register_or_join_turn(pid.clone()) {
                TurnRegistrationOutcome::Started(h) => h,
                _ => panic!("expected Started for non-persistent privacy policy"),
            };
            assert!(complete_turn_atomic(
                &ph,
                json!({ "turn_id": p_turn, "reply": "ephemeral_secret", "status": "completed" }),
                true
            ));
            // Must NOT return IdempotentReplay because !privacy.allows_memory_write()
            match register_or_join_turn(pid) {
                TurnRegistrationOutcome::Started(ph2) => {
                    abort_turn_atomic(&ph2);
                }
                TurnRegistrationOutcome::IdempotentReplay(_) => {
                    panic!(
                        "Privacy policy {:?} must NEVER retain or replay cached turn outputs!",
                        priv_policy
                    );
                }
                _ => panic!("unexpected registration outcome"),
            }
        }
    }

    #[tokio::test]
    async fn h01_cancel_vs_complete_race_stale_instance_seq_and_ttl_capacity_eviction() {
        let now = Instant::now();
        let mut reg = TurnRegistry::new();

        // A. Cancel wins before complete_turn_at -> complete_turn_at rejected, stays Cancelled
        let id_cancel_wins = TurnIdentity::from_request(
            "turn_race_cancel_wins",
            Some("ses_race"),
            "long task",
            None,
            true,
            "openai:gpt-4o-mini",
            "managed_broker_tools",
            PrivacySessionPolicy::Standard,
        );
        let h_cancel = match reg.register_or_join_at(id_cancel_wins.clone(), None, now) {
            TurnRegistrationOutcome::Started(h) => h,
            _ => panic!("expected Started"),
        };
        let waiter_handle = h_cancel.clone();
        let waiter = tokio::spawn(async move { waiter_handle.wait_finished_result().await });

        h_cancel.cancel();
        reg.push_cancelled_entry(CancelledTurnEntry {
            turn_id: "turn_race_cancel_wins".to_string(),
            instance_seq: Some(h_cancel.instance_seq),
            identity: Some(id_cancel_wins.clone()),
            cancelled_at: now,
        });

        assert!(
            !reg.complete_turn_at(
                &h_cancel,
                json!({ "status": "completed", "reply": "late_finish" }),
                true,
                now
            ),
            "cancelled turn must never overwrite Cancelled state with Finished"
        );
        assert_eq!(
            reg.lifecycle_state("turn_race_cancel_wins", now),
            Some(TurnLifecycleState::Cancelled)
        );
        assert!(
            waiter.await.unwrap().is_none(),
            "AlreadyRunning waiter must wake with None on cancellation"
        );
        assert!(matches!(
            reg.register_or_join_at(id_cancel_wins, None, now),
            TurnRegistrationOutcome::PreCancelled
        ));

        // B. Stale instance_seq handle must NEVER evict or overwrite newer turn owner
        let id_stale = TurnIdentity::from_request(
            "turn_stale_seq",
            Some("ses_stale"),
            "query status",
            None,
            true,
            "openai:gpt-4o-mini",
            "managed_broker_tools",
            PrivacySessionPolicy::Standard,
        );
        let h1 = match reg.register_or_join_at(id_stale.clone(), None, now) {
            TurnRegistrationOutcome::Started(h) => h,
            _ => panic!("expected Started h1"),
        };
        assert!(reg.abort_turn(&h1));

        let h2 = match reg.register_or_join_at(id_stale.clone(), None, now) {
            TurnRegistrationOutcome::Started(h) => h,
            _ => panic!("expected Started h2"),
        };
        assert!(h2.instance_seq > h1.instance_seq);

        // Stale h1 tries to abort and complete while h2 is active -> both rejected!
        assert!(!reg.abort_turn(&h1));
        assert!(!reg.complete_turn_at(
            &h1,
            json!({ "status": "completed", "reply": "stale_h1" }),
            true,
            now
        ));
        assert_eq!(
            reg.lifecycle_state("turn_stale_seq", now),
            Some(TurnLifecycleState::Running)
        );

        // Valid owner h2 completes cleanly into PausedApproval when pending_approval is set
        assert!(reg.complete_turn_at(
            &h2,
            json!({
                "status": "awaiting_approval",
                "pending_approval": { "approval_id": "apr_1" }
            }),
            true,
            now
        ));
        assert_eq!(
            reg.lifecycle_state("turn_stale_seq", now),
            Some(TurnLifecycleState::PausedApproval)
        );

        // C. 300s TTL eviction & 64-entry max capacity eviction
        let mut reg_ttl = TurnRegistry::new();
        for idx in 0..(MAX_COMPLETED_TURN_CACHE + 1) {
            let tid = format!("turn_cap_{idx}");
            let tid_ident = TurnIdentity::from_request(
                &tid,
                Some("ses_cap"),
                &format!("cmd {idx}"),
                None,
                true,
                "openai:gpt-4o-mini",
                "managed_broker_tools",
                PrivacySessionPolicy::Standard,
            );
            let h = match reg_ttl.register_or_join_at(tid_ident, None, now) {
                TurnRegistrationOutcome::Started(h) => h,
                _ => panic!("expected Started"),
            };
            assert!(reg_ttl.complete_turn_at(
                &h,
                json!({ "idx": idx, "status": "completed" }),
                true,
                now
            ));
        }
        // Entry 0 was evicted by capacity cap (64); entry 1 is still cached at t = now + 299s
        let id_0 = TurnIdentity::from_request(
            "turn_cap_0",
            Some("ses_cap"),
            "cmd 0",
            None,
            true,
            "openai:gpt-4o-mini",
            "managed_broker_tools",
            PrivacySessionPolicy::Standard,
        );
        match reg_ttl.register_or_join_at(id_0, None, now) {
            TurnRegistrationOutcome::Started(h0) => {
                reg_ttl.abort_turn(&h0);
            }
            _ => panic!("oldest entry beyond MAX_COMPLETED_TURN_CACHE (64) must be evicted"),
        }

        let id_1 = TurnIdentity::from_request(
            "turn_cap_1",
            Some("ses_cap"),
            "cmd 1",
            None,
            true,
            "openai:gpt-4o-mini",
            "managed_broker_tools",
            PrivacySessionPolicy::Standard,
        );
        assert!(matches!(
            reg_ttl.register_or_join_at(id_1.clone(), None, now + Duration::from_secs(299)),
            TurnRegistrationOutcome::IdempotentReplay(_)
        ));
        // Past 300s TTL -> evicted, starts fresh!
        match reg_ttl.register_or_join_at(id_1, None, now + Duration::from_secs(301)) {
            TurnRegistrationOutcome::Started(h_fresh) => {
                reg_ttl.abort_turn(&h_fresh);
            }
            _ => panic!("completed entry older than 300s TTL must be evicted"),
        }
    }

    #[tokio::test]
    async fn h03_cross_restart_checkpoint_resume_succeeds_and_rejects_tampered_digest_session_or_scope()
     {
        use crate::backend_bridge::broker_bridge::{
            QuickChatToolExecOutcome, execute_quick_chat_tool_call,
        };
        use crate::config::{AppConfig, BrainConfig, XdgPaths};
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("base");
        let auth_ws = tmp.path().join("auth_workspace");
        let external_dir = tmp.path().join("external_requires_approval");
        let fake_home = tmp.path().join("fake_home");
        std::fs::create_dir_all(&auth_ws).unwrap();
        std::fs::create_dir_all(&external_dir).unwrap();
        std::fs::create_dir_all(&fake_home).unwrap();

        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let xdg = XdgPaths::resolve(Some(&base), repo_root.clone());
        xdg.ensure_dirs().unwrap();
        let cfg = AppConfig {
            authorized_directories: vec![auth_ws.to_string_lossy().to_string()],
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

        let offline_opts = DiscoveryOptions {
            home_dir: fake_home.clone(),
            extra_bin_dirs: Vec::new(),
            include_system_paths: false,
            opt_zcode_cjs: None,
            ollama_tags_url: None,
            ollama_timeout_ms: 50,
            allow_env_keys: false,
            probe_remote_models: false,
            force_refresh_models: false,
        };
        let active = ActiveBackendSelection {
            backend: "openai".into(),
            provider: "test".into(),
            model: "gpt-4o-mini".into(),
            reasoning_effort: "medium".into(),
            base_url: None,
            pinned: false,
            auto_selected: true,
            direct_http_capable: true,
            pill_label: "OpenAI".into(),
        };

        let approved_file = external_dir.join("resumed_after_restart.txt");
        let raw_secret = "sk-restartSecretToken1234567890abcdef";
        let (approval_id, valid_digest, valid_nonce, task_id) = {
            // --- Daemon Instance #1 (`core1`) ---
            let core1 = IntentOsCore::initialize(Some(&base), repo_root.clone()).unwrap();
            let session = core1.sessions.get_or_create(Some("ses_h03_restart_owner"));
            let mut ledger = TurnEffectLedger::new("turn_h03_suspend")
                .with_privacy(PrivacySessionPolicy::Standard);
            let task_id = "task_h03_restart_01".to_string();
            let write_args = json!({
                "path": approved_file.to_string_lossy(),
                "content": "verified across daemon restart!"
            });

            let out = execute_quick_chat_tool_call(
                &core1,
                &active,
                BackendExecutionMode::ManagedBrokerTools,
                &task_id,
                &session,
                "write external report",
                false,
                &[Taint::User],
                DataClass::Personal,
                "call_pause_1",
                "file_write",
                &write_args,
                &mut ledger,
            )
            .await
            .expect("tool dispatch");

            let pa = match out {
                QuickChatToolExecOutcome::PausedForApproval { outcome, .. } => outcome
                    .pending_approval
                    .expect("must carry PendingApproval"),
                other => panic!(
                    "expected PausedForApproval, got {:?}",
                    matches!(other, QuickChatToolExecOutcome::ToolMessage { .. })
                ),
            };

            // Step must be recorded as `Prepared` (`AwaitingApproval`) before approval
            let prep_log = core1
                .state_db
                .get_step_execution_log(&task_id, "step_1")
                .unwrap()
                .expect("Prepared step row must exist");
            assert_eq!(prep_log.exec_state, StepExecState::Prepared);

            let cp = SuspendedTurnCheckpoint {
                created_at_instant: Instant::now(),
                approval_id: pa.approval_id.clone(),
                pending_approval: pa.clone(),
                task_id: task_id.clone(),
                session,
                user_text: "write external report".into(),
                incognito: false,
                active: active.clone(),
                discovery_opts: offline_opts.clone(),
                extra_blocks: Vec::new(),
                sys_text: "system".into(),
                taints: vec![Taint::User],
                data_class: DataClass::Personal,
                memory_hits: Vec::new(),
                memory_dot: None,
                context_compression: crate::memory_hub::ContextCompressionStats::default(),
                rounds_used: 1,
                paused_call_id: "call_pause_1".into(),
                paused_canonical_tool: "file.write".into(),
                paused_parsed_args: write_args,
                remaining_tool_calls: Vec::new(),
                effect_ledger: ledger,
                dialect: SuspendedDialectState::Anthropic {
                    base_url: "http://127.0.0.1:9".into(),
                    api_key: Some(raw_secret.into()),
                    trust: ProviderTrust::Trusted,
                    messages: vec![json!({
                        "role": "user",
                        "content": format!("context note with token {}", raw_secret)
                    })],
                    prior_tool_results: Vec::new(),
                    tools: Vec::new(),
                },
            };
            save_suspended_checkpoint(cp);

            let saved_row = core1
                .state_db
                .get_suspended_checkpoint_row(&pa.approval_id)
                .unwrap()
                .expect("Standard checkpoint must be persisted to SQLite");
            assert!(
                !saved_row.checkpoint_json.contains(raw_secret),
                "SensitiveDataGuard + PersistedDialectStateDto must scrub raw API keys from SQLite"
            );

            // Also verify EphemeralReadOnly & StrictIsolated checkpoints NEVER touch SQLite!
            let mut incog_cp = SUSPENDED_APPROVAL_TURNS
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .get(&pa.approval_id)
                .unwrap()
                .clone();
            incog_cp.approval_id = "apr_ephemeral_only".into();
            incog_cp.pending_approval.approval_id = "apr_ephemeral_only".into();
            assert!(
                !save_suspended_checkpoint_with_db(
                    &core1.state_db,
                    incog_cp.clone(),
                    PrivacySessionPolicy::EphemeralReadOnly,
                )
                .unwrap()
            );
            incog_cp.approval_id = "apr_strict_isolated".into();
            incog_cp.pending_approval.approval_id = "apr_strict_isolated".into();
            assert!(
                !save_suspended_checkpoint_with_db(
                    &core1.state_db,
                    incog_cp,
                    PrivacySessionPolicy::StrictIsolated,
                )
                .unwrap()
            );
            assert_eq!(core1.state_db.count_suspended_checkpoints().unwrap(), 1);

            (pa.approval_id, pa.digest, pa.nonce, task_id)
        };

        // Simulate full daemon restart: wipe all in-memory checkpoints and open a fresh `Core 2`!
        clear_in_memory_suspended_checkpoints();
        assert!(!approved_file.exists());

        let core2 = IntentOsCore::initialize(Some(&base), repo_root).unwrap();

        // (a) Reject wrong `session_id` (cross-session hijack attempt) without consuming valid checkpoint
        let bad_session_err = resume_persisted_checkpoint_across_restart(
            &core2,
            &json!({
                "approval_id": approval_id,
                "session_id": "ses_attacker_other",
                "digest": valid_digest,
                "decision": "once"
            }),
            &offline_opts,
        )
        .await
        .expect_err("mismatched session_id must be rejected");
        assert!(bad_session_err.to_string().contains("session_id"));

        // (b) Reject tampered `approval_digest`
        let bad_digest_err = resume_persisted_checkpoint_across_restart(
            &core2,
            &json!({
                "approval_id": approval_id,
                "session_id": "ses_h03_restart_owner",
                "digest": "0000000000000000deadbeef",
                "decision": "once"
            }),
            &offline_opts,
        )
        .await
        .expect_err("tampered approval_digest must be rejected");
        assert!(bad_digest_err.to_string().contains("approval_digest"));

        // (c) Reject mismatched/escalated `scope_value`
        let bad_scope_err = resume_persisted_checkpoint_across_restart(
            &core2,
            &json!({
                "approval_id": approval_id,
                "session_id": "ses_h03_restart_owner",
                "digest": valid_digest,
                "decision": "session",
                "scope_kind": "directory",
                "scope_value": "/etc"
            }),
            &offline_opts,
        )
        .await
        .expect_err("tampered scope_value must be rejected");
        assert!(bad_scope_err.to_string().contains("作用域"));

        // (d) Reject tampered checkpoint in SQLite pointing to forbidden `~/.ssh/id_ed25519`
        {
            let mut poisoned_row = core2
                .state_db
                .get_suspended_checkpoint_row(&approval_id)
                .unwrap()
                .unwrap();
            let mut poisoned_dto: PersistedCheckpointDto =
                serde_json::from_str(&poisoned_row.checkpoint_json).unwrap();
            let forbidden_args = json!({
                "path": "~/.ssh/id_ed25519",
                "content": "malicious key overwrite"
            });
            let forbidden_digest = PendingApproval::compute_digest("file.write", &forbidden_args);
            poisoned_dto.approval_id = "apr_poisoned_ssh".into();
            poisoned_dto.pending_approval.approval_id = "apr_poisoned_ssh".into();
            poisoned_dto.pending_approval.arguments = forbidden_args.clone();
            poisoned_dto.pending_approval.digest = forbidden_digest.clone();
            poisoned_dto.paused_parsed_args = forbidden_args;
            poisoned_row.approval_id = "apr_poisoned_ssh".into();
            poisoned_row.approval_digest = forbidden_digest.clone();
            poisoned_row.target_scope =
                compute_checkpoint_target_scope(&poisoned_dto.pending_approval);
            poisoned_row.checkpoint_json = serde_json::to_string(&poisoned_dto).unwrap();
            core2
                .state_db
                .save_suspended_checkpoint_row(&poisoned_row, PrivacySessionPolicy::Standard)
                .unwrap();

            let ssh_err = resume_persisted_checkpoint_across_restart(
                &core2,
                &json!({
                    "approval_id": "apr_poisoned_ssh",
                    "session_id": "ses_h03_restart_owner",
                    "digest": forbidden_digest,
                    "decision": "once"
                }),
                &offline_opts,
            )
            .await
            .expect_err(
                "forbidden ~/.ssh checkpoint must be rejected by PolicyEngine/SafeFsEngine",
            );
            assert!(
                ssh_err.to_string().contains("forbidden")
                    || ssh_err.to_string().contains("受禁")
                    || ssh_err.to_string().contains("拒绝")
            );
            assert!(
                core2
                    .state_db
                    .get_suspended_checkpoint_row("apr_poisoned_ssh")
                    .unwrap()
                    .is_none(),
                "poisoned checkpoint must be purged upon rejection"
            );
        }

        // (e) Legitimate approval resume across daemon restart succeeds and verifies!
        let resumed = resume_persisted_checkpoint_across_restart(
            &core2,
            &json!({
                "approval_id": approval_id,
                "session_id": "ses_h03_restart_owner",
                "digest": valid_digest,
                "nonce": valid_nonce,
                "decision": "once"
            }),
            &offline_opts,
        )
        .await
        .expect("valid cross-restart checkpoint resume must succeed");

        assert_eq!(resumed["status"], "completed");
        assert_eq!(resumed["approval_resolved"], "approved");
        assert_eq!(
            std::fs::read_to_string(&approved_file).unwrap(),
            "verified across daemon restart!"
        );

        let post_step = core2
            .state_db
            .get_step_execution_log(&task_id, "step_1")
            .unwrap()
            .expect("step_1 must be updated in step_execution_log");
        assert_eq!(post_step.exec_state, StepExecState::Verified);
        assert!(post_step.changeset_id.is_some());

        // Checkpoint row consumed: a second replay with the same valid payload must fail!
        assert_eq!(core2.state_db.count_suspended_checkpoints().unwrap(), 0);
        assert!(
            resume_persisted_checkpoint_across_restart(
                &core2,
                &json!({
                    "approval_id": approval_id,
                    "session_id": "ses_h03_restart_owner",
                    "digest": valid_digest,
                    "decision": "once"
                }),
                &offline_opts,
            )
            .await
            .is_err(),
            "consumed checkpoint must never replay a second time"
        );
    }
}
