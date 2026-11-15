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
use crate::security_guard::PrivacySessionPolicy;
use intentos_protocol::{
    ContextBlock, DataClass, Effect, ExecutionStatus, PendingApproval, ProviderTrust, Taint,
    TaskStep,
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

/// Rich per-step metadata tracked alongside `StepExecutionRecord` inside `TurnEffectLedger`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecutionMeta {
    pub step_id: String,
    pub call_id: String,
    pub attempt_id: String,
    pub policy: ToolIdempotencyPolicy,
    pub pre_state_epoch: u64,
    pub post_state_epoch: u64,
    pub is_error: bool,
    pub was_denied: bool,
    pub verification_status: String,
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
            state_epoch: 0,
            records: Vec::new(),
            step_metadata: Vec::new(),
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
        let meta = StepExecutionMeta {
            step_id: record.step_id.clone(),
            call_id: record.step_id.clone(),
            attempt_id: "attempt_1".to_string(),
            policy: default_policy,
            pre_state_epoch: pre_epoch,
            post_state_epoch: post_epoch,
            is_error: record.is_error(),
            was_denied: record.was_denied(),
            verification_status: record.verification_status.clone(),
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

    pub fn step_metadata(&self) -> &[StepExecutionMeta] {
        &self.step_metadata
    }

    /// Export a structured JSON summary of this turn's effect ledger for UI & audit diagnostics.
    pub fn summary_json(&self) -> Value {
        json!({
            "turn_id": self.turn_id,
            "state_epoch": self.state_epoch,
            "total_steps": self.records.len(),
            "mutated_steps": self.records.iter().filter(|r| r.mutated_state).count(),
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
}
