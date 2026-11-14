#![forbid(unsafe_code)]

//! IntentOS frozen protocol types (v1).
//! Covers Intent, Task, CapabilityDescriptor, Effect, DataClass, Taint,
//! GrantEnvelope, PendingApproval, ChangeSet, AgentRuntime IPC, and UI RPC.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u32 = 1;

/// Effect taxonomy (§7.3). Ordered by increasing impact severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Effect {
    #[serde(rename = "observe")]
    Observe = 0,
    #[serde(rename = "ui")]
    Ui = 1,
    #[serde(rename = "setting")]
    Setting = 2,
    #[serde(rename = "exec.sandboxed")]
    ExecSandboxed = 3,
    #[serde(rename = "write.reversible")]
    WriteReversible = 4,
    #[serde(rename = "egress")]
    Egress = 5,
    #[serde(rename = "process.control")]
    ProcessControl = 6,
    #[serde(rename = "write.destructive")]
    WriteDestructive = 7,
    #[serde(rename = "external.commit")]
    ExternalCommit = 8,
    #[serde(rename = "system.admin")]
    SystemAdmin = 9,
}

impl Effect {
    /// Simplified R0-R3 user-facing badge (§7.3).
    pub fn risk_badge(self) -> &'static str {
        match self {
            Self::Observe => "R0",
            Self::Ui | Self::Setting => "R1",
            Self::ExecSandboxed | Self::WriteReversible => "R2",
            Self::Egress
            | Self::ProcessControl
            | Self::WriteDestructive
            | Self::ExternalCommit
            | Self::SystemAdmin => "R3",
        }
    }

    pub fn is_reversible_by_default(self) -> bool {
        matches!(self, Self::Setting | Self::WriteReversible)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Ui => "ui",
            Self::Setting => "setting",
            Self::ExecSandboxed => "exec.sandboxed",
            Self::WriteReversible => "write.reversible",
            Self::Egress => "egress",
            Self::ProcessControl => "process.control",
            Self::WriteDestructive => "write.destructive",
            Self::ExternalCommit => "external.commit",
            Self::SystemAdmin => "system.admin",
        }
    }
}

/// Data sensitivity classification for Model Gateway egress control (§5.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataClass {
    #[default]
    Public = 0,
    Personal = 1,
    Sensitive = 2,
    Forbidden = 3,
}

/// Provider trust tier (§5.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderTrust {
    Trusted,
    #[default]
    Standard,
    Untrusted,
}

/// Provenance taint tag attached to every context block (§10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Taint {
    #[serde(rename = "user")]
    User,
    #[serde(rename = "system")]
    System,
    #[serde(rename = "memory")]
    Memory,
    #[serde(rename = "local.untrusted")]
    LocalUntrusted,
    #[serde(rename = "remote.untrusted")]
    RemoteUntrusted,
    #[serde(rename = "sensitive")]
    Sensitive,
}

impl Taint {
    pub fn is_untrusted(self) -> bool {
        matches!(self, Self::LocalUntrusted | Self::RemoteUntrusted)
    }
}

/// Routing layer (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RouteLayer {
    L0,
    L1,
    L2,
    #[serde(rename = "passthrough")]
    Passthrough,
}

/// Origin of a capability invocation (§10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationOrigin {
    UserExplicit,
    L1Inferred,
    L2AgentPlan,
    BackgroundAutomation,
}

/// Policy Engine decision (§10.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    AllowWithUndo,
    PreviewAndApprove { reason: String },
    ConfirmEach { reason: String },
    Deny { reason: String },
}

impl PolicyDecision {
    pub fn requires_approval(&self) -> bool {
        matches!(
            self,
            Self::PreviewAndApprove { .. } | Self::ConfirmEach { .. }
        )
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Verification outcome (§8.6). Principle 1: never claim unverified completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Passed,
    VerificationFailed,
    RequestedUnverified,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub state: VerificationState,
    pub method: String,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub details: Option<String>,
}

/// Execution status (§8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Spawned,
    Running,
    Exited,
    Timeout,
    Cancelled,
    Denied,
    VerificationFailed,
    RequestedUnverified,
}

/// Capability Descriptor — single source of truth (§7.2, §7.8.4, §8.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDescriptor {
    pub id: String,
    #[serde(default = "default_version")]
    pub version: u32,
    pub summary: String,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub l0_patterns: Vec<String>,
    #[serde(default = "default_object_schema")]
    pub input_schema: serde_json::Value,
    pub effects: Vec<Effect>,
    #[serde(default)]
    pub idempotent: bool,
    pub execution: ExecutionBackend,
    #[serde(default)]
    pub setting: Option<SettingMeta>,
    #[serde(default)]
    pub undo: UndoStrategy,
    #[serde(default)]
    pub verification: Option<VerificationRule>,
    #[serde(default)]
    pub feedback: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

fn default_version() -> u32 {
    1
}

fn default_category() -> String {
    "general".to_string()
}

fn default_object_schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": {} })
}

impl CapabilityDescriptor {
    pub fn max_effect(&self) -> Effect {
        self.effects.iter().copied().max().unwrap_or(Effect::Observe)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutionBackend {
    /// E1 registered command template — never uses a shell.
    ArgvTemplate {
        executable: String,
        arguments: Vec<String>,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
    /// Built-in Rust handler inside Core (e.g., E3 fsops, resource queries, web open).
    Builtin { handler: String },
    /// Unified System Settings framework (§7.8).
    SettingBackend {
        driver: SettingDriver,
        #[serde(default)]
        schema: Option<String>,
        #[serde(default)]
        key: Option<String>,
    },
}

fn default_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingDriver {
    Gsettings,
    WpctlVolume,
    WpctlMute,
    WpctlMicVolume,
    WpctlMicMute,
    AudioOutput,
    Backlight,
    NightLight,
    NightLightTemp,
    IdleDelay,
    ColorScheme,
    AccentColor,
    Font,
    CursorSize,
    Animations,
    Wallpaper,
    Clock,
    Dnd,
    Autolock,
    ScreenLock,
    WifiPower,
    WifiConnect,
    BluetoothPower,
    BluetoothConnect,
    AirplaneMode,
    PowerProfile,
    PowerSession,
    MouseSpeed,
    TouchpadSpeed,
    TouchpadNaturalScroll,
    TouchpadTapToClick,
    KeyboardRepeat,
    InputSource,
    MediaControl,
    Screenshot,
    Scene,
    ControlCenter,
    Reset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingMeta {
    pub key_id: String,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    #[serde(default)]
    pub step: Option<f64>,
    #[serde(default)]
    pub discrete_steps: Vec<f64>,
    #[serde(default)]
    pub enum_values: Vec<String>,
    #[serde(default)]
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndoStrategy {
    #[default]
    None,
    Changeset,
    RestorePreviousValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRule {
    pub kind: String,
    #[serde(default)]
    pub tolerance: Option<f64>,
}

/// Capability invocation request & result (§7.4, §8.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCall {
    pub request_id: String,
    pub task_id: String,
    pub capability_id: String,
    pub arguments: serde_json::Value,
    pub origin: InvocationOrigin,
    #[serde(default)]
    pub taints: Vec<Taint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityResult {
    pub request_id: String,
    pub capability_id: String,
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub message: String,
    #[serde(default)]
    pub data: serde_json::Value,
    #[serde(default)]
    pub stdout_preview: String,
    #[serde(default)]
    pub stderr_preview: String,
    #[serde(default)]
    pub truncated: bool,
    pub duration_ms: u64,
    #[serde(default)]
    pub changeset_id: Option<String>,
    pub verification: VerificationReport,
    #[serde(default)]
    pub backend_mode: String,
}

/// File identity (`dev` + `ino`) for ChangeSet conflict detection (§9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ChangeOp {
    Move {
        from: String,
        to: String,
        #[serde(default)]
        fs_id: Option<FileIdentity>,
        post_hash: String,
    },
    Copy {
        from: String,
        to: String,
        post_hash: String,
    },
    Create {
        path: String,
        post_hash: String,
    },
    Trash {
        original_path: String,
        trash_data_path: String,
        trash_info_path: String,
        pre_hash: String,
    },
    Overwrite {
        path: String,
        backup_path: String,
        pre_hash: String,
        post_hash: String,
    },
    Setting {
        capability_id: String,
        key: String,
        before: serde_json::Value,
        after: serde_json::Value,
        backend_mode: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSetStatus {
    Applied,
    Undone,
    Expired,
    Conflict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet {
    pub id: String,
    pub task_id: String,
    pub created_at: DateTime<Utc>,
    pub capability_id: String,
    pub layer: String,
    pub operations: Vec<ChangeOp>,
    pub backup_bytes: u64,
    pub status: ChangeSetStatus,
    pub undo_expires_at: DateTime<Utc>,
    #[serde(default)]
    pub summary: String,
}

/// Grant Envelope for multi-step bounded authorization (§10.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantEnvelope {
    pub envelope_id: String,
    pub task_id: String,
    pub capabilities: Vec<String>,
    pub resource_scope: Vec<String>,
    pub max_effect: Effect,
    pub max_operations: u32,
    pub network: bool,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
    pub policy_version: u32,
}

/// Nonce-bound Pending Approval (§10.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub approval_id: String,
    pub task_id: String,
    pub capability_id: String,
    pub arguments: serde_json::Value,
    pub summary: String,
    pub diff_preview: String,
    pub effects: Vec<Effect>,
    pub reversible: bool,
    pub nonce: String,
    pub digest: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PendingApproval {
    pub fn compute_digest(capability_id: &str, arguments: &serde_json::Value) -> String {
        let canonical = serde_json::to_string(arguments).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(capability_id.as_bytes());
        hasher.update(b":");
        hasher.update(canonical.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

/// Intent & Real-time Candidate structures (§3.1, §4, §15.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentRequest {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
    pub text: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub force_agent: bool,
    #[serde(default)]
    pub selected_candidate_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// Temporary privacy session (`M-01`, §11.3, §18.2): never stores history or memory candidates.
    #[serde(default)]
    pub incognito: bool,
}

fn default_protocol_version() -> u32 {
    PROTOCOL_VERSION
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    App,
    File,
    Web,
    WebSearch,
    Setting,
    Capability,
    Passthrough,
    Undo,
    AgentFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateItem {
    pub id: String,
    pub kind: CandidateKind,
    pub title: String,
    pub subtitle: String,
    pub badge: String,
    pub score: f64,
    pub capability_id: Option<String>,
    #[serde(default)]
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub resource_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateResponse {
    pub query: String,
    pub elapsed_us: u64,
    pub l0_direct_match: bool,
    pub items: Vec<CandidateItem>,
}

/// Task object & lifecycle (§13.1, §13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Created,
    Planning,
    AwaitingApproval,
    Running,
    Paused,
    Verifying,
    Completed,
    PartiallyCompleted,
    Failed,
    Cancelled,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskTrigger {
    User,
    Schedule,
    Event,
    Resume,
    Workflow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStep {
    pub step_id: String,
    pub capability_id: String,
    pub arguments_summary: String,
    pub status: ExecutionStatus,
    pub verification: VerificationReport,
    #[serde(default)]
    pub changeset_id: Option<String>,
    pub message: String,
    #[serde(default)]
    pub data: serde_json::Value,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskBudget {
    pub max_tool_calls: u32,
    pub max_runtime_seconds: u64,
    #[serde(default)]
    pub max_cost: Option<f64>,
}

impl Default for TaskBudget {
    fn default() -> Self {
        Self {
            max_tool_calls: 30,
            max_runtime_seconds: 180,
            max_cost: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub goal: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    pub trigger: TaskTrigger,
    pub route: RouteLayer,
    pub status: TaskStatus,
    pub steps: Vec<TaskStep>,
    #[serde(default)]
    pub changeset_ids: Vec<String>,
    #[serde(default)]
    pub pending_approval: Option<PendingApproval>,
    #[serde(default)]
    pub candidates_for_disambiguation: Vec<CandidateItem>,
    #[serde(default)]
    pub assistant_message: Option<String>,
    #[serde(default)]
    pub result_summary: Option<String>,
    #[serde(default)]
    pub handoff_command: Option<String>,
    #[serde(default)]
    pub taint: Vec<Taint>,
    #[serde(default)]
    pub data_class: DataClass,
    pub budget: TaskBudget,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Decision Adapter types (§4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRequest {
    pub state: serde_json::Value,
    pub questions: Vec<DecisionQuestion>,
    pub data_class: DataClass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DecisionQuestion {
    Binary {
        id: String,
        prompt: String,
    },
    Choice {
        id: String,
        prompt: String,
        options: Vec<String>,
    },
    Score {
        id: String,
        prompt: String,
        scale: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionAnswer {
    pub id: String,
    #[serde(default)]
    pub probability: Option<f64>,
    #[serde(default)]
    pub distribution: Option<BTreeMap<String, f64>>,
    #[serde(default)]
    pub value: Option<f64>,
    pub confidence: f64,
}

/// AgentRuntime protocol (§6.3) between Core and Worker (`pi-adapter` or `native`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub protocol_version: u32,
    pub gateway_socket_path: Option<String>,
    pub gateway_http_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub name: String,
    pub version: String,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBlock {
    pub id: String,
    pub label: String,
    pub content: String,
    pub taint: Taint,
    pub data_class: DataClass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    pub run_id: String,
    pub session_id: String,
    pub task_id: String,
    pub run_token: String,
    pub model_id: String,
    pub history: Vec<ChatMessage>,
    pub input: ChatMessage,
    pub context_blocks: Vec<ContextBlock>,
    pub tools: Vec<ToolSpec>,
    pub model_profile: String,
    pub budget: TaskBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RuntimeEvent {
    #[serde(rename = "run.started")]
    RunStarted { run_id: String },
    #[serde(rename = "message.delta")]
    MessageDelta { run_id: String, delta: String },
    #[serde(rename = "tool.requested")]
    ToolRequested {
        run_id: String,
        call_id: String,
        tool_name: String,
        arguments: serde_json::Value,
    },
    #[serde(rename = "tool.result")]
    ToolResult {
        run_id: String,
        call_id: String,
        output: serde_json::Value,
        is_error: bool,
    },
    #[serde(rename = "usage.updated")]
    UsageUpdated {
        run_id: String,
        input_tokens: u64,
        output_tokens: u64,
    },
    #[serde(rename = "run.finished")]
    RunFinished {
        run_id: String,
        final_message: String,
    },
    #[serde(rename = "run.failed")]
    RunFailed { run_id: String, error: String },
    #[serde(rename = "run.cancelled")]
    RunCancelled { run_id: String },
}

/// Core Event contract (§15.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreEvent {
    pub protocol_version: u32,
    pub event_id: String,
    pub sequence: u64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub task_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub payload: serde_json::Value,
}

/// Persistent explicit memory record (§11.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: String,
    pub mem_type: String,
    pub scope: String,
    pub subject: String,
    pub value: String,
    pub confidence: f64,
    pub data_class: DataClass,
    pub created_at: String,
    pub updated_at: String,
}

/// Private UI Channel JSON-RPC messages (§15.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum UiRpcRequest {
    QueryCandidates {
        query: String,
    },
    SubmitIntent(IntentRequest),
    Approve {
        approval_id: String,
        nonce: String,
        digest: String,
    },
    Deny {
        approval_id: String,
    },
    Undo {
        target_id: Option<String>,
    },
    RunPassthrough {
        command: String,
        cwd: Option<String>,
        confirmed_risky: bool,
    },
    ListTasks {
        limit: usize,
    },
    GetTask {
        task_id: String,
    },
    ListChangesets {
        limit: usize,
    },
    ListMemories,
    UpsertMemory {
        subject: String,
        value: String,
    },
    DeleteMemory {
        id: String,
    },
    ListScenes,
    SaveScene {
        name: String,
    },
    ListPassthroughHistory {
        limit: usize,
    },
    ClearPassthroughHistory,
    GetSettingsOverview,
    UpdateAuthorizedDirectories {
        directories: Vec<String>,
    },
    UpdateWebSettings {
        default_search: String,
    },
    UpdateBrainSettings {
        runtime: String,
        main_provider: String,
        main_model: String,
    },
    GetStatus,
    ProbeCapabilities,
    StopAll,
    ReindexResources,
    /// Modular domain RPC dispatch (`method = "module_rpc"`, `params = { "domain": "...", "action": "...", "payload": { ... } }`)
    /// Enables parallel functional modules (`intent_engine`, `config_center`, `execution_hub`, `web_ui`) to expose rich APIs without central enum lock-in.
    ModuleRpc {
        domain: String,
        action: String,
        #[serde(default)]
        payload: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiRpcEnvelope {
    pub id: String,
    #[serde(flatten)]
    pub request: UiRpcRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiRpcResponse {
    pub id: String,
    pub ok: bool,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
    pub protocol_version: u32,
    pub pid: u32,
    pub uptime_seconds: u64,
    pub indexed_apps: usize,
    pub indexed_files: usize,
    pub indexed_sites: usize,
    pub registered_capabilities: usize,
    pub active_sessions: usize,
    pub pending_approvals: usize,
    pub undo_changesets_available: usize,
    pub undo_backup_bytes: u64,
    pub runtime_mode: String,
    pub main_model_configured: bool,
    pub default_search_engine: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_ordering_and_badges() {
        assert!(Effect::Observe < Effect::Ui);
        assert!(Effect::Setting < Effect::WriteReversible);
        assert!(Effect::WriteReversible < Effect::WriteDestructive);
        assert!(Effect::WriteDestructive < Effect::SystemAdmin);
        assert_eq!(Effect::Observe.risk_badge(), "R0");
        assert_eq!(Effect::Setting.risk_badge(), "R1");
        assert_eq!(Effect::WriteReversible.risk_badge(), "R2");
        assert_eq!(Effect::SystemAdmin.risk_badge(), "R3");
    }

    #[test]
    fn approval_digest_is_deterministic() {
        let args = serde_json::json!({"percent": 30});
        let d1 = PendingApproval::compute_digest("sound.volume.set", &args);
        let d2 = PendingApproval::compute_digest("sound.volume.set", &args);
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
    }
}
