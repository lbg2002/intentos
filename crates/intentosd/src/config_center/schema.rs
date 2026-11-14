#![forbid(unsafe_code)]

//! Complete strongly-typed configuration structs, defaults, and validators for all
//! 11 Settings Center domains (§5.1–§5.6, §14.2, §16.1):
//! 1. `overview`
//! 2. `brain`
//! 3. `memory_config`
//! 4. `capabilities_config`
//! 5. `resources_config`
//! 6. `web_config`
//! 7. `permissions_config`
//! 8. `undo_config`
//! 9. `automation_config`
//! 10. `interaction_config`
//! 11. `maintenance_config`

use crate::config::{
    AppConfig, BrainConfig, SearchEngineEntry, SiteEntry, builtin_search_engines, builtin_sites,
};
use crate::config_center::egress_matrix::{
    EgressMatrixConfig, ForbiddenPathRule, builtin_forbidden_rules,
};
use intentos_protocol::ProviderTrust;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const ALL_DOMAIN_KEYS: [&str; 11] = [
    "overview",
    "brain",
    "memory_config",
    "capabilities_config",
    "resources_config",
    "web_config",
    "permissions_config",
    "undo_config",
    "automation_config",
    "interaction_config",
    "maintenance_config",
];

pub const MODEL_ROLES: [&str; 5] = ["main", "fast", "decision", "vision", "memory"];

/// Normalize user/frontend domain key aliases (`"web"` -> `"web_config"`, `"memory"` -> `"memory_config"`, etc.).
pub fn normalize_domain_key(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "overview" => Some("overview"),
        "brain" | "brain_config" | "gateway" => Some("brain"),
        "memory" | "memory_config" | "memories" => Some("memory_config"),
        "capabilities" | "capabilities_config" | "modules" => Some("capabilities_config"),
        "resources" | "resources_config" | "projects" => Some("resources_config"),
        "web" | "web_config" | "sites" | "search" => Some("web_config"),
        "permissions" | "permissions_config" | "security" | "trust" => Some("permissions_config"),
        "undo" | "undo_config" | "backup" => Some("undo_config"),
        "automation" | "automation_config" | "drive" => Some("automation_config"),
        "interaction" | "interaction_config" | "hotkeys" | "appearance" => {
            Some("interaction_config")
        }
        "maintenance" | "maintenance_config" | "debug" => Some("maintenance_config"),
        _ => None,
    }
}

// ============================================================================
// Domain 1: Overview (`overview`, §8.7, §14.2)
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageUsageStats {
    pub state_db_bytes: u64,
    pub index_db_bytes: u64,
    pub undo_backup_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliDependencyStatus {
    pub name: String,
    pub available: bool,
    pub path: Option<String>,
    pub version: String,
    pub category: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverviewDomain {
    pub daemon_version: String,
    pub protocol_version: u32,
    pub pid: u32,
    pub uptime_seconds: u64,
    pub runtime_mode: String,
    pub runtime_healthy: bool,
    pub main_model_configured: bool,
    pub indexed_apps: usize,
    pub indexed_files: usize,
    pub indexed_sites: usize,
    pub indexed_fonts: usize,
    pub registered_capabilities: usize,
    pub active_sessions: usize,
    pub pending_approvals: usize,
    pub storage_usage: StorageUsageStats,
    pub cli_dependencies: Vec<CliDependencyStatus>,
}

// ============================================================================
// Domain 2: Brain & Model Gateway (`brain`, §5.1–§5.6, B-01..B-12)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedProvider {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_provider_kind")]
    pub kind: String,
    pub base_url: String,
    #[serde(default)]
    pub credential_ref: String,
    #[serde(default)]
    pub trust: ProviderTrust,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub available_models: Vec<String>,
    #[serde(default)]
    pub notes: String,
    /// Runtime indicator whether an API key exists in Secret Service / secure vault (never contains the secret itself).
    #[serde(default)]
    pub has_api_key: bool,
}

fn default_provider_kind() -> String {
    "openai-compatible".to_string()
}

impl ManagedProvider {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.id.trim().is_empty() {
            anyhow::bail!("供应商 ID 不能为空");
        }
        if !matches!(
            self.kind.as_str(),
            "openai-compatible" | "anthropic" | "gemini" | "ollama-local"
        ) {
            anyhow::bail!(
                "不支持的供应商类型 '{}': 仅支持 openai-compatible / anthropic / gemini / ollama-local",
                self.kind
            );
        }
        let u = self.base_url.trim().to_ascii_lowercase();
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            anyhow::bail!("供应商 Base URL 必须以 http:// 或 https:// 开头");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRoleProfile {
    #[serde(default = "default_provider_id")]
    pub provider: String,
    #[serde(default = "default_model_id")]
    pub model: String,
    #[serde(default)]
    pub inherit: Option<String>,
    #[serde(default = "default_ctx_budget")]
    pub context_budget: usize,
    #[serde(default = "default_max_out")]
    pub max_output_tokens: usize,
    #[serde(default = "default_thinking")]
    pub thinking: String,
    #[serde(default = "default_temperature")]
    pub temperature: f64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// For `decision` role: `"emulated"` | `"native"` (§4.2)
    #[serde(default)]
    pub kind: Option<String>,
    /// For `decision` role: direct execution probability threshold (default 0.85)
    #[serde(default)]
    pub direct_threshold: Option<f64>,
    /// For `decision` role: top1-top2 margin threshold (default 0.30)
    #[serde(default)]
    pub margin_threshold: Option<f64>,
    /// For `decision` role: clarification probability threshold (default 0.50)
    #[serde(default)]
    pub clarify_threshold: Option<f64>,
}

fn default_provider_id() -> String {
    "default-openai".to_string()
}
fn default_model_id() -> String {
    std::env::var("INTENTOS_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string())
}
fn default_ctx_budget() -> usize {
    65536
}
fn default_max_out() -> usize {
    4096
}
fn default_thinking() -> String {
    "medium".to_string()
}
fn default_temperature() -> f64 {
    0.2
}
fn default_true() -> bool {
    true
}

impl ModelRoleProfile {
    pub fn validate(&self, role_name: &str) -> anyhow::Result<()> {
        if !matches!(self.thinking.as_str(), "off" | "low" | "medium" | "high") {
            anyhow::bail!(
                "角色 '{}' 的 thinking 强度无效 '{}': 仅允许 off / low / medium / high",
                role_name,
                self.thinking
            );
        }
        if !(0.0..=2.0).contains(&self.temperature) {
            anyhow::bail!(
                "角色 '{}' 的 temperature ({}) 超出范围 [0.0, 2.0]",
                role_name,
                self.temperature
            );
        }
        if self.context_budget < 1024 {
            anyhow::bail!("角色 '{}' 的 context_budget 不能小于 1024", role_name);
        }
        if self.max_output_tokens < 64 {
            anyhow::bail!("角色 '{}' 的 max_output_tokens 不能小于 64", role_name);
        }
        if let Some(ref k) = self.kind
            && !matches!(k.as_str(), "emulated" | "native")
        {
            anyhow::bail!(
                "决策角色 kind 仅允许 emulated 或 native，当前值: {}",
                k
            );
        }
        Ok(())
    }
}

pub fn default_five_model_profiles() -> BTreeMap<String, ModelRoleProfile> {
    let main_model = default_model_id();
    let mut map = BTreeMap::new();
    map.insert(
        "main".to_string(),
        ModelRoleProfile {
            provider: "default-openai".to_string(),
            model: main_model.clone(),
            inherit: None,
            context_budget: 65536,
            max_output_tokens: 4096,
            thinking: "medium".to_string(),
            temperature: 0.2,
            enabled: true,
            kind: None,
            direct_threshold: None,
            margin_threshold: None,
            clarify_threshold: None,
        },
    );
    map.insert(
        "fast".to_string(),
        ModelRoleProfile {
            provider: "default-openai".to_string(),
            model: main_model.clone(),
            inherit: Some("main".to_string()),
            context_budget: 32768,
            max_output_tokens: 2048,
            thinking: "off".to_string(),
            temperature: 0.1,
            enabled: true,
            kind: None,
            direct_threshold: None,
            margin_threshold: None,
            clarify_threshold: None,
        },
    );
    map.insert(
        "decision".to_string(),
        ModelRoleProfile {
            provider: "default-openai".to_string(),
            model: main_model.clone(),
            inherit: Some("fast".to_string()),
            context_budget: 16384,
            max_output_tokens: 1024,
            thinking: "off".to_string(),
            temperature: 0.0,
            enabled: true,
            kind: Some("emulated".to_string()),
            direct_threshold: Some(0.85),
            margin_threshold: Some(0.30),
            clarify_threshold: Some(0.50),
        },
    );
    map.insert(
        "vision".to_string(),
        ModelRoleProfile {
            provider: "default-openai".to_string(),
            model: "gpt-4o".to_string(),
            inherit: Some("main".to_string()),
            context_budget: 32768,
            max_output_tokens: 2048,
            thinking: "low".to_string(),
            temperature: 0.2,
            enabled: false,
            kind: None,
            direct_threshold: None,
            margin_threshold: None,
            clarify_threshold: None,
        },
    );
    map.insert(
        "memory".to_string(),
        ModelRoleProfile {
            provider: "default-openai".to_string(),
            model: main_model,
            inherit: Some("fast".to_string()),
            context_budget: 32768,
            max_output_tokens: 2048,
            thinking: "off".to_string(),
            temperature: 0.1,
            enabled: true,
            kind: None,
            direct_threshold: None,
            margin_threshold: None,
            clarify_threshold: None,
        },
    );
    map
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default = "default_true")]
    pub l0_enabled: bool,
    #[serde(default = "default_true")]
    pub l1_enabled: bool,
    #[serde(default)]
    pub fallback_enabled: bool,
    #[serde(default)]
    pub fallback_provider: Option<String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            l0_enabled: true,
            l1_enabled: true,
            fallback_enabled: false,
            fallback_provider: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedRuntimeLimits {
    #[serde(default = "default_max_tools")]
    pub max_tool_calls: u32,
    #[serde(default = "default_max_secs")]
    pub max_runtime_seconds: u64,
    #[serde(default = "default_max_sessions")]
    pub max_concurrent_sessions: usize,
    #[serde(default = "default_idle_mins")]
    pub session_idle_timeout_minutes: u64,
    #[serde(default)]
    pub single_task_cost_limit: f64,
    #[serde(default)]
    pub daily_cost_limit: f64,
    #[serde(default)]
    pub daily_token_limit: u64,
    #[serde(default)]
    pub fallback_enabled: bool,
}

fn default_max_tools() -> u32 {
    30
}
fn default_max_secs() -> u64 {
    180
}
fn default_max_sessions() -> usize {
    2
}
fn default_idle_mins() -> u64 {
    60
}

impl Default for ExtendedRuntimeLimits {
    fn default() -> Self {
        Self {
            max_tool_calls: 30,
            max_runtime_seconds: 180,
            max_concurrent_sessions: 2,
            session_idle_timeout_minutes: 60,
            single_task_cost_limit: 0.0,
            daily_cost_limit: 0.0,
            daily_token_limit: 0,
            fallback_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrainDomainConfig {
    #[serde(default = "default_runtime")]
    pub runtime: String,
    #[serde(default = "default_runtime")]
    pub active_runtime: String,
    #[serde(default = "default_main_str")]
    pub default_profile: String,
    #[serde(default = "default_providers")]
    pub providers: Vec<ManagedProvider>,
    #[serde(default = "default_five_model_profiles")]
    pub profiles: BTreeMap<String, ModelRoleProfile>,
    #[serde(default)]
    pub egress_matrix: EgressMatrixConfig,
    #[serde(default)]
    pub sensitive_directories: Vec<String>,
    #[serde(default = "builtin_forbidden_rules")]
    pub forbidden_rules: Vec<ForbiddenPathRule>,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub runtime_limits: ExtendedRuntimeLimits,
    #[serde(default)]
    pub main_model_configured: bool,
    #[serde(default = "default_empty_metrics")]
    pub gateway_metrics: Value,
}

fn default_runtime() -> String {
    "pi".to_string()
}
fn default_main_str() -> String {
    "main".to_string()
}
fn default_empty_metrics() -> Value {
    json!({
        "total_requests": 0,
        "blocked_egress": 0,
        "total_input_tokens": 0,
        "total_output_tokens": 0
    })
}

pub fn default_providers() -> Vec<ManagedProvider> {
    vec![ManagedProvider {
        id: "default-openai".to_string(),
        name: "Default OpenAI Compatible".to_string(),
        kind: "openai-compatible".to_string(),
        base_url: std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
        credential_ref: "secret-service://intentos/default-openai".to_string(),
        trust: ProviderTrust::Standard,
        enabled: true,
        available_models: vec![
            "gpt-4o-mini".to_string(),
            "gpt-4o".to_string(),
            "deepseek-chat".to_string(),
        ],
        notes: "默认 OpenAI 兼容网关端点".to_string(),
        has_api_key: false,
    }]
}

impl Default for BrainDomainConfig {
    fn default() -> Self {
        Self {
            runtime: "pi".to_string(),
            active_runtime: "pi".to_string(),
            default_profile: "main".to_string(),
            providers: default_providers(),
            profiles: default_five_model_profiles(),
            egress_matrix: EgressMatrixConfig::default(),
            sensitive_directories: Vec::new(),
            forbidden_rules: builtin_forbidden_rules(),
            routing: RoutingConfig::default(),
            runtime_limits: ExtendedRuntimeLimits::default(),
            main_model_configured: false,
            gateway_metrics: default_empty_metrics(),
        }
    }
}

// ============================================================================
// Domain 3: Memory (`memory_config`, §11, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDomainConfig {
    #[serde(default = "default_compaction_tokens")]
    pub session_compaction_threshold_tokens: usize,
    #[serde(default = "default_true")]
    pub propose_candidates_on_session_end: bool,
    #[serde(default = "default_true")]
    pub auto_save_explicit_preferences: bool,
    #[serde(default = "default_scope_filter")]
    pub default_scope_filter: String,
    #[serde(default = "default_max_recalled")]
    pub max_recalled_memories_per_turn: usize,
    #[serde(default)]
    pub active_memories_count: usize,
    #[serde(default)]
    pub memories: Vec<Value>,
}

fn default_compaction_tokens() -> usize {
    48000
}
fn default_scope_filter() -> String {
    "all".to_string()
}
fn default_max_recalled() -> usize {
    10
}

impl Default for MemoryDomainConfig {
    fn default() -> Self {
        Self {
            session_compaction_threshold_tokens: 48000,
            propose_candidates_on_session_end: true,
            auto_save_explicit_preferences: true,
            default_scope_filter: "all".to_string(),
            max_recalled_memories_per_turn: 10,
            active_memories_count: 0,
            memories: Vec::new(),
        }
    }
}

// ============================================================================
// Domain 4: Capabilities & Modules (`capabilities_config`, §7, §8.7, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub id: String,
    pub name: String,
    #[serde(default = "default_mcp_transport")]
    pub transport: String,
    pub command_or_url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_mcp_trust")]
    pub trust: String,
}

fn default_mcp_transport() -> String {
    "stdio".to_string()
}
fn default_mcp_trust() -> String {
    "sandboxed".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesDomainConfig {
    #[serde(default = "default_enabled_modules")]
    pub enabled_modules: BTreeMap<String, bool>,
    #[serde(default)]
    pub disabled_capabilities: Vec<String>,
    #[serde(default)]
    pub capability_overrides: BTreeMap<String, bool>,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
    #[serde(default)]
    pub cli_dependencies: Vec<CliDependencyStatus>,
    #[serde(default)]
    pub total_registered: usize,
}

pub fn default_enabled_modules() -> BTreeMap<String, bool> {
    let mut m = BTreeMap::new();
    for k in [
        "applications",
        "filesystem",
        "system",
        "devtools",
        "web",
        "desktop",
    ] {
        m.insert(k.to_string(), true);
    }
    m
}

impl Default for CapabilitiesDomainConfig {
    fn default() -> Self {
        Self {
            enabled_modules: default_enabled_modules(),
            disabled_capabilities: Vec::new(),
            capability_overrides: BTreeMap::new(),
            mcp_servers: Vec::new(),
            cli_dependencies: Vec::new(),
            total_registered: 0,
        }
    }
}

// ============================================================================
// Domain 5: Resources & Projects (`resources_config`, §12, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesDomainConfig {
    #[serde(default)]
    pub authorized_directories: Vec<String>,
    #[serde(default)]
    pub sensitive_directories: Vec<String>,
    #[serde(default = "default_exclude_patterns")]
    pub exclude_patterns: Vec<String>,
    #[serde(default = "default_true")]
    pub inotify_incremental_enabled: bool,
    #[serde(default = "default_true")]
    pub auto_discover_git_projects: bool,
    #[serde(default = "default_max_files")]
    pub max_file_index_count: usize,
    #[serde(default)]
    pub indexed_apps: usize,
    #[serde(default)]
    pub indexed_files: usize,
    #[serde(default)]
    pub indexed_sites: usize,
    #[serde(default)]
    pub indexed_fonts: usize,
}

pub fn default_exclude_patterns() -> Vec<String> {
    vec![
        "node_modules".into(),
        "target".into(),
        ".git".into(),
        ".venv".into(),
        "__pycache__".into(),
        ".cache".into(),
        "dist".into(),
        "build".into(),
    ]
}

fn default_max_files() -> usize {
    100_000
}

impl Default for ResourcesDomainConfig {
    fn default() -> Self {
        let app_cfg = AppConfig::default();
        Self {
            authorized_directories: app_cfg.authorized_directories,
            sensitive_directories: Vec::new(),
            exclude_patterns: default_exclude_patterns(),
            inotify_incremental_enabled: true,
            auto_discover_git_projects: true,
            max_file_index_count: 100_000,
            indexed_apps: 0,
            indexed_files: 0,
            indexed_sites: 0,
            indexed_fonts: 0,
        }
    }
}

// ============================================================================
// Domain 6: Web & Search (`web_config`, §4.7, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDomainConfig {
    #[serde(default = "default_google")]
    pub default_search: String,
    #[serde(default = "default_browser")]
    pub open_with: String,
    #[serde(default)]
    pub bookmark_index_enabled: bool,
    #[serde(default)]
    pub history_index_enabled: bool,
    #[serde(default = "builtin_search_engines")]
    pub search_engines: Vec<SearchEngineEntry>,
    #[serde(default = "builtin_sites")]
    pub sites: Vec<SiteEntry>,
}

fn default_google() -> String {
    "google".to_string()
}
fn default_browser() -> String {
    "default".to_string()
}

impl Default for WebDomainConfig {
    fn default() -> Self {
        Self {
            default_search: default_google(),
            open_with: default_browser(),
            bookmark_index_enabled: false,
            history_index_enabled: false,
            search_engines: builtin_search_engines(),
            sites: builtin_sites(),
        }
    }
}

// ============================================================================
// Domain 7: Permissions & Security (`permissions_config`, §10.2–§10.4, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsDomainConfig {
    #[serde(default = "default_max_auto_files")]
    pub max_auto_reversible_files: usize,
    #[serde(default = "default_max_auto_mb")]
    pub max_auto_backup_mb: u64,
    #[serde(default = "default_true")]
    pub progressive_trust_proposals_enabled: bool,
    #[serde(default = "default_min_approvals")]
    pub progressive_trust_min_approvals: u32,
    #[serde(default = "default_audit_days")]
    pub audit_retention_days: u32,
    #[serde(default = "default_true")]
    pub strict_taint_escalation: bool,
    #[serde(default)]
    pub recent_audit: Vec<Value>,
}

fn default_max_auto_files() -> usize {
    20
}
fn default_max_auto_mb() -> u64 {
    200
}
fn default_min_approvals() -> u32 {
    3
}
fn default_audit_days() -> u32 {
    90
}

impl Default for PermissionsDomainConfig {
    fn default() -> Self {
        Self {
            max_auto_reversible_files: 20,
            max_auto_backup_mb: 200,
            progressive_trust_proposals_enabled: true,
            progressive_trust_min_approvals: 3,
            audit_retention_days: 90,
            strict_taint_escalation: true,
            recent_audit: Vec::new(),
        }
    }
}

// ============================================================================
// Domain 8: Undo & Backup (`undo_config`, §9.2, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoDomainConfig {
    #[serde(default = "default_quota_gb")]
    pub quota_gb: u64,
    #[serde(default = "default_retention_days")]
    pub retention_days: i64,
    #[serde(default = "default_single_file_ratio")]
    pub single_file_max_ratio_percent: u8,
    #[serde(default = "default_true")]
    pub auto_prune_expired: bool,
    #[serde(default)]
    pub current_backup_bytes: u64,
    #[serde(default)]
    pub changesets_available: usize,
}

fn default_quota_gb() -> u64 {
    4
}
fn default_retention_days() -> i64 {
    30
}
fn default_single_file_ratio() -> u8 {
    25
}

impl Default for UndoDomainConfig {
    fn default() -> Self {
        Self {
            quota_gb: 4,
            retention_days: 30,
            single_file_max_ratio_percent: 25,
            auto_prune_expired: true,
            current_backup_bytes: 0,
            changesets_available: 0,
        }
    }
}

// ============================================================================
// Domain 9: Automation & Drive (`automation_config`, §13.3–§13.4, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationDomainConfig {
    #[serde(default = "default_autonomy_level")]
    pub autonomy_level: String,
    #[serde(default = "default_true")]
    pub pause_on_screen_lock: bool,
    #[serde(default = "default_max_triggers")]
    pub max_triggers_per_hour: u32,
    #[serde(default = "default_true")]
    pub schedule_enabled: bool,
    #[serde(default)]
    pub file_watch_triggers_enabled: bool,
}

fn default_autonomy_level() -> String {
    "L0_Manual".to_string()
}
fn default_max_triggers() -> u32 {
    5
}

impl Default for AutomationDomainConfig {
    fn default() -> Self {
        Self {
            autonomy_level: default_autonomy_level(),
            pause_on_screen_lock: true,
            max_triggers_per_hour: 5,
            schedule_enabled: true,
            file_watch_triggers_enabled: false,
        }
    }
}

// ============================================================================
// Domain 10: Interaction & Hotkeys (`interaction_config`, §3.1, §3.6, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionDomainConfig {
    #[serde(default = "default_hotkey")]
    pub hotkey: String,
    #[serde(default = "default_surface_mode")]
    pub default_surface_mode: String,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_ui_scale")]
    pub ui_scale_percent: u16,
    #[serde(default = "default_true")]
    pub auto_hide_on_focus_loss: bool,
    #[serde(default = "default_undo_banner_secs")]
    pub show_undo_banner_seconds: u16,
    #[serde(default = "default_voice_asr")]
    pub voice_asr_mode: String,
}

fn default_hotkey() -> String {
    "<Super><Shift>space".to_string()
}
fn default_surface_mode() -> String {
    "floating".to_string()
}
fn default_theme() -> String {
    "system".to_string()
}
fn default_ui_scale() -> u16 {
    100
}
fn default_undo_banner_secs() -> u16 {
    30
}
fn default_voice_asr() -> String {
    "disabled".to_string()
}

impl Default for InteractionDomainConfig {
    fn default() -> Self {
        Self {
            hotkey: default_hotkey(),
            default_surface_mode: default_surface_mode(),
            theme: default_theme(),
            ui_scale_percent: 100,
            auto_hide_on_focus_loss: true,
            show_undo_banner_seconds: 30,
            voice_asr_mode: default_voice_asr(),
        }
    }
}

// ============================================================================
// Domain 11: Maintenance & Debug (`maintenance_config`, §6.4, M-08, §14.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceDomainConfig {
    #[serde(default)]
    pub record_transcripts: bool,
    #[serde(default = "default_transcript_days")]
    pub transcript_retention_days: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_true")]
    pub auto_cleanup_temp_artifacts: bool,
    #[serde(default = "default_schema_version")]
    pub config_schema_version: u32,
}

fn default_transcript_days() -> u32 {
    7
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_schema_version() -> u32 {
    1
}

impl Default for MaintenanceDomainConfig {
    fn default() -> Self {
        Self {
            record_transcripts: false,
            transcript_retention_days: 7,
            log_level: default_log_level(),
            auto_cleanup_temp_artifacts: true,
            config_schema_version: 1,
        }
    }
}

// ============================================================================
// Aggregate 11-Domain Configuration State
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FullDomainsConfig {
    #[serde(default)]
    pub overview: OverviewDomain,
    #[serde(default)]
    pub brain: BrainDomainConfig,
    #[serde(default)]
    pub memory_config: MemoryDomainConfig,
    #[serde(default)]
    pub capabilities_config: CapabilitiesDomainConfig,
    #[serde(default)]
    pub resources_config: ResourcesDomainConfig,
    #[serde(default)]
    pub web_config: WebDomainConfig,
    #[serde(default)]
    pub permissions_config: PermissionsDomainConfig,
    #[serde(default)]
    pub undo_config: UndoDomainConfig,
    #[serde(default)]
    pub automation_config: AutomationDomainConfig,
    #[serde(default)]
    pub interaction_config: InteractionDomainConfig,
    #[serde(default)]
    pub maintenance_config: MaintenanceDomainConfig,
}

impl FullDomainsConfig {
    /// Enforce all cross-domain invariants (`forbidden` egress always `deny`, all 5 model roles present, UI scale bounds).
    pub fn enforce_invariants(&mut self) {
        self.brain.egress_matrix.enforce_invariants();
        self.brain.forbidden_rules = builtin_forbidden_rules();
        let defaults = default_five_model_profiles();
        for role in MODEL_ROLES {
            if !self.brain.profiles.contains_key(role)
                && let Some(def_prof) = defaults.get(role)
            {
                self.brain
                    .profiles
                    .insert(role.to_string(), def_prof.clone());
            }
        }
        self.interaction_config.ui_scale_percent =
            self.interaction_config.ui_scale_percent.clamp(85, 135);
        if self.maintenance_config.transcript_retention_days == 0 {
            self.maintenance_config.transcript_retention_days = 7;
        }
    }

    /// Synchronize fields from legacy `AppConfig` and `BrainConfig` into `FullDomainsConfig`.
    pub fn merge_from_core_configs(&mut self, app: &AppConfig, brain: &BrainConfig) {
        self.interaction_config.hotkey = app.hotkey.clone();
        self.resources_config.authorized_directories = app.authorized_directories.clone();
        self.web_config.default_search = app.web.default_search.clone();
        self.web_config.open_with = app.web.open_with.clone();
        if !app.web.search_engines.is_empty() {
            self.web_config.search_engines = app.web.search_engines.clone();
        }
        if !app.web.sites.is_empty() {
            self.web_config.sites = app.web.sites.clone();
        }
        self.undo_config.quota_gb = app.undo.quota_gb;
        self.undo_config.retention_days = app.undo.retention_days;

        self.brain.runtime = brain.runtime.clone();
        self.brain.default_profile = brain.default_profile.clone();
        self.brain.runtime_limits.max_tool_calls = brain.runtime_limits.max_tool_calls;
        self.brain.runtime_limits.max_runtime_seconds = brain.runtime_limits.max_runtime_seconds;
        self.brain.runtime_limits.max_concurrent_sessions =
            brain.runtime_limits.max_concurrent_sessions;
        self.brain.runtime_limits.session_idle_timeout_minutes =
            brain.runtime_limits.session_idle_timeout_minutes;
        self.brain.runtime_limits.daily_cost_limit = brain.runtime_limits.daily_cost_limit;

        for p in &brain.providers {
            if let Some(existing) = self.brain.providers.iter_mut().find(|x| x.id == p.id) {
                existing.kind = p.kind.clone();
                existing.base_url = p.base_url.clone();
                existing.credential_ref = p.credential_ref.clone();
                existing.trust = p.trust;
                existing.enabled = p.enabled;
            } else {
                self.brain.providers.push(ManagedProvider {
                    id: p.id.clone(),
                    name: p.id.clone(),
                    kind: p.kind.clone(),
                    base_url: p.base_url.clone(),
                    credential_ref: p.credential_ref.clone(),
                    trust: p.trust,
                    enabled: p.enabled,
                    available_models: vec!["gpt-4o-mini".to_string()],
                    notes: String::new(),
                    has_api_key: false,
                });
            }
        }

        for (role, prof) in &brain.profiles {
            let entry = self
                .brain
                .profiles
                .entry(role.clone())
                .or_insert_with(|| ModelRoleProfile {
                    provider: prof.provider.clone(),
                    model: prof.model.clone(),
                    inherit: None,
                    context_budget: prof.context_budget,
                    max_output_tokens: prof.max_output_tokens,
                    thinking: "medium".to_string(),
                    temperature: 0.2,
                    enabled: true,
                    kind: None,
                    direct_threshold: None,
                    margin_threshold: None,
                    clarify_threshold: None,
                });
            entry.provider = prof.provider.clone();
            entry.model = prof.model.clone();
            entry.context_budget = prof.context_budget;
            entry.max_output_tokens = prof.max_output_tokens;
        }

        self.enforce_invariants();
    }

    /// Project back into `AppConfig` and `BrainConfig` for writing `config.toml` and `brain.toml`.
    pub fn to_core_configs(&self, allow_sim_fallback: bool) -> (AppConfig, BrainConfig) {
        let app = AppConfig {
            hotkey: self.interaction_config.hotkey.clone(),
            authorized_directories: self.resources_config.authorized_directories.clone(),
            allow_simulated_hardware_fallback: allow_sim_fallback,
            web: crate::config::WebConfig {
                default_search: self.web_config.default_search.clone(),
                open_with: self.web_config.open_with.clone(),
                search_engines: self.web_config.search_engines.clone(),
                sites: self.web_config.sites.clone(),
            },
            undo: crate::config::UndoConfig {
                quota_gb: self.undo_config.quota_gb,
                retention_days: self.undo_config.retention_days,
            },
        };

        let providers = self
            .brain
            .providers
            .iter()
            .map(|p| crate::config::ProviderConfig {
                id: p.id.clone(),
                kind: p.kind.clone(),
                base_url: p.base_url.clone(),
                credential_ref: if p.credential_ref.trim().is_empty() {
                    format!("secret-service://intentos/{}", p.id)
                } else {
                    p.credential_ref.clone()
                },
                trust: p.trust,
                enabled: p.enabled,
            })
            .collect();

        let mut profiles = BTreeMap::new();
        for (role, prof) in &self.brain.profiles {
            profiles.insert(
                role.clone(),
                crate::config::ProfileConfig {
                    provider: prof.provider.clone(),
                    model: prof.model.clone(),
                    context_budget: prof.context_budget,
                    max_output_tokens: prof.max_output_tokens,
                },
            );
        }

        let brain = BrainConfig {
            runtime: self.brain.runtime.clone(),
            default_profile: self.brain.default_profile.clone(),
            providers,
            profiles,
            runtime_limits: crate::config::RuntimeLimits {
                max_tool_calls: self.brain.runtime_limits.max_tool_calls,
                max_runtime_seconds: self.brain.runtime_limits.max_runtime_seconds,
                max_concurrent_sessions: self.brain.runtime_limits.max_concurrent_sessions,
                session_idle_timeout_minutes: self
                    .brain
                    .runtime_limits
                    .session_idle_timeout_minutes,
                daily_cost_limit: self.brain.runtime_limits.daily_cost_limit,
            },
        };

        (app, brain)
    }
}
