#![forbid(unsafe_code)]

//! Unified `ResourceResolver` & Privacy-Gated On-Demand `WorldState` (`M2-B`).
//!
//! Architectural guarantees:
//! 1. **Unified `ResourceRef` & `ResourceResolution`**: Canonical representation across files,
//!    documents, directories, desktop apps, running processes, windows, Git projects, experiment
//!    results, and explicit clipboard/selection snippets — never silently guessing when candidate
//!    confidence margin is `< 0.12` (`AMBIGUITY_CONFIDENCE_MARGIN`).
//! 2. **Wayland Honesty (`StateField<T>`)**: On Wayland (`WAYLAND_DISPLAY` / `"wayland"` session)
//!    without a fresh (`<= 15s`) verified focus hint from the GNOME Shell extension,
//!    `desktop.active_window` explicitly returns
//!    `StateField::Unavailable { reason: "wayland_compositor_isolated" }` — **never fabricating
//!    fake window focus or coordinates**.
//! 3. **Zero Background Surveillance & Strict Privacy**: Sampled strictly on demand with bounded
//!    TTLs (`5s` `/proc` apps & health, `10s` network, `15s` desktop focus hint) and event-driven
//!    invalidation; `PrivacySessionPolicy::StrictIsolated` omits `active_project` history and
//!    blocks all `memory_hub` / `StateDb` personal memory reads.

use crate::core::IntentOsCore;
use crate::execution_hub::project_memory::{self, ProjectRecord};
use crate::memory_hub::{self, MemoryHubDb};
use crate::resource::{AppRecord, FileRecord, ResourceEngine, extract_binary_stem, to_pinyin_pair};
use crate::runtime::SessionState;
use crate::security_guard::{PrivacySessionPolicy, SensitiveDataGuard, UnifiedTaskStateMachine};
use crate::settings::SystemSettingsEngine;
use chrono::{DateTime, Datelike, Days, NaiveDate, TimeZone, Utc};
use intentos_capability_sdk::resolve_trusted_executable;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Minimum confidence margin `[0.0, 1.0]` required to pick a single top candidate without asking.
pub const AMBIGUITY_CONFIDENCE_MARGIN: f64 = 0.12;

/// Staleness TTL for verified GNOME Shell / desktop focus hints (`15s`).
pub const DESKTOP_FOCUS_HINT_TTL_SECS: i64 = 15;

/// On-demand cache TTL for `/proc` + `.desktop` running user applications (`5s`).
pub const RUNNING_APPS_TTL_SECS: i64 = 5;

/// On-demand cache TTL for `/proc/loadavg` + `/proc/meminfo` system health (`5s`).
pub const SYSTEM_HEALTH_TTL_SECS: i64 = 5;

/// On-demand cache TTL for `/proc/net/route` + proxy network status (`10s`).
pub const NETWORK_TTL_SECS: i64 = 10;

/// Canonical resource taxonomy for `ResourceRef` (`M2-B`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    File,
    Document,
    Directory,
    Application,
    RunningProcess,
    DesktopWindow,
    Project,
    ExperimentResult,
    ClipboardSelection,
}

impl ResourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Document => "document",
            Self::Directory => "directory",
            Self::Application => "application",
            Self::RunningProcess => "running_process",
            Self::DesktopWindow => "desktop_window",
            Self::Project => "project",
            Self::ExperimentResult => "experiment_result",
            Self::ClipboardSelection => "clipboard_selection",
        }
    }

    pub fn from_hint(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "file" | "files" => Some(Self::File),
            "document" | "doc" | "docs" | "paper" => Some(Self::Document),
            "directory" | "dir" | "folder" => Some(Self::Directory),
            "application" | "app" | "software" => Some(Self::Application),
            "running_process" | "process" | "proc" => Some(Self::RunningProcess),
            "desktop_window" | "window" | "win" => Some(Self::DesktopWindow),
            "project" | "repo" | "workspace" => Some(Self::Project),
            "experiment_result" | "experiment" | "result" | "metrics" => {
                Some(Self::ExperimentResult)
            }
            "clipboard_selection" | "clipboard" | "selection" => Some(Self::ClipboardSelection),
            _ => None,
        }
    }

    fn matches_filter(self, filter: Option<ResourceKind>) -> bool {
        let Some(f) = filter else {
            return true;
        };
        if self == f {
            return true;
        }
        // Treat Document and ExperimentResult as specialized File kinds when caller asks for File
        matches!(
            (f, self),
            (
                Self::File,
                Self::Document | Self::ExperimentResult | Self::File
            ) | (Self::Document, Self::ExperimentResult)
        )
    }
}

/// Unified, provenance-carrying reference to a real host or workspace resource (`M2-B`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceRef {
    pub id: String,
    pub kind: ResourceKind,
    pub uri: String,
    pub path: Option<PathBuf>,
    pub display_name: String,
    pub project_id: Option<String>,
    pub source: String,
    pub confidence: f64,
    pub last_verified_at: DateTime<Utc>,
    pub metadata: Value,
}

/// Deterministic SHA-256 resource identifier (`res_<kind>_<12hex>`).
pub fn compute_stable_resource_id(kind: ResourceKind, canonical_uri: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(canonical_uri.trim().as_bytes());
    let hex_digest = hex::encode(hasher.finalize());
    format!("res_{}_{}", kind.as_str(), &hex_digest[..12])
}

/// Outcome of resolving a natural-language or deictic resource query (`M2-B`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum ResourceResolution {
    Single(ResourceRef),
    MultipleComparative(Vec<ResourceRef>),
    Ambiguous {
        query: String,
        candidates: Vec<ResourceRef>,
        clarification_prompt: String,
    },
    Unavailable {
        query: String,
        reason: String,
    },
    NotFound {
        query: String,
    },
}

impl ResourceResolution {
    pub fn is_single(&self) -> bool {
        matches!(self, Self::Single(_))
    }

    pub fn as_single(&self) -> Option<&ResourceRef> {
        match self {
            Self::Single(r) => Some(r),
            _ => None,
        }
    }

    pub fn is_comparative(&self) -> bool {
        matches!(self, Self::MultipleComparative(_))
    }

    pub fn comparative_refs(&self) -> Option<&[ResourceRef]> {
        match self {
            Self::MultipleComparative(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn is_ambiguous(&self) -> bool {
        matches!(self, Self::Ambiguous { .. })
    }

    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }
}

/// Honest availability wrapper for environment fields that may be isolated by Wayland/OS policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StateField<T> {
    Available {
        value: T,
        source: String,
        observed_at: DateTime<Utc>,
    },
    Unavailable {
        reason: String,
    },
}

impl<T> StateField<T> {
    pub fn available(value: T, source: impl Into<String>, observed_at: DateTime<Utc>) -> Self {
        Self::Available {
            value,
            source: source.into(),
            observed_at,
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Available { value, .. } => Some(value),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        match self {
            Self::Unavailable { reason } => Some(reason.as_str()),
            Self::Available { .. } => None,
        }
    }
}

/// Verified foreground desktop window metadata (never fabricated on Wayland).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopWindowInfo {
    pub window_id: Option<String>,
    pub app_id: Option<String>,
    pub wm_class: Option<String>,
    pub title: String,
    pub pid: Option<u32>,
}

/// Desktop compositor, active window focus, and Do-Not-Disturb state (`M2-B`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopStateSnapshot {
    /// `"wayland"` | `"x11"` | `"headless"`
    pub session_type: String,
    pub active_window: StateField<DesktopWindowInfo>,
    pub dnd_enabled: StateField<bool>,
}

/// Summary of the user's currently active development/research project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveProjectBrief {
    pub project_id: String,
    pub name: String,
    pub root_path: PathBuf,
    pub git_branch: Option<String>,
    pub tech_stack: Vec<String>,
    pub source: String,
}

/// Summary of a currently running user-owned desktop application matched via `/proc` + `.desktop`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningAppBrief {
    pub app_id: String,
    pub display_name: String,
    pub binary_name: String,
    pub pids: Vec<u32>,
    pub desktop_source: Option<String>,
}

impl RunningAppBrief {
    pub fn to_resource_ref(&self, confidence: f64, observed_at: DateTime<Utc>) -> ResourceRef {
        let uri = format!("app://{}", self.app_id);
        ResourceRef {
            id: compute_stable_resource_id(ResourceKind::RunningProcess, &uri),
            kind: ResourceKind::RunningProcess,
            uri,
            path: self.desktop_source.as_ref().map(PathBuf::from),
            display_name: self.display_name.clone(),
            project_id: None,
            source: "world_state.running_user_apps".to_string(),
            confidence: confidence.clamp(0.0, 1.0),
            last_verified_at: observed_at,
            metadata: json!({
                "app_id": self.app_id,
                "binary_name": self.binary_name,
                "pids": self.pids,
                "desktop_source": self.desktop_source,
            }),
        }
    }
}

/// Lightweight `/proc/loadavg` + `/proc/meminfo` snapshot (`5s` TTL).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemHealthBrief {
    pub cpu_load_1m: f64,
    pub mem_used_pct: f64,
    pub mem_available_mb: u64,
    pub swap_used_mb: u64,
    pub sampled_at: DateTime<Utc>,
}

/// Lightweight network connectivity, primary interface, and scrubbed proxy hint (`10s` TTL).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBrief {
    pub online: bool,
    pub primary_interface: Option<String>,
    pub proxy_hint: Option<String>,
    pub sampled_at: DateTime<Utc>,
}

/// Point-in-time, privacy-filtered snapshot of the host environment (`M2-B`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldStateSnapshot {
    pub desktop: DesktopStateSnapshot,
    pub active_cwd: Option<PathBuf>,
    pub active_project: Option<ActiveProjectBrief>,
    pub running_user_apps: Vec<RunningAppBrief>,
    pub system_health: SystemHealthBrief,
    pub network: NetworkBrief,
    pub pending_tasks_count: usize,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct VerifiedFocusHint {
    window: DesktopWindowInfo,
    source: String,
    observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct CachedEntry<T> {
    value: T,
    sampled_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct WorldStateInner {
    session_type_override: Option<String>,
    focus_hint: Option<VerifiedFocusHint>,
    explicit_cwd: Option<PathBuf>,
    clipboard_selection_hint: Option<CachedEntry<String>>,
    running_apps_override: Option<Vec<RunningAppBrief>>,
    cached_running_apps: Option<CachedEntry<Vec<RunningAppBrief>>>,
    cached_system_health: Option<CachedEntry<SystemHealthBrief>>,
    cached_network: Option<CachedEntry<NetworkBrief>>,
}

///Protected daemon/shell/compositor binaries excluded when listing user GUI applications.
const INFRA_PROCESS_NAMES: &[&str] = &[
    "intentosd",
    "intentosctl",
    "intentos-launcher",
    "intentos-settings",
    "gnome-shell",
    "gnome-session",
    "gnome-session-binary",
    "systemd",
    "dbus-daemon",
    "dbus-broker",
    "pipewire",
    "pipewire-pulse",
    "wireplumber",
    "xorg",
    "xwayland",
    "ibus-daemon",
    "fcitx5",
    "bash",
    "zsh",
    "sh",
    "dash",
    "fish",
    "sshd",
    "tmux",
    "init",
    "cargo",
    "rustc",
    "rust-analyzer",
    "git",
];

/// Lightweight event-invalidated, on-demand `WorldState` manager with zero background polling.
pub struct WorldStateTracker {
    inner: Mutex<WorldStateInner>,
    health_samples: AtomicU64,
    running_apps_samples: AtomicU64,
    network_samples: AtomicU64,
}

impl Default for WorldStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl WorldStateTracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(WorldStateInner::default()),
            health_samples: AtomicU64::new(0),
            running_apps_samples: AtomicU64::new(0),
            network_samples: AtomicU64::new(0),
        }
    }

    pub fn with_session_type(session_type: impl Into<String>) -> Self {
        let tracker = Self::new();
        tracker.set_session_type_override(Some(session_type.into()));
        tracker
    }

    /// Retrieve the shared `WorldStateTracker` owned by `IntentOsCore`.
    pub fn for_core(core: &IntentOsCore) -> Arc<Self> {
        core.world_state.clone()
    }

    /// Override detected desktop session type (`"wayland"` | `"x11"` | `"headless"`), useful for
    /// deterministic tests running without `DISPLAY` / `WAYLAND_DISPLAY`.
    pub fn set_session_type_override(&self, session_type: Option<String>) {
        let mut guard = self.inner.lock().unwrap();
        guard.session_type_override = session_type.map(|s| s.trim().to_ascii_lowercase());
    }

    /// Inject a verified foreground window focus hint (e.g., from the GNOME Shell extension over
    /// trusted D-Bus / UI IPC). Valid for `DESKTOP_FOCUS_HINT_TTL_SECS` (`15s`).
    pub fn update_desktop_focus_hint(&self, window: DesktopWindowInfo) {
        self.update_desktop_focus_hint_at(window, "gnome_shell_extension", Utc::now());
    }

    /// Inject a verified foreground window focus hint with explicit source and observation timestamp.
    pub fn update_desktop_focus_hint_at(
        &self,
        mut window: DesktopWindowInfo,
        source: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) {
        window.title = SensitiveDataGuard::redact_text(window.title.trim()).0;
        let mut guard = self.inner.lock().unwrap();
        guard.focus_hint = Some(VerifiedFocusHint {
            window,
            source: source.into(),
            observed_at,
        });
    }

    pub fn clear_desktop_focus_hint(&self) {
        self.inner.lock().unwrap().focus_hint = None;
    }

    /// Record an explicit active working directory from user/terminal context.
    pub fn update_active_cwd(&self, cwd: PathBuf) {
        self.inner.lock().unwrap().explicit_cwd = Some(cwd);
    }

    /// Record an explicit user-triggered selection/clipboard snippet (never polled in background).
    pub fn update_selection_hint(&self, text: impl Into<String>, observed_at: DateTime<Utc>) {
        let scrubbed = SensitiveDataGuard::redact_text(&text.into()).0;
        if !scrubbed.trim().is_empty() {
            self.inner.lock().unwrap().clipboard_selection_hint = Some(CachedEntry {
                value: scrubbed,
                sampled_at: observed_at,
            });
        }
    }

    /// Set a deterministic list of running user apps (for hermetic tests).
    pub fn set_running_apps_override(&self, apps: Option<Vec<RunningAppBrief>>) {
        let mut guard = self.inner.lock().unwrap();
        guard.running_apps_override = apps;
        guard.cached_running_apps = None;
    }

    pub fn invalidate_desktop(&self) {
        self.inner.lock().unwrap().focus_hint = None;
    }

    pub fn invalidate_running_apps(&self) {
        self.inner.lock().unwrap().cached_running_apps = None;
    }

    pub fn invalidate_system_health(&self) {
        self.inner.lock().unwrap().cached_system_health = None;
    }

    pub fn invalidate_network(&self) {
        self.inner.lock().unwrap().cached_network = None;
    }

    pub fn invalidate_all(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.focus_hint = None;
        guard.cached_running_apps = None;
        guard.cached_system_health = None;
        guard.cached_network = None;
    }

    pub fn system_health_sample_count(&self) -> u64 {
        self.health_samples.load(Ordering::Relaxed)
    }

    pub fn running_apps_sample_count(&self) -> u64 {
        self.running_apps_samples.load(Ordering::Relaxed)
    }

    pub fn network_sample_count(&self) -> u64 {
        self.network_samples.load(Ordering::Relaxed)
    }

    /// Capture an on-demand, privacy-gated `WorldStateSnapshot` at the current UTC timestamp.
    pub fn snapshot(
        &self,
        core: Option<&IntentOsCore>,
        resources: Option<&ResourceEngine>,
        session: Option<&SessionState>,
        privacy: PrivacySessionPolicy,
    ) -> WorldStateSnapshot {
        self.snapshot_at(Utc::now(), core, resources, session, privacy)
    }

    /// Capture an on-demand, privacy-gated `WorldStateSnapshot` at `now` (enabling deterministic TTL tests).
    pub fn snapshot_at(
        &self,
        now: DateTime<Utc>,
        core: Option<&IntentOsCore>,
        resources: Option<&ResourceEngine>,
        session: Option<&SessionState>,
        privacy: PrivacySessionPolicy,
    ) -> WorldStateSnapshot {
        let effective_resources = resources.or_else(|| core.map(|c| c.resources.as_ref()));
        let settings = core.map(|c| c.settings.as_ref());

        let desktop = self.sample_desktop_at(now, settings);
        let running_user_apps = self.sample_running_apps_at(now, effective_resources);
        let system_health = self.sample_system_health_at(now);
        let network = self.sample_network_at(now);

        let (active_cwd, active_project, pending_tasks_count) =
            if privacy == PrivacySessionPolicy::StrictIsolated {
                // StrictIsolated invariant: NEVER expose active_project history, personal memory
                // CWD trails, or standard session pending task counts.
                (None, None, 0)
            } else {
                let cwd = self.resolve_active_cwd(core, effective_resources, session);
                let proj = self.resolve_active_project(core, cwd.as_deref(), privacy);
                let pending = core
                    .and_then(|c| c.state_db.list_tasks(50).ok())
                    .map(|tasks| {
                        tasks
                            .into_iter()
                            .filter(|t| !UnifiedTaskStateMachine::is_terminal(t.status))
                            .count()
                    })
                    .unwrap_or(0);
                (cwd, proj, pending)
            };

        WorldStateSnapshot {
            desktop,
            active_cwd,
            active_project,
            running_user_apps,
            system_health,
            network,
            pending_tasks_count,
            updated_at: now,
        }
    }

    fn detect_session_type(&self) -> String {
        if let Some(ref ov) = self.inner.lock().unwrap().session_type_override {
            return ov.clone();
        }
        let xdg = std::env::var("XDG_SESSION_TYPE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let has_wayland = std::env::var_os("WAYLAND_DISPLAY")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_x11 = std::env::var_os("DISPLAY")
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        if has_wayland || xdg == "wayland" {
            "wayland".to_string()
        } else if has_x11 || xdg == "x11" {
            "x11".to_string()
        } else {
            "headless".to_string()
        }
    }

    fn sample_desktop_at(
        &self,
        now: DateTime<Utc>,
        settings: Option<&SystemSettingsEngine>,
    ) -> DesktopStateSnapshot {
        let session_type = self.detect_session_type();

        let (fresh_hint, had_expired_hint) = {
            let guard = self.inner.lock().unwrap();
            match guard.focus_hint.as_ref() {
                Some(hint) => {
                    let age_secs = (now - hint.observed_at).num_seconds();
                    if (0..=DESKTOP_FOCUS_HINT_TTL_SECS).contains(&age_secs) {
                        (Some(hint.clone()), false)
                    } else {
                        (None, true)
                    }
                }
                None => (None, false),
            }
        };

        let active_window = if let Some(hint) = fresh_hint {
            StateField::Available {
                value: hint.window,
                source: hint.source,
                observed_at: hint.observed_at,
            }
        } else if session_type == "wayland" {
            // CRITICAL WAYLAND HONESTY: On Wayland without a fresh verified GNOME Shell extension
            // focus hint, global focused window cannot be read due to compositor isolation.
            // Never fabricate fake focus or fallback to misleading XWayland-only focus!
            StateField::Unavailable {
                reason: "wayland_compositor_isolated".to_string(),
            }
        } else if session_type == "x11" {
            match probe_x11_active_window() {
                Some(win) => StateField::Available {
                    value: win,
                    source: "x11_net_active_window".to_string(),
                    observed_at: now,
                },
                None => StateField::Unavailable {
                    reason: if had_expired_hint {
                        "desktop_focus_hint_expired".to_string()
                    } else {
                        "x11_active_window_unavailable".to_string()
                    },
                },
            }
        } else {
            StateField::Unavailable {
                reason: if had_expired_hint {
                    "desktop_focus_hint_expired".to_string()
                } else {
                    "headless_session_no_display".to_string()
                },
            }
        };

        let dnd_enabled = if let Some(s_eng) = settings {
            match s_eng.read_setting_value("notify.dnd") {
                Ok((val, src)) => {
                    if let Some(flag) = val.as_bool() {
                        StateField::Available {
                            value: flag,
                            source: src,
                            observed_at: now,
                        }
                    } else {
                        StateField::Unavailable {
                            reason: "dnd_setting_unparseable".to_string(),
                        }
                    }
                }
                Err(e) => StateField::Unavailable {
                    reason: format!("dnd_probe_failed:{}", e),
                },
            }
        } else {
            StateField::Unavailable {
                reason: "settings_engine_unavailable".to_string(),
            }
        };

        DesktopStateSnapshot {
            session_type,
            active_window,
            dnd_enabled,
        }
    }

    fn sample_running_apps_at(
        &self,
        now: DateTime<Utc>,
        resources: Option<&ResourceEngine>,
    ) -> Vec<RunningAppBrief> {
        {
            let guard = self.inner.lock().unwrap();
            if let Some(ref ov) = guard.running_apps_override {
                return ov.clone();
            }
            if let Some(ref cached) = guard.cached_running_apps {
                let age = (now - cached.sampled_at).num_seconds();
                if (0..RUNNING_APPS_TTL_SECS).contains(&age) {
                    return cached.value.clone();
                }
            }
        }

        self.running_apps_samples.fetch_add(1, Ordering::Relaxed);
        let sampled = sample_running_user_apps_from_proc(resources);
        let mut guard = self.inner.lock().unwrap();
        guard.cached_running_apps = Some(CachedEntry {
            value: sampled.clone(),
            sampled_at: now,
        });
        sampled
    }

    fn sample_system_health_at(&self, now: DateTime<Utc>) -> SystemHealthBrief {
        {
            let guard = self.inner.lock().unwrap();
            if let Some(ref cached) = guard.cached_system_health {
                let age = (now - cached.sampled_at).num_seconds();
                if (0..SYSTEM_HEALTH_TTL_SECS).contains(&age) {
                    return cached.value.clone();
                }
            }
        }

        self.health_samples.fetch_add(1, Ordering::Relaxed);
        let sampled = sample_system_health_from_proc(now);
        let mut guard = self.inner.lock().unwrap();
        guard.cached_system_health = Some(CachedEntry {
            value: sampled.clone(),
            sampled_at: now,
        });
        sampled
    }

    fn sample_network_at(&self, now: DateTime<Utc>) -> NetworkBrief {
        {
            let guard = self.inner.lock().unwrap();
            if let Some(ref cached) = guard.cached_network {
                let age = (now - cached.sampled_at).num_seconds();
                if (0..NETWORK_TTL_SECS).contains(&age) {
                    return cached.value.clone();
                }
            }
        }

        self.network_samples.fetch_add(1, Ordering::Relaxed);
        let sampled = sample_network_from_proc_and_env(now);
        let mut guard = self.inner.lock().unwrap();
        guard.cached_network = Some(CachedEntry {
            value: sampled.clone(),
            sampled_at: now,
        });
        sampled
    }

    fn resolve_active_cwd(
        &self,
        core: Option<&IntentOsCore>,
        resources: Option<&ResourceEngine>,
        session: Option<&SessionState>,
    ) -> Option<PathBuf> {
        let is_allowed = |p: &Path| -> bool {
            if !p.exists() {
                return false;
            }
            if let Some(res) = resources {
                !res.fs_engine().is_forbidden(p)
            } else if let Some(c) = core {
                !c.fs_engine.is_forbidden(p)
            } else {
                true
            }
        };

        if let Some(explicit) = self.inner.lock().unwrap().explicit_cwd.clone()
            && is_allowed(&explicit)
        {
            return Some(explicit);
        }

        if let Some(sess) = session
            && let Some(ref last) = sess.last_resource_path
        {
            let p = Path::new(last.trim());
            let dir = if p.is_dir() {
                Some(p.to_path_buf())
            } else {
                p.parent().map(Path::to_path_buf)
            };
            if let Some(d) = dir
                && is_allowed(&d)
            {
                return Some(d);
            }
        }

        if let Some(res) = resources {
            for root in res.authorized_roots() {
                if is_allowed(root) {
                    return Some(root.clone());
                }
            }
        } else if let Some(c) = core {
            for root in c.fs_engine.authorized_roots() {
                if is_allowed(root) {
                    return Some(root.clone());
                }
            }
        }
        None
    }

    fn resolve_active_project(
        &self,
        core: Option<&IntentOsCore>,
        active_cwd: Option<&Path>,
        privacy: PrivacySessionPolicy,
    ) -> Option<ActiveProjectBrief> {
        if !privacy.allows_memory_read() {
            return None;
        }

        // 1. Check upward from `active_cwd` for a Git / manifest project root
        if let Some(cwd) = active_cwd
            && let Some(brief) = detect_project_root_upward(cwd, core)
        {
            return Some(brief);
        }

        // 2. Reuse `execution_hub::project_memory` (avoiding disk writes when `!allows_memory_write()`)
        if let Some(c) = core {
            let projects = list_projects_privacy_safe(c, privacy);
            if let Some(first) = projects.into_iter().next() {
                return Some(ActiveProjectBrief {
                    project_id: first.project_id,
                    name: first.name,
                    root_path: PathBuf::from(first.root_path),
                    git_branch: first.git_branch,
                    tech_stack: first.tech_stack,
                    source: "execution_hub.project_memory".to_string(),
                });
            }
        }
        None
    }

    fn fresh_selection_hint(&self, now: DateTime<Utc>) -> Option<(String, DateTime<Utc>)> {
        let guard = self.inner.lock().unwrap();
        let entry = guard.clipboard_selection_hint.as_ref()?;
        let age = (now - entry.sampled_at).num_seconds();
        if (0..=30).contains(&age) {
            Some((entry.value.clone(), entry.sampled_at))
        } else {
            None
        }
    }
}

/// Unified multi-source `ResourceResolver` (`M2-B`).
pub struct ResourceResolver<'a> {
    core: Option<&'a IntentOsCore>,
    resources: &'a ResourceEngine,
    world_state: &'a WorldStateTracker,
}

impl<'a> ResourceResolver<'a> {
    pub fn new(core: &'a IntentOsCore, world_state: &'a WorldStateTracker) -> Self {
        Self {
            core: Some(core),
            resources: core.resources.as_ref(),
            world_state,
        }
    }

    pub fn with_engine(resources: &'a ResourceEngine, world_state: &'a WorldStateTracker) -> Self {
        Self {
            core: None,
            resources,
            world_state,
        }
    }

    pub fn world_state(&self) -> &'a WorldStateTracker {
        self.world_state
    }

    /// Resolve a natural-language, comparative, or deictic resource reference at the current UTC time.
    pub fn resolve(
        &self,
        query: &str,
        kind_filter: Option<ResourceKind>,
        session: Option<&SessionState>,
        privacy: PrivacySessionPolicy,
    ) -> ResourceResolution {
        self.resolve_at(Utc::now(), query, kind_filter, session, privacy)
    }

    /// Deterministic clock-injectable resource resolution (`M2-B`).
    pub fn resolve_at(
        &self,
        now: DateTime<Utc>,
        query: &str,
        kind_filter: Option<ResourceKind>,
        session: Option<&SessionState>,
        privacy: PrivacySessionPolicy,
    ) -> ResourceResolution {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return ResourceResolution::NotFound {
                query: String::new(),
            };
        }

        // 1. Explicit selection / clipboard reference
        if is_selection_or_clipboard_query(trimmed)
            || kind_filter == Some(ResourceKind::ClipboardSelection)
        {
            if let Some((text, observed_at)) = self.world_state.fresh_selection_hint(now) {
                let uri = "clipboard://selection".to_string();
                return ResourceResolution::Single(ResourceRef {
                    id: compute_stable_resource_id(ResourceKind::ClipboardSelection, &uri),
                    kind: ResourceKind::ClipboardSelection,
                    uri,
                    path: None,
                    display_name: text.chars().take(48).collect(),
                    project_id: None,
                    source: "world_state.selection_hint".to_string(),
                    confidence: 0.96,
                    last_verified_at: observed_at,
                    metadata: json!({ "text": text }),
                });
            }
            return ResourceResolution::Unavailable {
                query: trimmed.to_string(),
                reason: "clipboard_or_selection_not_provided".to_string(),
            };
        }

        // 2. Foreground window / app close deictic (`"把它关掉"`, `"关闭当前窗口"`, `"关掉它"`)
        if is_close_or_active_window_deictic(trimmed)
            || kind_filter == Some(ResourceKind::DesktopWindow)
        {
            return self.resolve_close_or_window_deictic(
                now,
                trimmed,
                kind_filter,
                session,
                privacy,
            );
        }

        // 3. Comparative dated / versioned multi-resource resolution
        //    (e.g. `"比较昨天与前天的实验结果"`, `"对比两个版本"`)
        if is_comparative_query(trimmed)
            && let Some(comp_res) = self.try_resolve_comparative(now, trimmed, privacy)
        {
            return comp_res;
        }

        // 4. Conversational file/resource deictic (`"打开刚才那个文件"`, `"我之前说的那个文件"`, `"打开它"`)
        if is_conversational_resource_deictic(trimmed) {
            return self.resolve_conversational_deictic(
                now,
                trimmed,
                kind_filter,
                session,
                privacy,
            );
        }

        // 5. Explicit filesystem path (`/abs/path` or `~/...`)
        if let Some(explicit_res) = self.try_resolve_explicit_path(now, trimmed, privacy) {
            return explicit_res;
        }

        // 6. General multi-source resolution across files, documents, directories, apps, projects, and memories
        self.resolve_general_candidates(now, trimmed, kind_filter, session, privacy)
    }

    fn resolve_close_or_window_deictic(
        &self,
        now: DateTime<Utc>,
        query: &str,
        kind_filter: Option<ResourceKind>,
        session: Option<&SessionState>,
        privacy: PrivacySessionPolicy,
    ) -> ResourceResolution {
        let snap =
            self.world_state
                .snapshot_at(now, self.core, Some(self.resources), session, privacy);

        if let StateField::Available {
            value: win,
            source,
            observed_at,
        } = &snap.desktop.active_window
            && !is_self_shell_window(win)
        {
            // Match against indexed `.desktop` apps if possible to attach canonical `app_id`
            let matched_app = win
                .app_id
                .as_deref()
                .and_then(|id| self.resources.resolve_best_app(id))
                .or_else(|| {
                    win.wm_class
                        .as_deref()
                        .and_then(|wm| self.resources.resolve_best_app(wm))
                })
                .or_else(|| self.resources.resolve_best_app(&win.title));

            let effective_kind = if kind_filter == Some(ResourceKind::Application) {
                ResourceKind::Application
            } else {
                ResourceKind::DesktopWindow
            };
            let app_id = matched_app
                .as_ref()
                .map(|a| a.app_id.clone())
                .or_else(|| win.app_id.clone());
            let display_name = matched_app
                .as_ref()
                .map(|a| a.name.clone())
                .or_else(|| win.wm_class.clone())
                .unwrap_or_else(|| win.title.clone());
            let uri_id = win
                .window_id
                .as_deref()
                .or(app_id.as_deref())
                .unwrap_or(win.title.as_str());
            let uri = format!("window://{}", uri_id);

            return ResourceResolution::Single(ResourceRef {
                id: compute_stable_resource_id(effective_kind, &uri),
                kind: effective_kind,
                uri,
                path: matched_app.as_ref().and_then(|a| {
                    let p = Path::new(&a.source);
                    p.is_file().then(|| p.to_path_buf())
                }),
                display_name,
                project_id: None,
                source: source.clone(),
                confidence: 0.96,
                last_verified_at: *observed_at,
                metadata: json!({
                    "window_id": win.window_id,
                    "app_id": app_id,
                    "wm_class": win.wm_class,
                    "title": win.title,
                    "pid": win.pid,
                }),
            });
        }

        let unavail_reason = snap
            .desktop
            .active_window
            .unavailable_reason()
            .unwrap_or("active_window_unavailable")
            .to_string();

        // Check if current session explicitly tracked a single target app/resource in-turn
        let is_explicit_window_phrase =
            query.contains("当前窗口") || query.contains("这个窗口") || query.contains("活动窗口");
        if !is_explicit_window_phrase
            && let Some(sess) = session
            && let Some(last_target) = sess
                .last_resource_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            if let Some(app) = self.resources.resolve_best_app(last_target) {
                return ResourceResolution::Single(
                    app.to_resource_ref(0.90, "session.last_resource_path"),
                );
            }
            let p = Path::new(last_target);
            if p.is_file()
                && !self.resources.fs_engine().is_forbidden(p)
                && let Some(frec) = FileRecord::from_path(p)
            {
                return ResourceResolution::Single(frec.to_resource_ref(
                    0.88,
                    "session.last_resource_path",
                    None,
                ));
            }
        }

        // Never guess on unverified Wayland or expired focus hint!
        // If user GUI apps are running, surface them as Ambiguous candidates asking which one to close;
        // otherwise return Unavailable with the exact honest reason (`wayland_compositor_isolated`, etc.).
        if !snap.running_user_apps.is_empty() {
            let candidates: Vec<ResourceRef> = snap
                .running_user_apps
                .iter()
                .take(6)
                .map(|app| app.to_resource_ref(0.55, now))
                .collect();
            let names: Vec<&str> = candidates.iter().map(|c| c.display_name.as_str()).collect();
            let clarification_prompt = format!(
                "当前无法直接确认前台焦点窗口（{}），检测到正在运行的应用：{}。请指定要关闭哪一个应用。",
                unavail_reason,
                names.join("、")
            );
            return ResourceResolution::Ambiguous {
                query: query.to_string(),
                candidates,
                clarification_prompt,
            };
        }

        ResourceResolution::Unavailable {
            query: query.to_string(),
            reason: unavail_reason,
        }
    }

    fn resolve_conversational_deictic(
        &self,
        now: DateTime<Utc>,
        query: &str,
        kind_filter: Option<ResourceKind>,
        session: Option<&SessionState>,
        privacy: PrivacySessionPolicy,
    ) -> ResourceResolution {
        // 1. Current session `last_resource_path`
        if let Some(sess) = session {
            if let Some(last) = sess
                .last_resource_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                && let Some(rref) =
                    self.path_or_app_to_ref(now, last, 0.95, "session.last_resource_path", privacy)
                && rref.kind.matches_filter(kind_filter)
            {
                return ResourceResolution::Single(rref);
            }

            // 2. Scan recent in-session message paths
            let msg_paths = extract_paths_from_session(sess);
            let mut valid_refs = Vec::new();
            for mp in msg_paths {
                if let Some(rref) =
                    self.path_or_app_to_ref(now, &mp, 0.86, "session.messages", privacy)
                    && rref.kind.matches_filter(kind_filter)
                {
                    valid_refs.push(rref);
                }
            }
            if valid_refs.len() == 1 {
                return ResourceResolution::Single(valid_refs.remove(0));
            } else if valid_refs.len() > 1 {
                let names: Vec<String> = valid_refs
                    .iter()
                    .take(4)
                    .map(|r| r.display_name.clone())
                    .collect();
                return ResourceResolution::Ambiguous {
                    query: query.to_string(),
                    candidates: valid_refs,
                    clarification_prompt: format!(
                        "当前会话中提到了多个文件（{}），请确认您指的是哪一个：",
                        names.join("、")
                    ),
                };
            }
        }

        // 3. Personal Memory Hub & StateDb (strictly gated on `privacy.allows_memory_read()`)
        if !privacy.allows_memory_read() {
            return ResourceResolution::Unavailable {
                query: query.to_string(),
                reason: "privacy_strict_isolated_memory_disabled".to_string(),
            };
        }

        if let Some(core) = self.core {
            let db_exists = MemoryHubDb::path_for_core(core).exists();
            if (privacy.allows_memory_write() || db_exists)
                && let Ok(mem_db) = MemoryHubDb::open_for_core(core)
                && let Ok(recalled) = memory_hub::recall_mentioned_entities(
                    &mem_db,
                    query,
                    None,
                    session.map(|s| s.session_id.as_str()),
                    5,
                )
            {
                let mut mem_refs = Vec::new();
                for (ent, raw_score) in recalled {
                    let conf = (raw_score / 120.0).clamp(0.45, 0.94);
                    if let Some(rref) = self.path_or_app_to_ref(
                        now,
                        &ent.canonical_value,
                        conf,
                        "memory_hub.mentioned_entities",
                        privacy,
                    ) && rref.kind.matches_filter(kind_filter)
                    {
                        mem_refs.push(rref);
                    }
                }
                if mem_refs.len() == 1 {
                    return ResourceResolution::Single(mem_refs.remove(0));
                } else if mem_refs.len() >= 2 {
                    let margin = mem_refs[0].confidence - mem_refs[1].confidence;
                    if margin < AMBIGUITY_CONFIDENCE_MARGIN {
                        let top_conf = mem_refs[0].confidence;
                        let close: Vec<ResourceRef> = mem_refs
                            .into_iter()
                            .filter(|c| (top_conf - c.confidence) < AMBIGUITY_CONFIDENCE_MARGIN)
                            .collect();
                        let names: Vec<String> =
                            close.iter().map(|c| c.display_name.clone()).collect();
                        return ResourceResolution::Ambiguous {
                            query: query.to_string(),
                            candidates: close,
                            clarification_prompt: format!(
                                "历史对话中存在多个相近候选（{}），请明确指定目标：",
                                names.join("、")
                            ),
                        };
                    }
                    return ResourceResolution::Single(mem_refs.remove(0));
                }
            }

            if let Some(mem_last) = core
                .state_db
                .get_memory_value("last_resource_path")
                .filter(|s| !s.trim().is_empty())
                && let Some(rref) =
                    self.path_or_app_to_ref(now, &mem_last, 0.85, "state_db.memory", privacy)
                && rref.kind.matches_filter(kind_filter)
            {
                return ResourceResolution::Single(rref);
            }
        }

        ResourceResolution::NotFound {
            query: query.to_string(),
        }
    }

    fn try_resolve_comparative(
        &self,
        now: DateTime<Utc>,
        query: &str,
        privacy: PrivacySessionPolicy,
    ) -> Option<ResourceResolution> {
        let extra_dirs: Vec<PathBuf> = if privacy != PrivacySessionPolicy::StrictIsolated {
            self.world_state
                .resolve_active_cwd(self.core, Some(self.resources), None)
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };
        let all_files = self.resources.collect_live_or_indexed_files(&extra_dirs);
        if all_files.is_empty() {
            return Some(ResourceResolution::NotFound {
                query: query.to_string(),
            });
        }

        let wants_experiment = is_experiment_domain_query(query);
        let today = now.date_naive();

        // Case A: Temporal pair comparison (`昨天` & `前天`, or `今天` & `昨天`, or `最近两次`)
        let mentions_yesterday = query.contains("昨天")
            || query.contains("昨日")
            || query.to_ascii_lowercase().contains("yesterday");
        let mentions_day_before = query.contains("前天")
            || query.contains("前日")
            || query.to_ascii_lowercase().contains("day before");
        let mentions_today = query.contains("今天")
            || query.contains("今日")
            || query.to_ascii_lowercase().contains("today");

        if mentions_yesterday && (mentions_day_before || mentions_today) {
            let (target_newer, target_older) = if mentions_yesterday && mentions_day_before {
                (
                    today.checked_sub_days(Days::new(1))?,
                    today.checked_sub_days(Days::new(2))?,
                )
            } else {
                (today, today.checked_sub_days(Days::new(1))?)
            };

            let mut dated_candidates: Vec<(&FileRecord, NaiveDate, f64, bool)> = Vec::new();
            for rec in &all_files {
                let dom_score = score_comparative_domain_relevance(rec, query, wants_experiment);
                if dom_score <= 0.0 {
                    continue;
                }
                if let Some(explicit_date) =
                    extract_date_from_filename_or_dir(&rec.name, &rec.parent_dir, today.year())
                {
                    dated_candidates.push((rec, explicit_date, dom_score + 0.15, true));
                } else if let Some(rel_date) = extract_relative_day_token(&rec.name, today) {
                    dated_candidates.push((rec, rel_date, dom_score + 0.12, true));
                } else if let Some(mtime_dt) = Utc.timestamp_opt(rec.mtime_secs, 0).single() {
                    dated_candidates.push((rec, mtime_dt.date_naive(), dom_score, false));
                }
            }

            // Try exact offset `0`, then timezone-tolerant `±1` day offset
            for day_shift in [0i64, 1, -1] {
                let d_new = shift_date(target_newer, day_shift);
                let d_old = shift_date(target_older, day_shift);
                let best_new = dated_candidates
                    .iter()
                    .filter(|(_, d, _, _)| *d == d_new)
                    .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
                let best_old = dated_candidates
                    .iter()
                    .filter(|(rec, d, _, _)| {
                        *d == d_old && best_new.map(|bn| bn.0.path != rec.path).unwrap_or(true)
                    })
                    .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));

                if let (
                    Some((rec_new, date_new, sc_new, _)),
                    Some((rec_old, date_old, sc_old, _)),
                ) = (best_new, best_old)
                {
                    let proj_new =
                        self.infer_project_id_for_path(Path::new(&rec_new.path), privacy);
                    let proj_old =
                        self.infer_project_id_for_path(Path::new(&rec_old.path), privacy);
                    let ref_new = build_comparative_file_ref(
                        rec_new,
                        *sc_new,
                        proj_new,
                        Some(date_new.to_string()),
                        None,
                        "newer",
                    );
                    let ref_old = build_comparative_file_ref(
                        rec_old,
                        *sc_old,
                        proj_old,
                        Some(date_old.to_string()),
                        None,
                        "older",
                    );
                    return Some(ResourceResolution::MultipleComparative(vec![
                        ref_new, ref_old,
                    ]));
                }
            }

            // Fallback: if exactly two distinct explicitly-dated relevant files exist, return them ordered newer -> older
            let mut explicit_only: Vec<_> = dated_candidates
                .iter()
                .filter(|(_, _, _, is_explicit)| *is_explicit)
                .collect();
            explicit_only.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
            });
            explicit_only.dedup_by(|a, b| a.1 == b.1);
            if explicit_only.len() == 2 {
                let (r1, d1, s1, _) = explicit_only[0];
                let (r2, d2, s2, _) = explicit_only[1];
                let ref1 = build_comparative_file_ref(
                    r1,
                    *s1,
                    self.infer_project_id_for_path(Path::new(&r1.path), privacy),
                    Some(d1.to_string()),
                    None,
                    "newer",
                );
                let ref2 = build_comparative_file_ref(
                    r2,
                    *s2,
                    self.infer_project_id_for_path(Path::new(&r2.path), privacy),
                    Some(d2.to_string()),
                    None,
                    "older",
                );
                return Some(ResourceResolution::MultipleComparative(vec![ref1, ref2]));
            }

            return Some(ResourceResolution::NotFound {
                query: query.to_string(),
            });
        }

        // Case B: Versioned pair comparison (`"对比两个版本"`, `"比较 report v1 和 v2"`, `"新旧版本"`)
        type VersionedCandidate<'b> = (&'b FileRecord, u32, f64);
        let mut groups: BTreeMap<String, Vec<VersionedCandidate<'_>>> = BTreeMap::new();
        for rec in &all_files {
            if let Some((base_stem, ver_num)) = extract_base_stem_and_version(&rec.stem) {
                let topic_score = score_version_group_relevance(rec, &base_stem, query);
                if topic_score > 0.0 {
                    let key = format!("{}::{}", rec.parent_dir, base_stem);
                    groups
                        .entry(key)
                        .or_default()
                        .push((rec, ver_num, topic_score));
                }
            }
        }

        let mut valid_groups: Vec<(f64, Vec<VersionedCandidate<'_>>)> = groups
            .into_values()
            .filter_map(|mut items| {
                items.sort_by(|a, b| {
                    b.1.cmp(&a.1)
                        .then_with(|| b.0.mtime_secs.cmp(&a.0.mtime_secs))
                });
                items.dedup_by(|a, b| a.1 == b.1);
                if items.len() >= 2 {
                    let best_sc = items[0].2;
                    Some((best_sc, items))
                } else {
                    None
                }
            })
            .collect();

        valid_groups.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        if valid_groups.len() >= 2
            && (valid_groups[0].0 - valid_groups[1].0) < AMBIGUITY_CONFIDENCE_MARGIN
        {
            let mut ambig_refs = Vec::new();
            for (_, grp) in valid_groups.iter().take(3) {
                for (rec, _, sc) in grp.iter().take(2) {
                    ambig_refs.push(rec.to_resource_ref(
                        *sc,
                        "resource_resolver.version_group",
                        self.infer_project_id_for_path(Path::new(&rec.path), privacy),
                    ));
                }
            }
            return Some(ResourceResolution::Ambiguous {
                query: query.to_string(),
                candidates: ambig_refs,
                clarification_prompt:
                    "检测到多组不同文档的版本文件，请指定要对比哪一份文档的版本。".to_string(),
            });
        }

        if let Some((_, top_group)) = valid_groups.into_iter().next() {
            let (newer, v_new, sc_new) = top_group[0];
            let (older, v_old, sc_old) = top_group[1];
            let ref_new = build_comparative_file_ref(
                newer,
                sc_new,
                self.infer_project_id_for_path(Path::new(&newer.path), privacy),
                None,
                Some(format!("v{}", v_new)),
                "newer_version",
            );
            let ref_old = build_comparative_file_ref(
                older,
                sc_old,
                self.infer_project_id_for_path(Path::new(&older.path), privacy),
                None,
                Some(format!("v{}", v_old)),
                "older_version",
            );
            return Some(ResourceResolution::MultipleComparative(vec![
                ref_new, ref_old,
            ]));
        }

        None
    }

    fn try_resolve_explicit_path(
        &self,
        now: DateTime<Utc>,
        query: &str,
        privacy: PrivacySessionPolicy,
    ) -> Option<ResourceResolution> {
        let candidate_str = if query.starts_with('/') || query.starts_with("~/") {
            Some(query.to_string())
        } else {
            extract_single_explicit_path(query)
        }?;

        let expanded = expand_tilde_path(&candidate_str);
        if self.resources.fs_engine().is_forbidden(&expanded) {
            return Some(ResourceResolution::Unavailable {
                query: query.to_string(),
                reason: "forbidden_path_blocked".to_string(),
            });
        }
        if !expanded.exists() {
            return Some(ResourceResolution::NotFound {
                query: query.to_string(),
            });
        }
        if expanded.is_dir() {
            let uri = format!("file://{}", expanded.to_string_lossy());
            let name = expanded
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| expanded.to_string_lossy().to_string());
            let proj_id = self.infer_project_id_for_path(&expanded, privacy);
            return Some(ResourceResolution::Single(ResourceRef {
                id: compute_stable_resource_id(ResourceKind::Directory, &uri),
                kind: ResourceKind::Directory,
                uri,
                path: Some(expanded),
                display_name: name,
                project_id: proj_id,
                source: "explicit_path".to_string(),
                confidence: 0.99,
                last_verified_at: now,
                metadata: json!({}),
            }));
        }
        let rec = FileRecord::from_path(&expanded)?;
        let proj_id = self.infer_project_id_for_path(&expanded, privacy);
        Some(ResourceResolution::Single(rec.to_resource_ref(
            0.99,
            "explicit_path",
            proj_id,
        )))
    }

    fn resolve_general_candidates(
        &self,
        now: DateTime<Utc>,
        raw_query: &str,
        kind_filter: Option<ResourceKind>,
        session: Option<&SessionState>,
        privacy: PrivacySessionPolicy,
    ) -> ResourceResolution {
        let cleaned = strip_resource_query_noise(raw_query);
        let effective_q = if cleaned.is_empty() {
            raw_query.trim()
        } else {
            cleaned.as_str()
        };
        let prefers_latest = raw_query.contains("最新")
            || raw_query.contains("最近")
            || raw_query.to_ascii_lowercase().contains("latest")
            || raw_query.to_ascii_lowercase().contains("newest");

        let mut candidates: Vec<ResourceRef> = Vec::new();

        // A. Named directory (`下载`, `文档`, `桌面`, `代码`)
        if (kind_filter.is_none() || kind_filter == Some(ResourceKind::Directory))
            && matches!(
                effective_q,
                "下载"
                    | "文档"
                    | "桌面"
                    | "代码"
                    | "downloads"
                    | "documents"
                    | "desktop"
                    | "下载目录"
                    | "文档目录"
            )
            && let Some(dir_path) = self.resources.resolve_named_directory(effective_q)
        {
            let uri = format!("file://{}", dir_path.to_string_lossy());
            let name = dir_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| dir_path.to_string_lossy().to_string());
            candidates.push(ResourceRef {
                id: compute_stable_resource_id(ResourceKind::Directory, &uri),
                kind: ResourceKind::Directory,
                uri,
                path: Some(dir_path),
                display_name: name,
                project_id: None,
                source: "resource_engine.named_directory".to_string(),
                confidence: 0.95,
                last_verified_at: now,
                metadata: json!({}),
            });
        }

        // B. Projects (when `privacy.allows_memory_read()`)
        if privacy.allows_memory_read()
            && (kind_filter.is_none() || kind_filter == Some(ResourceKind::Project))
            && let Some(core) = self.core
        {
            for proj in list_projects_privacy_safe(core, privacy) {
                let sc = score_project_match(&proj, effective_q);
                if sc >= 0.55 {
                    let uri = proj.uri.clone();
                    candidates.push(ResourceRef {
                        id: compute_stable_resource_id(ResourceKind::Project, &uri),
                        kind: ResourceKind::Project,
                        uri,
                        path: Some(PathBuf::from(&proj.root_path)),
                        display_name: proj.name.clone(),
                        project_id: Some(proj.project_id.clone()),
                        source: "execution_hub.project_memory".to_string(),
                        confidence: sc,
                        last_verified_at: now,
                        metadata: json!({
                            "git_branch": proj.git_branch,
                            "tech_stack": proj.tech_stack,
                            "manifest_files": proj.manifest_files,
                        }),
                    });
                }
            }
        }

        // C. Applications (`ResourceEngine::search_apps`)
        if kind_filter.is_none() || kind_filter == Some(ResourceKind::Application) {
            let looks_like_filename = effective_q.contains('.')
                && !effective_q.to_ascii_lowercase().ends_with(".desktop");
            if !looks_like_filename {
                for (app, app_sc) in self.resources.search_apps(effective_q, 5) {
                    if app_sc >= 72.0 {
                        let conf = (app_sc / 105.0).clamp(0.55, 0.96);
                        candidates.push(app.to_resource_ref(conf, "resource_engine.apps"));
                    }
                }
            }
        }

        // D. Files / Documents / ExperimentResults from live + indexed authorized directories
        if kind_filter.is_none()
            || matches!(
                kind_filter,
                Some(ResourceKind::File | ResourceKind::Document | ResourceKind::ExperimentResult)
            )
        {
            let all_files = self.resources.collect_live_or_indexed_files(&[]);
            for rec in &all_files {
                let file_kind = rec.infer_resource_kind();
                if !file_kind.matches_filter(kind_filter) {
                    continue;
                }
                let conf = score_file_match(rec, effective_q, now.timestamp(), prefers_latest);
                if conf >= 0.50 {
                    let proj_id = self.infer_project_id_for_path(Path::new(&rec.path), privacy);
                    candidates.push(rec.to_resource_ref(conf, "resource_engine.files", proj_id));
                }
            }

            // E. Supplement with `memory_hub` document outlines & mentioned entities when privacy permits
            if privacy.allows_memory_read()
                && let Some(core) = self.core
            {
                let db_exists = MemoryHubDb::path_for_core(core).exists();
                if (privacy.allows_memory_write() || db_exists)
                    && let Ok(mem_db) = MemoryHubDb::open_for_core(core)
                {
                    if let Ok(outlines) =
                        memory_hub::search_document_outlines(&mem_db, effective_q, None, 5)
                    {
                        for hit in outlines {
                            if hit.score < 50.0 {
                                continue;
                            }
                            let p = Path::new(&hit.record.path);
                            if self.resources.fs_engine().is_forbidden(p) || !p.is_file() {
                                continue;
                            }
                            if let Some(frec) = FileRecord::from_path(p) {
                                let conf = (hit.score / 110.0).clamp(0.55, 0.93);
                                let proj_id = self.infer_project_id_for_path(p, privacy);
                                let mut rref = frec.to_resource_ref(
                                    conf,
                                    "memory_hub.document_outlines",
                                    proj_id,
                                );
                                if let Some(obj) = rref.metadata.as_object_mut() {
                                    obj.insert(
                                        "doc_title".to_string(),
                                        json!(hit.record.doc_title),
                                    );
                                    obj.insert(
                                        "matched_section".to_string(),
                                        json!(hit.matched_section),
                                    );
                                }
                                if rref.kind.matches_filter(kind_filter) {
                                    candidates.push(rref);
                                }
                            }
                        }
                    }

                    if let Ok(mentions) = memory_hub::recall_mentioned_entities(
                        &mem_db,
                        effective_q,
                        None,
                        session.map(|s| s.session_id.as_str()),
                        4,
                    ) {
                        for (ent, m_sc) in mentions {
                            if m_sc < 55.0 {
                                continue;
                            }
                            if let Some(rref) = self.path_or_app_to_ref(
                                now,
                                &ent.canonical_value,
                                (m_sc / 120.0).clamp(0.52, 0.90),
                                "memory_hub.mentioned_entities",
                                privacy,
                            ) && rref.kind.matches_filter(kind_filter)
                            {
                                candidates.push(rref);
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate by URI, keeping highest confidence
        let mut deduped: HashMap<String, ResourceRef> = HashMap::new();
        for cand in candidates {
            match deduped.get_mut(&cand.uri) {
                Some(existing) => {
                    if cand.confidence > existing.confidence {
                        *existing = cand;
                    }
                }
                None => {
                    deduped.insert(cand.uri.clone(), cand);
                }
            }
        }

        let mut ranked: Vec<ResourceRef> = deduped.into_values().collect();
        ranked.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.display_name.cmp(&b.display_name))
        });

        if ranked.is_empty() {
            return ResourceResolution::NotFound {
                query: raw_query.to_string(),
            };
        }
        if ranked.len() == 1 {
            return ResourceResolution::Single(ranked.remove(0));
        }

        let top_conf = ranked[0].confidence;
        let second_conf = ranked[1].confidence;
        if (top_conf - second_conf) < AMBIGUITY_CONFIDENCE_MARGIN {
            let close_candidates: Vec<ResourceRef> = ranked
                .into_iter()
                .filter(|c| (top_conf - c.confidence) < AMBIGUITY_CONFIDENCE_MARGIN)
                .take(6)
                .collect();
            let labels: Vec<String> = close_candidates
                .iter()
                .map(|c| c.display_name.clone())
                .collect();
            let clarification_prompt = format!(
                "查询「{}」匹配到多个得分接近的候选资源（{}），请明确指定目标名称或路径：",
                raw_query,
                labels.join("、")
            );
            return ResourceResolution::Ambiguous {
                query: raw_query.to_string(),
                candidates: close_candidates,
                clarification_prompt,
            };
        }

        ResourceResolution::Single(ranked.remove(0))
    }

    fn path_or_app_to_ref(
        &self,
        now: DateTime<Utc>,
        value: &str,
        confidence: f64,
        source: &str,
        privacy: PrivacySessionPolicy,
    ) -> Option<ResourceRef> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        let expanded = expand_tilde_path(trimmed);
        if expanded.is_absolute() {
            if self.resources.fs_engine().is_forbidden(&expanded) {
                return None;
            }
            if expanded.is_file() {
                let rec = FileRecord::from_path(&expanded)?;
                let proj_id = self.infer_project_id_for_path(&expanded, privacy);
                return Some(rec.to_resource_ref(confidence, source, proj_id));
            }
            if expanded.is_dir() {
                let uri = format!("file://{}", expanded.to_string_lossy());
                let name = expanded
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| expanded.to_string_lossy().to_string());
                let proj_id = self.infer_project_id_for_path(&expanded, privacy);
                return Some(ResourceRef {
                    id: compute_stable_resource_id(ResourceKind::Directory, &uri),
                    kind: ResourceKind::Directory,
                    uri,
                    path: Some(expanded),
                    display_name: name,
                    project_id: proj_id,
                    source: source.to_string(),
                    confidence: confidence.clamp(0.0, 1.0),
                    last_verified_at: now,
                    metadata: json!({}),
                });
            }
        }

        if let Some(app) = self.resources.resolve_best_app(trimmed) {
            return Some(app.to_resource_ref(confidence, source));
        }
        None
    }

    fn infer_project_id_for_path(
        &self,
        path: &Path,
        privacy: PrivacySessionPolicy,
    ) -> Option<String> {
        if privacy == PrivacySessionPolicy::StrictIsolated {
            return None;
        }
        let start = if path.is_dir() { path } else { path.parent()? };
        detect_project_root_upward(start, self.core).map(|b| b.project_id)
    }
}

/// Convenience helper resolving a resource query directly against an `IntentOsCore` instance.
pub fn resolve_resource_for_core(
    core: &IntentOsCore,
    query: &str,
    kind_filter: Option<ResourceKind>,
    session: Option<&SessionState>,
    privacy: PrivacySessionPolicy,
) -> ResourceResolution {
    let tracker = WorldStateTracker::for_core(core);
    let resolver = ResourceResolver::new(core, &tracker);
    resolver.resolve(query, kind_filter, session, privacy)
}

/// JSON RPC helper for `world_state` actions (`snapshot`, `update_desktop_focus_hint`, `invalidate`, `resolve_resource`).
pub fn handle_world_state_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: &Value,
) -> anyhow::Result<Value> {
    let tracker = WorldStateTracker::for_core(core);
    let incog = payload
        .get("incognito")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let sid = payload.get("session_id").and_then(|v| v.as_str());
    let explicit_pol = payload
        .get("privacy_policy")
        .and_then(|v| v.as_str())
        .and_then(PrivacySessionPolicy::parse_policy_str);
    let privacy = PrivacySessionPolicy::resolve(explicit_pol, incog, sid);
    let session = sid.and_then(|id| core.sessions.peek(id));

    match action {
        "snapshot" => {
            let snap =
                tracker.snapshot(Some(core), Some(&core.resources), session.as_ref(), privacy);
            Ok(serde_json::to_value(snap)?)
        }
        "update_desktop_focus_hint" | "update_focus_hint" => {
            let title = payload
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if title.is_empty() {
                anyhow::bail!("update_desktop_focus_hint requires non-empty `title`");
            }
            let info = DesktopWindowInfo {
                window_id: payload
                    .get("window_id")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                app_id: payload
                    .get("app_id")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                wm_class: payload
                    .get("wm_class")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                title,
                pid: payload
                    .get("pid")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32),
            };
            let src = payload
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("gnome_shell_extension");
            tracker.update_desktop_focus_hint_at(info, src, Utc::now());
            Ok(json!({ "ok": true }))
        }
        "invalidate" => {
            match payload
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("all")
            {
                "desktop" => tracker.invalidate_desktop(),
                "running_apps" => tracker.invalidate_running_apps(),
                "system_health" => tracker.invalidate_system_health(),
                "network" => tracker.invalidate_network(),
                _ => tracker.invalidate_all(),
            }
            Ok(json!({ "ok": true }))
        }
        "resolve_resource" | "resolve" => {
            let query = payload.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let kind = payload
                .get("kind")
                .and_then(|v| v.as_str())
                .and_then(ResourceKind::from_hint);
            let resolver = ResourceResolver::new(core, &tracker);
            let res = resolver.resolve(query, kind, session.as_ref(), privacy);
            Ok(serde_json::to_value(res)?)
        }
        other => anyhow::bail!("unknown world_state action: {}", other),
    }
}

// ============================================================================
// Internal On-Demand Host Samplers & Pure Scoring Helpers
// ============================================================================

fn current_real_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse::<u32>().ok();
        }
    }
    None
}

fn sample_running_user_apps_from_proc(resources: Option<&ResourceEngine>) -> Vec<RunningAppBrief> {
    let Some(res) = resources else {
        return Vec::new();
    };
    let indexed_apps = res.list_indexed_apps();
    if indexed_apps.is_empty() {
        return Vec::new();
    }

    // Map normalized executable stems -> best AppRecord (preferring real on-disk `.desktop` files)
    let mut stem_to_app: HashMap<String, AppRecord> = HashMap::new();
    for rec in indexed_apps {
        let is_real = Path::new(&rec.source).is_file();
        let mut keys = Vec::new();
        let exec_stem = extract_binary_stem(&rec.exec_cmd).to_ascii_lowercase();
        if exec_stem.len() >= 2 {
            keys.push(exec_stem.clone());
            for suf in ["-stable", "-native", "_app", "-bin"] {
                if let Some(s) = exec_stem.strip_suffix(suf)
                    && s.len() >= 2
                {
                    keys.push(s.to_string());
                }
            }
        }
        let id_stem = rec.app_id.trim_end_matches(".desktop").to_ascii_lowercase();
        if !id_stem.contains('.') && id_stem.len() >= 2 {
            keys.push(id_stem);
        }
        for k in keys {
            if INFRA_PROCESS_NAMES.contains(&k.as_str()) {
                continue;
            }
            match stem_to_app.get(&k) {
                Some(prev) if Path::new(&prev.source).is_file() && !is_real => {}
                _ => {
                    stem_to_app.insert(k, rec.clone());
                }
            }
        }
    }

    let my_uid = current_real_uid();
    let self_pid = std::process::id();
    let Ok(rd) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut by_app_id: BTreeMap<String, RunningAppBrief> = BTreeMap::new();
    for entry in rd.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid <= 1 || pid == self_pid {
            continue;
        }
        let proc_dir = entry.path();
        let Ok(status_raw) = fs::read_to_string(proc_dir.join("status")) else {
            continue;
        };
        let mut proc_uid = None;
        let mut is_zombie = false;
        let mut comm = String::new();
        for line in status_raw.lines() {
            if let Some(rest) = line.strip_prefix("Name:") {
                comm = rest.trim().to_ascii_lowercase();
            } else if let Some(rest) = line.strip_prefix("State:") {
                if rest.trim_start().starts_with('Z') {
                    is_zombie = true;
                }
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                proc_uid = rest
                    .split_whitespace()
                    .next()
                    .and_then(|u| u.parse::<u32>().ok());
            }
        }
        if is_zombie {
            continue;
        }
        if let (Some(expected), Some(actual)) = (my_uid, proc_uid)
            && expected != actual
        {
            continue;
        }
        if INFRA_PROCESS_NAMES.contains(&comm.as_str()) {
            continue;
        }

        let exe_stem = fs::read_link(proc_dir.join("exe"))
            .ok()
            .and_then(|p| {
                p.file_name().map(|s| {
                    s.to_string_lossy()
                        .trim_end_matches(" (deleted)")
                        .to_ascii_lowercase()
                })
            })
            .unwrap_or_default();
        if !exe_stem.is_empty() && INFRA_PROCESS_NAMES.contains(&exe_stem.as_str()) {
            continue;
        }

        let matched = stem_to_app
            .get(&exe_stem)
            .or_else(|| stem_to_app.get(&comm));
        if let Some(app) = matched {
            let binary_name = if !exe_stem.is_empty() { exe_stem } else { comm };
            let entry_brief =
                by_app_id
                    .entry(app.app_id.clone())
                    .or_insert_with(|| RunningAppBrief {
                        app_id: app.app_id.clone(),
                        display_name: app.name.clone(),
                        binary_name,
                        pids: Vec::new(),
                        desktop_source: Path::new(&app.source)
                            .is_file()
                            .then(|| app.source.clone()),
                    });
            if !entry_brief.pids.contains(&pid) {
                entry_brief.pids.push(pid);
            }
        }
    }

    by_app_id.into_values().collect()
}

fn sample_system_health_from_proc(now: DateTime<Utc>) -> SystemHealthBrief {
    let cpu_load_1m = fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|raw| raw.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0);

    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut mem_total_kb: u64 = 0;
    let mut mem_avail_kb: Option<u64> = None;
    let mut mem_free_kb: u64 = 0;
    let mut swap_total_kb: u64 = 0;
    let mut swap_free_kb: u64 = 0;

    for line in meminfo.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let Some(val_kb) = parts.next().and_then(|v| v.parse::<u64>().ok()) else {
            continue;
        };
        match key {
            "MemTotal:" => mem_total_kb = val_kb,
            "MemAvailable:" => mem_avail_kb = Some(val_kb),
            "MemFree:" => mem_free_kb = val_kb,
            "SwapTotal:" => swap_total_kb = val_kb,
            "SwapFree:" => swap_free_kb = val_kb,
            _ => {}
        }
    }

    let avail_kb = mem_avail_kb.unwrap_or(mem_free_kb);
    let mem_used_pct = if mem_total_kb > 0 {
        let used = mem_total_kb.saturating_sub(avail_kb);
        (((used as f64 / mem_total_kb as f64) * 1000.0).round()) / 10.0
    } else {
        0.0
    };

    SystemHealthBrief {
        cpu_load_1m,
        mem_used_pct,
        mem_available_mb: avail_kb / 1024,
        swap_used_mb: swap_total_kb.saturating_sub(swap_free_kb) / 1024,
        sampled_at: now,
    }
}

fn sample_network_from_proc_and_env(now: DateTime<Utc>) -> NetworkBrief {
    let mut primary_interface: Option<String> = None;
    let mut online = false;

    if let Ok(routes) = fs::read_to_string("/proc/net/route") {
        for line in routes.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 {
                let iface = cols[0];
                let dest = cols[1];
                let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
                // Destination `00000000` + `RTF_UP` (`0x1`) indicates active default IPv4 route
                if iface != "lo" && dest == "00000000" && (flags & 0x1) != 0 {
                    primary_interface = Some(iface.to_string());
                    online = true;
                    break;
                }
            }
        }
    }

    if !online && let Ok(rd) = fs::read_dir("/sys/class/net") {
        for entry in rd.flatten() {
            let iface = entry.file_name().to_string_lossy().to_string();
            if iface == "lo" {
                continue;
            }
            if let Ok(state) = fs::read_to_string(entry.path().join("operstate"))
                && state.trim() == "up"
            {
                primary_interface = Some(iface);
                online = true;
                break;
            }
        }
    }

    let proxy_hint = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .into_iter()
    .find_map(|k| std::env::var(k).ok())
    .map(|raw| sanitize_proxy_url(&raw))
    .filter(|s| !s.is_empty());

    NetworkBrief {
        online,
        primary_interface,
        proxy_hint,
        sampled_at: now,
    }
}

fn sanitize_proxy_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let without_userinfo = if let Some((scheme, rest)) = trimmed.split_once("://") {
        if let Some((_userinfo, host_part)) = rest.rsplit_once('@') {
            format!("{}://{}", scheme, host_part)
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    };
    SensitiveDataGuard::redact_text(&without_userinfo).0
}

fn probe_x11_active_window() -> Option<DesktopWindowInfo> {
    if std::env::var_os("DISPLAY")
        .map(|v| v.is_empty())
        .unwrap_or(true)
    {
        return None;
    }
    let xprop = resolve_trusted_executable("xprop")?;
    let root_out = Command::new(&xprop)
        .args(["-root", "-notype", "_NET_ACTIVE_WINDOW"])
        .output()
        .ok()?;
    if !root_out.status.success() {
        return None;
    }
    let root_str = String::from_utf8_lossy(&root_out.stdout);
    let win_id = root_str
        .split_whitespace()
        .find(|tok| tok.starts_with("0x") && *tok != "0x0" && *tok != "0x0,")?
        .trim_end_matches(',')
        .to_string();

    let win_out = Command::new(&xprop)
        .args(["-id", &win_id, "_NET_WM_NAME", "WM_CLASS", "_NET_WM_PID"])
        .output()
        .ok()?;
    if !win_out.status.success() {
        return None;
    }

    let mut title = String::new();
    let mut wm_class = None;
    let mut pid = None;
    for line in String::from_utf8_lossy(&win_out.stdout).lines() {
        if line.starts_with("_NET_WM_NAME") {
            if let Some((_, rhs)) = line.split_once('=') {
                title = rhs.trim().trim_matches('"').to_string();
            }
        } else if line.starts_with("WM_CLASS") {
            if let Some((_, rhs)) = line.split_once('=') {
                let last_cls = rhs
                    .split(',')
                    .next_back()
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty());
                wm_class = last_cls;
            }
        } else if line.starts_with("_NET_WM_PID")
            && let Some((_, rhs)) = line.split_once('=')
        {
            pid = rhs.trim().parse::<u32>().ok();
        }
    }

    if title.is_empty() {
        return None;
    }
    Some(DesktopWindowInfo {
        window_id: Some(win_id),
        app_id: None,
        wm_class,
        title: SensitiveDataGuard::redact_text(&title).0,
        pid,
    })
}

fn detect_project_root_upward(
    start_dir: &Path,
    core: Option<&IntentOsCore>,
) -> Option<ActiveProjectBrief> {
    let mut cur = Some(start_dir);
    let mut depth = 0usize;
    while let Some(dir) = cur {
        if depth > 6 {
            break;
        }
        if let Some(c) = core
            && c.fs_engine.is_forbidden(dir)
        {
            return None;
        }
        let has_git = dir.join(".git").exists();
        let has_cargo = dir.join("Cargo.toml").is_file();
        let has_pkg = dir.join("package.json").is_file();
        let has_py = dir.join("pyproject.toml").is_file();
        let has_go = dir.join("go.mod").is_file();

        if has_git || has_cargo || has_pkg || has_py || has_go {
            let mut tech_stack = Vec::new();
            if has_cargo {
                tech_stack.push("Rust".to_string());
            }
            if has_pkg {
                tech_stack.push("Node.js".to_string());
            }
            if has_py {
                tech_stack.push("Python".to_string());
            }
            if has_go {
                tech_stack.push("Go".to_string());
            }
            if has_git {
                tech_stack.push("Git".to_string());
            }
            let folder_name = dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("project")
                .to_string();
            let project_id = slugify_project_id(&folder_name);
            let git_branch = read_git_head_branch(dir);
            return Some(ActiveProjectBrief {
                project_id,
                name: folder_name,
                root_path: dir.to_path_buf(),
                git_branch,
                tech_stack,
                source: "git_or_manifest_root".to_string(),
            });
        }
        cur = dir.parent();
        depth += 1;
    }
    None
}

fn read_git_head_branch(dir: &Path) -> Option<String> {
    let raw = fs::read_to_string(dir.join(".git/HEAD")).ok()?;
    let trimmed = raw.trim();
    if let Some(branch) = trimmed.strip_prefix("ref: refs/heads/") {
        Some(branch.trim().to_string())
    } else if trimmed.len() >= 7 {
        Some(trimmed[..7].to_string())
    } else {
        None
    }
}

fn slugify_project_id(raw: &str) -> String {
    let mut s = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            s.push(ch.to_ascii_lowercase());
        } else if ch == '.' || ch == ' ' {
            s.push('-');
        }
    }
    let clean = s.trim_matches('-').to_string();
    if clean.is_empty() {
        "project".to_string()
    } else {
        clean
    }
}

fn list_projects_privacy_safe(
    core: &IntentOsCore,
    privacy: PrivacySessionPolicy,
) -> Vec<ProjectRecord> {
    if !privacy.allows_memory_read() {
        return Vec::new();
    }
    if privacy.allows_memory_write() {
        return project_memory::discover_and_list_projects(core, false).unwrap_or_default();
    }
    // EphemeralReadOnly: read existing JSON store if present, NEVER write new files to disk
    let store_path = core.paths.data_dir.join("execution_hub_projects_mem.json");
    if let Ok(raw) = fs::read_to_string(store_path)
        && let Ok(val) = serde_json::from_str::<Value>(&raw)
        && let Some(obj) = val.get("projects").and_then(|v| v.as_object())
    {
        return obj
            .values()
            .filter_map(|item| serde_json::from_value::<ProjectRecord>(item.clone()).ok())
            .collect();
    }
    Vec::new()
}

fn is_self_shell_window(win: &DesktopWindowInfo) -> bool {
    let cls = win.wm_class.as_deref().unwrap_or("").to_ascii_lowercase();
    let app = win.app_id.as_deref().unwrap_or("").to_ascii_lowercase();
    let title = win.title.to_ascii_lowercase();
    cls.contains("intentos-launcher")
        || app.contains("intentos-launcher")
        || cls == "gnome-shell"
        || title.contains("intentos · 随问")
}

fn is_selection_or_clipboard_query(q: &str) -> bool {
    [
        "选中的文本",
        "选中文本",
        "选中的文字",
        "选中文字",
        "选中的内容",
        "剪贴板里的内容",
        "剪贴板内容",
        "剪贴板里的文字",
        "剪贴板",
    ]
    .iter()
    .any(|p| q.contains(p))
}

pub(crate) fn is_close_or_active_window_deictic(q: &str) -> bool {
    let trimmed = q.trim();
    if [
        "当前窗口",
        "这个窗口",
        "活动窗口",
        "前台窗口",
        "当前应用",
        "前台应用",
    ]
    .iter()
    .any(|p| trimmed.contains(p))
    {
        return true;
    }

    let close_phrases = [
        "把它关掉",
        "把它关闭",
        "把它关了",
        "把它退出",
        "将它关掉",
        "将它关闭",
        "关掉它",
        "关闭它",
        "退出它",
        "把这个软件关掉",
        "关掉这个软件",
        "关闭这个软件",
        "把这个应用关掉",
        "关掉这个应用",
        "关闭这个应用",
    ];
    close_phrases.iter().any(|p| trimmed.contains(p))
}

pub(crate) fn is_conversational_resource_deictic(q: &str) -> bool {
    let phrases = [
        "刚才那个文件",
        "刚才那份文件",
        "刚才的文件",
        "刚才改的文件",
        "刚才改的配置",
        "刚才打开的文件",
        "上一个文件",
        "上一个结果",
        "我之前说的那个文件",
        "之前说的那个文件",
        "上次提到的文档",
        "上次提到的文件",
        "刚才那个",
        "打开它",
        "复制它",
        "移动它",
        "查看它",
        "编辑它",
    ];
    phrases.iter().any(|p| q.contains(p))
}

pub(crate) fn is_comparative_query(q: &str) -> bool {
    let lc = q.to_ascii_lowercase();
    let has_comp_word = [
        "比较", "对比", "对照", "差异", "区别", "变化", "compare", "diff", "versus",
    ]
    .iter()
    .any(|w| lc.contains(w))
        || lc.contains(" vs ")
        || lc.contains("两个版本")
        || lc.contains("新旧版本");

    let has_dual_time = (q.contains("昨天") || q.contains("昨日") || lc.contains("yesterday"))
        && (q.contains("前天")
            || q.contains("前日")
            || q.contains("今天")
            || q.contains("今日")
            || lc.contains("today")
            || lc.contains("day before"));

    has_comp_word || has_dual_time
}

fn is_experiment_domain_query(q: &str) -> bool {
    let lc = q.to_ascii_lowercase();
    [
        "实验",
        "结果",
        "指标",
        "评测",
        "训练",
        "跑分",
        "experiment",
        "result",
        "metric",
        "eval",
        "bench",
        "ablation",
    ]
    .iter()
    .any(|kw| lc.contains(kw))
}

fn score_comparative_domain_relevance(
    rec: &FileRecord,
    query: &str,
    wants_experiment: bool,
) -> f64 {
    let ext = rec.ext.to_ascii_lowercase();
    let kind = rec.infer_resource_kind();

    if wants_experiment {
        let data_ext = matches!(
            ext.as_str(),
            "csv" | "json" | "jsonl" | "md" | "tsv" | "txt" | "yaml" | "yml" | "log"
        );
        if !data_ext {
            return 0.0;
        }
        if kind == ResourceKind::ExperimentResult {
            return 0.82;
        }
        return 0.66;
    }

    let cleaned = strip_comparative_words(query);
    if cleaned.is_empty() {
        return 0.70;
    }
    score_file_match(rec, &cleaned, 0, false).max(0.60)
}

fn strip_comparative_words(q: &str) -> String {
    let mut s = q.to_string();
    for w in [
        "比较",
        "对比",
        "对照",
        "查看",
        "检查",
        "分析",
        "昨天",
        "昨日",
        "前天",
        "前日",
        "今天",
        "今日",
        "与",
        "和",
        "跟",
        "以及",
        "两个版本",
        "新旧版本",
        "的",
        "一下",
    ] {
        s = s.replace(w, " ");
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_date_from_filename_or_dir(
    filename: &str,
    parent_dir: &str,
    default_year: i32,
) -> Option<NaiveDate> {
    static FULL_DATE_RE: OnceLock<Regex> = OnceLock::new();
    static COMPACT_DATE_RE: OnceLock<Regex> = OnceLock::new();
    static MD_DATE_RE: OnceLock<Regex> = OnceLock::new();

    let full_re = FULL_DATE_RE.get_or_init(|| {
        Regex::new(r"(20\d{2})[-_.](0[1-9]|1[0-2])[-_.](0[1-9]|[12]\d|3[01])").expect("date re")
    });
    let compact_re = COMPACT_DATE_RE.get_or_init(|| {
        Regex::new(r"(?:^|[^0-9])(20\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?:[^0-9]|$)")
            .expect("compact date re")
    });
    let md_re = MD_DATE_RE.get_or_init(|| {
        Regex::new(r"(?:^|[-_])(0[1-9]|1[0-2])[-_](0[1-9]|[12]\d|3[01])(?:[-_.]|$)")
            .expect("md date re")
    });

    let parent_leaf = Path::new(parent_dir)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    for target in [filename, parent_leaf] {
        if let Some(caps) = full_re.captures(target)
            && let (Ok(y), Ok(m), Ok(d)) = (
                caps[1].parse::<i32>(),
                caps[2].parse::<u32>(),
                caps[3].parse::<u32>(),
            )
            && let Some(nd) = NaiveDate::from_ymd_opt(y, m, d)
        {
            return Some(nd);
        }
        if let Some(caps) = compact_re.captures(target)
            && let (Ok(y), Ok(m), Ok(d)) = (
                caps[1].parse::<i32>(),
                caps[2].parse::<u32>(),
                caps[3].parse::<u32>(),
            )
            && let Some(nd) = NaiveDate::from_ymd_opt(y, m, d)
        {
            return Some(nd);
        }
        if let Some(caps) = md_re.captures(target)
            && let (Ok(m), Ok(d)) = (caps[1].parse::<u32>(), caps[2].parse::<u32>())
            && let Some(nd) = NaiveDate::from_ymd_opt(default_year, m, d)
        {
            return Some(nd);
        }
    }
    None
}

fn extract_relative_day_token(filename: &str, today: NaiveDate) -> Option<NaiveDate> {
    let lc = filename.to_ascii_lowercase();
    if lc.contains("day_before")
        || lc.contains("day-before")
        || lc.contains("prev_day")
        || filename.contains("前天")
    {
        today.checked_sub_days(Days::new(2))
    } else if lc.contains("yesterday") || filename.contains("昨天") {
        today.checked_sub_days(Days::new(1))
    } else if lc.contains("today") || filename.contains("今天") {
        Some(today)
    } else {
        None
    }
}

fn shift_date(date: NaiveDate, delta_days: i64) -> NaiveDate {
    if delta_days == 0 {
        date
    } else if delta_days > 0 {
        date.checked_add_days(Days::new(delta_days as u64))
            .unwrap_or(date)
    } else {
        date.checked_sub_days(Days::new((-delta_days) as u64))
            .unwrap_or(date)
    }
}

fn extract_base_stem_and_version(stem: &str) -> Option<(String, u32)> {
    static VER_RE: OnceLock<Regex> = OnceLock::new();
    let re = VER_RE.get_or_init(|| {
        Regex::new(r"(?i)^(.+?)[-_.\s]*(?:v|ver|version|draft|rev)(\d+)$").expect("ver re")
    });
    if let Some(caps) = re.captures(stem.trim()) {
        let base = caps[1].trim().to_lowercase();
        let ver = caps[2].parse::<u32>().ok()?;
        if !base.is_empty() {
            return Some((base, ver));
        }
    }
    if let Some(base) = stem.strip_suffix("初稿") {
        let clean = base.trim_matches(['_', '-', ' ']).to_lowercase();
        if !clean.is_empty() {
            return Some((clean, 1));
        }
    }
    if let Some(base) = stem.strip_suffix("终稿") {
        let clean = base.trim_matches(['_', '-', ' ']).to_lowercase();
        if !clean.is_empty() {
            return Some((clean, 2));
        }
    }
    None
}

fn score_version_group_relevance(rec: &FileRecord, base_stem: &str, query: &str) -> f64 {
    let cleaned = strip_comparative_words(query).to_lowercase();
    if cleaned.is_empty() {
        return 0.78;
    }
    if cleaned.contains(base_stem) || base_stem.contains(&cleaned) {
        return 0.92;
    }
    let (py_full, _) = to_pinyin_pair(&rec.name);
    let (q_py, _) = to_pinyin_pair(&cleaned);
    if !q_py.is_empty() && py_full.contains(&q_py) {
        return 0.85;
    }
    if (cleaned.contains("报告") && base_stem.contains("report"))
        || (cleaned.contains("论文")
            && (base_stem.contains("paper") || base_stem.contains("thesis")))
        || (cleaned.contains("文档") && rec.infer_resource_kind() == ResourceKind::Document)
    {
        return 0.84;
    }
    0.0
}

fn build_comparative_file_ref(
    rec: &FileRecord,
    confidence: f64,
    project_id: Option<String>,
    inferred_date: Option<String>,
    version_tag: Option<String>,
    comparison_role: &str,
) -> ResourceRef {
    let mut rref = rec.to_resource_ref(
        confidence.clamp(0.60, 0.98),
        "resource_resolver.comparative",
        project_id,
    );
    if let Some(obj) = rref.metadata.as_object_mut() {
        obj.insert("comparison_role".to_string(), json!(comparison_role));
        if let Some(d) = inferred_date {
            obj.insert("inferred_date".to_string(), json!(d));
        }
        if let Some(v) = version_tag {
            obj.insert("version_tag".to_string(), json!(v));
        }
    }
    rref
}

fn extract_paths_from_session(sess: &SessionState) -> Vec<String> {
    static PATH_RE: OnceLock<Regex> = OnceLock::new();
    let re = PATH_RE.get_or_init(|| {
        Regex::new(r#"(~[^\s，,。；;"'`]+|/[a-zA-Z0-9._/\-\u{4e00}-\u{9fa5}]+)"#)
            .expect("session path regex")
    });
    let mut out = Vec::new();
    for msg in sess.messages.iter().rev() {
        for caps in re.captures_iter(&msg.content) {
            let p = caps[1].trim().to_string();
            if p.len() > 2 && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

fn extract_single_explicit_path(q: &str) -> Option<String> {
    static PATH_RE: OnceLock<Regex> = OnceLock::new();
    let re = PATH_RE.get_or_init(|| {
        Regex::new(r#"(~[^\s，,。；;"'`]+|/[a-zA-Z0-9._/\-\u{4e00}-\u{9fa5}]+)"#)
            .expect("explicit path regex")
    });
    let mut iter = re.captures_iter(q);
    let first = iter.next()?[1].trim().to_string();
    if iter.next().is_some() {
        return None;
    }
    Some(first)
}

fn expand_tilde_path(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(raw)
    }
}

fn strip_resource_query_noise(raw: &str) -> String {
    let mut s = raw
        .trim()
        .trim_matches(['"', '\'', '“', '”', '「', '」', '《', '》', '`'])
        .to_string();
    for prefix in [
        "帮我打开",
        "帮我找一下",
        "帮我查找",
        "帮我查看",
        "请打开",
        "请查看",
        "打开最新的",
        "打开最近的",
        "查找文件",
        "查看文件",
        "打开文件",
        "打开文档",
        "打开",
        "查看",
        "读取",
        "编辑",
        "查找",
        "搜索",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let trimmed = rest.trim();
            if !trimmed.is_empty() {
                s = trimmed.to_string();
                break;
            }
        }
    }
    s.trim_matches(['"', '\'', '“', '”', '「', '」', '《', '》', '`'])
        .trim()
        .to_string()
}

fn score_project_match(proj: &ProjectRecord, q: &str) -> f64 {
    let ql = q.trim().to_lowercase();
    if ql.is_empty() {
        return 0.0;
    }
    let name_lc = proj.name.to_lowercase();
    let id_lc = proj.project_id.to_lowercase();
    if name_lc == ql || id_lc == ql {
        0.96
    } else if name_lc.starts_with(&ql) || id_lc.starts_with(&ql) {
        0.84
    } else if name_lc.contains(&ql) || id_lc.contains(&ql) {
        0.72
    } else {
        0.0
    }
}

fn score_file_match(rec: &FileRecord, query: &str, now_secs: i64, prefers_latest: bool) -> f64 {
    let ql = query.trim().to_lowercase();
    if ql.is_empty() {
        return 0.0;
    }

    let name_lc = rec.name.to_lowercase();
    let stem_lc = rec.stem.to_lowercase();
    let ext_lc = rec.ext.to_ascii_lowercase();

    let (q_stem, q_ext_opt) = match ql.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() && !e.is_empty() && e.len() <= 8 => (s, Some(e)),
        _ => (ql.as_str(), None),
    };

    // If caller explicitly included a file extension (e.g. `report.docx`), require matching extension
    // unless the full name still matches.
    if let Some(req_ext) = q_ext_opt
        && ext_lc != req_ext
        && !name_lc.contains(&ql)
    {
        return 0.0;
    }

    let (py_full, py_init) = to_pinyin_pair(&rec.stem);
    let (q_py_full, _) = to_pinyin_pair(q_stem);

    let base: f64 = if name_lc == ql {
        0.97
    } else if stem_lc == ql || (q_ext_opt.is_some() && stem_lc == q_stem) {
        0.95
    } else if stem_lc.starts_with(q_stem) && q_stem.chars().count() >= 2 {
        // Prefix match (e.g. `report` or `report.docx` matching `report_v1.docx` & `report_v2.docx`)
        0.82
    } else if !py_init.is_empty() && (py_init == q_stem || py_full == q_stem) {
        0.80
    } else if !q_py_full.is_empty()
        && q_py_full.len() >= 4
        && (py_full == q_py_full || stem_lc == q_py_full)
    {
        0.79
    } else if stem_lc.contains(q_stem) && q_stem.chars().count() >= 2 {
        0.72
    } else if !q_py_full.is_empty() && q_py_full.len() >= 4 && py_full.contains(&q_py_full) {
        0.65
    } else {
        0.0
    };

    if base <= 0.0 {
        return 0.0;
    }

    let recency_bonus = if now_secs > 0 {
        let age_hours = ((now_secs - rec.mtime_secs).max(0) as f64) / 3600.0;
        if prefers_latest {
            // Explicit `"最新"` / `"latest"` query intentionally breaks ties by modification time
            0.16 / (1.0 + age_hours / 12.0)
        } else {
            // Modest tie-breaker (`<= 0.02`) so competing versions (`report_v1` vs `report_v2`)
            // remain well within `< 0.12` ambiguity margin when user did not ask for latest!
            0.02 / (1.0 + age_hours / 48.0)
        }
    } else {
        0.0
    };

    (base + recency_bonus).clamp(0.0, 0.99)
}

// ============================================================================
// Unit Tests (`M2-B`)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::db::IndexDb;
    use chrono::Duration;
    use intentos_fsops::SafeFsEngine;
    use tempfile::TempDir;

    fn make_isolated_engine() -> (TempDir, Arc<ResourceEngine>) {
        let tmp = TempDir::new().expect("tempdir");
        let work = tmp.path().join("workspace");
        fs::create_dir_all(&work).unwrap();
        let idx = Arc::new(IndexDb::open_or_rebuild(&tmp.path().join("index.db")).unwrap());
        let fs_eng = Arc::new(
            SafeFsEngine::new(
                vec![work],
                vec![tmp.path().join("forbidden")],
                tmp.path().join("undo"),
                tmp.path().join("trash"),
            )
            .unwrap(),
        );
        let engine = Arc::new(ResourceEngine::new(idx, fs_eng, AppConfig::default()));
        (tmp, engine)
    }

    fn make_test_core() -> (TempDir, Arc<IntentOsCore>) {
        let tmp = TempDir::new().expect("tempdir");
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .to_path_buf();
        let core = IntentOsCore::initialize(Some(tmp.path()), repo_root).expect("init core");
        (tmp, core)
    }

    #[test]
    fn m2b_test_a_close_deictic_wayland_honesty_focus_ttl_and_no_silent_guessing() {
        let (_tmp, engine) = make_isolated_engine();
        let _ = engine.index_applications();
        let tracker = WorldStateTracker::with_session_type("wayland");
        tracker.set_running_apps_override(Some(Vec::new()));
        let resolver = ResourceResolver::with_engine(&engine, &tracker);

        let t0 = Utc.with_ymd_and_hms(2026, 11, 15, 9, 0, 0).unwrap();

        // 1. Unverified Wayland state (no focus hint, 0 running apps) -> Unavailable("wayland_compositor_isolated")
        let snap0 = tracker.snapshot_at(
            t0,
            None,
            Some(&engine),
            None,
            PrivacySessionPolicy::Standard,
        );
        assert_eq!(snap0.desktop.session_type, "wayland");
        assert_eq!(
            snap0.desktop.active_window.unavailable_reason(),
            Some("wayland_compositor_isolated")
        );

        let res_unverified =
            resolver.resolve_at(t0, "把它关掉", None, None, PrivacySessionPolicy::Standard);
        match res_unverified {
            ResourceResolution::Unavailable { reason, .. } => {
                assert_eq!(reason, "wayland_compositor_isolated");
            }
            other => panic!(
                "expected Unavailable on unverified Wayland, got {:?}",
                other
            ),
        }

        // 2. Inject fresh verified focus hint from GNOME Shell extension -> resolves exact foreground app!
        tracker.update_desktop_focus_hint_at(
            DesktopWindowInfo {
                window_id: Some("wayland:win:42".to_string()),
                app_id: Some("firefox.desktop".to_string()),
                wm_class: Some("firefox".to_string()),
                title: "ArXiv Paper - Mozilla Firefox".to_string(),
                pid: Some(4242),
            },
            "gnome_shell_extension",
            t0,
        );
        let t_fresh = t0 + Duration::seconds(8); // 8s <= 15s TTL
        let res_fresh = resolver.resolve_at(
            t_fresh,
            "把它关掉",
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        let single = res_fresh
            .as_single()
            .expect("fresh verified focus hint must resolve to Single");
        assert_eq!(single.kind, ResourceKind::DesktopWindow);
        assert_eq!(single.source, "gnome_shell_extension");
        assert_eq!(
            single.metadata.get("app_id").and_then(|v| v.as_str()),
            Some("firefox.desktop")
        );

        // 3. Expired focus hint (20s > 15s TTL) on Wayland with multiple running GUI apps -> Ambiguous (NEVER guesses!)
        tracker.set_running_apps_override(Some(vec![
            RunningAppBrief {
                app_id: "firefox.desktop".to_string(),
                display_name: "Firefox 浏览器".to_string(),
                binary_name: "firefox".to_string(),
                pids: vec![4242],
                desktop_source: None,
            },
            RunningAppBrief {
                app_id: "code.desktop".to_string(),
                display_name: "Visual Studio Code".to_string(),
                binary_name: "code".to_string(),
                pids: vec![5151],
                desktop_source: None,
            },
        ]));
        let t_expired = t0 + Duration::seconds(20);
        let snap_expired = tracker.snapshot_at(
            t_expired,
            None,
            Some(&engine),
            None,
            PrivacySessionPolicy::Standard,
        );
        assert_eq!(
            snap_expired.desktop.active_window.unavailable_reason(),
            Some("wayland_compositor_isolated")
        );

        let res_expired = resolver.resolve_at(
            t_expired,
            "把它关掉",
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        match res_expired {
            ResourceResolution::Ambiguous {
                candidates,
                clarification_prompt,
                ..
            } => {
                assert_eq!(candidates.len(), 2);
                assert!(clarification_prompt.contains("wayland_compositor_isolated"));
            }
            other => panic!(
                "expected Ambiguous when focus hint expired with multiple apps running, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn m2b_test_b_comparative_dated_experiment_results_and_versions() {
        let (_tmp, engine) = make_isolated_engine();
        let ws_root = engine.authorized_roots()[0].clone();
        let exp_dir = ws_root.join("experiments");
        fs::create_dir_all(&exp_dir).unwrap();

        // Today = 2026-11-15 -> yesterday = 2026-11-14, day before yesterday = 2026-11-13
        let now = Utc.with_ymd_and_hms(2026, 11, 15, 14, 30, 0).unwrap();

        let file_yest = exp_dir.join("exp_metrics_2026-11-14.json");
        let file_prev = exp_dir.join("exp_results_2026-11-13.csv");
        let file_old = exp_dir.join("exp_results_2026-11-01.md");
        fs::write(&file_yest, r#"{"acc": 0.942, "loss": 0.18}"#).unwrap();
        fs::write(&file_prev, "epoch,acc,loss\n10,0.915,0.24\n").unwrap();
        fs::write(&file_old, "# Old Baseline\nacc: 0.85\n").unwrap();

        let tracker = WorldStateTracker::with_session_type("headless");
        let resolver = ResourceResolver::with_engine(&engine, &tracker);

        let res = resolver.resolve_at(
            now,
            "比较昨天与前天的实验结果",
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        let pair = res
            .comparative_refs()
            .expect("expected MultipleComparative with two dated experiment files");
        assert_eq!(pair.len(), 2);
        assert_eq!(pair[0].kind, ResourceKind::ExperimentResult);
        assert_eq!(pair[1].kind, ResourceKind::ExperimentResult);
        assert_eq!(pair[0].path.as_deref(), Some(file_yest.as_path()));
        assert_eq!(pair[1].path.as_deref(), Some(file_prev.as_path()));
        assert_eq!(
            pair[0]
                .metadata
                .get("inferred_date")
                .and_then(|v| v.as_str()),
            Some("2026-11-14")
        );
        assert_eq!(
            pair[1]
                .metadata
                .get("inferred_date")
                .and_then(|v| v.as_str()),
            Some("2026-11-13")
        );
    }

    #[test]
    fn m2b_test_c_ambiguous_file_query_vs_specific_version_and_version_comparison() {
        let (_tmp, engine) = make_isolated_engine();
        let ws_root = engine.authorized_roots()[0].clone();
        let v1 = ws_root.join("report_v1.docx");
        let v2 = ws_root.join("report_v2.docx");
        fs::write(&v1, b"draft v1").unwrap();
        fs::write(&v2, b"draft v2").unwrap();

        let tracker = WorldStateTracker::with_session_type("headless");
        let resolver = ResourceResolver::with_engine(&engine, &tracker);
        let now = Utc.with_ymd_and_hms(2026, 11, 15, 10, 0, 0).unwrap();

        // 1. Ambiguous query `"打开 report.docx"` -> `< 0.12` margin -> `ResourceResolution::Ambiguous`!
        let ambig = resolver.resolve_at(
            now,
            "打开 report.docx",
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        match ambig {
            ResourceResolution::Ambiguous {
                candidates,
                clarification_prompt,
                ..
            } => {
                assert_eq!(candidates.len(), 2);
                let names: Vec<&str> = candidates.iter().map(|c| c.display_name.as_str()).collect();
                assert!(names.contains(&"report_v1.docx"));
                assert!(names.contains(&"report_v2.docx"));
                assert!(clarification_prompt.contains("report_v1.docx"));
                assert!(clarification_prompt.contains("report_v2.docx"));
            }
            other => panic!(
                "expected Ambiguous for report_v1 vs report_v2, got {:?}",
                other
            ),
        }

        // 2. Specific query `"report_v2.docx"` -> `ResourceResolution::Single`
        let exact = resolver.resolve_at(
            now,
            "report_v2.docx",
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        let single = exact
            .as_single()
            .expect("expected Single for report_v2.docx");
        assert_eq!(single.path.as_deref(), Some(v2.as_path()));
        assert_eq!(single.kind, ResourceKind::Document);

        // 3. Comparative version query `"对比两个版本的 report"` -> `MultipleComparative`
        let comp = resolver.resolve_at(
            now,
            "对比两个版本的 report",
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        let refs = comp
            .comparative_refs()
            .expect("expected MultipleComparative");
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn m2b_test_d_world_state_ttl_invalidation_and_strict_isolated_privacy_filtering() {
        let (_tmp, core) = make_test_core();
        let ws_root = core.fs_engine.authorized_roots()[0].clone();

        // Create a real Git/Rust project inside authorized workspace
        let proj_dir = ws_root.join("thesis-sim");
        fs::create_dir_all(proj_dir.join(".git")).unwrap();
        fs::write(
            proj_dir.join(".git/HEAD"),
            "ref: refs/heads/feat/ablation\n",
        )
        .unwrap();
        fs::write(
            proj_dir.join("Cargo.toml"),
            "[package]\nname = \"thesis-sim\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let note_file = proj_dir.join("notes.md");
        fs::write(&note_file, "# Research Notes\n").unwrap();

        // Record a personal memory file in Standard mode
        memory_hub::record_conversation_turn_with_policy(
            &core,
            &memory_hub::RecordTurnInput {
                session_id: Some("ses_std_1".to_string()),
                user_text: format!("请查看 `{}`", note_file.display()),
                assistant_text: "已读取 notes.md。".to_string(),
                thinking: None,
                tool_steps: Vec::new(),
                trace_dots: Vec::new(),
                incognito: false,
            },
            PrivacySessionPolicy::Standard,
        )
        .unwrap();

        let tracker = WorldStateTracker::with_session_type("wayland");
        tracker.update_active_cwd(proj_dir.clone());

        let t0 = Utc.with_ymd_and_hms(2026, 11, 15, 11, 0, 0).unwrap();

        // 1. Sample at t0 in Standard mode -> active_project is populated, health/apps/network sampled once
        let snap1 = tracker.snapshot_at(
            t0,
            Some(&core),
            Some(&core.resources),
            None,
            PrivacySessionPolicy::Standard,
        );
        assert_eq!(tracker.system_health_sample_count(), 1);
        assert_eq!(tracker.running_apps_sample_count(), 1);
        assert_eq!(tracker.network_sample_count(), 1);
        let proj = snap1
            .active_project
            .as_ref()
            .expect("Standard policy should include active_project");
        assert_eq!(proj.project_id, "thesis-sim");
        assert_eq!(proj.git_branch.as_deref(), Some("feat/ablation"));
        assert!(snap1.system_health.mem_available_mb > 0);

        // 2. Within 5s TTL (`t0 + 3s`) -> zero re-sampling!
        let _snap2 = tracker.snapshot_at(
            t0 + Duration::seconds(3),
            Some(&core),
            Some(&core.resources),
            None,
            PrivacySessionPolicy::Standard,
        );
        assert_eq!(tracker.system_health_sample_count(), 1);
        assert_eq!(tracker.running_apps_sample_count(), 1);
        assert_eq!(tracker.network_sample_count(), 1);

        // 3. At `t0 + 6s` -> 5s TTL expired for health & running_apps, 10s network TTL still cached!
        let _snap3 = tracker.snapshot_at(
            t0 + Duration::seconds(6),
            Some(&core),
            Some(&core.resources),
            None,
            PrivacySessionPolicy::Standard,
        );
        assert_eq!(tracker.system_health_sample_count(), 2);
        assert_eq!(tracker.running_apps_sample_count(), 2);
        assert_eq!(tracker.network_sample_count(), 1);

        // 4. Event-driven invalidation forces immediate refresh even before TTL expires
        tracker.invalidate_network();
        let _snap4 = tracker.snapshot_at(
            t0 + Duration::seconds(7),
            Some(&core),
            Some(&core.resources),
            None,
            PrivacySessionPolicy::Standard,
        );
        assert_eq!(tracker.network_sample_count(), 2);

        // 5. `StrictIsolated` policy -> omits `active_project`, `active_cwd`, `pending_tasks_count`,
        //    and blocks `memory_hub` deictic recall (`"我之前说的那个文件"`)!
        let snap_strict = tracker.snapshot_at(
            t0 + Duration::seconds(7),
            Some(&core),
            Some(&core.resources),
            None,
            PrivacySessionPolicy::StrictIsolated,
        );
        assert!(
            snap_strict.active_project.is_none(),
            "StrictIsolated MUST omit active_project"
        );
        assert!(
            snap_strict.active_cwd.is_none(),
            "StrictIsolated MUST omit historical active_cwd"
        );
        assert_eq!(snap_strict.pending_tasks_count, 0);

        let resolver = ResourceResolver::new(&core, &tracker);
        let std_recall = resolver.resolve_at(
            t0 + Duration::seconds(7),
            "打开我之前说的那个文件",
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        assert_eq!(
            std_recall.as_single().and_then(|r| r.path.as_deref()),
            Some(note_file.as_path())
        );

        let strict_recall = resolver.resolve_at(
            t0 + Duration::seconds(7),
            "打开我之前说的那个文件",
            None,
            None,
            PrivacySessionPolicy::StrictIsolated,
        );
        assert!(
            strict_recall.is_unavailable(),
            "StrictIsolated must NOT leak memory_hub entities, got {:?}",
            strict_recall
        );
    }
}
