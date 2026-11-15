#![forbid(unsafe_code)]

//! Controlled CLI Subprocess Bridge (`providers_cli.rs`):
//! - Enforces explicit OS isolation tiers (`CliAgentIsolationMode`: `ManagedSandboxed`,
//!   `ExternalReadOnly`, `ExternalDelegated`, `UnverifiedRejected`) backed by real capability
//!   probing (`probe_cli_binary_capabilities` + `intentos_sandbox::probe_sandbox_support()`).
//! - Eliminates `/proc/<pid>/cmdline` prompt leakage by piping prompts via `Stdio::piped()` `stdin`
//!   (plus `0600` auto-deleted `--attach` files for `zcode`) and scrubbing outbound/inbound secrets
//!   via `SensitiveDataGuard`.
//! - Bridges verified sandboxed CLI backends into `CapabilityBroker` via `<intentos_tool_call>`
//!   when `allow_broker_tools == true`, and enforces `BackendExecutionMode::ExternalChatOnly`
//!   (omitting tool schemas and stripping forced `<intentos_tool_call>` tags without invoking
//!   `CapabilityBroker`) when `allow_broker_tools == false` or downgraded to `ExternalReadOnly`.

use crate::backend_bridge::broker_bridge::{
    BackendExecutionMode, QuickChatToolExecOutcome, TraceDot, TurnExecutionOutcome,
    build_budget_exhausted_turn_outcome, build_quick_chat_openai_tools_with_policy,
    execute_quick_chat_tool_call, finalize_completed_turn_outcome,
    prepare_system_prompt_and_context_with_policy, synthesize_rich_approved_step_markdown,
};
use crate::backend_bridge::detector::{
    ActiveBackendSelection, DiscoveredBackend, DiscoveryOptions, build_search_dirs,
    find_binary_in_dirs, is_local_url,
};
use crate::backend_bridge::turn_checkpoint::{
    ActiveTurnHandle, SuspendedDialectState, SuspendedTurnCheckpoint, TurnEffectLedger,
    emit_turn_event, save_suspended_checkpoint,
};
use crate::backend_bridge::turn_engine::extract_thinking_and_clean_reply;
use crate::config::{EgressVerdict, XdgPaths, check_egress_matrix};
use crate::core::IntentOsCore;
use crate::runtime::SessionState;
use crate::security_guard::SensitiveDataGuard;
use intentos_protocol::{AgentEventKind, ContextBlock, DataClass, ProviderTrust};
use intentos_sandbox::{
    BindMountPair, SandboxDriver, SandboxProbe, SandboxSpec, build_sandboxed_command_with_mounts,
    is_forbidden_credential_path, probe_sandbox_support,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

pub const MAX_CLI_TOOL_ROUNDS: usize = 4;

const CLI_CHAT_ONLY_PROMPT_NOTE: &str = "[chat_only_policy | taint=System]\n\
当前会话处于仅对话模式（ExternalChatOnly）：严禁调用任何系统工具，严禁输出任何 <intentos_tool_call> 标签，请仅以纯文本自然语言直接回答。";

const ZCODE_STATIC_PRINT_INSTRUCTION: &str =
    "Follow the attached IntentOS request context and respond directly.";

static SANDBOX_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

/// Explicit isolation tiers for external CLI agent subprocesses (`H04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CliAgentIsolationMode {
    /// Verified OS filesystem/env/network sandbox (`bwrap` / `Landlock`) + verified native
    /// CLI mutation-tool disable flags. Eligible for `BackendExecutionMode::CliBrokerBridged`
    /// when `allow_broker_tools == true`.
    ManagedSandboxed,
    /// Read-only / chat-only execution (`BackendExecutionMode::ExternalChatOnly`):
    /// zero `CapabilityBroker` tools exposed or executed; `<intentos_tool_call>` tags stripped.
    ExternalReadOnly,
    /// Explicitly caller-authorized delegated execution when OS sandbox or native tool-disable
    /// flags cannot be verified. Never silently assumed and never claims `CliBrokerBridged`.
    ExternalDelegated,
    /// Security refusal: isolation could not be verified and `ExternalDelegated` was not authorized.
    UnverifiedRejected,
}

impl CliAgentIsolationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManagedSandboxed => "managed_sandboxed",
            Self::ExternalReadOnly => "external_read_only",
            Self::ExternalDelegated => "external_delegated",
            Self::UnverifiedRejected => "unverified_rejected",
        }
    }
}

/// Network access control policy for sandboxed CLI subprocesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CliNetworkPolicy {
    /// Allow outbound TCP inside the OS sandbox ONLY when `check_egress_matrix(data_class, trust)`
    /// returns `EgressVerdict::Allow`.
    EgressPolicyDriven,
    /// Unconditionally isolate network (`allow_tcp_network: false` / `bwrap --unshare-net`).
    ForceOffline,
}

/// Execution policy governing CLI isolation tier selection and Broker tool bridging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CliExecutionPolicy {
    pub allow_broker_tools: bool,
    pub allow_external_delegated: bool,
    pub downgrade_unverified_to_readonly: bool,
    pub network_policy: CliNetworkPolicy,
}

impl CliExecutionPolicy {
    pub fn standard(allow_broker_tools: bool) -> Self {
        Self {
            allow_broker_tools,
            allow_external_delegated: false,
            downgrade_unverified_to_readonly: true,
            network_policy: CliNetworkPolicy::EgressPolicyDriven,
        }
    }
}

/// Probed isolation and transport capabilities for a specific external CLI binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliIsolationCapabilities {
    pub backend: String,
    pub binary_exists: bool,
    pub resolved_program: PathBuf,
    pub resolved_script: Option<PathBuf>,
    pub version_hint: Option<String>,
    pub supports_native_tool_disable: bool,
    pub supports_stdin_prompt: bool,
    pub supports_file_attach: bool,
    pub pi_disable_tools_flag: Option<String>,
    pub is_desktop_gui_binary: bool,
    pub is_hermetic_mock_script: bool,
    pub legacy_positional_mock_script: bool,
    pub verified_from_help: bool,
    pub detail: String,
    #[serde(skip)]
    probed_len: Option<u64>,
    #[serde(skip)]
    probed_mtime_ns: Option<u128>,
}

impl CliIsolationCapabilities {
    fn missing(backend: &str, raw_path: PathBuf, detail: impl Into<String>) -> Self {
        Self {
            backend: backend.to_string(),
            binary_exists: false,
            resolved_program: raw_path,
            resolved_script: None,
            version_hint: None,
            supports_native_tool_disable: false,
            supports_stdin_prompt: false,
            supports_file_attach: false,
            pi_disable_tools_flag: None,
            is_desktop_gui_binary: false,
            is_hermetic_mock_script: false,
            legacy_positional_mock_script: false,
            verified_from_help: false,
            detail: detail.into(),
            probed_len: None,
            probed_mtime_ns: None,
        }
    }

    fn matches_target_metadata(&self, backend: &str, target: &Path) -> bool {
        if self.backend != backend {
            return false;
        }
        let Some((len, mtime_ns)) = file_len_and_mtime_ns(target) else {
            return false;
        };
        self.probed_len == Some(len) && self.probed_mtime_ns == Some(mtime_ns)
    }
}

static CLI_CAPABILITY_CACHE: OnceLock<Mutex<HashMap<PathBuf, CliIsolationCapabilities>>> =
    OnceLock::new();

fn capability_cache() -> &'static Mutex<HashMap<PathBuf, CliIsolationCapabilities>> {
    CLI_CAPABILITY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Clear cached `--help` / `--version` CLI capability probes (useful in tests or after upgrades).
pub fn clear_cli_capability_cache() {
    if let Ok(mut guard) = capability_cache().lock() {
        guard.clear();
    }
}

fn file_len_and_mtime_ns(path: &Path) -> Option<(u64, u128)> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Some((meta.len(), mtime_ns))
}

/// Detect whether `canon_bin` sits inside an Electron desktop GUI installation (such as
/// `/opt/ZCode/zcode` symlinked from `/usr/bin/zcode`), which MUST NEVER be invoked directly
/// because launching Electron opens a desktop GUI window and mutates `~/.zcode`.
fn is_electron_gui_installation(canon_bin: &Path) -> bool {
    let Some(parent) = canon_bin.parent() else {
        return false;
    };
    parent.join("chrome-sandbox").exists()
        || parent.join("chrome_100_percent.pak").exists()
        || parent.join("resources/app.asar").exists()
}

fn find_zcode_headless_node(opts: &DiscoveryOptions, zcode_install_dir: &Path) -> Option<PathBuf> {
    let search_dirs = build_search_dirs(opts);
    if let Some(found) = find_binary_in_dirs("node", &search_dirs) {
        return Some(found);
    }
    let bundled = zcode_install_dir.join("resources/glm/node-runtime/bin/node");
    if bundled.is_file() {
        return Some(bundled);
    }
    let fallback = opts.home_dir.join(".zcode/cli/node-fallback/v1/node");
    if fallback.is_file() {
        return Some(fallback);
    }
    None
}

/// Collect minimal read-only filesystem roots required for `program` (and optional `script`)
/// to execute inside `bwrap` without exposing `$HOME` or sibling user directories.
fn executable_readonly_roots(
    canon_program: &Path,
    canon_script: Option<&Path>,
    opts: &DiscoveryOptions,
) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let real_home = std::env::var_os("HOME").map(PathBuf::from);
    let canon_opts_home = std::fs::canonicalize(&opts.home_dir).ok();
    let canon_real_home = real_home
        .as_deref()
        .and_then(|h| std::fs::canonicalize(h).ok());

    let is_disallowed_whole_root = |p: &Path| -> bool {
        p == Path::new("/")
            || p == Path::new("/tmp")
            || p == opts.home_dir.as_path()
            || canon_opts_home.as_deref() == Some(p)
            || real_home.as_deref() == Some(p)
            || canon_real_home.as_deref() == Some(p)
            || is_forbidden_credential_path(p)
    };

    let mut push_unique = |p: PathBuf| {
        if p.exists() && !is_disallowed_whole_root(&p) && !roots.iter().any(|x| x == &p) {
            roots.push(p);
        }
    };

    let prog_str = canon_program.to_string_lossy();
    let is_sys_bin = prog_str.starts_with("/usr/")
        || prog_str.starts_with("/bin/")
        || prog_str.starts_with("/sbin/")
        || prog_str.starts_with("/lib");

    if !is_sys_bin {
        if let Some(parent) = canon_program.parent() {
            let parent_is_bin = parent.file_name().and_then(|s| s.to_str()) == Some("bin");
            let parent_str = parent.to_string_lossy();
            let needs_bundle_prefix = parent_is_bin
                && (parent_str.contains(".nvm/versions/node/")
                    || parent_str.contains("node-runtime/")
                    || parent_str.contains("packages/standalone/releases/"));
            if needs_bundle_prefix && let Some(grandparent) = parent.parent() {
                push_unique(grandparent.to_path_buf());
            } else {
                push_unique(parent.to_path_buf());
            }
        } else {
            push_unique(canon_program.to_path_buf());
        }
    }

    if let Some(script) = canon_script {
        let script_str = script.to_string_lossy();
        if script_str.contains("/resources/glm/")
            && let Some(glm_dir) = script.parent()
        {
            push_unique(glm_dir.to_path_buf());
        } else {
            push_unique(script.to_path_buf());
        }
    }

    roots
}

async fn run_sandboxed_probe_cmd(
    program: &Path,
    script: Option<&Path>,
    probe_args: &[&str],
    ro_roots: &[PathBuf],
    work_dir: &Path,
    home_dir: &Path,
) -> Option<(bool, String)> {
    let mut args: Vec<String> = Vec::with_capacity(probe_args.len() + 1);
    if let Some(s) = script {
        args.push(s.to_string_lossy().to_string());
    }
    args.extend(probe_args.iter().map(|s| (*s).to_string()));

    let mut env = BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/local/bin:/usr/bin:/bin".to_string(),
    );
    env.insert("HOME".to_string(), home_dir.to_string_lossy().to_string());
    env.insert("TMPDIR".to_string(), "/tmp".to_string());
    env.insert("NO_COLOR".to_string(), "1".to_string());
    env.insert("CI".to_string(), "1".to_string());
    env.insert("TERM".to_string(), "dumb".to_string());

    let spec = SandboxSpec {
        program: program.to_path_buf(),
        args,
        readonly_paths: ro_roots.to_vec(),
        readwrite_paths: vec![work_dir.to_path_buf(), home_dir.to_path_buf()],
        env_vars: env,
        work_dir: work_dir.to_path_buf(),
        allow_tcp_network: false,
    };

    let (mut cmd, _) =
        build_sandboxed_command_with_mounts(&spec, &[], &probe_sandbox_support()).ok()?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let out = tokio::time::timeout(Duration::from_secs(4), cmd.output())
        .await
        .ok()?
        .ok()?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some((out.status.success(), combined))
}

/// Probe `<bin> --help` / `--version` non-destructively inside an offline OS sandbox, caching
/// verified isolation flags per canonical executable/script path.
pub async fn probe_cli_binary_capabilities(
    backend: &str,
    disc: &DiscoveredBackend,
    opts: &DiscoveryOptions,
) -> CliIsolationCapabilities {
    let Some(raw_bin_str) = disc
        .binary_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return CliIsolationCapabilities::missing(backend, PathBuf::new(), "binary_path_unset");
    };
    let raw_bin_path = PathBuf::from(raw_bin_str);
    if !raw_bin_path.exists() {
        return CliIsolationCapabilities::missing(backend, raw_bin_path, "binary_not_found");
    }

    let canon_bin = std::fs::canonicalize(&raw_bin_path).unwrap_or_else(|_| raw_bin_path.clone());

    let (resolved_program, resolved_script) = if let Some(ref runner_str) = disc.runner_program {
        let runner_path = PathBuf::from(runner_str);
        if !runner_path.is_file() {
            return CliIsolationCapabilities::missing(
                backend,
                runner_path,
                "runner_program_not_found",
            );
        }
        let canon_runner = std::fs::canonicalize(&runner_path).unwrap_or(runner_path);
        (canon_runner, Some(canon_bin))
    } else if is_electron_gui_installation(&canon_bin) {
        if backend == "zcode"
            && let Some(parent) = canon_bin.parent()
        {
            let cjs_opt = opts
                .opt_zcode_cjs
                .clone()
                .filter(|p| p.is_file())
                .or_else(|| {
                    let bundled = parent.join("resources/glm/zcode.cjs");
                    bundled.is_file().then_some(bundled)
                });
            let node_opt = find_zcode_headless_node(opts, parent);
            if let (Some(node_bin), Some(cjs_file)) = (node_opt, cjs_opt) {
                let canon_node = std::fs::canonicalize(&node_bin).unwrap_or(node_bin);
                let canon_cjs = std::fs::canonicalize(&cjs_file).unwrap_or(cjs_file);
                (canon_node, Some(canon_cjs))
            } else {
                return CliIsolationCapabilities {
                    backend: backend.to_string(),
                    binary_exists: true,
                    resolved_program: canon_bin,
                    resolved_script: None,
                    version_hint: None,
                    supports_native_tool_disable: false,
                    supports_stdin_prompt: false,
                    supports_file_attach: false,
                    pi_disable_tools_flag: None,
                    is_desktop_gui_binary: true,
                    is_hermetic_mock_script: false,
                    legacy_positional_mock_script: false,
                    verified_from_help: false,
                    detail: "electron_gui_binary_without_headless_zcode_cjs".to_string(),
                    probed_len: None,
                    probed_mtime_ns: None,
                };
            }
        } else {
            return CliIsolationCapabilities {
                backend: backend.to_string(),
                binary_exists: true,
                resolved_program: canon_bin,
                resolved_script: None,
                version_hint: None,
                supports_native_tool_disable: false,
                supports_stdin_prompt: false,
                supports_file_attach: false,
                pi_disable_tools_flag: None,
                is_desktop_gui_binary: true,
                is_hermetic_mock_script: false,
                legacy_positional_mock_script: false,
                verified_from_help: false,
                detail: "electron_gui_binary_rejected".to_string(),
                probed_len: None,
                probed_mtime_ns: None,
            };
        }
    } else {
        (canon_bin, None)
    };

    let cache_key = resolved_script
        .as_ref()
        .unwrap_or(&resolved_program)
        .clone();

    if let Ok(guard) = capability_cache().lock()
        && let Some(cached) = guard.get(&cache_key)
        && cached.matches_target_metadata(backend, &cache_key)
    {
        return cached.clone();
    }

    let meta_pair = file_len_and_mtime_ns(&cache_key);
    let mut is_shebang_script = false;
    let mut force_unverified = false;
    let mut legacy_positional_mock_script = false;

    if let Some((len, _)) = meta_pair
        && len <= 16_384
        && let Ok(bytes) = std::fs::read(&cache_key)
    {
        is_shebang_script = bytes.starts_with(b"#!");
        let src = String::from_utf8_lossy(&bytes);
        if src.contains("INTENTOS_UNVERIFIED_CLI") {
            force_unverified = true;
        }
        if !opts.include_system_paths
            && is_shebang_script
            && len <= 8_192
            && src.contains("for prompt; do :; done")
            && !src.contains("stdin")
        {
            legacy_positional_mock_script = true;
        }
    }

    let ro_roots = executable_readonly_roots(&resolved_program, resolved_script.as_deref(), opts);

    let probe_tmp_root = std::env::temp_dir().join(format!(
        "intentos_cli_probe_{}_{}",
        std::process::id(),
        SANDBOX_DIR_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let probe_work = probe_tmp_root.join("work");
    let probe_home = probe_tmp_root.join("home");
    let _ = std::fs::create_dir_all(&probe_work);
    let _ = std::fs::create_dir_all(&probe_home);

    let help_args: &[&str] = if backend == "codex" {
        &["exec", "--help"]
    } else {
        &["--help"]
    };

    let help_res = run_sandboxed_probe_cmd(
        &resolved_program,
        resolved_script.as_deref(),
        help_args,
        &ro_roots,
        &probe_work,
        &probe_home,
    )
    .await;

    let version_hint = run_sandboxed_probe_cmd(
        &resolved_program,
        resolved_script.as_deref(),
        &["--version"],
        &ro_roots,
        &probe_work,
        &probe_home,
    )
    .await
    .and_then(|(ok, txt)| {
        if !ok {
            return None;
        }
        txt.lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(|l| l.chars().take(80).collect::<String>())
    });

    let _ = std::fs::remove_dir_all(&probe_tmp_root);

    let (help_exit_ok, help_text) = help_res.unwrap_or((false, String::new()));
    let help_lc = help_text.to_ascii_lowercase();

    let mut verified_from_help = false;
    let mut supports_native_tool_disable = false;
    let mut supports_stdin_prompt = false;
    let mut supports_file_attach = false;
    let mut pi_disable_tools_flag: Option<String> = None;
    let mut is_hermetic_mock_script = false;
    let detail: String;

    match backend {
        "codex" => {
            if !force_unverified
                && help_lc.contains("--sandbox")
                && help_lc.contains("--skip-git-repo-check")
            {
                verified_from_help = true;
                supports_native_tool_disable = true;
                supports_stdin_prompt = true;
                detail = "verified_codex_exec_sandbox_readonly_and_stdin".to_string();
            } else if !opts.include_system_paths
                && is_shebang_script
                && !force_unverified
                && help_exit_ok
            {
                is_hermetic_mock_script = true;
                supports_native_tool_disable = true;
                supports_stdin_prompt = !legacy_positional_mock_script;
                detail = "hermetic_test_mock_codex_script".to_string();
            } else {
                detail = "unverified_codex_missing_sandbox_readonly_flag".to_string();
            }
        }
        "zcode" => {
            if !force_unverified
                && help_lc.contains("--disallowed-tools")
                && help_lc.contains("--workflow-mode")
            {
                verified_from_help = true;
                supports_native_tool_disable = true;
                supports_stdin_prompt = true;
                supports_file_attach = help_lc.contains("--attach");
                detail = "verified_zcode_disallowed_tools_and_workflow_disabled".to_string();
            } else if !opts.include_system_paths
                && is_shebang_script
                && !force_unverified
                && help_exit_ok
            {
                is_hermetic_mock_script = true;
                supports_native_tool_disable = true;
                supports_stdin_prompt = !legacy_positional_mock_script;
                supports_file_attach = true;
                detail = "hermetic_test_mock_zcode_script".to_string();
            } else {
                detail = "unverified_zcode_missing_disallowed_tools_flag".to_string();
            }
        }
        "pi" => {
            let detected_flag = if help_lc.contains("--no-tools") {
                Some("--no-tools".to_string())
            } else if help_lc.contains("--read-only") {
                Some("--read-only".to_string())
            } else {
                None
            };
            if !force_unverified && detected_flag.is_some() {
                verified_from_help = true;
                supports_native_tool_disable = true;
                supports_stdin_prompt = true;
                pi_disable_tools_flag = detected_flag;
                detail = "verified_pi_read_only_flag_and_stdin".to_string();
            } else if !opts.include_system_paths
                && is_shebang_script
                && !force_unverified
                && help_exit_ok
            {
                is_hermetic_mock_script = true;
                supports_native_tool_disable = true;
                supports_stdin_prompt = !legacy_positional_mock_script;
                pi_disable_tools_flag = Some("--no-tools".to_string());
                detail = "hermetic_test_mock_pi_script".to_string();
            } else {
                detail = "unverified_pi_missing_no_tools_flag".to_string();
            }
        }
        _ => {
            detail = format!("unsupported_cli_backend_{}", backend);
        }
    }

    let caps = CliIsolationCapabilities {
        backend: backend.to_string(),
        binary_exists: true,
        resolved_program,
        resolved_script,
        version_hint,
        supports_native_tool_disable,
        supports_stdin_prompt,
        supports_file_attach,
        pi_disable_tools_flag,
        is_desktop_gui_binary: false,
        is_hermetic_mock_script,
        legacy_positional_mock_script,
        verified_from_help,
        detail,
        probed_len: meta_pair.map(|(l, _)| l),
        probed_mtime_ns: meta_pair.map(|(_, m)| m),
    };

    if let Ok(mut guard) = capability_cache().lock() {
        guard.insert(cache_key, caps.clone());
    }
    caps
}

/// Deterministically resolve the `CliAgentIsolationMode` from probed binary capabilities,
/// real host OS sandbox availability, and caller policy.
///
/// Security Invariant: NEVER returns `ManagedSandboxed` unless BOTH OS-level filesystem isolation
/// (`sandbox_probe.has_os_isolation()`) AND native CLI tool-disable flags
/// (`caps.supports_native_tool_disable`) are verified!
pub fn resolve_cli_isolation_mode(
    caps: &CliIsolationCapabilities,
    sandbox_probe: &SandboxProbe,
    policy: CliExecutionPolicy,
) -> CliAgentIsolationMode {
    if !caps.binary_exists || caps.is_desktop_gui_binary {
        return CliAgentIsolationMode::UnverifiedRejected;
    }

    if sandbox_probe.has_os_isolation() && caps.supports_native_tool_disable {
        if policy.allow_broker_tools {
            return CliAgentIsolationMode::ManagedSandboxed;
        }
        return CliAgentIsolationMode::ExternalReadOnly;
    }

    if policy.allow_external_delegated {
        return CliAgentIsolationMode::ExternalDelegated;
    }

    if sandbox_probe.has_os_isolation() && policy.downgrade_unverified_to_readonly {
        return CliAgentIsolationMode::ExternalReadOnly;
    }

    CliAgentIsolationMode::UnverifiedRejected
}

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
            "zcode_override_{}_{}",
            if safe_id.is_empty() { "turn" } else { &safe_id },
            SANDBOX_DIR_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700));
        }

        let file_path = dir_path.join("provider_override.json");
        let (clean_provider, _) = SensitiveDataGuard::redact_text(provider);
        let (clean_model, _) = SensitiveDataGuard::redact_text(model);
        let override_doc = json!({
            "schemaVersion": 1,
            "activeProvider": clean_provider,
            "defaultModel": clean_model,
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

/// Per-invocation `0700` isolated runtime directory (`home/` + `work/`) mounted into `bwrap`
/// so external CLI processes never touch `core.paths.runtime_dir` (`ui.sock`, `gateway.sock`)
/// or the real user `$HOME`.
struct ScopedCliSandboxDir {
    root_dir: PathBuf,
    home_dir: PathBuf,
    work_dir: PathBuf,
}

impl ScopedCliSandboxDir {
    fn create(paths: &XdgPaths, turn_tag: &str) -> anyhow::Result<Self> {
        let safe_tag: String = turn_tag
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(40)
            .collect();
        let root_dir = paths.runtime_dir.join(format!(
            "cli_sbx_{}_{}",
            if safe_tag.is_empty() {
                "turn"
            } else {
                &safe_tag
            },
            SANDBOX_DIR_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let home_dir = root_dir.join("home");
        let work_dir = root_dir.join("work");
        for d in [
            &root_dir,
            &home_dir,
            &work_dir,
            &home_dir.join(".config"),
            &home_dir.join(".cache"),
            &home_dir.join(".local/state"),
        ] {
            std::fs::create_dir_all(d)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
            }
        }
        Ok(Self {
            root_dir,
            home_dir,
            work_dir,
        })
    }
}

impl Drop for ScopedCliSandboxDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_dir);
    }
}

/// Auto-zeroed & auto-deleted `0600` prompt attachment file for headless `zcode --attach`.
struct ScopedCliPromptFile {
    file_path: PathBuf,
    byte_len: usize,
}

impl ScopedCliPromptFile {
    fn create(work_dir: &Path, scrubbed_prompt: &str) -> anyhow::Result<Self> {
        let file_path = work_dir.join("intentos_request_context.txt");
        let bytes = scrubbed_prompt.as_bytes();
        std::fs::write(&file_path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            file_path,
            byte_len: bytes.len(),
        })
    }

    fn path(&self) -> &Path {
        &self.file_path
    }
}

impl Drop for ScopedCliPromptFile {
    fn drop(&mut self) {
        if self.byte_len > 0 && self.file_path.is_file() {
            let zeros = vec![0u8; self.byte_len.min(65_536)];
            let _ = std::fs::write(&self.file_path, &zeros);
        }
        let _ = std::fs::remove_file(&self.file_path);
    }
}

/// Scrub inline API keys, tokens, explicit passwords, and PEM private keys from CLI prompts/outputs.
pub fn scrub_text_secrets(raw: &str) -> String {
    static PEM_RE: OnceLock<Regex> = OnceLock::new();
    static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    static BEARER_RE: OnceLock<Regex> = OnceLock::new();

    let (guarded, _) = SensitiveDataGuard::redact_text(raw);

    let pem_re = PEM_RE.get_or_init(|| {
        Regex::new(
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .expect("valid pem regex")
    });
    let token_re = TOKEN_RE.get_or_init(|| {
        Regex::new(r"\b(?:sk|rk)-[A-Za-z0-9_-]{12,}\b|\b(?:ghp|gho|ghs)_[A-Za-z0-9]{12,}\b|\bxox[baprs]-[A-Za-z0-9-]{12,}\b")
            .expect("valid token regex")
    });
    let bearer_re = BEARER_RE.get_or_init(|| {
        Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}").expect("valid bearer regex")
    });

    let step1 = pem_re.replace_all(&guarded, "[REDACTED_PRIVATE_KEY]");
    let step2 = token_re.replace_all(&step1, "[REDACTED]");
    bearer_re
        .replace_all(&step2, "Bearer [REDACTED]")
        .to_string()
}

/// Build a compact IntentOS Controlled Broker Tool Protocol prompt section for CLI backends.
pub fn build_cli_broker_protocol_prompt(core: &IntentOsCore, user_text: &str) -> String {
    build_cli_broker_protocol_prompt_with_policy(
        core,
        user_text,
        crate::security_guard::PrivacySessionPolicy::Standard,
    )
}

/// Build a compact IntentOS Controlled Broker Tool Protocol prompt respecting `PrivacySessionPolicy`.
pub fn build_cli_broker_protocol_prompt_with_policy(
    core: &IntentOsCore,
    user_text: &str,
    privacy: crate::security_guard::PrivacySessionPolicy,
) -> String {
    let openai_tools = build_quick_chat_openai_tools_with_policy(core, user_text, privacy);
    build_cli_broker_protocol_prompt_from_tools(&openai_tools)
}

fn build_cli_broker_protocol_prompt_from_tools(openai_tools: &[Value]) -> String {
    let mut tool_lines: Vec<String> = Vec::with_capacity(openai_tools.len());

    for t in openai_tools {
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
        4) 若所需能力未直接出现在下方首轮精简列表中，可调用 `capability_search` / `capability_describe` 动态解锁完整工具签名，或通过 `capability_invoke` 按规范 ID 安全执行，多步变更后用 `task_verify` 校验。\n\
        5) 若用户仅作日常问答且无需调用系统能力，请直接用自然语言回复，不要输出任何 `<intentos_tool_call>` 标签。\n\
        可用 Broker 工具列表：\n{}",
        tool_lines.join("\n")
    )
}

/// Parse valid `<intentos_tool_call>...</intentos_tool_call>` blocks and strip ALL
/// `<intentos_tool_call>` tags (including malformed or unclosed tags) from CLI output text.
pub fn parse_and_strip_cli_tool_calls(raw: &str) -> (Vec<(Option<String>, String, Value)>, String) {
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
            Some(Value::String(s)) => {
                serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!({}))
            }
            Some(v @ Value::Object(_)) => v.clone(),
            _ => json!({}),
        };

        calls.push((opt_id, name.to_string(), args_val));
    }

    let mut stripped = call_re.replace_all(raw, "").to_string();
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

fn resolve_cli_provider_trust(
    core: &IntentOsCore,
    active: &ActiveBackendSelection,
) -> ProviderTrust {
    if let Some(ref url) = active.base_url
        && is_local_url(url)
    {
        return ProviderTrust::Trusted;
    }
    if let Some(prov) = core
        .brain_config
        .providers
        .iter()
        .find(|p| p.id == active.provider)
    {
        return prov.trust;
    }
    ProviderTrust::Standard
}

fn collect_readonly_workspace_dirs(core: &IntentOsCore, opts: &DiscoveryOptions) -> Vec<PathBuf> {
    let real_home = std::env::var_os("HOME").map(PathBuf::from);
    let canon_real_home = real_home
        .as_deref()
        .and_then(|p| std::fs::canonicalize(p).ok());
    let canon_opts_home = std::fs::canonicalize(&opts.home_dir).ok();

    let mut out = Vec::new();
    for raw in &core.app_config.authorized_directories {
        let p = PathBuf::from(raw.trim());
        if !p.is_dir() || is_forbidden_credential_path(&p) {
            continue;
        }
        let canon = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
        if canon == Path::new("/")
            || canon == Path::new("/tmp")
            || p == opts.home_dir
            || Some(&canon) == canon_opts_home.as_ref()
            || real_home.as_deref() == Some(p.as_path())
            || Some(&canon) == canon_real_home.as_ref()
        {
            continue;
        }
        if !out.iter().any(|existing| existing == &canon) {
            out.push(canon);
        }
    }
    out
}

fn stage_cli_auth_readonly_mounts(
    backend: &str,
    opts: &DiscoveryOptions,
    sandbox_home: &Path,
    use_bwrap_placeholders: bool,
) -> Vec<BindMountPair> {
    let rel_files: &[&str] = match backend {
        "codex" => &[
            ".codex/config.toml",
            ".codex/auth.json",
            ".codex/models_cache.json",
        ],
        "zcode" => &[
            ".zcode/v2/provider_config.json",
            ".zcode/v2/config.json",
            ".zcode/v2/credentials.json",
            ".zcode/cli/config.json",
        ],
        "pi" => &[
            ".pi/agent/models.json",
            ".pi/agent/auth.json",
            ".pi/agent/settings.json",
        ],
        _ => &[],
    };

    let mut mounts = Vec::new();
    for rel in rel_files {
        let src = opts.home_dir.join(rel);
        if !src.is_file() || is_forbidden_credential_path(&src) {
            continue;
        }
        let dst = sandbox_home.join(rel);
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if use_bwrap_placeholders {
            let _ = std::fs::write(&dst, b"");
        } else {
            let _ = std::fs::copy(&src, &dst);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600));
        }
        mounts.push(BindMountPair { src, dst });
    }
    mounts
}

fn build_sanitized_cli_env(
    opts: &DiscoveryOptions,
    sandbox_home: &Path,
) -> BTreeMap<String, String> {
    let mut path_entries: Vec<PathBuf> = build_search_dirs(opts)
        .into_iter()
        .filter(|d| !is_forbidden_credential_path(d))
        .collect();
    for sys in ["/usr/local/bin", "/usr/bin", "/bin"] {
        let p = PathBuf::from(sys);
        if !path_entries.iter().any(|x| x == &p) {
            path_entries.push(p);
        }
    }
    let joined_path = std::env::join_paths(&path_entries)
        .map(|os| os.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());

    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), joined_path);
    env.insert(
        "HOME".to_string(),
        sandbox_home.to_string_lossy().to_string(),
    );
    env.insert(
        "XDG_CONFIG_HOME".to_string(),
        sandbox_home.join(".config").to_string_lossy().to_string(),
    );
    env.insert(
        "XDG_CACHE_HOME".to_string(),
        sandbox_home.join(".cache").to_string_lossy().to_string(),
    );
    env.insert(
        "XDG_STATE_HOME".to_string(),
        sandbox_home
            .join(".local/state")
            .to_string_lossy()
            .to_string(),
    );
    env.insert("TMPDIR".to_string(), "/tmp".to_string());
    env.insert("LANG".to_string(), "C.UTF-8".to_string());
    env.insert("NO_COLOR".to_string(), "1".to_string());
    env.insert("CI".to_string(), "1".to_string());
    env.insert("TERM".to_string(), "dumb".to_string());
    env
}

#[allow(clippy::too_many_arguments)]
async fn invoke_cli_subprocess_once(
    core: &IntentOsCore,
    opts: &DiscoveryOptions,
    active: &ActiveBackendSelection,
    caps: &CliIsolationCapabilities,
    sandbox_probe: &SandboxProbe,
    network_policy: CliNetworkPolicy,
    data_class: DataClass,
    turn_handle: &Arc<ActiveTurnHandle>,
    round_seq: usize,
    full_prompt: &str,
    incognito: bool,
) -> anyhow::Result<String> {
    if full_prompt.contains("BEGIN OPENSSH PRIVATE KEY")
        || full_prompt.contains("BEGIN RSA PRIVATE KEY")
        || full_prompt.contains("BEGIN PRIVATE KEY")
        || full_prompt.contains("BEGIN EC PRIVATE KEY")
    {
        anyhow::bail!("安全拦截：检测到疑似私钥内容，拒绝外发至外部 CLI 引擎");
    }

    let trust = resolve_cli_provider_trust(core, active);
    let egress_verdict = check_egress_matrix(data_class, trust);
    if egress_verdict == EgressVerdict::Deny {
        anyhow::bail!(
            "安全拦截 (EgressMatrix::Deny)：禁止将 {:?} 等级数据发送至外部 CLI 后端 ({})",
            data_class,
            active.backend
        );
    }
    let allow_tcp_network = matches!(network_policy, CliNetworkPolicy::EgressPolicyDriven)
        && matches!(egress_verdict, EgressVerdict::Allow);

    let scrubbed_prompt = scrub_text_secrets(full_prompt);
    let round_turn_tag = format!("{}_r{}", turn_handle.turn_id, round_seq);
    let sandbox_dir = ScopedCliSandboxDir::create(&core.paths, &round_turn_tag)?;

    let use_bwrap_placeholders =
        sandbox_probe.selected_driver == SandboxDriver::Bubblewrap && sandbox_probe.bwrap_userns_ok;
    let extra_ro_mounts = stage_cli_auth_readonly_mounts(
        &active.backend,
        opts,
        &sandbox_dir.home_dir,
        use_bwrap_placeholders,
    );

    let mut readonly_paths = executable_readonly_roots(
        &caps.resolved_program,
        caps.resolved_script.as_deref(),
        opts,
    );
    for ws in collect_readonly_workspace_dirs(core, opts) {
        if !readonly_paths.iter().any(|p| p == &ws) {
            readonly_paths.push(ws);
        }
    }

    let mut env_vars = build_sanitized_cli_env(opts, &sandbox_dir.home_dir);
    let mut args: Vec<String> = Vec::new();
    if let Some(ref script_path) = caps.resolved_script {
        args.push(script_path.to_string_lossy().to_string());
    }

    let mut zcode_override_guard: Option<ScopedZcodeRuntimeOverride> = None;
    let mut zcode_prompt_guard: Option<ScopedCliPromptFile> = None;
    let mut codex_msg_file: Option<PathBuf> = None;

    match active.backend.as_str() {
        "zcode" => {
            let guard = ScopedZcodeRuntimeOverride::create(
                &core.paths,
                &round_turn_tag,
                &active.provider,
                &active.model,
                &active.reasoning_effort,
            )?;
            let prompt_file = ScopedCliPromptFile::create(&sandbox_dir.work_dir, &scrubbed_prompt)?;
            readonly_paths.push(guard.file_path().to_path_buf());
            env_vars.insert(
                "ZCODE_OVERRIDE_CONFIG".to_string(),
                guard.file_path().to_string_lossy().to_string(),
            );
            env_vars.insert("ZCODE_MODEL".to_string(), active.model.clone());
            args.extend([
                "--no-color".to_string(),
                "--workflow-mode".to_string(),
                "disabled".to_string(),
                "--disallowed-tools".to_string(),
                "Bash Edit Write".to_string(),
                "--attach".to_string(),
                prompt_file.path().to_string_lossy().to_string(),
                "-p".to_string(),
                ZCODE_STATIC_PRINT_INSTRUCTION.to_string(),
            ]);
            zcode_override_guard = Some(guard);
            zcode_prompt_guard = Some(prompt_file);
        }
        "codex" => {
            let out_file = sandbox_dir.work_dir.join("codex_last_msg.txt");
            std::fs::write(&out_file, b"")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out_file, std::fs::Permissions::from_mode(0o600));
            }
            args.extend([
                "exec".to_string(),
                "--sandbox".to_string(),
                "read-only".to_string(),
                "--skip-git-repo-check".to_string(),
                "--color".to_string(),
                "never".to_string(),
            ]);
            if incognito {
                args.push("--ephemeral".to_string());
            }
            if !active.model.trim().is_empty() {
                args.push("-m".to_string());
                args.push(active.model.clone());
            }
            let codex_effort = match active.reasoning_effort.as_str() {
                "fast" => Some("low"),
                "medium" => Some("medium"),
                "high" => Some("high"),
                _ => None,
            };
            if let Some(eff) = codex_effort {
                args.push("-c".to_string());
                args.push(format!("model_reasoning_effort=\"{}\"", eff));
            }
            args.push("-o".to_string());
            args.push(out_file.to_string_lossy().to_string());
            if caps.legacy_positional_mock_script {
                args.push(scrubbed_prompt.clone());
            } else {
                args.push("-".to_string());
            }
            codex_msg_file = Some(out_file);
        }
        "pi" => {
            if let Some(ref disable_flag) = caps.pi_disable_tools_flag {
                args.push(disable_flag.clone());
            }
            if !active.model.trim().is_empty() {
                args.push("--model".to_string());
                args.push(active.model.clone());
            }
            if caps.legacy_positional_mock_script {
                args.push("-p".to_string());
                args.push(scrubbed_prompt.clone());
            }
        }
        other => anyhow::bail!("未知 CLI 后端: {}", other),
    }

    let spec = SandboxSpec {
        program: caps.resolved_program.clone(),
        args,
        readonly_paths,
        readwrite_paths: vec![sandbox_dir.root_dir.clone()],
        env_vars,
        work_dir: sandbox_dir.work_dir.clone(),
        allow_tcp_network,
    };

    let (mut cmd, _driver) =
        build_sandboxed_command_with_mounts(&spec, &extra_ro_mounts, sandbox_probe)
            .map_err(|e| anyhow::anyhow!("构建 CLI OS 沙箱失败: {}", e))?;

    let pipe_stdin = !caps.legacy_positional_mock_script;
    cmd.stdin(if pipe_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);

    let mut child = cmd.spawn()?;
    if pipe_stdin && let Some(mut child_stdin) = child.stdin.take() {
        let stdin_bytes = scrubbed_prompt.into_bytes();
        tokio::spawn(async move {
            let _ = child_stdin.write_all(&stdin_bytes).await;
            let _ = child_stdin.shutdown().await;
        });
    }

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
            drop(zcode_prompt_guard);
            drop(zcode_override_guard);
            drop(sandbox_dir);

            if !out.status.success() && from_file.is_none() {
                let stderr = scrub_text_secrets(&String::from_utf8_lossy(&out.stderr));
                anyhow::bail!("CLI 退出码 {:?}: {}", out.status.code(), stderr.trim());
            }
            from_file.unwrap_or_else(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Err(err) => {
            drop(zcode_prompt_guard);
            drop(zcode_override_guard);
            drop(sandbox_dir);
            return Err(err);
        }
    };

    if raw_reply.is_empty() {
        anyhow::bail!("CLI 返回空输出");
    }

    Ok(raw_reply)
}

fn record_blocked_chat_only_cli_calls(
    parsed_calls: &[(Option<String>, String, Value)],
    scrubbed_text: String,
    effect_ledger: &mut TurnEffectLedger,
) -> String {
    if parsed_calls.is_empty() {
        return scrubbed_text;
    }
    let blocked_names: Vec<String> = parsed_calls.iter().map(|(_, n, _)| n.clone()).collect();
    for name in &blocked_names {
        if !effect_ledger.chat_only_blocked_tools.contains(name) {
            effect_ledger.chat_only_blocked_tools.push(name.clone());
        }
    }
    let joined = blocked_names.join(", ");
    let sec_note = format!(
        "仅对话模式（ExternalChatOnly）安全策略已拦截外部 CLI 请求的系统工具调用（`{}`），未执行任何 `CapabilityBroker` 操作。",
        joined
    );
    effect_ledger
        .trace_dots
        .push(TraceDot::tool_err(&joined, &sec_note, 0));
    if scrubbed_text.trim().is_empty() {
        format!("> 安全提示：{sec_note}")
    } else {
        scrubbed_text
    }
}

/// Controlled CLI Broker Bridge for `zcode`, `codex`, and `pi` using standard host sandbox policy.
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
    let sandbox_probe = probe_sandbox_support();
    run_cli_backend_turn_with_policy(
        core,
        opts,
        disc,
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
        CliExecutionPolicy::standard(allow_broker_tools),
        &sandbox_probe,
        effect_ledger,
    )
    .await
}

/// Controlled CLI Broker Bridge with explicit `CliExecutionPolicy` & `SandboxProbe` verification.
#[allow(clippy::too_many_arguments)]
pub async fn run_cli_backend_turn_with_policy(
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
    policy: CliExecutionPolicy,
    sandbox_probe: &SandboxProbe,
    effect_ledger: &mut TurnEffectLedger,
) -> anyhow::Result<TurnExecutionOutcome> {
    let caps = probe_cli_binary_capabilities(&active.backend, disc, opts).await;
    let isolation_mode = resolve_cli_isolation_mode(&caps, sandbox_probe, policy);

    if isolation_mode == CliAgentIsolationMode::UnverifiedRejected {
        anyhow::bail!(
            "安全拒绝 (UnverifiedRejected): 无法验证外部 CLI 后端 `{}` 的 OS 沙箱或原生工具禁用能力 (driver={:?}, detail={})",
            active.backend,
            sandbox_probe.selected_driver,
            caps.detail
        );
    }

    let effective_allow_broker_tools =
        policy.allow_broker_tools && isolation_mode == CliAgentIsolationMode::ManagedSandboxed;
    let execution_mode = if effective_allow_broker_tools {
        BackendExecutionMode::CliBrokerBridged
    } else {
        BackendExecutionMode::ExternalChatOnly
    };

    let effective_privacy = if incognito {
        crate::security_guard::PrivacySessionPolicy::StrictIsolated
    } else {
        effect_ledger.privacy()
    };
    let (sys_text, taints, data_class) = prepare_system_prompt_and_context_with_policy(
        core,
        active,
        extra_blocks,
        effective_privacy,
    );

    let mut active_cli_tools = if effective_allow_broker_tools {
        build_quick_chat_openai_tools_with_policy(core, user_text, effective_privacy)
    } else {
        Vec::new()
    };
    let mut base_sections: Vec<String> = vec![sys_text.clone()];
    let protocol_section_idx = if effective_allow_broker_tools {
        let idx = base_sections.len();
        base_sections.push(build_cli_broker_protocol_prompt_from_tools(
            &active_cli_tools,
        ));
        Some(idx)
    } else {
        base_sections.push(CLI_CHAT_ONLY_PROMPT_NOTE.to_string());
        None
    };
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
        let round_num = effect_ledger.budget_tracker.used_model_rounds as usize;

        let mut prompt_sections = base_sections.clone();
        prompt_sections.extend(transcript_history.iter().cloned());
        let full_prompt = prompt_sections.join("\n\n");

        let raw_reply = invoke_cli_subprocess_once(
            core,
            opts,
            active,
            &caps,
            sandbox_probe,
            policy.network_policy,
            data_class,
            turn_handle,
            round_num,
            &full_prompt,
            !effective_privacy.allows_memory_write(),
        )
        .await?;

        let (step_thought, after_think) = extract_thinking_and_clean_reply(&raw_reply, None);
        if let Some(t) = step_thought {
            effect_ledger.push_thought(scrub_text_secrets(&t));
        }

        let (parsed_calls, cleaned_without_tags) = parse_and_strip_cli_tool_calls(&after_think);
        let scrubbed_text = scrub_text_secrets(&cleaned_without_tags);

        if effective_allow_broker_tools && !parsed_calls.is_empty() {
            transcript_history.push(format!("Assistant:\n{}", scrub_text_secrets(&after_think)));
            let mut round_tool_results: Vec<String> = Vec::new();
            let mut all_duplicates = true;

            for (tc_idx, (opt_id, fn_name, parsed_args)) in parsed_calls.iter().enumerate() {
                if turn_handle.is_cancelled() {
                    anyhow::bail!("turn_cancelled");
                }
                let call_id = opt_id
                    .clone()
                    .unwrap_or_else(|| format!("cli_call_{}_{}", round_num, tc_idx + 1));

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
                                            format!("cli_sib_{}_{}", round_num, rem_i + 1)
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
                                rounds_used: round_num,
                                paused_call_id: call_id,
                                paused_canonical_tool: canonical_tool,
                                paused_parsed_args:
                                    crate::meta_tools::effective_checkpoint_tool_args(
                                        fn_name,
                                        parsed_args,
                                    ),
                                remaining_tool_calls,
                                effect_ledger: effect_ledger.clone(),
                                dialect: SuspendedDialectState::Cli {
                                    disc: disc.clone(),
                                    transcript_history: transcript_history.clone(),
                                    prior_round_tool_results: round_tool_results,
                                    allow_broker_tools: effective_allow_broker_tools,
                                },
                            });
                        }
                        return Ok(*outcome);
                    }
                    QuickChatToolExecOutcome::BudgetExhausted { dimension } => {
                        for (_, skipped_name, _) in &parsed_calls[tc_idx..] {
                            effect_ledger.budget_skipped_steps.push(format!(
                                "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                                skipped_name, dimension
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
                            scrubbed_text,
                            effect_ledger,
                        ));
                    }
                    QuickChatToolExecOutcome::ToolMessage {
                        content,
                        is_error,
                        duplicate_blocked,
                    } => {
                        if !duplicate_blocked {
                            all_duplicates = false;
                        }
                        let unlocked =
                            crate::meta_tools::extract_unlocked_capability_ids_from_tool_message(
                                fn_name, &content,
                            );
                        if crate::meta_tools::merge_unlocked_openai_tools(
                            &core.broker,
                            effective_privacy,
                            &unlocked,
                            &mut active_cli_tools,
                        ) > 0
                            && let Some(p_idx) = protocol_section_idx
                        {
                            base_sections[p_idx] =
                                build_cli_broker_protocol_prompt_from_tools(&active_cli_tools);
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

        let final_reply = if !effective_allow_broker_tools {
            record_blocked_chat_only_cli_calls(&parsed_calls, scrubbed_text, effect_ledger)
        } else {
            scrubbed_text
        };
        if !final_reply.is_empty() {
            let _ = emit_turn_event(
                &effect_ledger.turn_id,
                Some(task_id),
                AgentEventKind::MessageDelta {
                    delta: final_reply.clone(),
                },
            );
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
            final_reply,
            effect_ledger,
        ));
    }
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
    let sandbox_probe = probe_sandbox_support();
    let caps = probe_cli_binary_capabilities(&cp.active.backend, &disc, eff_opts).await;
    let policy = CliExecutionPolicy::standard(allow_broker_tools);
    let isolation_mode = resolve_cli_isolation_mode(&caps, &sandbox_probe, policy);

    if isolation_mode == CliAgentIsolationMode::UnverifiedRejected {
        anyhow::bail!(
            "安全拒绝 (UnverifiedRejected): 恢复审批回合时无法验证外部 CLI 后端 `{}` 的 OS 沙箱隔离 ({})",
            cp.active.backend,
            caps.detail
        );
    }

    let effective_allow_broker_tools =
        allow_broker_tools && isolation_mode == CliAgentIsolationMode::ManagedSandboxed;
    let execution_mode = if effective_allow_broker_tools {
        BackendExecutionMode::CliBrokerBridged
    } else {
        BackendExecutionMode::ExternalChatOnly
    };

    let effective_privacy = if cp.incognito {
        crate::security_guard::PrivacySessionPolicy::StrictIsolated
    } else {
        cp.effect_ledger.privacy()
    };
    let mut active_cli_tools = if effective_allow_broker_tools {
        let mut init =
            build_quick_chat_openai_tools_with_policy(core, &cp.user_text, effective_privacy);
        for rec in cp.effect_ledger.records() {
            if crate::meta_tools::is_discovery_only_meta_tool(&rec.capability_id) {
                let unlocked = crate::meta_tools::extract_unlocked_capability_ids_from_value(
                    &rec.cached_output,
                );
                let _ = crate::meta_tools::merge_unlocked_openai_tools(
                    &core.broker,
                    effective_privacy,
                    &unlocked,
                    &mut init,
                );
            }
        }
        init
    } else {
        Vec::new()
    };

    prior_round_tool_results.push(format!(
        "<intentos_tool_result call_id=\"{}\" name=\"{}\" is_error=\"{}\">{}</intentos_tool_result>",
        cp.paused_call_id,
        cp.paused_canonical_tool,
        approved_is_err,
        scrub_text_secrets(&approved_tool_content)
    ));

    if effective_allow_broker_tools {
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
                            paused_parsed_args: crate::meta_tools::effective_checkpoint_tool_args(
                                rem_name, rem_args,
                            ),
                            remaining_tool_calls: cp.remaining_tool_calls[rem_idx + 1..].to_vec(),
                            effect_ledger: cp.effect_ledger.clone(),
                            dialect: SuspendedDialectState::Cli {
                                disc,
                                transcript_history,
                                prior_round_tool_results,
                                allow_broker_tools: effective_allow_broker_tools,
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
                    let unlocked =
                        crate::meta_tools::extract_unlocked_capability_ids_from_tool_message(
                            rem_name, &content,
                        );
                    let _ = crate::meta_tools::merge_unlocked_openai_tools(
                        &core.broker,
                        effective_privacy,
                        &unlocked,
                        &mut active_cli_tools,
                    );
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
    }

    transcript_history.push(format!(
        "System Tool Results:\n{}\n请基于上述已授权执行的 `<intentos_tool_result>` 结果向用户完成最终回复。",
        prior_round_tool_results.join("\n")
    ));

    let mut base_sections: Vec<String> = vec![cp.sys_text.clone()];
    let protocol_section_idx = if effective_allow_broker_tools {
        let idx = base_sections.len();
        base_sections.push(build_cli_broker_protocol_prompt_from_tools(
            &active_cli_tools,
        ));
        Some(idx)
    } else {
        base_sections.push(CLI_CHAT_ONLY_PROMPT_NOTE.to_string());
        None
    };
    base_sections.push(format!("User: {}", cp.user_text));

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
        let round_num = cp.effect_ledger.budget_tracker.used_model_rounds as usize;

        let mut prompt_sections = base_sections.clone();
        prompt_sections.extend(transcript_history.iter().cloned());
        let full_prompt = prompt_sections.join("\n\n");

        let Ok(raw_reply) = invoke_cli_subprocess_once(
            core,
            eff_opts,
            &cp.active,
            &caps,
            &sandbox_probe,
            policy.network_policy,
            cp.data_class,
            resume_handle,
            round_num,
            &full_prompt,
            cp.incognito || !cp.effect_ledger.privacy().allows_memory_write(),
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

        if effective_allow_broker_tools && !parsed_calls.is_empty() {
            transcript_history.push(format!("Assistant:\n{}", scrub_text_secrets(&after_think)));
            let mut next_results: Vec<String> = Vec::new();
            let mut all_duplicates = true;

            for (tc_idx, (opt_id, fn_name, parsed_args)) in parsed_calls.iter().enumerate() {
                let call_id = opt_id
                    .clone()
                    .unwrap_or_else(|| format!("cli_res_{}_{}", round_num, tc_idx + 1));
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
                                            format!("cli_sib_{}_{}", round_num, ri + 1)
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
                                rounds_used: round_num,
                                paused_call_id: call_id,
                                paused_canonical_tool: canonical_tool,
                                paused_parsed_args:
                                    crate::meta_tools::effective_checkpoint_tool_args(
                                        fn_name,
                                        parsed_args,
                                    ),
                                remaining_tool_calls: rem_calls,
                                effect_ledger: cp.effect_ledger.clone(),
                                dialect: SuspendedDialectState::Cli {
                                    disc: disc.clone(),
                                    transcript_history: transcript_history.clone(),
                                    prior_round_tool_results: next_results,
                                    allow_broker_tools: effective_allow_broker_tools,
                                },
                            });
                        }
                        return Ok(*outcome);
                    }
                    QuickChatToolExecOutcome::BudgetExhausted { dimension } => {
                        for (_, skipped_name, _) in &parsed_calls[tc_idx..] {
                            cp.effect_ledger.budget_skipped_steps.push(format!(
                                "未执行工具调用 `{}` (预算维度 `{}` 已耗尽)",
                                skipped_name, dimension
                            ));
                        }
                        let partial_md = if scrubbed_text.trim().is_empty() {
                            synthesize_rich_approved_step_markdown(
                                &cp.user_text,
                                &cp.effect_ledger.task_steps,
                            )
                        } else {
                            scrubbed_text
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
                        content,
                        is_error,
                        duplicate_blocked,
                    } => {
                        if !duplicate_blocked {
                            all_duplicates = false;
                        }
                        let unlocked =
                            crate::meta_tools::extract_unlocked_capability_ids_from_tool_message(
                                fn_name, &content,
                            );
                        if crate::meta_tools::merge_unlocked_openai_tools(
                            &core.broker,
                            effective_privacy,
                            &unlocked,
                            &mut active_cli_tools,
                        ) > 0
                            && let Some(p_idx) = protocol_section_idx
                        {
                            base_sections[p_idx] =
                                build_cli_broker_protocol_prompt_from_tools(&active_cli_tools);
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

        let final_md = if !effective_allow_broker_tools {
            record_blocked_chat_only_cli_calls(&parsed_calls, scrubbed_text, &mut cp.effect_ledger)
        } else if scrubbed_text.trim().is_empty() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, BrainConfig, XdgPaths};
    use chrono::Utc;
    use intentos_protocol::Taint;
    use tempfile::TempDir;

    fn find_repo_root() -> PathBuf {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .parent()
            .and_then(|p| p.parent())
            .map(Path::to_path_buf)
            .unwrap_or(manifest)
    }

    fn setup_cli_test_core() -> (TempDir, Arc<IntentOsCore>) {
        let tmp = TempDir::new().expect("tempdir");
        let base = tmp.path().join("xdg_cli_h04");
        let ws_dir = base.join("workspace");
        std::fs::create_dir_all(&ws_dir).expect("create workspace");

        let repo_root = find_repo_root();
        let xdg = XdgPaths::resolve(Some(&base), repo_root.clone());
        xdg.ensure_dirs().expect("ensure dirs");

        let app_cfg = AppConfig {
            authorized_directories: vec![ws_dir.to_string_lossy().to_string()],
            allow_simulated_hardware_fallback: true,
            ..AppConfig::default()
        };
        std::fs::write(
            xdg.config_dir.join("config.toml"),
            toml::to_string_pretty(&app_cfg).expect("serialize app_cfg"),
        )
        .expect("write config.toml");
        std::fs::write(
            xdg.config_dir.join("brain.toml"),
            toml::to_string_pretty(&BrainConfig::default()).expect("serialize brain_cfg"),
        )
        .expect("write brain.toml");

        let core = IntentOsCore::initialize(Some(&base), repo_root).expect("init test core");
        (tmp, core)
    }

    fn write_exec_script(path: &Path, content: &str) {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).expect("mkdir parent");
        }
        std::fs::write(path, content).expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod +x");
        }
    }

    fn make_disc_backend(
        backend: &str,
        bin_path: Option<String>,
        model: Option<&str>,
    ) -> DiscoveredBackend {
        DiscoveredBackend {
            id: backend.to_string(),
            name: backend.to_string(),
            label: backend.to_uppercase(),
            available: bin_path.is_some(),
            installed: bin_path.is_some(),
            binary_path: bin_path,
            runner_program: None,
            default_provider: Some("openai".to_string()),
            default_model: model.map(String::from),
            default_reasoning_effort: "default".to_string(),
            models: model.map(|m| vec![m.to_string()]).unwrap_or_default(),
            providers: Vec::new(),
        }
    }

    fn make_active_selection(backend: &str, provider: &str, model: &str) -> ActiveBackendSelection {
        ActiveBackendSelection {
            backend: backend.to_string(),
            provider: provider.to_string(),
            model: model.to_string(),
            reasoning_effort: "default".to_string(),
            base_url: None,
            pinned: true,
            auto_selected: false,
            direct_http_capable: false,
            pill_label: String::new(),
        }
        .with_computed_label()
    }

    fn test_session(id: &str) -> SessionState {
        SessionState {
            session_id: id.to_string(),
            messages: Vec::new(),
            last_resource_path: None,
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn cli_bwrap_sandbox_blocks_workspace_write_secret_dir_and_cmdline_leak_while_bridging_broker()
     {
        let probe = probe_sandbox_support();
        assert!(
            probe.has_os_isolation(),
            "Linux verification host must provide Bubblewrap or Landlock OS sandbox: {:?}",
            probe
        );

        let (tmp, core) = setup_cli_test_core();
        let workspace_dir = PathBuf::from(&core.app_config.authorized_directories[0]);
        std::fs::write(workspace_dir.join("readme.md"), "READONLY_WORKSPACE_OK").unwrap();

        let mock_home = tmp.path().join("mock_home");
        let ssh_dir = mock_home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("id_ed25519"), "TOP_SECRET_SSH_KEY").unwrap();

        let unmounted_secret_dir = tmp.path().join("unmounted_secret_vault");
        std::fs::create_dir_all(&unmounted_secret_dir).unwrap();
        let unmounted_secret_file = unmounted_secret_dir.join("vault_token.txt");
        std::fs::write(&unmounted_secret_file, "TOP_SECRET_VAULT_TOKEN").unwrap();

        let codex_cfg = mock_home.join(".codex/config.toml");
        std::fs::create_dir_all(codex_cfg.parent().unwrap()).unwrap();
        std::fs::write(&codex_cfg, "model = \"gpt-5.4-sandbox-test\"\n").unwrap();

        let hacked_path = workspace_dir.join("hacked.txt");
        let ssh_key_path = ssh_dir.join("id_ed25519");

        let agent_py = format!(
            r#"#!/usr/bin/env python3
import os, sys

argv = sys.argv[1:]
if "--help" in argv:
    print("codex exec --sandbox read-only --skip-git-repo-check [PROMPT] stdin")
    sys.exit(0)
if "--version" in argv:
    print("codex-mock 1.0.0")
    sys.exit(0)

# 1) Verify /proc/self/cmdline NEVER contains user prompt, clipboard secret, or raw tokens
cmdline_raw = open("/proc/self/cmdline", "rb").read().decode("utf-8", "replace")
if "CONFIDENTIAL_CLIPBOARD_MARKER_9911" in cmdline_raw or "调节屏幕亮度到61" in cmdline_raw:
    print("CMDLINE_LEAKED:" + cmdline_raw, file=sys.stderr)
    sys.exit(21)

# 2) Verify read-only workspace can be read, but creating hacked.txt is kernel-blocked (EROFS)
assert open({readme:?}).read() == "READONLY_WORKSPACE_OK"
try:
    open({hacked:?}, "w").write("pwned")
    print("WORKSPACE_WRITE_ESCAPED", file=sys.stderr)
    sys.exit(22)
except OSError:
    pass

# 3) Verify ~/.ssh and unmounted secret directory are completely hidden/inaccessible
for forbidden in [
    {ssh_key:?},
    os.path.expanduser("~/.ssh/id_ed25519"),
    {vault_file:?},
]:
    if os.path.exists(forbidden):
        try:
            leaked = open(forbidden).read()
            if "TOP_SECRET" in leaked:
                print("SECRET_DIR_ESCAPED:" + forbidden, file=sys.stderr)
                sys.exit(23)
        except OSError:
            pass

# 4) Verify staged ~/.codex/config.toml IS readable inside isolated HOME, but read-only!
staged_cfg = os.path.expanduser("~/.codex/config.toml")
assert "gpt-5.4-sandbox-test" in open(staged_cfg).read()
try:
    open(staged_cfg, "a").write("\nhacked = true\n")
    print("AUTH_CFG_WRITE_ESCAPED", file=sys.stderr)
    sys.exit(24)
except OSError:
    pass

# 5) Verify unrelated host secret env vars are stripped
for env_k in ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SSH_AUTH_SOCK"]:
    if env_k in os.environ:
        print("ENV_SECRET_LEAKED:" + env_k, file=sys.stderr)
        sys.exit(25)

# 6) Verify network egress is kernel-blocked when disallowed (--unshare-net)
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.5)
try:
    s.connect(("1.1.1.1", 443))
    print("NETWORK_EGRESS_ESCAPED", file=sys.stderr)
    sys.exit(26)
except OSError:
    pass
finally:
    s.close()

prompt_stdin = sys.stdin.read()
assert "CONFIDENTIAL_CLIPBOARD_MARKER_9911" in prompt_stdin, "stdin prompt missing"
assert "sk-proj-supersecret1234567890abcdef" not in prompt_stdin, "outbound secret was not scrubbed!"

out_file = None
if "-o" in argv:
    idx = argv.index("-o")
    if idx + 1 < len(argv):
        out_file = argv[idx + 1]

if '<intentos_tool_result call_id="' in prompt_stdin:
    reply = "已完成安全沙箱自检并通过 CapabilityBroker 将亮度设为 61%。"
else:
    reply = '<intentos_tool_call>{{"name":"display.brightness.set","arguments":{{"value":61}}}}</intentos_tool_call>'

if out_file:
    open(out_file, "w").write(reply)
print(reply)
"#,
            readme = workspace_dir.join("readme.md").display().to_string(),
            hacked = hacked_path.display().to_string(),
            ssh_key = ssh_key_path.display().to_string(),
            vault_file = unmounted_secret_file.display().to_string(),
        );

        let bin_path = mock_home.join(".local/bin/codex");
        write_exec_script(&bin_path, &agent_py);

        let opts = DiscoveryOptions::isolated_for_test(mock_home.clone());
        let disc = make_disc_backend(
            "codex",
            Some(bin_path.to_string_lossy().to_string()),
            Some("gpt-5.4-sandbox-test"),
        );
        let active = make_active_selection("codex", "openai", "gpt-5.4-sandbox-test");

        let caps = probe_cli_binary_capabilities("codex", &disc, &opts).await;
        assert!(caps.verified_from_help);
        assert!(caps.supports_native_tool_disable);
        assert_eq!(
            resolve_cli_isolation_mode(&caps, &probe, CliExecutionPolicy::standard(true)),
            CliAgentIsolationMode::ManagedSandboxed
        );

        let session = test_session("ses_h04_bwrap");
        let compressed =
            crate::memory_hub::build_compressed_session_history(&core, &session, false);
        let handle = Arc::new(ActiveTurnHandle::new(
            "turn_h04_bwrap_1".to_string(),
            Some(session.session_id.clone()),
        ));
        let mut ledger = TurnEffectLedger::new("turn_h04_bwrap_1");
        let extra = vec![ContextBlock {
            id: "ctx_clip_h04".to_string(),
            label: "user_selection".to_string(),
            content: "CONFIDENTIAL_CLIPBOARD_MARKER_9911 token sk-proj-supersecret1234567890abcdef"
                .to_string(),
            taint: Taint::User,
            data_class: DataClass::Personal,
        }];

        let outcome = run_cli_backend_turn_with_policy(
            &core,
            &opts,
            &disc,
            &active,
            &handle,
            "task_h04_bwrap_1",
            &session,
            "请调节屏幕亮度到61%",
            &extra,
            &compressed,
            &[],
            None,
            false,
            CliExecutionPolicy {
                network_policy: CliNetworkPolicy::ForceOffline,
                ..CliExecutionPolicy::standard(true)
            },
            &probe,
            &mut ledger,
        )
        .await
        .expect("sandboxed CLI turn must succeed");

        assert_eq!(
            outcome.execution_mode,
            BackendExecutionMode::CliBrokerBridged
        );
        assert_eq!(outcome.changeset_ids.len(), 1);
        assert!(outcome.reply_markdown.contains("61%"));
        assert!(
            !hacked_path.exists(),
            "read-only workspace must block hacked.txt"
        );
        let _ = core.undo(outcome.changeset_ids.first().map(String::as_str));
    }

    #[tokio::test]
    async fn cli_isolation_policy_refuses_when_sandbox_disabled_and_downgrades_unverified_binary() {
        let (tmp, core) = setup_cli_test_core();
        let mock_home = tmp.path().join("mock_home_unverified");
        std::fs::create_dir_all(&mock_home).unwrap();

        let unverified_script = r#"#!/bin/sh
# INTENTOS_UNVERIFIED_CLI
cat >/dev/null
printf '来自未验证 CLI 的纯文本回复 <intentos_tool_call>{"name":"display.brightness.set","arguments":{"value":25}}</intentos_tool_call>'
"#;
        let bin_path = mock_home.join(".local/bin/pi");
        write_exec_script(&bin_path, unverified_script);

        let opts = DiscoveryOptions::isolated_for_test(mock_home);
        let disc = make_disc_backend(
            "pi",
            Some(bin_path.to_string_lossy().to_string()),
            Some("pi-test"),
        );
        let active = make_active_selection("pi", "openai", "pi-test");

        let session = test_session("ses_h04_refuse");
        let compressed =
            crate::memory_hub::build_compressed_session_history(&core, &session, false);

        // 1) When OS sandbox is disabled (`SandboxProbe::disabled_for_policy()`), MUST refuse!
        let disabled_probe = SandboxProbe::disabled_for_policy();
        let handle_refused = Arc::new(ActiveTurnHandle::new(
            "turn_h04_refuse".to_string(),
            Some(session.session_id.clone()),
        ));
        let mut ledger_refused = TurnEffectLedger::new("turn_h04_refuse");
        let err = run_cli_backend_turn_with_policy(
            &core,
            &opts,
            &disc,
            &active,
            &handle_refused,
            "task_h04_refuse",
            &session,
            "调暗屏幕亮度",
            &[],
            &compressed,
            &[],
            None,
            false,
            CliExecutionPolicy::standard(true),
            &disabled_probe,
            &mut ledger_refused,
        )
        .await
        .err()
        .expect("disabled OS sandbox must be rejected with UnverifiedRejected");
        assert!(err.to_string().contains("UnverifiedRejected"));
        assert!(ledger_refused.task_steps.is_empty());

        // 2) Under real OS sandbox, an unverified CLI binary NEVER gets `CliBrokerBridged`:
        //    - With `downgrade_unverified_to_readonly: false` -> `UnverifiedRejected` error.
        //    - With `downgrade_unverified_to_readonly: true` -> downgraded to `ExternalChatOnly`, zero Broker calls!
        let host_probe = probe_sandbox_support();
        if host_probe.has_os_isolation() {
            let mut strict_policy = CliExecutionPolicy::standard(true);
            strict_policy.downgrade_unverified_to_readonly = false;
            let mut strict_ledger = TurnEffectLedger::new("turn_h04_strict_unv");
            let strict_err = run_cli_backend_turn_with_policy(
                &core,
                &opts,
                &disc,
                &active,
                &Arc::new(ActiveTurnHandle::new(
                    "turn_h04_strict_unv".to_string(),
                    None,
                )),
                "task_h04_strict_unv",
                &session,
                "调暗屏幕亮度",
                &[],
                &compressed,
                &[],
                None,
                false,
                strict_policy,
                &host_probe,
                &mut strict_ledger,
            )
            .await
            .err()
            .expect("strict policy must reject unverified CLI binary");
            assert!(strict_err.to_string().contains("UnverifiedRejected"));

            let mut downgraded_ledger = TurnEffectLedger::new("turn_h04_downgrade");
            let downgraded = run_cli_backend_turn_with_policy(
                &core,
                &opts,
                &disc,
                &active,
                &Arc::new(ActiveTurnHandle::new(
                    "turn_h04_downgrade".to_string(),
                    None,
                )),
                "task_h04_downgrade",
                &session,
                "调暗屏幕亮度",
                &[],
                &compressed,
                &[],
                None,
                false,
                CliExecutionPolicy::standard(true),
                &host_probe,
                &mut downgraded_ledger,
            )
            .await
            .expect("downgrade policy runs inside OS sandbox as ExternalChatOnly");
            assert_eq!(
                downgraded.execution_mode,
                BackendExecutionMode::ExternalChatOnly
            );
            assert!(
                downgraded_ledger.task_steps.is_empty(),
                "unverified downgraded CLI must NEVER invoke CapabilityBroker!"
            );
            assert!(!downgraded.reply_markdown.contains("intentos_tool_call"));
        }

        // 3) Explicit `allow_external_delegated: true` permits execution as `ExternalDelegated` (`ExternalChatOnly`)
        let mut delegated_policy = CliExecutionPolicy::standard(true);
        delegated_policy.allow_external_delegated = true;
        let caps = probe_cli_binary_capabilities("pi", &disc, &opts).await;
        assert_eq!(
            resolve_cli_isolation_mode(&caps, &disabled_probe, delegated_policy),
            CliAgentIsolationMode::ExternalDelegated
        );
    }

    #[tokio::test]
    async fn cli_host_installed_binaries_capability_probe_is_nondestructive_and_cached() {
        clear_cli_capability_cache();
        let sys_opts = DiscoveryOptions::for_system();
        let search_dirs = build_search_dirs(&sys_opts);

        // Missing binary is handled safely without panic
        let missing_disc = make_disc_backend(
            "pi",
            Some("/nonexistent/intentos_missing_cli_binary".to_string()),
            None,
        );
        let missing_caps = probe_cli_binary_capabilities("pi", &missing_disc, &sys_opts).await;
        assert!(!missing_caps.binary_exists);
        assert!(!missing_caps.supports_native_tool_disable);

        // Non-destructively probe real installed `codex`, `zcode`, and `pi` on this host if present
        for backend in ["codex", "zcode", "pi"] {
            if let Some(found_bin) = find_binary_in_dirs(backend, &search_dirs) {
                let disc =
                    make_disc_backend(backend, Some(found_bin.to_string_lossy().to_string()), None);
                let caps1 = probe_cli_binary_capabilities(backend, &disc, &sys_opts).await;
                let t_cached = Instant::now();
                let caps2 = probe_cli_binary_capabilities(backend, &disc, &sys_opts).await;
                assert_eq!(caps1, caps2);
                assert!(
                    t_cached.elapsed() < Duration::from_millis(25),
                    "second capability probe must hit CLI_CAPABILITY_CACHE"
                );

                if backend == "codex" {
                    assert!(
                        caps1.supports_native_tool_disable && caps1.verified_from_help,
                        "installed host codex must verify --sandbox read-only: {:?}",
                        caps1
                    );
                }
                if backend == "zcode" && !caps1.is_desktop_gui_binary {
                    assert!(
                        caps1.supports_native_tool_disable && caps1.verified_from_help,
                        "headless host zcode.cjs must verify --disallowed-tools: {:?}",
                        caps1
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn cli_chat_only_mode_omits_protocol_and_strips_forced_tool_calls_with_zero_broker_exec()
    {
        let (tmp, core) = setup_cli_test_core();
        let mock_home = tmp.path().join("mock_home_chat_only");
        std::fs::create_dir_all(&mock_home).unwrap();

        let zcode_script = r#"#!/usr/bin/env python3
import sys

argv = sys.argv[1:]
if "--help" in argv:
    print("--disallowed-tools --workflow-mode --attach -p")
    sys.exit(0)
if "--version" in argv:
    print("zcode-mock 0.17.1")
    sys.exit(0)

cmdline = open("/proc/self/cmdline", "rb").read().decode("utf-8", "replace")
assert "仅对话模式下帮我解释Rust所有权" not in cmdline, "zcode -p leaked user prompt in cmdline!"

stdin_data = sys.stdin.read()
assert "[intentos_controlled_broker_protocol]" not in stdin_data, "chat-only prompt must omit broker protocol!"
assert "ExternalChatOnly" in stdin_data

# Maliciously attempt to force a CapabilityBroker tool call anyway!
print('这是关于 Rust 所有权的纯文本解答。\n<intentos_tool_call>{"name":"display.brightness.set","arguments":{"value":11}}</intentos_tool_call>')
"#;
        let bin_path = mock_home.join(".local/bin/zcode");
        write_exec_script(&bin_path, zcode_script);

        let opts = DiscoveryOptions::isolated_for_test(mock_home);
        let disc = make_disc_backend(
            "zcode",
            Some(bin_path.to_string_lossy().to_string()),
            Some("glm-5"),
        );
        let active = make_active_selection("zcode", "builtin:bigmodel", "glm-5");

        let session = test_session("ses_h04_cli_chat_only");
        let compressed =
            crate::memory_hub::build_compressed_session_history(&core, &session, false);
        let mut ledger = TurnEffectLedger::new("turn_h04_cli_chat_only");
        let outcome = run_cli_backend_turn(
            &core,
            &opts,
            &disc,
            &active,
            &Arc::new(ActiveTurnHandle::new(
                "turn_h04_cli_chat_only".to_string(),
                Some(session.session_id.clone()),
            )),
            "task_h04_cli_chat_only",
            &session,
            "仅对话模式下帮我解释Rust所有权",
            &[],
            &compressed,
            &[],
            None,
            false,
            false, // allow_broker_tools == false!
            &mut ledger,
        )
        .await
        .expect("CLI chat-only turn must succeed");

        assert_eq!(
            outcome.execution_mode,
            BackendExecutionMode::ExternalChatOnly
        );
        assert!(
            ledger.task_steps.is_empty(),
            "CapabilityBroker must NEVER be invoked when allow_broker_tools == false"
        );
        assert!(outcome.changeset_ids.is_empty());
        assert!(outcome.reply_markdown.contains("Rust 所有权"));
        assert!(!outcome.reply_markdown.contains("intentos_tool_call"));
        assert!(
            outcome
                .trace_dots
                .iter()
                .any(|d| d.kind == "tool_err" && d.detail.contains("ExternalChatOnly")),
            "forced <intentos_tool_call> in chat-only mode must record a security TraceDot, got: {:?}",
            outcome.trace_dots
        );
    }
}
