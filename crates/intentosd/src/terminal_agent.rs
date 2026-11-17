#![forbid(unsafe_code)]

//! Milestone 2 Controlled General Terminal Agent (`M2-C`, GitHub Issue `#7`).
//!
//! Provides a structured, shell-free `CommandProposal` abstraction, a multi-factor trusted local
//! risk classifier (`C0`–`C4`), and a `Bubblewrap` / `Landlock` OS-sandboxed executor integrated
//! with `SafeFsEngine`, `PolicyEngine`, `ChangeSet` Undo, and `SensitiveDataGuard`:
//! - **Zero `/bin/sh -c` evaluation**: every execution uses discrete `execve` `program` + `argv` arrays.
//! - **Executable canonicalization anti-masquerade**: resolves binaries strictly inside trusted system
//!   directories (`/usr/bin`, `/bin`, `/usr/local/bin`, `/usr/sbin`, `/sbin`) and verifies canonical
//!   `readlink` family stems so symlinks like `df -> /bin/sh` are caught and blocked as `C4Forbidden`.
//! - **Anti-downgrade invariant**: `proposal.expected_effect` from an untrusted model can NEVER
//!   downgrade the locally classified `TerminalSafetyTier` or `Effect`.
//! - **5-Tier safety taxonomy**:
//!   - `C0ReadOnlyDiag`: Pure host observation (`df`, `free`, `uname`, `uptime`, `lscpu`, `lsblk`,
//!     `id`, `whoami`, `date`, `ps`, `ip addr/route`, `ss -tuln`, `systemctl status`) -> auto-executes
//!     in read-only OS sandbox (`Effect::Observe`, `network: false`).
//!   - `C1ScopedRead`: Path-scoped read-only inspection (`ls`, `stat`, `file`, `wc`, `head`, `tail`
//!     without `-f`, `rg`, `grep`, `du`, `sha256sum`, `git status/log/diff/show/branch`, `find` without
//!     `-exec`/`-delete`/`-fprint`) with every path + `cwd` verified via `SafeFsEngine` (zero symlink
//!     escape) -> auto-executes in read-only `bwrap` sandbox (`Effect::Observe`, `network: false`).
//!   - `C2ReversibleWrite`: Scoped workspace file creation/modification (`mkdir`, `cp`, `mv`, `touch`,
//!     `sed -i` inside authorized workspace) -> requires preview/approval, snapshots pre-existing
//!     regular files into `ChangeSet` for atomic Undo when reversible, confined to target dir in `bwrap`.
//!   - `C3SystemModify`: Package/service/env mutations (`apt`, `apt-get`, `dpkg`, `snap`, `flatpak`,
//!     `systemctl start/stop/restart/enable`, `pip install`, `cargo build`, authorized project scripts,
//!     or `network_access == true`) -> ALWAYS requires human approval (`reversible: false`), verified
//!     post-execution.
//!   - `C4Forbidden`: Unconditionally denied (`sudo`, `su`, `pkexec`, `visudo`, `passwd`, `dd` to
//!     `/dev/*`, `mkfs*`, `fdisk`, `rm -rf /` or `$HOME`, inline shell/interpreter `-c`/`-e` bypasses,
//!     executable/data symlink escapes, `LD_PRELOAD` injection, and secret/control-socket paths).

use crate::broker::BrokerDispatchOutcome;
use crate::core::IntentOsCore;
use crate::security_guard::SensitiveDataGuard;
use chrono::{Duration as ChronoDuration, Utc};
use intentos_protocol::{
    CapabilityCall, CapabilityDescriptor, CapabilityResult, ChangeOp, ChangeSet, ChangeSetStatus,
    Effect, ExecutionBackend, ExecutionStatus, UndoStrategy, VerificationReport, VerificationState,
};
use intentos_sandbox::{
    SandboxProbe, TerminalSandboxSpec, execute_terminal_sandbox_bounded,
    is_forbidden_credential_path, probe_sandbox_support,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use walkdir::WalkDir;

pub const TERMINAL_EXECUTE_CAPABILITY_ID: &str = "terminal.execute";
pub const MAX_TERMINAL_OUTPUT_BYTES: usize = 64 * 1024;
pub const MIN_TIMEOUT_SECONDS: u64 = 1;
pub const MAX_TIMEOUT_SECONDS: u64 = 60;
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 15;

pub const DEFAULT_TRUSTED_BIN_DIRS: &[&str] =
    &["/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin"];

const TRUSTED_CANONICAL_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"];

const MAX_DIRECTORY_SYMLINK_SCAN_ENTRIES: usize = 512;
const MAX_DIRECTORY_SYMLINK_SCAN_DEPTH: usize = 4;

fn default_timeout_seconds() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

fn default_proposal_cwd() -> PathBuf {
    PathBuf::from("/")
}

/// Structured, shell-free command execution proposal (`M2-C`).
///
/// Always executed via discrete `execve` `program` + `argv` arrays — NEVER evaluated through `/bin/sh -c`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandProposal {
    pub program: String,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default = "default_proposal_cwd")]
    pub cwd: PathBuf,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub expected_effect: Option<Effect>,
    #[serde(default)]
    pub required_paths: Vec<PathBuf>,
    #[serde(default)]
    pub network_access: bool,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl CommandProposal {
    /// Clamp `timeout_seconds` strictly into `[1, 60]`.
    pub fn clamped_timeout_seconds(&self) -> u64 {
        self.timeout_seconds
            .clamp(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)
    }

    /// Parse a `CommandProposal` from `CapabilityCall.arguments` JSON (`terminal.execute`).
    pub fn from_capability_args(args: &Value, core: Option<&IntentOsCore>) -> Result<Self, String> {
        let obj = args
            .as_object()
            .ok_or_else(|| "terminal.execute 参数必须是 JSON 对象".to_string())?;

        let (program, argv) = if let Some(command) = obj.get("command") {
            if obj.contains_key("program") || obj.contains_key("argv") {
                return Err("command 与 program/argv 不能同时提供".into());
            }
            parse_command_line(command.as_str().ok_or("command 必须是字符串")?)?
        } else {
            let program = obj
                .get("program")
                .and_then(Value::as_str)
                .ok_or_else(|| "缺少必需字符串字段 'program'".to_string())?
                .to_string();

            let argv = match obj.get("argv") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for (idx, item) in arr.iter().enumerate() {
                        let s = item
                            .as_str()
                            .ok_or_else(|| format!("argv[{}] 必须是字符串", idx))?;
                        out.push(s.to_string());
                    }
                    out
                }
                Some(_) => return Err("字段 'argv' 必须是字符串数组".to_string()),
            };

            (program, argv)
        };

        let fallback_cwd = core
            .and_then(|c| c.fs_engine.authorized_roots().first().cloned())
            .unwrap_or_else(|| PathBuf::from("/"));

        let cwd = match obj.get("cwd").and_then(Value::as_str) {
            Some(raw) if !raw.trim().is_empty() => expand_tilde(raw.trim()),
            _ => fallback_cwd,
        };

        let purpose = obj
            .get("purpose")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let expected_effect = match obj.get("expected_effect") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                serde_json::from_value::<Effect>(v.clone())
                    .map_err(|e| format!("无效的 expected_effect: {}", e))?,
            ),
        };

        let required_paths = match obj.get("required_paths") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(arr)) => {
                let mut out = Vec::with_capacity(arr.len());
                for (idx, item) in arr.iter().enumerate() {
                    let s = item
                        .as_str()
                        .ok_or_else(|| format!("required_paths[{}] 必须是路径字符串", idx))?;
                    out.push(expand_tilde(s.trim()));
                }
                out
            }
            Some(_) => return Err("字段 'required_paths' 必须是字符串数组".to_string()),
        };

        let network_access = obj
            .get("network_access")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let timeout_seconds = match obj.get("timeout_seconds") {
            None | Some(Value::Null) => DEFAULT_TIMEOUT_SECONDS,
            Some(v) => v
                .as_u64()
                .ok_or_else(|| "字段 'timeout_seconds' 必须是非负整数".to_string())?,
        };

        Ok(Self {
            program,
            argv,
            cwd,
            purpose,
            expected_effect,
            required_paths,
            network_access,
            timeout_seconds,
        })
    }

    /// Serialize into canonical `terminal.execute` JSON arguments for `PendingApproval` digests.
    pub fn to_capability_args(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("program".to_string(), json!(self.program));
        obj.insert("argv".to_string(), json!(self.argv));
        obj.insert("cwd".to_string(), json!(self.cwd.to_string_lossy()));
        obj.insert("purpose".to_string(), json!(self.purpose));
        if let Some(eff) = self.expected_effect {
            obj.insert("expected_effect".to_string(), json!(eff));
        }
        let req_paths: Vec<String> = self
            .required_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        obj.insert("required_paths".to_string(), json!(req_paths));
        obj.insert("network_access".to_string(), json!(self.network_access));
        obj.insert(
            "timeout_seconds".to_string(),
            json!(self.clamped_timeout_seconds()),
        );
        Value::Object(obj)
    }
}

/// Parse the supported Bash command-line subset without invoking a shell.
/// Only literal words, quoting and escaping are accepted. Expansions/operators
/// fail closed rather than silently changing Bash semantics.
pub fn parse_command_line(command: &str) -> Result<(String, Vec<String>), String> {
    if command.len() > 16_384 || command.chars().any(|c| c.is_control()) {
        return Err("命令过长或包含换行/控制字符；请使用单条命令".into());
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if quote == Some('\'') {
            if c == '\'' {
                quote = None;
            } else {
                word.push(c);
            }
            continue;
        }
        if c == '$' || c == '`' {
            return Err("暂不支持变量或命令替换；请传入明确参数或使用经审批的工作区脚本".into());
        }
        if c == '\\' {
            let next = chars.next().ok_or("命令末尾存在未闭合转义")?;
            if quote == Some('"') && !matches!(next, '$' | '`' | '"' | '\\') {
                word.push('\\');
            }
            word.push(next);
            started = true;
        } else if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
        } else if matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if c.is_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else if matches!(
            c,
            ';' | '|' | '&' | '<' | '>' | '(' | ')' | '{' | '}' | '*' | '?' | '[' | ']' | '~' | '#'
        ) {
            return Err(
                "暂不支持管道、重定向、通配符或复合 Bash 语法；请拆分步骤或使用经审批的工作区脚本"
                    .into(),
            );
        } else {
            word.push(c);
            started = true;
        }
    }
    if quote.is_some() {
        return Err("命令引号未闭合".into());
    }
    if started {
        words.push(word);
    }
    if words.is_empty() || words[0].is_empty() || words[0].contains('=') {
        return Err("缺少程序名或使用了环境变量赋值".into());
    }
    if words.len() > 65 {
        return Err("命令参数不得超过 64 项".into());
    }
    let program = words.remove(0);
    Ok((program, words))
}

/// 5-Tier Controlled Terminal Safety Taxonomy (`M2-C`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalSafetyTier {
    /// Pure system observation (`df`, `free`, `uname`, `uptime`, `lscpu`, `lsblk`, `id`, `whoami`,
    /// `date`, `ps`, `ip addr/route`, `ss -tuln`, `systemctl status`) -> auto-executable in read-only sandbox.
    C0ReadOnlyDiag = 0,
    /// Path-scoped read-only inspection (`ls`, `stat`, `file`, `wc`, `head`, `tail`, `rg`, `grep`,
    /// `du`, `sha256sum`, `git status/log/diff/show/branch`, safe `find`) inside verified workspace.
    C1ScopedRead = 1,
    /// Scoped workspace file creation/modification (`mkdir`, `cp`, `mv`, `touch`, `sed -i`) ->
    /// requires approval + `ChangeSet` Undo backup when reversible.
    C2ReversibleWrite = 2,
    /// Package/service/env mutations (`apt`, `dpkg`, `snap`, `flatpak`, `systemctl` mutations,
    /// `pip`, `cargo`, project scripts, or `network_access == true`) -> requires approval, `reversible: false`.
    C3SystemModify = 3,
    /// Hard-blocked unconditionally (`sudo`, `su`, `pkexec`, `/etc/shadow`, `~/.ssh`, symlink escape,
    /// inline shell/interpreter `-c`/`-e` bypasses, unauthorized writes, `LD_PRELOAD`, etc.).
    C4Forbidden = 4,
}

impl TerminalSafetyTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C0ReadOnlyDiag => "c0_read_only_diag",
            Self::C1ScopedRead => "c1_scoped_read",
            Self::C2ReversibleWrite => "c2_reversible_write",
            Self::C3SystemModify => "c3_system_modify",
            Self::C4Forbidden => "c4_forbidden",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Self::C0ReadOnlyDiag => "C0",
            Self::C1ScopedRead => "C1",
            Self::C2ReversibleWrite => "C2",
            Self::C3SystemModify => "C3",
            Self::C4Forbidden => "C4",
        }
    }

    pub fn is_auto_executable(self) -> bool {
        matches!(self, Self::C0ReadOnlyDiag | Self::C1ScopedRead)
    }

    pub fn requires_approval(self) -> bool {
        matches!(self, Self::C2ReversibleWrite | Self::C3SystemModify)
    }

    pub fn is_forbidden(self) -> bool {
        matches!(self, Self::C4Forbidden)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op_kind", rename_all = "snake_case")]
pub enum C2WritePlan {
    Mkdir {
        dirs: Vec<PathBuf>,
    },
    Touch {
        targets: Vec<PathBuf>,
    },
    Copy {
        sources: Vec<PathBuf>,
        dest: PathBuf,
        dest_is_existing_dir: bool,
        recursive: bool,
    },
    Move {
        sources: Vec<PathBuf>,
        dest: PathBuf,
        dest_is_existing_dir: bool,
    },
    SedInPlace {
        targets: Vec<PathBuf>,
    },
}

/// Full local risk classification output produced by [`classify_command_proposal`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandClassification {
    pub tier: TerminalSafetyTier,
    pub effective_effect: Effect,
    pub effects: Vec<Effect>,
    pub reversible: bool,
    pub requires_approval: bool,
    pub denied: bool,
    pub resolved_executable: Option<PathBuf>,
    pub canonical_executable: Option<PathBuf>,
    pub canonical_family: Option<String>,
    pub verified_readonly_paths: Vec<PathBuf>,
    pub verified_readwrite_paths: Vec<PathBuf>,
    pub c2_plan: Option<C2WritePlan>,
    pub downgrade_attempt_blocked: bool,
    pub reasons: Vec<String>,
}

fn expand_tilde(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if (trimmed == "~" || trimmed == "$HOME" || trimmed == "${HOME}")
        && let Some(h) = std::env::var_os("HOME")
    {
        return PathBuf::from(h);
    }
    for prefix in ["~/", "$HOME/", "${HOME}/"] {
        if let Some(rest) = trimmed.strip_prefix(prefix)
            && let Some(h) = std::env::var_os("HOME")
        {
            return PathBuf::from(h).join(rest);
        }
    }
    PathBuf::from(trimmed)
}

fn normalize_lexical_clean(path: &Path) -> PathBuf {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return path.to_path_buf();
    }
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::Normal(seg) => out.push(seg),
            Component::ParentDir => out.push(comp.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        path.to_path_buf()
    } else {
        out
    }
}

fn resolve_against_cwd(cwd: &Path, raw: &str) -> PathBuf {
    let expanded = expand_tilde(raw);
    if expanded.is_absolute() {
        normalize_lexical_clean(&expanded)
    } else {
        normalize_lexical_clean(&cwd.join(expanded))
    }
}

/// Map a binary's filename (`df`, `gnudf`, `dash`, `python3.14`, `mawk`, `snapd`, etc.)
/// to its canonical utility family so legitimate Ubuntu 22.04–26.04 symlinks (`df -> gnudf`) pass
/// while symlink masquerades (`df -> /bin/sh` / `dash`) are caught deterministically.
fn canonical_binary_family(file_name: &str) -> String {
    let lc = file_name.trim().to_ascii_lowercase();

    if matches!(
        lc.as_str(),
        "sh" | "dash" | "bash" | "rbash" | "zsh" | "ksh" | "mksh" | "csh" | "tcsh" | "fish" | "ash"
    ) {
        return "shell".to_string();
    }

    if lc == "python"
        || lc == "python3"
        || lc == "python2"
        || lc.starts_with("python3.")
        || lc.starts_with("python2.")
    {
        return "python".to_string();
    }
    if lc == "node" || lc == "nodejs" {
        return "node".to_string();
    }
    if lc == "perl" || lc.starts_with("perl5.") {
        return "perl".to_string();
    }
    if lc == "ruby" || lc.starts_with("ruby2.") || lc.starts_with("ruby3.") {
        return "ruby".to_string();
    }
    if matches!(
        lc.as_str(),
        "awk" | "mawk" | "gawk" | "nawk" | "original-awk"
    ) {
        return "awk".to_string();
    }
    if matches!(lc.as_str(), "rg" | "ripgrep") {
        return "rg".to_string();
    }
    if matches!(lc.as_str(), "snap" | "snapd") {
        return "snap".to_string();
    }
    if lc == "mkfs" || lc.starts_with("mkfs.") {
        return "mkfs".to_string();
    }

    const COREUTILS_WRAPPED: &[&str] = &[
        "df",
        "ls",
        "cp",
        "mv",
        "rm",
        "mkdir",
        "rmdir",
        "touch",
        "stat",
        "wc",
        "head",
        "tail",
        "du",
        "sha256sum",
        "id",
        "whoami",
        "date",
        "uname",
        "uptime",
        "chown",
        "chmod",
        "chgrp",
        "dd",
        "ln",
        "cat",
        "sort",
        "uniq",
        "tr",
        "cut",
        "realpath",
        "readlink",
    ];
    for prefix in ["gnu", "uu-", "uu_"] {
        if let Some(rest) = lc.strip_prefix(prefix)
            && COREUTILS_WRAPPED.contains(&rest)
        {
            return rest.to_string();
        }
    }

    lc
}

fn is_unconditional_c4_family(family_or_name: &str) -> bool {
    let lc = family_or_name.trim().to_ascii_lowercase();
    lc == "mkfs"
        || lc.starts_with("mkfs.")
        || matches!(
            lc.as_str(),
            "sudo"
                | "sudo-rs"
                | "su"
                | "pkexec"
                | "visudo"
                | "passwd"
                | "chpasswd"
                | "doas"
                | "usermod"
                | "useradd"
                | "userdel"
                | "groupadd"
                | "groupdel"
                | "gpasswd"
                | "chage"
                | "newgrp"
                | "fdisk"
                | "sfdisk"
                | "cfdisk"
                | "parted"
                | "gdisk"
                | "wipefs"
                | "badblocks"
                | "cryptsetup"
                | "losetup"
                | "mount"
                | "umount"
                | "swapon"
                | "swapoff"
                | "chroot"
                | "pivot_root"
                | "nsenter"
                | "unshare"
                | "insmod"
                | "rmmod"
                | "modprobe"
                | "setcap"
                | "iptables"
                | "ip6tables"
                | "nft"
                | "ufw"
                | "shutdown"
                | "reboot"
                | "poweroff"
                | "halt"
        )
}

fn is_forbidden_token_or_path(core: &IntentOsCore, raw: &str) -> Option<String> {
    if raw.contains('\0') {
        return Some("参数包含非法 NUL 字节".to_string());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("LD_PRELOAD=")
        || upper == "LD_PRELOAD"
        || upper.contains("LD_PRELOAD=")
        || upper.starts_with("LD_AUDIT=")
        || upper.contains("LD_AUDIT=")
    {
        return Some(format!("检测到动态链接器注入参数: {}", trimmed));
    }

    let lower = trimmed.to_ascii_lowercase();
    for sock_marker in ["ui.sock", "gateway.sock"] {
        if lower == sock_marker
            || lower.ends_with(&format!("/{}", sock_marker))
            || lower.contains(&format!("/{}", sock_marker))
        {
            return Some(format!(
                "严禁终端命令直接访问受保护内部控制套接字 ({})",
                sock_marker
            ));
        }
    }

    for secret_sub in [
        "/.ssh",
        "~/.ssh",
        "/.gnupg",
        "~/.gnupg",
        "/.aws",
        "~/.aws",
        "/.kube",
        "~/.kube",
        "/.config/gcloud",
        "~/.config/gcloud",
        "/.config/intentos",
        "~/.config/intentos",
        "/.local/share/intentos",
        "~/.local/share/intentos",
        "/.local/state/intentos",
        "~/.local/state/intentos",
        "/.local/share/keyrings",
        "~/.local/share/keyrings",
        "/.netrc",
        "~/.netrc",
        "/.git-credentials",
        "~/.git-credentials",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/dev/mem",
        "/dev/kmem",
        "/dev/port",
        "/proc/kcore",
    ] {
        if lower == secret_sub
            || lower.starts_with(&format!("{}/", secret_sub))
            || lower.contains(secret_sub)
        {
            return Some(format!("严禁访问高敏凭据或核心配置路径: {}", trimmed));
        }
    }

    // Also strip leading `--key=` when checking path values
    let candidate_slice = if let Some((_k, v)) = trimmed.split_once('=') {
        v.trim()
    } else {
        trimmed
    };
    let expanded = expand_tilde(candidate_slice);
    if core.fs_engine.is_forbidden(&expanded) || is_forbidden_credential_path(&expanded) {
        return Some(format!("安全内核拦截访问禁区路径: {}", trimmed));
    }
    for protected_dir in [
        &core.paths.config_dir,
        &core.paths.data_dir,
        &core.paths.state_dir,
        &core.paths.runtime_dir,
    ] {
        if expanded.starts_with(protected_dir) {
            return Some(format!(
                "严禁终端命令直接读写 IntentOS 守护进程私有目录: {}",
                expanded.display()
            ));
        }
    }

    None
}

fn is_system_critical_dir(path: &Path) -> bool {
    let clean = normalize_lexical_clean(path);
    if clean == Path::new("/") {
        return true;
    }
    for sys in [
        "/bin", "/sbin", "/usr", "/etc", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys",
        "/root", "/var", "/run",
    ] {
        if clean == Path::new(sys) || clean.starts_with(sys) {
            return true;
        }
    }
    false
}

fn is_home_root_or_wildcard(raw: &str) -> bool {
    let t = raw.trim().trim_end_matches('/');
    if matches!(
        t,
        "/" | "/*" | "~" | "~/*" | "$HOME" | "$HOME/*" | "${HOME}" | "${HOME}/*" | "/home"
    ) {
        return true;
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home_path = PathBuf::from(home);
        let expanded = normalize_lexical_clean(&expand_tilde(raw));
        if expanded == home_path {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone)]
enum ScopedPathVerdict {
    Authorized {
        mount_root: PathBuf,
        canonical_target: PathBuf,
    },
    OutsideAuthorizedScope(PathBuf),
    Forbidden(String),
}

fn collect_authorized_and_granted_roots(core: &IntentOsCore) -> Vec<(PathBuf, PathBuf)> {
    let mut roots: Vec<PathBuf> = core.fs_engine.authorized_roots().to_vec();
    for approved in core.fs_engine.list_approved_roots() {
        if !roots.contains(&approved) {
            roots.push(approved);
        }
    }
    for grant_val in core.policy.list_session_grants() {
        if grant_val.get("scope_kind").and_then(Value::as_str) == Some("directory")
            && let Some(sv) = grant_val.get("scope_value").and_then(Value::as_str)
        {
            let pb = expand_tilde(sv);
            if !core.fs_engine.is_forbidden(&pb) && !roots.contains(&pb) {
                roots.push(pb);
            }
        }
    }
    roots
        .into_iter()
        .filter(|r| !core.fs_engine.is_forbidden(r))
        .map(|r| {
            let canon = std::fs::canonicalize(&r).unwrap_or_else(|_| r.clone());
            (r, canon)
        })
        .collect()
}

/// Verify `candidate` against `SafeFsEngine` forbidden rules, parent traversal, symlink escapes,
/// and authorized/session-granted directory boundaries.
fn verify_scoped_path(
    core: &IntentOsCore,
    candidate: &Path,
    scan_dir_symlinks: bool,
) -> ScopedPathVerdict {
    let raw_str = candidate.to_string_lossy();
    if let Some(reason) = is_forbidden_token_or_path(core, &raw_str) {
        return ScopedPathVerdict::Forbidden(reason);
    }
    if !candidate.is_absolute() {
        return ScopedPathVerdict::Forbidden(format!(
            "路径必须为绝对路径: {}",
            candidate.display()
        ));
    }
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return ScopedPathVerdict::Forbidden(format!(
            "拒绝包含 '..' 的路径穿越: {}",
            candidate.display()
        ));
    }

    let auth_pairs = collect_authorized_and_granted_roots(core);

    // Find the most specific matching lexical root (if any)
    let mut matched_root: Option<(PathBuf, PathBuf)> = None;
    for (raw_root, canon_root) in &auth_pairs {
        if candidate.starts_with(raw_root) || candidate.starts_with(canon_root) {
            let replace = match &matched_root {
                None => true,
                Some((prev_raw, _)) => raw_root.as_os_str().len() > prev_raw.as_os_str().len(),
            };
            if replace {
                matched_root = Some((raw_root.clone(), canon_root.clone()));
            }
        }
    }

    // Walk prefixes from root down to candidate to catch intermediate/leaf symlinks (even dangling ones!)
    let mut cur = PathBuf::new();
    for comp in candidate.components() {
        cur.push(comp.as_os_str());
        if let Ok(sym_meta) = std::fs::symlink_metadata(&cur)
            && sym_meta.file_type().is_symlink()
        {
            // Only care about symlinks inside or at the target path (not standard OS root symlinks unless escaping)
            let inside_matched = matched_root
                .as_ref()
                .is_some_and(|(raw_r, canon_r)| cur.starts_with(raw_r) || cur.starts_with(canon_r));
            if inside_matched || cur == candidate {
                match std::fs::canonicalize(&cur) {
                    Ok(canon_link_target) => {
                        if let Some(reason) =
                            is_forbidden_token_or_path(core, &canon_link_target.to_string_lossy())
                        {
                            return ScopedPathVerdict::Forbidden(format!(
                                "符号链接指向禁区路径 ({} -> {}): {}",
                                cur.display(),
                                canon_link_target.display(),
                                reason
                            ));
                        }
                        let link_in_auth = auth_pairs
                            .iter()
                            .any(|(_, canon_r)| canon_link_target.starts_with(canon_r));
                        if !link_in_auth {
                            return ScopedPathVerdict::Forbidden(format!(
                                "检测到符号链接越界逃逸 (symlink escape: {} -> {})",
                                cur.display(),
                                canon_link_target.display()
                            ));
                        }
                    }
                    Err(_) => {
                        return ScopedPathVerdict::Forbidden(format!(
                            "拒绝悬空或不可解析的符号链接: {}",
                            cur.display()
                        ));
                    }
                }
            }
        }
    }

    // Resolve canonical target via existing path or nearest existing ancestor
    let mut probe_anc = candidate.to_path_buf();
    let canonical_target = loop {
        if probe_anc.exists() {
            match std::fs::canonicalize(&probe_anc) {
                Ok(canon_anc) => {
                    if let Ok(suffix) = candidate.strip_prefix(&probe_anc) {
                        break if suffix.as_os_str().is_empty() {
                            canon_anc
                        } else {
                            canon_anc.join(suffix)
                        };
                    }
                    break canon_anc;
                }
                Err(e) => {
                    return ScopedPathVerdict::Forbidden(format!(
                        "路径规范化校验失败 ({}): {}",
                        probe_anc.display(),
                        e
                    ));
                }
            }
        }
        if !probe_anc.pop() {
            break candidate.to_path_buf();
        }
    };

    if let Some(reason) = is_forbidden_token_or_path(core, &canonical_target.to_string_lossy()) {
        return ScopedPathVerdict::Forbidden(reason);
    }

    // Verify canonical target falls inside at least one canonical authorized/granted root
    let mut best_canon_match: Option<(PathBuf, PathBuf)> = None;
    for (raw_r, canon_r) in &auth_pairs {
        if canonical_target.starts_with(canon_r) {
            let replace = match &best_canon_match {
                None => true,
                Some((_, prev_canon)) => canon_r.as_os_str().len() > prev_canon.as_os_str().len(),
            };
            if replace {
                best_canon_match = Some((raw_r.clone(), canon_r.clone()));
            }
        }
    }

    let Some((_raw_root, canon_root)) = best_canon_match else {
        if matched_root.is_some() {
            return ScopedPathVerdict::Forbidden(format!(
                "检测到路径规范化越界逃逸 ({} -> {})",
                candidate.display(),
                canonical_target.display()
            ));
        }
        return ScopedPathVerdict::OutsideAuthorizedScope(canonical_target);
    };

    // Bounded directory symlink escape scan when inspecting/modifying a directory
    if scan_dir_symlinks && canonical_target.is_dir() {
        for entry in WalkDir::new(&canonical_target)
            .max_depth(MAX_DIRECTORY_SYMLINK_SCAN_DEPTH)
            .follow_links(false)
            .into_iter()
            .take(MAX_DIRECTORY_SYMLINK_SCAN_ENTRIES)
            .flatten()
        {
            if entry.file_type().is_symlink() {
                let sym_p = entry.path();
                match std::fs::canonicalize(sym_p) {
                    Ok(target_p) => {
                        if let Some(reason) =
                            is_forbidden_token_or_path(core, &target_p.to_string_lossy())
                        {
                            return ScopedPathVerdict::Forbidden(format!(
                                "目录内符号链接指向禁区 ({} -> {}): {}",
                                sym_p.display(),
                                target_p.display(),
                                reason
                            ));
                        }
                        let ok = auth_pairs.iter().any(|(_, cr)| target_p.starts_with(cr));
                        if !ok {
                            return ScopedPathVerdict::Forbidden(format!(
                                "目录内检测到越界符号链接逃逸 ({} -> {})",
                                sym_p.display(),
                                target_p.display()
                            ));
                        }
                    }
                    Err(_) => {
                        if let Ok(raw_link) = std::fs::read_link(sym_p) {
                            let joined = if raw_link.is_absolute() {
                                raw_link
                            } else {
                                sym_p.parent().unwrap_or(&canonical_target).join(raw_link)
                            };
                            if let Some(reason) =
                                is_forbidden_token_or_path(core, &joined.to_string_lossy())
                            {
                                return ScopedPathVerdict::Forbidden(reason);
                            }
                            let joined_clean = normalize_lexical_clean(&joined);
                            if joined_clean
                                .components()
                                .any(|c| matches!(c, Component::ParentDir))
                                || !auth_pairs.iter().any(|(rr, cr)| {
                                    joined_clean.starts_with(rr) || joined_clean.starts_with(cr)
                                })
                            {
                                return ScopedPathVerdict::Forbidden(format!(
                                    "目录内悬空符号链接指向未授权外部路径 ({} -> {})",
                                    sym_p.display(),
                                    joined_clean.display()
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    ScopedPathVerdict::Authorized {
        mount_root: canon_root,
        canonical_target,
    }
}

#[derive(Debug, Clone)]
enum ResolvedExec {
    TrustedSystem {
        resolved_path: PathBuf,
        canonical_path: PathBuf,
        requested_name: String,
        canonical_family: String,
    },
    AuthorizedWorkspaceScript {
        script_path: PathBuf,
        mount_root: PathBuf,
    },
    MissingTrustedBinary {
        requested_name: String,
        requested_family: String,
    },
    Forbidden(String),
}

fn resolve_and_verify_executable(
    core: &IntentOsCore,
    program: &str,
    cwd: &Path,
    trusted_bin_dirs: &[PathBuf],
    using_custom_bin_dirs: bool,
) -> ResolvedExec {
    if program.is_empty() || program.trim().is_empty() {
        return ResolvedExec::Forbidden("program 不能为空".to_string());
    }
    if program.contains('\0') || program.contains('\n') || program.contains('\r') {
        return ResolvedExec::Forbidden("program 包含非法控制字符".to_string());
    }
    if program.chars().any(char::is_whitespace)
        || program
            .chars()
            .any(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '>' | '<'))
    {
        return ResolvedExec::Forbidden(format!(
            "program '{}' 禁止包含空格或 Shell 元字符（必须通过离散 argv 数组传参，严禁 /bin/sh -c 拼接）",
            program
        ));
    }
    if let Some(reason) = is_forbidden_token_or_path(core, program) {
        return ResolvedExec::Forbidden(reason);
    }

    let prog_path = Path::new(program);
    if prog_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return ResolvedExec::Forbidden(format!("program 禁止包含 '..' 路径穿越: {}", program));
    }

    let Some(req_name_os) = prog_path.file_name() else {
        return ResolvedExec::Forbidden(format!("无法解析可执行文件名: {}", program));
    };
    let req_name = req_name_os.to_string_lossy().to_ascii_lowercase();
    let req_family = canonical_binary_family(&req_name);

    if is_unconditional_c4_family(&req_name) || is_unconditional_c4_family(&req_family) {
        return ResolvedExec::Forbidden(format!(
            "高危特权或破坏性系统命令 '{}' 被 C4 策略无条件拦截",
            req_name
        ));
    }

    if !program.contains('/') {
        for bin_dir in trusted_bin_dirs {
            let cand = bin_dir.join(&req_name);
            if let Ok(sym_meta) = std::fs::symlink_metadata(&cand) {
                let Ok(canon) = std::fs::canonicalize(&cand) else {
                    return ResolvedExec::Forbidden(format!(
                        "可信目录中存在悬空或损坏的可执行符号链接: {}",
                        cand.display()
                    ));
                };
                if !canon.is_file() {
                    return ResolvedExec::Forbidden(format!(
                        "可执行目标不是常规文件: {}",
                        canon.display()
                    ));
                }
                if !using_custom_bin_dirs {
                    let canon_s = canon.to_string_lossy();
                    if !TRUSTED_CANONICAL_PREFIXES
                        .iter()
                        .any(|pfx| canon_s.starts_with(pfx))
                    {
                        return ResolvedExec::Forbidden(format!(
                            "系统命令 '{}' 指向非可信系统目录 '{}'",
                            cand.display(),
                            canon.display()
                        ));
                    }
                }
                let canon_file_name = canon
                    .file_name()
                    .map(|s| s.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                let canon_family = canonical_binary_family(&canon_file_name);

                if is_unconditional_c4_family(&canon_file_name)
                    || is_unconditional_c4_family(&canon_family)
                {
                    return ResolvedExec::Forbidden(format!(
                        "可执行文件 '{}' 实际指向受禁命令 '{}'",
                        cand.display(),
                        canon.display()
                    ));
                }

                let is_system_multicall = !using_custom_bin_dirs
                    && matches!(
                        bin_dir.to_str(),
                        Some("/usr/bin") | Some("/bin") | Some("/sbin") | Some("/usr/sbin")
                    )
                    && matches!(canon_file_name.as_str(), "coreutils" | "busybox");

                if canon_family != req_family && !is_system_multicall {
                    let _ = sym_meta;
                    return ResolvedExec::Forbidden(format!(
                        "检测到可执行文件符号链接伪装: 请求 '{}' (family={}) 实际解析为 '{}' (family={})",
                        program,
                        req_family,
                        canon.display(),
                        canon_family
                    ));
                }

                return ResolvedExec::TrustedSystem {
                    resolved_path: cand,
                    canonical_path: canon,
                    requested_name: req_name,
                    canonical_family: req_family,
                };
            }
        }

        return ResolvedExec::MissingTrustedBinary {
            requested_name: req_name,
            requested_family: req_family,
        };
    }

    // Explicit path containing `/`
    let full_prog = resolve_against_cwd(cwd, program);
    let Ok(sym_meta) = std::fs::symlink_metadata(&full_prog) else {
        return ResolvedExec::Forbidden(format!("指定的可执行路径不存在: {}", full_prog.display()));
    };
    let Ok(canon) = std::fs::canonicalize(&full_prog) else {
        return ResolvedExec::Forbidden(format!(
            "指定的可执行符号链接无法解析: {}",
            full_prog.display()
        ));
    };
    if !canon.is_file() {
        return ResolvedExec::Forbidden(format!(
            "指定的可执行路径不是常规文件: {}",
            canon.display()
        ));
    }

    let canon_file_name = canon
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let canon_family = canonical_binary_family(&canon_file_name);

    if is_unconditional_c4_family(&canon_file_name) || is_unconditional_c4_family(&canon_family) {
        return ResolvedExec::Forbidden(format!(
            "指定的可执行路径 '{}' 指向受禁高危程序 '{}'",
            full_prog.display(),
            canon.display()
        ));
    }

    // Symlink masquerade check (e.g., `/tmp/xxx/df -> /bin/sh`)
    if (sym_meta.file_type().is_symlink() || canon_family == "shell") && canon_family != req_family
    {
        return ResolvedExec::Forbidden(format!(
            "检测到符号链接伪装绕过尝试: '{}' (family={}) 实际指向 '{}' (family={})",
            full_prog.display(),
            req_family,
            canon.display(),
            canon_family
        ));
    }

    let in_trusted_bin_dir = full_prog
        .parent()
        .is_some_and(|parent| trusted_bin_dirs.iter().any(|d| d == parent));

    if in_trusted_bin_dir {
        let is_system_multicall =
            !using_custom_bin_dirs && matches!(canon_file_name.as_str(), "coreutils" | "busybox");
        if canon_family != req_family && !is_system_multicall {
            return ResolvedExec::Forbidden(format!(
                "可信目录可执行文件伪装拦截: '{}' 实际指向 '{}'",
                full_prog.display(),
                canon.display()
            ));
        }
        return ResolvedExec::TrustedSystem {
            resolved_path: full_prog,
            canonical_path: canon,
            requested_name: req_name,
            canonical_family: req_family,
        };
    }

    // Executable outside trusted system dirs pointing to a system binary/shell -> block masquerade!
    let canon_s = canon.to_string_lossy();
    if TRUSTED_CANONICAL_PREFIXES
        .iter()
        .any(|pfx| canon_s.starts_with(pfx))
    {
        return ResolvedExec::Forbidden(format!(
            "拒绝通过非系统目录路径 '{}' 间接调用系统程序 '{}'",
            full_prog.display(),
            canon.display()
        ));
    }

    // Must be an authorized project script inside `SafeFsEngine` workspace -> C3 only!
    match verify_scoped_path(core, &full_prog, false) {
        ScopedPathVerdict::Authorized {
            mount_root,
            canonical_target,
        } => ResolvedExec::AuthorizedWorkspaceScript {
            script_path: canonical_target,
            mount_root,
        },
        ScopedPathVerdict::OutsideAuthorizedScope(p) => ResolvedExec::Forbidden(format!(
            "拒绝执行未授权目录外的外部程序或脚本: {}",
            p.display()
        )),
        ScopedPathVerdict::Forbidden(reason) => ResolvedExec::Forbidden(reason),
    }
}

fn finalize_classification(
    proposal: &CommandProposal,
    mut base: CommandClassification,
) -> CommandClassification {
    if base.tier == TerminalSafetyTier::C4Forbidden {
        base.denied = true;
        base.requires_approval = false;
        base.reversible = false;
        base.effective_effect = Effect::SystemAdmin;
        if !base.effects.contains(&Effect::SystemAdmin) {
            base.effects.push(Effect::SystemAdmin);
        }
        if proposal
            .expected_effect
            .is_some_and(|e| e < base.effective_effect)
        {
            base.downgrade_attempt_blocked = true;
        }
        return base;
    }

    // Any proposal requesting `network_access == true` MUST be upgraded to at least `C3SystemModify`!
    if proposal.network_access && base.tier < TerminalSafetyTier::C3SystemModify {
        base.tier = TerminalSafetyTier::C3SystemModify;
        base.reversible = false;
        base.requires_approval = true;
        base.c2_plan = None;
        if !base.effects.contains(&Effect::Egress) {
            base.effects.push(Effect::Egress);
        }
        if !base.effects.contains(&Effect::WriteDestructive)
            && !base.effects.contains(&Effect::SystemAdmin)
        {
            base.effects.push(Effect::WriteDestructive);
        }
        base.effective_effect = base
            .effects
            .iter()
            .copied()
            .max()
            .unwrap_or(Effect::WriteDestructive);
        base.reasons.push(
            "network_access == true 强制升级为 C3SystemModify（需人工逐次审批且不可自动撤销）"
                .to_string(),
        );
    } else if proposal.network_access && !base.effects.contains(&Effect::Egress) {
        base.effects.push(Effect::Egress);
    }

    // Anti-Bypass Rule #2: NEVER allow `proposal.expected_effect` to downgrade local tier/effect!
    if let Some(model_eff) = proposal.expected_effect {
        if model_eff < base.effective_effect {
            base.downgrade_attempt_blocked = true;
            base.reasons.push(format!(
                "已拦截模型自报 expected_effect ({}) 对本地可信分级 {} ({}) 的降级尝试",
                model_eff.as_str(),
                base.tier.short_label(),
                base.effective_effect.as_str()
            ));
        } else if model_eff > base.effective_effect {
            base.effective_effect = model_eff;
            if !base.effects.contains(&model_eff) {
                base.effects.push(model_eff);
            }
            if model_eff >= Effect::WriteReversible
                && base.tier < TerminalSafetyTier::C2ReversibleWrite
            {
                base.tier = TerminalSafetyTier::C3SystemModify;
                base.requires_approval = true;
                base.reversible = false;
            }
        }
    }

    if base.tier == TerminalSafetyTier::C3SystemModify {
        base.requires_approval = true;
        base.reversible = false;
    } else if base.tier == TerminalSafetyTier::C2ReversibleWrite {
        base.requires_approval = true;
    }

    base
}

fn c4_denied(
    proposal: &CommandProposal,
    resolved: Option<PathBuf>,
    canonical: Option<PathBuf>,
    family: Option<String>,
    reason: impl Into<String>,
) -> CommandClassification {
    finalize_classification(
        proposal,
        CommandClassification {
            tier: TerminalSafetyTier::C4Forbidden,
            effective_effect: Effect::SystemAdmin,
            effects: vec![Effect::SystemAdmin],
            reversible: false,
            requires_approval: false,
            denied: true,
            resolved_executable: resolved,
            canonical_executable: canonical,
            canonical_family: family,
            verified_readonly_paths: Vec::new(),
            verified_readwrite_paths: Vec::new(),
            c2_plan: None,
            downgrade_attempt_blocked: false,
            reasons: vec![reason.into()],
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn c3_modify(
    proposal: &CommandProposal,
    resolved: Option<PathBuf>,
    canonical: Option<PathBuf>,
    family: Option<String>,
    effect: Effect,
    ro_paths: Vec<PathBuf>,
    rw_paths: Vec<PathBuf>,
    reason: impl Into<String>,
) -> CommandClassification {
    let mut effects = vec![effect];
    if proposal.network_access && !effects.contains(&Effect::Egress) {
        effects.push(Effect::Egress);
    }
    let max_eff = effects.iter().copied().max().unwrap_or(effect);
    finalize_classification(
        proposal,
        CommandClassification {
            tier: TerminalSafetyTier::C3SystemModify,
            effective_effect: max_eff,
            effects,
            reversible: false,
            requires_approval: true,
            denied: false,
            resolved_executable: resolved,
            canonical_executable: canonical,
            canonical_family: family,
            verified_readonly_paths: ro_paths,
            verified_readwrite_paths: rw_paths,
            c2_plan: None,
            downgrade_attempt_blocked: false,
            reasons: vec![reason.into()],
        },
    )
}

/// Classify a `CommandProposal` using standard trusted system binary directories.
pub fn classify_command_proposal(
    core: &IntentOsCore,
    proposal: &CommandProposal,
) -> CommandClassification {
    let bin_dirs: Vec<PathBuf> = DEFAULT_TRUSTED_BIN_DIRS.iter().map(PathBuf::from).collect();
    classify_command_proposal_inner(core, proposal, &bin_dirs, false)
}

/// Classify a `CommandProposal` with explicit `trusted_bin_dirs` (used by security unit tests to
/// stage symlink-masquerade fixtures without modifying root-owned `/usr/bin`).
pub fn classify_command_proposal_with_bin_dirs(
    core: &IntentOsCore,
    proposal: &CommandProposal,
    trusted_bin_dirs: &[PathBuf],
) -> CommandClassification {
    classify_command_proposal_inner(core, proposal, trusted_bin_dirs, true)
}

fn classify_command_proposal_inner(
    core: &IntentOsCore,
    proposal: &CommandProposal,
    trusted_bin_dirs: &[PathBuf],
    using_custom_bin_dirs: bool,
) -> CommandClassification {
    // 1. Pre-scan `purpose`, `cwd`, `required_paths`, and every `argv` item for NUL bytes,
    //    `LD_PRELOAD` injection, control sockets, and forbidden credential/system paths.
    if proposal.purpose.contains('\0') {
        return c4_denied(proposal, None, None, None, "purpose 包含非法 NUL 字节");
    }
    if let Some(reason) = is_forbidden_token_or_path(core, &proposal.cwd.to_string_lossy()) {
        return c4_denied(proposal, None, None, None, reason);
    }
    if proposal
        .cwd
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return c4_denied(
            proposal,
            None,
            None,
            None,
            format!("cwd 禁止包含 '..' 路径穿越: {}", proposal.cwd.display()),
        );
    }
    for rp in &proposal.required_paths {
        if let Some(reason) = is_forbidden_token_or_path(core, &rp.to_string_lossy()) {
            return c4_denied(proposal, None, None, None, reason);
        }
        if rp.components().any(|c| matches!(c, Component::ParentDir)) {
            return c4_denied(
                proposal,
                None,
                None,
                None,
                format!("required_paths 禁止包含 '..' 路径穿越: {}", rp.display()),
            );
        }
    }
    for arg in &proposal.argv {
        if let Some(reason) = is_forbidden_token_or_path(core, arg) {
            return c4_denied(proposal, None, None, None, reason);
        }
    }

    // 2. Resolve and verify executable identity (catching `df -> /bin/sh` symlink masquerades!)
    let exec_res = resolve_and_verify_executable(
        core,
        &proposal.program,
        &proposal.cwd,
        trusted_bin_dirs,
        using_custom_bin_dirs,
    );

    let (resolved_opt, canonical_opt, prog_name, prog_family) = match exec_res {
        ResolvedExec::Forbidden(reason) => {
            return c4_denied(proposal, None, None, None, reason);
        }
        ResolvedExec::AuthorizedWorkspaceScript { .. } => {
            // SC-03 safe migration gate: no source-path execution until an
            // approval-bound immutable artifact is available. Approval alone
            // must not permit a TOCTOU script replacement.
            return c4_denied(
                proposal,
                None,
                None,
                None,
                "workspace scripts disabled pending SC-03 immutable artifact approval",
            );
        }
        ResolvedExec::TrustedSystem {
            resolved_path,
            canonical_path,
            requested_name,
            canonical_family,
        } => (
            Some(resolved_path),
            Some(canonical_path),
            requested_name,
            canonical_family,
        ),
        ResolvedExec::MissingTrustedBinary {
            requested_name,
            requested_family,
        } => (None, None, requested_name, requested_family),
    };

    // SC-03 fail-closed gate: interpreter scripts and module entrypoints
    // cannot be approved before script bytes are frozen and bound to nonce.
    // This intentionally disables previously supported C3 script execution.
    if matches!(prog_family.as_str(), "shell" | "python" | "node" | "perl" | "ruby")
        || matches!(prog_name.as_str(), "php" | "lua")
    {
        return c4_denied(
            proposal,
            resolved_opt,
            canonical_opt,
            Some(prog_family),
            "interpreter execution disabled pending SC-03 immutable artifact approval",
        );
    }

    // 3. Check `env` command wrapper bypasses (`env bash -c ...`, `env LD_PRELOAD=...`)
    if prog_name == "env" || prog_family == "env" {
        return c4_denied(
            proposal,
            resolved_opt,
            canonical_opt,
            Some(prog_family),
            "禁止通过 env 间接包装执行命令或注入环境变量",
        );
    }

    // 4. Hard C4 checks on `dd`, `rm`, `chown`, `chmod`, `chgrp`, shells, inline interpreters, `tar`, `awk`, `git -c`, `rg --pre`, `find -exec`
    if let Some(c4_reason) =
        check_command_specific_c4_blocks(core, proposal, &prog_name, &prog_family)
    {
        return c4_denied(
            proposal,
            resolved_opt,
            canonical_opt,
            Some(prog_family),
            c4_reason,
        );
    }

    // 5. Check known `C3SystemModify` commands (works even when optional host tools like `cargo`/`pip` are uninstalled)
    if let Some((c3_eff, c3_reason, need_workspace_rw)) =
        check_known_c3_commands(core, proposal, &prog_name, &prog_family)
    {
        let mut rw_mounts = Vec::new();
        if need_workspace_rw {
            match verify_scoped_path(core, &proposal.cwd, false) {
                ScopedPathVerdict::Authorized { mount_root, .. } => rw_mounts.push(mount_root),
                ScopedPathVerdict::Forbidden(reason) => {
                    return c4_denied(
                        proposal,
                        resolved_opt,
                        canonical_opt,
                        Some(prog_family),
                        reason,
                    );
                }
                ScopedPathVerdict::OutsideAuthorizedScope(p) => {
                    // Package/service commands (`apt-get`, `systemctl`) don't write to `cwd`,
                    // whereas project scripts (`python3 script.py`, `bash build.sh`) MUST live in authorized scope!
                    if matches!(
                        prog_family.as_str(),
                        "shell" | "python" | "node" | "perl" | "ruby"
                    ) {
                        return c4_denied(
                            proposal,
                            resolved_opt,
                            canonical_opt,
                            Some(prog_family),
                            format!(
                                "拒绝在授权工作区范围外运行解释器脚本 (cwd: {})",
                                p.display()
                            ),
                        );
                    }
                }
            }
            for rp in &proposal.required_paths {
                let resolved_rp = resolve_against_cwd(&proposal.cwd, &rp.to_string_lossy());
                match verify_scoped_path(core, &resolved_rp, false) {
                    ScopedPathVerdict::Authorized { mount_root, .. } => {
                        if !rw_mounts.contains(&mount_root) {
                            rw_mounts.push(mount_root);
                        }
                    }
                    ScopedPathVerdict::Forbidden(reason) => {
                        return c4_denied(
                            proposal,
                            resolved_opt,
                            canonical_opt,
                            Some(prog_family),
                            reason,
                        );
                    }
                    ScopedPathVerdict::OutsideAuthorizedScope(_) => {}
                }
            }
        }
        return c3_modify(
            proposal,
            resolved_opt,
            canonical_opt,
            Some(prog_family),
            c3_eff,
            Vec::new(),
            rw_mounts,
            c3_reason,
        );
    }

    // Beyond this point, `C0`, `C1`, and `C2` REQUIRE a verified installed binary in `trusted_bin_dirs`!
    if resolved_opt.is_none() {
        return c4_denied(
            proposal,
            None,
            None,
            Some(prog_family),
            format!(
                "未在可信系统目录 ({}) 中找到受控命令 '{}'",
                DEFAULT_TRUSTED_BIN_DIRS.join(", "),
                proposal.program
            ),
        );
    }

    // 6. Try `C0ReadOnlyDiag`
    if proposal.required_paths.is_empty()
        && let Some(c0_reason) = try_classify_c0(&prog_name, &prog_family, &proposal.argv)
    {
        let mut ro_mounts = Vec::new();
        if let ScopedPathVerdict::Authorized { mount_root, .. } =
            verify_scoped_path(core, &proposal.cwd, false)
        {
            ro_mounts.push(mount_root);
        }
        return finalize_classification(
            proposal,
            CommandClassification {
                tier: TerminalSafetyTier::C0ReadOnlyDiag,
                effective_effect: Effect::Observe,
                effects: vec![Effect::Observe],
                reversible: false,
                requires_approval: false,
                denied: false,
                resolved_executable: resolved_opt,
                canonical_executable: canonical_opt,
                canonical_family: Some(prog_family),
                verified_readonly_paths: ro_mounts,
                verified_readwrite_paths: Vec::new(),
                c2_plan: None,
                downgrade_attempt_blocked: false,
                reasons: vec![c0_reason],
            },
        );
    }

    // 7. Try `C1ScopedRead`
    match try_classify_c1(core, proposal, &prog_name, &prog_family) {
        C1Attempt::Matched { ro_mounts, reason } => {
            return finalize_classification(
                proposal,
                CommandClassification {
                    tier: TerminalSafetyTier::C1ScopedRead,
                    effective_effect: Effect::Observe,
                    effects: vec![Effect::Observe],
                    reversible: false,
                    requires_approval: false,
                    denied: false,
                    resolved_executable: resolved_opt,
                    canonical_executable: canonical_opt,
                    canonical_family: Some(prog_family),
                    verified_readonly_paths: ro_mounts,
                    verified_readwrite_paths: Vec::new(),
                    c2_plan: None,
                    downgrade_attempt_blocked: false,
                    reasons: vec![reason],
                },
            );
        }
        C1Attempt::Forbidden(reason) => {
            return c4_denied(
                proposal,
                resolved_opt,
                canonical_opt,
                Some(prog_family),
                reason,
            );
        }
        C1Attempt::OutsideScope(p) => {
            return c3_modify(
                proposal,
                resolved_opt,
                canonical_opt,
                Some(prog_family),
                Effect::Observe,
                vec![p.clone()],
                Vec::new(),
                format!(
                    "读取路径超出已授权目录范围 ({})，已升级出 C1 并要求人工确认",
                    p.display()
                ),
            );
        }
        C1Attempt::NotC1 => {}
    }

    // 8. Try `C2ReversibleWrite` (`mkdir`, `touch`, `cp`, `mv`, `sed -i` inside authorized workspace)
    match try_classify_c2(core, proposal, &prog_name, &prog_family) {
        C2Attempt::Matched {
            rw_mounts,
            plan,
            reversible,
            reason,
        } => {
            let eff = if reversible {
                Effect::WriteReversible
            } else {
                Effect::WriteDestructive
            };
            return finalize_classification(
                proposal,
                CommandClassification {
                    tier: TerminalSafetyTier::C2ReversibleWrite,
                    effective_effect: eff,
                    effects: vec![eff],
                    reversible,
                    requires_approval: true,
                    denied: false,
                    resolved_executable: resolved_opt,
                    canonical_executable: canonical_opt,
                    canonical_family: Some(prog_family),
                    verified_readonly_paths: Vec::new(),
                    verified_readwrite_paths: rw_mounts,
                    c2_plan: Some(plan),
                    downgrade_attempt_blocked: false,
                    reasons: vec![reason],
                },
            );
        }
        C2Attempt::Forbidden(reason) => {
            return c4_denied(
                proposal,
                resolved_opt,
                canonical_opt,
                Some(prog_family),
                reason,
            );
        }
        C2Attempt::NotC2 => {}
    }

    // 9. Conservative fallback for any remaining resolved system binary -> `C3SystemModify` (`RequiresApproval`, `reversible: false`)
    let mut ro_mounts = Vec::new();
    let mut rw_mounts = Vec::new();
    match verify_scoped_path(core, &proposal.cwd, false) {
        ScopedPathVerdict::Authorized { mount_root, .. } => {
            ro_mounts.push(mount_root.clone());
            rw_mounts.push(mount_root);
        }
        ScopedPathVerdict::Forbidden(reason) => {
            return c4_denied(
                proposal,
                resolved_opt,
                canonical_opt,
                Some(prog_family),
                reason,
            );
        }
        ScopedPathVerdict::OutsideAuthorizedScope(_) => {}
    }

    c3_modify(
        proposal,
        resolved_opt,
        canonical_opt,
        Some(prog_family),
        Effect::WriteDestructive,
        ro_mounts,
        rw_mounts,
        format!(
            "命令 '{}' 不属于 C0/C1/C2 白名单，默认归类为 C3SystemModify（需人工审批，不可自动撤销）",
            proposal.program
        ),
    )
}

fn collect_verified_paths_for_write(
    core: &IntentOsCore,
    proposal: &CommandProposal,
    paths: &[PathBuf],
    rw_mounts: &mut Vec<PathBuf>,
) -> Result<(), Box<CommandClassification>> {
    for p in paths {
        let resolved = resolve_against_cwd(&proposal.cwd, &p.to_string_lossy());
        match verify_scoped_path(core, &resolved, true) {
            ScopedPathVerdict::Authorized { mount_root, .. } => {
                if !rw_mounts.contains(&mount_root) {
                    rw_mounts.push(mount_root);
                }
            }
            ScopedPathVerdict::OutsideAuthorizedScope(out_p) => {
                return Err(Box::new(c4_denied(
                    proposal,
                    None,
                    None,
                    None,
                    format!(
                        "拒绝在授权工作区范围外执行终端修改操作: {}",
                        out_p.display()
                    ),
                )));
            }
            ScopedPathVerdict::Forbidden(reason) => {
                return Err(Box::new(c4_denied(proposal, None, None, None, reason)));
            }
        }
    }
    Ok(())
}

fn has_short_flag_char(arg: &str, ch: char) -> bool {
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() < 2 {
        return false;
    }
    arg[1..].chars().any(|c| c == ch)
}

fn check_command_specific_c4_blocks(
    core: &IntentOsCore,
    proposal: &CommandProposal,
    prog_name: &str,
    prog_family: &str,
) -> Option<String> {
    let argv = &proposal.argv;

    // 1. Shell inline code bypass (`bash -c`, `sh -c`, `dash -c`, `zsh -c`) or interactive shell without script
    if prog_family == "shell" {
        if argv.is_empty() {
            return Some("严禁在受控终端启动无参交互式 Shell".to_string());
        }
        for arg in argv {
            if arg == "-c"
                || arg == "-s"
                || arg == "-i"
                || has_short_flag_char(arg, 'c')
                || arg.starts_with("--rcfile")
                || arg.starts_with("--init-file")
            {
                return Some(format!(
                    "严禁通过 '{} {}' 执行内联 Shell 字符串代码（违反结构化 argv 安全边界）",
                    proposal.program, arg
                ));
            }
        }
    }

    // 2. Interpreter inline code bypass (`python3 -c`, `node -e/--eval/-p`, `perl -e/-E`, `ruby -e`, `php -r`)
    match prog_family {
        "python" => {
            if argv.is_empty() || argv.iter().any(|a| a == "-") {
                return Some("严禁启动无参交互式 Python 或标准输入代码执行".to_string());
            }
            for arg in argv {
                if arg == "-c" || arg.starts_with("-c") {
                    return Some("严禁通过 'python3 -c' 执行内联代码绕过检查".to_string());
                }
            }
        }
        "node" => {
            if argv.is_empty() {
                return Some("严禁启动无参交互式 Node REPL".to_string());
            }
            for arg in argv {
                if matches!(
                    arg.as_str(),
                    "-e" | "--eval" | "-p" | "--print" | "-i" | "--interactive"
                ) || arg.starts_with("--eval=")
                    || arg.starts_with("--print=")
                    || arg.starts_with("--import")
                    || arg.starts_with("--require")
                    || arg == "-r"
                {
                    return Some(format!("严禁通过 'node {}' 执行内联脚本或模块注入", arg));
                }
            }
        }
        "perl" | "ruby" => {
            if argv.is_empty() {
                return Some(format!("严禁启动无参 {} 解释器", prog_family));
            }
            for arg in argv {
                if matches!(arg.as_str(), "-e" | "-E")
                    || arg.starts_with("-e")
                    || arg.starts_with("-E")
                {
                    return Some(format!(
                        "严禁通过 '{} {}' 执行内联代码绕过检查",
                        prog_name, arg
                    ));
                }
            }
        }
        _ => {}
    }
    if matches!(prog_name, "php" | "lua")
        && argv
            .iter()
            .any(|a| a == "-r" || a == "-e" || a.starts_with("-r") || a.starts_with("-e"))
    {
        return Some(format!("严禁通过 '{} -e/-r' 执行内联代码", prog_name));
    }

    // 2b. Interpreter / shell script path MUST reside inside an authorized workspace root
    if matches!(prog_family, "shell" | "python" | "node" | "perl" | "ruby") {
        let is_python_module = prog_family == "python" && argv.iter().any(|a| a == "-m");
        if !is_python_module && let Some(raw_script) = argv.iter().find(|a| !a.starts_with('-')) {
            let script_path = resolve_against_cwd(&proposal.cwd, raw_script);
            match verify_scoped_path(core, &script_path, false) {
                ScopedPathVerdict::Authorized { .. } => {}
                ScopedPathVerdict::OutsideAuthorizedScope(out_p) => {
                    return Some(format!(
                        "C4 严禁运行授权工作区范围外的解释器或 Shell 脚本: {}",
                        out_p.display()
                    ));
                }
                ScopedPathVerdict::Forbidden(reason) => return Some(reason),
            }
        }
    }

    // 3. `dd` writing to `/dev/*` or system directories
    if prog_family == "dd" || prog_name == "dd" {
        for arg in argv {
            if let Some(of_val) = arg.strip_prefix("of=") {
                let target = resolve_against_cwd(&proposal.cwd, of_val);
                if target.starts_with("/dev") || is_system_critical_dir(&target) {
                    return Some(format!(
                        "C4 严禁 dd 写入块设备或系统目录: {}",
                        target.display()
                    ));
                }
                if !matches!(
                    verify_scoped_path(core, &target, false),
                    ScopedPathVerdict::Authorized { .. }
                ) {
                    return Some(format!(
                        "C4 严禁 dd 写入授权工作区外的路径: {}",
                        target.display()
                    ));
                }
            }
            if let Some(if_val) = arg.strip_prefix("if=") {
                let src = resolve_against_cwd(&proposal.cwd, if_val);
                if src.starts_with("/dev")
                    && src != Path::new("/dev/zero")
                    && src != Path::new("/dev/urandom")
                    && src != Path::new("/dev/null")
                {
                    return Some(format!("C4 严禁 dd 直接读取原始设备: {}", src.display()));
                }
            }
        }
    }

    // 4. `rm` / `shred` targeting `/`, `$HOME`, system dirs, or outside authorized workspace
    if matches!(prog_family, "rm" | "rmdir")
        || matches!(prog_name, "rm" | "rmdir" | "shred" | "unlink")
    {
        let mut positional = Vec::new();
        let mut after_dd = false;
        for arg in argv {
            if !after_dd && arg == "--" {
                after_dd = true;
                continue;
            }
            if !after_dd && arg.starts_with('-') {
                if arg == "--no-preserve-root" {
                    return Some("C4 严禁使用 --no-preserve-root".to_string());
                }
                continue;
            }
            positional.push(arg.as_str());
        }
        for raw_p in positional {
            if is_home_root_or_wildcard(raw_p) {
                return Some(format!("C4 严禁删除根目录或用户主目录 ('{}')", raw_p));
            }
            let target = resolve_against_cwd(&proposal.cwd, raw_p);
            if is_system_critical_dir(&target) {
                return Some(format!("C4 严禁删除系统关键目录: {}", target.display()));
            }
            if !matches!(
                verify_scoped_path(core, &target, false),
                ScopedPathVerdict::Authorized { .. }
            ) {
                return Some(format!(
                    "C4 严禁删除未授权目录中的文件: {}",
                    target.display()
                ));
            }
        }
    }

    // 5. `chown` / `chmod` / `chgrp` on system dirs, setuid bits, or outside authorized workspace
    if matches!(prog_family, "chown" | "chmod" | "chgrp") {
        let mut non_flags = Vec::new();
        let mut after_dd = false;
        for arg in argv {
            if !after_dd && arg == "--" {
                after_dd = true;
                continue;
            }
            if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                continue;
            }
            non_flags.push(arg.as_str());
        }
        if prog_family == "chmod"
            && let Some(mode_str) = non_flags.first()
            && (mode_str.contains("+s")
                || mode_str.contains("=s")
                || (mode_str.len() == 4
                    && mode_str.chars().all(|c| c.is_ascii_digit())
                    && !mode_str.starts_with('0')))
        {
            return Some(format!(
                "C4 严禁设置 setuid/setgid 特殊权限位 ({})",
                mode_str
            ));
        }
        for path_arg in non_flags.iter().skip(1) {
            let target = resolve_against_cwd(&proposal.cwd, path_arg);
            if is_system_critical_dir(&target) {
                return Some(format!(
                    "C4 严禁修改系统目录权限或属主: {}",
                    target.display()
                ));
            }
            if !matches!(
                verify_scoped_path(core, &target, false),
                ScopedPathVerdict::Authorized { .. }
            ) {
                return Some(format!(
                    "C4 严禁在授权工作区外执行 {}: {}",
                    prog_family,
                    target.display()
                ));
            }
        }
    }

    // 6. `awk` with `system(` or pipe command execution
    if prog_family == "awk" {
        for arg in argv {
            if arg.contains("system(")
                || arg.contains("system (")
                || arg.contains("| getline")
                || arg.contains("|getline")
            {
                return Some("C4 严禁 awk 脚本包含 system() 或管道子进程执行".to_string());
            }
        }
    }

    // 7. `tar` arbitrary command execution flags (`--checkpoint-action`, `--to-command`, `--use-compress-program`)
    if prog_name == "tar" || prog_family == "tar" {
        for arg in argv {
            if arg.starts_with("--checkpoint-action")
                || arg.starts_with("--to-command")
                || arg.starts_with("--use-compress-program")
                || arg == "-I"
                || arg == "-P"
                || arg == "--absolute-names"
            {
                return Some(format!("C4 严禁 tar 危险参数 '{}'", arg));
            }
        }
    }

    // 8. `find` subprocess execution (`-exec`, `-execdir`, `-ok`, `-okdir`) or unauthorized `-delete`/`-fprint`
    if prog_name == "find" || prog_family == "find" {
        for (idx, arg) in argv.iter().enumerate() {
            if matches!(arg.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
                return Some(format!("C4 严禁 find 使用 '{}' 间接执行任意子进程", arg));
            }
            if matches!(arg.as_str(), "-fprint" | "-fprint0" | "-fprintf" | "-fls") {
                if let Some(out_file) = argv.get(idx + 1) {
                    let target = resolve_against_cwd(&proposal.cwd, out_file);
                    if !matches!(
                        verify_scoped_path(core, &target, false),
                        ScopedPathVerdict::Authorized { .. }
                    ) {
                        return Some(format!(
                            "C4 严禁 find {} 写入未授权路径: {}",
                            arg,
                            target.display()
                        ));
                    }
                } else {
                    return Some(format!("find '{}' 缺少合法输出文件路径", arg));
                }
            }
        }
        if argv.iter().any(|a| a == "-delete") {
            let start_paths = extract_find_start_paths(proposal);
            for sp in start_paths {
                if !matches!(
                    verify_scoped_path(core, &sp, true),
                    ScopedPathVerdict::Authorized { .. }
                ) {
                    return Some(format!(
                        "C4 严禁在授权工作区外执行 find -delete: {}",
                        sp.display()
                    ));
                }
            }
        }
    }

    // 9. `sed` GNU `/e` shell execution modifier or unauthorized `-i` write
    if prog_name == "sed" || prog_family == "sed" {
        for arg in argv {
            if arg == "-f" || arg.starts_with("--file") {
                return Some("C4 严禁 sed 加载外部脚本文件 (-f/--file)".to_string());
            }
            // Detect `s/.../.../e` shell execution modifier in sed expressions
            if (arg.starts_with("s/") || arg.starts_with("s|") || arg.starts_with("s#"))
                && (arg.ends_with("/e")
                    || arg.ends_with("/ge")
                    || arg.ends_with("/eg")
                    || arg.ends_with("|e")
                    || arg.ends_with("#e"))
            {
                return Some("C4 严禁 sed 替换表达式使用 /e 执行任意外部命令".to_string());
            }
        }
    }

    // 10. `rg` preprocessor (`--pre`) arbitrary command execution
    if prog_family == "rg" {
        for arg in argv {
            if arg == "--pre" || arg.starts_with("--pre=") {
                return Some("C4 严禁 rg 使用 --pre 执行任意预处理器程序".to_string());
            }
        }
    }

    // 11. `git` config injection (`-c core.sshCommand=...`, `--exec-path`, `--upload-pack`)
    if prog_name == "git" || prog_family == "git" {
        for arg in argv {
            if arg == "-c"
                || arg.starts_with("-c") && arg.contains('=')
                || arg == "--config-env"
                || arg.starts_with("--config-env=")
                || arg.starts_with("--exec-path")
                || arg.starts_with("--upload-pack")
                || arg.starts_with("--receive-pack")
            {
                return Some(format!("C4 严禁 git 注入配置或外部命令钩子参数 '{}'", arg));
            }
        }
    }

    // 12. `ip netns exec` arbitrary command execution
    if prog_name == "ip"
        && argv
            .windows(2)
            .any(|w| w[0].starts_with("netns") && w[1].starts_with("exec"))
    {
        return Some("C4 严禁通过 'ip netns exec' 间接执行子进程".to_string());
    }

    // 13. `systemctl` system power/isolation verbs
    if prog_name == "systemctl" {
        for arg in argv {
            if matches!(
                arg.as_str(),
                "reboot" | "poweroff" | "halt" | "kexec" | "rescue" | "emergency" | "isolate"
            ) {
                return Some(format!(
                    "C4 严禁通过 systemctl 执行系统级关机或紧急切换动词 '{}'",
                    arg
                ));
            }
        }
    }

    // 14. `curl` / `wget` local `file://` read or unauthorized `-o` / `--output` write outside workspace
    if matches!(prog_name, "curl" | "wget") {
        let mut idx = 0usize;
        while idx < argv.len() {
            let arg = &argv[idx];
            let lower = arg.to_ascii_lowercase();
            if lower.starts_with("file://")
                || lower.starts_with("gopher://")
                || lower.starts_with("dict://")
                || lower.starts_with("ldap://")
            {
                return Some(format!(
                    "C4 严禁 {} 访问非 HTTP/HTTPS 协议: {}",
                    prog_name, arg
                ));
            }
            let out_target_opt =
                if matches!(arg.as_str(), "-o" | "--output" | "-O") && prog_name == "curl" {
                    if arg == "-O" {
                        Some(proposal.cwd.join("curl_download"))
                    } else {
                        argv.get(idx + 1)
                            .map(|v| resolve_against_cwd(&proposal.cwd, v))
                    }
                } else if let Some(v) = arg.strip_prefix("--output=") {
                    Some(resolve_against_cwd(&proposal.cwd, v))
                } else if prog_name == "wget" && matches!(arg.as_str(), "-O" | "-P") {
                    argv.get(idx + 1)
                        .map(|v| resolve_against_cwd(&proposal.cwd, v))
                } else {
                    None
                };
            if let Some(target) = out_target_opt
                && !matches!(
                    verify_scoped_path(core, &target, false),
                    ScopedPathVerdict::Authorized { .. }
                )
            {
                return Some(format!(
                    "C4 严禁 {} 将下载内容写入未授权目录: {}",
                    prog_name,
                    target.display()
                ));
            }
            idx += 1;
        }
    }

    None
}

fn check_known_c3_commands(
    core: &IntentOsCore,
    proposal: &CommandProposal,
    prog_name: &str,
    prog_family: &str,
) -> Option<(Effect, String, bool)> {
    let argv = &proposal.argv;

    // 1. System package managers (`apt`, `apt-get`, `dpkg`, `snap`, `flatpak`)
    if matches!(prog_name, "apt" | "apt-get" | "dpkg" | "snap" | "flatpak") || prog_family == "snap"
    {
        return Some((
            Effect::SystemAdmin,
            format!(
                "软件包管理操作 ('{}') 属于 C3SystemModify，必须人工审批且不可自动撤销 (reversible: false)",
                prog_name
            ),
            false,
        ));
    }

    // 2. `systemctl` mutating verbs (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, etc.)
    if prog_name == "systemctl" {
        let mutating = argv.iter().any(|a| {
            matches!(
                a.as_str(),
                "start"
                    | "stop"
                    | "restart"
                    | "reload"
                    | "try-restart"
                    | "reload-or-restart"
                    | "enable"
                    | "disable"
                    | "reenable"
                    | "mask"
                    | "unmask"
                    | "daemon-reload"
                    | "reset-failed"
                    | "kill"
                    | "set-property"
                    | "import-environment"
                    | "set-environment"
                    | "unset-environment"
            )
        });
        if mutating {
            return Some((
                Effect::SystemAdmin,
                "systemd 服务状态/自启变更属于 C3SystemModify，必须人工审批且不可自动撤销 (reversible: false)".to_string(),
                false,
            ));
        }
    }

    // 3. Language / build / package toolchains (`pip`, `pip3`, `uv`, `cargo`, `npm`, `pnpm`, `yarn`, `make`, `cmake`)
    if matches!(
        prog_name,
        "pip"
            | "pip3"
            | "uv"
            | "cargo"
            | "npm"
            | "pnpm"
            | "yarn"
            | "make"
            | "cmake"
            | "ninja"
            | "pytest"
    ) {
        return Some((
            Effect::WriteDestructive,
            format!(
                "开发环境构建或依赖变更 ('{}') 属于 C3SystemModify，必须人工审批且不可自动撤销",
                prog_name
            ),
            true,
        ));
    }

    // 4. Interpreter / shell running an authorized project script file (`python3 script.py`, `node app.js`, `bash build.sh`)
    if matches!(prog_family, "shell" | "python" | "node" | "perl" | "ruby") {
        let _ = core;
        return Some((
            Effect::WriteDestructive,
            format!(
                "运行项目解释器脚本 ('{}') 属于 C3SystemModify，必须人工审批且不可自动撤销",
                proposal.program
            ),
            true,
        ));
    }

    // 5. Network transfer / git remote / destructive git commands (`curl`, `wget`, `git clean/reset/push/pull/fetch/clone`)
    if matches!(prog_name, "curl" | "wget" | "rsync" | "ssh" | "scp") {
        let has_upload = argv.iter().any(|a| {
            matches!(
                a.as_str(),
                "-d" | "--data" | "--data-raw" | "--data-binary" | "-F" | "-T" | "--upload-file"
            ) || a.starts_with("--data")
        });
        let eff = if has_upload {
            Effect::ExternalCommit
        } else {
            Effect::WriteDestructive
        };
        return Some((
            eff,
            format!(
                "网络请求或传输命令 ('{}') 属于 C3SystemModify，严禁归入 C0/C1，必须人工审批",
                prog_name
            ),
            true,
        ));
    }

    if prog_name == "git" || prog_family == "git" {
        let subcmd = extract_git_subcommand(argv).map(|(_, sub, _)| sub);
        if let Some(sub) = subcmd
            && !matches!(sub, "status" | "log" | "diff" | "show" | "branch")
        {
            let eff = if matches!(sub, "push") {
                Effect::ExternalCommit
            } else {
                Effect::WriteDestructive
            };
            return Some((
                eff,
                format!(
                    "Git 变更/远端命令 ('git {}') 属于 C3SystemModify，必须人工审批且不可自动撤销",
                    sub
                ),
                true,
            ));
        }
    }

    // 6. `find -delete` / `find -fprint*` inside authorized workspace -> C3SystemModify
    if (prog_name == "find" || prog_family == "find")
        && argv.iter().any(|a| {
            matches!(
                a.as_str(),
                "-delete" | "-fprint" | "-fprint0" | "-fprintf" | "-fls"
            )
        })
    {
        return Some((
            Effect::WriteDestructive,
            "find 含写入或删除动作 (-delete/-fprint)，升级为 C3SystemModify（需人工审批，不可自动撤销）".to_string(),
            true,
        ));
    }

    // 7. `rm` inside authorized workspace -> C3SystemModify (`WriteDestructive`, `reversible: false`)
    if matches!(prog_family, "rm" | "rmdir") {
        return Some((
            Effect::WriteDestructive,
            "终端直接删除命令 (rm/rmdir) 不可自动撤销，归类为 C3SystemModify 并强制人工确认"
                .to_string(),
            true,
        ));
    }

    None
}

fn try_classify_c0(prog_name: &str, prog_family: &str, argv: &[String]) -> Option<String> {
    match prog_family {
        "df" => {
            for arg in argv {
                if !matches!(
                    arg.as_str(),
                    "-h" | "--human-readable"
                        | "-H"
                        | "--si"
                        | "-T"
                        | "--print-type"
                        | "-P"
                        | "--portability"
                        | "-i"
                        | "--inodes"
                        | "-k"
                        | "-m"
                        | "-l"
                        | "--local"
                        | "--total"
                        | "/"
                ) && !arg.starts_with("--output")
                    && !arg.starts_with("-x")
                    && !arg.starts_with("--exclude-type=")
                    && !arg.starts_with("-t")
                    && !arg.starts_with("--type=")
                {
                    return None;
                }
            }
            Some("C0 只读系统磁盘空间诊断 (df)".to_string())
        }
        "free" => {
            for arg in argv {
                if !matches!(
                    arg.as_str(),
                    "-b" | "-k"
                        | "-m"
                        | "-g"
                        | "--tera"
                        | "--peta"
                        | "-h"
                        | "--human"
                        | "--si"
                        | "-l"
                        | "--lohi"
                        | "-t"
                        | "--total"
                        | "-w"
                        | "--wide"
                ) {
                    return None;
                }
            }
            Some("C0 只读系统内存与交换分区诊断 (free)".to_string())
        }
        "uname" => {
            for arg in argv {
                if !matches!(
                    arg.as_str(),
                    "-a" | "-s"
                        | "-n"
                        | "-r"
                        | "-v"
                        | "-m"
                        | "-p"
                        | "-i"
                        | "-o"
                        | "--all"
                        | "--kernel-name"
                        | "--nodename"
                        | "--kernel-release"
                        | "--kernel-version"
                        | "--machine"
                        | "--operating-system"
                ) {
                    return None;
                }
            }
            Some("C0 只读内核与架构信息查询 (uname)".to_string())
        }
        "uptime" => {
            for arg in argv {
                if !matches!(arg.as_str(), "-p" | "--pretty" | "-s" | "--since") {
                    return None;
                }
            }
            Some("C0 只读系统运行时间与负载查询 (uptime)".to_string())
        }
        "id" => {
            for arg in argv {
                if !matches!(
                    arg.as_str(),
                    "-u" | "-g" | "-G" | "-n" | "-r" | "-un" | "-gn" | "-Gn"
                ) {
                    return None;
                }
            }
            Some("C0 只读当前用户身份查询 (id)".to_string())
        }
        "whoami" => {
            if !argv.is_empty() {
                return None;
            }
            Some("C0 只读当前用户名查询 (whoami)".to_string())
        }
        "date" => {
            for arg in argv {
                if arg == "-s"
                    || arg.starts_with("--set")
                    || arg == "-f"
                    || arg.starts_with("--file")
                {
                    return None;
                }
                if !(matches!(arg.as_str(), "-u" | "--utc" | "-R" | "--rfc-email" | "-I")
                    || arg.starts_with("--iso-8601")
                    || arg.starts_with('+'))
                {
                    return None;
                }
            }
            Some("C0 只读系统时间读取 (date)".to_string())
        }
        _ => match prog_name {
            "lscpu" => {
                for arg in argv {
                    if !matches!(
                        arg.as_str(),
                        "-J" | "--json" | "-B" | "--bytes" | "-a" | "-b" | "-c"
                    ) && !arg.starts_with("-e")
                        && !arg.starts_with("--extended")
                        && !arg.starts_with("-p")
                        && !arg.starts_with("--parse")
                    {
                        return None;
                    }
                }
                Some("C0 只读 CPU 拓扑诊断 (lscpu)".to_string())
            }
            "lsblk" => {
                let mut skip_next = false;
                for arg in argv {
                    if skip_next {
                        if arg.starts_with('-') || arg.contains('/') {
                            return None;
                        }
                        skip_next = false;
                        continue;
                    }
                    if matches!(arg.as_str(), "-o" | "--output") {
                        skip_next = true;
                        continue;
                    }
                    if !matches!(
                        arg.as_str(),
                        "-J" | "--json"
                            | "-f"
                            | "--fs"
                            | "-b"
                            | "--bytes"
                            | "-a"
                            | "--all"
                            | "-d"
                            | "--nodeps"
                            | "-p"
                            | "--paths"
                            | "-n"
                            | "--noheadings"
                            | "-l"
                            | "--list"
                    ) && !arg.starts_with("--output=")
                    {
                        return None;
                    }
                }
                if skip_next {
                    return None;
                }
                Some("C0 只读块设备拓扑诊断 (lsblk)".to_string())
            }
            "ps" => {
                let mut skip_next = false;
                for arg in argv {
                    if skip_next {
                        if arg.contains('/') {
                            return None;
                        }
                        skip_next = false;
                        continue;
                    }
                    if matches!(arg.as_str(), "-o" | "-p" | "-u" | "-C") {
                        skip_next = true;
                        continue;
                    }
                    if !matches!(
                        arg.as_str(),
                        "aux"
                            | "ax"
                            | "-ef"
                            | "-e"
                            | "-A"
                            | "-f"
                            | "-F"
                            | "-l"
                            | "-eo"
                            | "--no-headers"
                    ) && !arg.starts_with("--sort=")
                    {
                        return None;
                    }
                }
                if skip_next {
                    return None;
                }
                Some("C0 只读进程快照采样 (ps)".to_string())
            }
            "ip" => {
                let mut idx = 0usize;
                while idx < argv.len() {
                    let a = argv[idx].as_str();
                    if matches!(
                        a,
                        "-j" | "-json" | "-4" | "-6" | "-br" | "-brief" | "-c" | "-d" | "-s" | "-o"
                    ) {
                        idx += 1;
                    } else {
                        break;
                    }
                }
                let obj = argv.get(idx)?.as_str();
                if !matches!(obj, "addr" | "address" | "a" | "route" | "r" | "link" | "l") {
                    return None;
                }
                for rest in &argv[idx + 1..] {
                    if !matches!(rest.as_str(), "show" | "list" | "ls") {
                        return None;
                    }
                }
                Some(format!("C0 只读网络接口/路由观察 (ip {})", obj))
            }
            "ss" => {
                for arg in argv {
                    if arg == "-K" || arg == "--kill" || !arg.starts_with('-') {
                        return None;
                    }
                    if arg.starts_with("--") {
                        if !matches!(
                            arg.as_str(),
                            "--tcp"
                                | "--udp"
                                | "--listening"
                                | "--numeric"
                                | "--processes"
                                | "--all"
                                | "--ipv4"
                                | "--ipv6"
                                | "--summary"
                                | "--no-header"
                        ) {
                            return None;
                        }
                    } else if !arg[1..].chars().all(|c| {
                        matches!(
                            c,
                            't' | 'u'
                                | 'l'
                                | 'n'
                                | 'p'
                                | 'a'
                                | '4'
                                | '6'
                                | 's'
                                | 'H'
                                | 'e'
                                | 'm'
                                | 'i'
                        )
                    }) {
                        return None;
                    }
                }
                Some("C0 只读套接字监听诊断 (ss)".to_string())
            }
            "systemctl" => {
                let mut verb: Option<&str> = None;
                let mut unit_count = 0usize;
                let mut skip_next = false;
                for arg in argv {
                    if skip_next {
                        skip_next = false;
                        continue;
                    }
                    if matches!(
                        arg.as_str(),
                        "-n" | "--lines" | "-p" | "--property" | "-t" | "--type" | "--state"
                    ) {
                        skip_next = true;
                        continue;
                    }
                    if arg.starts_with('-') {
                        if !matches!(
                            arg.as_str(),
                            "--user"
                                | "--system"
                                | "--no-pager"
                                | "-l"
                                | "--full"
                                | "--plain"
                                | "--no-legend"
                                | "-q"
                                | "--quiet"
                        ) && !arg.starts_with("--lines=")
                            && !arg.starts_with("--property=")
                            && !arg.starts_with("--type=")
                            && !arg.starts_with("--state=")
                        {
                            return None;
                        }
                        continue;
                    }
                    if verb.is_none() {
                        if matches!(
                            arg.as_str(),
                            "status"
                                | "is-active"
                                | "is-enabled"
                                | "is-failed"
                                | "list-units"
                                | "list-unit-files"
                                | "list-timers"
                                | "show"
                        ) {
                            verb = Some(arg.as_str());
                        } else {
                            return None;
                        }
                    } else {
                        if arg.contains('/') || arg.contains("..") {
                            return None;
                        }
                        unit_count += 1;
                        if unit_count > 4 {
                            return None;
                        }
                    }
                }
                let v = verb?;
                Some(format!("C0 只读 systemd 服务状态查询 (systemctl {})", v))
            }
            _ => None,
        },
    }
}

enum C1Attempt {
    Matched {
        ro_mounts: Vec<PathBuf>,
        reason: String,
    },
    OutsideScope(PathBuf),
    Forbidden(String),
    NotC1,
}

fn extract_git_subcommand(argv: &[String]) -> Option<(Option<&str>, &str, &[String])> {
    let mut idx = 0usize;
    let mut repo_c: Option<&str> = None;
    while idx < argv.len() {
        let a = argv[idx].as_str();
        if a == "-C" {
            repo_c = argv.get(idx + 1).map(String::as_str);
            idx += 2;
            continue;
        }
        if matches!(a, "--no-pager" | "-P" | "--no-optional-locks") {
            idx += 1;
            continue;
        }
        if a.starts_with('-') {
            return None;
        }
        return Some((repo_c, a, &argv[idx + 1..]));
    }
    None
}

fn extract_find_start_paths(proposal: &CommandProposal) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for arg in &proposal.argv {
        if matches!(arg.as_str(), "-P" | "-O1" | "-O2" | "-O3") {
            continue;
        }
        if arg.starts_with('-') || matches!(arg.as_str(), "(" | ")" | "!" | ",") {
            break;
        }
        out.push(resolve_against_cwd(&proposal.cwd, arg));
    }
    if out.is_empty() {
        out.push(normalize_lexical_clean(&proposal.cwd));
    }
    out
}

fn try_classify_c1(
    core: &IntentOsCore,
    proposal: &CommandProposal,
    prog_name: &str,
    prog_family: &str,
) -> C1Attempt {
    let argv = &proposal.argv;
    let mut paths_to_verify: Vec<PathBuf> = vec![normalize_lexical_clean(&proposal.cwd)];
    for rp in &proposal.required_paths {
        paths_to_verify.push(resolve_against_cwd(&proposal.cwd, &rp.to_string_lossy()));
    }

    match prog_family {
        "ls" => {
            let mut after_dd = false;
            for arg in argv {
                if !after_dd && arg == "--" {
                    after_dd = true;
                    continue;
                }
                if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                    if arg == "-L" || arg == "--dereference" {
                        return C1Attempt::NotC1;
                    }
                    continue;
                }
                paths_to_verify.push(resolve_against_cwd(&proposal.cwd, arg));
            }
        }
        "stat" | "file" | "wc" | "sha256sum" | "du" => {
            let mut after_dd = false;
            let mut skip_next = false;
            for arg in argv {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if !after_dd && arg == "--" {
                    after_dd = true;
                    continue;
                }
                if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                    if matches!(
                        arg.as_str(),
                        "-L" | "--dereference"
                            | "-f"
                            | "--files-from"
                            | "--files0-from"
                            | "-c"
                            | "--check"
                    ) && prog_family != "stat"
                    {
                        return C1Attempt::NotC1;
                    }
                    if prog_family == "stat" && matches!(arg.as_str(), "-L" | "--dereference") {
                        return C1Attempt::NotC1;
                    }
                    if (prog_family == "stat"
                        && matches!(arg.as_str(), "-c" | "--format" | "--printf"))
                        || (prog_family == "du"
                            && matches!(arg.as_str(), "-d" | "--max-depth" | "--exclude"))
                    {
                        skip_next = true;
                    }
                    continue;
                }
                paths_to_verify.push(resolve_against_cwd(&proposal.cwd, arg));
            }
        }
        "head" | "tail" => {
            let mut after_dd = false;
            let mut skip_next = false;
            for arg in argv {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if !after_dd && arg == "--" {
                    after_dd = true;
                    continue;
                }
                if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                    if prog_family == "tail"
                        && (arg == "-f"
                            || arg == "-F"
                            || arg.starts_with("--follow")
                            || arg == "--retry"
                            || has_short_flag_char(arg, 'f')
                            || has_short_flag_char(arg, 'F'))
                    {
                        return C1Attempt::NotC1;
                    }
                    if matches!(arg.as_str(), "-n" | "--lines" | "-c" | "--bytes") {
                        skip_next = true;
                    }
                    continue;
                }
                paths_to_verify.push(resolve_against_cwd(&proposal.cwd, arg));
            }
        }
        "rg" | "grep" => {
            let mut after_dd = false;
            let mut skip_next = false;
            let mut skip_is_file = false;
            let mut explicit_pattern = false;
            let mut files_only_mode = false;
            let mut positional: Vec<&str> = Vec::new();

            for arg in argv {
                if skip_next {
                    if skip_is_file {
                        paths_to_verify.push(resolve_against_cwd(&proposal.cwd, arg));
                    }
                    skip_next = false;
                    skip_is_file = false;
                    continue;
                }
                if !after_dd && arg == "--" {
                    after_dd = true;
                    continue;
                }
                if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                    if matches!(
                        arg.as_str(),
                        "-L" | "--follow" | "-z" | "--search-zip" | "--pre"
                    ) || arg.starts_with("--pre=")
                    {
                        return C1Attempt::NotC1;
                    }
                    if arg == "--files" {
                        files_only_mode = true;
                        continue;
                    }
                    if matches!(arg.as_str(), "-e" | "--regexp") {
                        explicit_pattern = true;
                        skip_next = true;
                        continue;
                    }
                    if arg.starts_with("--regexp=") {
                        explicit_pattern = true;
                        continue;
                    }
                    if matches!(arg.as_str(), "-f" | "--file") {
                        explicit_pattern = true;
                        skip_next = true;
                        skip_is_file = true;
                        continue;
                    }
                    if let Some(fp) = arg.strip_prefix("--file=") {
                        explicit_pattern = true;
                        paths_to_verify.push(resolve_against_cwd(&proposal.cwd, fp));
                        continue;
                    }
                    if matches!(
                        arg.as_str(),
                        "-g" | "--glob"
                            | "-t"
                            | "--type"
                            | "-T"
                            | "--type-not"
                            | "-m"
                            | "--max-count"
                            | "-A"
                            | "-B"
                            | "-C"
                            | "--context"
                            | "--max-depth"
                            | "--max-filesize"
                            | "--include"
                            | "--exclude"
                            | "--exclude-dir"
                    ) {
                        skip_next = true;
                    }
                    continue;
                }
                positional.push(arg.as_str());
            }

            let path_slice = if explicit_pattern || files_only_mode {
                positional.as_slice()
            } else if positional.len() >= 2 {
                &positional[1..]
            } else {
                &[]
            };
            for p_str in path_slice {
                paths_to_verify.push(resolve_against_cwd(&proposal.cwd, p_str));
            }
        }
        _ => match prog_name {
            "git" => {
                let Some((repo_c, sub, rest)) = extract_git_subcommand(argv) else {
                    return C1Attempt::NotC1;
                };
                if !matches!(sub, "status" | "log" | "diff" | "show" | "branch") {
                    return C1Attempt::NotC1;
                }
                let base_repo = match repo_c {
                    Some(rc) => {
                        let resolved_rc = resolve_against_cwd(&proposal.cwd, rc);
                        paths_to_verify.push(resolved_rc.clone());
                        resolved_rc
                    }
                    None => normalize_lexical_clean(&proposal.cwd),
                };

                for r_arg in rest {
                    if r_arg.starts_with("--output") || r_arg == "--no-index" {
                        return C1Attempt::NotC1;
                    }
                }

                if sub == "branch" {
                    // `git branch <new_branch>` or `git branch -d/-D/-m/-M` mutates refs!
                    for r_arg in rest {
                        if !matches!(
                            r_arg.as_str(),
                            "-a" | "--all"
                                | "-r"
                                | "--remotes"
                                | "-v"
                                | "-vv"
                                | "--verbose"
                                | "--list"
                                | "--show-current"
                                | "--no-color"
                        ) && !r_arg.starts_with("--sort=")
                            && !r_arg.starts_with("--format=")
                        {
                            return C1Attempt::NotC1;
                        }
                    }
                } else {
                    let mut after_dd = false;
                    for r_arg in rest {
                        if !after_dd && r_arg == "--" {
                            after_dd = true;
                            continue;
                        }
                        if after_dd {
                            paths_to_verify.push(resolve_against_cwd(&base_repo, r_arg));
                            continue;
                        }
                        if r_arg.starts_with('-') {
                            continue;
                        }
                        if sub == "status"
                            || r_arg == ".."
                            || r_arg.starts_with("../")
                            || r_arg.contains("/..")
                            || r_arg.starts_with('/')
                        {
                            paths_to_verify.push(resolve_against_cwd(&base_repo, r_arg));
                        }
                    }
                }
            }
            "find" => {
                for arg in argv {
                    if matches!(
                        arg.as_str(),
                        "-exec"
                            | "-execdir"
                            | "-ok"
                            | "-okdir"
                            | "-delete"
                            | "-fprint"
                            | "-fprint0"
                            | "-fprintf"
                            | "-fls"
                            | "-L"
                            | "-follow"
                            | "-H"
                    ) {
                        return C1Attempt::NotC1;
                    }
                }
                for sp in extract_find_start_paths(proposal) {
                    paths_to_verify.push(sp);
                }
            }
            _ => return C1Attempt::NotC1,
        },
    }

    let mut ro_mounts = Vec::new();
    for p in paths_to_verify {
        match verify_scoped_path(core, &p, true) {
            ScopedPathVerdict::Authorized { mount_root, .. } => {
                if !ro_mounts.contains(&mount_root) {
                    ro_mounts.push(mount_root);
                }
            }
            ScopedPathVerdict::OutsideAuthorizedScope(out_p) => {
                return C1Attempt::OutsideScope(out_p);
            }
            ScopedPathVerdict::Forbidden(reason) => {
                return C1Attempt::Forbidden(reason);
            }
        }
    }

    C1Attempt::Matched {
        ro_mounts,
        reason: format!(
            "C1 授权范围只读检视 ({})，所有路径均通过 SafeFsEngine 边界与零符号链接逃逸校验",
            proposal.program
        ),
    }
}

enum C2Attempt {
    Matched {
        rw_mounts: Vec<PathBuf>,
        plan: C2WritePlan,
        reversible: bool,
        reason: String,
    },
    Forbidden(String),
    NotC2,
}

fn check_single_file_backup_quota(core: &IntentOsCore, path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return true;
    };
    if !meta.is_file() {
        return false;
    }
    let max_single = 1024 * 1024 * 1024u64; // 1 GiB single-file cap (§9.2)
    let used = core.fs_engine.current_backup_usage_bytes().unwrap_or(0);
    meta.len() <= max_single && used.saturating_add(meta.len()) <= 4 * max_single
}

fn try_classify_c2(
    core: &IntentOsCore,
    proposal: &CommandProposal,
    prog_name: &str,
    prog_family: &str,
) -> C2Attempt {
    let argv = &proposal.argv;
    let mut all_paths: Vec<PathBuf> = vec![normalize_lexical_clean(&proposal.cwd)];
    for rp in &proposal.required_paths {
        all_paths.push(resolve_against_cwd(&proposal.cwd, &rp.to_string_lossy()));
    }

    let (plan, mut reversible) = match prog_family {
        "mkdir" => {
            let mut dirs = Vec::new();
            let mut after_dd = false;
            for arg in argv {
                if !after_dd && arg == "--" {
                    after_dd = true;
                    continue;
                }
                if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                    if !matches!(arg.as_str(), "-p" | "--parents" | "-v" | "--verbose") {
                        return C2Attempt::NotC2;
                    }
                    continue;
                }
                let d = resolve_against_cwd(&proposal.cwd, arg);
                all_paths.push(d.clone());
                dirs.push(d);
            }
            if dirs.is_empty() {
                return C2Attempt::Forbidden("mkdir 缺少目标目录参数".to_string());
            }
            // Directory creation does not map to regular-file Trash undo in `SafeFsEngine`
            (C2WritePlan::Mkdir { dirs }, false)
        }
        "touch" => {
            let mut targets = Vec::new();
            let mut after_dd = false;
            let mut skip_next = false;
            for arg in argv {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if !after_dd && arg == "--" {
                    after_dd = true;
                    continue;
                }
                if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                    if matches!(arg.as_str(), "-d" | "--date" | "-t" | "-r" | "--reference") {
                        if matches!(arg.as_str(), "-r" | "--reference")
                            && let Some(ref_p) = argv.iter().skip_while(|x| *x != arg).nth(1)
                        {
                            all_paths.push(resolve_against_cwd(&proposal.cwd, ref_p));
                        }
                        skip_next = true;
                    }
                    continue;
                }
                let t = resolve_against_cwd(&proposal.cwd, arg);
                all_paths.push(t.clone());
                targets.push(t);
            }
            if targets.is_empty() {
                return C2Attempt::Forbidden("touch 缺少目标文件参数".to_string());
            }
            let rev = targets.iter().all(|t| !t.exists() || t.is_file());
            (C2WritePlan::Touch { targets }, rev)
        }
        "cp" | "mv" => {
            let mut positional = Vec::new();
            let mut target_dir_flag: Option<PathBuf> = None;
            let mut recursive = false;
            let mut after_dd = false;
            let mut idx = 0usize;
            while idx < argv.len() {
                let arg = &argv[idx];
                if !after_dd && arg == "--" {
                    after_dd = true;
                    idx += 1;
                    continue;
                }
                if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                    if prog_family == "cp"
                        && (arg == "-s"
                            || arg == "--symbolic-link"
                            || has_short_flag_char(arg, 's'))
                    {
                        return C2Attempt::Forbidden(
                            "禁止通过 cp -s 在工作区创建符号链接".to_string(),
                        );
                    }
                    if prog_family == "cp"
                        && (has_short_flag_char(arg, 'r')
                            || has_short_flag_char(arg, 'R')
                            || has_short_flag_char(arg, 'a')
                            || arg == "--recursive"
                            || arg == "--archive")
                    {
                        recursive = true;
                    }
                    if arg == "-t" || arg == "--target-directory" {
                        let Some(td) = argv.get(idx + 1) else {
                            return C2Attempt::Forbidden(format!(
                                "{} {} 缺少目标目录参数",
                                prog_family, arg
                            ));
                        };
                        target_dir_flag = Some(resolve_against_cwd(&proposal.cwd, td));
                        idx += 2;
                        continue;
                    }
                    if let Some(td) = arg.strip_prefix("--target-directory=") {
                        target_dir_flag = Some(resolve_against_cwd(&proposal.cwd, td));
                        idx += 1;
                        continue;
                    }
                    idx += 1;
                    continue;
                }
                positional.push(resolve_against_cwd(&proposal.cwd, arg));
                idx += 1;
            }

            let (sources, dest) = if let Some(td) = target_dir_flag {
                if positional.is_empty() {
                    return C2Attempt::Forbidden(format!("{} 缺少源路径参数", prog_family));
                }
                (positional, td)
            } else {
                if positional.len() < 2 {
                    return C2Attempt::Forbidden(format!(
                        "{} 需要至少一个源路径和一个目标路径",
                        prog_family
                    ));
                }
                let dst = positional.pop().unwrap();
                (positional, dst)
            };

            for s in &sources {
                all_paths.push(s.clone());
            }
            all_paths.push(dest.clone());

            let dest_is_existing_dir = dest.is_dir();
            let all_regular_sources = !recursive && sources.iter().all(|s| s.is_file());
            let mut rev = all_regular_sources;
            if rev {
                for src in &sources {
                    if !check_single_file_backup_quota(core, src) {
                        rev = false;
                        break;
                    }
                    let eff_dst = if dest_is_existing_dir {
                        if let Some(fname) = src.file_name() {
                            dest.join(fname)
                        } else {
                            rev = false;
                            break;
                        }
                    } else {
                        dest.clone()
                    };
                    if eff_dst.exists() && !check_single_file_backup_quota(core, &eff_dst) {
                        rev = false;
                        break;
                    }
                }
            }

            if prog_family == "cp" {
                (
                    C2WritePlan::Copy {
                        sources,
                        dest,
                        dest_is_existing_dir,
                        recursive,
                    },
                    rev,
                )
            } else {
                (
                    C2WritePlan::Move {
                        sources,
                        dest,
                        dest_is_existing_dir,
                    },
                    rev,
                )
            }
        }
        _ if (prog_name == "sed" || prog_family == "sed")
            && argv
                .iter()
                .any(|a| a == "-i" || a.starts_with("-i") || a.starts_with("--in-place")) =>
        {
            let mut expr_given = false;
            let mut skip_next = false;
            let mut after_dd = false;
            let mut positional = Vec::new();
            for arg in argv {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if !after_dd && arg == "--" {
                    after_dd = true;
                    continue;
                }
                if !after_dd && arg.starts_with('-') && arg.len() > 1 {
                    if arg == "-e" || arg == "--expression" {
                        expr_given = true;
                        skip_next = true;
                    } else if arg.starts_with("--expression=") || arg.starts_with("-e") {
                        expr_given = true;
                    }
                    continue;
                }
                positional.push(arg.as_str());
            }
            let file_slice = if expr_given {
                positional.as_slice()
            } else if positional.len() >= 2 {
                &positional[1..]
            } else {
                return C2Attempt::Forbidden("sed -i 缺少表达式或目标文件参数".to_string());
            };
            if file_slice.is_empty() {
                return C2Attempt::Forbidden("sed -i 缺少目标文件参数".to_string());
            }
            let mut targets = Vec::new();
            let mut rev = true;
            for f_str in file_slice {
                let t = resolve_against_cwd(&proposal.cwd, f_str);
                if !t.is_file() || !check_single_file_backup_quota(core, &t) {
                    rev = false;
                }
                all_paths.push(t.clone());
                targets.push(t);
            }
            (C2WritePlan::SedInPlace { targets }, rev)
        }
        _ => return C2Attempt::NotC2,
    };

    let mut rw_mounts = Vec::new();
    for p in &all_paths {
        match verify_scoped_path(core, p, true) {
            ScopedPathVerdict::Authorized { mount_root, .. } => {
                if !rw_mounts.contains(&mount_root) {
                    rw_mounts.push(mount_root);
                }
            }
            ScopedPathVerdict::OutsideAuthorizedScope(out_p) => {
                return C2Attempt::Forbidden(format!(
                    "拒绝在授权工作区范围外执行写入命令 '{}': {}",
                    proposal.program,
                    out_p.display()
                ));
            }
            ScopedPathVerdict::Forbidden(reason) => {
                return C2Attempt::Forbidden(reason);
            }
        }
    }

    if rw_mounts.is_empty() {
        reversible = false;
    }

    C2Attempt::Matched {
        rw_mounts,
        plan,
        reversible,
        reason: format!(
            "C2 授权工作区文件变更 ({})，需人工预览确认{}",
            proposal.program,
            if reversible {
                "（支持生成 ChangeSet 原子一键撤销）"
            } else {
                "（目录或复合写入，标记为不可自动撤销）"
            }
        ),
    }
}

#[derive(Debug)]
struct PreTargetSnapshot {
    target_path: PathBuf,
    existed_before: bool,
    pre_hash: Option<String>,
    backup_path: Option<PathBuf>,
    source_path: Option<PathBuf>,
    source_pre_hash: Option<String>,
    source_trash_data: Option<PathBuf>,
    source_trash_info: Option<PathBuf>,
}

struct CapturedC2Snapshot {
    cs_id: String,
    entries: Vec<PreTargetSnapshot>,
    backup_bytes: u64,
}

impl CapturedC2Snapshot {
    fn cleanup_unused_files(&self) {
        for entry in &self.entries {
            if let Some(ref bp) = entry.backup_path {
                let _ = std::fs::remove_file(bp);
            }
            if let Some(ref td) = entry.source_trash_data {
                let _ = std::fs::remove_file(td);
            }
            if let Some(ref ti) = entry.source_trash_info {
                let _ = std::fs::remove_file(ti);
            }
        }
    }
}

fn capture_c2_pre_snapshot(
    core: &IntentOsCore,
    plan: &C2WritePlan,
) -> anyhow::Result<CapturedC2Snapshot> {
    let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    std::fs::create_dir_all(core.fs_engine.backup_dir())?;
    let mut entries = Vec::new();
    let mut backup_bytes = 0u64;

    let backup_existing_file =
        |idx: usize, path: &Path| -> anyhow::Result<(String, PathBuf, u64)> {
            let (pre_hash, _, len) = core.fs_engine.hash_and_identity(path)?;
            let bak = core
                .fs_engine
                .backup_dir()
                .join(format!("{}_{}.bak", cs_id, idx));
            let mut src_f = core.fs_engine.open_readonly_safe(path)?;
            let mut dst_f = std::fs::File::create(&bak)?;
            std::io::copy(&mut src_f, &mut dst_f)?;
            dst_f.sync_all()?;
            Ok((pre_hash, bak, len))
        };

    match plan {
        C2WritePlan::Touch { targets } | C2WritePlan::SedInPlace { targets } => {
            for (idx, t) in targets.iter().enumerate() {
                if t.is_file() {
                    let (pre_hash, bak, len) = backup_existing_file(idx, t)?;
                    backup_bytes = backup_bytes.saturating_add(len);
                    entries.push(PreTargetSnapshot {
                        target_path: t.clone(),
                        existed_before: true,
                        pre_hash: Some(pre_hash),
                        backup_path: Some(bak),
                        source_path: None,
                        source_pre_hash: None,
                        source_trash_data: None,
                        source_trash_info: None,
                    });
                } else {
                    entries.push(PreTargetSnapshot {
                        target_path: t.clone(),
                        existed_before: false,
                        pre_hash: None,
                        backup_path: None,
                        source_path: None,
                        source_pre_hash: None,
                        source_trash_data: None,
                        source_trash_info: None,
                    });
                }
            }
        }
        C2WritePlan::Copy {
            sources,
            dest,
            dest_is_existing_dir,
            ..
        } => {
            for (idx, src) in sources.iter().enumerate() {
                let eff_dst = if *dest_is_existing_dir {
                    dest.join(src.file_name().unwrap_or_default())
                } else {
                    dest.clone()
                };
                if eff_dst.is_file() {
                    let (pre_hash, bak, len) = backup_existing_file(idx, &eff_dst)?;
                    backup_bytes = backup_bytes.saturating_add(len);
                    entries.push(PreTargetSnapshot {
                        target_path: eff_dst,
                        existed_before: true,
                        pre_hash: Some(pre_hash),
                        backup_path: Some(bak),
                        source_path: Some(src.clone()),
                        source_pre_hash: None,
                        source_trash_data: None,
                        source_trash_info: None,
                    });
                } else {
                    entries.push(PreTargetSnapshot {
                        target_path: eff_dst,
                        existed_before: false,
                        pre_hash: None,
                        backup_path: None,
                        source_path: Some(src.clone()),
                        source_pre_hash: None,
                        source_trash_data: None,
                        source_trash_info: None,
                    });
                }
            }
        }
        C2WritePlan::Move {
            sources,
            dest,
            dest_is_existing_dir,
        } => {
            let trash_root = core.paths.data_dir.join("trash");
            std::fs::create_dir_all(trash_root.join("files"))?;
            std::fs::create_dir_all(trash_root.join("info"))?;

            for (idx, src) in sources.iter().enumerate() {
                let eff_dst = if *dest_is_existing_dir {
                    dest.join(src.file_name().unwrap_or_default())
                } else {
                    dest.clone()
                };
                let (src_hash, _, src_len) = core.fs_engine.hash_and_identity(src)?;
                if eff_dst.is_file() {
                    let (dst_hash, dst_bak, dst_len) = backup_existing_file(idx, &eff_dst)?;
                    let src_entry_name = format!("{}_src_{}", cs_id, idx);
                    let trash_data = trash_root.join("files").join(&src_entry_name);
                    let trash_info = trash_root
                        .join("info")
                        .join(format!("{}.trashinfo", src_entry_name));
                    let mut sf = core.fs_engine.open_readonly_safe(src)?;
                    let mut tf = std::fs::File::create(&trash_data)?;
                    std::io::copy(&mut sf, &mut tf)?;
                    tf.sync_all()?;
                    std::fs::write(
                        &trash_info,
                        format!(
                            "[Trash Info]\nPath={}\nDeletionDate={}\n",
                            src.display(),
                            Utc::now().format("%Y-%m-%dT%H:%M:%S")
                        ),
                    )?;
                    backup_bytes = backup_bytes.saturating_add(dst_len).saturating_add(src_len);
                    entries.push(PreTargetSnapshot {
                        target_path: eff_dst,
                        existed_before: true,
                        pre_hash: Some(dst_hash),
                        backup_path: Some(dst_bak),
                        source_path: Some(src.clone()),
                        source_pre_hash: Some(src_hash),
                        source_trash_data: Some(trash_data),
                        source_trash_info: Some(trash_info),
                    });
                } else {
                    entries.push(PreTargetSnapshot {
                        target_path: eff_dst,
                        existed_before: false,
                        pre_hash: None,
                        backup_path: None,
                        source_path: Some(src.clone()),
                        source_pre_hash: Some(src_hash),
                        source_trash_data: None,
                        source_trash_info: None,
                    });
                }
            }
        }
        C2WritePlan::Mkdir { .. } => {}
    }

    Ok(CapturedC2Snapshot {
        cs_id,
        entries,
        backup_bytes,
    })
}

fn finalize_c2_changeset(
    core: &IntentOsCore,
    task_id: &str,
    proposal: &CommandProposal,
    plan: &C2WritePlan,
    captured: CapturedC2Snapshot,
) -> anyhow::Result<Option<ChangeSet>> {
    let mut ops = Vec::new();

    match plan {
        C2WritePlan::Touch { .. } | C2WritePlan::SedInPlace { .. } => {
            for entry in &captured.entries {
                let (post_hash, _, _) = core.fs_engine.hash_and_identity(&entry.target_path)?;
                if entry.existed_before {
                    let pre_hash = entry.pre_hash.clone().unwrap_or_default();
                    let bak = entry.backup_path.clone().unwrap();
                    if post_hash != pre_hash {
                        ops.push(ChangeOp::Overwrite {
                            path: entry.target_path.display().to_string(),
                            backup_path: bak.display().to_string(),
                            pre_hash,
                            post_hash,
                        });
                    } else {
                        let _ = std::fs::remove_file(bak);
                    }
                } else {
                    ops.push(ChangeOp::Create {
                        path: entry.target_path.display().to_string(),
                        post_hash,
                    });
                }
            }
        }
        C2WritePlan::Copy { .. } => {
            for entry in &captured.entries {
                let (post_hash, _, _) = core.fs_engine.hash_and_identity(&entry.target_path)?;
                if entry.existed_before {
                    ops.push(ChangeOp::Overwrite {
                        path: entry.target_path.display().to_string(),
                        backup_path: entry.backup_path.as_ref().unwrap().display().to_string(),
                        pre_hash: entry.pre_hash.clone().unwrap_or_default(),
                        post_hash,
                    });
                } else {
                    ops.push(ChangeOp::Copy {
                        from: entry
                            .source_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        to: entry.target_path.display().to_string(),
                        post_hash,
                    });
                }
            }
        }
        C2WritePlan::Move { .. } => {
            for entry in &captured.entries {
                let (post_hash, post_id, _) =
                    core.fs_engine.hash_and_identity(&entry.target_path)?;
                let src_p = entry.source_path.as_ref().unwrap();
                if entry.existed_before {
                    ops.push(ChangeOp::Trash {
                        original_path: src_p.display().to_string(),
                        trash_data_path: entry
                            .source_trash_data
                            .as_ref()
                            .unwrap()
                            .display()
                            .to_string(),
                        trash_info_path: entry
                            .source_trash_info
                            .as_ref()
                            .unwrap()
                            .display()
                            .to_string(),
                        pre_hash: entry.source_pre_hash.clone().unwrap_or_default(),
                    });
                    ops.push(ChangeOp::Overwrite {
                        path: entry.target_path.display().to_string(),
                        backup_path: entry.backup_path.as_ref().unwrap().display().to_string(),
                        pre_hash: entry.pre_hash.clone().unwrap_or_default(),
                        post_hash,
                    });
                } else {
                    ops.push(ChangeOp::Move {
                        from: src_p.display().to_string(),
                        to: entry.target_path.display().to_string(),
                        fs_id: Some(post_id),
                        post_hash,
                    });
                }
            }
        }
        C2WritePlan::Mkdir { .. } => return Ok(None),
    }

    if ops.is_empty() {
        return Ok(None);
    }

    let now = Utc::now();
    let retention_days = core.app_config.undo.retention_days.max(1);
    let cs = ChangeSet {
        id: captured.cs_id,
        task_id: task_id.to_string(),
        created_at: now,
        capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.to_string(),
        layer: "M2-C".to_string(),
        operations: ops,
        backup_bytes: captured.backup_bytes,
        status: ChangeSetStatus::Applied,
        undo_expires_at: now + ChronoDuration::days(retention_days),
        summary: format!(
            "受控终端 C2 写入: {} {}",
            proposal.program,
            proposal.argv.join(" ")
        ),
    };
    Ok(Some(cs))
}

fn verify_c2_postconditions(plan: &C2WritePlan) -> Result<Vec<String>, String> {
    let mut checks = vec!["exit_code == 0".to_string()];
    match plan {
        C2WritePlan::Mkdir { dirs } => {
            for d in dirs {
                if !d.is_dir() {
                    return Err(format!("mkdir 执行后目标目录不存在: {}", d.display()));
                }
                checks.push(format!("dir_exists:{}", d.display()));
            }
        }
        C2WritePlan::Touch { targets } | C2WritePlan::SedInPlace { targets } => {
            for t in targets {
                if !t.is_file() {
                    return Err(format!("命令执行后目标文件不存在: {}", t.display()));
                }
                checks.push(format!("file_exists:{}", t.display()));
            }
        }
        C2WritePlan::Copy {
            sources,
            dest,
            dest_is_existing_dir,
            ..
        } => {
            for s in sources {
                let eff_dst = if *dest_is_existing_dir {
                    dest.join(s.file_name().unwrap_or_default())
                } else {
                    dest.clone()
                };
                if !eff_dst.exists() {
                    return Err(format!("cp 执行后目标路径不存在: {}", eff_dst.display()));
                }
                checks.push(format!("copied_exists:{}", eff_dst.display()));
            }
        }
        C2WritePlan::Move {
            sources,
            dest,
            dest_is_existing_dir,
        } => {
            for s in sources {
                let eff_dst = if *dest_is_existing_dir {
                    dest.join(s.file_name().unwrap_or_default())
                } else {
                    dest.clone()
                };
                if s != &eff_dst && s.exists() {
                    return Err(format!("mv 执行后源路径仍残留: {}", s.display()));
                }
                if !eff_dst.exists() {
                    return Err(format!("mv 执行后目标路径不存在: {}", eff_dst.display()));
                }
                checks.push(format!("moved_verified:{}", eff_dst.display()));
            }
        }
    }
    Ok(checks)
}

async fn verify_c3_postconditions(
    proposal: &CommandProposal,
    probe: &SandboxProbe,
) -> VerificationReport {
    let mut checks = vec!["exit_code == 0".to_string()];
    let prog_name = Path::new(&proposal.program)
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    // Package state verification for `apt` / `apt-get install|remove|purge <pkg>`
    if matches!(prog_name.as_str(), "apt" | "apt-get") && Path::new("/usr/bin/dpkg-query").is_file()
    {
        let verb = proposal
            .argv
            .iter()
            .find(|a| matches!(a.as_str(), "install" | "remove" | "purge"))
            .map(String::as_str);
        let pkg = proposal
            .argv
            .iter()
            .skip_while(|a| !matches!(a.as_str(), "install" | "remove" | "purge"))
            .nth(1)
            .filter(|a| !a.starts_with('-'));

        if let (Some(v), Some(pkg_name)) = (verb, pkg) {
            let probe_spec = TerminalSandboxSpec {
                program: PathBuf::from("/usr/bin/dpkg-query"),
                args: vec![
                    "-W".to_string(),
                    "-f=${Status}".to_string(),
                    pkg_name.clone(),
                ],
                ro_bind_root: true,
                readonly_paths: Vec::new(),
                readwrite_paths: Vec::new(),
                masked_paths: Vec::new(),
                env_vars: BTreeMap::new(),
                work_dir: PathBuf::from("/"),
                allow_tcp_network: false,
            };
            if let Ok(q_out) =
                execute_terminal_sandbox_bounded(&probe_spec, Duration::from_secs(5), 4096, probe)
                    .await
            {
                let status_str = String::from_utf8_lossy(&q_out.stdout);
                let installed = status_str.contains("install ok installed");
                if v == "install" && !installed {
                    return VerificationReport {
                        state: VerificationState::VerificationFailed,
                        method: "dpkg_query_postcheck".to_string(),
                        checks,
                        details: Some(format!(
                            "dpkg-query 校验软件包 '{}' 未处于 installed 状态 ({})",
                            pkg_name, status_str
                        )),
                    };
                }
                if matches!(v, "remove" | "purge") && installed {
                    return VerificationReport {
                        state: VerificationState::VerificationFailed,
                        method: "dpkg_query_postcheck".to_string(),
                        checks,
                        details: Some(format!(
                            "dpkg-query 校验软件包 '{}' 仍处于 installed 状态",
                            pkg_name
                        )),
                    };
                }
                checks.push(format!("dpkg_query_verified:{}:{}", v, pkg_name));
            }
        }
    }

    // Service state verification for `systemctl [--user] start|restart|stop <unit>`
    if prog_name == "systemctl" && Path::new("/usr/bin/systemctl").is_file() {
        let user_mode = proposal.argv.iter().any(|a| a == "--user");
        let verb = proposal
            .argv
            .iter()
            .find(|a| matches!(a.as_str(), "start" | "restart" | "stop"))
            .map(String::as_str);
        let unit = proposal
            .argv
            .iter()
            .skip_while(|a| !matches!(a.as_str(), "start" | "restart" | "stop"))
            .nth(1)
            .filter(|a| !a.starts_with('-'));

        if let (Some(v), Some(unit_name)) = (verb, unit) {
            let mut check_args = Vec::new();
            if user_mode {
                check_args.push("--user".to_string());
            }
            check_args.push("is-active".to_string());
            check_args.push(unit_name.clone());
            if let Ok(out) = tokio::time::timeout(
                Duration::from_secs(4),
                tokio::process::Command::new("/usr/bin/systemctl")
                    .args(&check_args)
                    .output(),
            )
            .await
                && let Ok(res) = out
            {
                let active_state = String::from_utf8_lossy(&res.stdout).trim().to_string();
                let expect_active = matches!(v, "start" | "restart");
                if expect_active && active_state != "active" {
                    return VerificationReport {
                        state: VerificationState::VerificationFailed,
                        method: "systemctl_is_active_postcheck".to_string(),
                        checks,
                        details: Some(format!(
                            "systemctl is-active {} 返回 '{}'",
                            unit_name, active_state
                        )),
                    };
                }
                if v == "stop" && active_state == "active" {
                    return VerificationReport {
                        state: VerificationState::VerificationFailed,
                        method: "systemctl_is_active_postcheck".to_string(),
                        checks,
                        details: Some(format!("停止后服务 {} 仍处于 active", unit_name)),
                    };
                }
                checks.push(format!("systemctl_state:{}:{}", unit_name, active_state));
            }
        }
    }

    for rp in &proposal.required_paths {
        let resolved = resolve_against_cwd(&proposal.cwd, &rp.to_string_lossy());
        if resolved.exists() {
            checks.push(format!("required_path_present:{}", resolved.display()));
        }
    }

    VerificationReport {
        state: VerificationState::Passed,
        method: "c3_postcondition_and_exit_zero".to_string(),
        checks,
        details: None,
    }
}

fn synthetic_terminal_descriptor(
    classification: &CommandClassification,
    proposal: &CommandProposal,
) -> CapabilityDescriptor {
    let summary = if proposal.purpose.trim().is_empty() {
        format!(
            "[{}] 终端命令 {} {}",
            classification.tier.short_label(),
            proposal.program,
            proposal.argv.join(" ")
        )
    } else {
        format!(
            "[{}] {} ({} {})",
            classification.tier.short_label(),
            proposal.purpose.trim(),
            proposal.program,
            proposal.argv.join(" ")
        )
    };
    CapabilityDescriptor {
        id: TERMINAL_EXECUTE_CAPABILITY_ID.to_string(),
        version: 1,
        summary,
        category: "devtools".to_string(),
        aliases: Vec::new(),
        l0_patterns: Vec::new(),
        input_schema: json!({ "type": "object" }),
        effects: classification.effects.clone(),
        idempotent: classification.tier.is_auto_executable(),
        execution: ExecutionBackend::Builtin {
            handler: TERMINAL_EXECUTE_CAPABILITY_ID.to_string(),
        },
        setting: None,
        undo: if classification.reversible {
            UndoStrategy::Changeset
        } else {
            UndoStrategy::None
        },
        verification: None,
        feedback: None,
        dependencies: vec!["bwrap".to_string()],
    }
}

#[allow(clippy::too_many_arguments)]
fn record_terminal_audit(
    core: &IntentOsCore,
    task_id: &str,
    origin: &str,
    effect: Effect,
    policy_decision: &str,
    status: &str,
    proposal: &CommandProposal,
    summary: Option<&str>,
) {
    if !core.task_privacy_policy(task_id).allows_task_persistence() {
        return;
    }
    let mut scrubbed_args = proposal.to_capability_args();
    SensitiveDataGuard::redact_json(&mut scrubbed_args);
    let scrubbed_summary = summary.map(|s| SensitiveDataGuard::redact_text(s).0);
    let _ = core.state_db.record_audit(
        Some(task_id),
        TERMINAL_EXECUTE_CAPABILITY_ID,
        origin,
        effect.as_str(),
        policy_decision,
        status,
        &scrubbed_args,
        scrubbed_summary.as_deref(),
    );
}

/// Classify, policy-check, and either execute (`C0`/`C1`), issue a nonce-bound `PendingApproval`
/// (`C2`/`C3`), or deny (`C4`) a `CommandProposal` (`M2-C` single-entry dispatcher).
pub async fn execute_command_proposal(
    core: &IntentOsCore,
    task_id: &str,
    call: &CapabilityCall,
    proposal: &CommandProposal,
) -> anyhow::Result<BrokerDispatchOutcome> {
    let classification = classify_command_proposal(core, proposal);
    let origin_str = format!("{:?}", call.origin);

    // 1. Hard-block C4Forbidden unconditionally!
    if classification.tier == TerminalSafetyTier::C4Forbidden || classification.denied {
        let reason = classification
            .reasons
            .first()
            .cloned()
            .unwrap_or_else(|| "终端命令触发 C4 安全禁令，已拒绝执行".to_string());
        record_terminal_audit(
            core,
            task_id,
            &origin_str,
            Effect::SystemAdmin,
            "deny_c4_forbidden",
            "denied",
            proposal,
            Some(&reason),
        );
        return Ok(BrokerDispatchOutcome::Denied { reason });
    }

    // 2. Untrusted taint escalation in strict mode even for C1 reads
    let untrusted_taint = call.taints.iter().any(|t| t.is_untrusted());
    let force_taint_approval = untrusted_taint
        && (classification.tier >= TerminalSafetyTier::C2ReversibleWrite
            || (classification.tier == TerminalSafetyTier::C1ScopedRead
                && core.policy.security_mode() == "strict"));

    // 3. C2ReversibleWrite & C3SystemModify ALWAYS require human preview/approval!
    if classification.requires_approval || force_taint_approval {
        let desc = synthetic_terminal_descriptor(&classification, proposal);
        let reason = classification.reasons.join("；");
        // C3SystemModify MUST NEVER falsely claim `reversible == true`!
        let reversible = classification.tier == TerminalSafetyTier::C2ReversibleWrite
            && classification.reversible;
        let canonical_args = proposal.to_capability_args();
        let mut pa = core.policy.issue_pending_approval(
            task_id,
            &desc,
            &canonical_args,
            &reason,
            reversible,
        );
        pa.diff_preview = format!(
            "{}\n终端分级: {} ({})\n程序: {}\n参数 argv: {:?}\n工作目录: {}\n联网权限: {}\n超时上限: {}s",
            pa.diff_preview,
            classification.tier.short_label(),
            classification.tier.as_str(),
            proposal.program,
            proposal.argv,
            proposal.cwd.display(),
            proposal.network_access,
            proposal.clamped_timeout_seconds()
        );

        record_terminal_audit(
            core,
            task_id,
            &origin_str,
            classification.effective_effect,
            "awaiting_approval",
            "pending",
            proposal,
            Some(&reason),
        );
        return Ok(BrokerDispatchOutcome::RequiresApproval(pa));
    }

    // 4. Auto-executable `C0ReadOnlyDiag` & `C1ScopedRead` inside read-only OS sandbox!
    let res = run_classified_proposal_in_sandbox(
        core,
        &call.request_id,
        task_id,
        proposal,
        &classification,
    )
    .await?;

    record_terminal_audit(
        core,
        task_id,
        &origin_str,
        classification.effective_effect,
        "allow_sandboxed",
        &format!("{:?}", res.status),
        proposal,
        Some(&res.message),
    );
    Ok(BrokerDispatchOutcome::Executed(res))
}

/// Convenience helper parsing `CapabilityCall.arguments` into `CommandProposal` and dispatching
/// through [`execute_command_proposal`] (5-line `CapabilityBroker::dispatch` hook for `m2shepherd`).
pub async fn dispatch_terminal_capability(
    core: &IntentOsCore,
    call: &CapabilityCall,
) -> anyhow::Result<BrokerDispatchOutcome> {
    let proposal = match CommandProposal::from_capability_args(&call.arguments, Some(core)) {
        Ok(p) => p,
        Err(reason) => return Ok(BrokerDispatchOutcome::Denied { reason }),
    };
    execute_command_proposal(core, &call.task_id, call, &proposal).await
}

/// Execute a nonce-approved `CommandProposal` (`C2ReversibleWrite` or `C3SystemModify`),
/// re-running local C4 anti-bypass/TOCTOU checks first!
pub async fn execute_approved_command_proposal(
    core: &IntentOsCore,
    request_id: &str,
    task_id: &str,
    proposal: &CommandProposal,
) -> anyhow::Result<CapabilityResult> {
    let classification = classify_command_proposal(core, proposal);
    if classification.tier == TerminalSafetyTier::C4Forbidden || classification.denied {
        let reason = classification
            .reasons
            .first()
            .cloned()
            .unwrap_or_else(|| "C4 禁止命令即使在审批恢复阶段仍被硬拦截".to_string());
        anyhow::bail!("安全内核硬拦截 (C4Forbidden): {}", reason);
    }
    let res =
        run_classified_proposal_in_sandbox(core, request_id, task_id, proposal, &classification)
            .await?;
    record_terminal_audit(
        core,
        task_id,
        "ApprovedExecution",
        classification.effective_effect,
        "approved_executed",
        &format!("{:?}", res.status),
        proposal,
        Some(&res.message),
    );
    Ok(res)
}

/// Convenience helper for `CapabilityBroker::execute_builtin("terminal.execute", ...)` post-approval execution.
pub async fn execute_approved_terminal_call(
    core: &IntentOsCore,
    request_id: &str,
    task_id: &str,
    args: &Value,
) -> anyhow::Result<CapabilityResult> {
    let proposal = CommandProposal::from_capability_args(args, Some(core))
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    execute_approved_command_proposal(core, request_id, task_id, &proposal).await
}

async fn run_classified_proposal_in_sandbox(
    core: &IntentOsCore,
    request_id: &str,
    task_id: &str,
    proposal: &CommandProposal,
    classification: &CommandClassification,
) -> anyhow::Result<CapabilityResult> {
    let probe = probe_sandbox_support();
    if !probe.has_os_isolation() {
        return Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.to_string(),
            status: ExecutionStatus::Denied,
            exit_code: None,
            message: "当前宿主环境未提供 Bubblewrap 或 Landlock 内核隔离，已拒绝执行受控终端命令"
                .to_string(),
            data: json!({
                "tier": classification.tier.as_str(),
                "error": "os_sandbox_unavailable",
            }),
            stdout_preview: String::new(),
            stderr_preview: "OS sandbox unavailable".to_string(),
            truncated: false,
            duration_ms: 0,
            changeset_id: None,
            verification: VerificationReport {
                state: VerificationState::VerificationFailed,
                method: "sandbox_probe".to_string(),
                checks: Vec::new(),
                details: Some("Bubblewrap/Landlock unavailable".to_string()),
            },
            backend_mode: "sandbox_unavailable".to_string(),
        });
    }

    let Some(ref exec_path) = classification.resolved_executable else {
        return Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.to_string(),
            status: ExecutionStatus::Denied,
            exit_code: None,
            message: format!("未在本机可信路径找到命令 '{}'", proposal.program),
            data: json!({
                "tier": classification.tier.as_str(),
                "error": "executable_not_found",
                "program": proposal.program,
            }),
            stdout_preview: String::new(),
            stderr_preview: format!("executable not found: {}", proposal.program),
            truncated: false,
            duration_ms: 0,
            changeset_id: None,
            verification: VerificationReport {
                state: VerificationState::VerificationFailed,
                method: "executable_lookup".to_string(),
                checks: Vec::new(),
                details: Some("executable missing".to_string()),
            },
            backend_mode: "denied".to_string(),
        });
    };

    // Snapshot pre-existing files for reversible `C2ReversibleWrite` BEFORE running `bwrap`!
    let pre_snapshot = if classification.tier == TerminalSafetyTier::C2ReversibleWrite
        && classification.reversible
        && let Some(ref plan) = classification.c2_plan
    {
        Some(capture_c2_pre_snapshot(core, plan)?)
    } else {
        None
    };

    let mut env_vars = BTreeMap::new();
    env_vars.insert(
        "PATH".to_string(),
        "/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin".to_string(),
    );
    env_vars.insert("LANG".to_string(), "C.UTF-8".to_string());
    env_vars.insert("LC_ALL".to_string(), "C.UTF-8".to_string());
    env_vars.insert("PAGER".to_string(), "cat".to_string());
    env_vars.insert("GIT_PAGER".to_string(), "cat".to_string());
    env_vars.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    if classification.tier.is_auto_executable() {
        env_vars.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    }

    let allow_net = match classification.tier {
        TerminalSafetyTier::C0ReadOnlyDiag
        | TerminalSafetyTier::C1ScopedRead
        | TerminalSafetyTier::C2ReversibleWrite => false,
        TerminalSafetyTier::C3SystemModify => proposal.network_access,
        TerminalSafetyTier::C4Forbidden => false,
    };

    let work_dir = match classification.tier {
        TerminalSafetyTier::C0ReadOnlyDiag => {
            if classification
                .verified_readonly_paths
                .iter()
                .any(|r| proposal.cwd.starts_with(r))
                && proposal.cwd.is_dir()
            {
                proposal.cwd.clone()
            } else {
                PathBuf::from("/")
            }
        }
        _ => normalize_lexical_clean(&proposal.cwd),
    };

    let masked_paths = vec![
        core.paths.config_dir.clone(),
        core.paths.data_dir.clone(),
        core.paths.state_dir.clone(),
        core.paths.runtime_dir.clone(),
    ];

    let sandbox_spec = TerminalSandboxSpec {
        program: exec_path.clone(),
        args: proposal.argv.clone(),
        ro_bind_root: true,
        readonly_paths: classification.verified_readonly_paths.clone(),
        readwrite_paths: if classification.tier.is_auto_executable() {
            Vec::new()
        } else {
            classification.verified_readwrite_paths.clone()
        },
        masked_paths,
        env_vars,
        work_dir: work_dir.clone(),
        allow_tcp_network: allow_net,
    };

    let timeout = Duration::from_secs(proposal.clamped_timeout_seconds());
    let exec_out = match execute_terminal_sandbox_bounded(
        &sandbox_spec,
        timeout,
        MAX_TERMINAL_OUTPUT_BYTES,
        &probe,
    )
    .await
    {
        Ok(o) => o,
        Err(err) => {
            if let Some(snap) = pre_snapshot {
                snap.cleanup_unused_files();
            }
            return Err(anyhow::anyhow!("受控终端沙箱启动失败: {}", err));
        }
    };

    let raw_stdout = String::from_utf8_lossy(&exec_out.stdout).to_string();
    let raw_stderr = String::from_utf8_lossy(&exec_out.stderr).to_string();
    let (clean_stdout, stdout_redacted) = SensitiveDataGuard::redact_text(&raw_stdout);
    let (clean_stderr, stderr_redacted) = SensitiveDataGuard::redact_text(&raw_stderr);

    if exec_out.timed_out {
        if let Some(snap) = pre_snapshot {
            snap.cleanup_unused_files();
        }
        let msg = format!(
            "命令 '{} {}' 执行超过 {}s 上限，进程组已被终止",
            proposal.program,
            proposal.argv.join(" "),
            proposal.clamped_timeout_seconds()
        );
        return Ok(CapabilityResult {
            request_id: request_id.to_string(),
            capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.to_string(),
            status: ExecutionStatus::Timeout,
            exit_code: None,
            message: msg.clone(),
            data: json!({
                "tier": classification.tier.as_str(),
                "program": proposal.program,
                "argv": proposal.argv,
                "cwd": work_dir.to_string_lossy(),
                "timed_out": true,
                "timeout_seconds": proposal.clamped_timeout_seconds(),
                "sandbox_driver": format!("{:?}", exec_out.driver).to_ascii_lowercase(),
                "network_isolated": !allow_net,
            }),
            stdout_preview: clean_stdout,
            stderr_preview: clean_stderr,
            truncated: exec_out.truncated,
            duration_ms: exec_out.duration_ms,
            changeset_id: None,
            verification: VerificationReport {
                state: VerificationState::VerificationFailed,
                method: "process_group_timeout".to_string(),
                checks: vec!["sigkill_process_group_reaped".to_string()],
                details: Some(msg),
            },
            backend_mode: format!("{:?}", exec_out.driver).to_ascii_lowercase(),
        });
    }

    let exit_ok = exec_out.exit_code == Some(0);
    let mut changeset_id: Option<String> = None;

    let verification = if !exit_ok {
        if let Some(snap) = pre_snapshot {
            snap.cleanup_unused_files();
        }
        VerificationReport {
            state: VerificationState::VerificationFailed,
            method: "exit_code".to_string(),
            checks: Vec::new(),
            details: Some(format!(
                "进程退出码 {:?}: {}",
                exec_out.exit_code,
                clean_stderr.trim()
            )),
        }
    } else {
        match classification.tier {
            TerminalSafetyTier::C0ReadOnlyDiag | TerminalSafetyTier::C1ScopedRead => {
                VerificationReport {
                    state: VerificationState::Passed,
                    method: "sandboxed_readonly_exit_zero".to_string(),
                    checks: vec![
                        "exit_code == 0".to_string(),
                        format!("sandbox_driver == {:?}", exec_out.driver),
                        "network_namespace_isolated".to_string(),
                    ],
                    details: None,
                }
            }
            TerminalSafetyTier::C2ReversibleWrite => {
                if let Some(ref plan) = classification.c2_plan {
                    match verify_c2_postconditions(plan) {
                        Ok(mut checks) => {
                            if let Some(snap) = pre_snapshot
                                && let Some(cs) =
                                    finalize_c2_changeset(core, task_id, proposal, plan, snap)?
                                && core.task_privacy_policy(task_id).allows_task_persistence()
                            {
                                core.state_db.save_changeset(&cs)?;
                                let _ = core.resources.index_authorized_files();
                                changeset_id = Some(cs.id.clone());
                                checks.push(format!("changeset_saved:{}", cs.id));
                            }
                            VerificationReport {
                                state: VerificationState::Passed,
                                method: "c2_fs_postcondition_and_changeset".to_string(),
                                checks,
                                details: None,
                            }
                        }
                        Err(post_err) => {
                            if let Some(snap) = pre_snapshot {
                                snap.cleanup_unused_files();
                            }
                            VerificationReport {
                                state: VerificationState::VerificationFailed,
                                method: "c2_fs_postcondition".to_string(),
                                checks: Vec::new(),
                                details: Some(post_err),
                            }
                        }
                    }
                } else {
                    VerificationReport {
                        state: VerificationState::Passed,
                        method: "exit_code_zero".to_string(),
                        checks: vec!["exit_code == 0".to_string()],
                        details: None,
                    }
                }
            }
            TerminalSafetyTier::C3SystemModify => verify_c3_postconditions(proposal, &probe).await,
            TerminalSafetyTier::C4Forbidden => unreachable!("C4 blocked prior to execution"),
        }
    };

    let status = if verification.state == VerificationState::Passed {
        ExecutionStatus::Exited
    } else {
        ExecutionStatus::VerificationFailed
    };

    let msg = if status == ExecutionStatus::Exited {
        if let Some(ref csid) = changeset_id {
            format!(
                "✓ [{}] {} 执行成功 [变更集 {}，可一键撤销]",
                classification.tier.short_label(),
                proposal.program,
                csid
            )
        } else if !clean_stdout.trim().is_empty() {
            clean_stdout
                .lines()
                .next()
                .unwrap_or(&proposal.program)
                .to_string()
        } else {
            format!(
                "✓ [{}] {} 执行完成",
                classification.tier.short_label(),
                proposal.program
            )
        }
    } else {
        format!(
            "命令 '{}' 执行未通过验证 (exit={:?})",
            proposal.program, exec_out.exit_code
        )
    };

    let mut data = json!({
        "tier": classification.tier.as_str(),
        "tier_label": classification.tier.short_label(),
        "effective_effect": classification.effective_effect,
        "reversible": classification.reversible && changeset_id.is_some(),
        "program": proposal.program,
        "resolved_executable": exec_path.to_string_lossy(),
        "canonical_executable": classification
            .canonical_executable
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        "argv": proposal.argv,
        "cwd": work_dir.to_string_lossy(),
        "exit_code": exec_out.exit_code,
        "stdout": clean_stdout,
        "stderr": clean_stderr,
        "truncated": exec_out.truncated,
        "secrets_redacted": stdout_redacted || stderr_redacted,
        "sandbox_driver": format!("{:?}", exec_out.driver).to_ascii_lowercase(),
        "network_isolated": !allow_net,
        "timeout_seconds": proposal.clamped_timeout_seconds(),
        "changeset_id": changeset_id,
        "classification_reasons": classification.reasons,
    });
    SensitiveDataGuard::redact_json(&mut data);

    Ok(CapabilityResult {
        request_id: request_id.to_string(),
        capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.to_string(),
        status,
        exit_code: exec_out.exit_code,
        message: SensitiveDataGuard::redact_text(&msg).0,
        data,
        stdout_preview: clean_stdout,
        stderr_preview: clean_stderr,
        truncated: exec_out.truncated,
        duration_ms: exec_out.duration_ms,
        changeset_id,
        verification,
        backend_mode: format!(
            "terminal_{}_{}",
            classification.tier.short_label().to_ascii_lowercase(),
            format!("{:?}", exec_out.driver).to_ascii_lowercase()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_capability_sdk::{load_descriptors_from_dir, validate_arguments};
    use intentos_protocol::{InvocationOrigin, Taint};
    use std::os::unix::fs::symlink;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[test]
    fn command_line_literals_preserve_arguments_and_reject_dynamic_syntax() {
        let (program, argv) = parse_command_line(r#"printf '%s' "中文 文件" '' a\ b"#).unwrap();
        assert_eq!(program, "printf");
        assert_eq!(argv, vec!["%s", "中文 文件", "", "a b"]);
        assert_eq!(
            parse_command_line("printf '$HOME'").unwrap().1,
            vec!["$HOME"]
        );
        for raw in [
            "",
            "A=1 id",
            "id; reboot",
            "cat x | sh",
            "echo $(id)",
            "echo `id`",
            "echo $HOME",
            "echo *",
            "echo ~",
            "echo > x",
            "id\nwhoami",
            "echo '",
        ] {
            assert!(parse_command_line(raw).is_err(), "accepted {raw}");
        }
        assert!(
            CommandProposal::from_capability_args(&json!({"command":"id", "program":"rm"}), None)
                .is_err()
        );
        assert!(
            CommandProposal::from_capability_args(&json!({"command":"id", "argv":[]}), None)
                .is_err()
        );
    }

    #[test]
    fn sc03_unfrozen_scripts_fail_closed_before_any_approval() {
        let (_tmp, core, dir) = setup_test_core();
        let script = dir.join("sc03-test.sh");
        std::fs::write(&script, "echo original\\n").unwrap();
        for (program, argv) in [
            ("bash".to_string(), vec![script.to_string_lossy().into_owned()]),
            (script.to_string_lossy().into_owned(), Vec::new()),
            ("python3".to_string(), vec!["-m".into(), "http.server".into()]),
        ] {
            let proposal = CommandProposal {
                program,
                argv,
                cwd: dir.clone(),
                purpose: "SC03 negative gate".into(),
                expected_effect: None,
                required_paths: Vec::new(),
                network_access: false,
                timeout_seconds: 5,
            };
            assert_eq!(
                classify_command_proposal(&core, &proposal).tier,
                TerminalSafetyTier::C4Forbidden,
            );
        }
    }

    #[tokio::test]
    async fn command_line_mutations_require_approval_and_cannot_lower_risk() {
        let (_tmp, core, dir) = setup_test_core();
        let proposal = CommandProposal::from_capability_args(
            &json!({
                "command":"systemctl restart example.service", "cwd":dir,
                "expected_effect":"observe"
            }),
            Some(&core),
        )
        .unwrap();
        let classification = classify_command_proposal(&core, &proposal);
        assert!(classification.requires_approval);
        assert!(!classification.reversible);
        let outcome = execute_command_proposal(
            &core,
            "command-review",
            &make_call("command-review", &proposal),
            &proposal,
        )
        .await
        .unwrap();
        let BrokerDispatchOutcome::RequiresApproval(approval) = outcome else {
            panic!("expected approval");
        };
        assert_eq!(approval.arguments["program"], "systemctl");
        assert_eq!(
            approval.arguments["argv"],
            json!(["restart", "example.service"])
        );
        assert!(approval.arguments.get("command").is_none());
        for command in ["sudo id", "bash -c 'id'", "head /etc/shadow"] {
            let proposal = CommandProposal::from_capability_args(
                &json!({"command":command,"cwd":dir}),
                Some(&core),
            )
            .unwrap();
            assert_eq!(
                classify_command_proposal(&core, &proposal).tier,
                TerminalSafetyTier::C4Forbidden
            );
        }
        let descriptors = load_descriptors_from_dir(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/devtools"),
        )
        .unwrap();
        let descriptor = descriptors
            .iter()
            .find(|d| d.id == TERMINAL_EXECUTE_CAPABILITY_ID)
            .unwrap();
        validate_arguments(&descriptor.input_schema, &json!({"command":"df -h"})).unwrap();
    }

    fn setup_test_core() -> (TempDir, Arc<IntentOsCore>, PathBuf) {
        let tmp = TempDir::new().expect("create tempdir");
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let core = IntentOsCore::initialize(Some(tmp.path()), repo_root)
            .expect("initialize isolated IntentOsCore");
        let auth_dir = core
            .fs_engine
            .authorized_roots()
            .first()
            .expect("at least one authorized root")
            .clone();
        std::fs::create_dir_all(&auth_dir).unwrap();
        (tmp, core, auth_dir)
    }

    fn make_call(task_id: &str, proposal: &CommandProposal) -> CapabilityCall {
        CapabilityCall {
            request_id: format!("req_{}", uuid::Uuid::new_v4().simple()),
            task_id: task_id.to_string(),
            capability_id: TERMINAL_EXECUTE_CAPABILITY_ID.to_string(),
            arguments: proposal.to_capability_args(),
            origin: InvocationOrigin::L2AgentPlan,
            taints: vec![Taint::User],
        }
    }

    #[tokio::test]
    async fn c0_df_and_free_succeed_in_real_bwrap_readonly_sandbox() {
        let (_tmp, core, auth_dir) = setup_test_core();
        let probe = probe_sandbox_support();
        assert!(
            probe.bwrap_userns_ok,
            "Ubuntu host must provide real bwrap userns isolation: {:?}",
            probe
        );

        // 1) `df -h` -> C0ReadOnlyDiag -> auto-executes in bwrap
        let df_prop = CommandProposal {
            program: "df".to_string(),
            argv: vec!["-h".to_string()],
            cwd: auth_dir.clone(),
            purpose: "Inspect disk usage".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 10,
        };
        let df_cls = classify_command_proposal(&core, &df_prop);
        assert_eq!(df_cls.tier, TerminalSafetyTier::C0ReadOnlyDiag);
        assert_eq!(df_cls.effective_effect, Effect::Observe);
        assert!(!df_cls.requires_approval);

        let df_out = execute_command_proposal(
            &core,
            "task_c0_df",
            &make_call("task_c0_df", &df_prop),
            &df_prop,
        )
        .await
        .unwrap();
        let BrokerDispatchOutcome::Executed(df_res) = df_out else {
            panic!("expected C0 df -h to auto-execute");
        };
        assert_eq!(df_res.status, ExecutionStatus::Exited);
        assert_eq!(df_res.exit_code, Some(0));
        assert_eq!(df_res.verification.state, VerificationState::Passed);
        assert_eq!(df_res.data["sandbox_driver"], "bubblewrap");
        assert_eq!(df_res.data["network_isolated"], true);
        assert!(
            df_res.stdout_preview.contains("Filesystem") || df_res.stdout_preview.contains('/'),
            "unexpected df stdout: {}",
            df_res.stdout_preview
        );

        // 2) `free -h` -> C0ReadOnlyDiag -> auto-executes in bwrap
        let free_prop = CommandProposal {
            program: "free".to_string(),
            argv: vec!["-h".to_string()],
            cwd: PathBuf::from("/"),
            purpose: "Check RAM & swap".to_string(),
            expected_effect: None,
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 0, // tests clamping 0 -> 1s
        };
        assert_eq!(free_prop.clamped_timeout_seconds(), 1);
        let free_out = execute_command_proposal(
            &core,
            "task_c0_free",
            &make_call("task_c0_free", &free_prop),
            &free_prop,
        )
        .await
        .unwrap();
        let BrokerDispatchOutcome::Executed(free_res) = free_out else {
            panic!("expected C0 free -h to auto-execute");
        };
        assert_eq!(free_res.status, ExecutionStatus::Exited);
        assert_eq!(free_res.exit_code, Some(0));
        assert!(
            free_res.stdout_preview.contains("Mem:"),
            "unexpected free stdout: {}",
            free_res.stdout_preview
        );
    }

    #[tokio::test]
    async fn c1_rg_find_and_git_status_succeed_inside_authorized_tempdir_in_bwrap() {
        let (_tmp, core, auth_dir) = setup_test_core();
        let repo_dir = auth_dir.join("demo_repo");
        std::fs::create_dir_all(repo_dir.join("src")).unwrap();
        std::fs::write(
            repo_dir.join("src/lib.rs"),
            "pub fn magic_token_m2c() -> u32 { 42 }\n",
        )
        .unwrap();

        let git_init = std::process::Command::new("/usr/bin/git")
            .args(["-C", &repo_dir.to_string_lossy(), "init", "-q"])
            .status()
            .unwrap();
        assert!(git_init.success());

        // 1) `rg magic_token_m2c` inside authorized repo_dir -> C1ScopedRead
        let rg_prop = CommandProposal {
            program: "rg".to_string(),
            argv: vec![
                "-n".to_string(),
                "magic_token_m2c".to_string(),
                "src".to_string(),
            ],
            cwd: repo_dir.clone(),
            purpose: "Search symbol in authorized workspace".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![repo_dir.clone()],
            network_access: false,
            timeout_seconds: 10,
        };
        let rg_cls = classify_command_proposal(&core, &rg_prop);
        assert_eq!(rg_cls.tier, TerminalSafetyTier::C1ScopedRead);
        assert!(!rg_cls.requires_approval);

        let BrokerDispatchOutcome::Executed(rg_res) = execute_command_proposal(
            &core,
            "task_c1_rg",
            &make_call("task_c1_rg", &rg_prop),
            &rg_prop,
        )
        .await
        .unwrap() else {
            panic!("expected C1 rg to execute directly");
        };
        assert_eq!(rg_res.status, ExecutionStatus::Exited);
        assert_eq!(rg_res.data["sandbox_driver"], "bubblewrap");
        assert!(
            rg_res.stdout_preview.contains("src/lib.rs")
                && rg_res.stdout_preview.contains("magic_token_m2c"),
            "unexpected rg stdout: {}",
            rg_res.stdout_preview
        );

        // 2) `git status --short --branch` inside read-only bwrap -> C1ScopedRead
        let git_prop = CommandProposal {
            program: "git".to_string(),
            argv: vec![
                "status".to_string(),
                "--short".to_string(),
                "--branch".to_string(),
            ],
            cwd: repo_dir.clone(),
            purpose: "Inspect git working tree".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![repo_dir.clone()],
            network_access: false,
            timeout_seconds: 10,
        };
        let git_cls = classify_command_proposal(&core, &git_prop);
        assert_eq!(git_cls.tier, TerminalSafetyTier::C1ScopedRead);
        let BrokerDispatchOutcome::Executed(git_res) = execute_command_proposal(
            &core,
            "task_c1_git",
            &make_call("task_c1_git", &git_prop),
            &git_prop,
        )
        .await
        .unwrap() else {
            panic!("expected C1 git status to execute directly");
        };
        assert_eq!(git_res.status, ExecutionStatus::Exited);
        assert!(
            git_res.stdout_preview.contains("?? src/"),
            "unexpected git status output: {}",
            git_res.stdout_preview
        );

        // 3) Safe `find . -name "*.rs"` -> C1ScopedRead, whereas `tail -f` is NOT C1!
        let find_prop = CommandProposal {
            program: "find".to_string(),
            argv: vec![
                ".".to_string(),
                "-maxdepth".to_string(),
                "3".to_string(),
                "-name".to_string(),
                "*.rs".to_string(),
            ],
            cwd: repo_dir.clone(),
            purpose: "List Rust files".to_string(),
            expected_effect: None,
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 10,
        };
        assert_eq!(
            classify_command_proposal(&core, &find_prop).tier,
            TerminalSafetyTier::C1ScopedRead
        );
        let tail_f = CommandProposal {
            program: "tail".to_string(),
            argv: vec!["-f".to_string(), "src/lib.rs".to_string()],
            cwd: repo_dir,
            purpose: "Follow file".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 10,
        };
        let tail_cls = classify_command_proposal(&core, &tail_f);
        assert!(
            tail_cls.tier >= TerminalSafetyTier::C3SystemModify && tail_cls.requires_approval,
            "tail -f must never be C0/C1: {:?}",
            tail_cls
        );
    }

    #[tokio::test]
    async fn anti_bypass_blocks_shells_inline_code_flags_symlinks_secrets_unauth_writes_and_tcp() {
        let (_tmp, core, auth_dir) = setup_test_core();
        let outside_tmp = TempDir::new().unwrap();
        let outside_secret = outside_tmp.path().join("outside_secret.txt");
        std::fs::write(&outside_secret, "TOP_SECRET_OUTSIDE").unwrap();

        // 1) `bash -c "id"` & `python3 -c "open('x','w')"` & `node -e` & `perl -e` & `ruby -e`
        //    masquerading with `expected_effect: Some(Effect::Observe)` -> C4Forbidden (`Denied`)!
        for (prog, argv) in [
            ("bash", vec!["-c", "id"]),
            ("sh", vec!["-c", "whoami"]),
            ("python3", vec!["-c", "open('x','w').write('pwn')"]),
            ("node", vec!["-e", "process.exit(0)"]),
            ("perl", vec!["-e", "system('id')"]),
            ("ruby", vec!["-e", "puts 1"]),
            ("awk", vec!["BEGIN { system(\"id\") }"]),
            (
                "tar",
                vec!["--checkpoint-action=exec=sh", "-cf", "a.tar", "."],
            ),
            ("git", vec!["-c", "core.sshCommand=sh", "status"]),
            ("rg", vec!["--pre", "sh", "needle", "."]),
            ("find", vec![".", "-exec", "id", "{}", ";"]),
        ] {
            let prop = CommandProposal {
                program: prog.to_string(),
                argv: argv.into_iter().map(String::from).collect(),
                cwd: auth_dir.clone(),
                purpose: "Masquerade as read-only".to_string(),
                expected_effect: Some(Effect::Observe),
                required_paths: vec![],
                network_access: false,
                timeout_seconds: 5,
            };
            let cls = classify_command_proposal(&core, &prop);
            assert_eq!(
                cls.tier,
                TerminalSafetyTier::C4Forbidden,
                "expected C4Forbidden for {} {:?}, got {:?}",
                prog,
                prop.argv,
                cls
            );
            assert!(cls.downgrade_attempt_blocked);
            let out =
                execute_command_proposal(&core, "t_bypass", &make_call("t_bypass", &prop), &prop)
                    .await
                    .unwrap();
            assert!(matches!(out, BrokerDispatchOutcome::Denied { .. }));
        }

        // 2) `find . -delete`, `sed -i`, `git clean/reset/push`, `curl -o/-d/-T` are NEVER C0/C1!
        let existing_file = auth_dir.join("notes.txt");
        std::fs::write(&existing_file, "hello world\n").unwrap();

        let find_del = CommandProposal {
            program: "find".to_string(),
            argv: vec![
                ".".to_string(),
                "-name".to_string(),
                "*.tmp".to_string(),
                "-delete".to_string(),
            ],
            cwd: auth_dir.clone(),
            purpose: "Delete temp files".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 5,
        };
        let find_del_cls = classify_command_proposal(&core, &find_del);
        assert_eq!(find_del_cls.tier, TerminalSafetyTier::C3SystemModify);
        assert!(find_del_cls.requires_approval && !find_del_cls.reversible);
        assert!(find_del_cls.downgrade_attempt_blocked);

        let sed_i = CommandProposal {
            program: "sed".to_string(),
            argv: vec![
                "-i".to_string(),
                "s/hello/hi/g".to_string(),
                existing_file.to_string_lossy().to_string(),
            ],
            cwd: auth_dir.clone(),
            purpose: "In-place edit".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 5,
        };
        let sed_cls = classify_command_proposal(&core, &sed_i);
        assert_eq!(sed_cls.tier, TerminalSafetyTier::C2ReversibleWrite);
        assert!(sed_cls.requires_approval);
        assert!(sed_cls.downgrade_attempt_blocked);

        for (prog, args) in [
            ("git", vec!["clean", "-fd"]),
            ("git", vec!["reset", "--hard"]),
            ("git", vec!["push", "origin", "main"]),
            ("curl", vec!["-o", "dl.txt", "https://example.com"]),
            ("curl", vec!["-d", "k=v", "https://example.com"]),
            ("curl", vec!["-T", "notes.txt", "https://example.com"]),
        ] {
            let p = CommandProposal {
                program: prog.to_string(),
                argv: args.into_iter().map(String::from).collect(),
                cwd: auth_dir.clone(),
                purpose: "Check mutating/egress flags".to_string(),
                expected_effect: Some(Effect::Observe),
                required_paths: vec![],
                network_access: false,
                timeout_seconds: 5,
            };
            let c = classify_command_proposal(&core, &p);
            assert!(
                c.tier >= TerminalSafetyTier::C3SystemModify && c.requires_approval,
                "expected >= C3 for {} {:?}, got {:?}",
                prog,
                p.argv,
                c
            );
        }

        // 3) Executable symlink masquerade: symlink named `df` pointing to `/bin/sh`!
        let fake_bin_dir = TempDir::new().unwrap();
        let fake_df = fake_bin_dir.path().join("df");
        symlink("/bin/sh", &fake_df).unwrap();

        // 3a) Explicit path to symlink `/tmp/.../df`
        let sym_exec_explicit = CommandProposal {
            program: fake_df.to_string_lossy().to_string(),
            argv: vec!["-h".to_string()],
            cwd: auth_dir.clone(),
            purpose: "Fake df".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 5,
        };
        assert_eq!(
            classify_command_proposal(&core, &sym_exec_explicit).tier,
            TerminalSafetyTier::C4Forbidden
        );

        // 3b) Bare `df` resolved from a trusted bin dir containing `df -> /bin/sh`
        let sym_exec_bare = CommandProposal {
            program: "df".to_string(),
            argv: vec!["-h".to_string()],
            cwd: auth_dir.clone(),
            purpose: "Fake df in bin dir".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 5,
        };
        let bare_cls = classify_command_proposal_with_bin_dirs(
            &core,
            &sym_exec_bare,
            &[fake_bin_dir.path().to_path_buf()],
        );
        assert_eq!(bare_cls.tier, TerminalSafetyTier::C4Forbidden);

        // 4) Data symlink escape inside authorized workspace pointing outside authorized root!
        let escape_link = auth_dir.join("innocent_readme.md");
        symlink(&outside_secret, &escape_link).unwrap();
        let read_escape = CommandProposal {
            program: "head".to_string(),
            argv: vec![
                "-n".to_string(),
                "5".to_string(),
                escape_link.to_string_lossy().to_string(),
            ],
            cwd: auth_dir.clone(),
            purpose: "Read symlink".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 5,
        };
        assert_eq!(
            classify_command_proposal(&core, &read_escape).tier,
            TerminalSafetyTier::C4Forbidden
        );
        let _ = std::fs::remove_file(&escape_link);

        // 5) Reading `~/.ssh` or `ui.sock` or `LD_PRELOAD` injection -> C4Forbidden (`Denied`)
        for bad_arg in [
            "~/.ssh/id_ed25519",
            "~/.gnupg",
            "/run/user/1000/intentos/ui.sock",
            "LD_PRELOAD=/tmp/evil.so",
        ] {
            let ssh_prop = CommandProposal {
                program: "ls".to_string(),
                argv: vec![bad_arg.to_string()],
                cwd: auth_dir.clone(),
                purpose: "Probe secret".to_string(),
                expected_effect: Some(Effect::Observe),
                required_paths: vec![],
                network_access: false,
                timeout_seconds: 5,
            };
            assert_eq!(
                classify_command_proposal(&core, &ssh_prop).tier,
                TerminalSafetyTier::C4Forbidden,
                "expected C4Forbidden for arg {}",
                bad_arg
            );
        }

        // 6) Writing outside authorized dir -> C4Forbidden (`Denied`)
        let outside_write_target = outside_tmp.path().join("unauthorized_write.txt");
        let write_out_prop = CommandProposal {
            program: "touch".to_string(),
            argv: vec![outside_write_target.to_string_lossy().to_string()],
            cwd: auth_dir.clone(),
            purpose: "Write outside authorized scope".to_string(),
            expected_effect: None,
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 5,
        };
        let out_write_res = execute_command_proposal(
            &core,
            "t_out_write",
            &make_call("t_out_write", &write_out_prop),
            &write_out_prop,
        )
        .await
        .unwrap();
        assert!(matches!(
            out_write_res,
            BrokerDispatchOutcome::Denied { .. }
        ));
        assert!(!outside_write_target.exists());

        // 6b) Running an interpreter script outside authorized scope (even with authorized `cwd`) -> C4Forbidden
        let outside_script = outside_tmp.path().join("evil.py");
        std::fs::write(&outside_script, "print('evil')\n").unwrap();
        let outside_script_prop = CommandProposal {
            program: "python3".to_string(),
            argv: vec![outside_script.to_string_lossy().to_string()],
            cwd: auth_dir.clone(),
            purpose: "Attempt outside script".to_string(),
            expected_effect: None,
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 5,
        };
        assert_eq!(
            classify_command_proposal(&core, &outside_script_prop).tier,
            TerminalSafetyTier::C4Forbidden
        );

        // 7) Unauthorized TCP connect:
        //    (a) `network_access: true` upgrades `df -h` out of C0 to C3SystemModify (`RequiresApproval`)
        let net_prop = CommandProposal {
            program: "df".to_string(),
            argv: vec!["-h".to_string()],
            cwd: auth_dir.clone(),
            purpose: "df requesting net".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: true,
            timeout_seconds: 5,
        };
        let net_cls = classify_command_proposal(&core, &net_prop);
        assert_eq!(net_cls.tier, TerminalSafetyTier::C3SystemModify);
        assert!(net_cls.requires_approval && !net_cls.reversible);

        //    (b) Real kernel `--unshare-net` proof: start a real TCP listener on host 127.0.0.1:0,
        //        run an approved workspace Python script with `network_access: false`, and prove
        //        kernel network namespace blocks connecting to host loopback!
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let net_probe_script = auth_dir.join("net_probe.py");
        std::fs::write(
            &net_probe_script,
            format!(
                "import socket, sys\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.settimeout(1.0)\ntry:\n    s.connect(('127.0.0.1', {}))\n    print('TCP_ESCAPED')\n    sys.exit(2)\nexcept OSError as e:\n    print('TCP_KERNEL_BLOCKED', e.errno)\n    sys.exit(0)\n",
                port
            ),
        )
        .unwrap();

        let script_prop = CommandProposal {
            program: "python3".to_string(),
            argv: vec![net_probe_script.to_string_lossy().to_string()],
            cwd: auth_dir.clone(),
            purpose: "Verify offline sandbox TCP block".to_string(),
            expected_effect: None,
            required_paths: vec![auth_dir.clone()],
            network_access: false,
            timeout_seconds: 10,
        };
        // Without approval, C3 script requires approval first
        let script_dispatch = execute_command_proposal(
            &core,
            "t_net_script",
            &make_call("t_net_script", &script_prop),
            &script_prop,
        )
        .await
        .unwrap();
        assert!(matches!(
            script_dispatch,
            BrokerDispatchOutcome::RequiresApproval(_)
        ));

        // When approved, runs inside offline `bwrap --unshare-net` and TCP connect to host is blocked!
        let approved_res =
            execute_approved_command_proposal(&core, "req_net", "t_net_script", &script_prop)
                .await
                .unwrap();
        assert_eq!(approved_res.exit_code, Some(0));
        assert!(
            approved_res.stdout_preview.contains("TCP_KERNEL_BLOCKED"),
            "expected kernel netns block, got stdout={}, stderr={}",
            approved_res.stdout_preview,
            approved_res.stderr_preview
        );
        drop(listener);
    }

    #[tokio::test]
    async fn c4_sudo_and_etc_shadow_unconditionally_denied() {
        let (_tmp, core, auth_dir) = setup_test_core();

        for (prog, argv) in [
            ("sudo", vec!["id"]),
            ("pkexec", vec!["id"]),
            ("head", vec!["-n", "1", "/etc/shadow"]),
            (
                "dd",
                vec!["if=/dev/zero", "of=/dev/sda", "bs=512", "count=1"],
            ),
            ("rm", vec!["-rf", "/"]),
            ("rm", vec!["-rf", "~"]),
        ] {
            let prop = CommandProposal {
                program: prog.to_string(),
                argv: argv.into_iter().map(String::from).collect(),
                cwd: auth_dir.clone(),
                purpose: "Test C4 hard block".to_string(),
                expected_effect: None,
                required_paths: vec![],
                network_access: false,
                timeout_seconds: 5,
            };
            let cls = classify_command_proposal(&core, &prop);
            assert_eq!(cls.tier, TerminalSafetyTier::C4Forbidden);
            assert!(cls.denied);

            let out =
                execute_command_proposal(&core, "task_c4", &make_call("task_c4", &prop), &prop)
                    .await
                    .unwrap();
            assert!(
                matches!(out, BrokerDispatchOutcome::Denied { .. }),
                "expected Denied for {} {:?}",
                prog,
                prop.argv
            );

            // Defense-in-depth: even `execute_approved_command_proposal` refuses C4!
            assert!(
                execute_approved_command_proposal(&core, "req_c4", "task_c4", &prop)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn c3_apt_get_and_systemctl_require_approval_and_never_claim_reversible() {
        let (_tmp, core, auth_dir) = setup_test_core();

        for (prog, argv) in [
            ("apt-get", vec!["install", "-y", "htop"]),
            ("systemctl", vec!["restart", "foo.service"]),
            ("pip", vec!["install", "requests"]),
            ("cargo", vec!["build", "--release"]),
        ] {
            let prop = CommandProposal {
                program: prog.to_string(),
                argv: argv.into_iter().map(String::from).collect(),
                cwd: auth_dir.clone(),
                purpose: "System/package mutation".to_string(),
                expected_effect: Some(Effect::WriteReversible), // attempt to fake reversible
                required_paths: vec![],
                network_access: false,
                timeout_seconds: 30,
            };
            let cls = classify_command_proposal(&core, &prop);
            assert_eq!(cls.tier, TerminalSafetyTier::C3SystemModify);
            assert!(cls.requires_approval);
            assert!(!cls.reversible, "{} must NEVER be marked reversible", prog);
            assert!(cls.downgrade_attempt_blocked);

            let out =
                execute_command_proposal(&core, "task_c3", &make_call("task_c3", &prop), &prop)
                    .await
                    .unwrap();
            let BrokerDispatchOutcome::RequiresApproval(pa) = out else {
                panic!("expected RequiresApproval for {} {:?}", prog, prop.argv);
            };
            assert!(
                !pa.reversible,
                "PendingApproval for {} MUST have reversible == false!",
                prog
            );
            assert!(
                pa.effects
                    .iter()
                    .any(|e| matches!(e, Effect::SystemAdmin | Effect::WriteDestructive))
            );
        }
    }

    #[tokio::test]
    async fn c2_reversible_write_requires_approval_snapshots_changeset_and_undoes_plus_redacts() {
        let (_tmp, core, auth_dir) = setup_test_core();
        let doc = auth_dir.join("draft.txt");
        let original_bytes = b"version = 1\nstatus = clean\n";
        std::fs::write(&doc, original_bytes).unwrap();

        let sed_prop = CommandProposal {
            program: "sed".to_string(),
            argv: vec![
                "-i".to_string(),
                "s/version = 1/version = 2/g".to_string(),
                doc.to_string_lossy().to_string(),
            ],
            cwd: auth_dir.clone(),
            purpose: "Bump draft version".to_string(),
            expected_effect: None,
            required_paths: vec![doc.clone()],
            network_access: false,
            timeout_seconds: 10,
        };

        // 1) Initial call returns RequiresApproval with reversible == true
        let dispatch_out = execute_command_proposal(
            &core,
            "task_c2_undo",
            &make_call("task_c2_undo", &sed_prop),
            &sed_prop,
        )
        .await
        .unwrap();
        let BrokerDispatchOutcome::RequiresApproval(pa) = dispatch_out else {
            panic!("expected RequiresApproval for C2 sed -i");
        };
        assert!(pa.reversible);
        assert_eq!(std::fs::read(&doc).unwrap(), original_bytes);

        // 2) Verify & consume PendingApproval nonce/digest, then execute inside confined bwrap
        let consumed = core
            .policy
            .verify_and_consume(&pa.approval_id, &pa.nonce, &pa.digest)
            .expect("nonce approval valid");
        let res = execute_approved_terminal_call(
            &core,
            &consumed.approval_id,
            &consumed.task_id,
            &consumed.arguments,
        )
        .await
        .unwrap();
        assert_eq!(res.status, ExecutionStatus::Exited);
        assert!(res.changeset_id.is_some());
        assert_eq!(
            String::from_utf8_lossy(&std::fs::read(&doc).unwrap()),
            "version = 2\nstatus = clean\n"
        );

        // 3) Atomic Undo via `CapabilityBroker::undo_changeset` restores exact original bytes!
        let (undone_cs, _msg) = core
            .broker
            .undo_changeset(res.changeset_id.as_deref())
            .expect("undo C2 terminal changeset");
        assert_eq!(undone_cs.status, ChangeSetStatus::Undone);
        assert_eq!(std::fs::read(&doc).unwrap(), original_bytes);

        // 3b) Also verify `cp` creating a new file in workspace + atomic Undo removes created copy!
        let copied_doc = auth_dir.join("draft_copy.txt");
        let cp_prop = CommandProposal {
            program: "cp".to_string(),
            argv: vec![
                doc.to_string_lossy().to_string(),
                copied_doc.to_string_lossy().to_string(),
            ],
            cwd: auth_dir.clone(),
            purpose: "Copy draft".to_string(),
            expected_effect: None,
            required_paths: vec![doc.clone(), copied_doc.clone()],
            network_access: false,
            timeout_seconds: 10,
        };
        let BrokerDispatchOutcome::RequiresApproval(cp_pa) = execute_command_proposal(
            &core,
            "task_c2_cp",
            &make_call("task_c2_cp", &cp_prop),
            &cp_prop,
        )
        .await
        .unwrap() else {
            panic!("expected RequiresApproval for C2 cp");
        };
        assert!(cp_pa.reversible);
        let cp_consumed = core
            .policy
            .verify_and_consume(&cp_pa.approval_id, &cp_pa.nonce, &cp_pa.digest)
            .unwrap();
        let cp_res = execute_approved_terminal_call(
            &core,
            &cp_consumed.approval_id,
            &cp_consumed.task_id,
            &cp_consumed.arguments,
        )
        .await
        .unwrap();
        assert!(copied_doc.is_file());
        let (cp_undone, _) = core
            .broker
            .undo_changeset(cp_res.changeset_id.as_deref())
            .unwrap();
        assert_eq!(cp_undone.status, ChangeSetStatus::Undone);
        assert!(!copied_doc.exists());
        assert_eq!(std::fs::read(&doc).unwrap(), original_bytes);

        // 4) SensitiveDataGuard scrubs any leaked secrets in C1 stdout!
        let secret_doc = auth_dir.join("config_sample.txt");
        std::fs::write(
            &secret_doc,
            "OPENAI_KEY=sk-testSecretKeyValue1234567890ABCD\n",
        )
        .unwrap();
        let head_prop = CommandProposal {
            program: "head".to_string(),
            argv: vec![
                "-n".to_string(),
                "1".to_string(),
                secret_doc.to_string_lossy().to_string(),
            ],
            cwd: auth_dir,
            purpose: "Inspect sample header".to_string(),
            expected_effect: None,
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 5,
        };
        let BrokerDispatchOutcome::Executed(head_res) = execute_command_proposal(
            &core,
            "task_redact",
            &make_call("task_redact", &head_prop),
            &head_prop,
        )
        .await
        .unwrap() else {
            panic!("expected C1 head to execute");
        };
        assert!(head_res.stdout_preview.contains("[REDACTED_SECRET]"));
        assert!(!head_res.stdout_preview.contains("sk-testSecretKeyValue"));
    }

    #[test]
    fn yaml_descriptor_terminal_execute_loads_and_validates_schema() {
        let devtools_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/devtools");
        let descs = load_descriptors_from_dir(&devtools_dir).expect("load devtools descriptors");
        let term_desc = descs
            .iter()
            .find(|d| d.id == TERMINAL_EXECUTE_CAPABILITY_ID)
            .expect("terminal.execute descriptor must exist");

        let sample = CommandProposal {
            program: "df".to_string(),
            argv: vec!["-h".to_string()],
            cwd: PathBuf::from("/tmp"),
            purpose: "Check disk space".to_string(),
            expected_effect: Some(Effect::Observe),
            required_paths: vec![],
            network_access: false,
            timeout_seconds: 120, // schema permits >60 so runtime clamps to 60
        };
        assert_eq!(sample.clamped_timeout_seconds(), 60);
        let args = sample.to_capability_args();
        validate_arguments(&term_desc.input_schema, &args).expect("schema validation passes");
    }
}
