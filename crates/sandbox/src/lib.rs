//! Worker, E2 & External CLI Agent OS Sandbox Launcher (§6.6, §8.4, M1.1 H04).
//! Primary: Bubblewrap (`bwrap --unshare-user --unshare-pid ... --tmpfs /tmp --clearenv`) when available.
//! Fallback / Defense-in-depth: Linux Landlock (FS + ABI v4 TCP network block) + `PR_SET_NO_NEW_PRIVS` + clean environment.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use thiserror::Error;
use tokio::process::Command;

// Linux Landlock syscall numbers (x86_64 & aarch64 >= 5.13 / 6.7+)
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// Landlock FS access rights (ABI v1)
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

const FS_READ_EXEC: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
const FS_READ_WRITE_ALL: u64 = FS_READ_EXEC
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

// Landlock Network access rights (ABI v4, Linux 6.7+)
const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

/// Relative user credential directories/files that MUST NEVER be exposed inside a sandbox.
pub const FORBIDDEN_CREDENTIAL_REL_PATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".config/gcloud",
    ".kube",
    ".docker",
    ".pki",
    ".local/share/keyrings",
    ".netrc",
    ".git-credentials",
];

/// Host secret / ambient authority environment variables stripped from sandboxed child processes.
pub const SENSITIVE_HOST_ENV_KEYS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "KUBECONFIG",
    "DOCKER_AUTH_CONFIG",
    "NPM_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "PYPI_API_TOKEN",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
];

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDriver {
    Bubblewrap,
    Landlock,
    NodePermission,
    ProcessCleanEnv,
}

impl SandboxDriver {
    /// Returns `true` ONLY when kernel-level OS filesystem isolation (`Bubblewrap` mount namespace
    /// or Linux `Landlock` LSM) is actively enforced.
    pub fn enforces_os_fs_isolation(self) -> bool {
        matches!(self, Self::Bubblewrap | Self::Landlock)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProbe {
    pub bwrap_path: Option<String>,
    pub bwrap_userns_ok: bool,
    pub landlock_abi_version: Option<i32>,
    pub node_permission_available: bool,
    pub selected_driver: SandboxDriver,
}

impl SandboxProbe {
    /// Whether this host probe provides real kernel-enforced filesystem isolation.
    pub fn has_os_isolation(&self) -> bool {
        self.selected_driver.enforces_os_fs_isolation()
    }

    /// Construct a probe representing an environment where OS sandboxing is unavailable/disabled.
    pub fn disabled_for_policy() -> Self {
        Self {
            bwrap_path: None,
            bwrap_userns_ok: false,
            landlock_abi_version: None,
            node_permission_available: false,
            selected_driver: SandboxDriver::ProcessCleanEnv,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub readonly_paths: Vec<PathBuf>,
    pub readwrite_paths: Vec<PathBuf>,
    pub env_vars: BTreeMap<String, String>,
    pub work_dir: PathBuf,
    pub allow_tcp_network: bool,
}

/// Explicit source-to-destination read-only bind mount (`--ro-bind src dst`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMountPair {
    pub src: PathBuf,
    pub dst: PathBuf,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("failed to configure sandbox: {0}")]
    Setup(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

const NODE_ZERO_TCP_IMPORT: &str = "data:text/javascript,import net from \"node:net\";import dgram from \"node:dgram\";const orig=net.Socket.prototype.connect;const allowedSock=process.env.INTENTOS_GATEWAY_SOCK||\"\";net.Socket.prototype.connect=function(...args){const f=args[0];let sp=null;if(typeof f===\"string\"){sp=f;}else if(Array.isArray(f)&&f[0]&&typeof f[0]===\"object\"){sp=f[0].path||f[0].socketPath||null;}else if(f&&typeof f===\"object\"){sp=f.path||f.socketPath||null;}const ok=Boolean(sp)&&(!allowedSock||sp===allowedSock);if(!ok){const err=new Error(sp?\"Unauthorized Unix socket blocked by IntentOS sandbox\":\"TCP network disabled by IntentOS sandbox\");err.code=\"EACCES\";process.nextTick(()=>this.emit(\"error\",err));return this;}return orig.apply(this,args);};dgram.createSocket=()=>{const err=new Error(\"UDP disabled by IntentOS sandbox\");err.code=\"EACCES\";throw err;};globalThis.fetch=async()=>{const err=new Error(\"Fetch disabled by IntentOS sandbox\");err.code=\"EACCES\";throw err;};";

/// Check whether `path` targets a forbidden host credential directory or secret file
/// (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `/etc/shadow`, etc.).
pub fn is_forbidden_credential_path(path: &Path) -> bool {
    if path == Path::new("/etc/shadow") || path == Path::new("/etc/gshadow") {
        return true;
    }

    let components: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    for (idx, comp) in components.iter().enumerate() {
        if matches!(
            comp.as_str(),
            ".ssh"
                | ".gnupg"
                | ".aws"
                | ".kube"
                | ".docker"
                | ".netrc"
                | ".git-credentials"
                | ".pki"
        ) {
            return true;
        }
        if comp == ".config" && components.get(idx + 1).is_some_and(|next| next == "gcloud") {
            return true;
        }
        if comp == ".local"
            && components.get(idx + 1).is_some_and(|n1| n1 == "share")
            && components.get(idx + 2).is_some_and(|n2| n2 == "keyrings")
        {
            return true;
        }
    }

    false
}

/// Returns `true` if `key` is an unrelated host secret or ambient session bus variable
/// that must be stripped before spawning an external subprocess.
pub fn is_sensitive_host_env_key(key: &str) -> bool {
    let upper = key.trim().to_ascii_uppercase();
    if SENSITIVE_HOST_ENV_KEYS.contains(&upper.as_str()) {
        return true;
    }
    upper.ends_with("_PRIVATE_KEY")
        || upper.ends_with("_SECRET_KEY")
        || upper.ends_with("_CLIENT_SECRET")
        || upper.ends_with("_SESSION_TOKEN")
        || upper == "DOTENV_KEY"
}

/// Return a sanitized copy of `env_vars` with all `SENSITIVE_HOST_ENV_KEYS` stripped.
pub fn sanitize_env_map(env_vars: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    env_vars
        .iter()
        .filter(|(k, _)| !is_sensitive_host_env_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn probe_sandbox_live() -> SandboxProbe {
    let bwrap_path = find_in_path("bwrap");
    let bwrap_userns_ok = if let Some(ref bp) = bwrap_path {
        std::process::Command::new(bp)
            .args([
                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--ro-bind",
                "/",
                "/",
                "--tmpfs",
                "/tmp",
                "/bin/true",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        false
    };

    let landlock_abi_version = query_landlock_abi();
    let node_permission_available = find_in_path("node").is_some();
    let selected_driver = if bwrap_userns_ok {
        SandboxDriver::Bubblewrap
    } else if landlock_abi_version.unwrap_or(0) >= 1 {
        SandboxDriver::Landlock
    } else if node_permission_available {
        SandboxDriver::NodePermission
    } else {
        SandboxDriver::ProcessCleanEnv
    };

    SandboxProbe {
        bwrap_path,
        bwrap_userns_ok,
        landlock_abi_version,
        node_permission_available,
        selected_driver,
    }
}

/// Cached probe of OS sandbox support on the current Linux host (`Bubblewrap` / `Landlock`).
pub fn probe_sandbox_support() -> SandboxProbe {
    static CACHED_PROBE: OnceLock<SandboxProbe> = OnceLock::new();
    CACHED_PROBE.get_or_init(probe_sandbox_live).clone()
}

/// Probe available sandbox primitives on the current Linux host.
pub fn probe_sandbox() -> SandboxProbe {
    probe_sandbox_support()
}

pub fn query_landlock_abi() -> Option<i32> {
    // SAFETY: Querying Landlock ABI version passes NULL attr, 0 size, and VERSION flag.
    let v = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if v >= 1 { Some(v as i32) } else { None }
}

fn append_bwrap_credential_masks(cmd: &mut Command, bound_dir: &Path) {
    if !bound_dir.is_dir() {
        return;
    }
    for rel in FORBIDDEN_CREDENTIAL_REL_PATHS {
        let candidate = bound_dir.join(rel);
        if candidate.is_dir() {
            cmd.arg("--tmpfs").arg(&candidate);
        } else if candidate.is_file() && Path::new("/dev/null").exists() {
            cmd.arg("--ro-bind").arg("/dev/null").arg(&candidate);
        }
    }
}

/// Build an isolated `tokio::process::Command` enforcing no-HOME, no-DBus, clean env,
/// private `/tmp` tmpfs, hidden credential dirs, and optional TCP network isolation.
pub fn build_sandboxed_command(
    spec: &SandboxSpec,
) -> Result<(Command, SandboxDriver), SandboxError> {
    let probe = probe_sandbox_support();
    build_sandboxed_command_with_mounts(spec, &[], &probe)
}

/// Build an isolated `tokio::process::Command` with explicit source->destination read-only bind mounts
/// and a caller-supplied `SandboxProbe` (enabling deterministic policy tests when OS sandboxing is disabled).
pub fn build_sandboxed_command_with_mounts(
    spec: &SandboxSpec,
    extra_ro_mounts: &[BindMountPair],
    probe: &SandboxProbe,
) -> Result<(Command, SandboxDriver), SandboxError> {
    let clean_env = sanitize_env_map(&spec.env_vars);

    if probe.selected_driver == SandboxDriver::Bubblewrap
        && probe.bwrap_userns_ok
        && let Some(ref bwrap) = probe.bwrap_path
    {
        let mut cmd = Command::new(bwrap);
        cmd.env_clear();
        cmd.kill_on_drop(true);
        cmd.arg("--unshare-user")
            .arg("--unshare-pid")
            .arg("--unshare-uts")
            .arg("--unshare-ipc")
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--clearenv")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--tmpfs")
            .arg("/tmp");

        if !spec.allow_tcp_network {
            cmd.arg("--unshare-net");
        }

        for sys_ro in [
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/etc/alternatives",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/localtime",
            "/etc/ssl/certs",
            "/etc/ssl/openssl.cnf",
            "/etc/ca-certificates",
            "/etc/pki",
        ] {
            if Path::new(sys_ro).exists() {
                cmd.arg("--ro-bind").arg(sys_ro).arg(sys_ro);
            }
        }

        if spec.allow_tcp_network {
            for net_ro in ["/etc/hosts", "/etc/nsswitch.conf"] {
                if Path::new(net_ro).exists() {
                    cmd.arg("--ro-bind").arg(net_ro).arg(net_ro);
                }
            }
            let resolv = Path::new("/etc/resolv.conf");
            if let Ok(canon_resolv) = std::fs::canonicalize(resolv)
                && canon_resolv.exists()
            {
                cmd.arg("--ro-bind").arg(canon_resolv).arg(resolv);
            } else if resolv.exists() {
                cmd.arg("--ro-bind").arg(resolv).arg(resolv);
            }
        }

        for ro in &spec.readonly_paths {
            if ro.exists() && !is_forbidden_credential_path(ro) {
                cmd.arg("--ro-bind").arg(ro).arg(ro);
                append_bwrap_credential_masks(&mut cmd, ro);
            }
        }
        for rw in &spec.readwrite_paths {
            if rw.exists() && !is_forbidden_credential_path(rw) {
                cmd.arg("--bind").arg(rw).arg(rw);
                append_bwrap_credential_masks(&mut cmd, rw);
            }
        }
        // Overlay explicit `src -> dst` read-only mounts AFTER `readwrite_paths` so staged
        // auth/config files inside a private `HOME` stay kernel-enforced read-only!
        for pair in extra_ro_mounts {
            if pair.src.exists()
                && !is_forbidden_credential_path(&pair.src)
                && !is_forbidden_credential_path(&pair.dst)
            {
                cmd.arg("--ro-bind").arg(&pair.src).arg(&pair.dst);
            }
        }

        for (k, v) in &clean_env {
            cmd.arg("--setenv").arg(k).arg(v);
        }
        cmd.arg("--chdir").arg(&spec.work_dir);
        cmd.arg("--").arg(&spec.program).args(&spec.args);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        return Ok((cmd, SandboxDriver::Bubblewrap));
    }

    let is_node_program = spec
        .program
        .file_name()
        .and_then(|s| s.to_str())
        .map(|n| n == "node" || n.starts_with("node"))
        .unwrap_or(false);

    let mut final_args = Vec::new();
    let mut using_node_perm = false;
    if is_node_program && probe.landlock_abi_version.is_none() && probe.node_permission_available {
        using_node_perm = true;
        final_args.push("--permission".to_string());
        let mut read_allow = vec![
            PathBuf::from("/usr"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/etc/ssl"),
        ];
        read_allow.extend(
            spec.readonly_paths
                .iter()
                .filter(|p| !is_forbidden_credential_path(p))
                .cloned(),
        );
        read_allow.extend(
            spec.readwrite_paths
                .iter()
                .filter(|p| !is_forbidden_credential_path(p))
                .cloned(),
        );
        read_allow.extend(
            extra_ro_mounts
                .iter()
                .filter(|m| !is_forbidden_credential_path(&m.src))
                .map(|m| m.src.clone()),
        );
        for rp in read_allow {
            if rp.exists() {
                let canon = std::fs::canonicalize(&rp).unwrap_or(rp);
                final_args.push(format!("--allow-fs-read={}", canon.display()));
            }
        }
        for wp in &spec.readwrite_paths {
            if wp.exists() && !is_forbidden_credential_path(wp) {
                let canon = std::fs::canonicalize(wp).unwrap_or_else(|_| wp.clone());
                final_args.push(format!("--allow-fs-write={}", canon.display()));
            }
        }
        if !spec.allow_tcp_network {
            final_args.push("--import".to_string());
            final_args.push(NODE_ZERO_TCP_IMPORT.to_string());
        }
    }
    final_args.extend(spec.args.clone());

    // Landlock + Clean Environment + New Process Group isolation
    let mut cmd = Command::new(&spec.program);
    cmd.args(&final_args)
        .current_dir(&spec.work_dir)
        .env_clear()
        .envs(&clean_env)
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(abi) = probe.landlock_abi_version {
        let mut ro_list = vec![
            PathBuf::from("/usr"),
            PathBuf::from("/bin"),
            PathBuf::from("/sbin"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/etc/ld.so.cache"),
            PathBuf::from("/etc/ssl/certs"),
            PathBuf::from("/etc/ssl/openssl.cnf"),
            PathBuf::from("/etc/ca-certificates"),
            PathBuf::from("/proc"),
        ];
        if spec.allow_tcp_network {
            ro_list.push(PathBuf::from("/etc/hosts"));
            ro_list.push(PathBuf::from("/etc/nsswitch.conf"));
            if let Ok(canon_resolv) = std::fs::canonicalize("/etc/resolv.conf") {
                ro_list.push(canon_resolv);
            }
        }
        ro_list.extend(
            spec.readonly_paths
                .iter()
                .filter(|p| !is_forbidden_credential_path(p))
                .cloned(),
        );
        ro_list.extend(
            extra_ro_mounts
                .iter()
                .filter(|m| !is_forbidden_credential_path(&m.src))
                .map(|m| m.src.clone()),
        );
        let mut rw_list = vec![PathBuf::from("/dev/null"), PathBuf::from("/dev/urandom")];
        rw_list.extend(
            spec.readwrite_paths
                .iter()
                .filter(|p| !is_forbidden_credential_path(p))
                .cloned(),
        );
        let block_tcp = !spec.allow_tcp_network && abi >= 4;

        // SAFETY: `pre_exec` runs in the forked child before execve, using async-signal-safe syscalls
        // to set PR_SET_NO_NEW_PRIVS, process group, and Landlock FS/TCP restrictions.
        unsafe {
            cmd.pre_exec(move || {
                libc::setpgid(0, 0);
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                apply_landlock_in_child(&ro_list, &rw_list, block_tcp)?;
                Ok(())
            });
        }
        return Ok((cmd, SandboxDriver::Landlock));
    }

    // Enforce PR_SET_NO_NEW_PRIVS + process group + Node runtime permission sandbox
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            Ok(())
        });
    }
    Ok((
        cmd,
        if using_node_perm {
            SandboxDriver::NodePermission
        } else {
            SandboxDriver::ProcessCleanEnv
        },
    ))
}

fn apply_landlock_in_child(
    ro_paths: &[PathBuf],
    rw_paths: &[PathBuf],
    block_tcp: bool,
) -> std::io::Result<()> {
    let attr = LandlockRulesetAttr {
        handled_access_fs: FS_READ_WRITE_ALL,
        handled_access_net: if block_tcp {
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        } else {
            0
        },
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ruleset_fd = ruleset_fd as i32;

    for p in ro_paths {
        add_landlock_path_rule(ruleset_fd, p, FS_READ_EXEC);
    }
    for p in rw_paths {
        add_landlock_path_rule(ruleset_fd, p, FS_READ_WRITE_ALL);
    }

    let rc = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    unsafe {
        libc::close(ruleset_fd);
    }
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn add_landlock_path_rule(ruleset_fd: i32, path: &Path, access: u64) {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let is_dir = unsafe { libc::fstat(fd, &mut st as *mut libc::stat) == 0 }
        && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let effective_access = if is_dir {
        access
    } else {
        // Regular/device files only permit file-level rights in Landlock
        access
            & (LANDLOCK_ACCESS_FS_EXECUTE
                | LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_READ_FILE)
    };
    let rule = LandlockPathBeneathAttr {
        allowed_access: effective_access,
        parent_fd: fd,
    };
    unsafe {
        let _ = libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &rule as *const LandlockPathBeneathAttr,
            0u32,
        );
        libc::close(fd);
    }
}

fn find_in_path(bin_name: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let full = dir.join(bin_name);
        if full.is_file() {
            return Some(full.to_string_lossy().to_string());
        }
    }
    None
}

/// Dynamic-linker and runtime code-injection environment keys stripped for controlled terminal calls (`M2-C`).
pub const DANGEROUS_RUNTIME_INJECTION_ENV_KEYS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_CONFIG_FILE",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "SHELLOPTS",
    "BASHOPTS",
    "CDPATH",
    "IFS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "NODE_OPTIONS",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
];

/// Returns `true` if `key` is either a sensitive host credential variable or a dynamic-linker /
/// interpreter injection variable that must never be passed into controlled terminal execution.
pub fn is_unsafe_terminal_env_key(key: &str) -> bool {
    if is_sensitive_host_env_key(key) {
        return true;
    }
    let upper = key.trim().to_ascii_uppercase();
    DANGEROUS_RUNTIME_INJECTION_ENV_KEYS.contains(&upper.as_str()) || upper.starts_with("LD_")
}

/// Return a sanitized copy of `env_vars` with all sensitive host credentials and linker/interpreter
/// injection variables stripped.
pub fn sanitize_terminal_env_map(env_vars: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    env_vars
        .iter()
        .filter(|(k, _)| !is_unsafe_terminal_env_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Scoped OS sandbox specification for `M2-C` Controlled General Terminal (`C0`–`C3`).
#[derive(Debug, Clone)]
pub struct TerminalSandboxSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Mount `/` read-only (`--ro-bind / /`) while masking `$HOME`, `/tmp`, `/var/tmp`, `/root`,
    /// `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/run/user/<uid>`, and `masked_paths`, then
    /// selectively re-exposing only `readonly_paths` (`--ro-bind`) and `readwrite_paths` (`--bind`).
    pub ro_bind_root: bool,
    pub readonly_paths: Vec<PathBuf>,
    pub readwrite_paths: Vec<PathBuf>,
    pub masked_paths: Vec<PathBuf>,
    pub env_vars: BTreeMap<String, String>,
    pub work_dir: PathBuf,
    pub allow_tcp_network: bool,
}

/// Output of a bounded, process-group-managed sandboxed terminal command (`M2-C`).
#[derive(Debug, Clone)]
pub struct SandboxedExecOutput {
    pub driver: SandboxDriver,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub timed_out: bool,
    pub duration_ms: u64,
}

fn append_bwrap_intentos_and_credential_masks(cmd: &mut Command, bound_dir: &Path) {
    append_bwrap_credential_masks(cmd, bound_dir);
    if !bound_dir.is_dir() {
        return;
    }
    for rel in [
        ".config/intentos",
        ".local/share/intentos",
        ".local/state/intentos",
    ] {
        let candidate = bound_dir.join(rel);
        if candidate.is_dir() {
            cmd.arg("--tmpfs").arg(&candidate);
        } else if candidate.is_file() && Path::new("/dev/null").exists() {
            cmd.arg("--ro-bind").arg("/dev/null").arg(&candidate);
        }
    }
}

fn path_depth(p: &Path) -> usize {
    p.components().count()
}

/// Build an isolated `tokio::process::Command` for `M2-C` controlled terminal execution,
/// placing the child in a dedicated process group (`setpgid(0, 0)`) for tree-wide signal cleanup.
pub fn build_terminal_sandbox_command(
    spec: &TerminalSandboxSpec,
    probe: &SandboxProbe,
) -> Result<(Command, SandboxDriver), SandboxError> {
    let mut clean_env = sanitize_terminal_env_map(&spec.env_vars);
    clean_env
        .entry("PATH".to_string())
        .or_insert_with(|| "/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin".to_string());
    clean_env
        .entry("LANG".to_string())
        .or_insert_with(|| "C.UTF-8".to_string());
    clean_env
        .entry("LC_ALL".to_string())
        .or_insert_with(|| "C.UTF-8".to_string());

    let mut ro_sorted: Vec<PathBuf> = spec
        .readonly_paths
        .iter()
        .filter(|p| p.exists() && !is_forbidden_credential_path(p))
        .cloned()
        .collect();
    ro_sorted.sort_by_key(|p| path_depth(p));
    ro_sorted.dedup();

    let mut rw_sorted: Vec<PathBuf> = spec
        .readwrite_paths
        .iter()
        .filter(|p| p.exists() && !is_forbidden_credential_path(p))
        .cloned()
        .collect();
    rw_sorted.sort_by_key(|p| path_depth(p));
    rw_sorted.dedup();

    if probe.selected_driver == SandboxDriver::Bubblewrap
        && probe.bwrap_userns_ok
        && let Some(ref bwrap) = probe.bwrap_path
    {
        let mut cmd = Command::new(bwrap);
        cmd.env_clear();
        cmd.kill_on_drop(true);
        cmd.arg("--unshare-user")
            .arg("--unshare-pid")
            .arg("--unshare-uts")
            .arg("--unshare-ipc")
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--clearenv");

        if !spec.allow_tcp_network {
            cmd.arg("--unshare-net");
        }

        let host_home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute() && h != Path::new("/") && h.is_dir());
        // SAFETY: `getuid()` is thread-safe and side-effect-free.
        let uid = unsafe { libc::getuid() };
        let run_user_dir = PathBuf::from(format!("/run/user/{}", uid));

        let mut masked_roots = vec![PathBuf::from("/tmp")];

        if spec.ro_bind_root {
            cmd.arg("--ro-bind")
                .arg("/")
                .arg("/")
                .arg("--proc")
                .arg("/proc")
                .arg("--dev")
                .arg("/dev")
                .arg("--tmpfs")
                .arg("/tmp");

            if Path::new("/var/tmp").is_dir() {
                cmd.arg("--tmpfs").arg("/var/tmp");
                masked_roots.push(PathBuf::from("/var/tmp"));
            }
            if Path::new("/root").is_dir() {
                cmd.arg("--tmpfs").arg("/root");
                masked_roots.push(PathBuf::from("/root"));
            }
            if run_user_dir.is_dir() {
                cmd.arg("--tmpfs").arg(&run_user_dir);
                masked_roots.push(run_user_dir.clone());
            }
            if let Some(ref home_dir) = host_home {
                cmd.arg("--tmpfs").arg(home_dir);
                masked_roots.push(home_dir.clone());
            }
            if Path::new("/dev/null").exists() {
                for sys_secret in ["/etc/shadow", "/etc/gshadow", "/etc/sudoers"] {
                    if Path::new(sys_secret).exists() {
                        cmd.arg("--ro-bind").arg("/dev/null").arg(sys_secret);
                    }
                }
            }
        } else {
            cmd.arg("--proc")
                .arg("/proc")
                .arg("--dev")
                .arg("/dev")
                .arg("--tmpfs")
                .arg("/tmp");

            for sys_ro in [
                "/usr",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
                "/sys",
                "/etc/passwd",
                "/etc/group",
                "/etc/alternatives",
                "/etc/ld.so.cache",
                "/etc/ld.so.conf",
                "/etc/ld.so.conf.d",
                "/etc/localtime",
                "/etc/ssl/certs",
                "/etc/ssl/openssl.cnf",
                "/etc/ca-certificates",
                "/etc/pki",
            ] {
                if Path::new(sys_ro).exists() {
                    cmd.arg("--ro-bind").arg(sys_ro).arg(sys_ro);
                }
            }
            if spec.allow_tcp_network {
                for net_ro in ["/etc/hosts", "/etc/nsswitch.conf"] {
                    if Path::new(net_ro).exists() {
                        cmd.arg("--ro-bind").arg(net_ro).arg(net_ro);
                    }
                }
                let resolv = Path::new("/etc/resolv.conf");
                if let Ok(canon_resolv) = std::fs::canonicalize(resolv)
                    && canon_resolv.exists()
                {
                    cmd.arg("--ro-bind").arg(canon_resolv).arg(resolv);
                } else if resolv.exists() {
                    cmd.arg("--ro-bind").arg(resolv).arg(resolv);
                }
            }
        }

        for ro in &ro_sorted {
            cmd.arg("--ro-bind").arg(ro).arg(ro);
            append_bwrap_intentos_and_credential_masks(&mut cmd, ro);
        }
        for rw in &rw_sorted {
            cmd.arg("--bind").arg(rw).arg(rw);
            append_bwrap_intentos_and_credential_masks(&mut cmd, rw);
        }

        for mp in &spec.masked_paths {
            let hidden_by_unmounted_mask = masked_roots.iter().any(|mr| mp.starts_with(mr))
                && !ro_sorted.iter().any(|b| mp.starts_with(b))
                && !rw_sorted.iter().any(|b| mp.starts_with(b));
            if hidden_by_unmounted_mask {
                continue;
            }
            if mp.is_dir() {
                cmd.arg("--tmpfs").arg(mp);
            } else if mp.exists() && Path::new("/dev/null").exists() {
                cmd.arg("--ro-bind").arg("/dev/null").arg(mp);
            }
        }

        // Dedicated ephemeral scratch directory for tools needing TMPDIR, while locking `/tmp` & `$HOME` read-only!
        let scratch_tmp = "/tmp/.intentos_scratch";
        cmd.arg("--tmpfs").arg(scratch_tmp);
        clean_env.insert("TMPDIR".to_string(), scratch_tmp.to_string());

        if !rw_sorted.iter().any(|p| p == Path::new("/tmp")) {
            cmd.arg("--remount-ro").arg("/tmp");
        }
        if spec.ro_bind_root
            && Path::new("/var/tmp").is_dir()
            && !rw_sorted.iter().any(|p| p == Path::new("/var/tmp"))
        {
            cmd.arg("--remount-ro").arg("/var/tmp");
        }
        if spec.ro_bind_root
            && let Some(ref home_dir) = host_home
            && !rw_sorted.iter().any(|p| p == home_dir)
        {
            cmd.arg("--remount-ro").arg(home_dir);
        }

        let effective_chdir = {
            let hidden_in_mask = masked_roots.iter().any(|mr| spec.work_dir.starts_with(mr))
                && !ro_sorted.iter().any(|b| spec.work_dir.starts_with(b))
                && !rw_sorted.iter().any(|b| spec.work_dir.starts_with(b));
            if !spec.work_dir.is_dir() || hidden_in_mask {
                PathBuf::from("/")
            } else {
                spec.work_dir.clone()
            }
        };

        for (k, v) in &clean_env {
            cmd.arg("--setenv").arg(k).arg(v);
        }
        cmd.arg("--chdir").arg(&effective_chdir);
        cmd.arg("--").arg(&spec.program).args(&spec.args);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // SAFETY: `setpgid(0, 0)` is async-signal-safe and isolates `bwrap` in its own process group.
        unsafe {
            cmd.pre_exec(|| {
                let _ = libc::setpgid(0, 0);
                Ok(())
            });
        }

        return Ok((cmd, SandboxDriver::Bubblewrap));
    }

    // Fallback to Landlock + PR_SET_NO_NEW_PRIVS + process-group isolation
    let legacy_spec = SandboxSpec {
        program: spec.program.clone(),
        args: spec.args.clone(),
        readonly_paths: ro_sorted,
        readwrite_paths: rw_sorted,
        env_vars: clean_env,
        work_dir: if spec.work_dir.is_dir() {
            spec.work_dir.clone()
        } else {
            PathBuf::from("/")
        },
        allow_tcp_network: spec.allow_tcp_network,
    };
    let (mut cmd, driver) = build_sandboxed_command_with_mounts(&legacy_spec, &[], probe)?;
    cmd.stdin(Stdio::null());
    Ok((cmd, driver))
}

struct ProcessGroupKillGuard {
    pgid: Option<i32>,
}

impl ProcessGroupKillGuard {
    fn new(child_pid: Option<u32>) -> Self {
        let pgid = child_pid.and_then(|pid| {
            let p = pid as i32;
            // SAFETY: `getpid()` and `getpgrp()` are side-effect-free queries.
            let self_pid = unsafe { libc::getpid() };
            let self_pgrp = unsafe { libc::getpgrp() };
            if pid > 1 && p != self_pid && p != self_pgrp {
                Some(p)
            } else {
                None
            }
        });
        Self { pgid }
    }

    fn kill_group_now(&mut self) {
        if let Some(pgid) = self.pgid.take() {
            // SAFETY: `pgid` was verified `> 1` and distinct from our own PID/PGRP.
            unsafe {
                let _ = libc::killpg(pgid, libc::SIGKILL);
            }
        }
    }

}

impl Drop for ProcessGroupKillGuard {
    fn drop(&mut self) {
        self.kill_group_now();
    }
}

/// Spawn and await a sandboxed terminal command with strict wall-clock `timeout`, `max_output_bytes`
/// stdout/stderr truncation cap, and guaranteed process-group (`SIGKILL`) cleanup on timeout or drop.
pub async fn execute_terminal_sandbox_bounded(
    spec: &TerminalSandboxSpec,
    timeout: std::time::Duration,
    max_output_bytes: usize,
    probe: &SandboxProbe,
) -> Result<SandboxedExecOutput, SandboxError> {
    use tokio::io::AsyncReadExt;

    let (mut cmd, driver) = build_terminal_sandbox_command(spec, probe)?;
    let start = std::time::Instant::now();
    let mut child = cmd.spawn()?;
    let mut pg_guard = ProcessGroupKillGuard::new(child.id());

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let cap_limit = (max_output_bytes.saturating_add(1)) as u64;

    let read_and_wait = async {
        let out_fut = async move {
            let mut buf = Vec::new();
            if let Some(pipe) = stdout_pipe {
                let mut limited = pipe.take(cap_limit);
                let _ = limited.read_to_end(&mut buf).await;
                // Dropping `limited` closes the pipe read-end if output exceeded `max_output_bytes`,
                // delivering SIGPIPE/EPIPE to runaway producers rather than buffering unbounded memory.
            }
            buf
        };
        let err_fut = async move {
            let mut buf = Vec::new();
            if let Some(pipe) = stderr_pipe {
                let mut limited = pipe.take(cap_limit);
                let _ = limited.read_to_end(&mut buf).await;
            }
            buf
        };
        let (out_buf, err_buf) = tokio::join!(out_fut, err_fut);
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, out_buf, err_buf))
    };

    match tokio::time::timeout(timeout, read_and_wait).await {
        Ok(Ok((status, mut out_buf, mut err_buf))) => {
            // Do not disarm on leader exit: detached descendants in the
            // same process group may still be running. Drop kills the group.
            let duration_ms = start.elapsed().as_millis() as u64;
            let mut truncated = false;
            if out_buf.len() > max_output_bytes {
                out_buf.truncate(max_output_bytes);
                truncated = true;
            }
            if err_buf.len() > max_output_bytes {
                err_buf.truncate(max_output_bytes);
                truncated = true;
            }
            Ok(SandboxedExecOutput {
                driver,
                exit_code: status.code(),
                stdout: out_buf,
                stderr: err_buf,
                truncated,
                timed_out: false,
                duration_ms,
            })
        }
        Ok(Err(io_err)) => {
            pg_guard.kill_group_now();
            let _ = child.kill().await;
            Err(SandboxError::Io(io_err))
        }
        Err(_) => {
            pg_guard.kill_group_now();
            let _ = child.kill().await;
            let _ = child.wait().await;
            let duration_ms = start.elapsed().as_millis() as u64;
            Ok(SandboxedExecOutput {
                driver,
                exit_code: None,
                stdout: Vec::new(),
                stderr: format!(
                    "command timed out after {} ms and process group was terminated",
                    timeout.as_millis()
                )
                .into_bytes(),
                truncated: false,
                timed_out: true,
                duration_ms,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn sandbox_blocks_unmounted_secret_directory_and_clears_env() {
        let secret_dir = TempDir::new().unwrap();
        let secret_file = secret_dir.path().join("id_ed25519");
        std::fs::write(&secret_file, "PRIVATE_SSH_KEY").unwrap();

        let work_dir = TempDir::new().unwrap();
        let mut env = BTreeMap::new();
        env.insert("SAFE_VAR".to_string(), "1".to_string());
        env.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "leak_aws_secret".to_string(),
        );
        env.insert(
            "SSH_AUTH_SOCK".to_string(),
            "/tmp/host_ssh.sock".to_string(),
        );

        let spec = SandboxSpec {
            program: PathBuf::from("/usr/bin/python3"),
            args: vec![
                "-c".to_string(),
                format!(
                    r#"import os, sys
assert 'AWS_SECRET_ACCESS_KEY' not in os.environ, 'AWS leaked'
assert 'SSH_AUTH_SOCK' not in os.environ, 'SSH sock leaked'
assert os.environ.get('SAFE_VAR') == '1'
try:
    open({:?}).read()
    print('ESCAPED')
    sys.exit(2)
except PermissionError:
    print('BLOCKED_FS')
except FileNotFoundError:
    print('BLOCKED_NS')
"#,
                    secret_file.display().to_string()
                ),
            ],
            readonly_paths: vec![],
            readwrite_paths: vec![work_dir.path().to_path_buf()],
            env_vars: env,
            work_dir: work_dir.path().to_path_buf(),
            allow_tcp_network: false,
        };

        let (mut cmd, driver) = build_sandboxed_command(&spec).unwrap();
        let out = cmd.output().await.unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if matches!(driver, SandboxDriver::Bubblewrap | SandboxDriver::Landlock) {
            assert!(
                stdout.contains("BLOCKED_"),
                "expected sandbox to block secret file, driver={:?}, stdout={}, stderr={}",
                driver,
                stdout,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[tokio::test]
    async fn sandbox_blocks_direct_tcp_connect_when_disabled() {
        let probe = probe_sandbox();
        if probe.landlock_abi_version.unwrap_or(0) < 4 && !probe.bwrap_userns_ok {
            return;
        }
        let work_dir = TempDir::new().unwrap();
        let spec = SandboxSpec {
            program: PathBuf::from("/usr/bin/python3"),
            args: vec![
                "-c".to_string(),
                "import socket, sys\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.settimeout(1.0)\ntry:\n  s.connect(('127.0.0.1', 9))\n  print('CONNECTED')\nexcept PermissionError:\n  print('NET_BLOCKED_EACCES')\nexcept OSError as e:\n  print('NET_ERR', e.errno)\n".to_string(),
            ],
            readonly_paths: vec![],
            readwrite_paths: vec![work_dir.path().to_path_buf()],
            env_vars: BTreeMap::new(),
            work_dir: work_dir.path().to_path_buf(),
            allow_tcp_network: false,
        };
        let (mut cmd, _driver) = build_sandboxed_command(&spec).unwrap();
        let out = cmd.output().await.unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Either Landlock EACCES (NET_BLOCKED_EACCES) or bwrap ENETUNREACH / ECONNREFUSED on isolated loopback
        assert!(
            stdout.contains("NET_BLOCKED_EACCES") || stdout.contains("NET_ERR"),
            "unexpected output: {}",
            stdout
        );
    }

    #[tokio::test]
    async fn sandbox_enforces_readonly_workspace_private_tmpfs_and_credential_masking() {
        let probe = probe_sandbox_support();
        assert_eq!(
            probe.has_os_isolation(),
            matches!(
                probe.selected_driver,
                SandboxDriver::Bubblewrap | SandboxDriver::Landlock
            )
        );
        let disabled = SandboxProbe::disabled_for_policy();
        assert!(!disabled.has_os_isolation());
        assert_eq!(disabled.selected_driver, SandboxDriver::ProcessCleanEnv);

        if !probe.has_os_isolation() {
            return;
        }

        let tmp = TempDir::new().unwrap();
        let ro_workspace = tmp.path().join("workspace_ro");
        let mock_home = tmp.path().join("mock_home");
        let ssh_dir = mock_home.join(".ssh");
        let gcloud_dir = mock_home.join(".config/gcloud");
        let rw_runtime = tmp.path().join("runtime_rw");
        std::fs::create_dir_all(&ro_workspace).unwrap();
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::create_dir_all(&gcloud_dir).unwrap();
        std::fs::create_dir_all(&rw_runtime).unwrap();

        std::fs::write(ro_workspace.join("doc.md"), "SAFE_READONLY_DOC").unwrap();
        std::fs::write(ssh_dir.join("id_ed25519"), "FORBIDDEN_SSH_KEY").unwrap();
        std::fs::write(gcloud_dir.join("credentials.db"), "FORBIDDEN_GCLOUD").unwrap();
        assert!(is_forbidden_credential_path(&ssh_dir));
        assert!(is_forbidden_credential_path(&gcloud_dir));

        let host_tmp_probe = PathBuf::from(format!(
            "/tmp/intentos_sandbox_tmpfs_probe_{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&host_tmp_probe);

        let py_script = format!(
            r#"import os, sys
doc = open({doc:?}).read()
assert doc == "SAFE_READONLY_DOC", doc

# 1) Attempting to write inside read-only workspace MUST fail
try:
    open({hacked:?}, "w").write("pwned")
    print("WORKSPACE_WRITE_ESCAPED")
    sys.exit(3)
except OSError:
    print("WORKSPACE_WRITE_BLOCKED")

# 2) Direct ~/.ssh and ~/.config/gcloud paths MUST be blocked/masked even if parent was bound
for secret_p in [{ssh_key:?}, {gcloud_db:?}]:
    if os.path.exists(secret_p):
        try:
            data = open(secret_p).read()
            if "FORBIDDEN" in data:
                print("SECRET_LEAKED:" + secret_p)
                sys.exit(4)
        except OSError:
            pass
print("CREDENTIALS_HIDDEN")

# 3) Writing to /tmp writes ONLY to isolated tmpfs in Bubblewrap
open({tmp_probe:?}, "w").write("ephemeral_tmp")
print("DONE_OK")
"#,
            doc = ro_workspace.join("doc.md").display().to_string(),
            hacked = ro_workspace.join("hacked.txt").display().to_string(),
            ssh_key = ssh_dir.join("id_ed25519").display().to_string(),
            gcloud_db = gcloud_dir.join("credentials.db").display().to_string(),
            tmp_probe = host_tmp_probe.display().to_string(),
        );

        let spec = SandboxSpec {
            program: PathBuf::from("/usr/bin/python3"),
            args: vec!["-c".to_string(), py_script],
            readonly_paths: vec![
                ro_workspace.clone(),
                ssh_dir.clone(),   // Explicitly forbidden: must be skipped!
                mock_home.clone(), // Parent dir: .ssh & .config/gcloud must be masked in bwrap!
            ],
            readwrite_paths: vec![rw_runtime.clone()],
            env_vars: BTreeMap::new(),
            work_dir: rw_runtime,
            allow_tcp_network: false,
        };

        let (mut cmd, driver) = build_sandboxed_command(&spec).unwrap();
        let out = cmd.output().await.unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "sandbox python check failed: driver={:?}, stdout={}, stderr={}",
            driver,
            stdout,
            stderr
        );
        assert!(stdout.contains("WORKSPACE_WRITE_BLOCKED"));
        assert!(stdout.contains("CREDENTIALS_HIDDEN"));
        assert!(!ro_workspace.join("hacked.txt").exists());

        if driver == SandboxDriver::Bubblewrap {
            assert!(
                !host_tmp_probe.exists(),
                "bwrap /tmp tmpfs write MUST NOT leak onto host /tmp!"
            );
        } else {
            let _ = std::fs::remove_file(&host_tmp_probe);
        }
    }

    #[tokio::test]
    async fn sc04_normal_exit_reaps_surviving_process_group_descendants() {
        let probe = probe_sandbox_support();
        if !probe.has_os_isolation() {
            // Not a pass: L2 CI probe must gate this entire test suite.
            return;
        }
        let tmp = TempDir::new().unwrap();
        let marker_file = tmp.path().join("grandchild_marker");
        let python = format!(
            "import subprocess; subprocess.Popen(['/usr/bin/python3', '-c', {:?}], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
            format!("import time; time.sleep(1.0); open({:?}, 'w').write('escaped')", marker_file)
        );
        let spec = TerminalSandboxSpec {
            program: PathBuf::from("/usr/bin/python3"),
            args: vec!["-c".into(), python],
            ro_bind_root: true,
            readonly_paths: vec![tmp.path().to_path_buf()],
            readwrite_paths: vec![tmp.path().to_path_buf()],
            masked_paths: vec![],
            env_vars: BTreeMap::new(),
            work_dir: tmp.path().to_path_buf(),
            allow_tcp_network: false,
        };
        let out = execute_terminal_sandbox_bounded(
            &spec,
            std::time::Duration::from_secs(4),
            65536,
            &probe,
        ).await.unwrap();
        assert!(!out.timed_out, "leader should exit normally");
        tokio::time::sleep(std::time::Duration::from_millis(1400)).await;
        assert!(!marker_file.exists(), "surviving grandchild wrote after leader exit");
    }

    #[tokio::test]
    async fn terminal_sandbox_bounded_enforces_timeout_killpg_and_output_cap() {
        let probe = probe_sandbox_support();
        if !probe.has_os_isolation() {
            return;
        }
        let tmp = TempDir::new().unwrap();
        let mut env = BTreeMap::new();
        env.insert("LD_PRELOAD".to_string(), "/tmp/evil_preload.so".to_string());
        env.insert("SAFE_FLAG".to_string(), "ok".to_string());

        let sanitized = sanitize_terminal_env_map(&env);
        assert!(!sanitized.contains_key("LD_PRELOAD"));
        assert_eq!(sanitized.get("SAFE_FLAG").map(String::as_str), Some("ok"));

        // 1) Output cap truncation
        let spec_cap = TerminalSandboxSpec {
            program: PathBuf::from("/usr/bin/python3"),
            args: vec![
                "-c".to_string(),
                "import sys; sys.stdout.write('A' * 90000); sys.stdout.flush()".to_string(),
            ],
            ro_bind_root: true,
            readonly_paths: vec![tmp.path().to_path_buf()],
            readwrite_paths: vec![],
            masked_paths: vec![],
            env_vars: env.clone(),
            work_dir: tmp.path().to_path_buf(),
            allow_tcp_network: false,
        };
        let out_cap = execute_terminal_sandbox_bounded(
            &spec_cap,
            std::time::Duration::from_secs(5),
            65536,
            &probe,
        )
        .await
        .unwrap();
        assert!(!out_cap.timed_out);
        assert!(out_cap.truncated);
        assert_eq!(out_cap.stdout.len(), 65536);

        // 2) Timeout + grandchild process-group cleanup
        let spec_hang = TerminalSandboxSpec {
            program: PathBuf::from("/usr/bin/python3"),
            args: vec![
                "-c".to_string(),
                "import subprocess, time; p = subprocess.Popen(['/bin/sleep', '30']); time.sleep(30)"
                    .to_string(),
            ],
            ro_bind_root: true,
            readonly_paths: vec![tmp.path().to_path_buf()],
            readwrite_paths: vec![],
            masked_paths: vec![],
            env_vars: BTreeMap::new(),
            work_dir: tmp.path().to_path_buf(),
            allow_tcp_network: false,
        };
        let out_hang = execute_terminal_sandbox_bounded(
            &spec_hang,
            std::time::Duration::from_millis(400),
            65536,
            &probe,
        )
        .await
        .unwrap();
        assert!(out_hang.timed_out);
        assert!(out_hang.exit_code.is_none());
    }
}
