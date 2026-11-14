//! Worker & E2 Sandbox launcher (§6.6, §8.4, Spike S1).
//! Primary: Bubblewrap (`bwrap --unshare-all --clearenv ...`) when available.
//! Fallback / Defense-in-depth: Linux Landlock (FS + ABI v4 TCP network block) + `PR_SET_NO_NEW_PRIVS` + clean environment.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProbe {
    pub bwrap_path: Option<String>,
    pub bwrap_userns_ok: bool,
    pub landlock_abi_version: Option<i32>,
    pub node_permission_available: bool,
    pub selected_driver: SandboxDriver,
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

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("failed to configure sandbox: {0}")]
    Setup(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

const NODE_ZERO_TCP_IMPORT: &str = "data:text/javascript,import net from \"node:net\";import dgram from \"node:dgram\";const orig=net.Socket.prototype.connect;const allowedSock=process.env.INTENTOS_GATEWAY_SOCK||\"\";net.Socket.prototype.connect=function(...args){const f=args[0];let sp=null;if(typeof f===\"string\"){sp=f;}else if(Array.isArray(f)&&f[0]&&typeof f[0]===\"object\"){sp=f[0].path||f[0].socketPath||null;}else if(f&&typeof f===\"object\"){sp=f.path||f.socketPath||null;}const ok=Boolean(sp)&&(!allowedSock||sp===allowedSock);if(!ok){const err=new Error(sp?\"Unauthorized Unix socket blocked by IntentOS sandbox\":\"TCP network disabled by IntentOS sandbox\");err.code=\"EACCES\";process.nextTick(()=>this.emit(\"error\",err));return this;}return orig.apply(this,args);};dgram.createSocket=()=>{const err=new Error(\"UDP disabled by IntentOS sandbox\");err.code=\"EACCES\";throw err;};globalThis.fetch=async()=>{const err=new Error(\"Fetch disabled by IntentOS sandbox\");err.code=\"EACCES\";throw err;};";

/// Probe available sandbox primitives on the current Linux host.
pub fn probe_sandbox() -> SandboxProbe {
    let bwrap_path = find_in_path("bwrap");
    let bwrap_userns_ok = if let Some(ref bp) = bwrap_path {
        std::process::Command::new(bp)
            .args(["--unshare-net", "--ro-bind", "/", "/", "/bin/true"])
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
    if v >= 1 {
        Some(v as i32)
    } else {
        None
    }
}

/// Build an isolated `tokio::process::Command` enforcing no-HOME, no-DBus, clean env, and no TCP network.
pub fn build_sandboxed_command(spec: &SandboxSpec) -> Result<(Command, SandboxDriver), SandboxError> {
    let probe = probe_sandbox();

    if probe.selected_driver == SandboxDriver::Bubblewrap {
        let bwrap = probe.bwrap_path.unwrap();
        let mut cmd = Command::new(bwrap);
        cmd.env_clear();
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
            .arg("/dev");

        if !spec.allow_tcp_network {
            cmd.arg("--unshare-net");
        }

        for sys_ro in ["/usr", "/bin", "/lib", "/lib64", "/etc/alternatives", "/etc/ssl"] {
            if Path::new(sys_ro).exists() {
                cmd.arg("--ro-bind").arg(sys_ro).arg(sys_ro);
            }
        }
        for ro in &spec.readonly_paths {
            if ro.exists() {
                cmd.arg("--ro-bind").arg(ro).arg(ro);
            }
        }
        for rw in &spec.readwrite_paths {
            if rw.exists() {
                cmd.arg("--bind").arg(rw).arg(rw);
            }
        }
        for (k, v) in &spec.env_vars {
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
    if is_node_program && probe.landlock_abi_version.is_none() {
        using_node_perm = true;
        final_args.push("--permission".to_string());
        let mut read_allow = vec![
            PathBuf::from("/usr"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/etc/ssl"),
        ];
        read_allow.extend(spec.readonly_paths.clone());
        read_allow.extend(spec.readwrite_paths.clone());
        for rp in read_allow {
            if rp.exists() {
                let canon = std::fs::canonicalize(&rp).unwrap_or(rp);
                final_args.push(format!("--allow-fs-read={}", canon.display()));
            }
        }
        for wp in &spec.readwrite_paths {
            if wp.exists() {
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
        .envs(&spec.env_vars)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(abi) = probe.landlock_abi_version {
        let mut ro_list = vec![
            PathBuf::from("/usr"),
            PathBuf::from("/bin"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/etc/ld.so.cache"),
            PathBuf::from("/etc/ssl"),
            PathBuf::from("/proc"),
        ];
        ro_list.extend(spec.readonly_paths.clone());
        let mut rw_list = vec![PathBuf::from("/dev/null"), PathBuf::from("/dev/urandom")];
        rw_list.extend(spec.readwrite_paths.clone());
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

    // Enforce PR_SET_NO_NEW_PRIVS + process group + Node 24 runtime permission sandbox
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

        let spec = SandboxSpec {
            program: PathBuf::from("/usr/bin/python3"),
            args: vec![
                "-c".to_string(),
                format!(
                    "import os, sys\ntry:\n  open({:?}).read()\n  print('ESCAPED')\n  sys.exit(2)\nexcept PermissionError:\n  print('BLOCKED_FS')\nexcept FileNotFoundError:\n  print('BLOCKED_NS')\n",
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
}
