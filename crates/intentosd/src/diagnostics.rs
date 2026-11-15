#![forbid(unsafe_code)]

//! Unified Linux Diagnostic & Verified Repair Suite (`crates/intentosd/src/diagnostics.rs`, M2-D `#8`).
//!
//! Provides real host evidence collectors and structured, approval-gated repair planning/verification:
//! - `logs.query`: `journalctl --user` / `journalctl --no-pager` or `SafeFsEngine`-confined log file tail.
//! - `dependency.inspect`: `.desktop` + binary resolution, permissions, shebang interpreter, and dual-environment
//!   (`sanitized desktop env` vs `current env`) `ldd` inspection to catch missing `.so` libraries and Conda
//!   `LD_LIBRARY_PATH` symbol clashes.
//! - `service.status`: `systemctl [--user] show` (`LoadState`, `ActiveState`, `SubState`, `Result`, `ExecMainStatus`)
//!   plus recent unit journal tail.
//! - `package.inspect`: `dpkg-query -W`, `apt-cache policy`, `dpkg --audit`, `snap list`, and `flatpak info`.
//! - `network.diagnose`: `ip -j addr`, `ip route`, `/etc/resolv.conf`, bounded local proxy TCP liveness probe,
//!   and `/proc/mounts` FUSE/rclone/network mount health check.
//! - `system.bottleneck`: Enriched read-only `/proc/meminfo`, `/proc/loadavg`, `/proc/stat`, `/proc/vmstat`,
//!   `df -Pk`, and `/proc/<pid>/{status,stat,statm,cmdline}` top RSS/CPU/swap/zombie inspection — NEVER kills
//!   processes or mutates settings during observation.
//! - `repair.plan`: Builds a structured `RepairPlan` from real diagnostic evidence JSON without executing mutations.
//! - `repair.verify`: Re-executes the live diagnostic probe to verify whether a repair genuinely succeeded.
//!
//! All text and JSON outputs are scrubbed via `SensitiveDataGuard` before returning.

use crate::app_adapter::dynamic_profiler::discover_installed_desktop_apps;
use crate::app_adapter::sni_dbusmenu::{apply_clean_desktop_env_std, sanitize_ld_library_path};
use crate::app_adapter::uri_desktop::{parse_desktop_file_content, tokenize_desktop_exec};
use crate::core::IntentOsCore;
use crate::security_guard::SensitiveDataGuard;
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_fsops::SafeFsEngine;
use intentos_protocol::{
    CapabilityResult, Effect, ExecutionStatus, VerificationReport, VerificationState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_DIAG_CMD_OUTPUT_BYTES: usize = 64 * 1024;
const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_millis(3_500);

/// Return `true` if `id` names one of the M2-D unified Linux diagnostic capabilities.
pub fn is_diagnostic_capability(id: &str) -> bool {
    matches!(
        canonicalize_diag_id(id).as_str(),
        "logs.query"
            | "dependency.inspect"
            | "service.status"
            | "package.inspect"
            | "network.diagnose"
            | "system.bottleneck"
            | "repair.plan"
            | "repair.verify"
    )
}

fn canonicalize_diag_id(raw: &str) -> String {
    let trimmed = raw.trim();
    match trimmed {
        "logs_query" => "logs.query".to_string(),
        "dependency_inspect" => "dependency.inspect".to_string(),
        "service_status" => "service.status".to_string(),
        "package_inspect" => "package.inspect".to_string(),
        "network_diagnose" => "network.diagnose".to_string(),
        "system_bottleneck" => "system.bottleneck".to_string(),
        "repair_plan" => "repair.plan".to_string(),
        "repair_verify" => "repair.verify".to_string(),
        "process_health" => "process.health".to_string(),
        other => other.to_string(),
    }
}

/// Scrub secrets from a string using `SensitiveDataGuard`.
pub fn scrub_diag_text(raw: &str) -> String {
    SensitiveDataGuard::redact_text(raw).0
}

/// Recursively scrub every string inside a `serde_json::Value` via `SensitiveDataGuard`.
pub fn scrub_diag_json(val: Value) -> Value {
    match val {
        Value::String(s) => Value::String(SensitiveDataGuard::redact_text(&s).0),
        Value::Array(items) => Value::Array(items.into_iter().map(scrub_diag_json).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, scrub_diag_json(v)))
                .collect(),
        ),
        other => other,
    }
}

#[derive(Debug, Clone)]
struct BoundedCmdResult {
    exit_code: Option<i32>,
    success: bool,
    timed_out: bool,
    stdout: String,
    stderr: String,
    truncated: bool,
}

/// Execute a non-shell `std::process::Command` with bounded output bytes and a wall-clock timeout.
fn run_bounded_command(mut cmd: Command, timeout: Duration) -> anyhow::Result<BoundedCmdResult> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let stdout_handle = child.stdout.take().map(|mut out| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut out)
                .take((MAX_DIAG_CMD_OUTPUT_BYTES + 1) as u64)
                .read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut err| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut err)
                .take((MAX_DIAG_CMD_OUTPUT_BYTES + 1) as u64)
                .read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(st) => break Some(st),
            None => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(12));
            }
        }
    };

    let mut stdout_bytes = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let mut stderr_bytes = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

    let mut truncated = false;
    if stdout_bytes.len() > MAX_DIAG_CMD_OUTPUT_BYTES {
        stdout_bytes.truncate(MAX_DIAG_CMD_OUTPUT_BYTES);
        truncated = true;
    }
    if stderr_bytes.len() > MAX_DIAG_CMD_OUTPUT_BYTES {
        stderr_bytes.truncate(MAX_DIAG_CMD_OUTPUT_BYTES);
        truncated = true;
    }

    Ok(BoundedCmdResult {
        exit_code: status.and_then(|s| s.code()),
        success: status.is_some_and(|s| s.success()) && !timed_out,
        timed_out,
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        truncated,
    })
}

fn validate_safe_token(raw: &str, label: &str, max_len: usize) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("参数 `{}` 不能为空", label);
    }
    if trimmed.len() > max_len {
        anyhow::bail!("参数 `{}` 长度超出限制 ({})", label, max_len);
    }
    if trimmed.starts_with('-') || trimmed.contains('\0') || trimmed.contains('\n') {
        anyhow::bail!("安全拦截：参数 `{}` 包含非法前缀或控制字符", label);
    }
    Ok(trimmed.to_string())
}

fn validate_unit_or_pkg_identifier(raw: &str, label: &str) -> anyhow::Result<String> {
    let token = validate_safe_token(raw, label, 256)?;
    let valid = token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':' | '+'));
    if !valid {
        anyhow::bail!(
            "安全拦截：`{}` 仅允许标准服务/软件包标识符字符: {}",
            label,
            token
        );
    }
    Ok(token)
}

// =============================================================================
// 1. `logs.query`
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogQueryReport {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    pub lines_requested: usize,
    pub entries_count: usize,
    pub entries: Vec<String>,
    pub truncated: bool,
    pub secrets_redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Query `journalctl` (`--user` or system `--no-pager`) or tail an authorized log file via `SafeFsEngine`.
pub fn query_logs(fs_engine: &SafeFsEngine, args: &Value) -> anyhow::Result<LogQueryReport> {
    let lines_limit = args
        .get("lines")
        .and_then(|v| v.as_u64())
        .unwrap_or(40)
        .clamp(1, 100) as usize;
    let grep_opt = args
        .get("grep")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Branch A: Authorized log file tail (strictly enforced via `SafeFsEngine::open_readonly_safe`)
    if let Some(log_path_raw) = args
        .get("log_file")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let log_path = Path::new(log_path_raw);
        if fs_engine.is_forbidden(log_path) {
            anyhow::bail!("安全拦截：拒绝读取受保护路径日志: {}", log_path.display());
        }
        let file = fs_engine.open_readonly_safe(log_path).map_err(|e| {
            anyhow::anyhow!(
                "无法在已授权目录范围内打开日志文件 {}: {}",
                log_path.display(),
                e
            )
        })?;
        let mut raw_bytes = Vec::new();
        file.take(512 * 1024).read_to_end(&mut raw_bytes)?;
        let raw_text = String::from_utf8_lossy(&raw_bytes);
        let grep_lc = grep_opt.map(|g| g.to_ascii_lowercase());

        let mut matched: Vec<String> = Vec::new();
        for line in raw_text.lines() {
            if let Some(ref g) = grep_lc
                && !line.to_ascii_lowercase().contains(g)
            {
                continue;
            }
            matched.push(line.to_string());
        }
        let truncated = matched.len() > lines_limit;
        if matched.len() > lines_limit {
            matched = matched.split_off(matched.len() - lines_limit);
        }

        let mut redacted_any = false;
        let entries: Vec<String> = matched
            .into_iter()
            .map(|l| {
                let (clean, changed) = SensitiveDataGuard::redact_text(&l);
                if changed {
                    redacted_any = true;
                }
                clean
            })
            .collect();

        return Ok(LogQueryReport {
            source: "authorized_log_file".to_string(),
            unit: None,
            log_file: Some(log_path.display().to_string()),
            lines_requested: lines_limit,
            entries_count: entries.len(),
            entries,
            truncated,
            secrets_redacted: redacted_any,
            note: None,
        });
    }

    // Branch B: `journalctl` query (`--no-pager`)
    let unit_opt = match args
        .get("unit")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(u) => Some(validate_unit_or_pkg_identifier(u, "unit")?),
        None => None,
    };
    let since_opt = match args
        .get("since")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => Some(validate_safe_token(s, "since", 128)?),
        None => None,
    };
    let priority_opt = match args
        .get("priority")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(p) => {
            let clean = p.to_ascii_lowercase();
            if !matches!(
                clean.as_str(),
                "0" | "1"
                    | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "emerg"
                    | "alert"
                    | "crit"
                    | "err"
                    | "warning"
                    | "notice"
                    | "info"
                    | "debug"
            ) {
                anyhow::bail!("不支持的 journalctl priority 级别: {}", p);
            }
            Some(clean)
        }
        None => None,
    };
    let user_scope = args
        .get("user_scope")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let Some(jctl_bin) = resolve_trusted_executable("journalctl") else {
        return Ok(LogQueryReport {
            source: "journalctl_unavailable".to_string(),
            unit: unit_opt,
            log_file: None,
            lines_requested: lines_limit,
            entries_count: 0,
            entries: Vec::new(),
            truncated: false,
            secrets_redacted: false,
            note: Some("当前系统未找到 `/usr/bin/journalctl`".to_string()),
        });
    };

    let fetch_n = if grep_opt.is_some() {
        (lines_limit * 4).min(400)
    } else {
        lines_limit
    };
    let mut cmd = Command::new(&jctl_bin);
    apply_clean_desktop_env_std(&mut cmd);
    if user_scope {
        cmd.arg("--user");
    }
    cmd.args(["--no-pager", "-o", "short-iso", "-n", &fetch_n.to_string()]);
    if let Some(ref u) = unit_opt {
        cmd.args(["-u", u]);
    }
    if let Some(ref p) = priority_opt {
        cmd.args(["-p", p]);
    }
    if let Some(ref s) = since_opt {
        cmd.args(["--since", s]);
    }

    let res = run_bounded_command(cmd, DEFAULT_CMD_TIMEOUT)?;
    let grep_lc = grep_opt.map(|g| g.to_ascii_lowercase());
    let mut matched: Vec<String> = res
        .stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-- No entries --"))
        .filter(|l| {
            grep_lc
                .as_ref()
                .is_none_or(|g| l.to_ascii_lowercase().contains(g))
        })
        .map(ToString::to_string)
        .collect();

    let truncated = res.truncated || matched.len() > lines_limit;
    if matched.len() > lines_limit {
        matched = matched.split_off(matched.len() - lines_limit);
    }

    let mut redacted_any = false;
    let entries: Vec<String> = matched
        .into_iter()
        .map(|l| {
            let (clean, changed) = SensitiveDataGuard::redact_text(&l);
            if changed {
                redacted_any = true;
            }
            clean
        })
        .collect();

    let note = if res.timed_out {
        Some("journalctl 查询超时，仅返回已收集的部分日志".to_string())
    } else if !res.success && entries.is_empty() && !res.stderr.trim().is_empty() {
        Some(format!(
            "exit_code={:?}: {}",
            res.exit_code,
            scrub_diag_text(res.stderr.trim())
        ))
    } else {
        None
    };

    Ok(LogQueryReport {
        source: if user_scope {
            "journalctl_user".to_string()
        } else {
            "journalctl_system".to_string()
        },
        unit: unit_opt,
        log_file: None,
        lines_requested: lines_limit,
        entries_count: entries.len(),
        entries,
        truncated,
        secrets_redacted: redacted_any,
        note,
    })
}

// =============================================================================
// 2. `dependency.inspect`
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LddLibraryClash {
    pub soname: String,
    pub current_env_path: String,
    pub sanitized_env_path: String,
    pub is_conda_or_custom_override: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInspectionReport {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_executable: Option<String>,
    pub exists: bool,
    pub is_executable: bool,
    pub permissions_octal: String,
    pub binary_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shebang_interpreter: Option<String>,
    pub interpreter_exists: bool,
    pub missing_libraries_sanitized: Vec<String>,
    pub missing_libraries_current_env: Vec<String>,
    pub conda_or_env_clashes: Vec<LddLibraryClash>,
    pub symbol_or_version_errors: Vec<String>,
    pub desktop_issues: Vec<String>,
    pub root_cause: String,
    pub healthy: bool,
    pub summary: String,
}

/// Inspect an application, `.desktop` launcher, script, or ELF binary for missing `.so` libraries,
/// Conda/`LD_LIBRARY_PATH` symbol conflicts, broken `.desktop` entries, shebangs, and file permissions.
pub fn inspect_dependency(
    config_dir: Option<&Path>,
    args: &Value,
) -> anyhow::Result<DependencyInspectionReport> {
    let target = args
        .get("target")
        .or_else(|| args.get("app"))
        .or_else(|| args.get("path"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("`dependency.inspect` 缺少必填参数 `target`"))?;

    if target.contains('\0') {
        anyhow::bail!("安全拦截：`target` 包含非法空字节");
    }

    let extra_dirs: Vec<PathBuf> = args
        .get("extra_desktop_dirs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(PathBuf::from))
                .collect()
        })
        .unwrap_or_default();

    let ambient_ld_override = args
        .get("env_ld_library_path")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .or_else(|| std::env::var("LD_LIBRARY_PATH").ok());

    let mut desktop_file: Option<String> = None;
    let mut exec_raw: Option<String> = None;
    let mut desktop_issues: Vec<String> = Vec::new();
    let mut candidate_exec: Option<PathBuf> = None;

    let target_path = Path::new(target);

    // 1. Direct `.desktop` file path
    if target.ends_with(".desktop") && target_path.is_file() {
        desktop_file = Some(target_path.display().to_string());
        let raw_content = std::fs::read_to_string(target_path)?;
        inspect_desktop_content(
            target_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("app.desktop"),
            &raw_content,
            &mut exec_raw,
            &mut candidate_exec,
            &mut desktop_issues,
        );
    } else if target.starts_with('/') {
        // 2. Direct binary or script path
        candidate_exec = Some(target_path.to_path_buf());
    } else {
        // 3. Search extra_desktop_dirs first, then installed `.desktop` apps, then trusted system binaries
        for dir in &extra_dirs {
            let direct_dt = if target.ends_with(".desktop") {
                dir.join(target)
            } else {
                dir.join(format!("{}.desktop", target))
            };
            if direct_dt.is_file()
                && let Ok(raw_content) = std::fs::read_to_string(&direct_dt)
            {
                desktop_file = Some(direct_dt.display().to_string());
                inspect_desktop_content(
                    direct_dt
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("app.desktop"),
                    &raw_content,
                    &mut exec_raw,
                    &mut candidate_exec,
                    &mut desktop_issues,
                );
                break;
            }
        }

        if candidate_exec.is_none() && desktop_file.is_none() {
            let q_lc = target.to_ascii_lowercase();
            let discovered = discover_installed_desktop_apps(config_dir);
            if let Some(hit) = discovered.iter().find(|d| {
                d.id.eq_ignore_ascii_case(target)
                    || d.desktop_id.eq_ignore_ascii_case(target)
                    || d.name.to_ascii_lowercase().contains(&q_lc)
                    || d.name_zh
                        .as_deref()
                        .is_some_and(|zh| zh.to_ascii_lowercase().contains(&q_lc))
                    || d.binary_name
                        .as_deref()
                        .is_some_and(|b| b.eq_ignore_ascii_case(target))
            }) {
                desktop_file = Some(hit.desktop_file_path.clone());
                exec_raw = hit.exec_raw.clone();
                if let Ok(raw_content) = std::fs::read_to_string(&hit.desktop_file_path) {
                    inspect_desktop_content(
                        &hit.desktop_id,
                        &raw_content,
                        &mut exec_raw,
                        &mut candidate_exec,
                        &mut desktop_issues,
                    );
                } else if let Some(ref ep) = hit.exec_path {
                    candidate_exec = Some(PathBuf::from(ep));
                }
            }
        }

        if candidate_exec.is_none() {
            candidate_exec = resolve_executable_in_system(target);
        }
    }

    let Some(exec_path) = candidate_exec else {
        let root_cause = if !desktop_issues.is_empty() {
            "broken_desktop_entry".to_string()
        } else {
            "missing_executable".to_string()
        };
        let summary = format!(
            "未找到目标 `{}` 的可执行文件{}",
            scrub_diag_text(target),
            if desktop_issues.is_empty() {
                String::new()
            } else {
                format!("（{}）", desktop_issues.join("；"))
            }
        );
        return Ok(DependencyInspectionReport {
            target: scrub_diag_text(target),
            desktop_file,
            exec_raw: exec_raw.as_deref().map(scrub_diag_text),
            resolved_executable: None,
            canonical_executable: None,
            exists: false,
            is_executable: false,
            permissions_octal: "0000".to_string(),
            binary_kind: "missing".to_string(),
            shebang_interpreter: None,
            interpreter_exists: false,
            missing_libraries_sanitized: Vec::new(),
            missing_libraries_current_env: Vec::new(),
            conda_or_env_clashes: Vec::new(),
            symbol_or_version_errors: Vec::new(),
            desktop_issues,
            root_cause,
            healthy: false,
            summary,
        });
    };

    let exists = exec_path.is_file();
    if !exists {
        let root_cause = if desktop_file.is_some() {
            "broken_desktop_entry".to_string()
        } else {
            "missing_executable".to_string()
        };
        let summary = format!(
            "目标可执行文件不存在: {}",
            scrub_diag_text(&exec_path.display().to_string())
        );
        return Ok(DependencyInspectionReport {
            target: scrub_diag_text(target),
            desktop_file,
            exec_raw: exec_raw.as_deref().map(scrub_diag_text),
            resolved_executable: Some(exec_path.display().to_string()),
            canonical_executable: None,
            exists: false,
            is_executable: false,
            permissions_octal: "0000".to_string(),
            binary_kind: "missing".to_string(),
            shebang_interpreter: None,
            interpreter_exists: false,
            missing_libraries_sanitized: Vec::new(),
            missing_libraries_current_env: Vec::new(),
            conda_or_env_clashes: Vec::new(),
            symbol_or_version_errors: Vec::new(),
            desktop_issues,
            root_cause,
            healthy: false,
            summary,
        });
    }

    let meta = std::fs::metadata(&exec_path)?;
    let mode = meta.permissions().mode() & 0o7777;
    let is_executable = (mode & 0o111) != 0;
    let permissions_octal = format!("{:04o}", mode);
    let canonical_executable = std::fs::canonicalize(&exec_path)
        .ok()
        .map(|p| p.display().to_string());

    // Inspect binary header: ELF vs `#!` shebang script
    let mut header = [0u8; 256];
    let n_head = std::fs::File::open(&exec_path)
        .and_then(|mut f| f.read(&mut header))
        .unwrap_or(0);
    let head_slice = &header[..n_head];

    let mut binary_kind = "unknown".to_string();
    let mut shebang_interpreter: Option<String> = None;
    let mut interpreter_exists = true;
    let mut elf_to_probe: Option<PathBuf> = None;

    if head_slice.starts_with(b"\x7fELF") {
        binary_kind = "elf".to_string();
        elf_to_probe = Some(exec_path.clone());
    } else if head_slice.starts_with(b"#!") {
        binary_kind = "script".to_string();
        let first_line = String::from_utf8_lossy(head_slice)
            .lines()
            .next()
            .unwrap_or("")
            .trim_start_matches("#!")
            .trim()
            .to_string();
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if let Some(&interp) = parts.first() {
            let resolved_interp = if (interp == "/usr/bin/env" || interp == "/bin/env")
                && let Some(&cmd_name) = parts.get(1)
            {
                shebang_interpreter = Some(format!("{} {}", interp, cmd_name));
                resolve_executable_in_system(cmd_name)
            } else {
                shebang_interpreter = Some(interp.to_string());
                let ip = PathBuf::from(interp);
                if ip.is_file() { Some(ip) } else { None }
            };
            match resolved_interp {
                Some(ip) => {
                    interpreter_exists = true;
                    // If the interpreter itself is an ELF binary, only probe ldd if requested or relevant
                    let _ = ip;
                }
                None => {
                    interpreter_exists = false;
                }
            }
        }
    }

    let mut missing_sanitized = Vec::new();
    let mut missing_current = Vec::new();
    let mut conda_clashes = Vec::new();
    let mut symbol_errors = Vec::new();

    if let Some(ref elf_path) = elf_to_probe
        && let Some(ldd_bin) = resolve_trusted_executable("ldd")
    {
        // Pass 1: Sanitized clean desktop environment (strips Conda / custom LD_LIBRARY_PATH)
        let mut clean_cmd = Command::new(&ldd_bin);
        apply_clean_desktop_env_std(&mut clean_cmd);
        if let Some(ref raw_ld) = ambient_ld_override {
            if let Some(sanitized) = sanitize_ld_library_path(raw_ld) {
                clean_cmd.env("LD_LIBRARY_PATH", sanitized);
            } else {
                clean_cmd.env_remove("LD_LIBRARY_PATH");
            }
        }
        clean_cmd.arg("-r").arg(elf_path);
        let clean_out = run_bounded_command(clean_cmd, DEFAULT_CMD_TIMEOUT)?;
        let (clean_map, clean_missing, clean_sym_errs) =
            parse_ldd_output(&clean_out.stdout, &clean_out.stderr);
        missing_sanitized = clean_missing;

        // Pass 2: Current / Ambient environment (with `ambient_ld_override` if set)
        let mut cur_cmd = Command::new(&ldd_bin);
        if let Some(ref raw_ld) = ambient_ld_override {
            cur_cmd.env("LD_LIBRARY_PATH", raw_ld);
        }
        cur_cmd.arg("-r").arg(elf_path);
        let cur_out = run_bounded_command(cur_cmd, DEFAULT_CMD_TIMEOUT)?;
        let (cur_map, cur_missing, cur_sym_errs) =
            parse_ldd_output(&cur_out.stdout, &cur_out.stderr);
        missing_current = cur_missing;

        for err in cur_sym_errs.into_iter().chain(clean_sym_errs) {
            let clean_err = scrub_diag_text(&err);
            if !symbol_errors.contains(&clean_err) {
                symbol_errors.push(clean_err);
            }
        }

        for (soname, cur_resolved) in &cur_map {
            let san_resolved = clean_map.get(soname).cloned().unwrap_or_default();
            if !san_resolved.is_empty() && cur_resolved != &san_resolved {
                let lc = cur_resolved.to_ascii_lowercase();
                let is_conda = lc.contains("conda")
                    || lc.contains("mamba")
                    || ambient_ld_override.as_deref().is_some_and(|ld| {
                        !ld.is_empty()
                            && cur_resolved.starts_with(ld.split(':').next().unwrap_or(""))
                    });
                conda_clashes.push(LddLibraryClash {
                    soname: soname.clone(),
                    current_env_path: scrub_diag_text(cur_resolved),
                    sanitized_env_path: scrub_diag_text(&san_resolved),
                    is_conda_or_custom_override: is_conda,
                });
            }
        }
    }

    let root_cause = if !desktop_issues.is_empty() {
        "broken_desktop_entry".to_string()
    } else if !is_executable {
        "not_executable_permission".to_string()
    } else if !interpreter_exists {
        "broken_shebang_interpreter".to_string()
    } else if !missing_sanitized.is_empty() && missing_current.is_empty() {
        // Missing unless LD_LIBRARY_PATH is supplied
        "missing_shared_library".to_string()
    } else if !missing_sanitized.is_empty() {
        "missing_shared_library".to_string()
    } else if !conda_clashes.is_empty()
        && (conda_clashes.iter().any(|c| c.is_conda_or_custom_override)
            || !symbol_errors.is_empty())
    {
        "conda_ld_library_conflict".to_string()
    } else if !symbol_errors.is_empty() {
        "symbol_lookup_error".to_string()
    } else {
        "healthy".to_string()
    };

    let healthy = root_cause == "healthy";
    let summary = match root_cause.as_str() {
        "healthy" => format!(
            "可执行文件 `{}` 权限与动态库依赖正常（{}）",
            exec_path.display(),
            binary_kind
        ),
        "not_executable_permission" => format!(
            "可执行文件 `{}` 缺少执行权限（mode={}）",
            exec_path.display(),
            permissions_octal
        ),
        "broken_shebang_interpreter" => format!(
            "脚本 `{}` 指定的解释器不存在: {:?}",
            exec_path.display(),
            shebang_interpreter
        ),
        "missing_shared_library" => format!(
            "`{}` 缺失共享库: {}",
            exec_path.display(),
            missing_sanitized.join(", ")
        ),
        "conda_ld_library_conflict" => format!(
            "`{}` 检测到 Conda/LD_LIBRARY_PATH 动态库覆盖冲突（{} 项库被非系统路径劫持{}）",
            exec_path.display(),
            conda_clashes.len(),
            if symbol_errors.is_empty() {
                String::new()
            } else {
                format!("，伴随符号错误 {} 条", symbol_errors.len())
            }
        ),
        "broken_desktop_entry" => format!("桌面启动器配置异常：{}", desktop_issues.join("；")),
        other => format!("`{}` 依赖诊断发现异常 ({})", exec_path.display(), other),
    };

    Ok(DependencyInspectionReport {
        target: scrub_diag_text(target),
        desktop_file: desktop_file.as_deref().map(scrub_diag_text),
        exec_raw: exec_raw.as_deref().map(scrub_diag_text),
        resolved_executable: Some(scrub_diag_text(&exec_path.display().to_string())),
        canonical_executable: canonical_executable.as_deref().map(scrub_diag_text),
        exists,
        is_executable,
        permissions_octal,
        binary_kind,
        shebang_interpreter: shebang_interpreter.as_deref().map(scrub_diag_text),
        interpreter_exists,
        missing_libraries_sanitized: missing_sanitized,
        missing_libraries_current_env: missing_current,
        conda_or_env_clashes: conda_clashes,
        symbol_or_version_errors: symbol_errors,
        desktop_issues,
        root_cause,
        healthy,
        summary: scrub_diag_text(&summary),
    })
}

fn inspect_desktop_content(
    desktop_id: &str,
    content: &str,
    exec_raw: &mut Option<String>,
    candidate_exec: &mut Option<PathBuf>,
    desktop_issues: &mut Vec<String>,
) {
    let parsed = parse_desktop_file_content(desktop_id, content);
    for line in content.lines() {
        if let Some(try_exec) = line.trim().strip_prefix("TryExec=") {
            let te = try_exec.trim();
            if !te.is_empty() {
                let exists = if te.starts_with('/') {
                    Path::new(te).is_file()
                } else {
                    resolve_executable_in_system(te).is_some()
                };
                if !exists {
                    desktop_issues.push(format!("TryExec 指向的可执行文件不存在: {}", te));
                }
            }
        }
    }

    let Some(raw_exec) = parsed.exec else {
        desktop_issues.push("缺少有效的 Exec= 启动指令".to_string());
        return;
    };
    *exec_raw = Some(raw_exec.clone());

    match tokenize_desktop_exec(&raw_exec, None) {
        Ok((bin, _args)) => {
            if bin.starts_with('/') {
                let bp = PathBuf::from(&bin);
                if !bp.is_file() {
                    desktop_issues.push(format!("Exec= 指向的可执行文件不存在: {}", bin));
                }
                *candidate_exec = Some(bp);
            } else if let Some(resolved) = resolve_executable_in_system(&bin) {
                *candidate_exec = Some(resolved);
            } else {
                desktop_issues.push(format!("Exec= 程序 `{}` 未在系统目录中找到", bin));
            }
        }
        Err(err) => {
            desktop_issues.push(format!("Exec= 解析异常: {}", err));
        }
    }
}

fn resolve_executable_in_system(name: &str) -> Option<PathBuf> {
    if let Some(p) = resolve_trusted_executable(name) {
        return Some(p);
    }
    for extra in ["/snap/bin", "/usr/games"] {
        let cand = Path::new(extra).join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Parse `ldd -r` stdout & stderr into `(resolved_soname_map, missing_sonames, symbol_errors)`.
pub fn parse_ldd_output(
    stdout: &str,
    stderr: &str,
) -> (BTreeMap<String, String>, Vec<String>, Vec<String>) {
    let mut resolved = BTreeMap::new();
    let mut missing = Vec::new();
    let mut sym_errors = Vec::new();

    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("undefined symbol:")
            || trimmed.contains("symbol lookup error")
            || (trimmed.contains("version `") && trimmed.contains("not found"))
        {
            sym_errors.push(trimmed.to_string());
            continue;
        }
        if let Some((left, right)) = trimmed.split_once("=>") {
            let soname = left.trim().to_string();
            let rhs = right.trim();
            if rhs.starts_with("not found") {
                if !missing.contains(&soname) {
                    missing.push(soname);
                }
            } else if let Some(path_part) = rhs.split_whitespace().next()
                && path_part.starts_with('/')
            {
                resolved.insert(soname, path_part.to_string());
            }
        }
    }

    (resolved, missing, sym_errors)
}

// =============================================================================
// 3. `service.status`
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatusReport {
    pub unit: String,
    pub user_scope: bool,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub result: String,
    pub exec_main_pid: u32,
    pub exec_main_status: i32,
    pub unit_file_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub healthy: bool,
    pub recent_journal: Vec<String>,
    pub summary: String,
}

/// Inspect `systemctl [--user] show` properties + recent journal entries for a unit.
pub fn inspect_service_status(args: &Value) -> anyhow::Result<ServiceStatusReport> {
    let raw_unit = args
        .get("unit")
        .or_else(|| args.get("service"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`service.status` 缺少必填参数 `unit`"))?;
    let unit = validate_unit_or_pkg_identifier(raw_unit, "unit")?;
    let normalized_unit = if unit.contains('.') {
        unit
    } else {
        format!("{}.service", unit)
    };
    let user_scope = args
        .get("user_scope")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let journal_lines = args
        .get("journal_lines")
        .and_then(|v| v.as_u64())
        .unwrap_or(15)
        .clamp(0, 50) as usize;

    let systemctl_bin = resolve_trusted_executable("systemctl")
        .ok_or_else(|| anyhow::anyhow!("当前系统未安装 `systemctl`"))?;

    let mut cmd = Command::new(&systemctl_bin);
    apply_clean_desktop_env_std(&mut cmd);
    if user_scope {
        cmd.arg("--user");
    }
    cmd.args([
        "show",
        "--no-pager",
        "--property=Id,Description,LoadState,ActiveState,SubState,Result,ExecMainPID,ExecMainStatus,UnitFileState,FragmentPath",
        "--",
        &normalized_unit,
    ]);

    let out = run_bounded_command(cmd, DEFAULT_CMD_TIMEOUT)?;
    let mut props: BTreeMap<String, String> = BTreeMap::new();
    for line in out.stdout.lines() {
        if let Some((k, v)) = line.split_once('=') {
            props.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let load_state = props
        .get("LoadState")
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    let active_state = props
        .get("ActiveState")
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    let sub_state = props
        .get("SubState")
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    let result = props
        .get("Result")
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    let exec_main_pid = props
        .get("ExecMainPID")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let exec_main_status = props
        .get("ExecMainStatus")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0);
    let unit_file_state = props.get("UnitFileState").cloned().unwrap_or_default();
    let fragment_path = props
        .get("FragmentPath")
        .filter(|s| !s.is_empty())
        .map(|s| scrub_diag_text(s));
    let description = props
        .get("Description")
        .filter(|s| !s.is_empty())
        .map(|s| scrub_diag_text(s));

    let mut recent_journal = Vec::new();
    if journal_lines > 0
        && load_state != "not-found"
        && let Some(jctl_bin) = resolve_trusted_executable("journalctl")
    {
        let mut jcmd = Command::new(jctl_bin);
        apply_clean_desktop_env_std(&mut jcmd);
        if user_scope {
            jcmd.arg("--user");
        }
        jcmd.args([
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
            &journal_lines.to_string(),
            "-u",
            &normalized_unit,
        ]);
        if let Ok(jout) = run_bounded_command(jcmd, DEFAULT_CMD_TIMEOUT) {
            for line in jout.stdout.lines() {
                let t = line.trim();
                if !t.is_empty() && !t.starts_with("-- No entries --") {
                    recent_journal.push(scrub_diag_text(t));
                }
            }
        }
    }

    let healthy = load_state == "loaded"
        && (active_state == "active"
            || (active_state == "inactive" && result == "success" && exec_main_status == 0));

    let summary = format!(
        "服务 `{}` ({}): LoadState={}, ActiveState={} ({}), Result={}, ExitStatus={}",
        normalized_unit,
        if user_scope { "user" } else { "system" },
        load_state,
        active_state,
        sub_state,
        result,
        exec_main_status
    );

    Ok(ServiceStatusReport {
        unit: normalized_unit,
        user_scope,
        load_state,
        active_state,
        sub_state,
        result,
        exec_main_pid,
        exec_main_status,
        unit_file_state,
        fragment_path,
        description,
        healthy,
        recent_journal,
        summary,
    })
}

// =============================================================================
// 4. `package.inspect`
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInspectionReport {
    pub package: String,
    pub installed: bool,
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpkg_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    pub depends: Vec<String>,
    pub broken_dependencies: Vec<String>,
    pub healthy: bool,
    pub summary: String,
}

/// Check `dpkg-query -W`, `apt-cache policy`, `dpkg --audit`, `snap list`, and `flatpak info`.
pub fn inspect_package(args: &Value) -> anyhow::Result<PackageInspectionReport> {
    let raw_pkg = args
        .get("package")
        .or_else(|| args.get("name"))
        .or_else(|| args.get("query"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`package.inspect` 缺少必填参数 `package`"))?;
    let package = validate_unit_or_pkg_identifier(raw_pkg, "package")?;

    let mut installed = false;
    let mut sources: Vec<String> = Vec::new();
    let mut installed_version: Option<String> = None;
    let mut candidate_version: Option<String> = None;
    let mut dpkg_status: Option<String> = None;
    let mut architecture: Option<String> = None;
    let mut depends: Vec<String> = Vec::new();
    let mut broken_dependencies: Vec<String> = Vec::new();

    // 1. `dpkg-query -W`
    if let Some(dpkg_q) = resolve_trusted_executable("dpkg-query") {
        let mut cmd = Command::new(dpkg_q);
        apply_clean_desktop_env_std(&mut cmd);
        cmd.args([
            "-W",
            "-f=${Status}\\t${Version}\\t${Architecture}\\t${Depends}\\n",
            "--",
            &package,
        ]);
        if let Ok(res) = run_bounded_command(cmd, DEFAULT_CMD_TIMEOUT)
            && res.success
            && let Some(line) = res.stdout.lines().next()
        {
            let cols: Vec<&str> = line.split('\t').collect();
            if let Some(&st) = cols.first() {
                dpkg_status = Some(st.trim().to_string());
                if st.contains("install ok installed") {
                    installed = true;
                    sources.push("dpkg/apt".to_string());
                } else if !st.contains("unknown ok not-installed")
                    && !st.contains("deinstall ok config-files")
                {
                    broken_dependencies.push(format!("dpkg 状态异常: {}", st.trim()));
                }
            }
            if let Some(&ver) = cols.get(1)
                && !ver.trim().is_empty()
                && installed
            {
                installed_version = Some(ver.trim().to_string());
            }
            if let Some(&arch) = cols.get(2)
                && !arch.trim().is_empty()
            {
                architecture = Some(arch.trim().to_string());
            }
            if let Some(&deps_raw) = cols.get(3)
                && !deps_raw.trim().is_empty()
            {
                depends = deps_raw
                    .split(',')
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())
                    .take(30)
                    .collect();
            }
        }
    }

    // 2. `apt-cache policy`
    if let Some(apt_cache) = resolve_trusted_executable("apt-cache") {
        let mut cmd = Command::new(apt_cache);
        apply_clean_desktop_env_std(&mut cmd);
        cmd.env("LC_ALL", "C.UTF-8");
        cmd.args(["policy", "--", &package]);
        if let Ok(res) = run_bounded_command(cmd, DEFAULT_CMD_TIMEOUT)
            && res.success
        {
            for line in res.stdout.lines() {
                let t = line.trim();
                if let Some(iv) = t.strip_prefix("Installed:") {
                    let v = iv.trim();
                    if v != "(none)" && !v.is_empty() && installed_version.is_none() {
                        installed_version = Some(v.to_string());
                        installed = true;
                        if !sources.iter().any(|s| s == "dpkg/apt") {
                            sources.push("dpkg/apt".to_string());
                        }
                    }
                } else if let Some(cv) = t.strip_prefix("Candidate:") {
                    let v = cv.trim();
                    if v != "(none)" && !v.is_empty() {
                        candidate_version = Some(v.to_string());
                    }
                }
            }
        }
    }

    // 3. Read-only broken package check via `dpkg --audit`
    if let Some(dpkg_bin) = resolve_trusted_executable("dpkg") {
        let mut cmd = Command::new(dpkg_bin);
        apply_clean_desktop_env_std(&mut cmd);
        cmd.arg("--audit");
        if let Ok(res) = run_bounded_command(cmd, DEFAULT_CMD_TIMEOUT) {
            for line in res.stdout.lines() {
                let t = line.trim();
                if !t.is_empty() && t.contains(&package) {
                    broken_dependencies.push(scrub_diag_text(t));
                }
            }
        }
    }

    // 4. `snap list <package>`
    if let Some(snap_bin) = resolve_trusted_executable("snap") {
        let mut cmd = Command::new(snap_bin);
        apply_clean_desktop_env_std(&mut cmd);
        cmd.args(["list", &package]);
        if let Ok(res) = run_bounded_command(cmd, Duration::from_millis(2_500))
            && res.success
        {
            for line in res.stdout.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 2 && cols[0] == package {
                    installed = true;
                    sources.push("snap".to_string());
                    if installed_version.is_none() {
                        installed_version = Some(cols[1].to_string());
                    }
                }
            }
        }
    }

    // 5. `flatpak info <package>`
    if let Some(fp_bin) = resolve_trusted_executable("flatpak") {
        let mut cmd = Command::new(fp_bin);
        apply_clean_desktop_env_std(&mut cmd);
        cmd.env("LC_ALL", "C.UTF-8");
        cmd.args(["info", &package]);
        if let Ok(res) = run_bounded_command(cmd, Duration::from_millis(2_500))
            && res.success
        {
            installed = true;
            sources.push("flatpak".to_string());
            for line in res.stdout.lines() {
                if let Some(ver) = line.trim().strip_prefix("Version:")
                    && installed_version.is_none()
                {
                    installed_version = Some(ver.trim().to_string());
                }
            }
        }
    }

    let healthy = installed && broken_dependencies.is_empty();
    let summary = if installed {
        format!(
            "软件包 `{}` 已安装（来源: {}，版本: {}{}）",
            package,
            sources.join("+"),
            installed_version.as_deref().unwrap_or("unknown"),
            if broken_dependencies.is_empty() {
                "，依赖完整".to_string()
            } else {
                format!("，发现 {} 项依赖/状态异常", broken_dependencies.len())
            }
        )
    } else {
        format!(
            "软件包 `{}` 当前未安装（APT 候选版本: {}）",
            package,
            candidate_version.as_deref().unwrap_or("无")
        )
    };

    Ok(PackageInspectionReport {
        package,
        installed,
        sources,
        installed_version,
        candidate_version,
        dpkg_status,
        architecture,
        depends,
        broken_dependencies,
        healthy,
        summary,
    })
}

// =============================================================================
// 5. `network.diagnose`
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceDiag {
    pub name: String,
    pub operstate: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPortProbe {
    pub label: String,
    pub endpoint: String,
    pub reachable: bool,
    pub configured_in_env: bool,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMountHealth {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub healthy: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiagnosisReport {
    pub interfaces: Vec<NetworkInterfaceDiag>,
    pub has_non_loopback_ip: bool,
    pub default_routes: Vec<String>,
    pub has_default_route: bool,
    pub dns_nameservers: Vec<String>,
    pub systemd_resolved_stub: bool,
    pub proxy_probes: Vec<ProxyPortProbe>,
    pub stale_proxy_detected: bool,
    pub cloud_and_fuse_mounts: Vec<CloudMountHealth>,
    pub unhealthy_mounts_count: usize,
    pub root_cause: String,
    pub healthy: bool,
    pub summary: String,
}

/// Collect real interface IPs (`ip -j addr`), default route (`ip route`), DNS (`/etc/resolv.conf`),
/// local proxy TCP liveness, and `/proc/mounts` cloud/rclone FUSE mount health.
pub fn diagnose_network(args: &Value) -> anyhow::Result<NetworkDiagnosisReport> {
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(250)
        .clamp(50, 5_000);
    let probe_timeout = Duration::from_millis(timeout_ms);

    // 1. Interfaces via `ip -j addr` (with fallback to `ip -o addr`)
    let mut interfaces = Vec::new();
    let mut has_non_loopback_ip = false;
    if let Some(ip_bin) = resolve_trusted_executable("ip") {
        let mut cmd = Command::new(&ip_bin);
        apply_clean_desktop_env_std(&mut cmd);
        cmd.args(["-j", "addr", "show"]);
        if let Ok(res) = run_bounded_command(cmd, DEFAULT_CMD_TIMEOUT)
            && res.success
            && let Ok(arr) = serde_json::from_str::<Vec<Value>>(&res.stdout)
        {
            for item in arr {
                let ifname = item
                    .get("ifname")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let operstate = item
                    .get("operstate")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_string();
                let mut addrs = Vec::new();
                if let Some(addr_info) = item.get("addr_info").and_then(|v| v.as_array()) {
                    for ai in addr_info {
                        if let Some(local) = ai.get("local").and_then(|v| v.as_str()) {
                            let prefix = ai.get("prefixlen").and_then(|v| v.as_u64()).unwrap_or(0);
                            if ifname != "lo" && !local.starts_with("127.") && local != "::1" {
                                has_non_loopback_ip = true;
                            }
                            addrs.push(format!("{}/{}", local, prefix));
                        }
                    }
                }
                interfaces.push(NetworkInterfaceDiag {
                    name: ifname,
                    operstate,
                    addresses: addrs,
                });
            }
        }

        // 2. Default route via `ip route show default`
        let mut rcmd = Command::new(&ip_bin);
        apply_clean_desktop_env_std(&mut rcmd);
        rcmd.args(["route", "show", "default"]);
        let default_routes = if let Ok(rres) = run_bounded_command(rcmd, DEFAULT_CMD_TIMEOUT) {
            rres.stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(ToString::to_string)
                .collect()
        } else {
            Vec::new()
        };
        let has_default_route = !default_routes.is_empty();

        // 3. DNS nameservers from `/etc/resolv.conf`
        let resolv_raw = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let (dns_nameservers, systemd_resolved_stub) = parse_resolv_conf(&resolv_raw);

        // 4. Local proxy TCP liveness check
        let mut proxy_targets: Vec<(String, SocketAddr, bool)> = Vec::new();
        let mut seen_addrs: HashSet<SocketAddr> = HashSet::new();

        if let Some(explicit_url) = args
            .get("proxy_url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            && let Some(sa) = parse_local_proxy_socket_addr(explicit_url)
            && seen_addrs.insert(sa)
        {
            proxy_targets.push(("explicit_proxy_url".to_string(), sa, true));
        }

        for env_key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            if let Ok(val) = std::env::var(env_key)
                && !val.trim().is_empty()
                && let Some(sa) = parse_local_proxy_socket_addr(&val)
                && seen_addrs.insert(sa)
            {
                proxy_targets.push((format!("env:{}", env_key), sa, true));
            }
        }

        let explicit_ports: Vec<u16> = args
            .get("proxy_ports")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().and_then(|n| u16::try_from(n).ok()))
                    .collect()
            })
            .unwrap_or_else(|| vec![7890, 7897]);

        for port in explicit_ports {
            let sa = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            if seen_addrs.insert(sa) {
                proxy_targets.push((format!("local_port:{}", port), sa, false));
            }
        }

        let mut proxy_probes = Vec::new();
        let mut stale_proxy_detected = false;
        for (label, sa, configured_in_env) in proxy_targets {
            let t0 = Instant::now();
            let reachable = TcpStream::connect_timeout(&sa, probe_timeout).is_ok();
            let latency_ms = if reachable {
                Some(t0.elapsed().as_millis() as u64)
            } else {
                None
            };
            if configured_in_env && !reachable {
                stale_proxy_detected = true;
            }
            proxy_probes.push(ProxyPortProbe {
                label,
                endpoint: sa.to_string(),
                reachable,
                configured_in_env,
                latency_ms,
            });
        }

        // 5. Cloud / FUSE / Network mount health from `/proc/mounts`
        let mounts_raw = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        let cloud_and_fuse_mounts = inspect_cloud_and_fuse_mounts(&mounts_raw);
        let unhealthy_mounts_count = cloud_and_fuse_mounts.iter().filter(|m| !m.healthy).count();

        let root_cause = if stale_proxy_detected {
            "stale_local_proxy".to_string()
        } else if !has_non_loopback_ip {
            "no_active_interface_ip".to_string()
        } else if !has_default_route {
            "missing_default_route".to_string()
        } else if dns_nameservers.is_empty() {
            "missing_dns_nameserver".to_string()
        } else if unhealthy_mounts_count > 0 {
            "unhealthy_cloud_mount".to_string()
        } else {
            "healthy".to_string()
        };

        let healthy = root_cause == "healthy";
        let summary = format!(
            "网络诊断 [{}]: 网卡 {} 个, 默认路由={}, DNS={} ({}), 失效代理配置={}, 云盘/FUSE挂载 {} 个(异常 {})",
            root_cause,
            interfaces.len(),
            has_default_route,
            dns_nameservers.len(),
            dns_nameservers.join(","),
            stale_proxy_detected,
            cloud_and_fuse_mounts.len(),
            unhealthy_mounts_count
        );

        return Ok(NetworkDiagnosisReport {
            interfaces,
            has_non_loopback_ip,
            default_routes,
            has_default_route,
            dns_nameservers,
            systemd_resolved_stub,
            proxy_probes,
            stale_proxy_detected,
            cloud_and_fuse_mounts,
            unhealthy_mounts_count,
            root_cause,
            healthy,
            summary,
        });
    }

    anyhow::bail!("当前系统缺少 `/usr/sbin/ip` 或 `/usr/bin/ip` 工具，无法完成网络接口诊断")
}

/// Parse `/etc/resolv.conf` into `(nameservers, uses_systemd_resolved_stub)`.
pub fn parse_resolv_conf(raw: &str) -> (Vec<String>, bool) {
    let mut ns = Vec::new();
    for line in raw.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let ip = rest.trim();
            if !ip.is_empty() {
                ns.push(ip.to_string());
            }
        }
    }
    let stub = ns.iter().any(|ip| ip == "127.0.0.53");
    (ns, stub)
}

/// Parse a localhost proxy URL (`http://127.0.0.1:7890`, `socks5://localhost:1080`, `127.0.0.1:7897`)
/// into a local `SocketAddr` without exposing any embedded credentials.
pub fn parse_local_proxy_socket_addr(raw: &str) -> Option<SocketAddr> {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);

    if let Some(rest) = host_port.strip_prefix("[::1]:") {
        let port = rest.parse::<u16>().ok()?;
        return Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
    }
    let (host, port_s) = host_port.rsplit_once(':')?;
    let port = port_s.parse::<u16>().ok()?;
    match host.to_ascii_lowercase().as_str() {
        "127.0.0.1" | "localhost" => Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
        _ => None,
    }
}

fn unescape_mount_field(raw: &str) -> String {
    raw.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

/// Inspect FUSE/rclone/network mounts from `/proc/mounts` using a bounded timeout stat probe.
pub fn inspect_cloud_and_fuse_mounts(mounts_raw: &str) -> Vec<CloudMountHealth> {
    let mut out = Vec::new();
    for line in mounts_raw.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        let device = unescape_mount_field(cols[0]);
        let mount_point = unescape_mount_field(cols[1]);
        let fs_type = cols[2].to_string();

        // Skip standard system pseudo-FUSE mounts (`fusectl`, `portal` unless broken)
        let is_cloud_or_net = fs_type == "fuse.rclone"
            || fs_type == "fuse.sshfs"
            || fs_type == "fuse.gvfsd-fuse"
            || fs_type == "cifs"
            || fs_type == "nfs"
            || fs_type == "nfs4"
            || fs_type == "davfs"
            || device.to_ascii_lowercase().contains("rclone")
            || (fs_type.starts_with("fuse.") && fs_type != "fuse.portal");

        if !is_cloud_or_net {
            continue;
        }

        let mp_clone = PathBuf::from(&mount_point);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let res = std::fs::metadata(&mp_clone).map(|m| m.is_dir());
            let _ = tx.send(res);
        });

        let (healthy, detail) = match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(Ok(true)) => (true, "挂载点可正常访问".to_string()),
            Ok(Ok(false)) => (false, "挂载点不是有效目录".to_string()),
            Ok(Err(e)) => (
                false,
                format!("挂载点读取失败 (Transport endpoint disconnected?): {}", e),
            ),
            Err(_) => (
                false,
                "挂载点 stat 响应超时 (>300ms)，疑似网络/FUSE 挂死".to_string(),
            ),
        };

        out.push(CloudMountHealth {
            device: scrub_diag_text(&device),
            mount_point: scrub_diag_text(&mount_point),
            fs_type,
            healthy,
            detail,
        });
    }
    out
}

// =============================================================================
// 6. `system.bottleneck` / Enriched `system.inspect` Read-Only Helper
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMountUsage {
    pub filesystem: String,
    pub mount_point: String,
    pub total_kb: u64,
    pub used_kb: u64,
    pub available_kb: u64,
    pub used_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResourceSample {
    pub pid: u32,
    pub name: String,
    pub state: String,
    pub category: String,
    pub rss_kb: u64,
    pub swap_kb: u64,
    pub cpu_ticks: u64,
    pub cmdline_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemBottleneckReport {
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub mem_used_pct: f64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
    pub swap_used_kb: u64,
    pub swap_used_pct: f64,
    pub pswpin: u64,
    pub pswpout: u64,
    pub oom_kill_count: u64,
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub cpu_cores: usize,
    pub cpu_iowait_pct_est: f64,
    pub memory_pressure: String,
    pub zombie_count: usize,
    pub uninterruptible_io_count: usize,
    pub disks: Vec<DiskMountUsage>,
    pub top_rss_processes: Vec<ProcessResourceSample>,
    pub top_cpu_processes: Vec<ProcessResourceSample>,
    pub bottleneck_findings: Vec<String>,
    pub read_only_no_mutation: bool,
    pub summary: String,
}

/// Enriched read-only system bottleneck diagnosis over real `/proc` and `df -Pk`.
/// **Strictly read-only**: NEVER kills processes, drops caches, or alters system settings.
pub fn diagnose_system_bottleneck(args: &Value) -> anyhow::Result<SystemBottleneckReport> {
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(8)
        .clamp(1, 25) as usize;
    diagnose_system_bottleneck_from_proc(Path::new("/proc"), limit)
}

/// Testable `/proc`-parameterized bottleneck analyzer (called with `/proc` in production).
pub fn diagnose_system_bottleneck_from_proc(
    proc_root: &Path,
    limit: usize,
) -> anyhow::Result<SystemBottleneckReport> {
    let meminfo_raw = std::fs::read_to_string(proc_root.join("meminfo"))
        .map_err(|e| anyhow::anyhow!("无法读取 {:?}/meminfo: {}", proc_root, e))?;
    let mut mem_kv: BTreeMap<String, u64> = BTreeMap::new();
    for line in meminfo_raw.lines() {
        if let Some((k, rest)) = line.split_once(':')
            && let Some(num) = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
        {
            mem_kv.insert(k.trim().to_string(), num);
        }
    }

    let mem_total_kb = mem_kv.get("MemTotal").copied().unwrap_or(0);
    let mem_avail_kb = mem_kv
        .get("MemAvailable")
        .copied()
        .unwrap_or_else(|| mem_kv.get("MemFree").copied().unwrap_or(0));
    let mem_used_kb = mem_total_kb.saturating_sub(mem_avail_kb);
    let mem_used_pct = if mem_total_kb > 0 {
        ((mem_used_kb as f64 / mem_total_kb as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let swap_total_kb = mem_kv.get("SwapTotal").copied().unwrap_or(0);
    let swap_free_kb = mem_kv.get("SwapFree").copied().unwrap_or(0);
    let swap_used_kb = swap_total_kb.saturating_sub(swap_free_kb);
    let swap_used_pct = if swap_total_kb > 0 {
        ((swap_used_kb as f64 / swap_total_kb as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };

    // `/proc/vmstat` swap-in / swap-out & OOM events
    let vmstat_raw = std::fs::read_to_string(proc_root.join("vmstat")).unwrap_or_default();
    let mut pswpin = 0u64;
    let mut pswpout = 0u64;
    let mut oom_kill_count = 0u64;
    for line in vmstat_raw.lines() {
        let mut it = line.split_whitespace();
        if let (Some(k), Some(v)) = (it.next(), it.next())
            && let Ok(n) = v.parse::<u64>()
        {
            match k {
                "pswpin" => pswpin = n,
                "pswpout" => pswpout = n,
                "oom_kill" => oom_kill_count = n,
                _ => {}
            }
        }
    }

    // `/proc/loadavg`
    let loadavg_raw = std::fs::read_to_string(proc_root.join("loadavg")).unwrap_or_default();
    let load_cols: Vec<f64> = loadavg_raw
        .split_whitespace()
        .take(3)
        .filter_map(|s| s.parse::<f64>().ok())
        .collect();
    let load_1m = load_cols.first().copied().unwrap_or(0.0);
    let load_5m = load_cols.get(1).copied().unwrap_or(0.0);
    let load_15m = load_cols.get(2).copied().unwrap_or(0.0);
    let cpu_cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // `/proc/stat` aggregate CPU iowait ratio
    let stat_raw = std::fs::read_to_string(proc_root.join("stat")).unwrap_or_default();
    let cpu_iowait_pct_est = parse_proc_stat_iowait_pct(&stat_raw);

    // Sample processes from `<proc_root>/<pid>/{status,stat,statm,cmdline}`
    let page_kb = 4u64;
    let mut samples: Vec<ProcessResourceSample> = Vec::new();
    let mut zombie_count = 0usize;
    let mut uninterruptible_io_count = 0usize;

    if let Ok(rd) = std::fs::read_dir(proc_root) {
        for entry in rd.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let pdir = entry.path();
            let status_s = std::fs::read_to_string(pdir.join("status")).unwrap_or_default();
            if status_s.is_empty() {
                continue;
            }
            let mut name = String::new();
            let mut state_code = String::new();
            let mut rss_kb = 0u64;
            let mut swap_kb = 0u64;
            for line in status_s.lines() {
                if let Some(v) = line.strip_prefix("Name:") {
                    name = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("State:") {
                    state_code = v.split_whitespace().next().unwrap_or("").to_string();
                } else if let Some(v) = line.strip_prefix("VmRSS:") {
                    rss_kb = v
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse::<u64>().ok())
                        .unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("VmSwap:") {
                    swap_kb = v
                        .split_whitespace()
                        .next()
                        .and_then(|x| x.parse::<u64>().ok())
                        .unwrap_or(0);
                }
            }

            // Fallback to `/proc/<pid>/statm` resident pages when `VmRSS` was absent
            if rss_kb == 0
                && let Ok(statm_s) = std::fs::read_to_string(pdir.join("statm"))
                && let Some(res_pages) = statm_s
                    .split_whitespace()
                    .nth(1)
                    .and_then(|x| x.parse::<u64>().ok())
            {
                rss_kb = res_pages.saturating_mul(page_kb);
            }

            let cpu_ticks = std::fs::read_to_string(pdir.join("stat"))
                .ok()
                .map(|s| parse_proc_pid_cpu_ticks(&s))
                .unwrap_or(0);

            if state_code == "Z" {
                zombie_count += 1;
            } else if state_code == "D" {
                uninterruptible_io_count += 1;
            }

            let cmdline_raw = std::fs::read(pdir.join("cmdline"))
                .map(|b| {
                    b.split(|&c| c == 0)
                        .filter(|seg| !seg.is_empty())
                        .map(|seg| String::from_utf8_lossy(seg).into_owned())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let cmdline_preview =
                scrub_diag_text(&cmdline_raw.chars().take(160).collect::<String>());

            let category = classify_process_category(&name, &state_code, &cmdline_preview);
            if !name.is_empty() {
                samples.push(ProcessResourceSample {
                    pid,
                    name,
                    state: state_code,
                    category,
                    rss_kb,
                    swap_kb,
                    cpu_ticks,
                    cmdline_preview,
                });
            }
        }
    }

    let mut by_rss = samples.clone();
    by_rss.sort_by_key(|p| std::cmp::Reverse(p.rss_kb));
    by_rss.truncate(limit);

    let mut by_cpu = samples;
    by_cpu.sort_by_key(|p| std::cmp::Reverse(p.cpu_ticks));
    by_cpu.truncate(limit);

    let disks = collect_df_mounts();

    let memory_pressure = if mem_used_pct >= 92.0 || (swap_used_pct >= 50.0 && pswpout > 1000) {
        "critical_swap_thrashing".to_string()
    } else if mem_used_pct >= 82.0 || swap_used_pct >= 25.0 {
        "high".to_string()
    } else if mem_used_pct >= 65.0 {
        "moderate".to_string()
    } else {
        "low".to_string()
    };

    let mut findings = Vec::new();
    if memory_pressure == "critical_swap_thrashing" {
        findings.push(format!(
            "物理内存高度紧张 ({:.1}% 已用，可用 {:.1} MiB) 且发生明显 Swap 交换 ({:.1}% Swap 已用, pswpout={})",
            mem_used_pct,
            mem_avail_kb as f64 / 1024.0,
            swap_used_pct,
            pswpout
        ));
    } else if memory_pressure == "high" {
        findings.push(format!(
            "物理内存占用偏高 ({:.1}% 已用，剩余可用 {:.1} MiB)",
            mem_used_pct,
            mem_avail_kb as f64 / 1024.0
        ));
    }
    if load_1m > (cpu_cores as f64) * 1.25 {
        findings.push(format!(
            "1分钟平均负载 ({:.2}) 超过逻辑核心数 ({} 核)，CPU 调度或磁盘队列拥塞",
            load_1m, cpu_cores
        ));
    }
    if zombie_count > 0 {
        findings.push(format!("检测到 {} 个僵尸进程 (State=Z)", zombie_count));
    }
    if uninterruptible_io_count > 0 {
        findings.push(format!(
            "检测到 {} 个处于不可中断磁盘 I/O 等待的进程 (State=D)",
            uninterruptible_io_count
        ));
    }
    for d in &disks {
        if d.used_pct >= 90.0 {
            findings.push(format!(
                "磁盘挂载点 `{}` 空间告急 ({:.1}% 已用，仅剩 {:.2} GiB)",
                d.mount_point,
                d.used_pct,
                d.available_kb as f64 / 1_048_576.0
            ));
        }
    }
    if let Some(top) = by_rss.first() {
        findings.push(format!(
            "当前最大内存占用进程：`{}` (PID {}, 类型={}, RSS {:.1} MiB)",
            top.name,
            top.pid,
            top.category,
            top.rss_kb as f64 / 1024.0
        ));
    }

    let summary = format!(
        "系统瓶颈只读诊断：内存已用 {:.1}% (可用 {:.0} MiB, 压力={}) | Swap {:.1}% | 负载 {:.2}/{:.2}/{:.2} ({}核) | 僵尸进程={}",
        mem_used_pct,
        mem_avail_kb as f64 / 1024.0,
        memory_pressure,
        swap_used_pct,
        load_1m,
        load_5m,
        load_15m,
        cpu_cores,
        zombie_count
    );

    Ok(SystemBottleneckReport {
        mem_total_kb,
        mem_available_kb: mem_avail_kb,
        mem_used_pct,
        swap_total_kb,
        swap_free_kb,
        swap_used_kb,
        swap_used_pct,
        pswpin,
        pswpout,
        oom_kill_count,
        load_1m,
        load_5m,
        load_15m,
        cpu_cores,
        cpu_iowait_pct_est,
        memory_pressure,
        zombie_count,
        uninterruptible_io_count,
        disks,
        top_rss_processes: by_rss,
        top_cpu_processes: by_cpu,
        bottleneck_findings: findings,
        read_only_no_mutation: true,
        summary,
    })
}

fn parse_proc_stat_iowait_pct(stat_raw: &str) -> f64 {
    let Some(cpu_line) = stat_raw.lines().find(|l| l.starts_with("cpu ")) else {
        return 0.0;
    };
    let nums: Vec<u64> = cpu_line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse::<u64>().ok())
        .collect();
    if nums.len() < 5 {
        return 0.0;
    }
    let total: u64 = nums.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let iowait = nums[4];
    ((iowait as f64 / total as f64) * 1000.0).round() / 10.0
}

fn parse_proc_pid_cpu_ticks(stat_line: &str) -> u64 {
    let Some(rparen) = stat_line.rfind(')') else {
        return 0;
    };
    let after = stat_line[rparen + 1..].trim();
    let cols: Vec<&str> = after.split_whitespace().collect();
    // After `(comm)`: [0]=state, ..., [11]=utime, [12]=stime
    let utime = cols
        .get(11)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let stime = cols
        .get(12)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    utime.saturating_add(stime)
}

fn classify_process_category(name: &str, state: &str, cmdline: &str) -> String {
    if state == "Z" {
        return "zombie".to_string();
    }
    let n = name.to_ascii_lowercase();
    let c = cmdline.to_ascii_lowercase();
    if matches!(
        n.as_str(),
        "chrome" | "chromium" | "firefox" | "firefox-bin" | "msedge" | "brave"
    ) || c.contains("google-chrome")
    {
        "browser".to_string()
    } else if c.contains("--type=renderer")
        || c.contains("electron")
        || matches!(n.as_str(), "qq" | "wechat" | "feishu" | "wemeetapp")
    {
        "electron_or_desktop_client".to_string()
    } else if matches!(
        n.as_str(),
        "code" | "rust-analyzer" | "pyright" | "tsserver" | "cargo" | "rustc"
    ) {
        "ide_or_toolchain".to_string()
    } else if matches!(
        n.as_str(),
        "dockerd" | "containerd" | "qemu-system-x86" | "vboxheadless"
    ) {
        "container_or_vm".to_string()
    } else {
        "system_or_service".to_string()
    }
}

fn collect_df_mounts() -> Vec<DiskMountUsage> {
    let mut out = Vec::new();
    let Some(df_bin) = resolve_trusted_executable("df") else {
        return out;
    };
    let mut cmd = Command::new(df_bin);
    apply_clean_desktop_env_std(&mut cmd);
    cmd.args([
        "-Pk", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay",
    ]);
    if let Ok(res) = run_bounded_command(cmd, DEFAULT_CMD_TIMEOUT)
        && res.success
    {
        for line in res.stdout.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 {
                continue;
            }
            let total_kb = cols[1].parse::<u64>().unwrap_or(0);
            let used_kb = cols[2].parse::<u64>().unwrap_or(0);
            let available_kb = cols[3].parse::<u64>().unwrap_or(0);
            let used_pct = cols[4]
                .trim_end_matches('%')
                .parse::<f64>()
                .unwrap_or_else(|_| {
                    if total_kb > 0 {
                        (used_kb as f64 / total_kb as f64) * 100.0
                    } else {
                        0.0
                    }
                });
            out.push(DiskMountUsage {
                filesystem: cols[0].to_string(),
                mount_point: cols[5].to_string(),
                total_kb,
                used_kb,
                available_kb,
                used_pct,
            });
        }
    }
    out
}

// =============================================================================
// 7. `repair.plan`
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairStepProposal {
    pub step_index: usize,
    pub capability_id: String,
    pub suggested_arguments: Value,
    pub description: String,
    pub effect: Effect,
    pub risk_tier: String,
    pub requires_approval: bool,
    pub reversible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationProbeSpec {
    pub probe_capability_id: String,
    pub probe_arguments: Value,
    pub success_criteria: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairPlan {
    pub diagnosis_summary: String,
    pub root_cause: String,
    pub evidence_items: Vec<String>,
    pub proposed_steps: Vec<RepairStepProposal>,
    pub risk_tier: String,
    pub requires_approval: bool,
    pub reversible: bool,
    pub verification_probe: VerificationProbeSpec,
}

/// Build a structured, non-executing `RepairPlan` from collected diagnostic evidence JSON.
pub fn build_repair_plan(args: &Value) -> anyhow::Result<RepairPlan> {
    let evidence = args
        .get("evidence")
        .ok_or_else(|| anyhow::anyhow!("`repair.plan` 缺少必填参数 `evidence`"))?;
    if !evidence.is_object() {
        anyhow::bail!("`repair.plan` 的 `evidence` 必须为结构化 JSON 对象");
    }

    let root_cause = evidence
        .get("root_cause")
        .and_then(|v| v.as_str())
        .or_else(|| evidence.get("memory_pressure").and_then(|v| v.as_str()))
        .unwrap_or("unknown")
        .to_string();

    let mut evidence_items: Vec<String> = Vec::new();
    if let Some(sum) = evidence.get("summary").and_then(|v| v.as_str()) {
        evidence_items.push(scrub_diag_text(sum));
    }
    if let Some(arr) = evidence
        .get("bottleneck_findings")
        .and_then(|v| v.as_array())
    {
        for item in arr.iter().filter_map(|x| x.as_str()) {
            evidence_items.push(scrub_diag_text(item));
        }
    }
    if let Some(arr) = evidence.get("desktop_issues").and_then(|v| v.as_array()) {
        for item in arr.iter().filter_map(|x| x.as_str()) {
            evidence_items.push(format!("Desktop异常: {}", scrub_diag_text(item)));
        }
    }
    if let Some(arr) = evidence
        .get("conda_or_env_clashes")
        .and_then(|v| v.as_array())
    {
        for clash in arr {
            if let (Some(so), Some(cur), Some(san)) = (
                clash.get("soname").and_then(|v| v.as_str()),
                clash.get("current_env_path").and_then(|v| v.as_str()),
                clash.get("sanitized_env_path").and_then(|v| v.as_str()),
            ) {
                evidence_items.push(format!(
                    "动态库冲突 {}: 当前环境加载 `{}` vs 系统纯净环境 `{}`",
                    so,
                    scrub_diag_text(cur),
                    scrub_diag_text(san)
                ));
            }
        }
    }
    if let Some(arr) = evidence
        .get("missing_libraries_sanitized")
        .and_then(|v| v.as_array())
    {
        for so in arr.iter().filter_map(|x| x.as_str()) {
            evidence_items.push(format!("缺失共享库: {} => not found", so));
        }
    }
    if let Some(arr) = evidence
        .get("broken_dependencies")
        .and_then(|v| v.as_array())
    {
        for bd in arr.iter().filter_map(|x| x.as_str()) {
            evidence_items.push(scrub_diag_text(bd));
        }
    }

    let mut proposed_steps: Vec<RepairStepProposal> = Vec::new();
    let probe: VerificationProbeSpec = match root_cause.as_str() {
        "conda_ld_library_conflict" => {
            let target = evidence
                .get("target")
                .or_else(|| evidence.get("resolved_executable"))
                .and_then(|v| v.as_str())
                .unwrap_or("app");
            proposed_steps.push(RepairStepProposal {
                step_index: 1,
                capability_id: "app_adapter_invoke".to_string(),
                suggested_arguments: json!({
                    "app_hint": target,
                    "intent_action": "launch_app",
                    "params": { "sanitize_env": true }
                }),
                description: format!(
                    "通过纯净桌面环境（自动剥离 Conda `LD_LIBRARY_PATH` 劫持路径）启动 `{}`",
                    scrub_diag_text(target)
                ),
                effect: Effect::Ui,
                risk_tier: Effect::Ui.risk_badge().to_string(),
                requires_approval: false,
                reversible: true,
            });
            if let Some(dt_path) = evidence.get("desktop_file").and_then(|v| v.as_str()) {
                proposed_steps.push(RepairStepProposal {
                    step_index: 2,
                    capability_id: "file.write".to_string(),
                    suggested_arguments: json!({
                        "path": dt_path,
                        "reason": "在用户本地 .desktop 启动器中显式清理 LD_LIBRARY_PATH（自动生成 ChangeSet 备份支持一键撤销）"
                    }),
                    description: format!(
                        "可选持久化修复：更新启动器 `{}` 为 `env -u LD_LIBRARY_PATH`（已备份原文件，可一键 Undo）",
                        scrub_diag_text(dt_path)
                    ),
                    effect: Effect::WriteReversible,
                    risk_tier: Effect::WriteReversible.risk_badge().to_string(),
                    requires_approval: true,
                    reversible: true,
                });
            }
            VerificationProbeSpec {
                probe_capability_id: "dependency.inspect".to_string(),
                probe_arguments: json!({ "target": target }),
                success_criteria: vec![
                    "root_cause == 'healthy'".into(),
                    "missing_libraries_sanitized is empty".into(),
                ],
            }
        }
        "broken_desktop_entry" | "not_executable_permission" | "broken_shebang_interpreter" => {
            let target = evidence
                .get("desktop_file")
                .or_else(|| evidence.get("resolved_executable"))
                .or_else(|| evidence.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("target");
            if root_cause == "not_executable_permission" {
                let exec_p = evidence
                    .get("resolved_executable")
                    .and_then(|v| v.as_str())
                    .unwrap_or(target);
                proposed_steps.push(RepairStepProposal {
                    step_index: 1,
                    capability_id: "terminal.execute".to_string(),
                    suggested_arguments: json!({
                        "program": "chmod",
                        "argv": ["+x", exec_p],
                        "purpose": "恢复可执行文件运行权限"
                    }),
                    description: format!(
                        "为可执行文件 `{}` 添加 `+x` 执行权限",
                        scrub_diag_text(exec_p)
                    ),
                    effect: Effect::ProcessControl,
                    risk_tier: "R3".to_string(),
                    requires_approval: true,
                    reversible: false,
                });
            } else {
                proposed_steps.push(RepairStepProposal {
                    step_index: 1,
                    capability_id: "file.write".to_string(),
                    suggested_arguments: json!({
                        "path": target,
                        "reason": "修正损坏的 .desktop Exec=/解释器路径并生成可撤销备份"
                    }),
                    description: format!(
                        "修正 `{}` 中无效的可执行路径或解释器配置（保留原文件 ChangeSet 备份）",
                        scrub_diag_text(target)
                    ),
                    effect: Effect::WriteReversible,
                    risk_tier: "R2".to_string(),
                    requires_approval: true,
                    reversible: true,
                });
            }
            VerificationProbeSpec {
                probe_capability_id: "dependency.inspect".to_string(),
                probe_arguments: json!({ "target": target }),
                success_criteria: vec![
                    "exists == true".into(),
                    "is_executable == true".into(),
                    "desktop_issues is empty".into(),
                ],
            }
        }
        "missing_shared_library" => {
            let target = evidence
                .get("resolved_executable")
                .or_else(|| evidence.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("binary");
            let missing_list: Vec<&str> = evidence
                .get("missing_libraries_sanitized")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            let first_so = missing_list.first().copied().unwrap_or("libmissing.so");
            proposed_steps.push(RepairStepProposal {
                step_index: 1,
                capability_id: "package.search".to_string(),
                suggested_arguments: json!({ "query": first_so.split(".so").next().unwrap_or(first_so) }),
                description: format!("先只读检索提供 `{}` 的候选系统软件包", first_so),
                effect: Effect::Observe,
                risk_tier: "R0".to_string(),
                requires_approval: false,
                reversible: true,
            });
            proposed_steps.push(RepairStepProposal {
                step_index: 2,
                capability_id: "terminal.handoff".to_string(),
                suggested_arguments: json!({
                    "command": format!("sudo apt-get install {}", first_so.split(".so").next().unwrap_or(first_so)),
                    "explanation": "安装缺失的系统运行时共享库（系统包变更不可自动撤销，需人工确认执行）"
                }),
                description: format!("经用户确认安装缺失运行时库 ({})", missing_list.join(", ")),
                effect: Effect::SystemAdmin,
                risk_tier: "R3".to_string(),
                requires_approval: true,
                reversible: false,
            });
            VerificationProbeSpec {
                probe_capability_id: "dependency.inspect".to_string(),
                probe_arguments: json!({ "target": target }),
                success_criteria: vec!["missing_libraries_sanitized is empty".into()],
            }
        }
        "stale_local_proxy"
        | "missing_default_route"
        | "missing_dns_nameserver"
        | "unhealthy_cloud_mount" => {
            if root_cause == "stale_local_proxy" {
                proposed_steps.push(RepairStepProposal {
                    step_index: 1,
                    capability_id: "app_adapter_invoke".to_string(),
                    suggested_arguments: json!({
                        "app_hint": "flclash",
                        "intent_action": "probe_proxy_status",
                        "params": {}
                    }),
                    description: "检查本机代理客户端进程，或关闭环境变量中指向已离线端口的代理设置"
                        .to_string(),
                    effect: Effect::Setting,
                    risk_tier: "R1".to_string(),
                    requires_approval: true,
                    reversible: true,
                });
            } else {
                proposed_steps.push(RepairStepProposal {
                    step_index: 1,
                    capability_id: "terminal.handoff".to_string(),
                    suggested_arguments: json!({
                        "command": "resolvectl status",
                        "explanation": "检查网卡路由、DNS 解析服务或重新挂载异常的 rclone/FUSE 云盘"
                    }),
                    description: format!("针对 `{}` 进行受控网络/挂载恢复", root_cause),
                    effect: Effect::ProcessControl,
                    risk_tier: "R3".to_string(),
                    requires_approval: true,
                    reversible: false,
                });
            }
            VerificationProbeSpec {
                probe_capability_id: "network.diagnose".to_string(),
                probe_arguments: json!({}),
                success_criteria: vec![
                    "stale_proxy_detected == false".into(),
                    "healthy == true".into(),
                ],
            }
        }
        "critical_swap_thrashing" | "high" => {
            let top_pid = evidence
                .get("top_rss_processes")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|p| p.get("pid"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let top_name = evidence
                .get("top_rss_processes")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("high-rss-process");
            if top_pid > 1 {
                proposed_steps.push(RepairStepProposal {
                    step_index: 1,
                    capability_id: "process.terminate".to_string(),
                    suggested_arguments: json!({ "pid": top_pid }),
                    description: format!(
                        "（仅在用户确认无需保留未保存工作后）向高内存占用进程 `{}` (PID {}) 发送 SIGTERM 释放内存",
                        top_name, top_pid
                    ),
                    effect: Effect::ProcessControl,
                    risk_tier: "R3".to_string(),
                    requires_approval: true,
                    reversible: false,
                });
            }
            VerificationProbeSpec {
                probe_capability_id: "system.bottleneck".to_string(),
                probe_arguments: json!({ "limit": 5 }),
                success_criteria: vec!["memory_pressure != 'critical_swap_thrashing'".into()],
            }
        }
        _ if evidence.get("unit").is_some()
            && evidence.get("healthy").and_then(|v| v.as_bool()) == Some(false) =>
        {
            let unit = evidence
                .get("unit")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown.service");
            let user_scope = evidence
                .get("user_scope")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let argv = if user_scope {
                vec!["--user", "restart", unit]
            } else {
                vec!["restart", unit]
            };
            proposed_steps.push(RepairStepProposal {
                step_index: 1,
                capability_id: "terminal.execute".to_string(),
                suggested_arguments: json!({
                    "program": "systemctl",
                    "argv": argv,
                    "purpose": format!("重启异常服务 {}", unit)
                }),
                description: format!("经人工审批后重启异常 systemd 服务 `{}`", unit),
                effect: Effect::SystemAdmin,
                risk_tier: "R3".to_string(),
                requires_approval: true,
                reversible: false,
            });
            VerificationProbeSpec {
                probe_capability_id: "service.status".to_string(),
                probe_arguments: json!({ "unit": unit, "user_scope": user_scope }),
                success_criteria: vec!["active_state == 'active'".into()],
            }
        }
        _ if evidence.get("package").is_some()
            && evidence.get("healthy").and_then(|v| v.as_bool()) == Some(false) =>
        {
            let pkg = evidence
                .get("package")
                .and_then(|v| v.as_str())
                .unwrap_or("package");
            proposed_steps.push(RepairStepProposal {
                step_index: 1,
                capability_id: "terminal.execute".to_string(),
                suggested_arguments: json!({
                    "program": "apt-get",
                    "argv": ["install", "-f", pkg],
                    "network_access": true,
                    "purpose": format!("安装或修复软件包 {}", pkg)
                }),
                description: format!("经人工审批后安装或修复软件包 `{}`（不可自动撤销）", pkg),
                effect: Effect::SystemAdmin,
                risk_tier: "R3".to_string(),
                requires_approval: true,
                reversible: false,
            });
            VerificationProbeSpec {
                probe_capability_id: "package.inspect".to_string(),
                probe_arguments: json!({ "package": pkg }),
                success_criteria: vec![
                    "installed == true".into(),
                    "broken_dependencies is empty".into(),
                ],
            }
        }
        _ => VerificationProbeSpec {
            probe_capability_id: "system.bottleneck".to_string(),
            probe_arguments: json!({}),
            success_criteria: vec!["healthy == true".into()],
        },
    };

    let max_effect = proposed_steps
        .iter()
        .map(|s| s.effect)
        .max()
        .unwrap_or(Effect::Observe);
    let requires_approval = proposed_steps.iter().any(|s| s.requires_approval);
    let reversible = !proposed_steps.is_empty() && proposed_steps.iter().all(|s| s.reversible);
    let diagnosis_summary = if proposed_steps.is_empty() {
        format!("诊断结论 `{}`：当前状态健康或无需破坏性修改", root_cause)
    } else {
        format!(
            "针对根因 `{}` 生成 {} 步待确认修复方案（最高风险={}, 需人工审批={}, 可完全撤销={}）",
            root_cause,
            proposed_steps.len(),
            max_effect.risk_badge(),
            requires_approval,
            reversible
        )
    };

    Ok(RepairPlan {
        diagnosis_summary,
        root_cause,
        evidence_items,
        proposed_steps,
        risk_tier: max_effect.risk_badge().to_string(),
        requires_approval,
        reversible,
        verification_probe: probe,
    })
}

// =============================================================================
// 8. `repair.verify`
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairVerificationOutcome {
    pub probe: String,
    pub repair_succeeded: bool,
    pub checks_passed: Vec<String>,
    pub checks_failed: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_summary: Option<String>,
    pub after_evidence: Value,
    pub summary: String,
}

/// Re-run the live target diagnostic probe and verify whether the fault is genuinely resolved.
pub fn verify_repair(
    config_dir: Option<&Path>,
    fs_engine: &SafeFsEngine,
    args: &Value,
) -> anyhow::Result<RepairVerificationOutcome> {
    let raw_probe = args
        .get("probe")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`repair.verify` 缺少必填参数 `probe`"))?;
    let probe = canonicalize_diag_id(raw_probe);
    let probe_args = args.get("probe_args").cloned().unwrap_or_else(|| json!({}));
    let before_summary = args
        .get("before_evidence")
        .and_then(|b| b.get("summary"))
        .and_then(|v| v.as_str())
        .map(scrub_diag_text);

    let mut checks_passed = Vec::new();
    let mut checks_failed = Vec::new();
    let after_evidence: Value = match probe.as_str() {
        "dependency.inspect" => {
            let rep = inspect_dependency(config_dir, &probe_args)?;
            if rep.exists {
                checks_passed.push("executable_exists".into());
            } else {
                checks_failed.push("executable_missing".into());
            }
            if rep.is_executable {
                checks_passed.push("executable_permission_ok".into());
            } else {
                checks_failed.push("not_executable_permission".into());
            }
            if rep.interpreter_exists {
                checks_passed.push("interpreter_ok".into());
            } else {
                checks_failed.push("shebang_interpreter_missing".into());
            }
            if rep.missing_libraries_sanitized.is_empty() {
                checks_passed.push("all_shared_libraries_resolved_in_clean_env".into());
            } else {
                checks_failed.push(format!(
                    "missing_libraries: {}",
                    rep.missing_libraries_sanitized.join(",")
                ));
            }
            if rep.desktop_issues.is_empty() {
                checks_passed.push("desktop_entry_valid".into());
            } else {
                checks_failed.push(format!("desktop_issues: {}", rep.desktop_issues.join("; ")));
            }
            if rep.conda_or_env_clashes.is_empty() && rep.symbol_or_version_errors.is_empty() {
                checks_passed.push("zero_env_symbol_clashes".into());
            } else if !rep.symbol_or_version_errors.is_empty() {
                checks_failed.push("symbol_or_version_errors_remaining".into());
            }
            scrub_diag_json(serde_json::to_value(&rep)?)
        }
        "service.status" => {
            let rep = inspect_service_status(&probe_args)?;
            if rep.healthy {
                checks_passed.push(format!("service_active_or_clean ({})", rep.active_state));
            } else {
                checks_failed.push(format!(
                    "service_unhealthy: ActiveState={} Result={}",
                    rep.active_state, rep.result
                ));
            }
            scrub_diag_json(serde_json::to_value(&rep)?)
        }
        "package.inspect" => {
            let rep = inspect_package(&probe_args)?;
            if rep.installed {
                checks_passed.push("package_installed".into());
            } else {
                checks_failed.push("package_still_not_installed".into());
            }
            if rep.broken_dependencies.is_empty() {
                checks_passed.push("zero_broken_dependencies".into());
            } else {
                checks_failed.push(format!(
                    "broken_dependencies: {}",
                    rep.broken_dependencies.join("; ")
                ));
            }
            scrub_diag_json(serde_json::to_value(&rep)?)
        }
        "network.diagnose" => {
            let rep = diagnose_network(&probe_args)?;
            if !rep.stale_proxy_detected {
                checks_passed.push("no_stale_local_proxy".into());
            } else {
                checks_failed.push("stale_local_proxy_still_active".into());
            }
            if rep.has_non_loopback_ip {
                checks_passed.push("interface_ip_present".into());
            } else {
                checks_failed.push("no_non_loopback_ip".into());
            }
            if rep.unhealthy_mounts_count == 0 {
                checks_passed.push("cloud_mounts_healthy".into());
            } else {
                checks_failed.push(format!(
                    "unhealthy_mounts_remaining: {}",
                    rep.unhealthy_mounts_count
                ));
            }
            scrub_diag_json(serde_json::to_value(&rep)?)
        }
        "system.bottleneck" => {
            let rep = diagnose_system_bottleneck(&probe_args)?;
            if rep.memory_pressure != "critical_swap_thrashing" {
                checks_passed.push(format!("memory_pressure={}", rep.memory_pressure));
            } else {
                checks_failed.push("critical_swap_thrashing_persists".into());
            }
            scrub_diag_json(serde_json::to_value(&rep)?)
        }
        "process.health" => {
            let _ = fs_engine;
            let pid = probe_args
                .get("pid")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("`process.health` 探针缺少 `pid`"))?
                as u32;
            let expect_running = probe_args
                .get("expect_running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let proc_dir = PathBuf::from(format!("/proc/{}", pid));
            let is_alive = proc_dir.exists();
            if is_alive == expect_running {
                checks_passed.push(format!("pid_{}_alive_matches_{}", pid, expect_running));
            } else {
                checks_failed.push(format!(
                    "pid_{}_alive_is_{}_expected_{}",
                    pid, is_alive, expect_running
                ));
            }
            json!({
                "pid": pid,
                "alive": is_alive,
                "expect_running": expect_running,
            })
        }
        other => anyhow::bail!("不支持的 `repair.verify` 探针类型: {}", other),
    };

    let repair_succeeded = checks_failed.is_empty();
    let summary = if repair_succeeded {
        format!(
            "✓ 修复复检通过 (`{}`)：{} 项真实探针指标全部正常",
            probe,
            checks_passed.len()
        )
    } else {
        format!(
            "✗ 修复复检未通过 (`{}`)：仍有 {} 项异常 ({})",
            probe,
            checks_failed.len(),
            checks_failed.join(", ")
        )
    };

    Ok(RepairVerificationOutcome {
        probe,
        repair_succeeded,
        checks_passed,
        checks_failed,
        before_summary,
        after_evidence,
        summary,
    })
}

// =============================================================================
// Unified `CapabilityBroker` Builtin Handler Dispatcher
// =============================================================================

/// Execute any of the M2-D diagnostic capabilities and return a scrubbed `CapabilityResult`.
pub fn execute_diagnostic_capability(
    core: Option<&IntentOsCore>,
    fs_engine: &SafeFsEngine,
    request_id: &str,
    handler: &str,
    args: &Value,
) -> anyhow::Result<CapabilityResult> {
    let start = Instant::now();
    let canonical = canonicalize_diag_id(handler);
    let cfg_dir = core.map(|c| c.paths.config_dir.as_path());

    let (message, raw_data, checks, method) = match canonical.as_str() {
        "logs.query" => {
            let rep = query_logs(fs_engine, args)?;
            let msg = format!(
                "日志查询完成（来源={}，返回 {} 条，脱敏={}）",
                rep.source, rep.entries_count, rep.secrets_redacted
            );
            (
                msg,
                serde_json::to_value(&rep)?,
                vec!["sensitive_data_guard_applied".into(), rep.source.clone()],
                "logs_query",
            )
        }
        "dependency.inspect" => {
            let rep = inspect_dependency(cfg_dir, args)?;
            (
                rep.summary.clone(),
                serde_json::to_value(&rep)?,
                vec![
                    "dual_env_ldd_probed".into(),
                    format!("root_cause:{}", rep.root_cause),
                ],
                "dependency_inspect",
            )
        }
        "service.status" => {
            let rep = inspect_service_status(args)?;
            (
                rep.summary.clone(),
                serde_json::to_value(&rep)?,
                vec!["systemctl_show_queried".into()],
                "service_status",
            )
        }
        "package.inspect" => {
            let rep = inspect_package(args)?;
            (
                rep.summary.clone(),
                serde_json::to_value(&rep)?,
                vec!["readonly_pkg_db_queried".into()],
                "package_inspect",
            )
        }
        "network.diagnose" => {
            let rep = diagnose_network(args)?;
            (
                rep.summary.clone(),
                serde_json::to_value(&rep)?,
                vec![
                    "iproute2_queried".into(),
                    "resolv_conf_parsed".into(),
                    "proxy_and_mounts_probed".into(),
                ],
                "network_diagnose",
            )
        }
        "system.bottleneck" => {
            let rep = diagnose_system_bottleneck(args)?;
            (
                rep.summary.clone(),
                serde_json::to_value(&rep)?,
                vec![
                    "procfs_readonly_sampled".into(),
                    "zero_mutation_guaranteed".into(),
                ],
                "system_bottleneck",
            )
        }
        "repair.plan" => {
            let plan = build_repair_plan(args)?;
            (
                plan.diagnosis_summary.clone(),
                serde_json::to_value(&plan)?,
                vec!["evidence_driven_plan".into(), "zero_auto_mutation".into()],
                "repair_plan",
            )
        }
        "repair.verify" => {
            let out = verify_repair(cfg_dir, fs_engine, args)?;
            (
                out.summary.clone(),
                serde_json::to_value(&out)?,
                out.checks_passed.clone(),
                "repair_verify",
            )
        }
        other => anyhow::bail!("未知的诊断能力处理器: {}", other),
    };

    let clean_msg = scrub_diag_text(&message);
    let clean_data = scrub_diag_json(raw_data);

    Ok(CapabilityResult {
        request_id: request_id.to_string(),
        capability_id: canonical,
        status: ExecutionStatus::Exited,
        exit_code: Some(0),
        message: clean_msg.clone(),
        data: clean_data,
        stdout_preview: clean_msg,
        stderr_preview: String::new(),
        truncated: false,
        duration_ms: start.elapsed().as_millis() as u64,
        changeset_id: None,
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: method.to_string(),
            checks,
            details: None,
        },
        backend_mode: "linux_diagnostics".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_capability_sdk::{load_descriptors_from_dir, validate_arguments};
    use std::net::TcpListener;
    use tempfile::TempDir;

    fn make_test_fs(tmp: &TempDir) -> (SafeFsEngine, PathBuf) {
        let work = tmp.path().join("workspace");
        let backup = tmp.path().join("backup");
        let trash = tmp.path().join("trash");
        std::fs::create_dir_all(&work).unwrap();
        let fs = SafeFsEngine::new(vec![work.clone()], Vec::new(), backup, trash).unwrap();
        (fs, work)
    }

    #[test]
    fn m2d_seven_yaml_descriptors_load_and_validate_cleanly() {
        let devtools_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/devtools");
        let descs = load_descriptors_from_dir(&devtools_dir).expect("load devtools YAMLs");
        let expected_ids = [
            "logs.query",
            "dependency.inspect",
            "service.status",
            "package.inspect",
            "network.diagnose",
            "repair.plan",
            "repair.verify",
        ];
        for id in expected_ids {
            let d = descs
                .iter()
                .find(|x| x.id == id)
                .unwrap_or_else(|| panic!("missing YAML descriptor `{}`", id));
            assert_eq!(d.max_effect(), Effect::Observe);
            assert!(is_diagnostic_capability(id));
        }

        // Schema validation checks
        let logs_desc = descs.iter().find(|d| d.id == "logs.query").unwrap();
        assert!(validate_arguments(&logs_desc.input_schema, &json!({ "lines": 50 })).is_ok());
        assert!(validate_arguments(&logs_desc.input_schema, &json!({ "lines": 500 })).is_err());
    }

    #[test]
    fn m2d_scenario1_real_proc_system_bottleneck_and_synthetic_swap_zombie_detection() {
        // 1. Live host `/proc` bottleneck inspection (real numbers, strictly read-only)
        let live = diagnose_system_bottleneck(&json!({ "limit": 6 })).expect("live /proc sample");
        assert!(live.mem_total_kb > 0, "real host MemTotal must be > 0");
        assert!(
            live.mem_available_kb > 0,
            "real host MemAvailable must be > 0"
        );
        assert!(live.cpu_cores >= 1);
        assert!(live.read_only_no_mutation);
        assert!(
            !live.top_rss_processes.is_empty(),
            "real host /proc must expose running processes"
        );
        assert!(
            !live.disks.is_empty(),
            "real host df -Pk must return at least root filesystem"
        );

        // 2. Synthetic `/proc` tree proving critical swap thrashing, zombie process, and secret redaction
        let tmp = TempDir::new().unwrap();
        let fake_proc = tmp.path().join("proc");
        std::fs::create_dir_all(fake_proc.join("1001")).unwrap();
        std::fs::create_dir_all(fake_proc.join("1002")).unwrap();
        std::fs::write(
            fake_proc.join("meminfo"),
            "MemTotal:       16000000 kB\nMemFree:          300000 kB\nMemAvailable:     600000 kB\nSwapTotal:       8000000 kB\nSwapFree:        2000000 kB\n",
        )
        .unwrap();
        std::fs::write(
            fake_proc.join("vmstat"),
            "pswpin 8500\npswpout 19200\noom_kill 1\n",
        )
        .unwrap();
        std::fs::write(fake_proc.join("loadavg"), "12.40 8.10 4.50 4/512 2001\n").unwrap();
        std::fs::write(
            fake_proc.join("stat"),
            "cpu  10000 0 2000 50000 8000 0 0 0 0 0\n",
        )
        .unwrap();

        std::fs::write(
            fake_proc.join("1001/status"),
            "Name:\tchrome\nState:\tR (running)\nVmRSS:\t4200000 kB\nVmSwap:\t900000 kB\n",
        )
        .unwrap();
        std::fs::write(
            fake_proc.join("1001/stat"),
            "1001 (chrome) R 1 1001 1001 0 -1 0 0 0 0 0 9500 2100 0 0 20 0 8 0 100 0 0\n",
        )
        .unwrap();
        std::fs::write(
            fake_proc.join("1001/cmdline"),
            b"/opt/google/chrome/chrome\0--type=renderer\0--api-key=sk-SecretRendererKey1234567890\0",
        )
        .unwrap();

        std::fs::write(
            fake_proc.join("1002/status"),
            "Name:\tdefunct-worker\nState:\tZ (zombie)\nVmRSS:\t0 kB\n",
        )
        .unwrap();
        std::fs::write(
            fake_proc.join("1002/stat"),
            "1002 (defunct-worker) Z 1 1002 1002 0 -1 0 0 0 0 0 10 2 0 0 20 0 1 0 200 0 0\n",
        )
        .unwrap();

        let sim = diagnose_system_bottleneck_from_proc(&fake_proc, 5).unwrap();
        assert_eq!(sim.memory_pressure, "critical_swap_thrashing");
        assert_eq!(sim.zombie_count, 1);
        assert_eq!(sim.top_rss_processes[0].pid, 1001);
        assert_eq!(sim.top_rss_processes[0].category, "browser");
        assert!(
            !sim.top_rss_processes[0]
                .cmdline_preview
                .contains("sk-SecretRendererKey1234567890"),
            "SensitiveDataGuard must scrub cmdline API keys: {}",
            sim.top_rss_processes[0].cmdline_preview
        );
    }

    #[test]
    fn m2d_scenario2_real_elf_conda_ld_clash_and_broken_desktop_repair_loop() {
        let tmp = TempDir::new().unwrap();
        let (fs, work) = make_test_fs(&tmp);

        // Part A: Real host ELF binary (`/bin/ls`) with simulated Conda `LD_LIBRARY_PATH` library hijack!
        // Locate `libc.so.6` or `libselinux.so.1` from real `ldd /bin/ls` and create a dummy shadow `.so`
        // inside `<tmp>/miniconda3/lib` to reproduce a real `ldd` Conda library override!
        let ls_bin = resolve_trusted_executable("ls").expect("/bin/ls exists");
        let clean_probe = inspect_dependency(None, &json!({ "target": ls_bin.to_string_lossy() }))
            .expect("inspect /bin/ls");
        assert!(clean_probe.exists && clean_probe.is_executable);
        assert_eq!(clean_probe.binary_kind, "elf");

        // Build a real miniature shared library + ELF binary with `gcc` if available to test BOTH
        // missing `.so` (`=> not found`) AND Conda `LD_LIBRARY_PATH` hijack end-to-end!
        if let Some(gcc_bin) = resolve_trusted_executable("gcc") {
            let conda_lib_dir = tmp.path().join("miniconda3/lib");
            let sys_app_dir = work.join("custom_app");
            std::fs::create_dir_all(&conda_lib_dir).unwrap();
            std::fs::create_dir_all(&sys_app_dir).unwrap();

            let lib_c = sys_app_dir.join("m2dfoo.c");
            std::fs::write(&lib_c, "int m2d_ping(void) { return 42; }\n").unwrap();
            let lib_so = conda_lib_dir.join("libm2dfoo.so");
            let st_so = Command::new(&gcc_bin)
                .args(["-shared", "-fPIC"])
                .arg(&lib_c)
                .arg("-o")
                .arg(&lib_so)
                .status()
                .unwrap();
            assert!(st_so.success());

            let main_c = sys_app_dir.join("main.c");
            std::fs::write(
                &main_c,
                "int m2d_ping(void);\nint main(void) { return m2d_ping() == 42 ? 0 : 1; }\n",
            )
            .unwrap();
            let app_elf = sys_app_dir.join("m2d-demo-bin");
            let st_elf = Command::new(&gcc_bin)
                .arg(&main_c)
                .arg("-L")
                .arg(&conda_lib_dir)
                .arg("-lm2dfoo")
                .arg("-o")
                .arg(&app_elf)
                .status()
                .unwrap();
            assert!(st_elf.success());

            // 1) In clean desktop env, `libm2dfoo.so` is `=> not found`!
            let dep_missing = inspect_dependency(
                None,
                &json!({
                    "target": app_elf.to_string_lossy(),
                    "env_ld_library_path": ""
                }),
            )
            .unwrap();
            assert!(!dep_missing.healthy);
            assert_eq!(dep_missing.root_cause, "missing_shared_library");
            assert!(
                dep_missing
                    .missing_libraries_sanitized
                    .iter()
                    .any(|s| s.contains("libm2dfoo.so"))
            );

            // Plan for missing shared library -> requires_approval == true, reversible == false!
            let plan_missing = build_repair_plan(&json!({
                "evidence": serde_json::to_value(&dep_missing).unwrap()
            }))
            .unwrap();
            assert!(plan_missing.requires_approval);
            assert!(!plan_missing.reversible);
            assert_eq!(
                plan_missing.verification_probe.probe_capability_id,
                "dependency.inspect"
            );

            // 2) Now test Conda `LD_LIBRARY_PATH` override against an ELF with a valid RPATH!
            let sys_lib_dir = sys_app_dir.join("syslib");
            std::fs::create_dir_all(&sys_lib_dir).unwrap();
            std::fs::copy(&lib_so, sys_lib_dir.join("libm2dfoo.so")).unwrap();
            let app_rpath_elf = sys_app_dir.join("m2d-rpath-bin");
            let rpath_flag = format!("-Wl,-rpath,{}", sys_lib_dir.display());
            let st_rpath = Command::new(&gcc_bin)
                .arg(&main_c)
                .arg("-L")
                .arg(&sys_lib_dir)
                .arg("-lm2dfoo")
                .arg(&rpath_flag)
                .arg("-o")
                .arg(&app_rpath_elf)
                .status()
                .unwrap();
            assert!(st_rpath.success());

            let dep_conda = inspect_dependency(
                None,
                &json!({
                    "target": app_rpath_elf.to_string_lossy(),
                    "env_ld_library_path": conda_lib_dir.to_string_lossy()
                }),
            )
            .unwrap();
            assert!(!dep_conda.healthy);
            assert_eq!(dep_conda.root_cause, "conda_ld_library_conflict");
            assert_eq!(dep_conda.conda_or_env_clashes.len(), 1);
            assert!(dep_conda.conda_or_env_clashes[0].is_conda_or_custom_override);

            let plan_conda = build_repair_plan(&json!({
                "evidence": serde_json::to_value(&dep_conda).unwrap()
            }))
            .unwrap();
            assert!(!plan_conda.proposed_steps.is_empty());
            assert_eq!(
                plan_conda.proposed_steps[0].capability_id,
                "app_adapter_invoke"
            );

            // Verify with sanitized env (`env_ld_library_path: ""`) -> `repair_succeeded == true`!
            let verified_conda = verify_repair(
                None,
                &fs,
                &json!({
                    "probe": "dependency.inspect",
                    "probe_args": {
                        "target": app_rpath_elf.to_string_lossy(),
                        "env_ld_library_path": ""
                    },
                    "before_evidence": serde_json::to_value(&dep_conda).unwrap()
                }),
            )
            .unwrap();
            assert!(
                verified_conda.repair_succeeded,
                "verify: {:?}",
                verified_conda
            );
        }

        // Part B: Broken `.desktop` file -> `dependency.inspect` -> `repair.plan` -> fix `.desktop` -> `repair.verify`!
        let dt_path = work.join("research-viewer.desktop");
        std::fs::write(
            &dt_path,
            "[Desktop Entry]\nType=Application\nName=ResearchViewer\nExec=/nonexistent/opt/research-viewer %F\n",
        )
        .unwrap();

        let broken_dt =
            inspect_dependency(None, &json!({ "target": dt_path.to_string_lossy() })).unwrap();
        assert!(!broken_dt.healthy);
        assert_eq!(broken_dt.root_cause, "broken_desktop_entry");

        let dt_plan = build_repair_plan(&json!({
            "evidence": serde_json::to_value(&broken_dt).unwrap()
        }))
        .unwrap();
        assert!(dt_plan.requires_approval);
        assert!(dt_plan.reversible);
        assert_eq!(dt_plan.proposed_steps[0].capability_id, "file.write");

        // Before fixing, `repair.verify` must honestly report `repair_succeeded == false`!
        let verify_before = verify_repair(
            None,
            &fs,
            &json!({
                "probe": "dependency.inspect",
                "probe_args": { "target": dt_path.to_string_lossy() }
            }),
        )
        .unwrap();
        assert!(!verify_before.repair_succeeded);

        // Apply reversible fix to `.desktop` pointing to real `/bin/echo`
        let fixed_body = format!(
            "[Desktop Entry]\nType=Application\nName=ResearchViewer\nExec={} %F\n",
            ls_bin.display()
        );
        let _cs = fs
            .write_file_reversible("task_fix_dt", &dt_path, fixed_body.as_bytes())
            .unwrap();

        // Re-run `repair.verify` -> `repair_succeeded == true`!
        let verify_after = verify_repair(
            None,
            &fs,
            &json!({
                "probe": "dependency.inspect",
                "probe_args": { "target": dt_path.to_string_lossy() },
                "before_evidence": serde_json::to_value(&broken_dt).unwrap()
            }),
        )
        .unwrap();
        assert!(
            verify_after.repair_succeeded,
            "verify_after: {:?}",
            verify_after
        );
    }

    #[test]
    fn m2d_logs_query_redacts_secrets_and_blocks_forbidden_paths() {
        let tmp = TempDir::new().unwrap();
        let (fs, work) = make_test_fs(&tmp);

        let app_log = work.join("daemon.log");
        std::fs::write(
            &app_log,
            "2026-11-15T08:00:01Z INFO boot ok\n\
             2026-11-15T08:00:02Z ERROR upstream auth failed Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n\
             2026-11-15T08:00:03Z WARN openai key=sk-TestCredential1234567890abcdef leaked\n",
        )
        .unwrap();

        let res = execute_diagnostic_capability(
            None,
            &fs,
            "req_log_1",
            "logs.query",
            &json!({
                "log_file": app_log.to_string_lossy(),
                "lines": 2
            }),
        )
        .unwrap();
        assert_eq!(res.status, ExecutionStatus::Exited);
        assert_eq!(res.data["entries_count"], 2);
        assert_eq!(res.data["secrets_redacted"], true);
        let dumped = serde_json::to_string(&res).unwrap();
        assert!(!dumped.contains("sk-TestCredential1234567890abcdef"));
        assert!(!dumped.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(dumped.contains("[REDACTED_SECRET]"));

        // Forbidden path `/etc/shadow` MUST be blocked
        assert!(
            query_logs(&fs, &json!({ "log_file": "/etc/shadow" })).is_err(),
            "/etc/shadow must be rejected"
        );
    }

    #[test]
    fn m2d_scenario5_network_diagnose_service_and_package_inspect_real_host() {
        // Bind a real ephemeral local listener to prove live proxy TCP detection vs dead proxy trap!
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live_port = listener.local_addr().unwrap().port();

        // Pick an unused closed port by binding & immediately dropping
        let dead_port = {
            let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
            l2.local_addr().unwrap().port()
        };

        let net_ok = diagnose_network(&json!({
            "proxy_url": format!("http://user:SuperSecretPass123@127.0.0.1:{}", live_port),
            "proxy_ports": [live_port],
            "timeout_ms": 200
        }))
        .unwrap();
        assert!(!net_ok.interfaces.is_empty());
        assert!(!net_ok.stale_proxy_detected);
        assert!(
            net_ok
                .proxy_probes
                .iter()
                .any(|p| p.endpoint.ends_with(&format!(":{}", live_port)) && p.reachable)
        );
        // Ensure proxy credentials never appear in serialized report
        let net_json = serde_json::to_string(&net_ok).unwrap();
        assert!(!net_json.contains("SuperSecretPass123"));

        // Dead configured proxy must set `stale_proxy_detected == true` and build a repair plan!
        let net_stale = diagnose_network(&json!({
            "proxy_url": format!("http://127.0.0.1:{}", dead_port),
            "timeout_ms": 120
        }))
        .unwrap();
        assert!(net_stale.stale_proxy_detected);
        assert_eq!(net_stale.root_cause, "stale_local_proxy");
        let net_plan = build_repair_plan(&json!({
            "evidence": serde_json::to_value(&net_stale).unwrap()
        }))
        .unwrap();
        assert_eq!(
            net_plan.verification_probe.probe_capability_id,
            "network.diagnose"
        );
        drop(listener);

        // Real host `package.inspect` on `coreutils` vs nonexistent package
        let pkg_ok = inspect_package(&json!({ "package": "coreutils" })).unwrap();
        assert!(pkg_ok.installed);
        assert!(pkg_ok.installed_version.is_some());

        let pkg_missing =
            inspect_package(&json!({ "package": "intentos-nonexistent-pkg-zzz" })).unwrap();
        assert!(!pkg_missing.installed);

        // Real host `service.status`
        let svc = inspect_service_status(&json!({
            "unit": "systemd-journald.service",
            "journal_lines": 3
        }))
        .unwrap();
        assert!(!svc.load_state.is_empty());
    }
}
