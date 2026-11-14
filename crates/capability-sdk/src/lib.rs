#![forbid(unsafe_code)]

//! Capability Descriptor loader, typed schema validator, safe E1 `argv` template executor,
//! dependency prober, and automatic documentation/ToolSpec generator (§7.2, §8.3, §24.6).

use intentos_protocol::{
    CapabilityDescriptor, ExecutionStatus, ToolSpec, VerificationReport, VerificationState,
};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use walkdir::WalkDir;

pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

const TRUSTED_BIN_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin"];

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("descriptor parse error in {path}: {message}")]
    DescriptorParse { path: String, message: String },
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    #[error("trusted executable not found: {0}")]
    ExecutableNotFound(String),
    #[error("placeholder '{0}' missing or invalid in arguments")]
    MissingPlaceholder(String),
    #[error("execution error: {0}")]
    Execution(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct E1ExecOutput {
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub duration_ms: u64,
    pub verification: VerificationReport,
}

/// Load all `.yaml` / `.yml` Capability Descriptors recursively from a directory.
pub fn load_descriptors_from_dir(dir: &Path) -> Result<Vec<CapabilityDescriptor>, SdkError> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in WalkDir::new(dir).follow_links(false) {
        let entry = entry.map_err(|e| SdkError::Execution(e.to_string()))?;
        let path = entry.path();
        if path.is_file() {
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext == "yaml" || ext == "yml" {
                let raw = std::fs::read_to_string(path)?;
                let desc: CapabilityDescriptor =
                    serde_yaml::from_str(&raw).map_err(|e| SdkError::DescriptorParse {
                        path: path.display().to_string(),
                        message: e.to_string(),
                    })?;
                out.push(desc);
            }
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Resolve an executable ID strictly inside trusted system binary directories (§8.3).
pub fn resolve_trusted_executable(executable_id: &str) -> Option<PathBuf> {
    if executable_id.contains('/') || executable_id.contains("..") || executable_id.contains('\0') {
        return None;
    }
    for dir in TRUSTED_BIN_DIRS {
        let candidate = Path::new(dir).join(executable_id);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Validate capability invocation arguments against the descriptor's JSON Schema (§7.2, §19.2).
pub fn validate_arguments(schema: &Value, args: &Value) -> Result<(), SdkError> {
    let obj = args
        .as_object()
        .ok_or_else(|| SdkError::SchemaValidation("arguments must be a JSON object".into()))?;

    // Check required fields
    if let Some(req_arr) = schema.get("required").and_then(|v| v.as_array()) {
        for r in req_arr {
            if let Some(field) = r.as_str()
                && (!obj.contains_key(field) || obj.get(field) == Some(&Value::Null))
            {
                return Err(SdkError::SchemaValidation(format!(
                    "missing required field '{}'",
                    field
                )));
            }
        }
    }

    // Check oneOf (e.g., either `value` or `relative` required)
    if let Some(one_of) = schema.get("oneOf").and_then(|v| v.as_array()) {
        let mut matched = 0usize;
        for branch in one_of {
            if let Some(req_arr) = branch.get("required").and_then(|v| v.as_array()) {
                let ok = req_arr.iter().all(|r| {
                    r.as_str()
                        .map(|f| obj.contains_key(f) && obj.get(f) != Some(&Value::Null))
                        .unwrap_or(false)
                });
                if ok {
                    matched += 1;
                }
            }
        }
        if matched == 0 {
            return Err(SdkError::SchemaValidation(
                "arguments did not satisfy any 'oneOf' requirement".into(),
            ));
        }
    }

    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (k, val) in obj {
            if val.is_null() {
                continue;
            }
            if let Some(prop_schema) = props.get(k) {
                validate_single_value(k, prop_schema, val)?;
            }
        }
    }
    Ok(())
}

fn validate_single_value(name: &str, schema: &Value, val: &Value) -> Result<(), SdkError> {
    if let Some(expected_type) = schema.get("type").and_then(|v| v.as_str()) {
        match expected_type {
            "string" => {
                let s = val.as_str().ok_or_else(|| {
                    SdkError::SchemaValidation(format!("field '{}' must be string", name))
                })?;
                if s.contains('\0') {
                    return Err(SdkError::SchemaValidation(format!(
                        "field '{}' contains NUL byte",
                        name
                    )));
                }
                if let Some(max_len) = schema.get("maxLength").and_then(|v| v.as_u64())
                    && s.len() > max_len as usize
                {
                    return Err(SdkError::SchemaValidation(format!(
                        "field '{}' exceeds maxLength {}",
                        name, max_len
                    )));
                }
                if let Some(enums) = schema.get("enum").and_then(|v| v.as_array()) {
                    let allowed = enums.iter().any(|e| e.as_str() == Some(s));
                    if !allowed {
                        return Err(SdkError::SchemaValidation(format!(
                            "field '{}' value '{}' not in allowed enum",
                            name, s
                        )));
                    }
                }
            }
            "integer" => {
                let n = val.as_i64().ok_or_else(|| {
                    SdkError::SchemaValidation(format!("field '{}' must be integer", name))
                })?;
                if let Some(min) = schema.get("minimum").and_then(|v| v.as_i64())
                    && n < min
                {
                    return Err(SdkError::SchemaValidation(format!(
                        "field '{}'={} below minimum {}",
                        name, n, min
                    )));
                }
                if let Some(max) = schema.get("maximum").and_then(|v| v.as_i64())
                    && n > max
                {
                    return Err(SdkError::SchemaValidation(format!(
                        "field '{}'={} above maximum {}",
                        name, n, max
                    )));
                }
            }
            "number" => {
                let n = val.as_f64().ok_or_else(|| {
                    SdkError::SchemaValidation(format!("field '{}' must be number", name))
                })?;
                if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64())
                    && n < min
                {
                    return Err(SdkError::SchemaValidation(format!(
                        "field '{}'={} below minimum {}",
                        name, n, min
                    )));
                }
                if let Some(max) = schema.get("maximum").and_then(|v| v.as_f64())
                    && n > max
                {
                    return Err(SdkError::SchemaValidation(format!(
                        "field '{}'={} above maximum {}",
                        name, n, max
                    )));
                }
            }
            "boolean" => {
                if !val.is_boolean() {
                    return Err(SdkError::SchemaValidation(format!(
                        "field '{}' must be boolean",
                        name
                    )));
                }
            }
            "array" => {
                let arr = val.as_array().ok_or_else(|| {
                    SdkError::SchemaValidation(format!("field '{}' must be array", name))
                })?;
                if let Some(max_items) = schema.get("maxItems").and_then(|v| v.as_u64())
                    && arr.len() > max_items as usize
                {
                    return Err(SdkError::SchemaValidation(format!(
                        "field '{}' exceeds maxItems {}",
                        name, max_items
                    )));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Render an E1 `argv` template into safe discrete argument strings (NEVER shell-evaluated).
pub fn render_argv_template(template: &[String], args: &Value) -> Result<Vec<String>, SdkError> {
    let re = Regex::new(r"\$\{([a-zA-Z0-9_]+)\}").unwrap();
    let mut rendered = Vec::with_capacity(template.len());
    for item in template {
        let mut out = String::new();
        let mut last = 0usize;
        for cap in re.captures_iter(item) {
            let m = cap.get(0).unwrap();
            let key = &cap[1];
            out.push_str(&item[last..m.start()]);
            let val = args
                .get(key)
                .ok_or_else(|| SdkError::MissingPlaceholder(key.to_string()))?;
            let val_str = match val {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => {
                    return Err(SdkError::MissingPlaceholder(format!(
                        "{} must be scalar",
                        key
                    )));
                }
            };
            if val_str.contains('\0') {
                return Err(SdkError::SchemaValidation(format!(
                    "NUL byte in placeholder '{}'",
                    key
                )));
            }
            out.push_str(&val_str);
            last = m.end();
        }
        out.push_str(&item[last..]);
        rendered.push(out);
    }
    Ok(rendered)
}

/// Execute an E1 `argv_template` with clean environment, timeout, and output size cap (§8.3).
pub async fn execute_argv_template(
    executable_id: &str,
    template: &[String],
    args: &Value,
    timeout_ms: u64,
    extra_env: &BTreeMap<String, String>,
    unverified_launch: bool,
) -> Result<E1ExecOutput, SdkError> {
    let bin_path = resolve_trusted_executable(executable_id)
        .ok_or_else(|| SdkError::ExecutableNotFound(executable_id.to_string()))?;
    let argv = render_argv_template(template, args)?;

    let mut cmd = Command::new(&bin_path);
    cmd.args(&argv)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Pass desktop display env vars only if present for GUI launch capabilities
    for pass_key in [
        "HOME",
        "USER",
        "XDG_RUNTIME_DIR",
        "WAYLAND_DISPLAY",
        "DISPLAY",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        if let Ok(v) = std::env::var(pass_key) {
            cmd.env(pass_key, v);
        }
    }
    cmd.envs(extra_env);

    let start = Instant::now();
    let mut child = cmd.spawn()?;
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();

    let read_future = async {
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let mut out_take = (&mut stdout_pipe).take((MAX_OUTPUT_BYTES + 1) as u64);
        let mut err_take = (&mut stderr_pipe).take((MAX_OUTPUT_BYTES + 1) as u64);
        let _ = tokio::join!(
            out_take.read_to_end(&mut out_buf),
            err_take.read_to_end(&mut err_buf)
        );
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, out_buf, err_buf))
    };

    match tokio::time::timeout(Duration::from_millis(timeout_ms), read_future).await {
        Ok(Ok((exit_status, mut out_buf, mut err_buf))) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let mut truncated = false;
            if out_buf.len() > MAX_OUTPUT_BYTES {
                out_buf.truncate(MAX_OUTPUT_BYTES);
                truncated = true;
            }
            if err_buf.len() > MAX_OUTPUT_BYTES {
                err_buf.truncate(MAX_OUTPUT_BYTES);
                truncated = true;
            }
            let stdout = String::from_utf8_lossy(&out_buf).to_string();
            let stderr = String::from_utf8_lossy(&err_buf).to_string();
            let code = exit_status.code();
            if exit_status.success() {
                let (status, verification) = if unverified_launch {
                    (
                        ExecutionStatus::RequestedUnverified,
                        VerificationReport {
                            state: VerificationState::RequestedUnverified,
                            method: "spawn_exit_0".into(),
                            checks: vec!["launcher_accepted".into()],
                            details: Some("已发出请求（桌面窗口异步打开）".into()),
                        },
                    )
                } else {
                    (
                        ExecutionStatus::Exited,
                        VerificationReport {
                            state: VerificationState::Passed,
                            method: "exit_code_zero".into(),
                            checks: vec!["exit_code == 0".into()],
                            details: None,
                        },
                    )
                };
                Ok(E1ExecOutput {
                    status,
                    exit_code: code,
                    stdout,
                    stderr,
                    truncated,
                    duration_ms,
                    verification,
                })
            } else {
                Ok(E1ExecOutput {
                    status: ExecutionStatus::VerificationFailed,
                    exit_code: code,
                    stdout,
                    stderr: stderr.clone(),
                    truncated,
                    duration_ms,
                    verification: VerificationReport {
                        state: VerificationState::VerificationFailed,
                        method: "exit_code".into(),
                        checks: vec![],
                        details: Some(format!("command exited with {:?}", code)),
                    },
                })
            }
        }
        Ok(Err(io_err)) => Err(SdkError::Io(io_err)),
        Err(_) => {
            let _ = child.kill().await;
            let duration_ms = start.elapsed().as_millis() as u64;
            Ok(E1ExecOutput {
                status: ExecutionStatus::Timeout,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("execution timed out after {} ms", timeout_ms),
                truncated: false,
                duration_ms,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "timeout".into(),
                    checks: vec![],
                    details: Some("timed out".into()),
                },
            })
        }
    }
}

/// Convert a `CapabilityDescriptor` into an LLM `ToolSpec` (§6.5, §7.2).
pub fn descriptor_to_tool_spec(desc: &CapabilityDescriptor) -> ToolSpec {
    ToolSpec {
        name: desc.id.replace('.', "_"),
        description: format!(
            "{} (capability_id: {}, effects: {:?})",
            desc.summary, desc.id, desc.effects
        ),
        parameters: desc.input_schema.clone(),
    }
}

/// Generate Markdown reference documentation from loaded Capability Descriptors (§24.6 DoD).
pub fn generate_markdown_docs(descriptors: &[CapabilityDescriptor]) -> String {
    let mut md = String::from("# IntentOS 内置能力参考手册（自动生成）\n\n");
    md.push_str("| 能力 ID | 类别 | 效应 | 风险标签 | 可撤销 | 摘要 |\n");
    md.push_str("|---|---|---|---|---|---|\n");
    for d in descriptors {
        let effects_str = d
            .effects
            .iter()
            .map(|e| format!("`{}`", e.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let badge = d.max_effect().risk_badge();
        let undoable = if d.undo != intentos_protocol::UndoStrategy::None {
            "✅"
        } else {
            "—"
        };
        md.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            d.id, d.category, effects_str, badge, undoable, d.summary
        ));
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn argv_template_never_evaluates_shell_metacharacters() {
        let tpl = vec!["--query".to_string(), "${q}".to_string()];
        let args = json!({ "q": "foo; rm -rf / && $(whoami)" });
        let rendered = render_argv_template(&tpl, &args).unwrap();
        assert_eq!(rendered, vec!["--query", "foo; rm -rf / && $(whoami)"]);
    }

    #[test]
    fn schema_validator_enforces_bounds_and_oneof() {
        let schema = json!({
            "type": "object",
            "properties": {
                "value": { "type": "number", "minimum": 0.8, "maximum": 2.0 },
                "relative": { "type": "string", "enum": ["up", "down"] }
            },
            "oneOf": [
                { "required": ["value"] },
                { "required": ["relative"] }
            ]
        });
        assert!(validate_arguments(&schema, &json!({"value": 1.25})).is_ok());
        assert!(validate_arguments(&schema, &json!({"relative": "up"})).is_ok());
        assert!(validate_arguments(&schema, &json!({})).is_err());
        assert!(validate_arguments(&schema, &json!({"value": 5.0})).is_err());
        assert!(validate_arguments(&schema, &json!({"relative": "sideways"})).is_err());
    }
}
