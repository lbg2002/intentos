#![forbid(unsafe_code)]

//! Silent Background Document & Media Transformation Driver (`headless_bridge.rs`):
//! - Translates high-level intents (`convert_to_pdf`, `convert_document`, `convert_image`,
//!   `extract_text_preview`, `transcode_media`) into discrete non-shell `Command::new` invocations
//! - Strictly enforces `SafeFsEngine` authorized-directory and forbidden-path boundaries
//! - Records reversible `ChangeSet` (`ChangeOp::Create`) when new output files are produced

use crate::app_adapter::registry::{AdaptationChannel, AppAdapterProfile};
use crate::core::IntentOsCore;
use chrono::{Duration as ChronoDuration, Utc};
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_fsops::SafeFsEngine;
use intentos_protocol::{
    ChangeOp, ChangeSet, ChangeSetStatus, VerificationReport, VerificationState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

const ALLOWED_DOC_FORMATS: &[&str] = &[
    "pdf", "docx", "odt", "html", "txt", "rtf", "xlsx", "csv", "pptx",
];
const ALLOWED_IMAGE_FORMATS: &[&str] = &["png", "jpg", "jpeg", "webp", "bmp", "gif", "tiff", "ico"];
const ALLOWED_MEDIA_FORMATS: &[&str] = &["mp3", "wav", "flac", "ogg", "m4a", "mp4", "webm", "mkv"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessCommandPlan {
    pub action: String,
    pub executable_candidates: Vec<String>,
    pub args: Vec<String>,
    pub input_path: PathBuf,
    pub output_path: Option<PathBuf>,
    pub capture_stdout_preview: bool,
}

impl HeadlessCommandPlan {
    pub fn display_command(&self) -> String {
        let bin = self
            .executable_candidates
            .first()
            .map(String::as_str)
            .unwrap_or("headless-tool");
        format!("{} {}", bin, self.args.join(" "))
    }
}

#[derive(Debug, Clone)]
pub struct HeadlessDispatchResult {
    pub ok: bool,
    pub channel_used: AdaptationChannel,
    pub translated_command: String,
    pub summary: String,
    pub data: Value,
    pub simulated: bool,
    pub verification: VerificationReport,
    pub changeset_id: Option<String>,
}

/// Verify that `path` is absolute, free of `..` traversal, not forbidden, and within `authorized_roots`.
pub fn ensure_authorized_path(fs_engine: &SafeFsEngine, path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("安全拦截：路径必须为绝对路径: {}", path.display());
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            anyhow::bail!(
                "安全拦截：拒绝包含 '..' 父目录逃逸的路径: {}",
                path.display()
            );
        }
    }
    if fs_engine.is_forbidden(path) {
        anyhow::bail!("安全拦截：严禁访问敏感或受保护路径: {}", path.display());
    }
    let in_scope = fs_engine
        .authorized_roots()
        .iter()
        .any(|root| path.starts_with(root));
    if !in_scope {
        anyhow::bail!("安全拦截：路径不在已授权目录范围内: {}", path.display());
    }
    Ok(())
}

/// Construct a deterministic, non-shell `HeadlessCommandPlan` after validating authorized directory boundaries.
pub fn build_headless_plan(
    fs_engine: &SafeFsEngine,
    profile: &AppAdapterProfile,
    canonical_action: &str,
    params: &Value,
) -> anyhow::Result<HeadlessCommandPlan> {
    let raw_input = params
        .get("input")
        .or_else(|| params.get("path"))
        .or_else(|| params.get("source"))
        .or_else(|| params.get("file"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Headless 转换缺少输入文件路径参数 (`path` / `input`)"))?;

    let input_path = PathBuf::from(raw_input.trim());
    ensure_authorized_path(fs_engine, &input_path)?;

    let stem = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("converted");
    let default_outdir = input_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("无法确定输入文件所在父目录: {}", input_path.display()))?
        .to_path_buf();

    match canonical_action {
        "convert_to_pdf" | "convert_document" => {
            let target_fmt = if canonical_action == "convert_to_pdf" {
                "pdf".to_string()
            } else {
                params
                    .get("format")
                    .and_then(|v| v.as_str())
                    .unwrap_or("pdf")
                    .trim()
                    .trim_start_matches('.')
                    .to_ascii_lowercase()
            };
            if !ALLOWED_DOC_FORMATS.contains(&target_fmt.as_str()) {
                anyhow::bail!("不支持的目标文档转换格式: {}", target_fmt);
            }

            let outdir = params
                .get("outdir")
                .or_else(|| params.get("output_dir"))
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or(default_outdir);
            ensure_authorized_path(fs_engine, &outdir)?;

            let out_file = outdir.join(format!("{}.{}", stem, target_fmt));
            ensure_authorized_path(fs_engine, &out_file)?;

            let is_drawio = profile.id == "drawio"
                || input_path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|e| e.eq_ignore_ascii_case("drawio"))
                    .unwrap_or(false);

            if is_drawio && target_fmt == "pdf" {
                Ok(HeadlessCommandPlan {
                    action: canonical_action.to_string(),
                    executable_candidates: vec!["drawio".into()],
                    args: vec![
                        "--export".into(),
                        "--format".into(),
                        "pdf".into(),
                        "--output".into(),
                        out_file.to_string_lossy().to_string(),
                        input_path.to_string_lossy().to_string(),
                    ],
                    input_path,
                    output_path: Some(out_file),
                    capture_stdout_preview: false,
                })
            } else {
                Ok(HeadlessCommandPlan {
                    action: canonical_action.to_string(),
                    executable_candidates: vec!["libreoffice".into(), "soffice".into()],
                    args: vec![
                        "--headless".into(),
                        "--convert-to".into(),
                        target_fmt,
                        "--outdir".into(),
                        outdir.to_string_lossy().to_string(),
                        input_path.to_string_lossy().to_string(),
                    ],
                    input_path,
                    output_path: Some(out_file),
                    capture_stdout_preview: false,
                })
            }
        }
        "convert_image" => {
            let out_file = resolve_target_output_path(
                fs_engine,
                params,
                &default_outdir,
                stem,
                "png",
                ALLOWED_IMAGE_FORMATS,
            )?;

            // Prefer `ffmpeg` discrete invocation; fallback to ImageMagick `convert`
            let prefer_convert = resolve_trusted_executable("ffmpeg").is_none()
                && resolve_trusted_executable("convert").is_some();
            if prefer_convert {
                Ok(HeadlessCommandPlan {
                    action: canonical_action.to_string(),
                    executable_candidates: vec!["convert".into()],
                    args: vec![
                        input_path.to_string_lossy().to_string(),
                        out_file.to_string_lossy().to_string(),
                    ],
                    input_path,
                    output_path: Some(out_file),
                    capture_stdout_preview: false,
                })
            } else {
                Ok(HeadlessCommandPlan {
                    action: canonical_action.to_string(),
                    executable_candidates: vec!["ffmpeg".into(), "convert".into()],
                    args: vec![
                        "-nostdin".into(),
                        "-y".into(),
                        "-i".into(),
                        input_path.to_string_lossy().to_string(),
                        out_file.to_string_lossy().to_string(),
                    ],
                    input_path,
                    output_path: Some(out_file),
                    capture_stdout_preview: false,
                })
            }
        }
        "extract_text_preview" => Ok(HeadlessCommandPlan {
            action: canonical_action.to_string(),
            executable_candidates: vec!["pdftotext".into()],
            args: vec![input_path.to_string_lossy().to_string(), "-".into()],
            input_path,
            output_path: None,
            capture_stdout_preview: true,
        }),
        "transcode_media" => {
            let out_file = resolve_target_output_path(
                fs_engine,
                params,
                &default_outdir,
                stem,
                "mp3",
                ALLOWED_MEDIA_FORMATS,
            )?;
            Ok(HeadlessCommandPlan {
                action: canonical_action.to_string(),
                executable_candidates: vec!["ffmpeg".into()],
                args: vec![
                    "-nostdin".into(),
                    "-y".into(),
                    "-i".into(),
                    input_path.to_string_lossy().to_string(),
                    out_file.to_string_lossy().to_string(),
                ],
                input_path,
                output_path: Some(out_file),
                capture_stdout_preview: false,
            })
        }
        other => anyhow::bail!("不支持的 Headless 后台转换动作: {}", other),
    }
}

fn resolve_target_output_path(
    fs_engine: &SafeFsEngine,
    params: &Value,
    default_outdir: &Path,
    stem: &str,
    default_ext: &str,
    allowed_exts: &[&str],
) -> anyhow::Result<PathBuf> {
    if let Some(explicit_out) = params
        .get("output")
        .or_else(|| params.get("target"))
        .and_then(|v| v.as_str())
    {
        let out_pb = PathBuf::from(explicit_out.trim());
        ensure_authorized_path(fs_engine, &out_pb)?;
        let ext = out_pb
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !allowed_exts.contains(&ext.as_str()) {
            anyhow::bail!("不支持的输出文件扩展名: .{}", ext);
        }
        return Ok(out_pb);
    }

    let fmt = params
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or(default_ext)
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if !allowed_exts.contains(&fmt.as_str()) {
        anyhow::bail!("不支持的目标格式: {}", fmt);
    }
    let outdir = params
        .get("outdir")
        .or_else(|| params.get("output_dir"))
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_outdir.to_path_buf());
    ensure_authorized_path(fs_engine, &outdir)?;
    let out_pb = outdir.join(format!("{}.{}", stem, fmt));
    ensure_authorized_path(fs_engine, &out_pb)?;
    Ok(out_pb)
}

fn compute_file_sha256(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Execute a validated headless transformation plan safely without a shell, recording reversible `ChangeSet`s when applicable.
pub async fn execute_headless_transform(
    core: &IntentOsCore,
    profile: &AppAdapterProfile,
    canonical_action: &str,
    params: &Value,
) -> anyhow::Result<HeadlessDispatchResult> {
    let plan = build_headless_plan(&core.fs_engine, profile, canonical_action, params)?;
    let translated_command = plan.display_command();

    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if force_dry_run {
        return Ok(HeadlessDispatchResult {
            ok: true,
            channel_used: AdaptationChannel::HeadlessCli,
            translated_command,
            summary: format!(
                "已完成「{}」Headless 转换计划构建 `{}`（dry_run 预演）",
                profile.name, plan.action
            ),
            data: json!({
                "plan": plan,
            }),
            simulated: true,
            verification: VerificationReport {
                state: VerificationState::Skipped,
                method: "dry_run_plan".into(),
                checks: vec![
                    "authorized_scope_verified".into(),
                    "non_shell_argv_verified".into(),
                ],
                details: Some("dry_run 预演模式未实际写入磁盘".into()),
            },
            changeset_id: None,
        });
    }

    if !plan.input_path.is_file() {
        return Ok(HeadlessDispatchResult {
            ok: false,
            channel_used: AdaptationChannel::HeadlessCli,
            translated_command,
            summary: format!(
                "Headless 转换源输入文件不存在: {}",
                plan.input_path.display()
            ),
            data: json!({ "input_path": plan.input_path }),
            simulated: false,
            verification: VerificationReport {
                state: VerificationState::VerificationFailed,
                method: "stat_input".into(),
                checks: vec!["authorized_scope_verified".into()],
                details: Some("source file does not exist".into()),
            },
            changeset_id: None,
        });
    }

    // Fast pure-Rust text preview if `extract_text_preview` is invoked on a plain UTF-8 file
    if plan.capture_stdout_preview {
        let ext = plan
            .input_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(
            ext.as_str(),
            "txt" | "md" | "markdown" | "csv" | "json" | "toml" | "yaml" | "yml" | "log"
        ) && let Ok(text) = fs::read_to_string(&plan.input_path)
        {
            let preview: String = text.chars().take(4000).collect();
            return Ok(HeadlessDispatchResult {
                ok: true,
                channel_used: AdaptationChannel::HeadlessCli,
                translated_command,
                summary: format!(
                    "已静默提取文档文本预览（共 {} 字符）: {}",
                    preview.chars().count(),
                    plan.input_path.display()
                ),
                data: json!({
                    "input_path": plan.input_path,
                    "text_preview": preview,
                    "truncated": text.chars().count() > 4000,
                }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::Passed,
                    method: "utf8_direct_preview".into(),
                    checks: vec!["authorized_scope_verified".into(), "read_succeeded".into()],
                    details: None,
                },
                changeset_id: None,
            });
        }
    }

    let resolved_bin = plan
        .executable_candidates
        .iter()
        .find_map(|c| resolve_trusted_executable(c).map(|pb| (c.clone(), pb)));

    let Some((chosen_name, bin_path)) = resolved_bin else {
        if core.app_config.allow_simulated_hardware_fallback {
            return Ok(HeadlessDispatchResult {
                ok: true,
                channel_used: AdaptationChannel::HeadlessCli,
                translated_command,
                summary: format!(
                    "已生成「{}」Headless 后台转换指令 `{}`（当前主机未安装 {:?}，已完成仿真预演）",
                    profile.name, plan.action, plan.executable_candidates
                ),
                data: json!({
                    "plan": plan,
                    "missing_binaries": plan.executable_candidates,
                }),
                simulated: true,
                verification: VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "simulated_missing_headless_binary".into(),
                    checks: vec![
                        "authorized_scope_verified".into(),
                        "non_shell_argv_verified".into(),
                    ],
                    details: Some("本机未安装对应办公/媒体命令行组件，返回安全转译结果".into()),
                },
                changeset_id: None,
            });
        }
        anyhow::bail!(
            "当前系统未安装执行 `{}` 所需的无头工具 ({:?})",
            plan.action,
            plan.executable_candidates
        );
    };

    // Adjust arguments if fallback switched from `ffmpeg` to `convert`
    let effective_args = if chosen_name == "convert" && plan.action == "convert_image" {
        if let Some(ref out_p) = plan.output_path {
            vec![
                plan.input_path.to_string_lossy().to_string(),
                out_p.to_string_lossy().to_string(),
            ]
        } else {
            plan.args.clone()
        }
    } else {
        plan.args.clone()
    };

    let output_existed_before = plan
        .output_path
        .as_ref()
        .map(|p| p.exists())
        .unwrap_or(false);

    let mut cmd = Command::new(&bin_path);
    cmd.args(&effective_args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }

    let child = cmd.spawn()?;
    match tokio::time::timeout(Duration::from_secs(15), child.wait_with_output()).await {
        Ok(Ok(out)) if out.status.success() => {
            if plan.capture_stdout_preview {
                let raw_text = String::from_utf8_lossy(&out.stdout);
                let preview: String = raw_text.chars().take(4000).collect();
                return Ok(HeadlessDispatchResult {
                    ok: true,
                    channel_used: AdaptationChannel::HeadlessCli,
                    translated_command: format!("{} {}", chosen_name, effective_args.join(" ")),
                    summary: format!(
                        "已通过 `{}` 静默提取文档文本预览（{} 字符）",
                        chosen_name,
                        preview.chars().count()
                    ),
                    data: json!({
                        "input_path": plan.input_path,
                        "text_preview": preview,
                        "truncated": raw_text.chars().count() > 4000,
                    }),
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: format!("{}_stdout", chosen_name),
                        checks: vec!["authorized_scope_verified".into(), "exit_code_0".into()],
                        details: None,
                    },
                    changeset_id: None,
                });
            }

            if let Some(ref out_file) = plan.output_path {
                if !out_file.is_file() {
                    return Ok(HeadlessDispatchResult {
                        ok: false,
                        channel_used: AdaptationChannel::HeadlessCli,
                        translated_command: format!("{} {}", chosen_name, effective_args.join(" ")),
                        summary: format!(
                            "`{}` 进程已退出，但未找到预期输出文件: {}",
                            chosen_name,
                            out_file.display()
                        ),
                        data: json!({
                            "expected_output": out_file,
                            "stderr": String::from_utf8_lossy(&out.stderr),
                        }),
                        simulated: false,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "output_file_stat".into(),
                            checks: vec![],
                            details: Some("output file was not created".into()),
                        },
                        changeset_id: None,
                    });
                }

                // Record reversible ChangeSet (`ChangeOp::Create`) when newly created
                let mut changeset_id = None;
                if !output_existed_before && let Ok(post_hash) = compute_file_sha256(out_file) {
                    let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
                    let now = Utc::now();
                    let cs = ChangeSet {
                        id: cs_id.clone(),
                        task_id: format!(
                            "adapter_{}",
                            &uuid::Uuid::new_v4().simple().to_string()[..8]
                        ),
                        created_at: now,
                        capability_id: format!("app_adapter.{}", plan.action),
                        layer: "app_adapter".into(),
                        operations: vec![ChangeOp::Create {
                            path: out_file.to_string_lossy().to_string(),
                            post_hash,
                        }],
                        backup_bytes: 0,
                        status: ChangeSetStatus::Applied,
                        undo_expires_at: now + ChronoDuration::days(30),
                        summary: format!("Headless 生成文件 {}", out_file.display()),
                    };
                    if core.state_db.save_changeset(&cs).is_ok() {
                        changeset_id = Some(cs_id);
                    }
                    let _ = core.resources.index_authorized_files();
                }

                return Ok(HeadlessDispatchResult {
                    ok: true,
                    channel_used: AdaptationChannel::HeadlessCli,
                    translated_command: format!("{} {}", chosen_name, effective_args.join(" ")),
                    summary: format!(
                        "✓ 已通过 `{}` 静默生成转换结果: {}",
                        chosen_name,
                        out_file.display()
                    ),
                    data: json!({
                        "input_path": plan.input_path,
                        "output_path": out_file,
                        "changeset_id": changeset_id,
                    }),
                    simulated: false,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "output_file_sha256".into(),
                        checks: vec![
                            "authorized_scope_verified".into(),
                            "exit_code_0".into(),
                            "output_file_exists".into(),
                        ],
                        details: None,
                    },
                    changeset_id,
                });
            }

            Ok(HeadlessDispatchResult {
                ok: true,
                channel_used: AdaptationChannel::HeadlessCli,
                translated_command: format!("{} {}", chosen_name, effective_args.join(" ")),
                summary: format!("已完成 `{}` 静默处理", chosen_name),
                data: json!({ "input_path": plan.input_path }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::Passed,
                    method: "exit_code_0".into(),
                    checks: vec!["exit_code_0".into()],
                    details: None,
                },
                changeset_id: None,
            })
        }
        Ok(Ok(out)) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Ok(HeadlessDispatchResult {
                ok: false,
                channel_used: AdaptationChannel::HeadlessCli,
                translated_command: format!("{} {}", chosen_name, effective_args.join(" ")),
                summary: format!("Headless 转换 `{}` 执行失败: {}", chosen_name, stderr),
                data: json!({ "stderr": stderr, "exit_code": out.status.code() }),
                simulated: false,
                verification: VerificationReport {
                    state: VerificationState::VerificationFailed,
                    method: "exit_code".into(),
                    checks: vec![],
                    details: Some(stderr),
                },
                changeset_id: None,
            })
        }
        Ok(Err(io_err)) => Err(io_err.into()),
        Err(_) => Ok(HeadlessDispatchResult {
            ok: false,
            channel_used: AdaptationChannel::HeadlessCli,
            translated_command: format!("{} {}", chosen_name, effective_args.join(" ")),
            summary: format!("Headless 转换 `{}` 超时（> 15s）已自动中止", chosen_name),
            data: json!({ "timeout_secs": 15 }),
            simulated: false,
            verification: VerificationReport {
                state: VerificationState::VerificationFailed,
                method: "timeout".into(),
                checks: vec![],
                details: Some("timed out after 15s".into()),
            },
            changeset_id: None,
        }),
    }
}
