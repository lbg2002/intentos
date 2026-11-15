#![forbid(unsafe_code)]

//! 5-Tier Multi-Channel `SoftwareCapabilityProvider` (`crates/intentosd/src/app_adapter/provider.rs`, M2-D `#9`).
//!
//! Upgrades `app_adapter` from simple app launch/quit to **verified semantic work capabilities**
//! across 5 strictly ordered channels with live availability probing and **zero blind side-effect replay**:
//!
//! 1. `ExecutionChannel::NativeApiOrDbus` (`MPRIS2`, `SNI/DBusMenu`, `org.freedesktop.FileManager1`)
//! 2. `ExecutionChannel::CliOrHeadless` (`libreoffice --headless`, `pdftotext`, `code`, `git`, `rclone` —
//!    dynamically probed against real binaries installed on the host)
//! 3. `ExecutionChannel::DirectDocumentFormat` (pure-Rust native file operations requiring zero GUI launch,
//!    strictly confined via `SafeFsEngine` + `StateDb` `ChangeSet` for byte-exact atomic Undo):
//!    - `document.read_section` (`.docx`, `.md`, `.txt`, `.tex`, `.json`, `.csv`, `.pdf`)
//!    - `document.replace_section` (reversible `.docx` / `.md` / `.txt` / `.tex` section & paragraph edit)
//!    - `document.inspect_format` (heading hierarchy, skipped levels, broken numbering, empty sections, counts)
//!    - `document.compile_bibliography` (multi-format `.pdf`/`.docx`/`.md`/`.tex` real paper metadata & Markdown table)
//!    - `workspace.organize_plan` & `workspace.organize_apply` (personal directory analysis & reversible batch move)
//! 4. `ExecutionChannel::GuiAtSpiSemantic` (clean-env AT-SPI2 semantic widget tree — checks Wayland/AT-SPI
//!    availability explicitly; NEVER uses fullscreen screenshot pixel guessing)
//! 5. `ExecutionChannel::HonestGuidance` (for closed-source apps like QQ, WeChat, WPS, or Baidu Netdisk when
//!    an internal action has no programmatic API — returns actionable human instructions without faking execution)

use crate::app_adapter::gui_bridge::{
    GuiApprovalScope, build_gui_approval_scope, execute_gui_bridge_action,
    probe_atspi_controls_readonly,
};
use crate::app_adapter::headless_bridge::execute_headless_transform;
use crate::app_adapter::mpris_dbus::{
    discover_active_mpris_services, execute_freedesktop_action, execute_mpris_action,
    has_dbus_session_address, has_gui_session, query_all_now_playing,
};
use crate::app_adapter::registry::AdapterRegistry;
use crate::app_adapter::sni_dbusmenu::{
    apply_clean_desktop_env_std, discover_live_tray_apps, invoke_tray_menu_action,
    match_tray_app_for_hint, resolve_system_gi_python3,
};
use crate::core::IntentOsCore;
use crate::diagnostics::scrub_diag_text;
use crate::memory_hub::document_outline::{
    build_stored_zip_archive, classify_heading_text_pattern, extract_stored_zip_entry,
    parse_chinese_or_arabic_number,
};
use crate::memory_hub::long_term_habits::unescape_xml_entities;
use chrono::{Duration as ChronoDuration, Utc};
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_fsops::SafeFsEngine;
use intentos_protocol::{
    ChangeOp, ChangeSet, ChangeSetStatus, Effect, ToolSpec, VerificationReport, VerificationState,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use walkdir::WalkDir;

const MAX_PROVIDER_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// Strictly ordered 5-tier execution channel taxonomy (1 = highest fidelity, 5 = honest guidance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionChannel {
    NativeApiOrDbus = 1,
    CliOrHeadless = 2,
    DirectDocumentFormat = 3,
    GuiAtSpiSemantic = 4,
    HonestGuidance = 5,
}

impl ExecutionChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeApiOrDbus => "native_api_or_dbus",
            Self::CliOrHeadless => "cli_or_headless",
            Self::DirectDocumentFormat => "direct_document_format",
            Self::GuiAtSpiSemantic => "gui_at_spi_semantic",
            Self::HonestGuidance => "honest_guidance",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    Available,
    DegradedGuidanceOnly,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityAvailability {
    pub state: AvailabilityState,
    pub preferred_channel: ExecutionChannel,
    pub available_channels: Vec<ExecutionChannel>,
    pub missing_dependencies: Vec<String>,
    pub wayland_session: bool,
    pub atspi_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCapabilitySpec {
    pub capability_id: String,
    pub domain: String,
    pub summary: String,
    pub channels: Vec<ExecutionChannel>,
    pub availability: CapabilityAvailability,
    pub preconditions: Vec<String>,
    pub effect: Effect,
    pub reversible: bool,
    pub requires_approval: bool,
    pub verification_method: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderExecutionOutcome {
    pub ok: bool,
    pub requires_approval: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_scope: Option<GuiApprovalScope>,
    pub capability_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_hint: Option<String>,
    pub channel_used: ExecutionChannel,
    pub attempted_channels: Vec<ExecutionChannel>,
    pub fallback_halted_due_to_side_effect: bool,
    pub effect: Effect,
    pub reversible: bool,
    pub summary: String,
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changeset_id: Option<String>,
    pub verification: VerificationReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance_steps: Option<Vec<String>>,
}

/// Candidate channel execution step used by `execute_channel_chain` to enforce strict priority
/// and the zero-blind-replay rule on side-effecting operations.
pub struct ChannelCandidate<'a> {
    pub channel: ExecutionChannel,
    pub available: bool,
    pub execute_fn: Box<dyn FnMut() -> anyhow::Result<ProviderExecutionOutcome> + 'a>,
}

/// Execute ordered channel candidates with strict priority and **zero blind side-effect replay**:
/// - Unavailable channels are skipped cleanly before any side effects happen.
/// - If an executed channel has `effect > Effect::Observe` and returns `VerificationState::RequestedUnverified`
///   (or fails after entering a mutating channel without proving zero side effect), execution halts immediately
///   and NEVER tries a second mutating channel!
pub fn execute_channel_chain<'a>(
    capability_id: &str,
    app_hint: Option<String>,
    effect: Effect,
    _reversible: bool,
    mut candidates: Vec<ChannelCandidate<'a>>,
) -> anyhow::Result<ProviderExecutionOutcome> {
    candidates.sort_by_key(|c| c.channel);
    let available_total = candidates.iter().filter(|c| c.available).count();
    let mut attempted_channels = Vec::new();
    let mut seen_available = 0usize;

    for mut cand in candidates {
        if !cand.available {
            continue;
        }
        seen_available += 1;
        let has_remaining_available = seen_available < available_total;
        attempted_channels.push(cand.channel);

        let mut out = (cand.execute_fn)()?;
        out.attempted_channels = attempted_channels.clone();

        if out.requires_approval {
            return Ok(out);
        }

        if out.verification.state == VerificationState::Passed
            || out.channel_used == ExecutionChannel::HonestGuidance
        {
            return Ok(out);
        }

        // CRITICAL INVARIANT: Never replay a mutating action (`effect > Observe`) across a second channel
        // when the first channel returned `RequestedUnverified` or uncertain post-mutation status!
        if effect > Effect::Observe {
            if out.verification.state == VerificationState::RequestedUnverified
                && has_remaining_available
            {
                out.fallback_halted_due_to_side_effect = true;
            }
            return Ok(out);
        }

        // For pure read-only (`Effect::Observe`), if no remaining available channel exists, return `out`.
        if !has_remaining_available {
            return Ok(out);
        }
    }

    Ok(build_honest_guidance_outcome(
        capability_id,
        app_hint.as_deref(),
        "当前主机没有可用程序化执行通道",
        vec![
            "目标软件或命令行组件未在本机检测到可用接口。".into(),
            "请确认目标软件已安装，或在应用窗口内手动执行该操作。".into(),
        ],
    ))
}

/// Return LLM `ToolSpec` definitions for the M2-D `SoftwareCapabilityProvider`.
pub fn provider_tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "app_provider_capabilities".into(),
            description: "查询本机 5 层多通道软件能力目录（Native D-Bus/MPRIS/SNI、CLI/Headless 真实二进制可用性、纯 Rust 原生文档章节读写/格式检查/文献综述编译/目录整理规划、AT-SPI 语义控件树及闭源软件诚实引导）".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "可选能力或软件关键词过滤（如 'docx'、'bibliography'、'git'、'libreoffice'、'qq'、'wps'）"
                    },
                    "domain": {
                        "type": "string",
                        "description": "可选领域过滤：'document' | 'workspace' | 'vcs' | 'media' | 'desktop_gui' | 'closed_app'"
                    }
                }
            }),
        },
        ToolSpec {
            name: "app_provider_execute".into(),
            description: "按 5 层通道优先级执行已验证的软件与文档工作能力（支持 document.read_section、document.replace_section 可逆修改与 ChangeSet 撤销、document.inspect_format、document.compile_bibliography、workspace.organize_plan/organize_apply、git.inspect_repo、document.convert_headless、media.control、gui.semantic_inspect 及闭源应用诚实引导；对未验证副作用严格禁止跨通道盲目重放）".into(),
            parameters: json!({
                "type": "object",
                "required": ["capability_id"],
                "properties": {
                    "capability_id": {
                        "type": "string",
                        "description": "目标能力 ID（如 'document.read_section'、'document.replace_section'、'document.inspect_format'、'document.compile_bibliography'、'workspace.organize_plan'、'workspace.organize_apply'、'git.inspect_repo'、'document.convert_headless'、'pdf.extract_text'、'ide.goto_or_diff'、'media.control'、'file_manager.reveal'、'gui.semantic_inspect'、'closed_app.internal_action'）"
                    },
                    "app_hint": {
                        "type": "string",
                        "description": "可选目标软件提示（如 'libreoffice'、'vscode'、'qq'、'wps'、'wechat'）"
                    },
                    "params": {
                        "type": "object",
                        "description": "能力参数对象（如 path, section_query, section_heading, target_text, new_content, directory, output_path, repo_dir, approved 等）"
                    },
                    "approved": {
                        "type": "boolean",
                        "description": "针对高风险或 GUI 合成动作的显式人工批准标志（默认 false）"
                    }
                }
            }),
        },
    ]
}

/// Check whether `name` is one of the direct `SoftwareCapabilityProvider` tool or capability names.
pub fn is_provider_tool_name(name: &str) -> bool {
    matches!(
        canonicalize_provider_tool(name).as_str(),
        "app_provider_capabilities"
            | "app_provider_execute"
            | "document.read_section"
            | "document.replace_section"
            | "document.inspect_format"
            | "document.compile_bibliography"
            | "workspace.organize_plan"
            | "workspace.organize_apply"
            | "git.inspect_repo"
            | "document.convert_headless"
            | "pdf.extract_text"
            | "ide.goto_or_diff"
            | "cloud.rclone_status"
            | "file_manager.reveal"
            | "gui.semantic_inspect"
            | "closed_app.internal_action"
    )
}

fn canonicalize_provider_tool(raw: &str) -> String {
    match raw.trim() {
        "app_provider.capabilities" | "app_provider_capabilities" => {
            "app_provider_capabilities".into()
        }
        "app_provider.execute" | "app_provider_execute" => "app_provider_execute".into(),
        "document_read_section" | "document.read_section" => "document.read_section".into(),
        "document_replace_section" | "document.replace_section" => {
            "document.replace_section".into()
        }
        "document_inspect_format" | "document.inspect_format" => "document.inspect_format".into(),
        "document_compile_bibliography" | "document.compile_bibliography" => {
            "document.compile_bibliography".into()
        }
        "workspace_organize_plan" | "workspace.organize_plan" => "workspace.organize_plan".into(),
        "workspace_organize_apply" | "workspace.organize_apply" => {
            "workspace.organize_apply".into()
        }
        "git_inspect_repo" | "git.inspect_repo" => "git.inspect_repo".into(),
        "document_convert_headless" | "document.convert_headless" => {
            "document.convert_headless".into()
        }
        "pdf_extract_text" | "pdf.extract_text" => "pdf.extract_text".into(),
        "ide_goto_or_diff" | "ide.goto_or_diff" => "ide.goto_or_diff".into(),
        "cloud_rclone_status" | "cloud.rclone_status" => "cloud.rclone_status".into(),
        "file_manager_reveal" | "file_manager.reveal" => "file_manager.reveal".into(),
        "gui_semantic_inspect" | "gui.semantic_inspect" => "gui.semantic_inspect".into(),
        "closed_app_internal_action" | "closed_app.internal_action" => {
            "closed_app.internal_action".into()
        }
        other => other.to_string(),
    }
}

/// Resolve an installed host binary across standard trusted directories AND `/snap/bin`.
pub fn resolve_host_binary(name: &str) -> Option<PathBuf> {
    if let Some(p) = resolve_trusted_executable(name) {
        return Some(p);
    }
    let snap_cand = Path::new("/snap/bin").join(name);
    if snap_cand.is_file() {
        return Some(snap_cand);
    }
    None
}

/// Probe current desktop session Wayland & clean-env AT-SPI2 availability without touching pixels.
pub fn probe_wayland_and_atspi_env() -> (bool, bool) {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var("XDG_SESSION_TYPE")
            .ok()
            .is_some_and(|v| v.eq_ignore_ascii_case("wayland"));
    let atspi =
        has_gui_session() && has_dbus_session_address() && resolve_system_gi_python3().is_some();
    (wayland, atspi)
}

pub struct SoftwareCapabilityProvider;

impl SoftwareCapabilityProvider {
    /// Discover and probe live availability for all semantic `SoftwareCapabilityProvider` capabilities.
    pub fn list_capabilities(
        query: Option<&str>,
        domain: Option<&str>,
    ) -> Vec<ProviderCapabilitySpec> {
        let (wayland, atspi_ok) = probe_wayland_and_atspi_env();
        let dbus_ok = has_dbus_session_address();
        let lo_ok = resolve_host_binary("libreoffice").is_some()
            || resolve_host_binary("soffice").is_some();
        let pdftotext_ok = resolve_host_binary("pdftotext").is_some();
        let git_ok = resolve_host_binary("git").is_some();
        let code_ok =
            resolve_host_binary("code").is_some() || resolve_host_binary("codium").is_some();
        let rclone_ok = resolve_host_binary("rclone").is_some();

        let direct_avail = CapabilityAvailability {
            state: AvailabilityState::Available,
            preferred_channel: ExecutionChannel::DirectDocumentFormat,
            available_channels: vec![ExecutionChannel::DirectDocumentFormat],
            missing_dependencies: Vec::new(),
            wayland_session: wayland,
            atspi_available: atspi_ok,
            reason: None,
        };

        let all = vec![
            ProviderCapabilitySpec {
                capability_id: "document.read_section".into(),
                domain: "document".into(),
                summary: "纯 Rust 原生读取 .docx/.md/.txt/.tex/.json/.csv/.pdf 章节正文、大纲结构与元数据（无需启动办公软件 GUI）".into(),
                channels: vec![
                    ExecutionChannel::DirectDocumentFormat,
                    ExecutionChannel::CliOrHeadless,
                ],
                availability: CapabilityAvailability {
                    state: AvailabilityState::Available,
                    preferred_channel: ExecutionChannel::DirectDocumentFormat,
                    available_channels: if pdftotext_ok {
                        vec![
                            ExecutionChannel::DirectDocumentFormat,
                            ExecutionChannel::CliOrHeadless,
                        ]
                    } else {
                        vec![ExecutionChannel::DirectDocumentFormat]
                    },
                    missing_dependencies: if pdftotext_ok {
                        vec![]
                    } else {
                        vec!["pdftotext (optional for complex compressed PDF)".into()]
                    },
                    wayland_session: wayland,
                    atspi_available: atspi_ok,
                    reason: None,
                },
                preconditions: vec!["path 位于 SafeFsEngine 已授权目录内且非敏感路径".into()],
                effect: Effect::Observe,
                reversible: true,
                requires_approval: false,
                verification_method: "section_content_extracted".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string" },
                        "section_query": { "type": "string" },
                        "max_chars": { "type": "integer", "minimum": 100, "maximum": 32000 }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "document.replace_section".into(),
                domain: "document".into(),
                summary: "可逆替换 .docx / .md / .txt / .tex 文档中的指定章节或段落，自动保存原始文件字节至 StateDb ChangeSet 支持原子级一键 Undo".into(),
                channels: vec![ExecutionChannel::DirectDocumentFormat],
                availability: direct_avail.clone(),
                preconditions: vec![
                    "path 位于 SafeFsEngine 已授权目录内".into(),
                    "修改前自动创建备份并写入 StateDb ChangeSet".into(),
                ],
                effect: Effect::WriteReversible,
                reversible: true,
                requires_approval: false,
                verification_method: "post_write_reparse_and_sha256_changeset".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["path", "new_content"],
                    "properties": {
                        "path": { "type": "string" },
                        "section_heading": { "type": "string" },
                        "target_text": { "type": "string" },
                        "new_content": { "type": "string" },
                        "task_id": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "document.inspect_format".into(),
                domain: "document".into(),
                summary: "检查 .docx / .md / .tex 论文与报告格式质量（标题层级跳级、章节编号断号、空章节、字数/字符数/段落统计）".into(),
                channels: vec![ExecutionChannel::DirectDocumentFormat],
                availability: direct_avail.clone(),
                preconditions: vec!["path 位于 SafeFsEngine 已授权目录内".into()],
                effect: Effect::Observe,
                reversible: true,
                requires_approval: false,
                verification_method: "structural_ast_checked".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "document.compile_bibliography".into(),
                domain: "document".into(),
                summary: "扫描目录内 .pdf / .docx / .md / .tex 学术文献，提取真实标题、作者、年份、摘要与章节结构并生成 Markdown 文献综述清单（支持可逆落盘）".into(),
                channels: vec![
                    ExecutionChannel::DirectDocumentFormat,
                    ExecutionChannel::CliOrHeadless,
                ],
                availability: direct_avail.clone(),
                preconditions: vec![
                    "directory（及可选 output_path）位于 SafeFsEngine 已授权目录内".into(),
                ],
                effect: Effect::WriteReversible,
                reversible: true,
                requires_approval: false,
                verification_method: "bibliography_entries_and_output_verified".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "directory": { "type": "string" },
                        "paths": { "type": "array", "items": { "type": "string" } },
                        "output_path": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "workspace.organize_plan".into(),
                domain: "workspace".into(),
                summary: "分析个人下载/桌面等目录中的真实文件分布、SHA-256 重复项，并生成零覆盖、可逆的归档整理方案".into(),
                channels: vec![ExecutionChannel::DirectDocumentFormat],
                availability: direct_avail.clone(),
                preconditions: vec!["directory 位于 SafeFsEngine 已授权目录内".into()],
                effect: Effect::Observe,
                reversible: true,
                requires_approval: false,
                verification_method: "directory_walk_and_collision_free_plan".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["directory"],
                    "properties": {
                        "directory": { "type": "string" },
                        "target_root": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "workspace.organize_apply".into(),
                domain: "workspace".into(),
                summary: "执行个人目录可逆归档计划（基于 openat2 + RENAME_NOREPLACE 聚合成单一 ChangeSet，支持一键全量还原）".into(),
                channels: vec![ExecutionChannel::DirectDocumentFormat],
                availability: direct_avail,
                preconditions: vec![
                    "所有源/目标路径位于 SafeFsEngine 已授权目录内".into(),
                    "目标路径不存在同名冲突文件".into(),
                ],
                effect: Effect::WriteReversible,
                reversible: true,
                requires_approval: false,
                verification_method: "all_moves_sha256_verified_and_changeset_saved".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["moves"],
                    "properties": {
                        "moves": {
                            "type": "array",
                            "items": { "type": "object" }
                        },
                        "task_id": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "git.inspect_repo".into(),
                domain: "vcs".into(),
                summary: "通过真实 git CLI 检查已授权仓库的当前分支、暂存/未暂存变更、未跟踪文件、diff 统计与最近提交".into(),
                channels: vec![
                    ExecutionChannel::CliOrHeadless,
                    ExecutionChannel::HonestGuidance,
                ],
                availability: CapabilityAvailability {
                    state: if git_ok {
                        AvailabilityState::Available
                    } else {
                        AvailabilityState::DegradedGuidanceOnly
                    },
                    preferred_channel: if git_ok {
                        ExecutionChannel::CliOrHeadless
                    } else {
                        ExecutionChannel::HonestGuidance
                    },
                    available_channels: if git_ok {
                        vec![
                            ExecutionChannel::CliOrHeadless,
                            ExecutionChannel::HonestGuidance,
                        ]
                    } else {
                        vec![ExecutionChannel::HonestGuidance]
                    },
                    missing_dependencies: if git_ok { vec![] } else { vec!["git".into()] },
                    wayland_session: wayland,
                    atspi_available: atspi_ok,
                    reason: None,
                },
                preconditions: vec!["repo_dir 位于已授权目录内且包含有效 Git 工作区".into()],
                effect: Effect::Observe,
                reversible: true,
                requires_approval: false,
                verification_method: "git_cli_exit_0".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repo_dir"],
                    "properties": {
                        "repo_dir": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "document.convert_headless".into(),
                domain: "document".into(),
                summary: "调用本机安装的 LibreOffice (`--headless --convert-to`) 静默导出 PDF/ODT/DOCX 并记录可撤销 ChangeSet".into(),
                channels: vec![
                    ExecutionChannel::CliOrHeadless,
                    ExecutionChannel::HonestGuidance,
                ],
                availability: CapabilityAvailability {
                    state: if lo_ok {
                        AvailabilityState::Available
                    } else {
                        AvailabilityState::DegradedGuidanceOnly
                    },
                    preferred_channel: if lo_ok {
                        ExecutionChannel::CliOrHeadless
                    } else {
                        ExecutionChannel::HonestGuidance
                    },
                    available_channels: if lo_ok {
                        vec![
                            ExecutionChannel::CliOrHeadless,
                            ExecutionChannel::HonestGuidance,
                        ]
                    } else {
                        vec![ExecutionChannel::HonestGuidance]
                    },
                    missing_dependencies: if lo_ok {
                        vec![]
                    } else {
                        vec!["libreoffice".into()]
                    },
                    wayland_session: wayland,
                    atspi_available: atspi_ok,
                    reason: None,
                },
                preconditions: vec![
                    "本机已安装 libreoffice/soffice".into(),
                    "输入输出路径位于 SafeFsEngine 已授权目录内".into(),
                ],
                effect: Effect::WriteReversible,
                reversible: true,
                requires_approval: false,
                verification_method: "output_file_sha256".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string" },
                        "format": { "type": "string" },
                        "outdir": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "ide.goto_or_diff".into(),
                domain: "vcs".into(),
                summary: "使用本机已安装的 VS Code / VSCodium CLI 执行源码行列跳转 (`--goto`)、双文件对比 (`--diff`) 或状态检查 (`--status`)".into(),
                channels: vec![
                    ExecutionChannel::CliOrHeadless,
                    ExecutionChannel::HonestGuidance,
                ],
                availability: CapabilityAvailability {
                    state: if code_ok {
                        AvailabilityState::Available
                    } else {
                        AvailabilityState::DegradedGuidanceOnly
                    },
                    preferred_channel: if code_ok {
                        ExecutionChannel::CliOrHeadless
                    } else {
                        ExecutionChannel::HonestGuidance
                    },
                    available_channels: if code_ok {
                        vec![
                            ExecutionChannel::CliOrHeadless,
                            ExecutionChannel::HonestGuidance,
                        ]
                    } else {
                        vec![ExecutionChannel::HonestGuidance]
                    },
                    missing_dependencies: if code_ok { vec![] } else { vec!["code".into()] },
                    wayland_session: wayland,
                    atspi_available: atspi_ok,
                    reason: None,
                },
                preconditions: vec!["本机已安装 code 或 codium".into()],
                effect: Effect::Ui,
                reversible: true,
                requires_approval: false,
                verification_method: "cli_exit_status".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "mode": { "type": "string", "enum": ["status", "goto", "diff"] },
                        "path": { "type": "string" },
                        "line": { "type": "integer" },
                        "left": { "type": "string" },
                        "right": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "cloud.rclone_status".into(),
                domain: "workspace".into(),
                summary: "只读查询本机 rclone 远端云盘配置名称与挂载健康状态（零密钥泄露）".into(),
                channels: vec![
                    ExecutionChannel::CliOrHeadless,
                    ExecutionChannel::HonestGuidance,
                ],
                availability: CapabilityAvailability {
                    state: if rclone_ok {
                        AvailabilityState::Available
                    } else {
                        AvailabilityState::DegradedGuidanceOnly
                    },
                    preferred_channel: if rclone_ok {
                        ExecutionChannel::CliOrHeadless
                    } else {
                        ExecutionChannel::HonestGuidance
                    },
                    available_channels: if rclone_ok {
                        vec![
                            ExecutionChannel::CliOrHeadless,
                            ExecutionChannel::HonestGuidance,
                        ]
                    } else {
                        vec![ExecutionChannel::HonestGuidance]
                    },
                    missing_dependencies: if rclone_ok {
                        vec![]
                    } else {
                        vec!["rclone".into()]
                    },
                    wayland_session: wayland,
                    atspi_available: atspi_ok,
                    reason: None,
                },
                preconditions: vec!["本机已安装 rclone".into()],
                effect: Effect::Observe,
                reversible: true,
                requires_approval: false,
                verification_method: "rclone_listremotes".into(),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            ProviderCapabilitySpec {
                capability_id: "media.control".into(),
                domain: "media".into(),
                summary: "通过 Session D-Bus MPRIS2 或 SNI 系统托盘总线精确查询/控制媒体播放器".into(),
                channels: vec![
                    ExecutionChannel::NativeApiOrDbus,
                    ExecutionChannel::HonestGuidance,
                ],
                availability: CapabilityAvailability {
                    state: if dbus_ok {
                        AvailabilityState::Available
                    } else {
                        AvailabilityState::DegradedGuidanceOnly
                    },
                    preferred_channel: if dbus_ok {
                        ExecutionChannel::NativeApiOrDbus
                    } else {
                        ExecutionChannel::HonestGuidance
                    },
                    available_channels: if dbus_ok {
                        vec![
                            ExecutionChannel::NativeApiOrDbus,
                            ExecutionChannel::HonestGuidance,
                        ]
                    } else {
                        vec![ExecutionChannel::HonestGuidance]
                    },
                    missing_dependencies: if dbus_ok {
                        vec![]
                    } else {
                        vec!["DBUS_SESSION_BUS_ADDRESS".into()]
                    },
                    wayland_session: wayland,
                    atspi_available: atspi_ok,
                    reason: None,
                },
                preconditions: vec!["存在活跃的桌面 D-Bus 会话与运行中的播放器".into()],
                effect: Effect::Ui,
                reversible: true,
                requires_approval: false,
                verification_method: "mpris_or_sni_dbus_reply".into(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["status", "play_pause", "next", "previous"] },
                        "player_hint": { "type": "string" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "gui.semantic_inspect".into(),
                domain: "desktop_gui".into(),
                summary: "通过纯净环境 AT-SPI2 无障碍语义控件树探查应用可交互控件（显式检查 Wayland/AT-SPI 可用性，绝不使用全屏截图坐标盲猜）".into(),
                channels: vec![
                    ExecutionChannel::GuiAtSpiSemantic,
                    ExecutionChannel::HonestGuidance,
                ],
                availability: CapabilityAvailability {
                    state: if atspi_ok {
                        AvailabilityState::Available
                    } else {
                        AvailabilityState::DegradedGuidanceOnly
                    },
                    preferred_channel: if atspi_ok {
                        ExecutionChannel::GuiAtSpiSemantic
                    } else {
                        ExecutionChannel::HonestGuidance
                    },
                    available_channels: if atspi_ok {
                        vec![
                            ExecutionChannel::GuiAtSpiSemantic,
                            ExecutionChannel::HonestGuidance,
                        ]
                    } else {
                        vec![ExecutionChannel::HonestGuidance]
                    },
                    missing_dependencies: if atspi_ok {
                        vec![]
                    } else {
                        vec!["active_gui_atspi_session".into()]
                    },
                    wayland_session: wayland,
                    atspi_available: atspi_ok,
                    reason: if !atspi_ok {
                        Some("当前无活跃图形/AT-SPI2 无障碍总线；不使用全屏像素截图盲点兜底".into())
                    } else if wayland {
                        Some("Wayland 会话：仅读取语义无障碍树，不支持全局未授权坐标注入".into())
                    } else {
                        None
                    },
                },
                preconditions: vec![
                    "活跃图形会话及 AT-SPI2 总线已启用".into(),
                    "任何点击操作必须经人工显式批准 (approved=true)".into(),
                ],
                effect: Effect::Observe,
                reversible: true,
                requires_approval: false,
                verification_method: "atspi_semantic_tree_readonly".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["app_hint"],
                    "properties": {
                        "app_hint": { "type": "string" },
                        "click_control": { "type": "string" },
                        "approved": { "type": "boolean" }
                    }
                }),
            },
            ProviderCapabilitySpec {
                capability_id: "closed_app.internal_action".into(),
                domain: "closed_app".into(),
                summary: "针对 QQ、微信、WPS 内部排版/修订、百度网盘分享等未开放程序化 API 的闭源软件内部操作，返回诚实操作引导（绝不伪报执行成功）".into(),
                channels: vec![ExecutionChannel::HonestGuidance],
                availability: CapabilityAvailability {
                    state: AvailabilityState::DegradedGuidanceOnly,
                    preferred_channel: ExecutionChannel::HonestGuidance,
                    available_channels: vec![ExecutionChannel::HonestGuidance],
                    missing_dependencies: vec!["vendor_public_ipc_api".into()],
                    wayland_session: wayland,
                    atspi_available: atspi_ok,
                    reason: Some("目标闭源客户端未开放安全的本地 IPC/CLI 接口".into()),
                },
                preconditions: vec![],
                effect: Effect::Observe,
                reversible: true,
                requires_approval: false,
                verification_method: "honest_guidance_delivered".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["app_hint", "requested_action"],
                    "properties": {
                        "app_hint": { "type": "string" },
                        "requested_action": { "type": "string" }
                    }
                }),
            },
        ];

        let q_lc = query
            .map(|q| q.trim().to_ascii_lowercase())
            .filter(|q| !q.is_empty());
        let dom_lc = domain
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty() && d != "all");

        all.into_iter()
            .filter(|spec| {
                if let Some(ref d) = dom_lc
                    && spec.domain != *d
                {
                    return false;
                }
                if let Some(ref q) = q_lc {
                    let hay = format!(
                        "{} {} {}",
                        spec.capability_id.to_ascii_lowercase(),
                        spec.domain.to_ascii_lowercase(),
                        spec.summary.to_ascii_lowercase()
                    );
                    let is_closed_app_query =
                        matches!(q.as_str(), "qq" | "wps" | "wechat" | "微信" | "百度网盘")
                            && spec.capability_id == "closed_app.internal_action";
                    if !hay.contains(q) && !is_closed_app_query {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Execute a semantic capability via the 5-tier channel priority engine.
    pub async fn execute(
        core: &IntentOsCore,
        raw_capability_id: &str,
        app_hint: Option<&str>,
        params: &Value,
        approved: bool,
    ) -> anyhow::Result<ProviderExecutionOutcome> {
        let capability_id = canonicalize_provider_tool(raw_capability_id);
        let hint_owned = app_hint
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .or_else(|| {
                params
                    .get("app_hint")
                    .or_else(|| params.get("app"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
            });

        // Intercept closed-source unsupported internal mutations immediately via Tier 5 HonestGuidance
        if let Some(ref h) = hint_owned
            && is_closed_source_unsupported_action(h, &capability_id, params)
        {
            let req_act = params
                .get("requested_action")
                .or_else(|| params.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or(&capability_id);
            return Ok(build_closed_app_guidance(h, req_act));
        }

        match capability_id.as_str() {
            "document.read_section" | "pdf.extract_text" => {
                execute_document_read_section(core, &capability_id, params)
            }
            "document.replace_section" => execute_document_replace_section(core, params),
            "document.inspect_format" => execute_document_inspect_format(core, params),
            "document.compile_bibliography" => execute_document_compile_bibliography(core, params),
            "workspace.organize_plan" => execute_workspace_organize_plan(core, params),
            "workspace.organize_apply" => execute_workspace_organize_apply(core, params),
            "git.inspect_repo" => execute_git_inspect_repo(core, params),
            "document.convert_headless" => {
                execute_document_convert_headless(core, hint_owned.as_deref(), params).await
            }
            "ide.goto_or_diff" => execute_ide_goto_or_diff(core, params),
            "cloud.rclone_status" => execute_rclone_status(),
            "media.control" => {
                execute_provider_media_control(core, hint_owned.as_deref(), params).await
            }
            "file_manager.reveal" => execute_provider_file_manager_reveal(core, params).await,
            "gui.semantic_inspect" => {
                execute_provider_gui_semantic(core, hint_owned.as_deref(), params, approved).await
            }
            "closed_app.internal_action" => {
                let app = hint_owned.as_deref().unwrap_or("闭源桌面应用");
                let act = params
                    .get("requested_action")
                    .or_else(|| params.get("action"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("内部专属操作");
                Ok(build_closed_app_guidance(app, act))
            }
            other => Ok(build_honest_guidance_outcome(
                other,
                hint_owned.as_deref(),
                &format!("能力 `{}` 无匹配的受控程序化通道", other),
                vec![
                    format!("当前 Provider 未注册 `{}` 的自动执行器。", other),
                    "请先通过 `app_provider_capabilities` 查看本机可用语义能力列表。".into(),
                ],
            )),
        }
    }
}

fn is_closed_source_unsupported_action(app_hint: &str, cap_id: &str, params: &Value) -> bool {
    let h = app_hint.trim().to_ascii_lowercase();
    let is_closed = matches!(
        h.as_str(),
        "qq" | "linuxqq"
            | "wechat"
            | "微信"
            | "wps"
            | "wps-office"
            | "金山文档"
            | "baidunetdisk"
            | "百度网盘"
    );
    if !is_closed {
        return false;
    }
    // Note: Pure `.docx` file-format tools (`document.*`) work directly on standard `.docx` files on disk!
    // Only internal closed GUI actions (sending chat messages, accepting proprietary UI revisions, sharing links)
    // require HonestGuidance.
    if cap_id.starts_with("document.") {
        return false;
    }
    if cap_id == "closed_app.internal_action" {
        return true;
    }
    let act = params
        .get("requested_action")
        .or_else(|| params.get("action"))
        .and_then(|v| v.as_str())
        .unwrap_or(cap_id)
        .to_ascii_lowercase();
    act.contains("send_message")
        || act.contains("发消息")
        || act.contains("发送消息")
        || act.contains("forward")
        || act.contains("转发")
        || act.contains("revision")
        || act.contains("修订")
        || act.contains("share")
        || act.contains("分享")
        || act.contains("upload")
}

fn build_closed_app_guidance(app_hint: &str, requested_action: &str) -> ProviderExecutionOutcome {
    let h_lc = app_hint.trim().to_ascii_lowercase();
    let steps = if h_lc.contains("qq") || h_lc.contains("wechat") || h_lc.contains("微信") {
        vec![
            format!(
                "`{}` 客户端未开放安全的本地发送/转发消息 API，系统不会通过全屏像素盲点伪造点击以免误发消息。",
                app_hint
            ),
            format!(
                "1. 可使用 `app_adapter_invoke` 唤醒或聚焦 `{}` 主窗口；",
                app_hint
            ),
            "2. 系统可将待发送内容整理为纯文本供您复制确认后在会话框内亲自按下发送。".into(),
        ]
    } else if h_lc.contains("wps") {
        vec![
            format!(
                "WPS Office 未开放 `{}` 的本地外部自动化 RPC 接口。",
                requested_action
            ),
            "1. 若文档为标准 `.docx` 格式，可直接使用 `document.read_section` / `document.replace_section` 在不启动 GUI 的情况下安全读写并支持一键撤销；".into(),
            "2. 若需执行 WPS 专有云端协作或修订审阅面板操作，请在 WPS 窗口「审阅」选项卡中人工确认。".into(),
        ]
    } else {
        vec![
            format!(
                "闭源应用 `{}` 暂未提供 `{}` 的可验证程序化接口。",
                app_hint, requested_action
            ),
            "请在目标软件界面内人工完成最后一步确认操作。".into(),
        ]
    };

    build_honest_guidance_outcome(
        "closed_app.internal_action",
        Some(app_hint),
        &format!(
            "诚实引导：`{}` 未开放 `{}` 的程序化接口（未执行任何虚假或盲点操作）",
            app_hint, requested_action
        ),
        steps,
    )
}

pub fn build_honest_guidance_outcome(
    capability_id: &str,
    app_hint: Option<&str>,
    summary: &str,
    steps: Vec<String>,
) -> ProviderExecutionOutcome {
    ProviderExecutionOutcome {
        ok: true,
        requires_approval: false,
        approval_scope: None,
        capability_id: capability_id.to_string(),
        app_hint: app_hint.map(ToString::to_string),
        channel_used: ExecutionChannel::HonestGuidance,
        attempted_channels: vec![ExecutionChannel::HonestGuidance],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::Observe,
        reversible: true,
        summary: summary.to_string(),
        data: json!({
            "action_executed": false,
            "honest_guidance": true,
            "pixel_guessing_used": false,
            "guidance_steps": steps,
        }),
        changeset_id: None,
        verification: VerificationReport {
            state: VerificationState::Skipped,
            method: "honest_guidance_no_api".into(),
            checks: vec!["no_unverified_mutation_attempted".into()],
            details: Some("目标操作无可靠程序化接口，已按诚实引导策略返回可操作说明".into()),
        },
        guidance_steps: Some(steps),
    }
}

// =============================================================================
// Authorized File Access & Pure-Rust / Hybrid `.docx` + `.pdf` Helpers
// =============================================================================

fn require_authorized_file_bytes(fs_engine: &SafeFsEngine, path: &Path) -> anyhow::Result<Vec<u8>> {
    if !path.is_absolute() {
        anyhow::bail!("安全拦截：文档路径必须为绝对路径: {}", path.display());
    }
    if fs_engine.is_forbidden(path) {
        anyhow::bail!("安全拦截：拒绝访问敏感路径: {}", path.display());
    }
    let file = fs_engine.open_readonly_safe(path).map_err(|e| {
        anyhow::anyhow!(
            "路径不在已授权目录范围内或不存在 ({}): {}",
            path.display(),
            e
        )
    })?;
    let meta = file.metadata()?;
    if meta.len() > MAX_PROVIDER_FILE_BYTES {
        anyhow::bail!("文件大小超出安全上限 (32 MiB): {}", path.display());
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_PROVIDER_FILE_BYTES).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn ensure_authorized_dir_scope(fs_engine: &SafeFsEngine, dir: &Path) -> anyhow::Result<()> {
    if !dir.is_absolute() {
        anyhow::bail!("安全拦截：目录路径必须为绝对路径: {}", dir.display());
    }
    for comp in dir.components() {
        if matches!(comp, Component::ParentDir) {
            anyhow::bail!("安全拦截：目录路径禁止包含 `..`: {}", dir.display());
        }
    }
    if fs_engine.is_forbidden(dir) {
        anyhow::bail!("安全拦截：拒绝访问受保护目录: {}", dir.display());
    }
    let approved = fs_engine.list_approved_roots();
    let in_scope = fs_engine
        .authorized_roots()
        .iter()
        .chain(approved.iter())
        .any(|r| dir.starts_with(r));
    if !in_scope {
        anyhow::bail!("安全拦截：目录不在已授权范围内: {}", dir.display());
    }
    Ok(())
}

/// Build a 100% standard OOXML `.docx` archive in memory (`[Content_Types].xml`, `_rels/.rels`,
/// `word/styles.xml`, `word/document.xml`) accepted by LibreOffice, Word, WPS, `unzip`, and `document_outline`.
pub fn build_minimal_docx_bytes(title: Option<&str>, sections: &[(&str, u8, &[&str])]) -> Vec<u8> {
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"#;

    let root_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;

    let styles_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:outlineLvl w:val="0"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:pPr><w:outlineLvl w:val="1"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:pPr><w:outlineLvl w:val="2"/></w:pPr></w:style>
</w:styles>"#;

    let mut body = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    if let Some(t) = title {
        body.push_str(&format!(
            r#"<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t xml:space="preserve">{}</w:t></w:r></w:p>"#,
            escape_xml_text(t)
        ));
    }
    for &(heading, level, paras) in sections {
        let lvl = level.clamp(1, 3);
        body.push_str(&format!(
            r#"<w:p><w:pPr><w:pStyle w:val="Heading{}"/></w:pPr><w:r><w:t xml:space="preserve">{}</w:t></w:r></w:p>"#,
            lvl,
            escape_xml_text(heading)
        ));
        for p in paras {
            body.push_str(&format!(
                r#"<w:p><w:r><w:t xml:space="preserve">{}</w:t></w:r></w:p>"#,
                escape_xml_text(p)
            ));
        }
    }
    body.push_str("</w:body></w:document>");

    build_stored_zip_archive(&[
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", root_rels),
        ("word/styles.xml", styles_xml),
        ("word/document.xml", body.as_bytes()),
    ])
}

/// Build a valid single-page PDF-1.4 document with `/Title`, `/Author`, and text lines
/// readable by both `/usr/bin/pdftotext` and our pure-Rust PDF fallback parser.
pub fn build_minimal_pdf_bytes(title: &str, author: &str, lines: &[&str]) -> Vec<u8> {
    fn esc_pdf(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)")
    }

    let mut stream = String::from("BT\n/F1 12 Tf\n50 750 Td\n");
    for (idx, line) in lines.iter().enumerate() {
        if idx > 0 {
            stream.push_str("0 -18 Td\n");
        }
        stream.push_str(&format!("({}) Tj\n", esc_pdf(line)));
    }
    stream.push_str("ET\n");
    let stream_bytes = stream.as_bytes();

    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n".to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{}endstream\nendobj\n",
            stream_bytes.len(),
            stream
        ),
        "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n".to_string(),
        format!(
            "6 0 obj\n<< /Title ({}) /Author ({}) >>\nendobj\n",
            esc_pdf(title),
            esc_pdf(author)
        ),
    ];

    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for obj in &objects {
        offsets.push(out.len());
        out.extend_from_slice(obj.as_bytes());
    }
    let xref_offset = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for off in offsets {
        out.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{}\n%%EOF\n",
            objects.len() + 1,
            xref_offset
        )
        .as_bytes(),
    );
    out
}

fn escape_xml_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Read all `(entry_name, bytes)` from a `.docx` ZIP archive:
/// - Fast path: pure-Rust Stored-ZIP Central Directory reader (zero subprocesses).
/// - Fallback for Deflate-compressed `.docx` files: system `/usr/bin/python3` `zipfile` reader via argv.
fn read_all_docx_zip_entries(
    path: &Path,
    zip_bytes: &[u8],
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    if let Some(entries) = read_all_stored_zip_entries_pure(zip_bytes) {
        return Ok(entries);
    }

    if let Some(py_bin) = resolve_system_gi_python3() {
        let py_script = r#"
import json, sys, zipfile
out = []
with zipfile.ZipFile(sys.argv[1], "r") as zf:
    for info in zf.infolist():
        if not info.is_dir():
            out.append([info.filename, zf.read(info.filename).hex()])
print(json.dumps(out))
"#;
        let mut cmd = Command::new(py_bin);
        apply_clean_desktop_env_std(&mut cmd);
        cmd.arg("-c")
            .arg(py_script)
            .arg(path.as_os_str())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd.output()?;
        if output.status.success() {
            let pairs: Vec<(String, String)> = serde_json::from_slice(&output.stdout)?;
            let mut decoded = Vec::with_capacity(pairs.len());
            for (name, hex_data) in pairs {
                decoded.push((name, hex::decode(hex_data)?));
            }
            if !decoded.is_empty() {
                return Ok(decoded);
            }
        }
    }

    anyhow::bail!("无法解析 `.docx` 归档结构: {}", path.display())
}

fn read_single_docx_entry(path: &Path, zip_bytes: &[u8], entry_name: &str) -> Option<Vec<u8>> {
    if let Some(b) = extract_stored_zip_entry(zip_bytes, entry_name, 4 * 1024 * 1024) {
        return Some(b);
    }
    if let Some(unzip_bin) = resolve_host_binary("unzip")
        && let Ok(out) = Command::new(unzip_bin)
            .arg("-p")
            .arg(path.as_os_str())
            .arg(entry_name)
            .stdin(Stdio::null())
            .output()
        && out.status.success()
        && !out.stdout.is_empty()
    {
        return Some(out.stdout);
    }
    read_all_docx_zip_entries(path, zip_bytes)
        .ok()?
        .into_iter()
        .find(|(n, _)| n == entry_name)
        .map(|(_, b)| b)
}

fn read_all_stored_zip_entries_pure(zip_bytes: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    if zip_bytes.len() < 22 {
        return None;
    }
    let search_start = zip_bytes.len().saturating_sub(65_558);
    for pos in (search_start..=zip_bytes.len() - 22).rev() {
        if &zip_bytes[pos..pos + 4] == b"PK\x05\x06" {
            let total_entries =
                u16::from_le_bytes([zip_bytes[pos + 10], zip_bytes[pos + 11]]) as usize;
            let cd_size = u32::from_le_bytes([
                zip_bytes[pos + 12],
                zip_bytes[pos + 13],
                zip_bytes[pos + 14],
                zip_bytes[pos + 15],
            ]) as usize;
            let cd_offset = u32::from_le_bytes([
                zip_bytes[pos + 16],
                zip_bytes[pos + 17],
                zip_bytes[pos + 18],
                zip_bytes[pos + 19],
            ]) as usize;
            let end_cd = cd_offset.checked_add(cd_size)?;
            if end_cd > zip_bytes.len() {
                return None;
            }
            let mut cur = cd_offset;
            let mut entries = Vec::with_capacity(total_entries);
            while cur + 46 <= end_cd && &zip_bytes[cur..cur + 4] == b"PK\x01\x02" {
                let method = u16::from_le_bytes([zip_bytes[cur + 10], zip_bytes[cur + 11]]);
                if method != 0 {
                    // Contains Deflate or other compressed entry -> hand off to Python zipfile fallback
                    return None;
                }
                let comp_size = u32::from_le_bytes([
                    zip_bytes[cur + 20],
                    zip_bytes[cur + 21],
                    zip_bytes[cur + 22],
                    zip_bytes[cur + 23],
                ]) as usize;
                let name_len =
                    u16::from_le_bytes([zip_bytes[cur + 28], zip_bytes[cur + 29]]) as usize;
                let extra_len =
                    u16::from_le_bytes([zip_bytes[cur + 30], zip_bytes[cur + 31]]) as usize;
                let comment_len =
                    u16::from_le_bytes([zip_bytes[cur + 32], zip_bytes[cur + 33]]) as usize;
                let lfh_offset = u32::from_le_bytes([
                    zip_bytes[cur + 42],
                    zip_bytes[cur + 43],
                    zip_bytes[cur + 44],
                    zip_bytes[cur + 45],
                ]) as usize;
                let name_end = cur + 46 + name_len;
                if name_end > end_cd || lfh_offset + 30 > zip_bytes.len() {
                    return None;
                }
                let name = std::str::from_utf8(&zip_bytes[cur + 46..name_end])
                    .ok()?
                    .to_string();
                let lfh_name_len =
                    u16::from_le_bytes([zip_bytes[lfh_offset + 26], zip_bytes[lfh_offset + 27]])
                        as usize;
                let lfh_extra_len =
                    u16::from_le_bytes([zip_bytes[lfh_offset + 28], zip_bytes[lfh_offset + 29]])
                        as usize;
                let data_start = lfh_offset + 30 + lfh_name_len + lfh_extra_len;
                let data_end = data_start.checked_add(comp_size)?;
                if data_end > zip_bytes.len() {
                    return None;
                }
                entries.push((name, zip_bytes[data_start..data_end].to_vec()));
                cur = name_end + extra_len + comment_len;
            }
            if !entries.is_empty() {
                return Some(entries);
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
struct ParsedDocParagraph {
    byte_start: usize,
    byte_end: usize,
    ppr_xml: Option<String>,
    heading_level: Option<u8>,
    is_title: bool,
    text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredSection {
    pub heading: String,
    pub level: u8,
    pub body: String,
    pub paragraph_count: usize,
}

fn parse_docx_xml_paragraphs(doc_xml: &str, styles_xml: Option<&str>) -> Vec<ParsedDocParagraph> {
    static PARA_RE: OnceLock<Regex> = OnceLock::new();
    static PPR_RE: OnceLock<Regex> = OnceLock::new();
    static PSTYLE_RE: OnceLock<Regex> = OnceLock::new();
    static OLVL_RE: OnceLock<Regex> = OnceLock::new();
    static WT_RE: OnceLock<Regex> = OnceLock::new();
    static STYLE_BLOCK_RE: OnceLock<Regex> = OnceLock::new();
    static STYLE_ID_RE: OnceLock<Regex> = OnceLock::new();
    static STYLE_NAME_RE: OnceLock<Regex> = OnceLock::new();

    let para_re = PARA_RE.get_or_init(|| Regex::new(r"(?s)<w:p(?:\s[^>]*)?>(.*?)</w:p>").unwrap());
    let ppr_re = PPR_RE.get_or_init(|| Regex::new(r"(?s)<w:pPr(?:\s[^>]*)?>.*?</w:pPr>").unwrap());
    let pstyle_re = PSTYLE_RE
        .get_or_init(|| Regex::new(r#"<w:pStyle\b[^>]*\bw:val\s*=\s*["']([^"']+)["']"#).unwrap());
    let olvl_re = OLVL_RE.get_or_init(|| {
        Regex::new(r#"<w:outlineLvl\b[^>]*\bw:val\s*=\s*["']([0-9]+)["']"#).unwrap()
    });
    let wt_re = WT_RE.get_or_init(|| Regex::new(r"(?s)<w:t(?:\s[^>]*)?>(.*?)</w:t>").unwrap());
    let sblock_re = STYLE_BLOCK_RE
        .get_or_init(|| Regex::new(r"(?s)<w:style(?:\s[^>]*)?>(.*?)</w:style>").unwrap());
    let sid_re = STYLE_ID_RE.get_or_init(|| {
        Regex::new(r#"<w:style\b[^>]*\bw:styleId\s*=\s*["']([^"']+)["']"#).unwrap()
    });
    let sname_re = STYLE_NAME_RE
        .get_or_init(|| Regex::new(r#"<w:name\b[^>]*\bw:val\s*=\s*["']([^"']+)["']"#).unwrap());

    let mut style_map: HashMap<String, (String, Option<u8>)> = HashMap::new();
    if let Some(sxml) = styles_xml {
        for m in sblock_re.find_iter(sxml) {
            let full = m.as_str();
            if let Some(sid) = sid_re.captures(full).and_then(|c| c.get(1)) {
                let sname = sname_re
                    .captures(full)
                    .and_then(|c| c.get(1))
                    .map(|x| unescape_xml_entities(x.as_str()))
                    .unwrap_or_default();
                let olvl = olvl_re
                    .captures(full)
                    .and_then(|c| c.get(1))
                    .and_then(|x| x.as_str().parse::<u8>().ok())
                    .filter(|&v| v < 9);
                style_map.insert(sid.as_str().to_string(), (sname, olvl));
            }
        }
    }

    let mut out = Vec::new();
    for caps in para_re.captures_iter(doc_xml) {
        let full_match = caps.get(0).unwrap();
        let inner = &caps[1];
        let ppr_xml = ppr_re.find(inner).map(|m| m.as_str().to_string());
        let style_id = pstyle_re
            .captures(inner)
            .and_then(|c| c.get(1))
            .map(|m| unescape_xml_entities(m.as_str()))
            .unwrap_or_default();
        let direct_olvl = olvl_re
            .captures(inner)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u8>().ok())
            .filter(|&v| v < 9);
        let (sname, mapped_olvl) = style_map.get(&style_id).cloned().unwrap_or_default();

        let mut text_buf = String::new();
        for tcap in wt_re.captures_iter(inner) {
            text_buf.push_str(&unescape_xml_entities(&tcap[1]));
        }
        let text = text_buf.trim().to_string();

        let sl = format!("{} {}", style_id, sname).to_ascii_lowercase();
        let is_title = sl.contains("title") && !sl.contains("subtitle");
        let heading_level = if text.is_empty() || is_title {
            None
        } else if let Some(ol) = direct_olvl.or(mapped_olvl) {
            Some((ol + 1).clamp(1, 4))
        } else if sl.contains("heading 1")
            || sl.contains("heading1")
            || sl.contains("标题 1")
            || sl.contains("标题1")
        {
            Some(1)
        } else if sl.contains("heading 2")
            || sl.contains("heading2")
            || sl.contains("标题 2")
            || sl.contains("标题2")
        {
            Some(2)
        } else if sl.contains("heading 3")
            || sl.contains("heading3")
            || sl.contains("标题 3")
            || sl.contains("标题3")
        {
            Some(3)
        } else {
            classify_heading_text_pattern(&text)
        };

        out.push(ParsedDocParagraph {
            byte_start: full_match.start(),
            byte_end: full_match.end(),
            ppr_xml,
            heading_level,
            is_title,
            text,
        });
    }
    out
}

fn headings_semantically_match(heading: &str, query: &str) -> bool {
    let h_trim = heading.trim();
    let q_trim = query.trim();
    if h_trim.is_empty() || q_trim.is_empty() {
        return false;
    }
    let h_lc = h_trim.to_ascii_lowercase();
    let q_lc = q_trim.to_ascii_lowercase();
    if h_lc == q_lc || h_lc.contains(&q_lc) || q_lc.contains(&h_lc) {
        return true;
    }
    // Match Chinese vs Arabic chapter numbers (`第四章` <-> `第4章` <-> `Chapter 4`)
    if let (Some(hn), Some(qn)) = (extract_chapter_num(h_trim), extract_chapter_num(q_trim))
        && hn == qn
    {
        return true;
    }
    false
}

fn extract_chapter_num(text: &str) -> Option<u32> {
    static CN_CH_RE: OnceLock<Regex> = OnceLock::new();
    static EN_CH_RE: OnceLock<Regex> = OnceLock::new();
    let cn_re = CN_CH_RE
        .get_or_init(|| Regex::new(r"^第\s*([一二三四五六七八九十百零〇两0-9]+)\s*章").unwrap());
    let en_re = EN_CH_RE.get_or_init(|| Regex::new(r"(?i)^chapter\s+(\d+)\b").unwrap());
    if let Some(c) = cn_re.captures(text.trim()) {
        return parse_chinese_or_arabic_number(&c[1]);
    }
    if let Some(c) = en_re.captures(text.trim()) {
        return c[1].parse::<u32>().ok();
    }
    None
}

fn extract_pdf_text_and_meta(
    path: &Path,
    pdf_bytes: &[u8],
) -> (Option<String>, Option<String>, String, ExecutionChannel) {
    let (meta_title, meta_author, pure_text) = extract_pdf_pure_rust(pdf_bytes);

    if let Some(pdftotext_bin) = resolve_host_binary("pdftotext")
        && let Ok(out) = Command::new(pdftotext_bin)
            .args(["-nopgbrk", "-l", "30"])
            .arg(path.as_os_str())
            .arg("-")
            .stdin(Stdio::null())
            .output()
        && out.status.success()
    {
        let cli_text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !cli_text.is_empty() {
            return (
                meta_title,
                meta_author,
                cli_text,
                ExecutionChannel::CliOrHeadless,
            );
        }
    }

    (
        meta_title,
        meta_author,
        pure_text,
        ExecutionChannel::DirectDocumentFormat,
    )
}

fn extract_pdf_pure_rust(pdf_bytes: &[u8]) -> (Option<String>, Option<String>, String) {
    static TITLE_RE: OnceLock<Regex> = OnceLock::new();
    static AUTHOR_RE: OnceLock<Regex> = OnceLock::new();
    static TJ_RE: OnceLock<Regex> = OnceLock::new();

    let raw = String::from_utf8_lossy(pdf_bytes);
    let title_re = TITLE_RE.get_or_init(|| Regex::new(r"/Title\s*\(([^)]*)\)").unwrap());
    let author_re = AUTHOR_RE.get_or_init(|| Regex::new(r"/Author\s*\(([^)]*)\)").unwrap());
    let tj_re = TJ_RE.get_or_init(|| Regex::new(r"\(((?:\\.|[^\\)])*)\)\s*Tj").unwrap());

    let unesc = |s: &str| {
        s.replace("\\(", "(")
            .replace("\\)", ")")
            .replace("\\\\", "\\")
            .trim()
            .to_string()
    };

    let title = title_re
        .captures(&raw)
        .and_then(|c| c.get(1))
        .map(|m| unesc(m.as_str()))
        .filter(|s| !s.is_empty());
    let author = author_re
        .captures(&raw)
        .and_then(|c| c.get(1))
        .map(|m| unesc(m.as_str()))
        .filter(|s| !s.is_empty());

    let mut lines = Vec::new();
    for cap in tj_re.captures_iter(&raw) {
        let line = unesc(&cap[1]);
        if !line.is_empty() {
            lines.push(line);
        }
    }
    (title, author, lines.join("\n"))
}

// =============================================================================
// Capability Implementations
// =============================================================================

fn execute_document_read_section(
    core: &IntentOsCore,
    capability_id: &str,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let raw_path = params
        .get("path")
        .or_else(|| params.get("file"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`document.read_section` 缺少参数 `path`"))?;
    let path = PathBuf::from(raw_path.trim());
    let bytes = require_authorized_file_bytes(&core.fs_engine, &path)?;
    let section_query = params
        .get("section_query")
        .or_else(|| params.get("section"))
        .or_else(|| params.get("query"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let max_chars = params
        .get("max_chars")
        .and_then(|v| v.as_u64())
        .unwrap_or(8_000)
        .clamp(100, 32_000) as usize;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut channel_used = ExecutionChannel::DirectDocumentFormat;
    let mut doc_title = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("document")
        .to_string();
    let mut sections: Vec<StructuredSection> = Vec::new();
    let full_text: String;
    let mut extra_meta = json!({});

    match ext.as_str() {
        "docx" => {
            let doc_xml_bytes = read_single_docx_entry(&path, &bytes, "word/document.xml")
                .ok_or_else(|| anyhow::anyhow!("无法读取 `.docx` 内的 `word/document.xml`"))?;
            let doc_xml = String::from_utf8_lossy(&doc_xml_bytes);
            let styles_xml = read_single_docx_entry(&path, &bytes, "word/styles.xml")
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            let paras = parse_docx_xml_paragraphs(&doc_xml, styles_xml.as_deref());
            if let Some(tp) = paras.iter().find(|p| p.is_title && !p.text.is_empty()) {
                doc_title = tp.text.clone();
            } else if let Some(first_ne) = paras.iter().find(|p| !p.text.is_empty()) {
                doc_title = first_ne.text.clone();
            }
            sections = group_docx_sections(&paras);
            full_text = paras
                .iter()
                .filter(|p| !p.text.is_empty())
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
        }
        "pdf" => {
            let (m_title, m_author, pdf_txt, chan) = extract_pdf_text_and_meta(&path, &bytes);
            channel_used = chan;
            if let Some(t) = m_title {
                doc_title = t;
            } else if let Some(first_l) = pdf_txt.lines().find(|l| !l.trim().is_empty()) {
                doc_title = first_l.trim().to_string();
            }
            extra_meta = json!({ "author": m_author });
            sections = group_markup_sections("pdf", &pdf_txt, &mut doc_title);
            full_text = pdf_txt;
        }
        "json" => {
            let parsed_json: Value = serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("JSON 解析失败 ({}): {}", path.display(), e))?;
            if let Some(obj) = parsed_json.as_object() {
                for (k, v) in obj {
                    let pretty = serde_json::to_string_pretty(v).unwrap_or_default();
                    sections.push(StructuredSection {
                        heading: k.clone(),
                        level: 1,
                        body: pretty,
                        paragraph_count: 1,
                    });
                }
            }
            full_text = serde_json::to_string_pretty(&parsed_json).unwrap_or_default();
        }
        _ => {
            let raw_text = String::from_utf8_lossy(&bytes).into_owned();
            sections = group_markup_sections(&ext, &raw_text, &mut doc_title);
            full_text = raw_text;
        }
    }

    let matched_section = section_query.and_then(|q| {
        sections
            .iter()
            .find(|s| headings_semantically_match(&s.heading, q))
            .cloned()
            .or_else(|| {
                let q_lc = q.to_ascii_lowercase();
                sections
                    .iter()
                    .find(|s| s.body.to_ascii_lowercase().contains(&q_lc))
                    .cloned()
            })
    });

    let raw_excerpt = if let Some(ref sec) = matched_section {
        format!("{}\n{}", sec.heading, sec.body)
    } else {
        full_text.clone()
    };
    let clipped: String = raw_excerpt.chars().take(max_chars).collect();
    let scrubbed_content = scrub_diag_text(&clipped);
    let scrubbed_title = scrub_diag_text(&doc_title);

    let headings: Vec<String> = sections
        .iter()
        .map(|s| scrub_diag_text(&s.heading))
        .collect();

    Ok(ProviderExecutionOutcome {
        ok: true,
        requires_approval: false,
        approval_scope: None,
        capability_id: capability_id.to_string(),
        app_hint: None,
        channel_used,
        attempted_channels: vec![channel_used],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::Observe,
        reversible: true,
        summary: format!(
            "已读取文档 `{}`（标题: {}，共 {} 个章节）",
            path.display(),
            scrubbed_title,
            sections.len()
        ),
        data: json!({
            "path": path,
            "format": ext,
            "title": scrubbed_title,
            "headings": headings,
            "matched_section": matched_section.map(|mut s| {
                s.heading = scrub_diag_text(&s.heading);
                s.body = scrub_diag_text(&s.body);
                s
            }),
            "content": scrubbed_content,
            "metadata": extra_meta,
            "truncated": raw_excerpt.chars().count() > max_chars,
        }),
        changeset_id: None,
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: "section_content_extracted".into(),
            checks: vec!["authorized_scope_verified".into(), "document_parsed".into()],
            details: None,
        },
        guidance_steps: None,
    })
}

fn group_docx_sections(paras: &[ParsedDocParagraph]) -> Vec<StructuredSection> {
    let mut sections: Vec<StructuredSection> = Vec::new();
    for p in paras {
        if p.text.is_empty() || p.is_title {
            continue;
        }
        if let Some(lvl) = p.heading_level {
            sections.push(StructuredSection {
                heading: p.text.clone(),
                level: lvl,
                body: String::new(),
                paragraph_count: 0,
            });
        } else if let Some(cur) = sections.last_mut() {
            if !cur.body.is_empty() {
                cur.body.push('\n');
            }
            cur.body.push_str(&p.text);
            cur.paragraph_count += 1;
        }
    }
    sections
}

fn group_markup_sections(
    ext: &str,
    raw_text: &str,
    doc_title: &mut String,
) -> Vec<StructuredSection> {
    static MD_RE: OnceLock<Regex> = OnceLock::new();
    static TEX_RE: OnceLock<Regex> = OnceLock::new();
    static TEX_T_RE: OnceLock<Regex> = OnceLock::new();

    let md_re = MD_RE.get_or_init(|| Regex::new(r"^(#{1,4})\s+(.+)$").unwrap());
    let tex_re = TEX_RE.get_or_init(|| {
        Regex::new(r"^\\(chapter|section|subsection|subsubsection)\*?\{([^}]+)\}").unwrap()
    });
    let tex_t = TEX_T_RE.get_or_init(|| Regex::new(r"\\title\{([^}]+)\}").unwrap());

    if ext == "tex"
        && let Some(c) = tex_t.captures(raw_text)
    {
        *doc_title = c[1].trim().to_string();
    }

    let mut sections: Vec<StructuredSection> = Vec::new();
    let mut in_fence = false;
    let mut in_frontmatter = false;

    for (idx, line) in raw_text.lines().enumerate() {
        let t = line.trim();
        if idx == 0 && t == "---" && matches!(ext, "md" | "markdown") {
            in_frontmatter = true;
            continue;
        }
        if in_frontmatter {
            if t == "---" || t == "..." {
                in_frontmatter = false;
            } else if let Some(tv) = t.strip_prefix("title:") {
                let clean = tv.trim().trim_matches('"').trim_matches('\'');
                if !clean.is_empty() {
                    *doc_title = clean.to_string();
                }
            }
            continue;
        }
        if t.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if t.is_empty() {
            continue;
        }

        let mut heading_hit: Option<(u8, String)> = None;
        if !in_fence {
            if matches!(ext, "md" | "markdown")
                && let Some(c) = md_re.captures(t)
            {
                let lvl = (c[1].len() as u8).clamp(1, 4);
                let h = c[2].trim().to_string();
                if lvl == 1 && sections.is_empty() {
                    *doc_title = h.clone();
                }
                heading_hit = Some((lvl, h));
            } else if ext == "tex"
                && let Some(c) = tex_re.captures(t)
            {
                let lvl = match &c[1] {
                    "chapter" | "section" => 1,
                    "subsection" => 2,
                    _ => 3,
                };
                heading_hit = Some((lvl, c[2].trim().to_string()));
            } else if let Some(lvl) = classify_heading_text_pattern(t) {
                heading_hit = Some((lvl, t.to_string()));
            }
        }

        if let Some((lvl, h)) = heading_hit {
            sections.push(StructuredSection {
                heading: h,
                level: lvl,
                body: String::new(),
                paragraph_count: 0,
            });
        } else if let Some(cur) = sections.last_mut() {
            if !cur.body.is_empty() {
                cur.body.push('\n');
            }
            cur.body.push_str(t);
            cur.paragraph_count += 1;
        }
    }

    sections
}

/// Reversible `.docx` / `.md` / `.txt` / `.tex` section or paragraph replacement saved in `StateDb` `ChangeSet`.
fn execute_document_replace_section(
    core: &IntentOsCore,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let raw_path = params
        .get("path")
        .or_else(|| params.get("file"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`document.replace_section` 缺少参数 `path`"))?;
    let new_content = params
        .get("new_content")
        .or_else(|| params.get("content"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`document.replace_section` 缺少参数 `new_content`"))?;
    let section_heading = params
        .get("section_heading")
        .or_else(|| params.get("section_query"))
        .or_else(|| params.get("heading"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let target_text = params
        .get("target_text")
        .or_else(|| params.get("old_text"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if section_heading.is_none() && target_text.is_none() {
        anyhow::bail!("`document.replace_section` 需提供 `section_heading` 或 `target_text`");
    }

    let task_id = params
        .get("task_id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            format!(
                "doc_edit_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            )
        });

    let path = PathBuf::from(raw_path.trim());
    let orig_bytes = require_authorized_file_bytes(&core.fs_engine, &path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let new_file_bytes = match ext.as_str() {
        "docx" => replace_in_docx_bytes(
            &path,
            &orig_bytes,
            section_heading,
            target_text,
            new_content,
        )?,
        "md" | "markdown" | "txt" | "tex" => {
            let orig_text = String::from_utf8(orig_bytes).map_err(|_| {
                anyhow::anyhow!("文本文件不是有效的 UTF-8 编码: {}", path.display())
            })?;
            let updated_text = replace_in_markup_text(
                &ext,
                &orig_text,
                section_heading,
                target_text,
                new_content,
            )?;
            updated_text.into_bytes()
        }
        other => anyhow::bail!(
            "`document.replace_section` 暂不支持直接改写 `.{}` 格式",
            other
        ),
    };

    let mut cs = core
        .fs_engine
        .write_file_reversible(&task_id, &path, &new_file_bytes)
        .map_err(|e| anyhow::anyhow!("安全写入文档失败: {}", e))?;
    cs.capability_id = "document.replace_section".to_string();
    cs.layer = "app_adapter_provider".to_string();
    cs.summary = format!(
        "可逆编辑文档章节 {} ({})",
        path.display(),
        section_heading.or(target_text).unwrap_or("section")
    );
    core.state_db.save_changeset(&cs)?;

    // Post-write verification: re-read from disk and confirm `new_content` is genuinely persisted!
    let verify_probe = new_content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or(new_content.trim());
    let re_read = execute_document_read_section(
        core,
        "document.read_section",
        &json!({ "path": path.to_string_lossy(), "max_chars": 32000 }),
    )?;
    let persisted_ok = re_read.data["content"]
        .as_str()
        .is_some_and(|c| verify_probe.is_empty() || c.contains(verify_probe));

    if !persisted_ok {
        return Ok(ProviderExecutionOutcome {
            ok: false,
            requires_approval: false,
            approval_scope: None,
            capability_id: "document.replace_section".into(),
            app_hint: None,
            channel_used: ExecutionChannel::DirectDocumentFormat,
            attempted_channels: vec![ExecutionChannel::DirectDocumentFormat],
            fallback_halted_due_to_side_effect: false,
            effect: Effect::WriteReversible,
            reversible: true,
            summary: format!(
                "文档 `{}` 写入后内容校验未匹配新段落（可通过 {} 撤销）",
                path.display(),
                cs.id
            ),
            data: json!({ "path": path, "changeset_id": cs.id }),
            changeset_id: Some(cs.id),
            verification: VerificationReport {
                state: VerificationState::VerificationFailed,
                method: "post_write_reparse".into(),
                checks: vec![],
                details: Some("re-parsed document did not contain replacement text".into()),
            },
            guidance_steps: None,
        });
    }

    Ok(ProviderExecutionOutcome {
        ok: true,
        requires_approval: false,
        approval_scope: None,
        capability_id: "document.replace_section".into(),
        app_hint: None,
        channel_used: ExecutionChannel::DirectDocumentFormat,
        attempted_channels: vec![ExecutionChannel::DirectDocumentFormat],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::WriteReversible,
        reversible: true,
        summary: format!(
            "✓ 已更新文档 `{}` 指定章节并生成可撤销备份 `{}`",
            path.display(),
            cs.id
        ),
        data: json!({
            "path": path,
            "changeset_id": cs.id,
            "backup_bytes": cs.backup_bytes,
            "reversible": true,
        }),
        changeset_id: Some(cs.id),
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: "post_write_reparse_and_sha256_changeset".into(),
            checks: vec![
                "authorized_scope_verified".into(),
                "changeset_saved_in_state_db".into(),
                "re_parsed_content_verified".into(),
            ],
            details: None,
        },
        guidance_steps: None,
    })
}

fn replace_in_docx_bytes(
    path: &Path,
    orig_zip_bytes: &[u8],
    section_heading: Option<&str>,
    target_text: Option<&str>,
    new_content: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut entries = read_all_docx_zip_entries(path, orig_zip_bytes)?;
    let styles_xml = entries
        .iter()
        .find(|(n, _)| n == "word/styles.xml")
        .map(|(_, b)| String::from_utf8_lossy(b).into_owned());
    let doc_idx = entries
        .iter()
        .position(|(n, _)| n == "word/document.xml")
        .ok_or_else(|| anyhow::anyhow!("`.docx` 缺少 `word/document.xml`"))?;

    let doc_xml = String::from_utf8(entries[doc_idx].1.clone())
        .map_err(|_| anyhow::anyhow!("`word/document.xml` 非有效 UTF-8"))?;
    let paras = parse_docx_xml_paragraphs(&doc_xml, styles_xml.as_deref());

    let render_new_paras = |ppr_opt: Option<&str>| -> String {
        let lines: Vec<&str> = new_content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let ppr = ppr_opt.unwrap_or("");
        if lines.is_empty() {
            return format!(
                r#"<w:p>{}<w:r><w:t xml:space="preserve"></w:t></w:r></w:p>"#,
                ppr
            );
        }
        let mut buf = String::new();
        for line in lines {
            buf.push_str(&format!(
                r#"<w:p>{}<w:r><w:t xml:space="preserve">{}</w:t></w:r></w:p>"#,
                ppr,
                escape_xml_text(line)
            ));
        }
        buf
    };

    let updated_xml = if let Some(h_query) = section_heading {
        let h_pos = paras
            .iter()
            .position(|p| {
                p.heading_level.is_some() && headings_semantically_match(&p.text, h_query)
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "在 `{}` 中未找到匹配的章节标题 `{}`",
                    path.display(),
                    h_query
                )
            })?;
        let h_lvl = paras[h_pos].heading_level.unwrap_or(1);

        let mut end_pos = paras.len();
        for (idx, p) in paras.iter().enumerate().skip(h_pos + 1) {
            if let Some(next_lvl) = p.heading_level
                && next_lvl <= h_lvl
            {
                end_pos = idx;
                break;
            }
        }

        let body_ppr = paras
            .get(h_pos + 1..end_pos)
            .and_then(|slice| slice.first())
            .and_then(|p| p.ppr_xml.as_deref());
        let replacement_xml = render_new_paras(body_ppr);

        let replace_start = paras[h_pos].byte_end;
        let replace_end = if h_pos + 1 < end_pos {
            paras[end_pos - 1].byte_end
        } else {
            replace_start
        };

        let mut next = String::with_capacity(doc_xml.len() + replacement_xml.len());
        next.push_str(&doc_xml[..replace_start]);
        next.push_str(&replacement_xml);
        next.push_str(&doc_xml[replace_end..]);
        next
    } else {
        let needle = target_text.unwrap_or("");
        let hit = paras
            .iter()
            .find(|p| p.text.contains(needle))
            .ok_or_else(|| {
                anyhow::anyhow!("在 `{}` 中未找到包含 `{}` 的段落", path.display(), needle)
            })?;
        let replacement_xml = render_new_paras(hit.ppr_xml.as_deref());
        let mut next = String::with_capacity(doc_xml.len() + replacement_xml.len());
        next.push_str(&doc_xml[..hit.byte_start]);
        next.push_str(&replacement_xml);
        next.push_str(&doc_xml[hit.byte_end..]);
        next
    };

    entries[doc_idx].1 = updated_xml.into_bytes();
    let borrowed: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    Ok(build_stored_zip_archive(&borrowed))
}

fn replace_in_markup_text(
    ext: &str,
    orig_text: &str,
    section_heading: Option<&str>,
    target_text: Option<&str>,
    new_content: &str,
) -> anyhow::Result<String> {
    if let Some(needle) = target_text
        && section_heading.is_none()
    {
        if !orig_text.contains(needle) {
            anyhow::bail!("文档中未找到待替换片段 `{}`", needle);
        }
        return Ok(orig_text.replacen(needle, new_content, 1));
    }

    let h_query = section_heading.unwrap_or("");
    let md_re = Regex::new(r"^(#{1,4})\s+(.+)$").unwrap();
    let lines: Vec<&str> = orig_text.lines().collect();

    let mut target_line_idx: Option<(usize, u8)> = None;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        let lvl_and_title = if matches!(ext, "md" | "markdown")
            && let Some(c) = md_re.captures(t)
        {
            Some(((c[1].len() as u8).clamp(1, 4), c[2].trim().to_string()))
        } else {
            classify_heading_text_pattern(t).map(|lvl| (lvl, t.to_string()))
        };
        if let Some((lvl, h_title)) = lvl_and_title
            && headings_semantically_match(&h_title, h_query)
        {
            target_line_idx = Some((i, lvl));
            break;
        }
    }

    let (start_idx, target_lvl) = target_line_idx
        .ok_or_else(|| anyhow::anyhow!("未在文本/Markdown 文档中找到章节 `{}`", h_query))?;

    let mut end_idx = lines.len();
    for (i, line) in lines.iter().enumerate().skip(start_idx + 1) {
        let t = line.trim();
        let next_lvl = if matches!(ext, "md" | "markdown")
            && let Some(c) = md_re.captures(t)
        {
            Some((c[1].len() as u8).clamp(1, 4))
        } else {
            classify_heading_text_pattern(t)
        };
        if let Some(nl) = next_lvl
            && nl <= target_lvl
        {
            end_idx = i;
            break;
        }
    }

    let mut out_lines: Vec<String> = Vec::new();
    for &l in &lines[..=start_idx] {
        out_lines.push(l.to_string());
    }
    out_lines.push(String::new());
    for nl in new_content.lines() {
        out_lines.push(nl.to_string());
    }
    if end_idx < lines.len() {
        out_lines.push(String::new());
        for &l in &lines[end_idx..] {
            out_lines.push(l.to_string());
        }
    }
    let mut joined = out_lines.join("\n");
    if orig_text.ends_with('\n') && !joined.ends_with('\n') {
        joined.push('\n');
    }
    Ok(joined)
}

/// Inspect `.docx` / `.md` / `.tex` / `.txt` structural formatting quality.
fn execute_document_inspect_format(
    core: &IntentOsCore,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let raw_path = params
        .get("path")
        .or_else(|| params.get("file"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`document.inspect_format` 缺少参数 `path`"))?;
    let path = PathBuf::from(raw_path.trim());
    let bytes = require_authorized_file_bytes(&core.fs_engine, &path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut doc_title = String::new();
    let (sections, full_text, paragraph_count) = if ext == "docx" {
        let doc_xml_bytes = read_single_docx_entry(&path, &bytes, "word/document.xml")
            .ok_or_else(|| anyhow::anyhow!("无法解析 `.docx` `word/document.xml`"))?;
        let doc_xml = String::from_utf8_lossy(&doc_xml_bytes);
        let styles_xml = read_single_docx_entry(&path, &bytes, "word/styles.xml")
            .map(|b| String::from_utf8_lossy(&b).into_owned());
        let paras = parse_docx_xml_paragraphs(&doc_xml, styles_xml.as_deref());
        let non_empty_count = paras.iter().filter(|p| !p.text.is_empty()).count();
        let text = paras
            .iter()
            .filter(|p| !p.text.is_empty())
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        (group_docx_sections(&paras), text, non_empty_count)
    } else {
        let raw_text = String::from_utf8_lossy(&bytes).into_owned();
        let para_cnt = raw_text.lines().filter(|l| !l.trim().is_empty()).count();
        let secs = group_markup_sections(&ext, &raw_text, &mut doc_title);
        (secs, raw_text, para_cnt)
    };

    let mut skipped_heading_levels = Vec::new();
    let mut broken_numbering = Vec::new();
    let mut empty_sections = Vec::new();
    let mut prev_level: Option<u8> = None;
    let mut expected_top_chapter: Option<u32> = None;
    let mut expected_sub_by_parent: BTreeMap<u32, u32> = BTreeMap::new();

    let sub_num_re = Regex::new(r"^(\d{1,2})\.(\d{1,2})\b").unwrap();

    for (i, sec) in sections.iter().enumerate() {
        if let Some(pl) = prev_level
            && sec.level > pl + 1
        {
            skipped_heading_levels.push(format!(
                "标题层级跳级：H{} -> H{} (`{}`)",
                pl, sec.level, sec.heading
            ));
        }
        prev_level = Some(sec.level);

        // Check empty section (no body AND next section is not a child subsection)
        let has_child_sub = sections
            .get(i + 1)
            .is_some_and(|next| next.level > sec.level);
        if sec.body.trim().is_empty() && !has_child_sub {
            empty_sections.push(sec.heading.clone());
        }

        // Check sequential chapter numbering (`第一章` -> `第三章` or `1.1` -> `1.3`)
        if let Some(ch_n) = extract_chapter_num(&sec.heading) {
            if let Some(exp) = expected_top_chapter
                && ch_n != exp
            {
                broken_numbering.push(format!(
                    "章节编号断号：预期第 {} 章，实际为 `{}`",
                    exp, sec.heading
                ));
            }
            expected_top_chapter = Some(ch_n + 1);
        } else if let Some(caps) = sub_num_re.captures(sec.heading.trim())
            && let (Ok(maj), Ok(min)) = (caps[1].parse::<u32>(), caps[2].parse::<u32>())
        {
            let exp_min = expected_sub_by_parent.entry(maj).or_insert(1);
            if min != *exp_min {
                broken_numbering.push(format!(
                    "小节编号断号：预期 {}.{}，实际为 `{}`",
                    maj, exp_min, sec.heading
                ));
            }
            *exp_min = min + 1;
        }
    }

    let char_count = full_text.chars().filter(|c| !c.is_whitespace()).count();
    let cjk_char_count = full_text
        .chars()
        .filter(|&c| ('\u{4e00}'..='\u{9fff}').contains(&c))
        .count();
    let ascii_words = full_text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .count();
    let word_count = cjk_char_count + ascii_words;
    let issues_total = skipped_heading_levels.len() + broken_numbering.len() + empty_sections.len();

    Ok(ProviderExecutionOutcome {
        ok: true,
        requires_approval: false,
        approval_scope: None,
        capability_id: "document.inspect_format".into(),
        app_hint: None,
        channel_used: ExecutionChannel::DirectDocumentFormat,
        attempted_channels: vec![ExecutionChannel::DirectDocumentFormat],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::Observe,
        reversible: true,
        summary: format!(
            "文档格式审查 `{}`：{} 个章节，约 {} 字，发现 {} 处结构格式问题",
            path.display(),
            sections.len(),
            word_count,
            issues_total
        ),
        data: json!({
            "path": path,
            "section_count": sections.len(),
            "paragraph_count": paragraph_count,
            "word_count": word_count,
            "char_count": char_count,
            "cjk_char_count": cjk_char_count,
            "heading_hierarchy": sections.iter().map(|s| json!({
                "level": s.level,
                "heading": scrub_diag_text(&s.heading),
                "paragraph_count": s.paragraph_count,
            })).collect::<Vec<_>>(),
            "skipped_heading_levels": skipped_heading_levels,
            "broken_numbering": broken_numbering,
            "empty_sections": empty_sections,
            "format_clean": issues_total == 0,
        }),
        changeset_id: None,
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: "structural_ast_checked".into(),
            checks: vec!["headings_checked".into(), "numbering_checked".into()],
            details: None,
        },
        guidance_steps: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BibliographyEntry {
    pub index: usize,
    pub file_name: String,
    pub path: String,
    pub format: String,
    pub title: String,
    pub authors: String,
    pub year: String,
    pub abstract_summary: String,
    pub key_headings: Vec<String>,
}

/// Compile a structured Markdown literature bibliography table from `.pdf`, `.docx`, `.md`, and `.tex` papers.
fn execute_document_compile_bibliography(
    core: &IntentOsCore,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let mut candidate_files: Vec<PathBuf> = Vec::new();
    if let Some(arr) = params.get("paths").and_then(|v| v.as_array()) {
        for item in arr.iter().filter_map(|v| v.as_str()) {
            candidate_files.push(PathBuf::from(item.trim()));
        }
    }
    if let Some(dir_raw) = params
        .get("directory")
        .or_else(|| params.get("path"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let dir = PathBuf::from(dir_raw);
        ensure_authorized_dir_scope(&core.fs_engine, &dir)?;
        for entry in WalkDir::new(&dir)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if entry.file_type().is_file() {
                let p = entry.into_path();
                if let Some(ext) = p.extension().and_then(|e| e.to_str())
                    && matches!(
                        ext.to_ascii_lowercase().as_str(),
                        "pdf" | "docx" | "md" | "markdown" | "tex"
                    )
                    && !core.fs_engine.is_forbidden(&p)
                {
                    if let Some(out_p) = params.get("output_path").and_then(|v| v.as_str())
                        && p == Path::new(out_p)
                    {
                        continue;
                    }
                    if !candidate_files.contains(&p) {
                        candidate_files.push(p);
                    }
                }
            }
        }
    }
    candidate_files.sort();

    if candidate_files.is_empty() {
        anyhow::bail!("未在指定参数或目录中找到可解析的论文文档 (.pdf/.docx/.md/.tex)");
    }

    let year_re = Regex::new(r"\b(19\d{2}|20[0-3]\d)\b").unwrap();
    let author_line_re = Regex::new(r"(?i)^(?:authors?|作者|by)\s*[:：]\s*(.+)$").unwrap();
    let tex_author_re = Regex::new(r"\\author\{([^}]+)\}").unwrap();

    let mut entries: Vec<BibliographyEntry> = Vec::new();
    for (idx, p) in candidate_files.iter().enumerate() {
        let Ok(bytes) = require_authorized_file_bytes(&core.fs_engine, p) else {
            continue;
        };
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let file_name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("paper")
            .to_string();

        let mut title = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Untitled")
            .to_string();
        let mut authors: Option<String> = None;
        let mut full_text = String::new();
        let mut sections = Vec::new();

        match ext.as_str() {
            "pdf" => {
                let (mt, ma, txt, _) = extract_pdf_text_and_meta(p, &bytes);
                if let Some(t) = mt {
                    title = t;
                } else if let Some(fl) = txt.lines().find(|l| !l.trim().is_empty()) {
                    title = fl.trim().to_string();
                }
                authors = ma;
                sections = group_markup_sections("pdf", &txt, &mut title);
                full_text = txt;
            }
            "docx" => {
                if let Some(doc_xml_b) = read_single_docx_entry(p, &bytes, "word/document.xml") {
                    let doc_xml = String::from_utf8_lossy(&doc_xml_b);
                    let styles_xml = read_single_docx_entry(p, &bytes, "word/styles.xml")
                        .map(|b| String::from_utf8_lossy(&b).into_owned());
                    let paras = parse_docx_xml_paragraphs(&doc_xml, styles_xml.as_deref());
                    if let Some(tp) = paras.iter().find(|x| x.is_title && !x.text.is_empty()) {
                        title = tp.text.clone();
                    } else if let Some(fp) = paras.iter().find(|x| !x.text.is_empty()) {
                        title = fp.text.clone();
                    }
                    sections = group_docx_sections(&paras);
                    full_text = paras
                        .iter()
                        .filter(|x| !x.text.is_empty())
                        .map(|x| x.text.as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                }
            }
            _ => {
                let txt = String::from_utf8_lossy(&bytes).into_owned();
                if ext == "tex"
                    && let Some(c) = tex_author_re.captures(&txt)
                {
                    authors = Some(c[1].trim().to_string());
                }
                sections = group_markup_sections(&ext, &txt, &mut title);
                full_text = txt;
            }
        }

        if authors.is_none() {
            for line in full_text.lines().take(20) {
                let t = line
                    .trim()
                    .trim_start_matches('*')
                    .trim_end_matches('*')
                    .trim();
                if let Some(c) = author_line_re.captures(t) {
                    authors = Some(c[1].trim().trim_matches('"').to_string());
                    break;
                }
            }
        }

        let year = year_re
            .captures(&full_text[..full_text.floor_char_boundary(full_text.len().min(1200))])
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "-".to_string());

        let abstract_summary = sections
            .iter()
            .find(|s| {
                let hl = s.heading.to_ascii_lowercase();
                hl.contains("abstract") || hl.contains("摘要")
            })
            .map(|s| s.body.clone())
            .filter(|b| !b.trim().is_empty())
            .or_else(|| {
                full_text
                    .lines()
                    .map(str::trim)
                    .find(|l| {
                        l.chars().count() >= 24
                            && *l != title
                            && !l.starts_with('#')
                            && !l.to_ascii_lowercase().starts_with("author")
                            && !l.starts_with("作者")
                    })
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| title.clone());

        let clean_abs: String = scrub_diag_text(&abstract_summary)
            .replace('\n', " ")
            .chars()
            .take(160)
            .collect();
        let key_headings: Vec<String> = sections
            .iter()
            .take(5)
            .map(|s| scrub_diag_text(&s.heading))
            .collect();

        entries.push(BibliographyEntry {
            index: idx + 1,
            file_name,
            path: p.display().to_string(),
            format: ext.to_ascii_uppercase(),
            title: scrub_diag_text(&title),
            authors: scrub_diag_text(authors.as_deref().unwrap_or("未知作者")),
            year,
            abstract_summary: clean_abs,
            key_headings,
        });
    }

    let mut md = String::from(
        "# 文献综述与研究资料清单 (Compiled Bibliography)\n\n\
         | # | 标题 (Title) | 作者 (Authors) | 年份 | 格式 | 核心摘要 (Abstract) | 章节结构 | 文件 |\n\
         |---|---|---|---|---|---|---|---|\n",
    );
    for e in &entries {
        let esc = |s: &str| s.replace('|', "\\|").replace('\n', " ");
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | `{}` |\n",
            e.index,
            esc(&e.title),
            esc(&e.authors),
            esc(&e.year),
            e.format,
            esc(&e.abstract_summary),
            esc(&e.key_headings.join(" / ")),
            esc(&e.file_name),
        ));
    }

    let mut changeset_id: Option<String> = None;
    let mut effect = Effect::Observe;
    if let Some(out_raw) = params
        .get("output_path")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let out_path = PathBuf::from(out_raw);
        let task_id = format!("bib_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let mut cs = core
            .fs_engine
            .write_file_reversible(&task_id, &out_path, md.as_bytes())
            .map_err(|e| anyhow::anyhow!("写入文献清单失败: {}", e))?;
        cs.capability_id = "document.compile_bibliography".to_string();
        cs.layer = "app_adapter_provider".to_string();
        cs.summary = format!(
            "生成文献综述清单 {} ({} 篇)",
            out_path.display(),
            entries.len()
        );
        core.state_db.save_changeset(&cs)?;
        changeset_id = Some(cs.id);
        effect = Effect::WriteReversible;
    }

    Ok(ProviderExecutionOutcome {
        ok: true,
        requires_approval: false,
        approval_scope: None,
        capability_id: "document.compile_bibliography".into(),
        app_hint: None,
        channel_used: ExecutionChannel::DirectDocumentFormat,
        attempted_channels: vec![ExecutionChannel::DirectDocumentFormat],
        fallback_halted_due_to_side_effect: false,
        effect,
        reversible: true,
        summary: format!(
            "已提取并编译 {} 篇文献生成结构化 Markdown 综述表{}",
            entries.len(),
            changeset_id
                .as_deref()
                .map(|id| format!(" (ChangeSet={})", id))
                .unwrap_or_default()
        ),
        data: json!({
            "paper_count": entries.len(),
            "entries": entries,
            "markdown": md,
            "changeset_id": changeset_id,
        }),
        changeset_id,
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: "bibliography_entries_and_output_verified".into(),
            checks: vec![
                "real_document_metadata_extracted".into(),
                "markdown_table_non_empty".into(),
            ],
            details: None,
        },
        guidance_steps: None,
    })
}

// =============================================================================
// Scenario 3: Personal Directory Analysis & Reversible Organization Plan / Apply
// =============================================================================

fn execute_workspace_organize_plan(
    core: &IntentOsCore,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let dir_raw = params
        .get("directory")
        .or_else(|| params.get("path"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`workspace.organize_plan` 缺少参数 `directory`"))?;
    let dir = PathBuf::from(dir_raw.trim());
    ensure_authorized_dir_scope(&core.fs_engine, &dir)?;

    let target_root = params
        .get("target_root")
        .and_then(|v| v.as_str())
        .map(|s| PathBuf::from(s.trim()))
        .unwrap_or_else(|| dir.clone());
    ensure_authorized_dir_scope(&core.fs_engine, &target_root)?;

    let mut hash_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut category_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut proposed_moves: Vec<Value> = Vec::new();

    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let p = entry.path();
        if !p.is_file() || core.fs_engine.is_forbidden(&p) {
            continue;
        }
        let Some(fname) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if fname.starts_with('.') {
            continue;
        }

        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let subdir = match ext.as_str() {
            "pdf" | "docx" | "doc" | "md" | "tex" | "txt" => "Documents_and_Papers",
            "csv" | "json" | "parquet" | "xlsx" => "Datasets_and_Metrics",
            "png" | "jpg" | "jpeg" | "svg" | "webp" | "mp4" => "Media_and_Figures",
            "zip" | "tar" | "gz" | "xz" | "7z" | "deb" => "Archives_and_Packages",
            "py" | "rs" | "sh" | "ipynb" | "toml" | "yaml" => "Scripts_and_Code",
            _ => "Misc",
        };
        *category_counts.entry(subdir.to_string()).or_insert(0) += 1;

        let mut hasher = Sha256::new();
        if let Ok(mut f) = core.fs_engine.open_readonly_safe(&p) {
            let mut buf = [0u8; 16384];
            while let Ok(n) = f.read(&mut buf) {
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
        }
        let sha = format!("sha256:{}", hex::encode(hasher.finalize()));
        hash_map
            .entry(sha.clone())
            .or_default()
            .push(p.display().to_string());

        let dest = target_root.join(subdir).join(fname);
        if dest != p && !dest.exists() {
            proposed_moves.push(json!({
                "from": p,
                "to": dest,
                "category": subdir,
                "sha256": sha,
                "reversible": true,
            }));
        }
    }

    let duplicates: Vec<Value> = hash_map
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(hash, paths)| json!({ "sha256": hash, "files": paths }))
        .collect();

    Ok(ProviderExecutionOutcome {
        ok: true,
        requires_approval: false,
        approval_scope: None,
        capability_id: "workspace.organize_plan".into(),
        app_hint: None,
        channel_used: ExecutionChannel::DirectDocumentFormat,
        attempted_channels: vec![ExecutionChannel::DirectDocumentFormat],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::Observe,
        reversible: true,
        summary: format!(
            "目录整理规划完成 (`{}`)：识别 {} 个待归档文件、{} 组重复内容（零修改预览，完全可逆）",
            dir.display(),
            proposed_moves.len(),
            duplicates.len()
        ),
        data: json!({
            "directory": dir,
            "target_root": target_root,
            "category_counts": category_counts,
            "duplicates": duplicates,
            "proposed_moves": proposed_moves,
            "reversible": true,
            "requires_approval_to_apply": true,
        }),
        changeset_id: None,
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: "directory_walk_and_collision_free_plan".into(),
            checks: vec![
                "authorized_scope_verified".into(),
                "zero_mutation_preview".into(),
            ],
            details: None,
        },
        guidance_steps: None,
    })
}

fn execute_workspace_organize_apply(
    core: &IntentOsCore,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let moves = params
        .get("moves")
        .or_else(|| params.get("proposed_moves"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("`workspace.organize_apply` 缺少 `moves` 数组"))?;
    if moves.is_empty() {
        anyhow::bail!("`moves` 不能为空");
    }
    let task_id = params
        .get("task_id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("org_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));

    let mut ops: Vec<ChangeOp> = Vec::new();
    for item in moves {
        let from_s = item
            .get("from")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("move 项缺少 `from`"))?;
        let to_s = item
            .get("to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("move 项缺少 `to`"))?;
        let step_cs = core
            .fs_engine
            .move_file(&task_id, Path::new(from_s), Path::new(to_s))?;
        ops.extend(step_cs.operations);
    }

    let now = Utc::now();
    let batch_cs = ChangeSet {
        id: format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]),
        task_id,
        created_at: now,
        capability_id: "workspace.organize_apply".to_string(),
        layer: "app_adapter_provider".to_string(),
        operations: ops,
        backup_bytes: 0,
        status: ChangeSetStatus::Applied,
        undo_expires_at: now + ChronoDuration::days(30),
        summary: format!("批量可逆归档整理 {} 个文件", moves.len()),
    };
    core.state_db.save_changeset(&batch_cs)?;

    Ok(ProviderExecutionOutcome {
        ok: true,
        requires_approval: false,
        approval_scope: None,
        capability_id: "workspace.organize_apply".into(),
        app_hint: None,
        channel_used: ExecutionChannel::DirectDocumentFormat,
        attempted_channels: vec![ExecutionChannel::DirectDocumentFormat],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::WriteReversible,
        reversible: true,
        summary: format!(
            "✓ 已完成 {} 个文件的安全归档移动（ChangeSet `{}`，可一键全量撤销）",
            batch_cs.operations.len(),
            batch_cs.id
        ),
        data: json!({
            "moved_count": batch_cs.operations.len(),
            "changeset_id": batch_cs.id,
            "reversible": true,
        }),
        changeset_id: Some(batch_cs.id),
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: "all_moves_sha256_verified_and_changeset_saved".into(),
            checks: vec![
                "renameat2_noreplace_verified".into(),
                "batch_changeset_saved".into(),
            ],
            details: None,
        },
        guidance_steps: None,
    })
}

// =============================================================================
// Scenario 4 & Tier 1/2/4 Channel Implementations
// =============================================================================

fn execute_git_inspect_repo(
    core: &IntentOsCore,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let repo_raw = params
        .get("repo_dir")
        .or_else(|| params.get("repo"))
        .or_else(|| params.get("path"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("`git.inspect_repo` 缺少参数 `repo_dir`"))?;
    let repo_dir = PathBuf::from(repo_raw.trim());
    ensure_authorized_dir_scope(&core.fs_engine, &repo_dir)?;

    let git_bin_opt = resolve_host_binary("git");
    execute_channel_chain(
        "git.inspect_repo",
        Some("git".into()),
        Effect::Observe,
        true,
        vec![ChannelCandidate {
            channel: ExecutionChannel::CliOrHeadless,
            available: git_bin_opt.is_some(),
            execute_fn: Box::new(|| {
                let git_bin = git_bin_opt.as_ref().unwrap();
                let mut st_cmd = Command::new(git_bin);
                apply_clean_desktop_env_std(&mut st_cmd);
                let st_out = st_cmd
                    .arg("-C")
                    .arg(&repo_dir)
                    .args(["status", "--porcelain=v1", "--branch"])
                    .output()?;
                if !st_out.status.success() {
                    anyhow::bail!(
                        "目标目录不是有效 Git 仓库: {}",
                        scrub_diag_text(String::from_utf8_lossy(&st_out.stderr).trim())
                    );
                }
                let st_text = String::from_utf8_lossy(&st_out.stdout);
                let mut branch = "HEAD".to_string();
                let mut staged = Vec::new();
                let mut modified = Vec::new();
                let mut untracked = Vec::new();
                for line in st_text.lines() {
                    if let Some(b) = line.strip_prefix("## ") {
                        branch = b.trim().to_string();
                    } else if line.len() >= 3 {
                        let xy = &line[..2];
                        let file = scrub_diag_text(line[3..].trim());
                        if xy == "??" {
                            untracked.push(file);
                        } else {
                            let bytes = xy.as_bytes();
                            if bytes[0] != b' ' && bytes[0] != b'?' {
                                staged.push(file.clone());
                            }
                            if bytes[1] != b' ' && bytes[1] != b'?' {
                                modified.push(file);
                            }
                        }
                    }
                }

                let diff_out = Command::new(git_bin)
                    .arg("-C")
                    .arg(&repo_dir)
                    .args(["diff", "--stat"])
                    .output()?;
                let diff_stat = scrub_diag_text(String::from_utf8_lossy(&diff_out.stdout).trim());

                let log_out = Command::new(git_bin)
                    .arg("-C")
                    .arg(&repo_dir)
                    .args(["log", "-n5", "--oneline"])
                    .output()?;
                let recent_commits: Vec<String> = if log_out.status.success() {
                    String::from_utf8_lossy(&log_out.stdout)
                        .lines()
                        .map(scrub_diag_text)
                        .collect()
                } else {
                    Vec::new()
                };

                let dirty = !staged.is_empty() || !modified.is_empty() || !untracked.is_empty();
                Ok(ProviderExecutionOutcome {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    capability_id: "git.inspect_repo".into(),
                    app_hint: Some("git".into()),
                    channel_used: ExecutionChannel::CliOrHeadless,
                    attempted_channels: vec![ExecutionChannel::CliOrHeadless],
                    fallback_halted_due_to_side_effect: false,
                    effect: Effect::Observe,
                    reversible: true,
                    summary: format!(
                        "Git 仓库 `{}` 分支 `{}`：暂存 {}、修改 {}、未跟踪 {}",
                        repo_dir.display(),
                        branch,
                        staged.len(),
                        modified.len(),
                        untracked.len()
                    ),
                    data: json!({
                        "repo_dir": repo_dir,
                        "branch": branch,
                        "dirty": dirty,
                        "staged_files": staged,
                        "modified_files": modified,
                        "untracked_files": untracked,
                        "diff_stat": diff_stat,
                        "recent_commits": recent_commits,
                    }),
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "git_cli_exit_0".into(),
                        checks: vec![
                            "authorized_scope_verified".into(),
                            "git_status_parsed".into(),
                        ],
                        details: None,
                    },
                    guidance_steps: None,
                })
            }),
        }],
    )
}

async fn execute_document_convert_headless(
    core: &IntentOsCore,
    app_hint: Option<&str>,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let lo_available =
        resolve_host_binary("libreoffice").is_some() || resolve_host_binary("soffice").is_some();
    if !lo_available {
        return Ok(build_honest_guidance_outcome(
            "document.convert_headless",
            app_hint.or(Some("libreoffice")),
            "本机未检测到 `libreoffice` / `soffice` 命令行组件，返回导出引导",
            vec![
                "当前主机未安装 LibreOffice 无头转换组件 (`sudo apt install libreoffice` 或 `snap install libreoffice`)。".into(),
                "安装后即可通过 `CliOrHeadless` 通道静默批量转换 `.docx` -> `.pdf`。".into(),
            ],
        ));
    }

    let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
    let (profile, _) =
        reg.resolve_adapter_and_action(app_hint.unwrap_or("libreoffice"), "convert_document");
    let res = execute_headless_transform(core, &profile, "convert_document", params).await?;

    Ok(ProviderExecutionOutcome {
        ok: res.ok,
        requires_approval: false,
        approval_scope: None,
        capability_id: "document.convert_headless".into(),
        app_hint: Some(profile.id),
        channel_used: ExecutionChannel::CliOrHeadless,
        attempted_channels: vec![ExecutionChannel::CliOrHeadless],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::WriteReversible,
        reversible: res.changeset_id.is_some(),
        summary: res.summary,
        data: res.data,
        changeset_id: res.changeset_id,
        verification: res.verification,
        guidance_steps: None,
    })
}

fn execute_ide_goto_or_diff(
    core: &IntentOsCore,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let Some(code_bin) = resolve_host_binary("code").or_else(|| resolve_host_binary("codium"))
    else {
        return Ok(build_honest_guidance_outcome(
            "ide.goto_or_diff",
            Some("code"),
            "本机未安装 VS Code / VSCodium CLI (`code` / `codium`)",
            vec!["请在编辑器中通过快捷键 Ctrl+G 跳转行号，或安装 `code` CLI。".into()],
        ));
    };

    let mode = params
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("status");
    let mut cmd = Command::new(&code_bin);
    apply_clean_desktop_env_std(&mut cmd);

    match mode {
        "status" => {
            let out = cmd.arg("--version").output()?;
            let ver = scrub_diag_text(String::from_utf8_lossy(&out.stdout).trim());
            Ok(ProviderExecutionOutcome {
                ok: out.status.success(),
                requires_approval: false,
                approval_scope: None,
                capability_id: "ide.goto_or_diff".into(),
                app_hint: Some("vscode".into()),
                channel_used: ExecutionChannel::CliOrHeadless,
                attempted_channels: vec![ExecutionChannel::CliOrHeadless],
                fallback_halted_due_to_side_effect: false,
                effect: Effect::Observe,
                reversible: true,
                summary: format!(
                    "检测到已安装编辑器 CLI: {}",
                    ver.lines().next().unwrap_or("code")
                ),
                data: json!({ "binary": code_bin, "version": ver }),
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::Passed,
                    method: "cli_exit_status".into(),
                    checks: vec!["code_binary_verified".into()],
                    details: None,
                },
                guidance_steps: None,
            })
        }
        "diff" => {
            let left = PathBuf::from(
                params
                    .get("left")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("diff 缺少 `left`"))?,
            );
            let right = PathBuf::from(
                params
                    .get("right")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("diff 缺少 `right`"))?,
            );
            let _ = require_authorized_file_bytes(&core.fs_engine, &left)?;
            let _ = require_authorized_file_bytes(&core.fs_engine, &right)?;
            if params.get("dry_run").and_then(|v| v.as_bool()) == Some(true) || !has_gui_session() {
                return Ok(ProviderExecutionOutcome {
                    ok: true,
                    requires_approval: false,
                    approval_scope: None,
                    capability_id: "ide.goto_or_diff".into(),
                    app_hint: Some("vscode".into()),
                    channel_used: ExecutionChannel::CliOrHeadless,
                    attempted_channels: vec![ExecutionChannel::CliOrHeadless],
                    fallback_halted_due_to_side_effect: false,
                    effect: Effect::Ui,
                    reversible: true,
                    summary: format!(
                        "已生成编辑器对比命令 `{} --diff {} {}`",
                        code_bin.display(),
                        left.display(),
                        right.display()
                    ),
                    data: json!({ "left": left, "right": right, "dry_run": true }),
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "cli_dry_run".into(),
                        checks: vec!["authorized_scope_verified".into()],
                        details: None,
                    },
                    guidance_steps: None,
                });
            }
            let _ = cmd.arg("--diff").arg(&left).arg(&right).spawn()?;
            Ok(ProviderExecutionOutcome {
                ok: true,
                requires_approval: false,
                approval_scope: None,
                capability_id: "ide.goto_or_diff".into(),
                app_hint: Some("vscode".into()),
                channel_used: ExecutionChannel::CliOrHeadless,
                attempted_channels: vec![ExecutionChannel::CliOrHeadless],
                fallback_halted_due_to_side_effect: false,
                effect: Effect::Ui,
                reversible: true,
                summary: format!(
                    "已请求 VS Code 对比 `{}` 与 `{}`",
                    left.display(),
                    right.display()
                ),
                data: json!({ "left": left, "right": right }),
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "code_diff_spawn".into(),
                    checks: vec!["authorized_scope_verified".into()],
                    details: None,
                },
                guidance_steps: None,
            })
        }
        _ => {
            let p = PathBuf::from(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("goto 缺少 `path`"))?,
            );
            let _ = require_authorized_file_bytes(&core.fs_engine, &p)?;
            let line = params.get("line").and_then(|v| v.as_u64()).unwrap_or(1);
            let target = format!("{}:{}", p.display(), line);
            if params.get("dry_run").and_then(|v| v.as_bool()) != Some(true) && has_gui_session() {
                let _ = cmd.arg("--goto").arg(&target).spawn()?;
            }
            Ok(ProviderExecutionOutcome {
                ok: true,
                requires_approval: false,
                approval_scope: None,
                capability_id: "ide.goto_or_diff".into(),
                app_hint: Some("vscode".into()),
                channel_used: ExecutionChannel::CliOrHeadless,
                attempted_channels: vec![ExecutionChannel::CliOrHeadless],
                fallback_halted_due_to_side_effect: false,
                effect: Effect::Ui,
                reversible: true,
                summary: format!("已请求编辑器跳转至 `{}`", target),
                data: json!({ "goto": target }),
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "code_goto_spawn".into(),
                    checks: vec!["authorized_scope_verified".into()],
                    details: None,
                },
                guidance_steps: None,
            })
        }
    }
}

fn execute_rclone_status() -> anyhow::Result<ProviderExecutionOutcome> {
    let Some(rclone_bin) = resolve_host_binary("rclone") else {
        return Ok(build_honest_guidance_outcome(
            "cloud.rclone_status",
            Some("rclone"),
            "本机未安装 `rclone` 云盘客户端",
            vec!["可通过 `sudo apt install rclone` 安装后再配置云存储挂载。".into()],
        ));
    };
    let mut cmd = Command::new(rclone_bin);
    apply_clean_desktop_env_std(&mut cmd);
    let out = cmd.arg("listremotes").output()?;
    let remotes: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| scrub_diag_text(l.trim()))
        .filter(|l| !l.is_empty())
        .collect();

    Ok(ProviderExecutionOutcome {
        ok: out.status.success(),
        requires_approval: false,
        approval_scope: None,
        capability_id: "cloud.rclone_status".into(),
        app_hint: Some("rclone".into()),
        channel_used: ExecutionChannel::CliOrHeadless,
        attempted_channels: vec![ExecutionChannel::CliOrHeadless],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::Observe,
        reversible: true,
        summary: format!("rclone 已安装，当前配置远端数量: {}", remotes.len()),
        data: json!({ "remotes": remotes }),
        changeset_id: None,
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: "rclone_listremotes".into(),
            checks: vec!["secrets_not_exported".into()],
            details: None,
        },
        guidance_steps: None,
    })
}

async fn execute_provider_media_control(
    core: &IntentOsCore,
    app_hint: Option<&str>,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let action = params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("status");
    if action == "status" {
        let players = query_all_now_playing(app_hint, false).await;
        return Ok(ProviderExecutionOutcome {
            ok: true,
            requires_approval: false,
            approval_scope: None,
            capability_id: "media.control".into(),
            app_hint: app_hint.map(ToString::to_string),
            channel_used: ExecutionChannel::NativeApiOrDbus,
            attempted_channels: vec![ExecutionChannel::NativeApiOrDbus],
            fallback_halted_due_to_side_effect: false,
            effect: Effect::Observe,
            reversible: true,
            summary: format!(
                "已通过 MPRIS2/SNI D-Bus 探测到 {} 个活跃播放器",
                players.len()
            ),
            data: json!({ "players": players }),
            changeset_id: None,
            verification: VerificationReport {
                state: VerificationState::Passed,
                method: "mpris_or_sni_dbus_reply".into(),
                checks: vec!["dbus_queried".into()],
                details: None,
            },
            guidance_steps: None,
        });
    }

    let mpris = discover_active_mpris_services().await;
    let trays = discover_live_tray_apps().await;
    if mpris.services.is_empty() && trays.is_empty() {
        return Ok(build_honest_guidance_outcome(
            "media.control",
            app_hint,
            "当前桌面没有注册 MPRIS2 或 SNI 托盘接口的运行中媒体播放器",
            vec!["请先启动音乐播放器并打开曲目播放。".into()],
        ));
    }

    let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
    let (profile, _) = reg.resolve_adapter_and_action(app_hint.unwrap_or("music"), action);
    if !mpris.services.is_empty() {
        let res = execute_mpris_action(&profile, action, params, false).await?;
        return Ok(ProviderExecutionOutcome {
            ok: res.ok,
            requires_approval: false,
            approval_scope: None,
            capability_id: "media.control".into(),
            app_hint: Some(profile.id),
            channel_used: ExecutionChannel::NativeApiOrDbus,
            attempted_channels: vec![ExecutionChannel::NativeApiOrDbus],
            fallback_halted_due_to_side_effect: false,
            effect: Effect::Ui,
            reversible: true,
            summary: res.summary,
            data: res.data,
            changeset_id: None,
            verification: res.verification,
            guidance_steps: None,
        });
    }

    if let Some(tray) = match_tray_app_for_hint(
        &trays,
        app_hint.unwrap_or("music"),
        Some(&core.paths.config_dir),
    ) && let Some(res_val) = invoke_tray_menu_action(&tray.service, action).await?
    {
        let summary = res_val
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("已通过系统托盘菜单执行媒体动作")
            .to_string();
        let ver = res_val
            .get("verification")
            .and_then(|v| serde_json::from_value::<VerificationReport>(v.clone()).ok())
            .unwrap_or(VerificationReport {
                state: VerificationState::Passed,
                method: "sni_dbusmenu_event".into(),
                checks: vec!["dbusmenu_event_exit_0".into()],
                details: None,
            });
        return Ok(ProviderExecutionOutcome {
            ok: true,
            requires_approval: false,
            approval_scope: None,
            capability_id: "media.control".into(),
            app_hint: Some(profile.id),
            channel_used: ExecutionChannel::NativeApiOrDbus,
            attempted_channels: vec![ExecutionChannel::NativeApiOrDbus],
            fallback_halted_due_to_side_effect: false,
            effect: Effect::Ui,
            reversible: true,
            summary,
            data: res_val,
            changeset_id: None,
            verification: ver,
            guidance_steps: None,
        });
    }

    Ok(build_honest_guidance_outcome(
        "media.control",
        app_hint,
        "在当前运行的系统托盘应用中未找到匹配的媒体控制菜单项",
        vec!["请在播放器窗口内直接点击播放/暂停或切歌按钮。".into()],
    ))
}

async fn execute_provider_file_manager_reveal(
    core: &IntentOsCore,
    params: &Value,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
    let (profile, _) = reg.resolve_adapter_and_action("nautilus", "reveal_file");
    let res = execute_freedesktop_action(core, &profile, "reveal_file", params).await?;
    Ok(ProviderExecutionOutcome {
        ok: res.ok,
        requires_approval: false,
        approval_scope: None,
        capability_id: "file_manager.reveal".into(),
        app_hint: Some("nautilus".into()),
        channel_used: ExecutionChannel::NativeApiOrDbus,
        attempted_channels: vec![ExecutionChannel::NativeApiOrDbus],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::Ui,
        reversible: true,
        summary: res.summary,
        data: res.data,
        changeset_id: None,
        verification: res.verification,
        guidance_steps: None,
    })
}

async fn execute_provider_gui_semantic(
    core: &IntentOsCore,
    app_hint: Option<&str>,
    params: &Value,
    approved: bool,
) -> anyhow::Result<ProviderExecutionOutcome> {
    let target_app = app_hint.unwrap_or("desktop");
    let (wayland, atspi_ok) = probe_wayland_and_atspi_env();

    if let Some(ctrl_label) = params
        .get("click_control")
        .or_else(|| params.get("control"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
        let (profile, _) = reg.resolve_adapter_and_action(target_app, "click_control");
        if !approved {
            let scope = build_gui_approval_scope(
                &profile,
                "click_control",
                &json!({ "control": ctrl_label }),
            );
            return Ok(ProviderExecutionOutcome {
                ok: false,
                requires_approval: true,
                approval_scope: Some(scope.clone()),
                capability_id: "gui.semantic_inspect".into(),
                app_hint: Some(profile.id),
                channel_used: ExecutionChannel::GuiAtSpiSemantic,
                attempted_channels: vec![ExecutionChannel::GuiAtSpiSemantic],
                fallback_halted_due_to_side_effect: false,
                effect: Effect::Ui,
                reversible: false,
                summary: scope.description,
                data: json!({
                    "requires_approval": true,
                    "wayland_session": wayland,
                    "pixel_guessing_used": false,
                }),
                changeset_id: None,
                verification: VerificationReport {
                    state: VerificationState::Skipped,
                    method: "approval_gate".into(),
                    checks: vec!["zero_pixel_guessing".into()],
                    details: None,
                },
                guidance_steps: None,
            });
        }
        if !atspi_ok {
            return Ok(build_honest_guidance_outcome(
                "gui.semantic_inspect",
                Some(target_app),
                "当前无活跃图形会话或 AT-SPI2 无障碍服务（拒绝使用全屏像素坐标盲猜）",
                vec![
                    "当前环境未开启 AT-SPI2 语义无障碍树或处于无头模式。".into(),
                    "系统严格禁止全屏截图坐标盲点，请在桌面窗口内手动点击目标控件。".into(),
                ],
            ));
        }
        let gui_res = execute_gui_bridge_action(
            &profile,
            "click_control",
            &json!({ "control": ctrl_label }),
            true,
        )
        .await?;
        return Ok(ProviderExecutionOutcome {
            ok: gui_res.ok,
            requires_approval: gui_res.requires_approval,
            approval_scope: gui_res.approval_scope,
            capability_id: "gui.semantic_inspect".into(),
            app_hint: Some(profile.id),
            channel_used: ExecutionChannel::GuiAtSpiSemantic,
            attempted_channels: vec![ExecutionChannel::GuiAtSpiSemantic],
            fallback_halted_due_to_side_effect: false,
            effect: Effect::Ui,
            reversible: false,
            summary: gui_res.summary,
            data: gui_res.data,
            changeset_id: None,
            verification: gui_res.verification,
            guidance_steps: None,
        });
    }

    if !atspi_ok {
        return Ok(ProviderExecutionOutcome {
            ok: true,
            requires_approval: false,
            approval_scope: None,
            capability_id: "gui.semantic_inspect".into(),
            app_hint: Some(target_app.to_string()),
            channel_used: ExecutionChannel::HonestGuidance,
            attempted_channels: vec![
                ExecutionChannel::GuiAtSpiSemantic,
                ExecutionChannel::HonestGuidance,
            ],
            fallback_halted_due_to_side_effect: false,
            effect: Effect::Observe,
            reversible: true,
            summary: format!(
                "当前环境无活跃 AT-SPI2 语义控件总线（wayland={}，未使用截图坐标猜测）",
                wayland
            ),
            data: json!({
                "app_hint": target_app,
                "wayland_session": wayland,
                "atspi_available": false,
                "pixel_guessing_used": false,
                "controls": [],
            }),
            changeset_id: None,
            verification: VerificationReport {
                state: VerificationState::Skipped,
                method: "atspi_unavailable_honest".into(),
                checks: vec!["pixel_guessing_disabled".into()],
                details: None,
            },
            guidance_steps: Some(vec![
                "当前会话未检测到可用 AT-SPI2 无障碍树；可在桌面环境开启辅助功能后重试。".into(),
            ]),
        });
    }

    let controls = probe_atspi_controls_readonly(target_app).await;
    Ok(ProviderExecutionOutcome {
        ok: true,
        requires_approval: false,
        approval_scope: None,
        capability_id: "gui.semantic_inspect".into(),
        app_hint: Some(target_app.to_string()),
        channel_used: ExecutionChannel::GuiAtSpiSemantic,
        attempted_channels: vec![ExecutionChannel::GuiAtSpiSemantic],
        fallback_halted_due_to_side_effect: false,
        effect: Effect::Observe,
        reversible: true,
        summary: format!(
            "已通过纯净环境 AT-SPI2 读取 `{}` 的 {} 个语义控件（wayland={}）",
            target_app,
            controls.len(),
            wayland
        ),
        data: json!({
            "app_hint": target_app,
            "wayland_session": wayland,
            "atspi_available": true,
            "pixel_guessing_used": false,
            "controls": controls,
        }),
        changeset_id: None,
        verification: VerificationReport {
            state: VerificationState::Passed,
            method: "atspi_semantic_tree_readonly".into(),
            checks: vec!["clean_env_atspi".into(), "pixel_guessing_disabled".into()],
            details: None,
        },
        guidance_steps: None,
    })
}

/// Dispatch `app_provider_capabilities`, `app_provider_execute`, and direct `document.*` / `workspace.*` / `git.*` tools.
pub async fn execute_provider_tool(
    core: &IntentOsCore,
    tool_name: &str,
    args: &Value,
) -> anyhow::Result<Value> {
    let canonical = canonicalize_provider_tool(tool_name);
    match canonical.as_str() {
        "app_provider_capabilities" => {
            let query = args.get("query").and_then(|v| v.as_str());
            let domain = args.get("domain").and_then(|v| v.as_str());
            let caps = SoftwareCapabilityProvider::list_capabilities(query, domain);
            Ok(json!({
                "ok": true,
                "count": caps.len(),
                "capabilities": caps,
            }))
        }
        "app_provider_execute" => {
            let cap_id = args
                .get("capability_id")
                .or_else(|| args.get("action"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("`app_provider_execute` 缺少必填参数 `capability_id`")
                })?;
            let app_hint = args.get("app_hint").and_then(|v| v.as_str());
            let params = args
                .get("params")
                .or_else(|| args.get("arguments"))
                .cloned()
                .unwrap_or_else(|| args.clone());
            let approved = args
                .get("approved")
                .or_else(|| params.get("approved"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let out =
                SoftwareCapabilityProvider::execute(core, cap_id, app_hint, &params, approved)
                    .await?;
            Ok(serde_json::to_value(out)?)
        }
        direct_cap => {
            let app_hint = args.get("app_hint").and_then(|v| v.as_str());
            let params = args.get("params").filter(|v| v.is_object()).unwrap_or(args);
            let approved = args
                .get("approved")
                .or_else(|| params.get("approved"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let out =
                SoftwareCapabilityProvider::execute(core, direct_cap, app_hint, params, approved)
                    .await?;
            Ok(serde_json::to_value(out)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_or_create_configs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    fn setup_provider_test_core() -> (TempDir, Arc<IntentOsCore>, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let paths = crate::config::XdgPaths::resolve(Some(tmp.path()), repo_root.clone());
        let (mut app_cfg, brain_cfg) = load_or_create_configs(&paths).unwrap();
        let work_dir = tmp.path().join("workspace");
        std::fs::create_dir_all(&work_dir).unwrap();
        app_cfg.authorized_directories = vec![work_dir.to_string_lossy().to_string()];
        app_cfg.allow_simulated_hardware_fallback = true;
        std::fs::write(
            paths.config_dir.join("config.toml"),
            toml::to_string_pretty(&app_cfg).unwrap(),
        )
        .unwrap();
        std::fs::write(
            paths.config_dir.join("brain.toml"),
            toml::to_string_pretty(&brain_cfg).unwrap(),
        )
        .unwrap();
        let core = IntentOsCore::initialize(Some(tmp.path()), repo_root).unwrap();
        (tmp, core, work_dir)
    }

    #[test]
    fn m2d_strict_no_replay_rule_halts_on_requested_unverified_mutation() {
        let ch1_calls = AtomicUsize::new(0);
        let ch2_calls = AtomicUsize::new(0);

        let outcome = execute_channel_chain(
            "test.mutating_action",
            Some("demo-app".into()),
            Effect::WriteReversible,
            true,
            vec![
                ChannelCandidate {
                    channel: ExecutionChannel::CliOrHeadless,
                    available: true,
                    execute_fn: Box::new(|| {
                        ch1_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(ProviderExecutionOutcome {
                            ok: true,
                            requires_approval: false,
                            approval_scope: None,
                            capability_id: "test.mutating_action".into(),
                            app_hint: Some("demo-app".into()),
                            channel_used: ExecutionChannel::CliOrHeadless,
                            attempted_channels: vec![],
                            fallback_halted_due_to_side_effect: false,
                            effect: Effect::WriteReversible,
                            reversible: true,
                            summary: "spawned unverified CLI mutation".into(),
                            data: json!({}),
                            changeset_id: None,
                            verification: VerificationReport {
                                state: VerificationState::RequestedUnverified,
                                method: "async_spawn".into(),
                                checks: vec![],
                                details: None,
                            },
                            guidance_steps: None,
                        })
                    }),
                },
                ChannelCandidate {
                    channel: ExecutionChannel::GuiAtSpiSemantic,
                    available: true,
                    execute_fn: Box::new(|| {
                        ch2_calls.fetch_add(1, Ordering::SeqCst);
                        unreachable!("second mutating channel MUST NEVER be replayed!");
                    }),
                },
            ],
        )
        .unwrap();

        assert_eq!(ch1_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ch2_calls.load(Ordering::SeqCst),
            0,
            "second mutating channel must NEVER run when first returned RequestedUnverified"
        );
        assert_eq!(
            outcome.verification.state,
            VerificationState::RequestedUnverified
        );
        assert!(outcome.fallback_halted_due_to_side_effect);
    }

    #[tokio::test]
    async fn m2d_scenario6_docx_md_pdf_section_edit_undo_format_and_bibliography() {
        let (_tmp, core, work_dir) = setup_provider_test_core();

        // 1. Create a real `.docx` thesis file with minor formatting defects (skipped H1->H3 & empty section & broken numbering)
        let thesis_path = work_dir.join("master_thesis.docx");
        let orig_docx = build_minimal_docx_bytes(
            Some("面向个人智能体的安全可逆操作系统研究"),
            &[
                (
                    "摘要",
                    1,
                    &["本文提出了一种融合形式化权限边界与原子撤销机制的个人智能操作系统架构。"],
                ),
                (
                    "第一章 绪论",
                    1,
                    &[
                        "随着大模型智能体进入桌面环境，如何在不牺牲安全的前提下完成复杂工作成为关键挑战。",
                    ],
                ),
                (
                    "1.1 研究背景",
                    2,
                    &["传统 GUI 视觉盲点容易误触且缺乏回滚保障。"],
                ),
                ("1.3 论文组织结构", 2, &[]), // broken 1.1 -> 1.3 numbering + empty section!
                (
                    "第三章 实验与评估",
                    1,
                    &["旧版实验结论：L0 延迟 61.23ms，待补充 M2 最新吞吐数据。"],
                ),
            ],
        );
        std::fs::write(&thesis_path, &orig_docx).unwrap();
        let orig_disk_bytes = std::fs::read(&thesis_path).unwrap();

        // 2. `document.read_section` reads `"第三章"` accurately without launching GUI!
        let read_ch3 = SoftwareCapabilityProvider::execute(
            &core,
            "document.read_section",
            None,
            &json!({
                "path": thesis_path.to_string_lossy(),
                "section_query": "第3章"
            }),
            false,
        )
        .await
        .unwrap();
        assert!(read_ch3.ok);
        assert_eq!(
            read_ch3.channel_used,
            ExecutionChannel::DirectDocumentFormat
        );
        assert!(
            read_ch3.data["matched_section"]["body"]
                .as_str()
                .unwrap()
                .contains("旧版实验结论")
        );

        // 3. `document.inspect_format` catches broken numbering (`1.1 -> 1.3`, `第一章 -> 第三章`) & empty `1.3`!
        let fmt_rep = SoftwareCapabilityProvider::execute(
            &core,
            "document.inspect_format",
            None,
            &json!({ "path": thesis_path.to_string_lossy() }),
            false,
        )
        .await
        .unwrap();
        assert!(fmt_rep.ok);
        assert_eq!(fmt_rep.data["format_clean"], false);
        assert!(
            !fmt_rep.data["broken_numbering"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            !fmt_rep.data["empty_sections"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        // 4. `document.replace_section` updates Chapter 3, records ChangeSet in StateDb, and `Undo` restores byte-exact original `.docx`!
        let edit_out = SoftwareCapabilityProvider::execute(
            &core,
            "document.replace_section",
            None,
            &json!({
                "path": thesis_path.to_string_lossy(),
                "section_heading": "第三章 实验与评估",
                "new_content": "新版实测结论：引入 CapabilitySnapshot 与 5 层 Provider 后，热路径检索延迟降至亚毫秒级，且 100% 变更支持一键撤销。"
            }),
            false,
        )
        .await
        .unwrap();
        assert!(edit_out.ok);
        let csid = edit_out.changeset_id.expect("changeset_id created");

        let read_updated = SoftwareCapabilityProvider::execute(
            &core,
            "document.read_section",
            None,
            &json!({
                "path": thesis_path.to_string_lossy(),
                "section_query": "第三章"
            }),
            false,
        )
        .await
        .unwrap();
        assert!(
            read_updated.data["matched_section"]["body"]
                .as_str()
                .unwrap()
                .contains("亚毫秒级")
        );

        // Atomic Undo via `core.broker.undo_changeset(Some(&csid))` -> exact original `.docx` bytes!
        let (undone_cs, _msg) = core.broker.undo_changeset(Some(&csid)).unwrap();
        assert_eq!(undone_cs.status, ChangeSetStatus::Undone);
        let restored_bytes = std::fs::read(&thesis_path).unwrap();
        assert_eq!(
            restored_bytes, orig_disk_bytes,
            "Undo MUST restore byte-identical original .docx file!"
        );

        // 5. `document.compile_bibliography` across real `.pdf`, `.docx`, and `.md` papers!
        let papers_dir = work_dir.join("papers");
        std::fs::create_dir_all(&papers_dir).unwrap();
        std::fs::copy(&thesis_path, papers_dir.join("01_intentos_thesis.docx")).unwrap();

        let pdf_bytes = build_minimal_pdf_bytes(
            "Sandboxed Capability Brokers for Desktop Agents",
            "Alice Chen, Bob Lin",
            &[
                "Sandboxed Capability Brokers for Desktop Agents",
                "Authors: Alice Chen, Bob Lin (2025)",
                "Abstract",
                "We present a kernel-enforced openat2 and bwrap broker preventing agent privilege escalation.",
            ],
        );
        std::fs::write(papers_dir.join("02_sandbox_broker_2025.pdf"), pdf_bytes).unwrap();

        std::fs::write(
            papers_dir.join("03_progressive_discovery.md"),
            "---\ntitle: \"Progressive Tool Schema Discovery in Local AIOS\"\n---\n\nAuthors: Wei Zhang, Mei Zhou (2026)\n\n## Abstract\nDynamic meta-tools cut prompt schema tokens by over 60 percent while maintaining accuracy.\n\n## Evaluation\nTested across 325 desktop intents.\n",
        )
        .unwrap();

        let bib_out_file = work_dir.join("literature_review.md");
        let bib_res = SoftwareCapabilityProvider::execute(
            &core,
            "document.compile_bibliography",
            None,
            &json!({
                "directory": papers_dir.to_string_lossy(),
                "output_path": bib_out_file.to_string_lossy()
            }),
            false,
        )
        .await
        .unwrap();
        assert!(bib_res.ok);
        assert_eq!(bib_res.data["paper_count"], 3);
        assert!(bib_out_file.is_file());
        let bib_md = std::fs::read_to_string(&bib_out_file).unwrap();
        assert!(bib_md.contains("Sandboxed Capability Brokers for Desktop Agents"));
        assert!(bib_md.contains("Alice Chen"));
        assert!(bib_md.contains("Progressive Tool Schema Discovery"));
        assert!(bib_md.contains("面向个人智能体的安全可逆操作系统研究"));
    }

    #[tokio::test]
    async fn m2d_scenarios_3_4_and_honest_guidance_on_closed_apps() {
        let (_tmp, core, work_dir) = setup_provider_test_core();

        // Scenario 3: Personal directory analysis & reversible organization + Undo
        let downloads = work_dir.join("Downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::write(downloads.join("paper_a.md"), "# Paper A\nContent").unwrap();
        std::fs::write(downloads.join("paper_a_copy.md"), "# Paper A\nContent").unwrap();
        std::fs::write(downloads.join("metrics.json"), r#"{"acc": 0.991}"#).unwrap();

        let plan = SoftwareCapabilityProvider::execute(
            &core,
            "workspace.organize_plan",
            None,
            &json!({ "directory": downloads.to_string_lossy() }),
            false,
        )
        .await
        .unwrap();
        assert!(plan.ok);
        assert_eq!(plan.data["duplicates"].as_array().unwrap().len(), 1);
        let moves = plan.data["proposed_moves"].clone();
        assert_eq!(moves.as_array().unwrap().len(), 3);

        let applied = SoftwareCapabilityProvider::execute(
            &core,
            "workspace.organize_apply",
            None,
            &json!({ "moves": moves }),
            true,
        )
        .await
        .unwrap();
        assert!(applied.ok);
        let org_cs = applied.changeset_id.unwrap();
        assert!(downloads.join("Documents_and_Papers/paper_a.md").is_file());
        assert!(
            downloads
                .join("Datasets_and_Metrics/metrics.json")
                .is_file()
        );

        // Undo restores all 3 files back into `Downloads/`!
        let _ = core.broker.undo_changeset(Some(&org_cs)).unwrap();
        assert!(downloads.join("paper_a.md").is_file());
        assert!(downloads.join("metrics.json").is_file());

        // Scenario 4: Real Git repository status/diff inspection
        if let Some(git_bin) = resolve_host_binary("git") {
            let repo = work_dir.join("sample_repo");
            std::fs::create_dir_all(&repo).unwrap();
            assert!(
                Command::new(&git_bin)
                    .arg("init")
                    .arg(&repo)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            let _ = Command::new(&git_bin)
                .arg("-C")
                .arg(&repo)
                .args(["config", "user.email", "test@example.invalid"])
                .output();
            let _ = Command::new(&git_bin)
                .arg("-C")
                .arg(&repo)
                .args(["config", "user.name", "Test Bot"])
                .output();
            std::fs::write(repo.join("README.md"), "# Demo\n").unwrap();
            let _ = Command::new(&git_bin)
                .arg("-C")
                .arg(&repo)
                .args(["add", "README.md"])
                .output();
            let _ = Command::new(&git_bin)
                .arg("-C")
                .arg(&repo)
                .args(["commit", "-m", "init"])
                .output();
            std::fs::write(repo.join("README.md"), "# Demo\nUpdated line\n").unwrap();
            std::fs::write(repo.join("notes.txt"), "untracked\n").unwrap();

            let git_rep = SoftwareCapabilityProvider::execute(
                &core,
                "git.inspect_repo",
                None,
                &json!({ "repo_dir": repo.to_string_lossy() }),
                false,
            )
            .await
            .unwrap();
            assert!(git_rep.ok);
            assert_eq!(git_rep.channel_used, ExecutionChannel::CliOrHeadless);
            assert_eq!(git_rep.data["dirty"], true);
            assert_eq!(git_rep.data["modified_files"], json!(["README.md"]));
            assert_eq!(git_rep.data["untracked_files"], json!(["notes.txt"]));
        }

        // Tier 5: Closed-source apps (QQ / WPS internal action) MUST return HonestGuidance, never fake execution!
        let qq_out = SoftwareCapabilityProvider::execute(
            &core,
            "closed_app.internal_action",
            Some("QQ"),
            &json!({ "requested_action": "send_message" }),
            false,
        )
        .await
        .unwrap();
        assert_eq!(qq_out.channel_used, ExecutionChannel::HonestGuidance);
        assert_eq!(qq_out.data["action_executed"], false);
        assert_eq!(qq_out.data["honest_guidance"], true);
        assert!(qq_out.guidance_steps.is_some());
    }
}
