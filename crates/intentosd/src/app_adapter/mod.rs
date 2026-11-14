#![forbid(unsafe_code)]

//! Universal Software Command & Interface Translation Layer (`crates/intentosd/src/app_adapter/`):
//! Solves: "有些桌面软件不支持终端命令行驱动，需要做指令接口适配（转译层）"
//!
//! 5 Progressive Adaptation Channels:
//! 1. `registry.rs` — Declarative Software Adapter Registry (24 built-ins + `${config_dir}/adapters/*.{toml,json}`)
//! 2. `mpris_dbus.rs` — Session D-Bus & MPRIS2 Non-CLI GUI App Driver (`PlayPause`, `Next`, `xesam:title`, `FileManager1.ShowItems`)
//! 3. `uri_desktop.rs` — URI Deep-Link (`vscode://`, `obsidian://`, `tg://`, `mailto:`) & `.desktop` `[Desktop Action]` Driver
//! 4. `headless_bridge.rs` — Silent Background Document/Media Transformation (`libreoffice --headless`, `pdftotext`, `ffmpeg`)
//! 5. `gui_bridge.rs` — Window Focus & AT-SPI2 Accessibility Inspection / Approval-Gated UI Action Fallback

pub mod dynamic_profiler;
pub mod gui_bridge;
pub mod headless_bridge;
pub mod local_scanner;
pub mod mpris_dbus;
pub mod registry;
pub mod sni_dbusmenu;
pub mod uri_desktop;

pub use dynamic_profiler::{
    CustomActionMapping, CustomAppsStoreFile, CustomSoftwareProfile, DiscoveredDesktopSoftware,
    clear_desktop_discovery_cache, close_application_verified, discover_installed_desktop_apps,
    inspect_live_app, load_custom_apps_store,
};
pub use gui_bridge::{DesktopWindowInfo, GuiApprovalScope};
pub use headless_bridge::HeadlessCommandPlan;
pub use local_scanner::{
    CategoryScanSummary, CompanionCliTool, DeepScanCatalog, LocalScanOptions,
    ScannedDesktopAction, ScannedSoftwareEntry, SoftwareCategoryMeta, SynthesizedActionSpec,
    all_software_categories, categories_match, classify_software_category, clear_deep_scan_cache,
    deep_scan_local_software, execute_desktop_action_by_id, normalize_software_category,
};
pub use mpris_dbus::{MprisDiscoveryReport, MprisNowPlaying};
pub use registry::{AdaptationChannel, AdapterRegistry, AppAdapterProfile, SemanticAppAction};
pub use sni_dbusmenu::{
    LiveTrayApp, TrayMenuItem, activate_or_show_tray_app, apply_clean_desktop_env,
    apply_clean_desktop_env_std, invoke_tray_menu_action, parse_dbusmenu_layout_gvariant,
    resolve_system_gi_python3, sanitize_ld_library_path,
};
pub use uri_desktop::{DesktopActionSection, ParsedDesktopFile};

use crate::core::IntentOsCore;
use intentos_capability_sdk::resolve_trusted_executable;
use intentos_protocol::{ToolSpec, VerificationReport, VerificationState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;

/// Structured UI `Trace Dot` matching `WAVE2_AIOS_QUICK_CHAT_ARCHITECTURE.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterTraceDot {
    pub kind: String,
    pub color: String,
    pub title: String,
    pub detail: String,
}

/// Unified execution outcome returned by `translate_and_execute` and `app_adapter_invoke`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterExecutionOutcome {
    pub ok: bool,
    pub requires_approval: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_scope: Option<GuiApprovalScope>,
    pub channel_used: String,
    pub app_id: String,
    pub app_name: String,
    pub intent_action: String,
    pub translated_command: String,
    pub summary: String,
    pub data: Value,
    pub simulated: bool,
    pub verification: VerificationReport,
    pub trace_dot: AdapterTraceDot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changeset_id: Option<String>,
}

/// Check whether a tool name belongs to the `app_adapter` LLM tool suite.
pub fn is_adapter_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "app_adapter_invoke"
            | "app_adapter.invoke"
            | "app_adapter_list"
            | "app_adapter.list"
            | "app_adapter_now_playing"
            | "app_adapter.now_playing"
            | "app_adapter_inspect_app"
            | "app_adapter.inspect_app"
    )
}

/// Expose LLM `ToolSpec` definitions so the AIOS Brain can inspect and control non-CLI desktop GUI apps directly.
pub fn adapter_tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "app_adapter_invoke".into(),
            description: "通过软件指令转译层控制本机 9 大分类桌面与个性化软件（支持 StatusNotifierItem/dbusmenu 系统托盘菜单点击如汽水音乐/WPS云盘/FlClash/QQ/微信、多阶段已验证优雅关闭、腾讯会议会议号一键入会、飞书深度链接、QQ音乐软件渲染启动、MPRIS2 音乐播放与切歌、LocalSend 局域网投送、FlClash/Tailscale 代理组网探针、IDE 工程与源码行列跳转/对比、LibreOffice/draw.io 无头转换导出、Evince PDF 跳页/检索、VirtualBox/RustDesk 受审批控制、Fcitx5 输入法切换、NVIDIA GPU 遥测及 AT-SPI2 窗口桥接）".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "app_hint": {
                        "type": "string",
                        "description": "目标软件名称、中文名、拼音、关键词或 .desktop ID，例如 '汽水音乐'、'QQ音乐'、'腾讯会议'、'飞书'、'微信'、'QQ'、'WPS'、'永中'、'LibreOffice'、'Evince'、'LocalSend'、'百度网盘'、'FlClash'、'Tailscale'、'VS Code'、'ZCode'、'Trae CN'、'Antigravity'、'draw.io'、'VirtualBox'、'RustDesk'、'Fcitx5'、'NVIDIA'"
                    },
                    "intent_action": {
                        "type": "string",
                        "description": "高层语义动作或实时托盘菜单项名称，例如 'launch_app'、'click_tray_menu'、'quit'、'join_meeting'、'open_feishu_uri'、'wake_main_window'、'play_pause'、'next'、'previous'、'get_now_playing'、'open_media'、'convert_to_pdf'、'convert_document'、'open_pdf_page'、'find_in_pdf'、'open_pdf_arranger'、'new_document'、'send_file'、'wake_cloud_drive'、'open_download_folder'、'probe_proxy_status'、'tailscale_status'、'open_incognito'、'open_app_mode'、'open_project'、'goto_file_line'、'diff_two_files'、'export_diagram'、'list_vms'、'start_vm'、'savestate_vm'、'get_device_id'、'connect_peer'、'input_method_status'、'activate_chinese'、'deactivate_chinese'、'query_gpu_telemetry'、'select_in_folder'、'reveal_file'、'focus_window'"
                    },
                    "params": {
                        "type": "object",
                        "description": "动作参数对象（如 meeting_code, menu_label, path, paths, page, keyword, format, out_dir, url, uri, line, column, left, right, vm, peer_id, volume, control, shortcut 等）"
                    },
                    "approved": {
                        "type": "boolean",
                        "description": "针对需要显式审批的动作（如 VirtualBox start_vm/savestate_vm、RustDesk connect_peer、敏感托盘账号操作、gui_atspi 合成点击/快捷键、或需强制结束的进程）的用户显式批准标志（默认 false）"
                    }
                },
                "required": ["app_hint", "intent_action"]
            }),
        },
        ToolSpec {
            name: "app_adapter_list".into(),
            description: "深度扫描并按 9 大分类查询本机全部桌面软件与指令接口转译目录（覆盖 APT / Snap / Flatpak / /opt 厂商目录 / 用户本地 / PWA、运行态 PID 与托盘/MPRIS 总线及用户自定义规则）".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "可选过滤关键词（软件名、中文名、拼音、功能或动作名）"
                    },
                    "category": {
                        "type": "string",
                        "description": "可选 9 大分类过滤：'media_entertainment' | 'social_collab' | 'office_notes_doc' | 'cloud_transfer' | 'network_browser' | 'dev_ai_ide' | 'creative_disc' | 'remote_vm' | 'hardware_system' | 'all'"
                    },
                    "only_running": {
                        "type": "boolean",
                        "description": "可选仅返回当前正在运行的软件（默认 false）"
                    }
                }
            }),
        },
        ToolSpec {
            name: "app_adapter_now_playing".into(),
            description: "探测当前桌面正在运行的 MPRIS2 与系统托盘 StatusNotifierItem 音乐/媒体播放器（汽水音乐 SodaM、QQ音乐、网易云音乐、Spotify、VLC、Rhythmbox、浏览器音视频）并读取当前曲目标题、歌手与播放状态".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "player_hint": {
                        "type": "string",
                        "description": "可选指定播放器标识（如 '汽水音乐'、'sodam'、'qqmusic'、'spotify'），留空则查询全部活跃播放器"
                    }
                }
            }),
        },
        ToolSpec {
            name: "app_adapter_inspect_app".into(),
            description: "实时探测本机任意软件的完整动态适配画像（合并 .desktop 路径与快捷动作、/proc 运行 PID、StatusNotifierItem 系统托盘服务及实时标题与 dbusmenu 菜单项、MPRIS2 媒体总线、AT-SPI2 无障碍控件、用户自定义规则与推荐动作）。遇到个性化国产软件或未知应用时可先调用此工具查看实时可控菜单与通道".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "app": {
                        "type": "string",
                        "description": "软件名称，如 汽水音乐 / FlClash / WPS / 飞书 / 轻笺"
                    }
                },
                "required": ["app"]
            }),
        },
    ]
}

/// Execute one of the `app_adapter_*` LLM tools against `IntentOsCore`.
pub async fn execute_adapter_tool(
    core: &IntentOsCore,
    tool_name: &str,
    args: &Value,
) -> anyhow::Result<Value> {
    match tool_name {
        "app_adapter_invoke" | "app_adapter.invoke" => {
            let app_hint = args
                .get("app_hint")
                .or_else(|| args.get("app"))
                .and_then(|v| v.as_str())
                .unwrap_or("auto");
            let intent_action = args
                .get("intent_action")
                .or_else(|| args.get("action"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少必填参数 `intent_action`"))?;
            let params = args
                .get("params")
                .or_else(|| args.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let approved = args
                .get("approved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let outcome =
                translate_and_execute(core, app_hint, intent_action, &params, approved).await?;
            Ok(serde_json::to_value(outcome)?)
        }
        "app_adapter_list" | "app_adapter.list" => {
            let query = args.get("query").and_then(|v| v.as_str());
            let category = args.get("category").and_then(|v| v.as_str());
            let only_running = args
                .get("only_running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
            let adapters = reg.list_filtered(query, category, None);
            let scan_opts = local_scanner::LocalScanOptions {
                category: category.map(ToString::to_string),
                query: query.map(ToString::to_string),
                only_running,
                ..Default::default()
            };
            let catalog = local_scanner::deep_scan_local_software(
                Some(&core.paths.config_dir),
                &reg,
                &scan_opts,
            )
            .await;
            Ok(json!({
                "count": adapters.len(),
                "adapters": adapters,
                "total_scanned": catalog.total_scanned,
                "total_adapted": catalog.total_adapted,
                "running_count": catalog.running_count,
                "categories": catalog.categories,
                "scanned_apps": catalog.apps,
            }))
        }
        "app_adapter_now_playing" | "app_adapter.now_playing" => {
            let hint = args
                .get("player_hint")
                .or_else(|| args.get("app_hint"))
                .and_then(|v| v.as_str());
            let players = mpris_dbus::query_all_now_playing(
                hint,
                core.app_config.allow_simulated_hardware_fallback,
            )
            .await;
            Ok(json!({
                "count": players.len(),
                "players": players,
            }))
        }
        "app_adapter_inspect_app" | "app_adapter.inspect_app" => {
            let app = args
                .get("app")
                .or_else(|| args.get("app_hint"))
                .or_else(|| args.get("query"))
                .or_else(|| args.get("name"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少必填参数 `app`"))?;
            dynamic_profiler::inspect_live_app(core, app).await
        }
        other => anyhow::bail!("未知的 app_adapter 工具名: {}", other),
    }
}

/// Core progressive software command translation & execution engine.
pub async fn translate_and_execute(
    core: &IntentOsCore,
    app_hint: &str,
    raw_intent_action: &str,
    params: &Value,
    approved: bool,
) -> anyhow::Result<AdapterExecutionOutcome> {
    let registry = AdapterRegistry::load(Some(&core.paths.config_dir));
    let (profile, semantic_action) = registry.resolve_adapter_and_action(app_hint, raw_intent_action);
    let canonical_action = semantic_action.action.clone();

    // Record frecency boost for adapted app usage
    core.index_db
        .record_frecency(&format!("adapter:{}", profile.id));

    // 1. Check user-customized action translation rules (`adapters/custom_apps.json`) first
    let outcome = if let Some((custom_prof, act_key, mapping)) =
        dynamic_profiler::find_custom_action_mapping(
            &core.paths.config_dir,
            &profile.id,
            &canonical_action,
            raw_intent_action,
        ) {
        let (ok, req_app, scope, chan, cmd, summary, data, simulated, ver) =
            dynamic_profiler::execute_custom_action_mapping(
                core,
                &profile,
                &custom_prof,
                &act_key,
                &mapping,
                params,
                approved,
            )
            .await?;
        build_outcome_from_parts(
            &profile,
            &act_key,
            ok,
            req_app,
            scope,
            chan,
            cmd,
            summary,
            data,
            simulated,
            ver,
            None,
        )
    } else if canonical_action == "quit" {
        // 2. Real multi-stage verified process close (`close_application_verified`)
        let target_query = if !app_hint.trim().is_empty()
            && !app_hint.trim().eq_ignore_ascii_case("auto")
        {
            app_hint.trim()
        } else {
            profile.name.as_str()
        };
        let close_res =
            dynamic_profiler::close_application_verified(core, target_query, approved).await?;
        let ok = close_res
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let req_app = close_res
            .get("requires_approval")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let summary = close_res
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("已完成应用关闭请求")
            .to_string();
        let approval_scope = if req_app {
            Some(GuiApprovalScope {
                scope_id: format!("process_lifecycle:{}:quit_force", profile.id),
                app_id: profile.id.clone(),
                app_name: profile.name.clone(),
                action: "quit".into(),
                target_detail: target_query.to_string(),
                risk_badge: "sensitive_approval".into(),
                description: summary.clone(),
            })
        } else {
            None
        };
        let verification = close_res
            .get("verification")
            .and_then(|v| serde_json::from_value::<VerificationReport>(v.clone()).ok())
            .unwrap_or(VerificationReport {
                state: if ok {
                    VerificationState::Passed
                } else {
                    VerificationState::VerificationFailed
                },
                method: "close_application_verified".into(),
                checks: vec!["procfs_uid_scan".into()],
                details: None,
            });
        build_outcome_from_parts(
            &profile,
            &canonical_action,
            ok,
            req_app,
            approval_scope,
            AdaptationChannel::ProcessLifecycle,
            format!("close_application_verified({})", target_query),
            summary,
            close_res,
            false,
            verification,
            None,
        )
    } else if let Some(rich_outcome) = local_scanner::try_execute_rich_local_action(
        core,
        &registry,
        app_hint,
        &canonical_action,
        raw_intent_action,
        params,
        approved,
    )
    .await
    {
        rich_outcome
    } else {
        match semantic_action.channel {
            AdaptationChannel::DbusMpris => {
                let res = mpris_dbus::execute_mpris_action(
                    &profile,
                    &canonical_action,
                    params,
                    core.app_config.allow_simulated_hardware_fallback,
                )
                .await?;
                build_outcome_from_parts(
                    &profile,
                    &canonical_action,
                    res.ok,
                    false,
                    None,
                    res.channel_used,
                    res.translated_command,
                    res.summary,
                    res.data,
                    res.simulated,
                    res.verification,
                    None,
                )
            }
            AdaptationChannel::DbusFreedesktop => {
                let res = mpris_dbus::execute_freedesktop_action(
                    core,
                    &profile,
                    &canonical_action,
                    params,
                )
                .await?;
                build_outcome_from_parts(
                    &profile,
                    &canonical_action,
                    res.ok,
                    false,
                    None,
                    res.channel_used,
                    res.translated_command,
                    res.summary,
                    res.data,
                    res.simulated,
                    res.verification,
                    None,
                )
            }
            AdaptationChannel::UriScheme => {
                let res =
                    uri_desktop::execute_uri_deeplink(core, &profile, &semantic_action, params)?;
                build_outcome_from_parts(
                    &profile,
                    &canonical_action,
                    res.ok,
                    false,
                    None,
                    res.channel_used,
                    res.translated_command,
                    res.summary,
                    res.data,
                    res.simulated,
                    res.verification,
                    None,
                )
            }
            AdaptationChannel::DesktopAction => {
                let res =
                    uri_desktop::execute_desktop_action(core, &profile, &semantic_action, params)?;
                build_outcome_from_parts(
                    &profile,
                    &canonical_action,
                    res.ok,
                    false,
                    None,
                    res.channel_used,
                    res.translated_command,
                    res.summary,
                    res.data,
                    res.simulated,
                    res.verification,
                    None,
                )
            }
            AdaptationChannel::HeadlessCli => {
                let res = headless_bridge::execute_headless_transform(
                    core,
                    &profile,
                    &canonical_action,
                    params,
                )
                .await?;
                build_outcome_from_parts(
                    &profile,
                    &canonical_action,
                    res.ok,
                    false,
                    None,
                    res.channel_used,
                    res.translated_command,
                    res.summary,
                    res.data,
                    res.simulated,
                    res.verification,
                    res.changeset_id,
                )
            }
            AdaptationChannel::SniDbusMenu => {
                execute_sni_tray_menu_outcome(
                    core,
                    &profile,
                    app_hint,
                    &canonical_action,
                    raw_intent_action,
                    params,
                    approved,
                )
                .await?
            }
            AdaptationChannel::CliWrapper | AdaptationChannel::ProcessLifecycle => {
                execute_cli_wrapper_action(core, &profile, &canonical_action, params)?
            }
            AdaptationChannel::GuiAtspi => {
                // Before falling into generic AT-SPI2 approval gate for non-standard actions,
                // check if `raw_intent_action` (or `params.menu_label`) matches a live `StatusNotifierItem`
                // tray menu item (e.g. `"查看传输详情"`, `"启动 WPS 云盘"`, `"系统代理"`, `"切换账号"`)!
                let is_standard_gui_action = matches!(
                    canonical_action.as_str(),
                    "list_windows"
                        | "focus_window"
                        | "inspect_ui_tree"
                        | "click_control"
                        | "trigger_shortcut"
                        | "type_text"
                );
                if (!is_standard_gui_action || params.get("menu_label").is_some())
                    && let Some(tray_outcome) = try_match_and_execute_live_tray_label(
                        core,
                        &profile,
                        app_hint,
                        raw_intent_action,
                        params,
                        approved,
                    )
                    .await?
                {
                    tray_outcome
                } else {
                    let res = gui_bridge::execute_gui_bridge_action(
                        &profile,
                        &canonical_action,
                        params,
                        approved,
                    )
                    .await?;
                    build_outcome_from_parts(
                        &profile,
                        &canonical_action,
                        res.ok,
                        res.requires_approval,
                        res.approval_scope,
                        res.channel_used,
                        res.translated_command,
                        res.summary,
                        res.data,
                        res.simulated,
                        res.verification,
                        None,
                    )
                }
            }
        }
    };

    // Persist audit record for software translation execution / approval gate
    let decision_str = if outcome.requires_approval {
        "awaiting_approval"
    } else if outcome.ok {
        "allow"
    } else {
        "failed"
    };
    let _ = core.state_db.record_audit(
        None,
        &format!("app_adapter.{}.{}", outcome.app_id, outcome.intent_action),
        "app_adapter",
        if outcome.changeset_id.is_some() {
            "write.reversible"
        } else {
            "ui"
        },
        decision_str,
        if outcome.ok { "ok" } else { "blocked_or_failed" },
        params,
        Some(&outcome.summary),
    );

    Ok(outcome)
}

async fn execute_sni_tray_menu_outcome(
    core: &IntentOsCore,
    profile: &AppAdapterProfile,
    app_hint: &str,
    canonical_action: &str,
    raw_intent_action: &str,
    params: &Value,
    approved: bool,
) -> anyhow::Result<AdapterExecutionOutcome> {
    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let requested_label = params
        .get("menu_label")
        .or_else(|| params.get("label"))
        .or_else(|| params.get("item"))
        .or_else(|| params.get("target"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if canonical_action == "click_tray_menu" {
                raw_intent_action.trim()
            } else {
                canonical_action
            }
        });

    if sni_dbusmenu::is_sensitive_tray_menu_label(requested_label) && !approved {
        let desc = format!(
            "系统托盘菜单项「{} · {}」涉及账号或敏感状态变更，需显式批准后执行",
            profile.name, requested_label
        );
        let scope = GuiApprovalScope {
            scope_id: format!("sni_dbusmenu:{}:{}", profile.id, requested_label),
            app_id: profile.id.clone(),
            app_name: profile.name.clone(),
            action: "click_tray_menu".into(),
            target_detail: requested_label.to_string(),
            risk_badge: "sensitive_approval".into(),
            description: desc.clone(),
        };
        return Ok(build_outcome_from_parts(
            profile,
            "click_tray_menu",
            false,
            true,
            Some(scope),
            AdaptationChannel::SniDbusMenu,
            format!("sni_dbusmenu::invoke_tray_menu_action({}, {})", profile.id, requested_label),
            desc,
            json!({ "menu_label": requested_label, "requires_approval": true }),
            false,
            VerificationReport {
                state: VerificationState::Skipped,
                method: "sni_tray_approval_gate".into(),
                checks: vec!["sensitive_tray_item_gated".into()],
                details: None,
            },
            None,
        ));
    }

    if force_dry_run || !mpris_dbus::has_gui_session() || !mpris_dbus::has_dbus_session_address() {
        return Ok(build_outcome_from_parts(
            profile,
            canonical_action,
            true,
            false,
            None,
            AdaptationChannel::SniDbusMenu,
            format!("sni_dbusmenu::invoke_tray_menu_action({}, {})", profile.id, requested_label),
            format!(
                "已构建「{}」系统托盘菜单动作 `{}` 转译指令（dry_run / 无头预演）",
                profile.name, requested_label
            ),
            json!({ "menu_label": requested_label }),
            true,
            VerificationReport {
                state: VerificationState::RequestedUnverified,
                method: "simulated_sni_dbusmenu".into(),
                checks: vec!["sni_dbusmenu_args_validated".into()],
                details: None,
            },
            None,
        ));
    }

    if let Some(matched_out) = try_match_and_execute_live_tray_label(
        core,
        profile,
        app_hint,
        requested_label,
        params,
        approved,
    )
    .await?
    {
        return Ok(matched_out);
    }

    let tray_apps = sni_dbusmenu::discover_live_tray_apps().await;
    let matched_tray =
        sni_dbusmenu::match_tray_app_for_hint(&tray_apps, app_hint, Some(&core.paths.config_dir))
            .or_else(|| {
                sni_dbusmenu::match_tray_app_for_hint(
                    &tray_apps,
                    &profile.id,
                    Some(&core.paths.config_dir),
                )
            });

    let (fail_summary, fail_data) = if let Some(tray) = matched_tray {
        let available: Vec<&str> = tray.menu_items.iter().map(|m| m.label.as_str()).collect();
        (
            format!(
                "在「{}」系统托盘菜单中未找到匹配 `{}` 的菜单项（当前可用菜单：{:?}）",
                profile.name, requested_label, available
            ),
            json!({
                "service": tray.service,
                "requested_label": requested_label,
                "available_menu_items": tray.menu_items,
            }),
        )
    } else {
        (
            format!(
                "当前未在系统托盘检测到「{}」运行实例，请先启动该应用",
                profile.name
            ),
            json!({ "requested_label": requested_label, "is_running": false }),
        )
    };

    Ok(build_outcome_from_parts(
        profile,
        canonical_action,
        false,
        false,
        None,
        AdaptationChannel::SniDbusMenu,
        format!("sni_dbusmenu::invoke_tray_menu_action({}, {})", profile.id, requested_label),
        fail_summary,
        fail_data,
        false,
        VerificationReport {
            state: VerificationState::VerificationFailed,
            method: "sni_dbusmenu_lookup".into(),
            checks: vec![],
            details: Some("tray service or menu item not found".into()),
        },
        None,
    ))
}

async fn try_match_and_execute_live_tray_label(
    core: &IntentOsCore,
    profile: &AppAdapterProfile,
    app_hint: &str,
    raw_action_or_label: &str,
    params: &Value,
    approved: bool,
) -> anyhow::Result<Option<AdapterExecutionOutcome>> {
    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if force_dry_run || !mpris_dbus::has_dbus_session_address() {
        return Ok(None);
    }

    let label_candidate = params
        .get("menu_label")
        .or_else(|| params.get("label"))
        .or_else(|| params.get("item"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| raw_action_or_label.trim());

    if label_candidate.is_empty() || label_candidate.eq_ignore_ascii_case("click_tray_menu") {
        return Ok(None);
    }

    let tray_apps = sni_dbusmenu::discover_live_tray_apps().await;
    let matched_tray =
        sni_dbusmenu::match_tray_app_for_hint(&tray_apps, app_hint, Some(&core.paths.config_dir))
            .or_else(|| {
                sni_dbusmenu::match_tray_app_for_hint(
                    &tray_apps,
                    &profile.id,
                    Some(&core.paths.config_dir),
                )
            });

    let Some(tray) = matched_tray else {
        return Ok(None);
    };
    let Some(matched_item) =
        sni_dbusmenu::match_menu_item_for_action(&tray.menu_items, label_candidate)
    else {
        return Ok(None);
    };

    if sni_dbusmenu::is_sensitive_tray_menu_label(&matched_item.label) && !approved {
        let desc = format!(
            "系统托盘菜单项「{} · {}」涉及账号或敏感状态变更，需显式批准后执行",
            profile.name, matched_item.label
        );
        let scope = GuiApprovalScope {
            scope_id: format!("sni_dbusmenu:{}:{}", profile.id, matched_item.id),
            app_id: profile.id.clone(),
            app_name: profile.name.clone(),
            action: "click_tray_menu".into(),
            target_detail: matched_item.label.clone(),
            risk_badge: "sensitive_approval".into(),
            description: desc.clone(),
        };
        return Ok(Some(build_outcome_from_parts(
            profile,
            "click_tray_menu",
            false,
            true,
            Some(scope),
            AdaptationChannel::SniDbusMenu,
            format!(
                "gdbus call --session --dest {} --object-path {} --method com.canonical.dbusmenu.Event -- {} clicked",
                tray.service,
                tray.menu_path.as_deref().unwrap_or("/MenuBar"),
                matched_item.id
            ),
            desc,
            json!({
                "service": tray.service,
                "menu_item": matched_item,
                "requires_approval": true,
            }),
            false,
            VerificationReport {
                state: VerificationState::Skipped,
                method: "sni_tray_approval_gate".into(),
                checks: vec!["sensitive_tray_item_gated".into()],
                details: None,
            },
            None,
        )));
    }

    if let Some(res_val) =
        sni_dbusmenu::invoke_tray_menu_action(&tray.service, &matched_item.label).await?
    {
        let cmd = res_val
            .get("translated_command")
            .and_then(|v| v.as_str())
            .unwrap_or("sni_dbusmenu.Event")
            .to_string();
        let summary = res_val
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("已通过系统托盘菜单执行动作")
            .to_string();
        let ver = res_val
            .get("verification")
            .and_then(|v| serde_json::from_value::<VerificationReport>(v.clone()).ok())
            .unwrap_or(VerificationReport {
                state: VerificationState::Passed,
                method: "sni_dbusmenu_event_readback".into(),
                checks: vec!["dbusmenu_event_exit_0".into()],
                details: None,
            });
        return Ok(Some(build_outcome_from_parts(
            profile,
            "click_tray_menu",
            true,
            false,
            None,
            AdaptationChannel::SniDbusMenu,
            cmd,
            summary,
            res_val,
            false,
            ver,
            None,
        )));
    }

    Ok(None)
}

fn execute_cli_wrapper_action(
    core: &IntentOsCore,
    profile: &AppAdapterProfile,
    canonical_action: &str,
    params: &Value,
) -> anyhow::Result<AdapterExecutionOutcome> {
    let force_dry_run = params
        .get("dry_run")
        .or_else(|| params.get("simulate"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let bin_name = profile
        .cli_executables
        .first()
        .cloned()
        .unwrap_or_else(|| profile.id.clone());

    let args: Vec<String> = match canonical_action {
        "diff_files" => {
            let left = params
                .get("left")
                .or_else(|| params.get("source"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("`diff_files` 缺少 `left` 文件路径"))?;
            let right = params
                .get("right")
                .or_else(|| params.get("target"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("`diff_files` 缺少 `right` 文件路径"))?;
            if core.fs_engine.is_forbidden(Path::new(left))
                || core.fs_engine.is_forbidden(Path::new(right))
            {
                anyhow::bail!("安全拦截：禁止在编辑器中对比敏感路径文件");
            }
            vec!["--diff".into(), left.to_string(), right.to_string()]
        }
        "open_settings_panel" => {
            let panel = params
                .get("panel")
                .or_else(|| params.get("page"))
                .and_then(|v| v.as_str())
                .unwrap_or("wifi");
            if panel.is_empty()
                || !panel
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                anyhow::bail!("安全拦截：非法的系统设置子面板名称 `{}`", panel);
            }
            vec![panel.to_string()]
        }
        "open_file_at_line" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("缺少 `path` 参数"))?;
            if core.fs_engine.is_forbidden(Path::new(path)) {
                anyhow::bail!("安全拦截：禁止打开敏感路径 {}", path);
            }
            let page = params
                .get("page")
                .or_else(|| params.get("line"))
                .and_then(|v| v.as_u64())
                .unwrap_or(1);
            vec!["-p".into(), page.to_string(), path.to_string()]
        }
        _ => {
            if let Some(p) = params.get("path").and_then(|v| v.as_str()) {
                if core.fs_engine.is_forbidden(Path::new(p)) {
                    anyhow::bail!("安全拦截：禁止打开敏感路径 {}", p);
                }
                vec![p.to_string()]
            } else {
                Vec::new()
            }
        }
    };

    let translated_command = if args.is_empty() {
        bin_name.clone()
    } else {
        format!("{} {}", bin_name, args.join(" "))
    };

    if !force_dry_run
        && mpris_dbus::has_gui_session()
        && let Some(resolved) = resolve_trusted_executable(&bin_name)
    {
        let mut cmd = Command::new(&resolved);
        sni_dbusmenu::apply_clean_desktop_env_std(&mut cmd);
        if cmd.args(&args).spawn().is_ok() {
            return Ok(build_outcome_from_parts(
                profile,
                canonical_action,
                true,
                false,
                None,
                AdaptationChannel::CliWrapper,
                translated_command,
                format!(
                    "已通过受控非 Shell 参数启动「{}」(`{}`)",
                    profile.name, canonical_action
                ),
                json!({ "executable": resolved, "args": args }),
                false,
                VerificationReport {
                    state: VerificationState::RequestedUnverified,
                    method: "cli_wrapper_spawn".into(),
                    checks: vec!["non_shell_argv".into(), "path_not_forbidden".into()],
                    details: None,
                },
                None,
            ));
        }
    }

    Ok(build_outcome_from_parts(
        profile,
        canonical_action,
        true,
        false,
        None,
        AdaptationChannel::CliWrapper,
        translated_command,
        format!(
            "已完成「{}」受控参数封装 `{}`（无头环境安全预演）",
            profile.name, canonical_action
        ),
        json!({ "executable": bin_name, "args": args }),
        true,
        VerificationReport {
            state: VerificationState::RequestedUnverified,
            method: "simulated_cli_wrapper".into(),
            checks: vec!["non_shell_argv".into(), "path_not_forbidden".into()],
            details: None,
        },
        None,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_outcome_from_parts(
    profile: &AppAdapterProfile,
    canonical_action: &str,
    ok: bool,
    requires_approval: bool,
    approval_scope: Option<GuiApprovalScope>,
    channel: AdaptationChannel,
    translated_command: String,
    summary: String,
    data: Value,
    simulated: bool,
    verification: VerificationReport,
    changeset_id: Option<String>,
) -> AdapterExecutionOutcome {
    let trace_dot = if requires_approval {
        AdapterTraceDot {
            kind: "approval".into(),
            color: "orange".into(),
            title: format!("待审批: {} · {}", profile.name, canonical_action),
            detail: summary.clone(),
        }
    } else if ok {
        AdapterTraceDot {
            kind: "adapter".into(),
            color: "cyan".into(),
            title: format!(
                "转译层 ({}): {} · {}",
                channel.as_str(),
                profile.name,
                canonical_action
            ),
            detail: format!("{}\n`{}`", summary, translated_command),
        }
    } else {
        AdapterTraceDot {
            kind: "tool_err".into(),
            color: "red".into(),
            title: format!("转译失败: {} · {}", profile.name, canonical_action),
            detail: summary.clone(),
        }
    };

    AdapterExecutionOutcome {
        ok,
        requires_approval,
        approval_scope,
        channel_used: channel.as_str().to_string(),
        app_id: profile.id.clone(),
        app_name: profile.name.clone(),
        intent_action: canonical_action.to_string(),
        translated_command,
        summary,
        data,
        simulated,
        verification,
        trace_dot,
        changeset_id,
    }
}

/// Probe currently live/controllable desktop applications across MPRIS2, SNI tray services, desktop windows, and `DBusActivatable` manifests.
pub async fn probe_live_controllable_apps(core: &IntentOsCore) -> Value {
    let discovery = mpris_dbus::discover_active_mpris_services().await;
    let mpris_players = if discovery.dbus_session_available {
        mpris_dbus::query_all_now_playing(None, false).await
    } else {
        Vec::new()
    };
    let tray_apps = sni_dbusmenu::discover_live_tray_apps().await;
    let running_windows = gui_bridge::enumerate_desktop_windows().await;
    let dbus_activatable_count = mpris_dbus::count_dbus_activatable_apps();
    let registry = AdapterRegistry::load(Some(&core.paths.config_dir));

    json!({
        "mpris_players": mpris_players,
        "mpris_services": discovery.services,
        "tray_apps": tray_apps,
        "running_windows": running_windows,
        "dbus_activatable_count": dbus_activatable_count,
        "dbus_session_available": discovery.dbus_session_available,
        "gui_session_available": mpris_dbus::has_gui_session(),
        "registered_adapters_count": registry.profiles().len(),
    })
}

/// Unified `UiRpcRequest::ModuleRpc` dispatcher for `domain = "app_adapter"`.
pub async fn handle_module_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    match action {
        "ping" => {
            let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
            Ok(json!({
                "module": "app_adapter",
                "status": "ok",
                "builtin_adapter_count": reg.builtin_count(),
                "total_adapter_count": reg.profiles().len(),
                "channels": [
                    "dbus_mpris",
                    "sni_dbusmenu",
                    "dbus_freedesktop",
                    "uri_scheme",
                    "desktop_action",
                    "headless_cli",
                    "process_lifecycle",
                    "gui_atspi",
                    "cli_wrapper"
                ],
                "supported_actions": [
                    "ping",
                    "list_adapters",
                    "deep_scan_local_software",
                    "get_categorized_catalog",
                    "execute_desktop_action",
                    "translate_and_execute",
                    "probe_live_controllable_apps",
                    "get_now_playing",
                    "discover_personal_apps",
                    "save_custom_adapter",
                    "delete_custom_adapter",
                    "close_app_verified",
                    "inspect_live_app",
                    "list_live_tray_apps",
                    "trigger_tray_menu"
                ],
                "categories": local_scanner::all_software_categories()
            }))
        }
        "deep_scan_local_software" | "get_categorized_catalog" => {
            let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
            let mut opts: local_scanner::LocalScanOptions =
                serde_json::from_value(payload.clone()).unwrap_or_default();
            if action == "get_categorized_catalog"
                && payload.get("force_refresh").is_none()
            {
                opts.force_refresh = false;
            }
            let catalog = local_scanner::deep_scan_local_software(
                Some(&core.paths.config_dir),
                &reg,
                &opts,
            )
            .await;
            Ok(serde_json::to_value(catalog)?)
        }
        "execute_desktop_action" => {
            let desktop_id = payload
                .get("desktop_id")
                .or_else(|| payload.get("app_id"))
                .or_else(|| payload.get("app"))
                .or_else(|| payload.get("app_hint"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("app_adapter.execute_desktop_action: 缺少 `desktop_id`")
                })?;
            let action_id = payload
                .get("action_id")
                .or_else(|| payload.get("desktop_action"))
                .or_else(|| payload.get("action"))
                .or_else(|| payload.get("intent_action"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("launch_app");
            let params = payload
                .get("params")
                .or_else(|| payload.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let approved = payload
                .get("approved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let extra_dirs: Vec<std::path::PathBuf> = payload
                .get("extra_dirs")
                .or_else(|| payload.get("scan_dirs"))
                .or_else(|| payload.get("desktop_dirs"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(std::path::PathBuf::from))
                        .collect()
                })
                .unwrap_or_default();

            let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
            let is_explicit_desktop_sec = matches!(
                action_id,
                "" | "launch" | "launch_app" | "open_app"
            ) || action_id.starts_with("desktop_action:")
                || local_scanner::find_scanned_app(core, &reg, desktop_id)
                    .await
                    .is_some_and(|s| {
                        s.desktop_actions
                            .iter()
                            .any(|da| da.action_id.eq_ignore_ascii_case(action_id))
                    });

            let outcome = if is_explicit_desktop_sec || !extra_dirs.is_empty() {
                local_scanner::execute_desktop_action_by_id(
                    core,
                    &reg,
                    desktop_id,
                    action_id,
                    &params,
                    &extra_dirs,
                )
                .await
            } else {
                translate_and_execute(core, desktop_id, action_id, &params, approved).await?
            };
            Ok(serde_json::to_value(outcome)?)
        }
        "list_adapters" => {
            let query = payload.get("query").and_then(|v| v.as_str());
            let category = payload.get("category").and_then(|v| v.as_str());
            let channel = payload.get("channel").and_then(|v| v.as_str());
            let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
            let adapters = reg.list_filtered(query, category, channel);
            Ok(json!({
                "count": adapters.len(),
                "adapters": adapters,
            }))
        }
        "discover_personal_apps" => {
            let query = payload
                .get("query")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let discovered =
                dynamic_profiler::discover_installed_desktop_apps(Some(&core.paths.config_dir));
            let custom_store = dynamic_profiler::load_custom_apps_store(&core.paths.config_dir);
            let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
            let adapters = reg.list_filtered(query, None, None);

            let mut apps: Vec<Value> = Vec::new();
            for c in &custom_store.custom_apps {
                let prof = dynamic_profiler::custom_software_to_adapter_profile(c);
                if let Some(q) = query
                    && registry::score_profile_against_hint(&prof, &q.to_lowercase()) <= 0.0
                {
                    continue;
                }
                let bin = c
                    .binary_name
                    .clone()
                    .unwrap_or_else(|| c.id.clone());
                apps.push(json!({
                    "id": c.id,
                    "name": c.name,
                    "display_name": c.name,
                    "aliases": prof.aliases,
                    "keywords": c.keywords,
                    "binary": bin,
                    "binary_name": c.binary_name,
                    "exec_path": c.exec_path,
                    "desktop_id": c.desktop_id,
                    "startup_wm_class": c.wm_class,
                    "category": c.category,
                    "channels": prof.channels,
                    "inferred_channels": prof.channels,
                    "custom_actions": c.actions,
                    "source": "custom",
                }));
            }

            for sw in &discovered {
                if apps.iter().any(|x| {
                    x.get("id")
                        .and_then(|v| v.as_str())
                        .is_some_and(|id| id.eq_ignore_ascii_case(&sw.id))
                }) {
                    continue;
                }
                let prof = dynamic_profiler::desktop_software_to_adapter_profile(sw);
                if let Some(q) = query
                    && registry::score_profile_against_hint(&prof, &q.to_lowercase()) <= 0.0
                {
                    continue;
                }
                let bin = sw
                    .binary_name
                    .clone()
                    .unwrap_or_else(|| sw.id.clone());
                apps.push(json!({
                    "id": sw.id,
                    "name": prof.name,
                    "display_name": prof.name,
                    "name_zh_cn": sw.name_zh,
                    "generic_name": sw.generic_name,
                    "aliases": prof.aliases,
                    "keywords": sw.keywords,
                    "binary": bin,
                    "binary_name": sw.binary_name,
                    "exec_path": sw.exec_path,
                    "desktop_id": sw.desktop_id,
                    "desktop_path": sw.desktop_file_path,
                    "startup_wm_class": sw.startup_wm_class,
                    "category": sw.inferred_category,
                    "channels": sw.inferred_channels,
                    "inferred_channels": sw.inferred_channels,
                    "uri_schemes": sw.uri_schemes,
                    "dbus_activatable": sw.dbus_activatable,
                    "source": format!("desktop_auto:{}", sw.desktop_id),
                }));
            }

            Ok(json!({
                "count": apps.len(),
                "apps": apps,
                "adapters": adapters,
                "custom_apps": custom_store.custom_apps,
            }))
        }
        "save_custom_adapter" => {
            let res = dynamic_profiler::upsert_custom_adapter_from_payload(core, &payload);
            local_scanner::clear_deep_scan_cache();
            res
        }
        "delete_custom_adapter" => {
            let res = dynamic_profiler::delete_custom_adapter_by_id(core, &payload);
            local_scanner::clear_deep_scan_cache();
            res
        }
        "close_app_verified" => {
            let app_query = payload
                .get("app_query")
                .or_else(|| payload.get("app_hint"))
                .or_else(|| payload.get("app"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("app_adapter.close_app_verified: 缺少 `app_query`"))?;
            let force_kill_approved = payload
                .get("force_kill_approved")
                .or_else(|| payload.get("approved"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            dynamic_profiler::close_application_verified(core, app_query, force_kill_approved).await
        }
        "translate_and_execute" => {
            let app_hint = payload
                .get("app_hint")
                .or_else(|| payload.get("app"))
                .and_then(|v| v.as_str())
                .unwrap_or("auto");
            let intent_action = payload
                .get("intent_action")
                .or_else(|| payload.get("action"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("app_adapter.translate_and_execute: 缺少 `intent_action`"))?;
            let params = payload
                .get("params")
                .or_else(|| payload.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let approved = payload
                .get("approved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let outcome =
                translate_and_execute(core, app_hint, intent_action, &params, approved).await?;
            Ok(serde_json::to_value(outcome)?)
        }
        "probe_live_controllable_apps" => Ok(probe_live_controllable_apps(core).await),
        "get_now_playing" => {
            let hint = payload
                .get("player_hint")
                .or_else(|| payload.get("app_hint"))
                .and_then(|v| v.as_str());
            let players = mpris_dbus::query_all_now_playing(
                hint,
                core.app_config.allow_simulated_hardware_fallback,
            )
            .await;
            Ok(json!({
                "count": players.len(),
                "players": players,
            }))
        }
        "inspect_live_app" => {
            let app = payload
                .get("app")
                .or_else(|| payload.get("app_query"))
                .or_else(|| payload.get("app_hint"))
                .or_else(|| payload.get("query"))
                .or_else(|| payload.get("name"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("app_adapter.inspect_live_app: 缺少 `app`"))?;
            dynamic_profiler::inspect_live_app(core, app).await
        }
        "list_live_tray_apps" => {
            let tray_apps = sni_dbusmenu::discover_live_tray_apps().await;
            let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
            let enriched: Vec<Value> = tray_apps
                .iter()
                .map(|t| {
                    let probe_key = t
                        .comm
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .unwrap_or(t.id.as_str());
                    let (prof, _) = reg.resolve_adapter_and_action(probe_key, "focus_window");
                    let known = prof.source != "dynamic_gui_fallback"
                        && prof.id != "generic-gui-window";
                    let app_id = if known {
                        prof.id.clone()
                    } else {
                        t.comm.clone().unwrap_or_else(|| t.id.clone())
                    };
                    let display_name = if known {
                        prof.name.clone()
                    } else {
                        t.comm.clone().unwrap_or_else(|| t.id.clone())
                    };
                    let mut obj = serde_json::to_value(t).unwrap_or_else(|_| json!({}));
                    if let Some(map) = obj.as_object_mut() {
                        map.insert("app_id".into(), json!(app_id));
                        map.insert("display_name".into(), json!(display_name));
                        map.insert("live_title".into(), json!(t.title));
                    }
                    obj
                })
                .collect();
            Ok(json!({
                "count": enriched.len(),
                "tray_apps": enriched,
                "apps": enriched,
            }))
        }
        "trigger_tray_menu" => {
            let app_hint = payload
                .get("app")
                .or_else(|| payload.get("app_hint"))
                .or_else(|| payload.get("service"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("app_adapter.trigger_tray_menu: 缺少 `app`"))?;
            let menu_label = payload
                .get("menu_label")
                .or_else(|| payload.get("action"))
                .or_else(|| payload.get("label"))
                .or_else(|| payload.get("intent_action"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("app_adapter.trigger_tray_menu: 缺少 `menu_label`")
                })?;
            let approved = payload
                .get("approved")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let outcome = translate_and_execute(
                core,
                app_hint,
                "click_tray_menu",
                &json!({ "menu_label": menu_label }),
                approved,
            )
            .await?;
            Ok(serde_json::to_value(outcome)?)
        }
        other => anyhow::bail!("app_adapter: 未知的模块 RPC 动作 `{}`", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_or_create_configs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn setup_test_core() -> (TempDir, Arc<IntentOsCore>, PathBuf) {
        let tmp = TempDir::new().expect("create temp dir");
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
    fn registry_ships_16_plus_builtins_and_loads_custom_toml_and_json() {
        let (_tmp, core, _) = setup_test_core();
        let base_reg = AdapterRegistry::load(Some(&core.paths.config_dir));
        assert!(
            base_reg.builtin_count() >= 20,
            "expected >= 20 built-in profiles, got {}",
            base_reg.builtin_count()
        );

        // Verify Chinese/English/Pinyin matching across diverse desktop apps
        let (qq, qq_act) = base_reg.resolve_adapter_and_action("QQ音乐", "切歌");
        assert_eq!(qq.id, "qqmusic");
        assert_eq!(qq_act.action, "next");
        assert_eq!(qq_act.channel, AdaptationChannel::DbusMpris);

        let (ne, _) = base_reg.resolve_adapter_and_action("wyy", "暂停");
        assert_eq!(ne.id, "netease-cloud-music");

        let (fm, fm_act) = base_reg.resolve_adapter_and_action("nautilus", "在文件夹中显示");
        assert_eq!(fm.id, "nautilus");
        assert_eq!(fm_act.action, "reveal_file");
        assert_eq!(fm_act.channel, AdaptationChannel::DbusFreedesktop);

        let (obs, obs_act) = base_reg.resolve_adapter_and_action("黑曜石", "新建笔记");
        assert_eq!(obs.id, "obsidian");
        assert_eq!(obs_act.action, "new_note");
        assert_eq!(obs_act.channel, AdaptationChannel::UriScheme);

        // Write custom .toml and .json adapter manifests into `${config_dir}/adapters/`
        let adapters_dir = core.paths.config_dir.join("adapters");
        std::fs::create_dir_all(&adapters_dir).unwrap();

        let custom_toml = r#"
id = "feishu-desktop"
name = "飞书桌面版 (Feishu)"
desktop_ids = ["bytedance-feishu.desktop"]
aliases = ["飞书", "feishu", "lark"]
category = "communication"
channels = ["uri_scheme", "gui_atspi"]
uri_schemes = ["applink.feishu"]
notes = "通过飞书自定义协议唤起"

[[supported_actions]]
action = "open_chat"
aliases = ["打开飞书会话"]
channel = "uri_scheme"
summary = "打开飞书工作台链接"
target_template = "applink.feishu://client/chat/open?id={chat_id}"
"#;
        std::fs::write(adapters_dir.join("feishu.toml"), custom_toml).unwrap();

        let custom_json = serde_json::json!({
            "id": "zotero",
            "name": "Zotero 文献管理",
            "desktop_ids": ["zotero.desktop"],
            "aliases": ["zotero", "文献管理"],
            "category": "knowledge",
            "channels": ["uri_scheme"],
            "uri_schemes": ["zotero"],
            "supported_actions": [
                {
                    "action": "open_uri",
                    "channel": "uri_scheme",
                    "summary": "打开 Zotero 文献条目",
                    "target_template": "zotero://select/items/{item}"
                }
            ]
        });
        std::fs::write(
            adapters_dir.join("zotero.json"),
            serde_json::to_string_pretty(&custom_json).unwrap(),
        )
        .unwrap();

        let ext_reg = AdapterRegistry::load(Some(&core.paths.config_dir));
        let feishu = ext_reg.get_by_id("feishu-desktop").expect("loaded feishu.toml");
        assert_eq!(feishu.source, "user_custom:feishu.toml");
        let zotero = ext_reg.get_by_id("zotero").expect("loaded zotero.json");
        assert_eq!(zotero.source, "user_custom:zotero.json");
    }

    #[tokio::test]
    async fn mpris_and_file_manager_command_construction_and_headless_fallback() {
        // 1. MPRIS2 command & volume GVariant construction
        let play_argv = mpris_dbus::build_mpris_gdbus_args(
            "org.mpris.MediaPlayer2.qqmusic",
            "play_pause",
            &json!({}),
        )
        .unwrap();
        assert_eq!(
            play_argv.last().unwrap(),
            "org.mpris.MediaPlayer2.Player.PlayPause"
        );

        let vol_argv = mpris_dbus::build_mpris_gdbus_args(
            "org.mpris.MediaPlayer2.spotify",
            "set_volume",
            &json!({ "volume": 65 }),
        )
        .unwrap();
        assert_eq!(vol_argv.last().unwrap(), "<0.6500>");

        // 2. GVariant metadata & service list parsing
        let raw_names = "(['org.freedesktop.DBus', 'org.mpris.MediaPlayer2.spotify', 'org.mpris.MediaPlayer2.qqmusic.instance99'],)";
        let svcs = mpris_dbus::parse_mpris_names_from_gdbus(raw_names);
        assert_eq!(
            svcs,
            vec![
                "org.mpris.MediaPlayer2.qqmusic.instance99",
                "org.mpris.MediaPlayer2.spotify"
            ]
        );

        let raw_props = "({'PlaybackStatus': <'Playing'>, 'Metadata': <{'xesam:title': <'晴天'>, 'xesam:artist': <['周杰伦']>, 'xesam:album': <'叶惠美'>}>, 'Volume': <0.8>},)";
        let np = mpris_dbus::parse_mpris_properties_gvariant(
            "org.mpris.MediaPlayer2.qqmusic",
            raw_props,
        );
        assert_eq!(np.playback_status, "Playing");
        assert_eq!(np.title.as_deref(), Some("晴天"));
        assert_eq!(np.artists, vec!["周杰伦"]);
        assert_eq!(np.album.as_deref(), Some("叶惠美"));
        assert_eq!(np.volume, Some(0.8));

        // 3. Freedesktop FileManager1.ShowItems encoding with spaces & Chinese characters
        let fm_argv = mpris_dbus::build_file_manager_gdbus_args(
            "ShowItems",
            Path::new("/home/user/文档/Q3 周报 2026.pdf"),
            "intentos",
        )
        .unwrap();
        assert_eq!(fm_argv[7], "org.freedesktop.FileManager1.ShowItems");
        assert!(fm_argv[8].contains("file:///home/user/"));
        assert!(fm_argv[8].contains("Q3%20"));

        // 4. Dry-run / headless fallback execution via `translate_and_execute`
        let (_tmp, core, work_dir) = setup_test_core();
        let out = translate_and_execute(
            &core,
            "qqmusic",
            "next",
            &json!({ "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(out.ok);
        assert!(out.simulated);
        assert_eq!(out.channel_used, "dbus_mpris");
        assert_eq!(out.trace_dot.kind, "adapter");
        assert_eq!(out.trace_dot.color, "cyan");

        // Forbidden `.ssh` path rejected in FileManager1 reveal
        let ssh_err = translate_and_execute(
            &core,
            "nautilus",
            "reveal_file",
            &json!({ "path": "/home/user/.ssh/id_ed25519", "dry_run": true }),
            false,
        )
        .await;
        assert!(ssh_err.is_err());

        let sample_doc = work_dir.join("note.txt");
        std::fs::write(&sample_doc, "hello").unwrap();
        let reveal_ok = translate_and_execute(
            &core,
            "nautilus",
            "reveal_file",
            &json!({ "path": sample_doc.to_string_lossy(), "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(reveal_ok.ok);
        assert_eq!(reveal_ok.channel_used, "dbus_freedesktop");
    }

    #[test]
    fn uri_deeplink_encoding_and_strict_dangerous_scheme_blocking() {
        let (_tmp, core, work_dir) = setup_test_core();
        let reg = AdapterRegistry::load(None);

        // 1. VS Code file + line + column deep-link
        let (vsc, vsc_act) = reg.resolve_adapter_and_action("vscode", "open_file_at_line");
        let target_rs = work_dir.join("my file.rs");
        let vsc_uri = uri_desktop::build_uri_deeplink(
            Some(&core),
            &vsc,
            &vsc_act,
            &json!({ "path": target_rs.to_string_lossy(), "line": 42, "column": 8 }),
        )
        .unwrap();
        assert!(vsc_uri.starts_with("vscode://file/"));
        assert!(vsc_uri.ends_with("my%20file.rs:42:8"));

        // 2. Obsidian vault + note deep-link
        let (obs, obs_act) = reg.resolve_adapter_and_action("obsidian", "open_note");
        let obs_uri = uri_desktop::build_uri_deeplink(
            Some(&core),
            &obs,
            &obs_act,
            &json!({ "vault": "AI 笔记", "file": "2026/架构设计" }),
        )
        .unwrap();
        assert_eq!(
            obs_uri,
            "obsidian://open?vault=AI%20%E7%AC%94%E8%AE%B0&file=2026%2F%E6%9E%B6%E6%9E%84%E8%AE%BE%E8%AE%A1"
        );

        // 3. Mailto & Telegram encoding
        let (mail, mail_act) = reg.resolve_adapter_and_action("mail-client", "compose_email");
        let mail_uri = uri_desktop::build_uri_deeplink(
            Some(&core),
            &mail,
            &mail_act,
            &json!({ "to": "team@example.com", "subject": "周报 & 计划", "body": "请查收" }),
        )
        .unwrap();
        assert_eq!(
            mail_uri,
            "mailto:team@example.com?subject=%E5%91%A8%E6%8A%A5%20%26%20%E8%AE%A1%E5%88%92&body=%E8%AF%B7%E6%9F%A5%E6%94%B6"
        );

        // 4. Strictly block javascript:, data:, vbscript:, file:
        for bad in [
            "javascript:alert(document.cookie)",
            "  JAVASCRIPT:evil()",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:msgbox(1)",
            "file:///etc/shadow",
        ] {
            assert!(
                uri_desktop::validate_uri_safety(bad, &[]).is_err(),
                "expected dangerous URI `{}` to be blocked",
                bad
            );
        }

        // 5. Block forbidden `.ssh` file inside vscode://file/...
        let ssh_vsc = uri_desktop::build_uri_deeplink(
            Some(&core),
            &vsc,
            &vsc_act,
            &json!({ "path": "/home/user/.ssh/id_rsa", "line": 1 }),
        );
        assert!(ssh_vsc.is_err());
    }

    #[test]
    fn desktop_action_section_parsing_and_safe_non_shell_tokenization() {
        let sample_desktop = r#"
[Desktop Entry]
Version=1.0
Name=Google Chrome
Name[zh_CN]=Google Chrome 浏览器
Exec=/usr/bin/google-chrome-stable %U
Actions=new-window;new-private-window;

[Desktop Action new-window]
Name=New Window
Name[zh_CN]=新建窗口
Exec=/usr/bin/google-chrome-stable --new-window %U

[Desktop Action new-private-window]
Name=New Incognito Window
Name[zh_CN]=新建无痕式窗口
Exec=env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/chrome.desktop /usr/bin/google-chrome-stable --incognito %U
"#;

        let parsed =
            uri_desktop::parse_desktop_file_content("google-chrome.desktop", sample_desktop);
        assert_eq!(parsed.name, "Google Chrome 浏览器");
        assert_eq!(
            parsed.declared_actions,
            vec!["new-window", "new-private-window"]
        );
        let incog = parsed
            .actions
            .get("new-private-window")
            .expect("incognito action parsed");
        assert_eq!(
            incog.localized_name.as_deref(),
            Some("新建无痕式窗口")
        );

        let (bin, args) =
            uri_desktop::tokenize_desktop_exec(&incog.exec, Some("https://example.com")).unwrap();
        assert_eq!(bin, "/usr/bin/google-chrome-stable");
        assert_eq!(args, vec!["--incognito", "https://example.com"]);

        // Shell interpreter inside Exec= must be rejected
        assert!(uri_desktop::tokenize_desktop_exec("sh -c 'rm -rf /'", None).is_err());
    }

    #[tokio::test]
    async fn headless_bridge_enforces_authorized_scope_and_extracts_preview() {
        let (_tmp, core, work_dir) = setup_test_core();
        let reg = AdapterRegistry::load(None);
        let (lo, _) = reg.resolve_adapter_and_action("libreoffice", "convert_to_pdf");

        let doc_in = work_dir.join("proposal.docx");
        std::fs::write(&doc_in, "dummy docx bytes").unwrap();

        let plan = headless_bridge::build_headless_plan(
            &core.fs_engine,
            &lo,
            "convert_to_pdf",
            &json!({ "path": doc_in.to_string_lossy() }),
        )
        .unwrap();
        assert_eq!(plan.executable_candidates[0], "libreoffice");
        assert_eq!(
            plan.args[..3],
            ["--headless", "--convert-to", "pdf"]
        );
        assert_eq!(plan.output_path, Some(work_dir.join("proposal.pdf")));

        // Path outside authorized directory MUST be rejected
        let unauthorized = headless_bridge::build_headless_plan(
            &core.fs_engine,
            &lo,
            "convert_to_pdf",
            &json!({ "path": "/etc/hosts" }),
        );
        assert!(unauthorized.is_err());

        // Real UTF-8 text preview extraction inside authorized directory
        let md_path = work_dir.join("architecture.md");
        std::fs::write(&md_path, "# IntentOS Wave 2\nUniversal Adapter Ready.").unwrap();
        let preview_out = translate_and_execute(
            &core,
            "evince",
            "extract_text_preview",
            &json!({ "path": md_path.to_string_lossy() }),
            false,
        )
        .await
        .unwrap();
        assert!(preview_out.ok);
        assert_eq!(preview_out.channel_used, "headless_cli");
        assert!(
            preview_out.data["text_preview"]
                .as_str()
                .unwrap_or("")
                .contains("Universal Adapter Ready")
        );
    }

    #[tokio::test]
    async fn gui_bridge_strictly_gates_unapproved_actions_and_validates_shortcuts() {
        let (_tmp, core, _) = setup_test_core();

        // 1. Unapproved synthetic click MUST be blocked with `requires_approval: true`
        let unapproved = translate_and_execute(
            &core,
            "legacy-erp-client",
            "click_control",
            &json!({ "control": "导出报表", "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(!unapproved.ok);
        assert!(unapproved.requires_approval);
        assert_eq!(unapproved.channel_used, "gui_atspi");
        assert_eq!(unapproved.trace_dot.kind, "approval");
        assert_eq!(unapproved.trace_dot.color, "orange");
        let scope = unapproved.approval_scope.expect("approval_scope populated");
        assert_eq!(scope.scope_id, "gui_atspi:legacy-erp-client:click_control");
        assert!(scope.description.contains("导出报表"));

        // 2. Once `approved == true`, the synthetic action proceeds safely (dry_run)
        let approved = translate_and_execute(
            &core,
            "legacy-erp-client",
            "click_control",
            &json!({ "control": "导出报表", "dry_run": true }),
            true,
        )
        .await
        .unwrap();
        assert!(approved.ok);
        assert!(!approved.requires_approval);
        assert_eq!(approved.trace_dot.kind, "adapter");

        // 3. Dangerous system shortcut is rejected even with `approved == true`
        let bad_sc = translate_and_execute(
            &core,
            "legacy-erp-client",
            "trigger_shortcut",
            &json!({ "shortcut": "Ctrl+Alt+Delete", "dry_run": true }),
            true,
        )
        .await;
        assert!(bad_sc.is_err());

        // 4. `wmctrl -lx` output parser test
        let wm_out = "0x01a00007  0 code.Code             devbox mod.rs - Visual Studio Code\n0x02200001  0 qqmusic.qqmusic       devbox QQ音乐";
        let wins = gui_bridge::parse_wmctrl_lx_output(wm_out);
        assert_eq!(wins.len(), 2);
        assert_eq!(wins[0].title, "mod.rs - Visual Studio Code");
        assert_eq!(wins[1].title, "QQ音乐");
    }

    #[tokio::test]
    async fn module_rpc_and_llm_tool_specs_end_to_end() {
        let (_tmp, core, _) = setup_test_core();

        // Check LLM tool specs (4 tools including `app_adapter_inspect_app`)
        let specs = adapter_tool_specs();
        assert_eq!(specs.len(), 4);
        assert!(specs.iter().any(|s| s.name == "app_adapter_invoke"));
        assert!(specs.iter().any(|s| s.name == "app_adapter_list"));
        assert!(specs.iter().any(|s| s.name == "app_adapter_now_playing"));
        assert!(specs.iter().any(|s| s.name == "app_adapter_inspect_app"));
        assert!(is_adapter_tool("app_adapter_inspect_app"));
        assert!(is_adapter_tool("app_adapter.inspect_app"));

        // Module RPC: ping, list_adapters, probe_live_controllable_apps, translate_and_execute
        let ping = handle_module_rpc(&core, "ping", json!({})).await.unwrap();
        assert_eq!(ping["status"], "ok");

        let listed = handle_module_rpc(&core, "list_adapters", json!({ "query": "media" }))
            .await
            .unwrap();
        assert!(listed["count"].as_u64().unwrap_or(0) >= 5);

        let probed = handle_module_rpc(&core, "probe_live_controllable_apps", json!({}))
            .await
            .unwrap();
        assert!(probed.get("mpris_players").is_some());
        assert!(probed.get("running_windows").is_some());
        assert!(probed.get("dbus_activatable_count").is_some());

        // LLM tool invoke: Chrome private window
        let tool_res = execute_adapter_tool(
            &core,
            "app_adapter_invoke",
            &json!({
                "app_hint": "chrome",
                "intent_action": "new_private_window",
                "params": { "dry_run": true }
            }),
        )
        .await
        .unwrap();
        assert_eq!(tool_res["ok"], true);
        assert_eq!(tool_res["channel_used"], "desktop_action");
    }

    #[tokio::test]
    async fn dynamic_desktop_profiler_sodam_verified_close_and_custom_apps_store() {
        let (tmp, core, _) = setup_test_core();

        // Prepare a real non-root dummy binary `sodam-tray-dummy` (executable Python tray-app stand-in)
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let dummy_bin = bin_dir.join("sodam-tray-dummy");
        std::fs::write(&dummy_bin, "#!/usr/bin/python3\nimport time\ntime.sleep(45)\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dummy_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Create `<base>/applications/sodam.desktop` (read-only resolution check for real SodaM / 汽水音乐)
        // AND `<base>/applications/sodamock.desktop` (isolated process-close target that never touches host apps)
        let apps_dir = tmp.path().join("applications");
        std::fs::create_dir_all(&apps_dir).unwrap();
        let sodam_desktop = "[Desktop Entry]\n\
             Type=Application\n\
             Name=SodaM\n\
             GenericName=Music Player\n\
             Exec=/usr/bin/sodam\n\
             Categories=AudioVideo;Audio;Music;Player;\n\
             Keywords=music;qishui;soda;sodam;\n\
             StartupWMClass=SodaM\n";
        std::fs::write(apps_dir.join("sodam.desktop"), sodam_desktop).unwrap();

        let sodamock_desktop = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=SodaMock\n\
             GenericName=Music Player\n\
             Exec={} 45\n\
             Categories=AudioVideo;Audio;Music;Player;\n\
             Keywords=music;qishuiceshi;qishuitest;sodamock;\n\
             StartupWMClass=SodaMock\n",
            dummy_bin.display()
        );
        std::fs::write(apps_dir.join("sodamock.desktop"), sodamock_desktop).unwrap();
        clear_desktop_discovery_cache();

        // 1. `discover_personal_apps` RPC discovers `sodam.desktop` & resolves `"汽水音乐"` via `Keywords=qishui`
        let personal = handle_module_rpc(
            &core,
            "discover_personal_apps",
            json!({ "query": "汽水音乐" }),
        )
        .await
        .unwrap();
        let apps_arr = personal["apps"].as_array().expect("apps array");
        assert!(
            apps_arr.iter().any(|a| a["id"] == "sodam"),
            "expected `sodam` resolved for `汽水音乐` via Keywords=qishui, got: {}",
            personal
        );

        let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
        let (sodam_prof, quit_act) = reg.resolve_adapter_and_action("SODAM音乐", "优雅关闭");
        assert_eq!(sodam_prof.id, "sodam");
        assert_eq!(quit_act.action, "quit");
        assert_eq!(quit_act.channel, AdaptationChannel::ProcessLifecycle);
        assert!(sodam_prof.channels.contains(&AdaptationChannel::DbusMpris));
        assert!(
            sodam_prof
                .channels
                .contains(&AdaptationChannel::ProcessLifecycle)
        );

        // 2. Honest not-running check on isolated `SodaMock` when no `sodam-tray-dummy` PID is alive
        let not_running = close_application_verified(&core, "SODAMOCK音乐", false)
            .await
            .unwrap();
        assert_eq!(not_running["ok"], true);
        assert_eq!(not_running["already_closed"], true);

        // 3. Spawn real `sodam-tray-dummy 45` and close via `app_adapter_invoke` (`"汽水测试音乐"`, `"关闭"`)
        let mut child = std::process::Command::new(&dummy_bin)
            .arg("45")
            .spawn()
            .expect("spawn sodam-tray-dummy");
        let child_pid = child.id();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;

        let close_tool = execute_adapter_tool(
            &core,
            "app_adapter_invoke",
            &json!({
                "app_hint": "汽水测试音乐",
                "intent_action": "关闭"
            }),
        )
        .await
        .unwrap();
        let _ = child.wait();

        assert_eq!(close_tool["ok"], true, "close_tool: {}", close_tool);
        assert_eq!(close_tool["channel_used"], "process_lifecycle");
        assert_eq!(close_tool["verification"]["state"], "passed");
        let closed_pids: Vec<u32> = close_tool["data"]["closed_pids"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u32))
            .collect();
        assert!(
            closed_pids.contains(&child_pid),
            "expected PID {} in closed_pids {:?}",
            child_pid,
            closed_pids
        );

        // 4. Spawn a `SIGTERM`-ignoring tray process (`stubborn-tray-app.py`) -> requires_approval first, SIGKILL when approved
        let stubborn_script = bin_dir.join("stubborn-tray-app.py");
        std::fs::write(
            &stubborn_script,
            "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(45)\n",
        )
        .unwrap();
        let stubborn_desktop = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=StubbornTray\n\
             Exec=/usr/bin/python3 {}\n\
             Categories=Utility;\n\
             Keywords=stubborn;\n",
            stubborn_script.display()
        );
        std::fs::write(apps_dir.join("stubborn-tray.desktop"), stubborn_desktop).unwrap();
        clear_desktop_discovery_cache();

        let mut stubborn_child = std::process::Command::new("/usr/bin/python3")
            .arg(&stubborn_script)
            .spawn()
            .expect("spawn stubborn python tray process");
        let stubborn_pid = stubborn_child.id();
        // Give Python 120ms to install SIG_IGN handler
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;

        let unapproved_kill = close_application_verified(&core, "stubborn-tray-app", false)
            .await
            .unwrap();
        assert_eq!(unapproved_kill["ok"], false, "res: {}", unapproved_kill);
        assert_eq!(unapproved_kill["requires_approval"], true);
        let surviving: Vec<u32> = unapproved_kill["surviving_pids"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u32))
            .collect();
        assert!(surviving.contains(&stubborn_pid));

        let approved_kill = close_application_verified(&core, "stubborn-tray-app", true)
            .await
            .unwrap();
        let _ = stubborn_child.wait();
        assert_eq!(approved_kill["ok"], true, "res: {}", approved_kill);
        assert_eq!(approved_kill["forced_kill"], true);

        // 5. User-customized software translation rules (`save_custom_adapter` & `delete_custom_adapter`)
        let saved = handle_module_rpc(
            &core,
            "save_custom_adapter",
            json!({
                "id": "betternotes-pro",
                "name": "BetterNotes Pro",
                "aliases": ["妙记Pro", "bnotes"],
                "binary_name": "betternotes-pro",
                "custom_actions": {
                    "quick_capture": {
                        "channel": "uri",
                        "command_or_target": "betternotes://capture?text={text}",
                        "requires_approval": false
                    },
                    "export_vault": {
                        "channel": "shortcut",
                        "command_or_target": "Ctrl+Shift+E",
                        "requires_approval": true
                    }
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(saved["ok"], true);

        let uri_out = translate_and_execute(
            &core,
            "妙记Pro",
            "quick_capture",
            &json!({ "text": "AIOS Wave 3" }),
            false,
        )
        .await
        .unwrap();
        assert!(uri_out.ok);
        assert_eq!(uri_out.channel_used, "uri_scheme");
        assert!(uri_out.translated_command.contains("betternotes://capture?text=AIOS%20Wave%203"));

        let gated_out = translate_and_execute(&core, "bnotes", "export_vault", &json!({}), false)
            .await
            .unwrap();
        assert!(!gated_out.ok);
        assert!(gated_out.requires_approval);
        assert!(gated_out.approval_scope.is_some());

        let deleted = handle_module_rpc(
            &core,
            "delete_custom_adapter",
            json!({ "id": "betternotes-pro" }),
        )
        .await
        .unwrap();
        assert_eq!(deleted["ok"], true);
        assert_eq!(deleted["deleted"], true);
    }

    #[tokio::test]
    async fn universal_live_inspector_chinese_aliases_and_tray_menu_approval_gate() {
        let (tmp, core, _) = setup_test_core();

        // 1. Verify Chinese alias expansion across domestic apps in `AdapterRegistry`
        let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
        let expected_pairs = [
            ("汽水音乐", "sodam"),
            ("QQ音乐", "qqmusic"),
            ("微信", "wechat"),
            ("飞书", "bytedance-feishu"),
            ("腾讯会议", "wemeetapp"),
            ("百度网盘", "baidunetdisk"),
            ("移动云盘", "mcloud"),
            ("轻笺", "betternotes"),
            ("代理", "flclash"),
            ("Clash", "flclash"),
            ("光铸", "discforge"),
            ("永中", "yozo"),
            ("WPS云盘", "wps-office"),
        ];
        for (zh_query, expected_id) in expected_pairs {
            let (prof, _) = reg.resolve_adapter_and_action(zh_query, "focus_window");
            assert_eq!(
                prof.id, expected_id,
                "expected `{}` -> `{}`, got `{}`",
                zh_query, expected_id, prof.id
            );
        }

        // 2. Verify bidirectional query <-> Pinyin matching against `.desktop` `Keywords=`
        let apps_dir = tmp.path().join("applications");
        std::fs::create_dir_all(&apps_dir).unwrap();
        let mock_note_desktop = "[Desktop Entry]\n\
            Type=Application\n\
            Name=CloudMemo\n\
            Name[zh_CN]=星云手账\n\
            Exec=/usr/bin/cloudmemo\n\
            Categories=Utility;\n\
            Keywords=云端速记;xingyun;\n";
        std::fs::write(apps_dir.join("cloudmemo.desktop"), mock_note_desktop).unwrap();
        clear_desktop_discovery_cache();

        // Pinyin query `"yunduansuji"` matches Chinese `Keywords=云端速记;`!
        let by_pinyin = handle_module_rpc(
            &core,
            "inspect_live_app",
            json!({ "app": "yunduansuji" }),
        )
        .await
        .unwrap();
        assert_eq!(by_pinyin["found"], true);
        assert_eq!(by_pinyin["app_id"], "cloudmemo");
        assert_eq!(by_pinyin["desktop_id"], "cloudmemo.desktop");

        // Chinese query `"星云"` matches ASCII `Keywords=xingyun;`!
        let by_chinese = execute_adapter_tool(
            &core,
            "app_adapter_inspect_app",
            &json!({ "app": "星云" }),
        )
        .await
        .unwrap();
        assert_eq!(by_chinese["found"], true);
        assert_eq!(by_chinese["app_id"], "cloudmemo");
        for required_key in [
            "found",
            "app_id",
            "name",
            "desktop_id",
            "exec_cmd",
            "is_running",
            "running_pids",
            "tray_bus",
            "mpris_bus",
            "desktop_actions",
            "atspi_controls",
            "custom_rules",
            "suggested_actions",
        ] {
            assert!(
                by_chinese.get(required_key).is_some(),
                "inspect_live_app missing key `{}` in {}",
                required_key,
                by_chinese
            );
        }

        // 3. Verify `list_live_tray_apps` ModuleRpc returns structured array
        let tray_list = handle_module_rpc(&core, "list_live_tray_apps", json!({}))
            .await
            .unwrap();
        assert!(tray_list["tray_apps"].is_array());

        // 4. Verify sensitive tray menu items (`"切换账号"`) require approval while normal items execute in dry_run
        let gated_tray = translate_and_execute(
            &core,
            "WPS云盘",
            "click_tray_menu",
            &json!({ "menu_label": "切换账号", "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(!gated_tray.ok);
        assert!(gated_tray.requires_approval);
        assert_eq!(gated_tray.channel_used, "sni_dbusmenu");

        let safe_tray = translate_and_execute(
            &core,
            "WPS云盘",
            "click_tray_menu",
            &json!({ "menu_label": "查看传输详情", "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(safe_tray.ok);
        assert!(!safe_tray.requires_approval);
        assert_eq!(safe_tray.channel_used, "sni_dbusmenu");
    }

    #[tokio::test]
    async fn wave5_deep_scanner_nine_categories_and_rich_domain_translators_end_to_end() {
        let (tmp, core, work_dir) = setup_test_core();

        // 1. Built-in curated profiles >= 55 across all 9 categories
        let reg = AdapterRegistry::builtin_only();
        assert!(
            reg.builtin_count() >= 55,
            "expected >= 55 curated built-in profiles, got {}",
            reg.builtin_count()
        );
        for cat in all_software_categories() {
            let matches = reg.list_filtered(None, Some(cat.id), None);
            assert!(
                !matches.is_empty(),
                "expected curated profiles for category `{}`",
                cat.id
            );
        }

        // 2. ModuleRpc `deep_scan_local_software`, `get_categorized_catalog` & `execute_desktop_action`
        let scan_dir = tmp.path().join("wave5_apps");
        std::fs::create_dir_all(&scan_dir).unwrap();
        std::fs::write(
            scan_dir.join("chrome-test.desktop"),
            "[Desktop Entry]\nType=Application\nName=Chrome Test\nName[zh_CN]=测试浏览器\nExec=/usr/bin/google-chrome %U\nActions=new-private-window;\n\n[Desktop Action new-private-window]\nName=Incognito\nName[zh_CN]=新建无痕窗口\nExec=/usr/bin/google-chrome --incognito %U\n",
        )
        .unwrap();

        let scan_res = handle_module_rpc(
            &core,
            "deep_scan_local_software",
            json!({
                "force_refresh": true,
                "scan_dirs": [scan_dir.to_string_lossy()]
            }),
        )
        .await
        .unwrap();
        assert_eq!(scan_res["total_scanned"], 1);
        assert_eq!(scan_res["categories"].as_array().unwrap().len(), 9);
        assert_eq!(scan_res["apps"][0]["category_id"], "network_browser");

        let cat_res = handle_module_rpc(
            &core,
            "get_categorized_catalog",
            json!({
                "category": "network_browser",
                "scan_dirs": [scan_dir.to_string_lossy()]
            }),
        )
        .await
        .unwrap();
        assert_eq!(cat_res["filtered_count"], 1);

        let exec_da = handle_module_rpc(
            &core,
            "execute_desktop_action",
            json!({
                "desktop_id": "chrome-test.desktop",
                "action_id": "new-private-window",
                "params": { "url": "https://example.org", "dry_run": true },
                "extra_dirs": [scan_dir.to_string_lossy()]
            }),
        )
        .await
        .unwrap();
        assert_eq!(exec_da["ok"], true);
        assert_eq!(exec_da["channel_used"], "desktop_action");
        assert!(
            exec_da["translated_command"]
                .as_str()
                .unwrap_or("")
                .contains("--incognito https://example.org")
        );

        // 3. Tencent Meeting (`wemeetapp`) `join_meeting` strips spaces/hyphens
        let wemeet_out = translate_and_execute(
            &core,
            "腾讯会议",
            "加入会议",
            &json!({ "meeting_code": "987-654-321", "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(wemeet_out.ok);
        assert_eq!(wemeet_out.channel_used, "uri_scheme");
        assert_eq!(
            wemeet_out.data["uri"],
            "wemeet://page/inmeeting?meeting_code=987654321"
        );

        // 4. QQMusic preserves `LIBGL_ALWAYS_SOFTWARE=1` when launching
        let qm_launch = translate_and_execute(
            &core,
            "QQ音乐",
            "launch_app",
            &json!({ "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(qm_launch.ok);
        assert!(
            qm_launch
                .translated_command
                .contains("LIBGL_ALWAYS_SOFTWARE=1")
        );

        // 5. Evince `open_pdf_page`, PDF Arranger, LocalSend `send_file`, Trae CN `goto_file_line` & `diff_two_files`
        let sample_pdf = work_dir.join("report.pdf");
        std::fs::write(&sample_pdf, "%PDF-1.4\n").unwrap();
        let ev_page = translate_and_execute(
            &core,
            "evince",
            "跳转pdf页码",
            &json!({ "path": sample_pdf.to_string_lossy(), "page": 12, "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(ev_page.ok);
        assert!(ev_page.translated_command.contains("--page-index=12"));

        let ls_send = translate_and_execute(
            &core,
            "LocalSend",
            "局域网传文件",
            &json!({ "path": sample_pdf.to_string_lossy(), "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(ls_send.ok);
        assert!(ls_send.translated_command.contains("localsend"));

        let file_a = work_dir.join("a.rs");
        let file_b = work_dir.join("b.rs");
        std::fs::write(&file_a, "fn a() {}\n").unwrap();
        std::fs::write(&file_b, "fn b() {}\n").unwrap();
        let trae_diff = translate_and_execute(
            &core,
            "Trae CN",
            "diff_two_files",
            &json!({
                "left": file_a.to_string_lossy(),
                "right": file_b.to_string_lossy(),
                "dry_run": true
            }),
            false,
        )
        .await
        .unwrap();
        assert!(trae_diff.ok);
        assert!(trae_diff.translated_command.contains("--diff"));

        // 6. Strict approval gating for VirtualBox `start_vm` and RustDesk `connect_peer`
        let vbox_unapproved = translate_and_execute(
            &core,
            "VirtualBox",
            "启动虚拟机",
            &json!({ "vm": "Ubuntu-Test", "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(!vbox_unapproved.ok);
        assert!(vbox_unapproved.requires_approval);
        assert!(vbox_unapproved.approval_scope.is_some());

        let vbox_approved = translate_and_execute(
            &core,
            "VirtualBox",
            "启动虚拟机",
            &json!({ "vm": "Ubuntu-Test", "dry_run": true }),
            true,
        )
        .await
        .unwrap();
        assert!(vbox_approved.ok);
        assert!(!vbox_approved.requires_approval);
        assert!(
            vbox_approved
                .translated_command
                .contains("VBoxManage startvm Ubuntu-Test --type gui")
        );

        let rd_unapproved = translate_and_execute(
            &core,
            "RustDesk",
            "发起远控",
            &json!({ "peer_id": "123 456 789", "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(!rd_unapproved.ok);
        assert!(rd_unapproved.requires_approval);

        let rd_approved = translate_and_execute(
            &core,
            "RustDesk",
            "发起远控",
            &json!({ "peer_id": "123 456 789", "dry_run": true }),
            true,
        )
        .await
        .unwrap();
        assert!(rd_approved.ok);
        assert!(
            rd_approved
                .translated_command
                .contains("rustdesk --connect 123456789")
        );

        // 7. FlClash probe, Fcitx5 status, NVIDIA telemetry, Nautilus `--select`
        let flclash_probe = translate_and_execute(
            &core,
            "FlClash",
            "探测代理状态",
            &json!({ "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(flclash_probe.ok);
        assert!(flclash_probe.data.get("open_ports").is_some());

        let fcitx_st = translate_and_execute(
            &core,
            "Fcitx5",
            "输入法状态",
            &json!({ "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(fcitx_st.ok);

        let gpu_tel = translate_and_execute(
            &core,
            "NVIDIA",
            "查询显存温度",
            &json!({ "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(gpu_tel.ok);

        let naut_sel = translate_and_execute(
            &core,
            "nautilus",
            "select_in_folder",
            &json!({ "path": sample_pdf.to_string_lossy(), "dry_run": true }),
            false,
        )
        .await
        .unwrap();
        assert!(naut_sel.ok);
        assert!(naut_sel.translated_command.contains("--select"));
    }
}
