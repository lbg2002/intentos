#![forbid(unsafe_code)]

//! Wave 2 Functional Module: Single Floating Quick-Chat AIOS Dialog (`crates/intentosd/src/web_ui/`)
//!
//! Redesigned after `gnome-quick-chat` (`✦ IntentOS · 随问`):
//! 1. Serves a single centered glassmorphic floating Quick-Chat AIOS dialog (`width: min(560px, 94vw); height: min(740px, 90vh)`)
//!    over a minimal desktop backdrop with zero dashboard clutter and 100% offline assets.
//! 2. Minimal Top Header with inline `▾` Quick Switcher (`自动 / ZCode / Codex / Pi / OpenAI API`, Provider & Model,
//!    Reasoning Effort `默认 / 快 / 标准 / 深入`, inline 0600 API Key setup), `📋` Clipboard Context, `🧠` Memory & Software
//!    Translation Layer Popover, `🕒` / `+` Session Switcher, `🔒` Incognito toggle, and `⚙` 11-Page Settings Modal.
//! 3. Streaming Markdown Chat Stream + `20px` Horizontal Colored `Trace Dots` (`thinking`, `memory`, `adapter`, `approval`,
//!    `tool_ok` with inline `↶ 撤销`, `tool_err`) + `@` inline mention menu for remembered files and controllable apps.

use crate::core::IntentOsCore;
use serde_json::{Value, json};
use std::path::Path;

const EMBEDDED_INDEX_HTML: &str = include_str!("assets/index.html");
const FALLBACK_HTML: &str = include_str!("../web_shell.html");

/// Required modular asset paths relative to `crates/intentosd/src/web_ui/assets/`.
pub const REQUIRED_STATIC_ASSETS: &[&str] = &[
    "styles/design-tokens.css",
    "styles/launcher-spotlight.css",
    "styles/workspace-surface.css",
    "styles/settings-center.css",
    "styles/quick-chat-dialog.css",
    "js/rpc-client.js",
    "js/markdown-renderer.js",
    "js/trace-dots.js",
    "js/memory-adapter-popover.js",
    "js/keyboard-engine.js",
    "js/candidate-view.js",
    "js/result-surfaces.js",
    "js/workspace-panel.js",
    "js/settings-11pages.js",
    "js/main.js",
];

/// Load modular `assets/index.html` from disk (for live reload) or embedded compile-time asset,
/// falling back to `web_shell.html` only if empty.
pub fn render_index_html(repo_root: &Path) -> String {
    let modular_index = repo_root.join("crates/intentosd/src/web_ui/assets/index.html");
    if let Ok(content) = std::fs::read_to_string(&modular_index)
        && !content.trim().is_empty()
    {
        return content;
    }
    if !EMBEDDED_INDEX_HTML.trim().is_empty() {
        return EMBEDDED_INDEX_HTML.to_string();
    }
    FALLBACK_HTML.to_string()
}

fn embedded_static_asset(rel_path: &str) -> Option<&'static [u8]> {
    match rel_path {
        "styles/design-tokens.css" => Some(include_bytes!("assets/styles/design-tokens.css")),
        "styles/launcher-spotlight.css" => {
            Some(include_bytes!("assets/styles/launcher-spotlight.css"))
        }
        "styles/workspace-surface.css" => {
            Some(include_bytes!("assets/styles/workspace-surface.css"))
        }
        "styles/settings-center.css" => Some(include_bytes!("assets/styles/settings-center.css")),
        "styles/quick-chat-dialog.css" => {
            Some(include_bytes!("assets/styles/quick-chat-dialog.css"))
        }
        "js/rpc-client.js" => Some(include_bytes!("assets/js/rpc-client.js")),
        "js/markdown-renderer.js" => Some(include_bytes!("assets/js/markdown-renderer.js")),
        "js/trace-dots.js" => Some(include_bytes!("assets/js/trace-dots.js")),
        "js/memory-adapter-popover.js" => {
            Some(include_bytes!("assets/js/memory-adapter-popover.js"))
        }
        "js/keyboard-engine.js" => Some(include_bytes!("assets/js/keyboard-engine.js")),
        "js/candidate-view.js" => Some(include_bytes!("assets/js/candidate-view.js")),
        "js/result-surfaces.js" => Some(include_bytes!("assets/js/result-surfaces.js")),
        "js/workspace-panel.js" => Some(include_bytes!("assets/js/workspace-panel.js")),
        "js/settings-11pages.js" => Some(include_bytes!("assets/js/settings-11pages.js")),
        "js/main.js" => Some(include_bytes!("assets/js/main.js")),
        _ => None,
    }
}

fn mime_for_path(rel_path: &str) -> &'static str {
    if rel_path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if rel_path.ends_with(".js") || rel_path.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if rel_path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if rel_path.ends_with(".svg") {
        "image/svg+xml"
    } else if rel_path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    }
}

/// Serve static modular CSS/JS assets from `crates/intentosd/src/web_ui/assets/<rel_path>`.
pub fn load_static_asset(repo_root: &Path, rel_path: &str) -> Option<(&'static str, Vec<u8>)> {
    if rel_path.contains("..") || rel_path.starts_with('/') || rel_path.contains('\\') {
        return None;
    }
    let mime = mime_for_path(rel_path);
    let full = repo_root
        .join("crates/intentosd/src/web_ui/assets")
        .join(rel_path);
    if let Ok(bytes) = std::fs::read(&full) {
        return Some((mime, bytes));
    }
    embedded_static_asset(rel_path).map(|b| (mime, b.to_vec()))
}

pub async fn handle_module_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    match action {
        "ping" => Ok(json!({
            "module": "web_ui",
            "status": "ready",
            "paradigm": "floating_quick_chat_dialog",
            "assets_count": REQUIRED_STATIC_ASSETS.len(),
            "payload": payload,
        })),
        "get_ui_manifest" => Ok(json!({
            "module": "web_ui",
            "version": "0.5.0-wave3",
            "paradigm": "floating_quick_chat_dialog",
            "modes": ["quick_chat", "spotlight", "workspace"],
            "trace_dots": ["thinking", "memory", "adapter", "approval", "tool_ok", "tool_err"],
            "security_modes": ["strict", "balanced", "developer"],
            "declarative_surfaces": [
                "ResourceListView",
                "ApprovalDiffCard",
                "DiagnosticCard",
                "TerminalOutputPanel",
                "TaskStepsView"
            ],
            "settings_pages_count": 11,
            "assets": REQUIRED_STATIC_ASSETS,
        })),
        "save_ui_layout" => {
            let view_mode = payload
                .get("view_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("quick_chat");
            Ok(json!({
                "saved": true,
                "view_mode": view_mode,
            }))
        }
        "get_ui_snapshot" => Ok(json!({
            "status": core.status(),
            "manifest": {
                "paradigm": "floating_quick_chat_dialog",
                "modes": ["quick_chat", "spotlight", "workspace"],
                "settings_pages": 11,
            }
        })),
        other => anyhow::bail!("web_ui: unknown action '{}'", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .parent()
            .expect("repo root")
            .to_path_buf()
    }

    #[test]
    fn test_render_index_html_loads_floating_quick_chat_and_is_100_percent_offline() {
        let root = test_repo_root();
        let html = render_index_html(&root);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("/assets/styles/design-tokens.css"));
        assert!(html.contains("/assets/styles/quick-chat-dialog.css"));
        assert!(html.contains("/assets/styles/settings-center.css"));
        assert!(html.contains("/assets/js/main.js"));

        // Single floating Quick-Chat AIOS dialog & key controls
        assert!(html.contains("id=\"quick-chat-dialog\""));
        assert!(html.contains("✦ IntentOS · 随问"));
        assert!(html.contains("id=\"qc-engine-strip\""));
        assert!(html.contains("id=\"qc-memory-popover\""));
        assert!(html.contains("id=\"qc-sessions-popover\""));
        assert!(html.contains("id=\"qc-mention-menu\""));

        // 4 Smart AIOS Quick-Starter Pills
        assert!(html.contains("我最近和长期常用的文件有哪些？"));
        assert!(html.contains("我电脑上装了哪些常用软件？"));
        assert!(html.contains("用转译层查看或控制当前音乐播放"));
        assert!(html.contains("屏幕太亮了，帮我调暗并开启护眼"));

        // Hidden Settings Modal & Undo Toast preserved
        assert!(html.contains("action-menu-popover"));
        assert!(html.contains("undo-toast-banner"));
        assert!(html.contains("settings-sidebar-nav"));

        // Verify zero external CDN links in <script>/<link>/<img> tags (100% offline capable)
        for line in html.lines() {
            let trimmed = line.trim().to_ascii_lowercase();
            if trimmed.starts_with("<script")
                || trimmed.starts_with("<link")
                || trimmed.starts_with("<img")
            {
                assert!(
                    !trimmed.contains("http://") && !trimmed.contains("https://"),
                    "External resource forbidden in offline UI tag: {}",
                    line
                );
            }
        }
        assert!(!html.contains("https://cdn."));
        assert!(!html.contains("http://cdn."));
        assert!(!html.contains("unpkg.com"));
        assert!(!html.contains("jsdelivr.net"));
        assert!(!html.contains("cdnjs.cloudflare.com"));
    }

    #[test]
    fn test_all_required_css_and_js_assets_exist_with_valid_mime_types() {
        let root = test_repo_root();
        for &rel_path in REQUIRED_STATIC_ASSETS {
            let loaded = load_static_asset(&root, rel_path);
            assert!(
                loaded.is_some(),
                "Expected static asset '{}' to exist on disk",
                rel_path
            );
            let embedded = embedded_static_asset(rel_path);
            assert!(
                embedded.is_some(),
                "Expected static asset '{}' to be embedded at compile time",
                rel_path
            );
            let (mime, bytes) = loaded.unwrap();
            assert!(
                !bytes.is_empty(),
                "Expected static asset '{}' to be non-empty",
                rel_path
            );
            if rel_path.ends_with(".css") {
                assert_eq!(mime, "text/css; charset=utf-8");
            } else if rel_path.ends_with(".js") {
                assert_eq!(mime, "application/javascript; charset=utf-8");
            }
        }
    }

    #[test]
    fn test_quick_chat_dialog_dimensions_and_trace_dots_contract() {
        let root = test_repo_root();
        let (_, css_bytes) = load_static_asset(&root, "styles/quick-chat-dialog.css")
            .expect("quick-chat-dialog.css");
        let css = String::from_utf8(css_bytes).expect("utf8 css");
        assert!(css.contains("width: min(560px, 94vw)"));
        assert!(css.contains("height: min(740px, 90vh)"));
        assert!(css.contains("border-radius: 20px"));
        assert!(css.contains("height: 20px"));

        let (_, dots_bytes) = load_static_asset(&root, "js/trace-dots.js").expect("trace-dots.js");
        let dots_js = String::from_utf8(dots_bytes).expect("utf8 trace-dots.js");
        for kind in [
            "thinking", "memory", "adapter", "approval", "tool_ok", "tool_err",
        ] {
            assert!(
                dots_js.contains(kind),
                "Expected trace-dots.js to support '{}' dot",
                kind
            );
        }
        assert!(dots_js.contains("批准本次"));
        assert!(dots_js.contains("本会话放行该范围"));
        assert!(dots_js.contains("本会话放行此范围"));
        assert!(dots_js.contains("拒绝"));
        assert!(dots_js.contains("↶ 撤销"));
        assert!(dots_js.contains("qc-trace-more-pill"));
    }

    #[test]
    fn test_wave3_live_models_security_approval_outlines_and_light_dark_theme_contracts() {
        let root = test_repo_root();
        let html = render_index_html(&root);

        // 1. Live `/v1/models` refresh button & searchable scrollable model picker
        assert!(html.contains("id=\"btn-refresh-models\""));
        assert!(html.contains("↻ 刷新接口模型"));
        assert!(html.contains("id=\"qc-model-search\""));
        assert!(html.contains("搜索模型 (共"));
        assert!(html.contains("id=\"qc-model-picker-list\""));

        // 2. Security posture header pill (`🛡`) & explicit `◑` Dark/Light theme toggle
        assert!(html.contains("id=\"btn-security-pill\""));
        assert!(html.contains("id=\"qc-security-popover\""));
        assert!(html.contains("id=\"btn-header-theme-toggle\""));
        assert!(html.contains("prefers-color-scheme"));
        assert!(html.contains("localStorage"));

        let (_, css_bytes) = load_static_asset(&root, "styles/quick-chat-dialog.css")
            .expect("quick-chat-dialog.css");
        let css = String::from_utf8(css_bytes).expect("utf8 css");
        assert!(css.contains("max-height: 190px"));
        assert!(css.contains("overflow-y: auto"));
        assert!(css.contains("[data-theme=\"light\"]"));

        // 3. `main.js` wires live `/v1/models`, security posture, and scoped approval RPCs
        let (_, main_bytes) = load_static_asset(&root, "js/main.js").expect("main.js");
        let main_js = String::from_utf8(main_bytes).expect("utf8 main.js");
        assert!(main_js.contains("refresh_models"));
        assert!(main_js.contains("get_backends_catalog"));
        assert!(main_js.contains("refresh_remote"));
        assert!(main_js.contains("get_security_posture"));
        assert!(main_js.contains("set_security_mode"));
        assert!(main_js.contains("grant_session_scope"));
        assert!(main_js.contains("revoke_session_grant"));
        assert!(main_js.contains("已拒绝执行"));

        // 4. `memory-adapter-popover.js` & `settings-11pages.js` wire document outlines & personal apps
        let (_, mem_bytes) = load_static_asset(&root, "js/memory-adapter-popover.js")
            .expect("memory-adapter-popover.js");
        let mem_js = String::from_utf8(mem_bytes).expect("utf8 mem_js");
        assert!(mem_js.contains("document_outlines_preview"));
        assert!(mem_js.contains("inspect_document"));
        assert!(mem_js.contains("discover_personal_apps"));

        let (_, cfg_bytes) =
            load_static_asset(&root, "js/settings-11pages.js").expect("settings-11pages.js");
        let cfg_js = String::from_utf8(cfg_bytes).expect("utf8 cfg_js");
        assert!(cfg_js.contains("refresh_models"));
        assert!(cfg_js.contains("set_security_mode"));
        assert!(cfg_js.contains("discover_personal_apps"));
        assert!(cfg_js.contains("save_custom_adapter"));
        assert!(cfg_js.contains("delete_custom_adapter"));
        assert!(cfg_js.contains("close_app_verified"));
    }

    #[test]
    fn test_wave4_honest_unverified_dots_and_live_tray_adapter_workbench_contracts() {
        let root = test_repo_root();

        let (_, css_bytes) = load_static_asset(&root, "styles/quick-chat-dialog.css")
            .expect("quick-chat-dialog.css");
        let css = String::from_utf8(css_bytes).expect("utf8 css");
        assert!(css.contains(".dot-blue"));
        assert!(css.contains("#38bdf8"));
        assert!(css.contains("#10b981"));
        assert!(css.contains("#ef4444"));
        assert!(css.contains(".qc-channel-pill.unverified"));

        let (_, dots_bytes) = load_static_asset(&root, "js/trace-dots.js").expect("trace-dots.js");
        let dots_js = String::from_utf8(dots_bytes).expect("utf8 trace-dots.js");
        assert!(dots_js.contains("tool_unverified"));
        assert!(dots_js.contains("RequestedUnverified"));
        assert!(dots_js.contains("simulated"));
        assert!(dots_js.contains("已发送请求（待桌面响应）"));

        let (_, mem_bytes) = load_static_asset(&root, "js/memory-adapter-popover.js")
            .expect("memory-adapter-popover.js");
        let mem_js = String::from_utf8(mem_bytes).expect("utf8 mem_js");
        assert!(mem_js.contains("list_live_tray_apps"));
        assert!(mem_js.contains("inspect_live_app"));
        assert!(mem_js.contains("trigger_tray_menu"));
        assert!(mem_js.contains("探测接口"));

        let (_, cfg_bytes) =
            load_static_asset(&root, "js/settings-11pages.js").expect("settings-11pages.js");
        let cfg_js = String::from_utf8(cfg_bytes).expect("utf8 cfg_js");
        assert!(cfg_js.contains("5. 本机软件深度扫描与分类转译中心"));
        assert!(cfg_js.contains("list_live_tray_apps"));
        assert!(cfg_js.contains("inspect_live_app"));
        assert!(cfg_js.contains("trigger_tray_menu"));
        assert!(cfg_js.contains("深度探测该软件可转译能力"));
        assert!(cfg_js.contains("填入自定义转译规则表单"));
    }

    #[test]
    fn test_wave5_approval_continuation_deep_scan_context_decay_and_asr_speech_contracts() {
        let root = test_repo_root();

        let (_, html_bytes) = load_static_asset(&root, "index.html").expect("index.html");
        let html = String::from_utf8(html_bytes).expect("utf8 html");
        assert!(html.contains("id=\"btn-voice-input\""));
        assert!(html.contains("id=\"qc-voice-banner\""));

        let (_, css_bytes) = load_static_asset(&root, "styles/quick-chat-dialog.css")
            .expect("quick-chat-dialog.css");
        let css = String::from_utf8(css_bytes).expect("utf8 css");
        assert!(css.contains(".qc-btn-approve:disabled"));
        assert!(css.contains(".qc-btn-scope:disabled"));
        assert!(css.contains(".qc-btn-deny:disabled"));
        assert!(css.contains("opacity: 0.48"));
        assert!(css.contains(".qc-mic-recording"));
        assert!(css.contains(".qc-approval-resolved-card"));

        let (_, dots_bytes) = load_static_asset(&root, "js/trace-dots.js").expect("trace-dots.js");
        let dots_js = String::from_utf8(dots_bytes).expect("utf8 trace-dots.js");
        assert!(dots_js.contains("正在执行并继续会话推理"));
        assert!(dots_js.contains("敏感权限已批准 · 已继续会话"));
        assert!(dots_js.contains("已放行本会话范围 · 已继续会话"));
        assert!(dots_js.contains("已拒绝执行该敏感操作"));

        let (_, main_bytes) = load_static_asset(&root, "js/main.js").expect("main.js");
        let main_js = String::from_utf8(main_bytes).expect("utf8 main.js");
        assert!(main_js.contains("resume_approved_turn"));
        assert!(main_js.contains("context_compression"));
        assert!(main_js.contains("speech_hub"));
        assert!(main_js.contains("get_speech_overview"));
        assert!(main_js.contains("start_recording"));
        assert!(main_js.contains("stop_and_transcribe"));
        assert!(main_js.contains("cancel_recording"));
        assert!(main_js.contains("打开语音识别模型下载与开关设置"));

        let (_, cfg_bytes) =
            load_static_asset(&root, "js/settings-11pages.js").expect("settings-11pages.js");
        let cfg_js = String::from_utf8(cfg_bytes).expect("utf8 cfg_js");
        assert!(cfg_js.contains("5. 本机软件深度扫描与分类转译中心"));
        assert!(cfg_js.contains("deep_scan_local_software"));
        assert!(cfg_js.contains("execute_desktop_action"));
        for cat in [
            "media_entertainment",
            "social_collab",
            "office_notes_doc",
            "cloud_transfer",
            "network_browser",
            "dev_ai_ide",
            "creative_disc",
            "remote_vm",
            "hardware_system",
        ] {
            assert!(cfg_js.contains(cat), "missing 9-category id: {}", cat);
        }
        assert!(cfg_js.contains("get_context_compression_config"));
        assert!(cfg_js.contains("set_context_compression_config"));
        assert!(cfg_js.contains("本地离线语音识别 (ASR) 与模型下载中心"));
        assert!(cfg_js.contains("download_model"));
        assert!(cfg_js.contains("get_download_progress"));
        assert!(cfg_js.contains("cancel_download"));
        assert!(cfg_js.contains("delete_model"));

        let (_, mem_bytes) = load_static_asset(&root, "js/memory-adapter-popover.js")
            .expect("memory-adapter-popover.js");
        let mem_js = String::from_utf8(mem_bytes).expect("utf8 mem_js");
        assert!(mem_js.contains("deep_scan_local_software"));
        assert!(mem_js.contains("preview_session_compression"));
    }

    #[test]
    fn test_static_asset_loader_blocks_path_traversal() {
        let root = test_repo_root();
        assert!(load_static_asset(&root, "../mod.rs").is_none());
        assert!(load_static_asset(&root, "../../Cargo.toml").is_none());
        assert!(load_static_asset(&root, "/etc/passwd").is_none());
        assert!(load_static_asset(&root, "styles\\..\\mod.rs").is_none());
    }
}
