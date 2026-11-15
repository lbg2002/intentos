#![forbid(unsafe_code)]

//! Multi-Turn Context, Deictic & Comparative Resource Resolver (`context_resolver.rs`, `M2-B`).
//!
//! Resolves conversational pronouns (`它`, `刚才那个文件`, `这些文件`, `我之前说的那个文件`),
//! foreground desktop deictics (`把它关掉`, `当前窗口`, `选中文本`, `剪贴板`), and comparative
//! temporal/version references (`比较昨天与前天的实验结果`, `对比两个版本`) using:
//! - [`SessionState`] (`last_resource_path` & message history),
//! - [`WorldStateTracker`] / [`ResourceResolver`] (with Wayland compositor isolation honesty & `15s` focus TTL),
//! - [`StateDb`] & `memory_hub` (strictly gated on `PrivacySessionPolicy::allows_memory_read()`).
//!
//! Never blind-guesses when foreground focus is `Unavailable` on Wayland or when multiple candidates compete.

use crate::db::StateDb;
use crate::runtime::SessionState;
use crate::security_guard::PrivacySessionPolicy;
use crate::world_state::{
    ResourceResolution, ResourceResolver, StateField, WorldStateSnapshot,
    is_close_or_active_window_deictic, is_comparative_query, is_conversational_resource_deictic,
};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Snapshot of the user's current desktop environment passed alongside an intent query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesktopContext {
    #[serde(default)]
    pub active_window: Option<String>,
    #[serde(default)]
    pub selected_text: Option<String>,
    #[serde(default)]
    pub clipboard_text: Option<String>,
    #[serde(default)]
    pub selected_files: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
}

impl DesktopContext {
    /// Project a privacy-filtered [`WorldStateSnapshot`] into `DesktopContext`.
    /// When `desktop.active_window` is `StateField::Unavailable` (e.g. `wayland_compositor_isolated`),
    /// `active_window` remains `None` — never fabricating focus!
    pub fn from_world_state(snapshot: &WorldStateSnapshot) -> Self {
        let active_window = match &snapshot.desktop.active_window {
            StateField::Available { value, .. } => value
                .app_id
                .clone()
                .or_else(|| value.wm_class.clone())
                .or_else(|| {
                    let t = value.title.trim();
                    (!t.is_empty()).then(|| t.to_string())
                }),
            StateField::Unavailable { .. } => None,
        };
        Self {
            active_window,
            selected_text: None,
            clipboard_text: None,
            selected_files: Vec::new(),
            cwd: snapshot
                .active_cwd
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
        }
    }
}

/// Result of resolving pronouns and desktop context references in user input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ContextResolutionOutcome {
    /// Input contained no pronouns or context references requiring substitution.
    Unchanged { text: String },
    /// Pronoun, comparative reference, or desktop target was unambiguously resolved.
    Resolved {
        original_text: String,
        rewritten_text: String,
        matched_reference: String,
        resolved_targets: Vec<String>,
        source: String,
    },
    /// Pronoun was detected, but either multiple competing referents exist or foreground state is unavailable.
    NeedsClarification {
        original_text: String,
        matched_reference: String,
        prompt: String,
        candidate_targets: Vec<String>,
    },
}

impl ContextResolutionOutcome {
    /// Return the effective text to feed into downstream routing.
    pub fn effective_text(&self) -> &str {
        match self {
            Self::Unchanged { text } => text,
            Self::Resolved { rewritten_text, .. } => rewritten_text,
            Self::NeedsClarification { original_text, .. } => original_text,
        }
    }

    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved { .. })
    }

    pub fn needs_clarification(&self) -> bool {
        matches!(self, Self::NeedsClarification { .. })
    }
}

/// Resolve deictic, comparative, and conversational references backed by [`ResourceResolver`] and [`WorldStateTracker`] (`M2-B`).
pub fn resolve_context_with_world_state(
    raw_text: &str,
    resolver: &ResourceResolver<'_>,
    session: Option<&SessionState>,
    state_db: Option<&StateDb>,
    desktop_ctx: Option<&DesktopContext>,
    privacy: PrivacySessionPolicy,
) -> ContextResolutionOutcome {
    resolve_context_with_world_state_at(
        Utc::now(),
        raw_text,
        resolver,
        session,
        state_db,
        desktop_ctx,
        privacy,
    )
}

/// Clock-injectable variant of [`resolve_context_with_world_state`] for deterministic TTL testing (`M2-B`).
pub fn resolve_context_with_world_state_at(
    now: DateTime<Utc>,
    raw_text: &str,
    resolver: &ResourceResolver<'_>,
    session: Option<&SessionState>,
    state_db: Option<&StateDb>,
    desktop_ctx: Option<&DesktopContext>,
    privacy: PrivacySessionPolicy,
) -> ContextResolutionOutcome {
    let trimmed = raw_text.trim();
    if trimmed.is_empty() {
        return ContextResolutionOutcome::Unchanged {
            text: String::new(),
        };
    }

    let allowed_state_db = if privacy.allows_memory_read() {
        state_db
    } else {
        None
    };

    // 1. Close / active-window deictic (`"把它关掉"`, `"关闭当前窗口"`, `"关掉它"`)
    if is_close_or_active_window_deictic(trimmed) {
        let resolution = resolver.resolve_at(now, trimmed, None, session, privacy);
        return match resolution {
            ResourceResolution::Single(rref) => {
                let target = rref
                    .metadata
                    .get("app_id")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| rref.path.as_ref().map(|p| p.to_string_lossy().to_string()))
                    .unwrap_or_else(|| rref.display_name.clone());
                let rewritten = rewrite_close_deictic_text(trimmed, &target);
                ContextResolutionOutcome::Resolved {
                    original_text: trimmed.to_string(),
                    rewritten_text: rewritten,
                    matched_reference: extract_close_deictic_token(trimmed).to_string(),
                    resolved_targets: vec![target],
                    source: rref.source,
                }
            }
            ResourceResolution::Ambiguous {
                candidates,
                clarification_prompt,
                ..
            } => {
                let cand_targets = candidates
                    .into_iter()
                    .map(|c| {
                        c.metadata
                            .get("app_id")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .unwrap_or(c.display_name)
                    })
                    .collect();
                ContextResolutionOutcome::NeedsClarification {
                    original_text: trimmed.to_string(),
                    matched_reference: extract_close_deictic_token(trimmed).to_string(),
                    prompt: clarification_prompt,
                    candidate_targets: cand_targets,
                }
            }
            ResourceResolution::Unavailable { reason, .. } => {
                ContextResolutionOutcome::NeedsClarification {
                    original_text: trimmed.to_string(),
                    matched_reference: extract_close_deictic_token(trimmed).to_string(),
                    prompt: format!(
                        "当前无法确认要关闭的前台窗口（{}），请直接说明要关闭的应用名称。",
                        reason
                    ),
                    candidate_targets: Vec::new(),
                }
            }
            ResourceResolution::NotFound { .. } => ContextResolutionOutcome::NeedsClarification {
                original_text: trimmed.to_string(),
                matched_reference: extract_close_deictic_token(trimmed).to_string(),
                prompt: "未找到可关闭的目标应用或窗口，请明确指定应用名称。".to_string(),
                candidate_targets: Vec::new(),
            },
            ResourceResolution::MultipleComparative(_) => ContextResolutionOutcome::Unchanged {
                text: trimmed.to_string(),
            },
        };
    }

    // 2. Comparative temporal / version queries (`"比较昨天与前天的实验结果"`, `"对比两个版本"`)
    if is_comparative_query(trimmed) {
        let resolution = resolver.resolve_at(now, trimmed, None, session, privacy);
        match resolution {
            ResourceResolution::MultipleComparative(refs) if refs.len() >= 2 => {
                let targets: Vec<String> = refs
                    .iter()
                    .map(|r| {
                        r.path
                            .as_ref()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|| r.uri.clone())
                    })
                    .collect();
                let rewritten = format!("{} [{}]", trimmed, targets.join(" , "));
                return ContextResolutionOutcome::Resolved {
                    original_text: trimmed.to_string(),
                    rewritten_text: rewritten,
                    matched_reference: "comparative_resources".to_string(),
                    resolved_targets: targets,
                    source: "resource_resolver.comparative".to_string(),
                };
            }
            ResourceResolution::Ambiguous {
                candidates,
                clarification_prompt,
                ..
            } => {
                let cand_targets = candidates
                    .into_iter()
                    .map(|c| {
                        c.path
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or(c.display_name)
                    })
                    .collect();
                return ContextResolutionOutcome::NeedsClarification {
                    original_text: trimmed.to_string(),
                    matched_reference: "comparative_resources".to_string(),
                    prompt: clarification_prompt,
                    candidate_targets: cand_targets,
                };
            }
            _ => {}
        }
    }

    // 3. Conversational file/document deictics (`"打开刚才那个文件"`, `"我之前说的那个文件"`)
    if is_conversational_resource_deictic(trimmed) {
        let resolution = resolver.resolve_at(now, trimmed, None, session, privacy);
        match resolution {
            ResourceResolution::Single(rref) => {
                let target = rref
                    .path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| rref.display_name.clone());
                let matched_tok = match_conversational_token(trimmed);
                let rewritten = if !matched_tok.is_empty() && trimmed.contains(matched_tok) {
                    trimmed.replacen(matched_tok, &target, 1)
                } else {
                    format!("{} {}", trimmed, target)
                };
                return ContextResolutionOutcome::Resolved {
                    original_text: trimmed.to_string(),
                    rewritten_text: rewritten,
                    matched_reference: matched_tok.to_string(),
                    resolved_targets: vec![target],
                    source: rref.source,
                };
            }
            ResourceResolution::Ambiguous {
                candidates,
                clarification_prompt,
                ..
            } => {
                let cand_targets = candidates
                    .into_iter()
                    .map(|c| {
                        c.path
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or(c.display_name)
                    })
                    .collect();
                return ContextResolutionOutcome::NeedsClarification {
                    original_text: trimmed.to_string(),
                    matched_reference: match_conversational_token(trimmed).to_string(),
                    prompt: clarification_prompt,
                    candidate_targets: cand_targets,
                };
            }
            ResourceResolution::Unavailable { reason, .. } => {
                return ContextResolutionOutcome::NeedsClarification {
                    original_text: trimmed.to_string(),
                    matched_reference: match_conversational_token(trimmed).to_string(),
                    prompt: format!(
                        "当前会话无法读取所指代的历史资源（{}），请直接提供文件名或路径。",
                        reason
                    ),
                    candidate_targets: Vec::new(),
                };
            }
            _ => {}
        }
    }

    // 4. Fallback to classic pronoun & explicit DesktopContext resolution (only sample WorldState on demand)
    let snap_dctx;
    let needs_desktop_snap = [
        "当前窗口",
        "这个窗口",
        "活动窗口",
        "选中",
        "剪贴板",
        "当前目录",
        "它",
        "这个",
        "那个",
        "刚才",
        "上次",
        "刚下载",
    ]
    .iter()
    .any(|p| trimmed.contains(p));
    let effective_dctx = match desktop_ctx {
        Some(d) => Some(d),
        None if needs_desktop_snap => {
            let snap = resolver
                .world_state()
                .snapshot_at(now, None, None, session, privacy);
            snap_dctx = DesktopContext::from_world_state(&snap);
            Some(&snap_dctx)
        }
        None => None,
    };

    resolve_context_references(trimmed, session, allowed_state_db, effective_dctx)
}

/// Resolve structured [`ResourceResolution`] directly for deictic or comparative user inputs (`M2-B`).
pub fn resolve_deictic_resource(
    raw_text: &str,
    resolver: &ResourceResolver<'_>,
    session: Option<&SessionState>,
    privacy: PrivacySessionPolicy,
) -> Option<ResourceResolution> {
    let trimmed = raw_text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_close_or_active_window_deictic(trimmed)
        || is_comparative_query(trimmed)
        || is_conversational_resource_deictic(trimmed)
    {
        Some(resolver.resolve(trimmed, None, session, privacy))
    } else {
        None
    }
}

/// Resolve pronouns and desktop context references in `raw_text`.
pub fn resolve_context_references(
    raw_text: &str,
    session: Option<&SessionState>,
    state_db: Option<&StateDb>,
    desktop_ctx: Option<&DesktopContext>,
) -> ContextResolutionOutcome {
    let trimmed = raw_text.trim();
    if trimmed.is_empty() {
        return ContextResolutionOutcome::Unchanged {
            text: String::new(),
        };
    }

    // 1. Desktop context explicit references (`当前窗口`, `选中文本`, `剪贴板`)
    if let Some(dctx) = desktop_ctx {
        for phrase in ["当前窗口", "这个窗口", "活动窗口"] {
            if trimmed.contains(phrase) {
                if let Some(win) = dctx.active_window.as_ref().filter(|s| !s.trim().is_empty()) {
                    let rewritten = trimmed.replace(phrase, win.trim());
                    return ContextResolutionOutcome::Resolved {
                        original_text: trimmed.to_string(),
                        rewritten_text: rewritten,
                        matched_reference: phrase.to_string(),
                        resolved_targets: vec![win.trim().to_string()],
                        source: "desktop_context.active_window".to_string(),
                    };
                } else {
                    return ContextResolutionOutcome::NeedsClarification {
                        original_text: trimmed.to_string(),
                        matched_reference: phrase.to_string(),
                        prompt: format!(
                            "您提到了「{}」，但当前未检测到活动窗口名称，请指定目标应用或窗口。",
                            phrase
                        ),
                        candidate_targets: Vec::new(),
                    };
                }
            }
        }

        // Support foreground close deictic (`把它关掉` / `关掉它` / `关闭它`) via verified `dctx.active_window`
        // when no session file target or selected files override it.
        if is_close_or_active_window_deictic(trimmed)
            && dctx.selected_files.is_empty()
            && session
                .and_then(|s| s.last_resource_path.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_none()
            && let Some(win) = dctx.active_window.as_ref().filter(|s| !s.trim().is_empty())
        {
            let target = win.trim().to_string();
            let rewritten = rewrite_close_deictic_text(trimmed, &target);
            return ContextResolutionOutcome::Resolved {
                original_text: trimmed.to_string(),
                rewritten_text: rewritten,
                matched_reference: extract_close_deictic_token(trimmed).to_string(),
                resolved_targets: vec![target],
                source: "desktop_context.active_window".to_string(),
            };
        }

        for phrase in [
            "选中的文本",
            "选中文本",
            "选中的文字",
            "选中文字",
            "选中的内容",
        ] {
            if trimmed.contains(phrase) {
                if let Some(sel) = dctx.selected_text.as_ref().filter(|s| !s.trim().is_empty()) {
                    let rewritten = trimmed.replace(phrase, sel.trim());
                    return ContextResolutionOutcome::Resolved {
                        original_text: trimmed.to_string(),
                        rewritten_text: rewritten,
                        matched_reference: phrase.to_string(),
                        resolved_targets: vec![sel.trim().to_string()],
                        source: "desktop_context.selected_text".to_string(),
                    };
                } else {
                    return ContextResolutionOutcome::NeedsClarification {
                        original_text: trimmed.to_string(),
                        matched_reference: phrase.to_string(),
                        prompt: format!("您提到了「{}」，但当前没有选中的文本内容。", phrase),
                        candidate_targets: Vec::new(),
                    };
                }
            }
        }

        let is_clipboard_destination_or_clear = [
            "复制到剪贴板",
            "拷贝到剪贴板",
            "拷到剪贴板",
            "写入剪贴板",
            "写到剪贴板",
            "放到剪贴板",
            "存入剪贴板",
            "发到剪贴板",
            "到剪贴板",
            "进剪贴板",
            "清空剪贴板",
        ]
        .iter()
        .any(|pat| trimmed.contains(pat));

        for phrase in [
            "剪贴板里的内容",
            "剪贴板中的内容",
            "剪贴板内容",
            "剪贴板里的文字",
            "剪贴板",
        ] {
            if phrase == "剪贴板" && is_clipboard_destination_or_clear {
                continue;
            }
            if trimmed.contains(phrase) {
                if let Some(clip) = dctx
                    .clipboard_text
                    .as_ref()
                    .filter(|s| !s.trim().is_empty())
                {
                    let rewritten = trimmed.replace(phrase, clip.trim());
                    return ContextResolutionOutcome::Resolved {
                        original_text: trimmed.to_string(),
                        rewritten_text: rewritten,
                        matched_reference: phrase.to_string(),
                        resolved_targets: vec![clip.trim().to_string()],
                        source: "desktop_context.clipboard_text".to_string(),
                    };
                } else {
                    return ContextResolutionOutcome::NeedsClarification {
                        original_text: trimmed.to_string(),
                        matched_reference: phrase.to_string(),
                        prompt: format!("您提到了「{}」，但当前剪贴板为空。", phrase),
                        candidate_targets: Vec::new(),
                    };
                }
            }
        }
    }

    // Gather candidate resource paths from session, desktop_ctx, and state_db
    let (primary_target, recent_targets, source_label) =
        collect_recent_targets(session, state_db, desktop_ctx);

    // 2. Check plural pronouns (`这些文件`, `刚才那些文件`, `刚才搜出来的文件`, `它们`)
    let plural_pronouns = [
        "刚才搜出来的文件",
        "刚才找到的文件",
        "刚才那些文件",
        "选中的文件",
        "这些文件",
        "那些文件",
        "它们",
    ];
    for pro in plural_pronouns {
        if trimmed.contains(pro) {
            if recent_targets.is_empty() {
                return ContextResolutionOutcome::NeedsClarification {
                    original_text: trimmed.to_string(),
                    matched_reference: pro.to_string(),
                    prompt: format!(
                        "您提到了「{}」，但当前会话中没有最近操作或搜索到的文件记录，请先搜索或指定文件路径。",
                        pro
                    ),
                    candidate_targets: Vec::new(),
                };
            }
            let joined = recent_targets.join(" ");
            let rewritten = trimmed.replace(pro, &joined);
            return ContextResolutionOutcome::Resolved {
                original_text: trimmed.to_string(),
                rewritten_text: rewritten,
                matched_reference: pro.to_string(),
                resolved_targets: recent_targets,
                source: source_label,
            };
        }
    }

    // 3. Check singular pronouns (`刚才那个文件`, `刚才的文件`, `上一个文件`, `上一个结果`, `刚才那个`, `这个文件`, `那份文件`, `它`)
    // Ordered longest-first so `刚才那个文件` matches before `它`.
    let singular_pronouns = [
        "我之前说的那个文件",
        "之前说的那个文件",
        "上次提到的文档",
        "上次提到的文件",
        "刚才那个文件",
        "刚才那份文件",
        "刚才改的文件",
        "刚才改的配置",
        "刚才的文件",
        "上一个文件",
        "上一个结果",
        "刚才那个",
        "这个文件",
        "那个文件",
        "那份文件",
        "这份文件",
        "它",
    ];

    for pro in singular_pronouns {
        if contains_pronoun_token(trimmed, pro) {
            if let Some(primary) = primary_target {
                let rewritten = trimmed.replacen(pro, &primary, 1);
                return ContextResolutionOutcome::Resolved {
                    original_text: trimmed.to_string(),
                    rewritten_text: rewritten,
                    matched_reference: pro.to_string(),
                    resolved_targets: vec![primary],
                    source: source_label,
                };
            } else if recent_targets.len() == 1 {
                let target = recent_targets[0].clone();
                let rewritten = trimmed.replacen(pro, &target, 1);
                return ContextResolutionOutcome::Resolved {
                    original_text: trimmed.to_string(),
                    rewritten_text: rewritten,
                    matched_reference: pro.to_string(),
                    resolved_targets: vec![target],
                    source: source_label,
                };
            } else if recent_targets.len() > 1 {
                return ContextResolutionOutcome::NeedsClarification {
                    original_text: trimmed.to_string(),
                    matched_reference: pro.to_string(),
                    prompt: format!(
                        "您提到的「{}」可能指代以下多个目标，请确认要操作哪一个：",
                        pro
                    ),
                    candidate_targets: recent_targets,
                };
            } else {
                return ContextResolutionOutcome::NeedsClarification {
                    original_text: trimmed.to_string(),
                    matched_reference: pro.to_string(),
                    prompt: format!(
                        "您提到了「{}」，但当前上下文中没有可指代的目标文件或资源，请明确指定名称或路径。",
                        pro
                    ),
                    candidate_targets: Vec::new(),
                };
            }
        }
    }

    ContextResolutionOutcome::Unchanged {
        text: trimmed.to_string(),
    }
}

fn rewrite_close_deictic_text(trimmed: &str, target: &str) -> String {
    for full_phrase in [
        "把它关掉",
        "把它关闭",
        "把它关了",
        "把它退出",
        "将它关掉",
        "将它关闭",
        "关掉它",
        "关闭它",
        "退出它",
        "把这个软件关掉",
        "关掉这个软件",
        "关闭这个软件",
        "把这个应用关掉",
        "关掉这个应用",
        "关闭这个应用",
    ] {
        if trimmed == full_phrase {
            return format!("关闭 {}", target);
        }
        if trimmed.contains(full_phrase) {
            return trimmed.replacen(full_phrase, &format!("关闭 {}", target), 1);
        }
    }
    for win_phrase in [
        "当前窗口",
        "这个窗口",
        "活动窗口",
        "前台窗口",
        "当前应用",
        "前台应用",
    ] {
        if trimmed.contains(win_phrase) {
            return trimmed.replacen(win_phrase, target, 1);
        }
    }
    format!("关闭 {}", target)
}

fn extract_close_deictic_token(trimmed: &str) -> &str {
    for tok in [
        "当前窗口",
        "这个窗口",
        "活动窗口",
        "前台窗口",
        "这个软件",
        "这个应用",
        "当前应用",
        "它",
    ] {
        if trimmed.contains(tok) {
            return tok;
        }
    }
    trimmed
}

fn match_conversational_token(trimmed: &str) -> &str {
    for tok in [
        "我之前说的那个文件",
        "之前说的那个文件",
        "上次提到的文档",
        "上次提到的文件",
        "刚才那个文件",
        "刚才那份文件",
        "刚才改的文件",
        "刚才改的配置",
        "刚才打开的文件",
        "刚才的文件",
        "上一个文件",
        "上一个结果",
        "刚才那个",
        "它",
    ] {
        if trimmed.contains(tok) {
            return tok;
        }
    }
    ""
}

fn contains_pronoun_token(text: &str, pronoun: &str) -> bool {
    if pronoun != "它" {
        return text.contains(pronoun);
    }
    // For single-char `它`, avoid matching words like `其它` or `它们`
    if text.contains("其它") || text.contains("它们") {
        let cleaned = text.replace("其它", "").replace("它们", "");
        return cleaned.contains('它');
    }
    text.contains('它')
}

fn collect_recent_targets(
    session: Option<&SessionState>,
    state_db: Option<&StateDb>,
    desktop_ctx: Option<&DesktopContext>,
) -> (Option<String>, Vec<String>, String) {
    static SESSION_PATH_RE: OnceLock<Regex> = OnceLock::new();
    let mut all_targets = Vec::new();
    let mut primary = None;
    let mut source = String::from("none");

    // 1. Desktop selected files take immediate priority if present
    if let Some(dctx) = desktop_ctx
        && !dctx.selected_files.is_empty()
    {
        for f in &dctx.selected_files {
            let trimmed = f.trim();
            if !trimmed.is_empty() && !all_targets.contains(&trimmed.to_string()) {
                all_targets.push(trimmed.to_string());
            }
        }
        if all_targets.len() == 1 {
            primary = Some(all_targets[0].clone());
        }
        source = "desktop_context.selected_files".to_string();
    }

    // 2. Session `last_resource_path`
    if let Some(sess) = session {
        if let Some(last) = sess
            .last_resource_path
            .as_ref()
            .filter(|s| !s.trim().is_empty())
        {
            let clean = last.trim().to_string();
            if primary.is_none() {
                primary = Some(clean.clone());
                source = "session.last_resource_path".to_string();
            }
            if !all_targets.contains(&clean) {
                all_targets.push(clean);
            }
        }

        // Also scan recent session messages in reverse for file paths (`/path/...` or `~/...`)
        let path_re = SESSION_PATH_RE.get_or_init(|| {
            Regex::new(r#"(~[^\s，,。；;"'`]+|/[a-zA-Z0-9._/\-\u{4e00}-\u{9fa5}]+)"#)
                .expect("valid regex")
        });
        for msg in sess.messages.iter().rev() {
            for caps in path_re.captures_iter(&msg.content) {
                let p = caps[1].trim().to_string();
                if p.len() > 2 && !all_targets.contains(&p) {
                    all_targets.push(p);
                    if source == "none" {
                        source = "session.messages".to_string();
                    }
                }
            }
        }
    }

    // 3. Fallback to `StateDb` memory (`last_resource_path`)
    if primary.is_none()
        && let Some(db) = state_db
        && let Some(mem_path) = db
            .get_memory_value("last_resource_path")
            .filter(|s| !s.trim().is_empty())
    {
        let clean = mem_path.trim().to_string();
        if all_targets.is_empty() {
            primary = Some(clean.clone());
        }
        if !all_targets.contains(&clean) {
            all_targets.push(clean);
        }
        if source == "none" {
            source = "state_db.memory".to_string();
        }
    }

    (primary, all_targets, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::core::IntentOsCore;
    use crate::db::IndexDb;
    use crate::memory_hub::{self, RecordTurnInput};
    use crate::resource::ResourceEngine;
    use crate::world_state::{DesktopWindowInfo, RunningAppBrief, WorldStateTracker};
    use chrono::{Duration, TimeZone};
    use intentos_fsops::SafeFsEngine;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn setup_engine() -> (TempDir, Arc<ResourceEngine>) {
        let tmp = TempDir::new().expect("tempdir");
        let ws = tmp.path().join("workspace");
        fs::create_dir_all(&ws).unwrap();
        let idx = Arc::new(IndexDb::open_or_rebuild(&tmp.path().join("idx.db")).unwrap());
        let fs_eng = Arc::new(
            SafeFsEngine::new(
                vec![ws],
                vec![tmp.path().join("forbidden")],
                tmp.path().join("undo"),
                tmp.path().join("trash"),
            )
            .unwrap(),
        );
        let engine = Arc::new(ResourceEngine::new(idx, fs_eng, AppConfig::default()));
        let _ = engine.index_applications();
        (tmp, engine)
    }

    #[test]
    fn test_close_deictic_fresh_focus_vs_expired_and_wayland_unverified() {
        let (_tmp, engine) = setup_engine();
        let tracker = WorldStateTracker::with_session_type("wayland");
        tracker.set_running_apps_override(Some(Vec::new()));
        let resolver = ResourceResolver::with_engine(&engine, &tracker);
        let t0 = Utc.with_ymd_and_hms(2026, 11, 15, 12, 0, 0).unwrap();

        // 1. Unverified Wayland without focus hint -> NeedsClarification (never guesses!)
        let out_unverified = resolve_context_with_world_state_at(
            t0,
            "把它关掉",
            &resolver,
            None,
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        assert!(out_unverified.needs_clarification());
        if let ContextResolutionOutcome::NeedsClarification { prompt, .. } = out_unverified {
            assert!(prompt.contains("wayland_compositor_isolated"));
        }

        // 2. Fresh verified focus hint (`+5s <= 15s`) -> Resolved to exact foreground app!
        tracker.update_desktop_focus_hint_at(
            DesktopWindowInfo {
                window_id: Some("wayland:101".to_string()),
                app_id: Some("org.gnome.Calculator.desktop".to_string()),
                wm_class: Some("gnome-calculator".to_string()),
                title: "计算器".to_string(),
                pid: Some(9001),
            },
            "gnome_shell_extension",
            t0,
        );
        let out_fresh = resolve_context_with_world_state_at(
            t0 + Duration::seconds(5),
            "把它关掉",
            &resolver,
            None,
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        assert!(out_fresh.is_resolved());
        assert_eq!(
            out_fresh.effective_text(),
            "关闭 org.gnome.Calculator.desktop"
        );

        // 3. Focus hint expired (`+18s > 15s`) with 2 running apps -> NeedsClarification listing candidates!
        tracker.set_running_apps_override(Some(vec![
            RunningAppBrief {
                app_id: "org.gnome.Calculator.desktop".to_string(),
                display_name: "计算器".to_string(),
                binary_name: "gnome-calculator".to_string(),
                pids: vec![9001],
                desktop_source: None,
            },
            RunningAppBrief {
                app_id: "firefox.desktop".to_string(),
                display_name: "Firefox 浏览器".to_string(),
                binary_name: "firefox".to_string(),
                pids: vec![9002],
                desktop_source: None,
            },
        ]));
        let out_expired = resolve_context_with_world_state_at(
            t0 + Duration::seconds(18),
            "把它关掉",
            &resolver,
            None,
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        match out_expired {
            ContextResolutionOutcome::NeedsClarification {
                candidate_targets, ..
            } => {
                assert_eq!(candidate_targets.len(), 2);
                assert!(candidate_targets.contains(&"org.gnome.Calculator.desktop".to_string()));
                assert!(candidate_targets.contains(&"firefox.desktop".to_string()));
            }
            other => panic!(
                "expected NeedsClarification on expired focus, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_comparative_experiment_results_context_resolution() {
        let (_tmp, engine) = setup_engine();
        let ws = engine.authorized_roots()[0].clone();
        let r_yest = ws.join("ablation_result_2026-11-14.md");
        let r_prev = ws.join("ablation_result_2026-11-13.csv");
        fs::write(&r_yest, "# 2026-11-14 F1=0.91").unwrap();
        fs::write(&r_prev, "metric,val\nF1,0.87\n").unwrap();

        let tracker = WorldStateTracker::with_session_type("headless");
        let resolver = ResourceResolver::with_engine(&engine, &tracker);
        let now = Utc.with_ymd_and_hms(2026, 11, 15, 16, 0, 0).unwrap();

        let out = resolve_context_with_world_state_at(
            now,
            "比较昨天与前天的实验结果",
            &resolver,
            None,
            None,
            None,
            PrivacySessionPolicy::Standard,
        );
        match out {
            ContextResolutionOutcome::Resolved {
                resolved_targets,
                source,
                ..
            } => {
                assert_eq!(source, "resource_resolver.comparative");
                assert_eq!(resolved_targets.len(), 2);
                assert_eq!(resolved_targets[0], r_yest.to_string_lossy().to_string());
                assert_eq!(resolved_targets[1], r_prev.to_string_lossy().to_string());
            }
            other => panic!("expected Resolved comparative outcome, got {:?}", other),
        }
    }

    #[test]
    fn test_open_recent_file_deictic_and_strict_isolated_privacy() {
        let tmp = TempDir::new().expect("tempdir");
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .to_path_buf();
        let core = IntentOsCore::initialize(Some(tmp.path()), repo_root).expect("init core");
        let ws = core.fs_engine.authorized_roots()[0].clone();
        let paper = ws.join("thesis_draft.docx");
        fs::write(&paper, b"thesis content").unwrap();

        memory_hub::record_conversation_turn_with_policy(
            &core,
            &RecordTurnInput {
                session_id: Some("ses_mem".to_string()),
                user_text: format!("帮我检查一下 `{}`", paper.display()),
                assistant_text: "已检查 thesis_draft.docx。".to_string(),
                thinking: None,
                tool_steps: Vec::new(),
                trace_dots: Vec::new(),
                incognito: false,
            },
            PrivacySessionPolicy::Standard,
        )
        .unwrap();

        let tracker = WorldStateTracker::for_core(&core);
        let resolver = ResourceResolver::new(&core, &tracker);
        let now = Utc::now();

        // Standard policy recalls the mentioned file
        let std_out = resolve_context_with_world_state_at(
            now,
            "打开我之前说的那个文件",
            &resolver,
            None,
            Some(&core.state_db),
            None,
            PrivacySessionPolicy::Standard,
        );
        assert!(std_out.is_resolved());
        assert!(
            std_out
                .effective_text()
                .contains(&paper.to_string_lossy().to_string())
        );

        // StrictIsolated policy NEVER leaks personal memory entities
        let strict_out = resolve_context_with_world_state_at(
            now,
            "打开我之前说的那个文件",
            &resolver,
            None,
            Some(&core.state_db),
            None,
            PrivacySessionPolicy::StrictIsolated,
        );
        assert!(strict_out.needs_clarification());
        assert!(!strict_out.effective_text().contains("thesis_draft.docx"));
    }
}
