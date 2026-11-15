#![forbid(unsafe_code)]

//! Multi-Turn Context & Pronoun Resolver (`context_resolver.rs`, §3.1, §4.2, §4.4).
//!
//! Resolves conversational pronouns (`它`, `刚才那个文件`, `这些文件`, `上一个结果`)
//! and desktop environment references (`当前窗口`, `选中文本`, `剪贴板`, `当前目录`)
//! using `SessionState`, `StateDb` memory, and optional `DesktopContext`.
//! When a pronoun is ambiguous across multiple candidates or has no referent,
//! produces a structured clarification prompt instead of blind-guessing.

use crate::db::StateDb;
use crate::runtime::SessionState;
use regex::Regex;
use serde::{Deserialize, Serialize};

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

/// Result of resolving pronouns and desktop context references in user input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ContextResolutionOutcome {
    /// Input contained no pronouns or context references requiring substitution.
    Unchanged { text: String },
    /// Pronoun or desktop reference was unambiguously resolved.
    Resolved {
        original_text: String,
        rewritten_text: String,
        matched_reference: String,
        resolved_targets: Vec<String>,
        source: String,
    },
    /// Pronoun was detected, but either multiple competing referents exist or none exist.
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

        for phrase in ["剪贴板里的内容", "剪贴板内容", "剪贴板里的文字", "剪贴板"]
        {
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
        "刚才那个文件",
        "刚才那份文件",
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
        let path_re = Regex::new(r#"(~[^\s，,。；;"'`]+|/[a-zA-Z0-9._/\-\u{4e00}-\u{9fa5}]+)"#)
            .expect("valid regex");
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
