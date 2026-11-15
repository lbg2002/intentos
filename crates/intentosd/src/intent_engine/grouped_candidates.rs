#![forbid(unsafe_code)]

//! Grouped Candidate Generator & `Alt+Enter` Contextual Action Menu (`grouped_candidates.rs`, §3.1, §4.6).
//!
//! Produces multi-source grouped candidates across 7 canonical groups:
//! 1. `direct_intent` (直达意图)
//! 2. `apps` (应用)
//! 3. `files` (文件)
//! 4. `web` (网页与搜索)
//! 5. `settings` (系统设置)
//! 6. `skills` (技能与工具)
//! 7. `passthrough` (AI 深度推理 / 自由指令兜底)
//!
//! Also provides `get_candidate_actions` for the `Alt+Enter` secondary action menu
//! on any candidate item (`file`, `app`, `web`, `setting`, `skill`).

use crate::core::IntentOsCore;
use crate::intent_engine::fuzzy_scorer::{MatchTier, rank_capabilities, score_query_against_term};
use crate::intent_engine::pattern_compiler::PatternCompiler;
use crate::intent_engine::slot_extractor::{extract_slots_for_descriptor, extract_universal_slots};
use crate::resource::{FileSearchFilter, FileSortOrder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A secondary contextual action shown when pressing `Alt+Enter` on a candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateAction {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub shortcut: String,
    pub capability_id: Option<String>,
    pub arguments: Value,
    pub danger: bool,
}

/// A single candidate item enriched with group metadata, `Tab` completion text, and `Alt+Enter` actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupedCandidateItem {
    pub id: String,
    pub group_key: String,
    pub kind: String,
    pub title: String,
    pub subtitle: String,
    pub badge: String,
    pub score: f64,
    pub match_tier: MatchTier,
    pub capability_id: Option<String>,
    pub arguments: Value,
    pub target: Option<String>,
    pub completion_text: String,
    pub actions: Vec<CandidateAction>,
}

/// A named group of candidates in the Launcher dropdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateGroup {
    pub key: String,
    pub title: String,
    pub shortcut_hint: String,
    pub items: Vec<GroupedCandidateItem>,
}

/// Complete response for `query_grouped_candidates`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupedCandidateResponse {
    pub query: String,
    pub category_filter: String,
    pub total_count: usize,
    pub top_completion: Option<String>,
    pub groups: Vec<CandidateGroup>,
    pub items: Vec<GroupedCandidateItem>,
}

/// Build contextual `Alt+Enter` actions for a candidate item based on its `kind` and `target`.
pub fn get_candidate_actions(
    core: &IntentOsCore,
    candidate_id: &str,
    kind: &str,
    target: Option<&str>,
    capability_id: Option<&str>,
    arguments: &Value,
) -> Vec<CandidateAction> {
    let target_str = target
        .or_else(|| arguments.get("target").and_then(|v| v.as_str()))
        .or_else(|| arguments.get("path").and_then(|v| v.as_str()))
        .or_else(|| arguments.get("app").and_then(|v| v.as_str()))
        .unwrap_or(candidate_id);

    match kind {
        "file" => {
            let parent_dir = std::path::Path::new(target_str)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| target_str.to_string());

            vec![
                CandidateAction {
                    id: "open".to_string(),
                    title: "打开文件".to_string(),
                    subtitle: format!("使用系统默认应用打开 {}", target_str),
                    shortcut: "Enter".to_string(),
                    capability_id: Some("xdg.open".to_string()),
                    arguments: json!({ "target": target_str }),
                    danger: false,
                },
                CandidateAction {
                    id: "open_with".to_string(),
                    title: "用其他应用打开...".to_string(),
                    subtitle: "选择桌面应用程序打开此文件".to_string(),
                    shortcut: "Alt+O".to_string(),
                    capability_id: Some("app.launch".to_string()),
                    arguments: json!({ "app": "xdg-open", "args": [target_str] }),
                    danger: false,
                },
                CandidateAction {
                    id: "reveal".to_string(),
                    title: "在文件夹中显示".to_string(),
                    subtitle: format!("打开所在目录 {}", parent_dir),
                    shortcut: "Alt+R".to_string(),
                    capability_id: Some("xdg.reveal".to_string()),
                    arguments: json!({ "path": target_str }),
                    danger: false,
                },
                CandidateAction {
                    id: "copy_path".to_string(),
                    title: "复制完整路径".to_string(),
                    subtitle: target_str.to_string(),
                    shortcut: "Alt+C".to_string(),
                    capability_id: None,
                    arguments: json!({ "clipboard_text": target_str }),
                    danger: false,
                },
                CandidateAction {
                    id: "rename".to_string(),
                    title: "重命名文件...".to_string(),
                    subtitle: "修改文件名称（受安全策略保护）".to_string(),
                    shortcut: "F2".to_string(),
                    capability_id: Some("fs.rename".to_string()),
                    arguments: json!({ "path": target_str, "new_name": "" }),
                    danger: false,
                },
                CandidateAction {
                    id: "trash".to_string(),
                    title: "移到回收站".to_string(),
                    subtitle: "安全移入系统回收站（可恢复）".to_string(),
                    shortcut: "Alt+Backspace".to_string(),
                    capability_id: Some("fs.trash".to_string()),
                    arguments: json!({ "paths": [target_str] }),
                    danger: true,
                },
            ]
        }
        "app" => vec![
            CandidateAction {
                id: "launch".to_string(),
                title: "启动 / 聚焦应用".to_string(),
                subtitle: format!("打开或切换到 {}", target_str),
                shortcut: "Enter".to_string(),
                capability_id: Some("app.launch".to_string()),
                arguments: json!({ "app": target_str }),
                danger: false,
            },
            CandidateAction {
                id: "focus".to_string(),
                title: "切换到已打开窗口".to_string(),
                subtitle: format!("聚焦 {} 的活动窗口", target_str),
                shortcut: "Alt+F".to_string(),
                capability_id: Some("app.focus".to_string()),
                arguments: json!({ "app": target_str }),
                danger: false,
            },
            CandidateAction {
                id: "new_window".to_string(),
                title: "新建应用窗口".to_string(),
                subtitle: format!("启动 {} 的新窗口实例", target_str),
                shortcut: "Alt+N".to_string(),
                capability_id: Some("app.launch".to_string()),
                arguments: json!({ "app": target_str, "args": ["--new-window"] }),
                danger: false,
            },
            CandidateAction {
                id: "quit".to_string(),
                title: "退出应用".to_string(),
                subtitle: format!("关闭 {} 进程", target_str),
                shortcut: "Alt+Q".to_string(),
                capability_id: Some("app.quit".to_string()),
                arguments: json!({ "app": target_str }),
                danger: true,
            },
        ],
        "web" => {
            let mut actions = vec![
                CandidateAction {
                    id: "open_url".to_string(),
                    title: "在默认浏览器中打开".to_string(),
                    subtitle: target_str.to_string(),
                    shortcut: "Enter".to_string(),
                    capability_id: Some("web.open".to_string()),
                    arguments: json!({ "target": target_str }),
                    danger: false,
                },
                CandidateAction {
                    id: "copy_url".to_string(),
                    title: "复制网址链接".to_string(),
                    subtitle: target_str.to_string(),
                    shortcut: "Alt+C".to_string(),
                    capability_id: None,
                    arguments: json!({ "clipboard_text": target_str }),
                    danger: false,
                },
            ];
            if let Some(site) = core.resources.find_site(target_str)
                && site.search.is_some()
            {
                let site_display = site
                    .names
                    .first()
                    .cloned()
                    .unwrap_or_else(|| site.id.clone());
                actions.push(CandidateAction {
                    id: "search_site".to_string(),
                    title: format!("在 {} 中站内搜索...", site_display),
                    subtitle: format!("使用 {} 站内搜索模板", site_display),
                    shortcut: "Alt+S".to_string(),
                    capability_id: Some("web.search".to_string()),
                    arguments: json!({ "site": site.id, "query": "" }),
                    danger: false,
                });
            }
            actions
        }
        "setting" | "intent" => {
            let cap = capability_id.unwrap_or("settings.open_panel");
            let panel = infer_setting_panel(cap);
            let default_args = infer_setting_reset_args(core, cap);

            vec![
                CandidateAction {
                    id: "execute".to_string(),
                    title: "立即执行此项设置".to_string(),
                    subtitle: format!("调用能力 {}", cap),
                    shortcut: "Enter".to_string(),
                    capability_id: Some(cap.to_string()),
                    arguments: arguments.clone(),
                    danger: false,
                },
                CandidateAction {
                    id: "reset_setting".to_string(),
                    title: "恢复默认值".to_string(),
                    subtitle: format!("将 {} 重置为推荐默认状态", cap),
                    shortcut: "Alt+D".to_string(),
                    capability_id: Some(cap.to_string()),
                    arguments: default_args,
                    danger: false,
                },
                CandidateAction {
                    id: "open_panel".to_string(),
                    title: "打开系统设置控制面板".to_string(),
                    subtitle: format!("跳转到「{}」设置面板", panel),
                    shortcut: "Alt+P".to_string(),
                    capability_id: Some("settings.open_panel".to_string()),
                    arguments: json!({ "panel": panel }),
                    danger: false,
                },
            ]
        }
        _ => vec![CandidateAction {
            id: "execute".to_string(),
            title: "执行命令".to_string(),
            subtitle: capability_id.unwrap_or("发送给 IntentOS 执行").to_string(),
            shortcut: "Enter".to_string(),
            capability_id: capability_id.map(|s| s.to_string()),
            arguments: arguments.clone(),
            danger: false,
        }],
    }
}

fn infer_setting_panel(capability_id: &str) -> &'static str {
    if capability_id.starts_with("sound.") {
        "sound"
    } else if capability_id.starts_with("display.") {
        "display"
    } else if capability_id.starts_with("appearance.") {
        "appearance"
    } else if capability_id.starts_with("bluetooth.") {
        "bluetooth"
    } else if capability_id.starts_with("network.") {
        "network"
    } else if capability_id.starts_with("power.") {
        "power"
    } else {
        "display"
    }
}

fn infer_setting_reset_args(core: &IntentOsCore, capability_id: &str) -> Value {
    match capability_id {
        "sound.volume.set" => json!({ "value": 50 }),
        "sound.mute.set" | "sound.mic.mute.set" | "notify.dnd.set" | "display.night_light.set" => {
            json!({ "state": "off" })
        }
        "display.brightness.set" => json!({ "value": 70 }),
        "display.night_light.temperature" => json!({ "value": 4500 }),
        "appearance.color_scheme.set" => json!({ "scheme": "light" }),
        "appearance.text_scale.set" => json!({ "value": 1.0 }),
        "power.profile.set" => json!({ "profile": "balanced" }),
        _ => {
            if let Some(desc) = core.broker.get_descriptor(capability_id)
                && let Some(meta) = &desc.setting
                && let (Some(lo), Some(hi)) = (meta.min, meta.max)
            {
                return json!({ "value": (lo + hi) / 2.0 });
            }
            json!({})
        }
    }
}

/// Query and assemble grouped candidates across `direct_intent`, `apps`, `files`, `web`,
/// `settings`, `skills`, and `passthrough`.
pub fn query_grouped_candidates(
    core: &IntentOsCore,
    raw_query: &str,
    category_filter: Option<&str>,
    compiler: &PatternCompiler,
) -> GroupedCandidateResponse {
    let trimmed = raw_query.trim();
    let cat_filter = category_filter.unwrap_or("all").trim().to_ascii_lowercase();

    let mut direct_intent_items: Vec<GroupedCandidateItem> = Vec::new();
    let mut app_items: Vec<GroupedCandidateItem> = Vec::new();
    let mut file_items: Vec<GroupedCandidateItem> = Vec::new();
    let mut web_items: Vec<GroupedCandidateItem> = Vec::new();
    let mut setting_items: Vec<GroupedCandidateItem> = Vec::new();
    let mut skill_items: Vec<GroupedCandidateItem> = Vec::new();
    let mut passthrough_items: Vec<GroupedCandidateItem> = Vec::new();

    if trimmed.is_empty() {
        // Zero-input default suggestions: frequent commands & system settings
        for cap_id in [
            "scene.apply",
            "sound.volume.set",
            "display.brightness.set",
            "appearance.color_scheme.set",
            "system.inspect",
            "disk.free",
        ] {
            if let Some(desc) = core.broker.get_descriptor(cap_id) {
                let default_args = extract_slots_for_descriptor(
                    desc,
                    desc.aliases.first().map(|s| s.as_str()).unwrap_or(&desc.id),
                    &std::collections::HashMap::new(),
                    &core.resources,
                );
                let actions = get_candidate_actions(
                    core,
                    &desc.id,
                    "setting",
                    None,
                    Some(&desc.id),
                    &default_args,
                );
                setting_items.push(GroupedCandidateItem {
                    id: format!("cap:{}", desc.id),
                    group_key: "settings".to_string(),
                    kind: "setting".to_string(),
                    title: desc.summary.clone(),
                    subtitle: format!("{} · {}", desc.category, desc.id),
                    badge: "常用能力".to_string(),
                    score: 85.0,
                    match_tier: MatchTier::Prefix,
                    capability_id: Some(desc.id.clone()),
                    arguments: default_args,
                    target: None,
                    completion_text: desc
                        .aliases
                        .first()
                        .cloned()
                        .unwrap_or_else(|| desc.id.clone()),
                    actions,
                });
            }
        }
    } else {
        // 1. Score capabilities via PatternCompiler + FuzzyScorer + SlotExtractor
        let scored_caps = rank_capabilities(trimmed, compiler, Some(&core.index_db), 10);
        for (idx, sc) in scored_caps.into_iter().enumerate() {
            let Some(desc) = core.broker.get_descriptor(&sc.capability_id) else {
                continue;
            };
            let args =
                extract_slots_for_descriptor(desc, trimmed, &sc.captured_slots, &core.resources);
            let is_setting = desc.category == "settings"
                || desc.setting.is_some()
                || desc.id.starts_with("sound.")
                || desc.id.starts_with("display.")
                || desc.id.starts_with("appearance.")
                || desc.id.starts_with("bluetooth.")
                || desc.id.starts_with("network.wifi.")
                || desc.id.starts_with("power.profile")
                || desc.id.starts_with("notify.dnd")
                || desc.id == "scene.apply";

            let kind = if is_setting { "setting" } else { "skill" };
            let actions = get_candidate_actions(core, &desc.id, kind, None, Some(&desc.id), &args);
            let completion = desc
                .aliases
                .iter()
                .find(|a| {
                    a.to_ascii_lowercase()
                        .starts_with(&trimmed.to_ascii_lowercase())
                })
                .or_else(|| desc.aliases.first())
                .cloned()
                .unwrap_or_else(|| trimmed.to_string());

            // Top high-confidence match goes to `direct_intent` as well as its category group
            if idx == 0 && sc.confidence >= 0.72 {
                direct_intent_items.push(GroupedCandidateItem {
                    id: format!("direct:{}", desc.id),
                    group_key: "direct_intent".to_string(),
                    kind: "intent".to_string(),
                    title: format!("{} ({})", desc.summary, format_args_preview(&args)),
                    subtitle: format!(
                        "直达执行 · {} · 置信度 {:.0}%",
                        desc.id,
                        sc.confidence * 100.0
                    ),
                    badge: "直达意图".to_string(),
                    score: sc.total_score + 15.0,
                    match_tier: sc.breakdown.tier,
                    capability_id: Some(desc.id.clone()),
                    arguments: args.clone(),
                    target: None,
                    completion_text: completion.clone(),
                    actions: actions.clone(),
                });
            }

            let group_key = if is_setting { "settings" } else { "skills" };
            let badge = if is_setting {
                "系统设置"
            } else {
                "技能工具"
            };
            let item = GroupedCandidateItem {
                id: format!("cap:{}", desc.id),
                group_key: group_key.to_string(),
                kind: kind.to_string(),
                title: desc.summary.clone(),
                subtitle: format!("{} · 匹配「{}」", desc.id, sc.breakdown.matched_term),
                badge: badge.to_string(),
                score: sc.total_score,
                match_tier: sc.breakdown.tier,
                capability_id: Some(desc.id.clone()),
                arguments: args,
                target: None,
                completion_text: completion,
                actions,
            };

            if is_setting {
                setting_items.push(item);
            } else {
                skill_items.push(item);
            }
        }

        // 2. Search Applications (`apps`)
        let app_query = trimmed
            .trim_start_matches("打开应用")
            .trim_start_matches("打开")
            .trim_start_matches("启动")
            .trim();
        let effective_app_q = if app_query.is_empty() {
            trimmed
        } else {
            app_query
        };
        for (app, app_base_score) in core.resources.search_apps(effective_app_q, 6) {
            let frecency = core
                .index_db
                .get_frecency_boost(&format!("app:{}", app.app_id));
            let bd = score_query_against_term(effective_app_q, &app.name, false, frecency);
            let score = app_base_score.max(bd.total_score) + frecency;
            let args = json!({ "app": app.name });
            let actions = get_candidate_actions(
                core,
                &app.app_id,
                "app",
                Some(&app.name),
                Some("app.launch"),
                &args,
            );
            app_items.push(GroupedCandidateItem {
                id: format!("app:{}", app.app_id),
                group_key: "apps".to_string(),
                kind: "app".to_string(),
                title: app.name.clone(),
                subtitle: if app.generic_name.is_empty() {
                    app.exec_cmd.clone()
                } else {
                    format!("{} · {}", app.generic_name, app.exec_cmd)
                },
                badge: "应用".to_string(),
                score,
                match_tier: bd.tier.max(MatchTier::Pinyin),
                capability_id: Some("app.launch".to_string()),
                arguments: args,
                target: Some(app.name.clone()),
                completion_text: format!("打开 {}", app.name),
                actions,
            });
        }

        // 3. Search Files (`files`) with universal slot filters (time range, size, extension, directory)
        let uni_slots = extract_universal_slots(trimmed, &core.resources);
        let file_q = trimmed
            .trim_start_matches("打开文件")
            .trim_start_matches("查找文件")
            .trim_start_matches("搜索文件")
            .trim_start_matches("找一下")
            .trim_start_matches("找")
            .trim_start_matches("搜")
            .trim();
        let now_secs = chrono::Utc::now().timestamp();
        let modified_after_secs = uni_slots.time_range.as_ref().and_then(|tr| {
            if let Some(h) = tr.modified_within_hours {
                Some(now_secs - (h as i64) * 3600)
            } else {
                tr.modified_within_days
                    .map(|d| now_secs - (d as i64) * 86400)
            }
        });
        let filter = FileSearchFilter {
            query: if file_q.is_empty() {
                None
            } else {
                Some(file_q.to_string())
            },
            extensions: uni_slots
                .file_type
                .as_ref()
                .map(|ft| ft.extensions.clone())
                .unwrap_or_default(),
            category: None,
            directory_prefix: uni_slots.locations.first().map(|l| l.resolved_path.clone()),
            min_size_bytes: uni_slots
                .size_range
                .as_ref()
                .and_then(|sr| sr.min_size_bytes),
            max_size_bytes: uni_slots
                .size_range
                .as_ref()
                .and_then(|sr| sr.max_size_bytes),
            modified_after_secs,
            modified_before_secs: None,
            sort_by: FileSortOrder::RelevanceAndRecent,
            limit: 6,
        };
        for (f, f_base_score) in core.resources.search_files(&filter) {
            let frecency = core
                .index_db
                .get_frecency_boost(&format!("file:{}", f.path));
            let score = f_base_score + frecency;
            let args = json!({ "target": f.path });
            let actions = get_candidate_actions(
                core,
                &f.path,
                "file",
                Some(&f.path),
                Some("xdg.open"),
                &args,
            );
            file_items.push(GroupedCandidateItem {
                id: format!("file:{}", f.path),
                group_key: "files".to_string(),
                kind: "file".to_string(),
                title: f.name.clone(),
                subtitle: f.path.clone(),
                badge: if f.category == "directory" {
                    "文件夹".to_string()
                } else {
                    "文件".to_string()
                },
                score,
                match_tier: MatchTier::Prefix,
                capability_id: Some("xdg.open".to_string()),
                arguments: args,
                target: Some(f.path.clone()),
                completion_text: f.path.clone(),
                actions,
            });
        }

        // 4. Web & Bookmarks & Site Search (`web`)
        if let Ok(Some(web_res)) = core.resources.resolve_web_target(trimmed) {
            let url = web_res.url;
            let title = format!("打开 {} ({})", web_res.title, url);
            let badge = match web_res.source.as_str() {
                "site" => "常用站点",
                "site_search" => "站内搜索",
                "search_engine" => "网页搜索",
                _ => "网址直达",
            };
            let score = if web_res.source == "search_engine" {
                78.0
            } else {
                92.0
            };
            let args = json!({ "target": url });
            let actions =
                get_candidate_actions(core, &url, "web", Some(&url), Some("web.open"), &args);
            web_items.push(GroupedCandidateItem {
                id: format!("web:{}", url),
                group_key: "web".to_string(),
                kind: "web".to_string(),
                title,
                subtitle: url.clone(),
                badge: badge.to_string(),
                score,
                match_tier: MatchTier::AliasSynonym,
                capability_id: Some("web.open".to_string()),
                arguments: args,
                target: Some(url.clone()),
                completion_text: url,
                actions,
            });
        }

        for (bm_title, bm_url, bm_source) in core.resources.search_bookmarks(trimmed, 4) {
            let args = json!({ "target": bm_url });
            let actions =
                get_candidate_actions(core, &bm_url, "web", Some(&bm_url), Some("web.open"), &args);
            web_items.push(GroupedCandidateItem {
                id: format!("bm:{}", bm_url),
                group_key: "web".to_string(),
                kind: "web".to_string(),
                title: bm_title,
                subtitle: format!("{} · {}", bm_source, bm_url),
                badge: "书签".to_string(),
                score: 82.0,
                match_tier: MatchTier::Prefix,
                capability_id: Some("web.open".to_string()),
                arguments: args,
                target: Some(bm_url.clone()),
                completion_text: bm_url,
                actions,
            });
        }

        // Always provide a fallback web search option if `web_items` is empty
        if web_items.is_empty() {
            let (search_url, engine_name) = core.resources.build_search_url(trimmed, None);
            let args = json!({ "query": trimmed });
            let actions = get_candidate_actions(
                core,
                &search_url,
                "web",
                Some(&search_url),
                Some("web.search"),
                &args,
            );
            web_items.push(GroupedCandidateItem {
                id: format!("websearch:{}", trimmed),
                group_key: "web".to_string(),
                kind: "web".to_string(),
                title: format!("使用 {} 搜索「{}」", engine_name, trimmed),
                subtitle: search_url.clone(),
                badge: "网页搜索".to_string(),
                score: 42.0,
                match_tier: MatchTier::FuzzyEditBigram,
                capability_id: Some("web.search".to_string()),
                arguments: args,
                target: Some(search_url),
                completion_text: format!("搜索 {}", trimmed),
                actions,
            });
        }

        // 5. Passthrough / AI Natural Language Fallback (`passthrough`)
        let pass_args = json!({ "text": trimmed });
        passthrough_items.push(GroupedCandidateItem {
            id: format!("passthrough:{}", trimmed),
            group_key: "passthrough".to_string(),
            kind: "passthrough".to_string(),
            title: format!("交由 IntentOS AI 深度理解并执行：「{}」", trimmed),
            subtitle: "支持多步复合任务规划、上下文指代消解与自由对话".to_string(),
            badge: "AI 意图".to_string(),
            score: 35.0,
            match_tier: MatchTier::FuzzyEditBigram,
            capability_id: None,
            arguments: pass_args.clone(),
            target: Some(trimmed.to_string()),
            completion_text: trimmed.to_string(),
            actions: get_candidate_actions(
                core,
                trimmed,
                "passthrough",
                Some(trimmed),
                None,
                &pass_args,
            ),
        });
    }

    let raw_groups = vec![
        (
            "direct_intent",
            "直达意图",
            "Enter 立即执行",
            direct_intent_items,
        ),
        ("apps", "应用程序", "Alt+Enter 更多操作", app_items),
        ("files", "文件与目录", "Alt+Enter 打开方式/位置", file_items),
        ("web", "网页与书签", "Alt+Enter 复制/站内搜索", web_items),
        (
            "settings",
            "系统设置",
            "Alt+Enter 恢复默认/面板",
            setting_items,
        ),
        ("skills", "技能与系统工具", "Enter 调用能力", skill_items),
        (
            "passthrough",
            "AI 深度理解兜底",
            "Enter 发送给 AI",
            passthrough_items,
        ),
    ];

    let mut groups = Vec::new();
    let mut flat_items = Vec::new();

    for (key, title, hint, mut items) in raw_groups {
        if items.is_empty() {
            continue;
        }
        if cat_filter != "all"
            && !cat_filter.is_empty()
            && key != cat_filter
            && !key.starts_with(&cat_filter)
        {
            continue;
        }
        items.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for it in &items {
            flat_items.push(it.clone());
        }
        groups.push(CandidateGroup {
            key: key.to_string(),
            title: title.to_string(),
            shortcut_hint: hint.to_string(),
            items,
        });
    }

    let top_completion = flat_items.first().map(|it| it.completion_text.clone());

    GroupedCandidateResponse {
        query: trimmed.to_string(),
        category_filter: cat_filter,
        total_count: flat_items.len(),
        top_completion,
        groups,
        items: flat_items,
    }
}

fn format_args_preview(args: &Value) -> String {
    let Some(obj) = args.as_object() else {
        return String::new();
    };
    if obj.is_empty() {
        return "默认参数".to_string();
    }
    obj.iter()
        .map(|(k, v)| match v {
            Value::String(s) => format!("{}={}", k, s),
            _ => format!("{}={}", k, v),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
