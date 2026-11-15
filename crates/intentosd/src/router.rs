#![forbid(unsafe_code)]

//! Intent Router (WP06, §4, `v0.1` full grammar):
//! - Real-time L0 candidate matching (`<30ms` P95) + `$ ` passthrough history autocomplete
//! - Deterministic Chinese & developer colloquial L0 grammar across D1–D6 + 60+ system settings
//! - Explicit file-association preference memory (`A22`: `"记住 docx 用 WPS 打开"`) & custom scene saving
//! - §4.6 "Search and Open" disambiguation strategy

use crate::db::StateDb;
use crate::resource::{FileSearchFilter, FileSortOrder, ResourceEngine};
use crate::settings::SystemSettingsEngine;
use chrono::{Datelike, Duration, Local, TimeZone, Utc};
use intentos_protocol::{CandidateItem, CandidateKind, CandidateResponse};
use regex::Regex;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum RoutedIntent {
    /// High-confidence single L0 capability call.
    ExecuteL0 {
        capability_id: String,
        arguments: Value,
        summary: String,
    },
    /// Security rejection detected at router boundary (e.g. `javascript:` / `file:` URL, unregistered setting).
    Rejected { reason: String },
    /// Multiple plausible candidates — ask user to pick instead of guessing (`误打开率 < 1%`, §4.6).
    Disambiguate {
        prompt: String,
        candidates: Vec<CandidateItem>,
    },
    /// Undo previous reversible operation (`撤销` / `undo`).
    UndoLatest,
    /// Save explicit user preference memory (`记住...`).
    SaveExplicitMemory { subject: String, value: String },
    /// Save current system settings snapshot as a reusable named scene (`把现在的设置保存为XX模式`).
    SaveCurrentScene { name: String },
    /// Escalate colloquial / multi-step / low-confidence request to L1 Decision Adapter -> L2 Agent Runtime.
    EscalateL2 { reason: String },
}

pub struct IntentRouter {
    resources: Arc<ResourceEngine>,
    state_db: Option<Arc<StateDb>>,
}

impl IntentRouter {
    pub fn new(resources: Arc<ResourceEngine>) -> Self {
        Self {
            resources,
            state_db: None,
        }
    }

    pub fn with_state_db(mut self, state_db: Arc<StateDb>) -> Self {
        self.state_db = Some(state_db);
        self
    }

    /// Generate real-time as-you-type candidates for Intent Shell / TUI / Web Launcher (UI-02, <30ms P95).
    pub fn query_candidates(&self, raw_query: &str) -> CandidateResponse {
        let start = Instant::now();
        let trimmed = raw_query.trim();
        if trimmed.is_empty() {
            return CandidateResponse {
                query: String::new(),
                elapsed_us: start.elapsed().as_micros() as u64,
                l0_direct_match: false,
                items: Vec::new(),
            };
        }

        let mut items = Vec::new();
        let mut l0_direct = false;

        // 1. `$ ` Command Passthrough preview + Passthrough History suggestions (§8.8)
        if let Some(cmd) = trimmed.strip_prefix('$') {
            let clean_cmd = cmd.trim();
            items.push(CandidateItem {
                id: "passthrough:cmd".into(),
                kind: CandidateKind::Passthrough,
                title: format!(
                    "执行终端命令: {}",
                    if clean_cmd.is_empty() {
                        "<输入命令>"
                    } else {
                        clean_cmd
                    }
                ),
                subtitle: "命令直通模式（以当前用户身份执行，不可撤销）".into(),
                badge: "直通".into(),
                score: 120.0,
                capability_id: None,
                arguments: json!({ "command": clean_cmd }),
                resource_uri: None,
            });
            for (idx, h) in self
                .resources
                .index_db()
                .list_passthrough_history(6)
                .into_iter()
                .enumerate()
            {
                if let Some(prev_cmd) = h.get("command").and_then(|v| v.as_str())
                    && (clean_cmd.is_empty() || prev_cmd.contains(clean_cmd))
                {
                    let cwd = h.get("cwd").and_then(|v| v.as_str()).unwrap_or("~");
                    items.push(CandidateItem {
                        id: format!("passthrough:hist:{}", idx),
                        kind: CandidateKind::Passthrough,
                        title: format!("$ {}", prev_cmd),
                        subtitle: format!("历史直通命令 · cwd={}", cwd),
                        badge: "历史".into(),
                        score: 105.0 - (idx as f64),
                        capability_id: None,
                        arguments: json!({ "command": prev_cmd }),
                        resource_uri: None,
                    });
                }
            }
            return CandidateResponse {
                query: trimmed.to_string(),
                elapsed_us: start.elapsed().as_micros() as u64,
                l0_direct_match: true,
                items,
            };
        }

        // 2. Deterministic L0 grammar match first!
        match self.route_text(trimmed, false) {
            RoutedIntent::ExecuteL0 {
                capability_id,
                arguments,
                summary,
            } => {
                l0_direct = true;
                let kind = classify_candidate_kind(&capability_id);
                items.push(CandidateItem {
                    id: format!("l0:{}:0", capability_id),
                    kind,
                    title: summary,
                    subtitle: format!("L0 即时执行 · {}", capability_id),
                    badge: "L0".into(),
                    score: 110.0,
                    capability_id: Some(capability_id),
                    arguments,
                    resource_uri: None,
                });
            }
            RoutedIntent::UndoLatest => {
                l0_direct = true;
                items.push(CandidateItem {
                    id: "l0:undo".into(),
                    kind: CandidateKind::Undo,
                    title: "撤销上一次可逆修改".into(),
                    subtitle: "L0 即时还原（无需模型）".into(),
                    badge: "撤销".into(),
                    score: 115.0,
                    capability_id: None,
                    arguments: json!({}),
                    resource_uri: None,
                });
            }
            RoutedIntent::Disambiguate { candidates, .. } => {
                items.extend(candidates);
            }
            _ => {}
        }

        // 3. Supplement with live App, File, Site, and Bookmark index matches for bare/prefix typing
        let bare = strip_open_verb(trimmed).unwrap_or(trimmed);
        for (app, score) in self.resources.search_apps(bare, 4) {
            let cid = format!("app:{}", app.app_id);
            if !items.iter().any(|i| i.id == cid) {
                items.push(CandidateItem {
                    id: cid,
                    kind: CandidateKind::App,
                    title: app.name.clone(),
                    subtitle: format!("应用 · {}", app.app_id),
                    badge: "应用".into(),
                    score,
                    capability_id: Some("app.launch".into()),
                    arguments: json!({ "app_id": app.app_id, "app_name": app.name }),
                    resource_uri: Some(format!("resource://app/{}", app.app_id)),
                });
            }
        }

        if let Ok(Some(site)) = self.resources.resolve_web_target(bare) {
            let sid = format!("web:{}", site.url);
            if !items
                .iter()
                .any(|i| i.arguments.get("url").and_then(|u| u.as_str()) == Some(&site.url))
            {
                items.push(CandidateItem {
                    id: sid,
                    kind: CandidateKind::Web,
                    title: format!("打开 {}", site.title),
                    subtitle: site.url.clone(),
                    badge: "网站".into(),
                    score: 94.0,
                    capability_id: Some("web.open".into()),
                    arguments: json!({ "url": site.url, "title": site.title }),
                    resource_uri: None,
                });
            }
        }

        for (b_url, b_title, browser) in self.resources.search_bookmarks(bare, 2) {
            if !items
                .iter()
                .any(|i| i.arguments.get("url").and_then(|u| u.as_str()) == Some(&b_url))
            {
                items.push(CandidateItem {
                    id: format!("bm:{}", b_url),
                    kind: CandidateKind::Web,
                    title: format!("书签：{}", b_title),
                    subtitle: format!("{} · {}", browser, b_url),
                    badge: "书签".into(),
                    score: 86.0,
                    capability_id: Some("web.open".into()),
                    arguments: json!({ "url": b_url, "title": b_title }),
                    resource_uri: None,
                });
            }
        }

        let file_filter = FileSearchFilter {
            query: Some(bare.to_string()),
            limit: 5,
            ..Default::default()
        };
        for (frec, score) in self.resources.search_files(&file_filter) {
            let fid = format!("file:{}", frec.path);
            if !items.iter().any(|i| i.id == fid) {
                items.push(CandidateItem {
                    id: fid,
                    kind: CandidateKind::File,
                    title: frec.name.clone(),
                    subtitle: format!("{} · {}", frec.parent_dir, human_bytes(frec.size_bytes)),
                    badge: "文件".into(),
                    score,
                    capability_id: Some("file.open".into()),
                    arguments: json!({ "path": frec.path }),
                    resource_uri: Some(format!("file://{}", frec.path)),
                });
            }
        }

        // 4. Always offer Google search & L2 Agent fallback at the bottom
        let (google_url, engine_name) = self.resources.build_search_url(trimmed, None);
        items.push(CandidateItem {
            id: "websearch:default".into(),
            kind: CandidateKind::WebSearch,
            title: format!("在 {} 搜索 “{}”", engine_name, trimmed),
            subtitle: google_url,
            badge: "搜索".into(),
            score: 40.0,
            capability_id: Some("web.search".into()),
            arguments: json!({ "query": trimmed, "engine": self.resources.app_config().web.default_search }),
            resource_uri: None,
        });

        items.push(CandidateItem {
            id: "agent:l2".into(),
            kind: CandidateKind::AgentFallback,
            title: "作为复杂意图交给智能体处理（Ctrl+Enter）".to_string(),
            subtitle: "L1/L2 多步规划与受控执行".into(),
            badge: "L2".into(),
            score: 20.0,
            capability_id: None,
            arguments: json!({ "text": trimmed }),
            resource_uri: None,
        });

        items.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        items.truncate(10);

        CandidateResponse {
            query: trimmed.to_string(),
            elapsed_us: start.elapsed().as_micros() as u64,
            l0_direct_match: l0_direct,
            items,
        }
    }

    /// Deterministic L0 routing entry point (§4.1, §4.5, §4.6).
    pub fn route_text(&self, raw_input: &str, force_agent: bool) -> RoutedIntent {
        let text = raw_input.trim();
        if text.is_empty() {
            return RoutedIntent::Rejected {
                reason: "输入为空".into(),
            };
        }
        if force_agent {
            return RoutedIntent::EscalateL2 {
                reason: "用户强制使用智能体路由".into(),
            };
        }

        let lc = text.to_ascii_lowercase();
        if lc == "sudo"
            || lc.starts_with("sudo ")
            || text.contains("给我 root shell")
            || text.contains("提权到 root")
        {
            return RoutedIntent::Rejected {
                reason:
                    "安全策略拒绝直接请求 sudo 或无限制 root Shell；系统级任务须走受控 Polkit 能力"
                        .into(),
            };
        }

        // 0. Undo commands
        if matches!(
            lc.as_str(),
            "撤销"
                | "undo"
                | "撤回"
                | "撤销刚才的操作"
                | "撤销刚才的修改"
                | "撤销刚才的整理"
                | "恢复刚才的设置"
                | "恢复刚才的亮度"
                | "恢复刚才的音量"
                | "恢复之前的设置"
        ) {
            return RoutedIntent::UndoLatest;
        }

        // 1a. Save current settings as custom scene ("把现在的设置保存为写作模式" / "把当前设置存成深夜码字模式")
        let save_scene_re =
            Regex::new(r"^(?:把)?(?:现在|当前)?(?:的)?设置(?:保存为|保存成|存成|存为)\s*(.+?)$")
                .unwrap();
        if let Some(caps) = save_scene_re.captures(text) {
            let name = caps[1].trim();
            if !name.is_empty() {
                return RoutedIntent::SaveCurrentScene {
                    name: name.to_string(),
                };
            }
        }

        // 1b. Explicit Memory ("记住 docx 用 WPS 打开" -> `open_with.docx`, or generic `user.preference`, A22)
        if let Some(routed) = self.try_route_explicit_memory(text) {
            return routed;
        }

        // 1c. Cognitive Goal, System Diagnosis, Procedural How-To & Multi-Goal Task Escalation (`v0.2-M1`)
        let structured_goal = crate::intent_engine::parse_structured_intent(text, &[]);
        if structured_goal.intent_type.requires_agent_planning() {
            return RoutedIntent::EscalateL2 {
                reason: structured_goal.escalation_summary(),
            };
        }

        if looks_multi_step_complex(text) {
            return RoutedIntent::EscalateL2 {
                reason: "检测到跨能力多步复合意图，升级至 L2 Agent 循环".into(),
            };
        }

        // 2. D5 System Settings, Scenes & Control Center Panels
        if let Some(routed) = self.try_route_system_settings(text) {
            return routed;
        }

        // 3. D6 Devtools / Quick System Queries
        if let Some(routed) = self.try_route_devtools(text) {
            return routed;
        }

        // 4. D1 App Quit & Window Focus / List
        if let Some(routed) = self.try_route_app_and_window(text) {
            return routed;
        }

        // 5. D4 Site-Specific Search & General Web Search (Default Google)
        if let Some(routed) = self.try_route_web_search(text) {
            return routed;
        }

        // 6. D3 File Move / Rename / Copy / Trash / Reveal / Recent / Archive
        if let Some(routed) = self.try_route_file_move(text) {
            return routed;
        }
        if let Some(routed) = self.try_route_file_mutations_and_archives(text) {
            return routed;
        }

        // 7. D2 "用 <App> 打开 <File>"
        if let Some(routed) = self.try_route_open_with(text) {
            return routed;
        }

        // 8. D3 File Grep ("哪个文件里写了 API_BASE")
        if let Some(routed) = self.try_route_file_grep(text) {
            return routed;
        }

        // 9. D3 File Search / Filter ("找...", "下载里大于 1G 的文件", "上周改过的 md")
        if let Some(routed) = self.try_route_file_search(text) {
            return routed;
        }

        // 10. D1 / D2 / D4 Unified "Search and Open" ("打开 X" or bare shortcut)
        if let Some(routed) = self.try_route_open_target(text) {
            return routed;
        }

        // 11. Escalate remaining colloquial or multi-step tasks to L1 Decision Adapter -> L2 Agent!
        RoutedIntent::EscalateL2 {
            reason: "L0 无高置信确定性匹配，交由 L1/L2 决策与智能体处理".into(),
        }
    }

    fn try_route_explicit_memory(&self, text: &str) -> Option<RoutedIntent> {
        let rest = text
            .strip_prefix("记住")
            .or_else(|| text.strip_prefix("以后默认"))?;
        let fact = rest
            .trim()
            .trim_start_matches(['：', ':', '，', ','])
            .trim();
        if fact.is_empty() {
            return None;
        }

        // Structured file-association preference (`A22`: "docx 用 WPS 打开" / "用 Okular 打开 pdf")
        let assoc_re1 = Regex::new(
            r"^(?:把)?\s*\.?([a-zA-Z0-9]{1,10})\s*(?:文件|文档)?\s*(?:默认|都)?用\s*(.+?)\s*打开$",
        )
        .unwrap();
        let assoc_re2 =
            Regex::new(r"^用\s*(.+?)\s*打开\s*\.?([a-zA-Z0-9]{1,10})\s*(?:文件|文档)?$").unwrap();

        if let Some(caps) = assoc_re1.captures(fact) {
            let ext = caps[1].trim().to_ascii_lowercase();
            let app_hint = caps[2].trim();
            let resolved_app = self
                .resources
                .resolve_best_app(app_hint)
                .map(|a| a.app_id)
                .unwrap_or_else(|| app_hint.to_string());
            return Some(RoutedIntent::SaveExplicitMemory {
                subject: format!("open_with.{}", ext),
                value: resolved_app,
            });
        }
        if let Some(caps) = assoc_re2.captures(fact) {
            let app_hint = caps[1].trim();
            let ext = caps[2].trim().to_ascii_lowercase();
            let resolved_app = self
                .resources
                .resolve_best_app(app_hint)
                .map(|a| a.app_id)
                .unwrap_or_else(|| app_hint.to_string());
            return Some(RoutedIntent::SaveExplicitMemory {
                subject: format!("open_with.{}", ext),
                value: resolved_app,
            });
        }

        Some(RoutedIntent::SaveExplicitMemory {
            subject: "user.preference".into(),
            value: fact.to_string(),
        })
    }

    fn try_route_app_and_window(&self, text: &str) -> Option<RoutedIntent> {
        let t = text.trim();

        if matches!(
            t,
            "列出窗口" | "当前有哪些窗口" | "查看打开的窗口" | "打开了哪些窗口" | "窗口列表"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "window.list".into(),
                arguments: json!({}),
                summary: "列出当前打开的桌面窗口".into(),
            });
        }

        let focus_re = Regex::new(r"^(?:切到|切回|聚焦|切换到|唤醒|前置)\s*(.+?)\s*窗口$").unwrap();
        if let Some(caps) = focus_re.captures(t) {
            let q = caps[1].trim();
            if !q.is_empty() {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "window.focus".into(),
                    arguments: json!({ "query": q }),
                    summary: format!("聚焦「{}」窗口", q),
                });
            }
        }
        let focus_front_re = Regex::new(r"^把\s*(.+?)\s*(?:窗口)?(?:切到前台|置顶|前置)$").unwrap();
        if let Some(caps) = focus_front_re.captures(t) {
            let q = caps[1].trim();
            if !q.is_empty() {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "window.focus".into(),
                    arguments: json!({ "query": q }),
                    summary: format!("聚焦「{}」窗口", q),
                });
            }
        }

        let quit_re =
            Regex::new(r"^(?:关闭应用|退出应用|关闭软件|关闭进程|关闭|关掉|退出)\s*(.+)$").unwrap();
        if let Some(caps) = quit_re.captures(t) {
            let target = caps[1]
                .trim()
                .trim_matches(['"', '\'', '“', '”', '「', '」']);
            let setting_words = [
                "静音",
                "勿扰",
                "蓝牙",
                "wifi",
                "wi-fi",
                "无线",
                "夜灯",
                "护眼",
                "防蓝光",
                "动画",
                "飞行模式",
                "自动锁屏",
                "自然滚动",
                "轻触点击",
                "电脑",
                "深色",
                "浅色",
                "暗黑",
                "省电",
                "续航",
                "性能",
                "麦克风",
                "秒数",
            ];
            let tl = target.to_ascii_lowercase();
            if !target.is_empty() && !setting_words.iter().any(|w| tl.contains(w)) {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "app.quit".into(),
                    arguments: json!({ "app": target }),
                    summary: format!("关闭应用「{}」并验证进程退出", target),
                });
            }
        }

        None
    }

    fn try_route_file_mutations_and_archives(&self, text: &str) -> Option<RoutedIntent> {
        let t = text.trim();

        // 1. Recent files
        if matches!(
            t,
            "最近改过的文件"
                | "最近修改的文件"
                | "最近的文件"
                | "最近文档"
                | "查看最近文件"
                | "recent files"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "file.recent".into(),
                arguments: json!({ "limit": 10 }),
                summary: "列出最近修改的授权文件".into(),
            });
        }

        // 2. Reveal in file manager ("打开 X 所在文件夹" / "在文件管理器中显示 X")
        let reveal_re =
            Regex::new(r"^(?:打开|查看|定位)\s*(.+?)\s*所在(?:的)?(?:文件夹|目录)$").unwrap();
        if let Some(caps) = reveal_re.captures(t) {
            let raw = caps[1].trim();
            if let Some(path) = self.resolve_single_file_hint(raw) {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "file.reveal".into(),
                    arguments: json!({ "path": path }),
                    summary: format!("在文件管理器中定位 {}", path),
                });
            }
        }

        // 3. Rename ("把 X 重命名为 Y" / "把 X 改名为 Y")
        let rename_re = Regex::new(r"^把\s*(.+?)\s*(?:重命名为|改名为|名字改成)\s*(.+)$").unwrap();
        if let Some(caps) = rename_re.captures(t) {
            let src_raw = caps[1].trim();
            let new_name = caps[2].trim().trim_matches(['"', '\'', '“', '”']);
            if let Some(src_path) = self.resolve_single_file_hint(src_raw)
                && !new_name.is_empty()
            {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "file.rename".into(),
                    arguments: json!({ "source": src_path, "new_name": new_name }),
                    summary: format!("将文件重命名为 {}", new_name),
                });
            }
        }

        // 4. Copy ("把 X 复制到 Y")
        let copy_re = Regex::new(r"^把\s*(.+?)\s*(?:复制到|拷贝到|备份到)\s*(.+)$").unwrap();
        if let Some(caps) = copy_re.captures(t) {
            let src_raw = caps[1].trim();
            let dst_raw = caps[2].trim();
            if let Some(src_path) = self.resolve_single_file_hint(src_raw) {
                let dst_dir = if dst_raw.starts_with('/') {
                    Some(std::path::PathBuf::from(dst_raw))
                } else {
                    self.resources.resolve_named_directory(dst_raw)
                };
                if let Some(d) = dst_dir
                    && let Some(leaf) = Path::new(&src_path).file_name()
                {
                    let final_dst = if d.extension().is_some() {
                        d
                    } else {
                        d.join(leaf)
                    };
                    return Some(RoutedIntent::ExecuteL0 {
                        capability_id: "file.copy".into(),
                        arguments: json!({
                            "source": src_path,
                            "target": final_dst.to_string_lossy().to_string()
                        }),
                        summary: format!("复制文件至 {}", final_dst.display()),
                    });
                }
            }
        }

        // 5. Trash ("把 X 移到回收站" / "删除文件 X")
        let trash_re = Regex::new(
            r"^(?:把\s*(.+?)\s*(?:移到|丢进|放入)回收站|(?:删除文件|移入回收站)\s+(.+))$",
        )
        .unwrap();
        if let Some(caps) = trash_re.captures(t) {
            let raw = caps.get(1).or_else(|| caps.get(2))?.as_str().trim();
            if let Some(p) = self.resolve_single_file_hint(raw) {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "file.trash".into(),
                    arguments: json!({ "path": p }),
                    summary: format!("将 {} 移入回收站（可一键撤销）", p),
                });
            }
        }

        // 6. Archive Extract ("解压 X" / "把 X 解压到 Y")
        let ext_to_re = Regex::new(r"^把\s*(.+?)\s*解压到\s*(.+)$").unwrap();
        if let Some(caps) = ext_to_re.captures(t) {
            let arch_raw = caps[1].trim();
            let dst_raw = caps[2].trim();
            if let Some(arch) = self.resolve_single_file_hint(arch_raw) {
                let dst = if dst_raw.starts_with('/') {
                    Some(std::path::PathBuf::from(dst_raw))
                } else {
                    self.resources.resolve_named_directory(dst_raw)
                };
                if let Some(d) = dst {
                    return Some(RoutedIntent::ExecuteL0 {
                        capability_id: "archive.extract".into(),
                        arguments: json!({
                            "archive": arch,
                            "destination": d.to_string_lossy().to_string()
                        }),
                        summary: format!("解压 {} 至 {}", arch, d.display()),
                    });
                }
            }
        }
        if let Some(rest) = t.strip_prefix("解压") {
            let arch_raw = rest.trim();
            if let Some(arch) = self.resolve_single_file_hint(arch_raw) {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "archive.extract".into(),
                    arguments: json!({ "archive": arch }),
                    summary: format!("解压归档 {}", arch),
                });
            }
        }

        // 7. Archive Create ("把 X 打包成 Y" / "把 X 压缩为 Y")
        let pack_re = Regex::new(r"^把\s*(.+?)\s*(?:打包成|打包为|压缩成|压缩为)\s*(.+)$").unwrap();
        if let Some(caps) = pack_re.captures(t) {
            let src_raw = caps[1].trim();
            let out_raw = caps[2].trim();
            let src_resolved = self.resolve_single_file_hint(src_raw).or_else(|| {
                self.resources
                    .resolve_named_directory(src_raw)
                    .map(|p| p.to_string_lossy().to_string())
            });
            if let Some(src_p) = src_resolved {
                let out_p = if out_raw.starts_with('/') {
                    out_raw.to_string()
                } else {
                    let parent = Path::new(&src_p)
                        .parent()
                        .unwrap_or_else(|| Path::new("/tmp"));
                    parent.join(out_raw).to_string_lossy().to_string()
                };
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "archive.create".into(),
                    arguments: json!({ "source": src_p, "output": out_p }),
                    summary: format!("打包 {} → {}", src_p, out_p),
                });
            }
        }

        // 8. Clipboard copy ("复制文本 XXX" / "把 XXX 复制到剪贴板")
        let clip_re = Regex::new(r"^(?:把\s*(.+?)\s*复制到剪贴板|复制文本\s+(.+))$").unwrap();
        if let Some(caps) = clip_re.captures(t) {
            let content = caps.get(1).or_else(|| caps.get(2))?.as_str().trim();
            if !content.is_empty() {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "clipboard.copy".into(),
                    arguments: json!({ "text": content }),
                    summary: "复制文本到系统剪贴板".into(),
                });
            }
        }

        None
    }

    fn resolve_single_file_hint(&self, hint: &str) -> Option<String> {
        let h = hint.trim();
        if h.starts_with('/') {
            return Some(h.to_string());
        }
        let hits = self.resources.search_files(&FileSearchFilter {
            query: Some(h.to_string()),
            limit: 2,
            ..Default::default()
        });
        if hits.len() == 1 || (hits.len() >= 2 && hits[0].1 - hits[1].1 >= 12.0) {
            Some(hits[0].0.path.clone())
        } else {
            None
        }
    }

    fn try_route_system_settings(&self, text: &str) -> Option<RoutedIntent> {
        let t = text.trim();
        let lc = t.to_ascii_lowercase();

        // Reject unregistered dangerous settings explicitly (§7.8.3, §19.2)
        if t.contains("修改系统代理")
            || t.contains("把代理改成")
            || lc.starts_with("gsettings set ")
            || t.contains("改全局快捷键")
        {
            return Some(RoutedIntent::Rejected {
                reason: "安全策略拒绝模型或未登记指令直接修改任意 gsettings / 代理 / 快捷键（白名单保护 D20）"
                    .into(),
            });
        }

        if t.starts_with("怎么") || t.starts_with("如何") || t.starts_with("怎样") {
            return None;
        }

        // Composite Scenes (`scene.apply`, §7.8.2 K, A11e)
        for scene_name in ["护眼模式", "演示模式", "安静模式", "会议模式", "专注模式"]
        {
            if t == scene_name
                || t == format!("开启{}", scene_name)
                || t == format!("打开{}", scene_name)
                || t == format!("进入{}", scene_name)
                || t == format!("切到{}", scene_name)
            {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "scene.apply".into(),
                    arguments: json!({ "scene": scene_name }),
                    summary: format!("应用「{}」组合设置", scene_name),
                });
            }
        }
        // Custom user-saved scenes in state_db
        if let Some(ref db) = self.state_db {
            let stripped = t
                .strip_prefix("开启")
                .or_else(|| t.strip_prefix("打开"))
                .or_else(|| t.strip_prefix("进入"))
                .or_else(|| t.strip_prefix("切到"))
                .unwrap_or(t)
                .trim();
            if db.get_custom_scene(stripped).is_some() {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "scene.apply".into(),
                    arguments: json!({ "scene": stripped }),
                    summary: format!("应用自定义场景「{}」", stripped),
                });
            }
        }

        // Reset to default ("字体恢复默认", "音量恢复默认", "亮度恢复默认")
        if let Some(prefix) = t
            .strip_suffix("恢复默认")
            .or_else(|| t.strip_suffix("重置默认"))
        {
            let p = prefix.trim();
            let key_id = if p.contains("等宽字体") {
                Some("appearance.font.monospace")
            } else if p.contains("界面字体") {
                Some("appearance.font.interface")
            } else if p.contains("字体") || p.contains("文字") || p.contains("字号") {
                Some("appearance.text_scale")
            } else if p.contains("麦克风") {
                Some("sound.mic.volume")
            } else if p.contains("音量") || p.contains("声音") {
                Some("sound.volume")
            } else if p.contains("亮度") || p.contains("屏幕") {
                Some("display.brightness")
            } else if p.contains("色温") {
                Some("display.night_light.temperature")
            } else if p.contains("光标") || p.contains("指针") {
                Some("appearance.cursor_size")
            } else if p.contains("主题") || p.contains("外观") || p.contains("深色") {
                Some("appearance.color_scheme")
            } else if p.contains("勿扰") {
                Some("notify.dnd")
            } else {
                None
            };
            if let Some(k) = key_id {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "settings.reset".into(),
                    arguments: json!({ "key_id": k }),
                    summary: format!("将「{}」恢复为默认值", p),
                });
            }
        }

        // Settings Home ("打开设置", "打开系统设置", "系统设置")
        if matches!(
            t,
            "打开设置" | "打开系统设置" | "系统设置" | "设置中心" | "open settings"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "settings.open".into(),
                arguments: json!({}),
                summary: "打开系统设置首页".into(),
            });
        }

        // Open Specific Settings Panel ("打开蓝牙设置", "显示设置", "蓝牙设置在哪")
        let panel_re =
            Regex::new(r"^(?:打开|进入|查看|去)?\s*(.+?)\s*设置(?:页|面板|在哪|在哪里)?$").unwrap();
        if let Some(caps) = panel_re.captures(t) {
            let raw_panel = caps[1].trim();
            if raw_panel != "系统"
                && !raw_panel.is_empty()
                && let Some((panel_id, label)) = SystemSettingsEngine::normalize_panel_id(raw_panel)
            {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "settings.open_panel".into(),
                    arguments: json!({ "panel": panel_id }),
                    summary: format!("打开「{}」系统设置面板", label),
                });
            }
        }

        // Color Scheme: Dark / Light
        if matches!(
            lc.as_str(),
            "深色模式"
                | "暗黑模式"
                | "夜间模式"
                | "暗色模式"
                | "开深色模式"
                | "开启深色模式"
                | "切换到深色模式"
                | "切到深色模式"
                | "换成深色模式"
                | "换成暗黑模式"
                | "dark mode"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.color_scheme.set".into(),
                arguments: json!({ "scheme": "prefer-dark" }),
                summary: "切换为深色模式".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "浅色模式"
                | "亮色模式"
                | "日间模式"
                | "开浅色模式"
                | "开启浅色模式"
                | "切换到浅色模式"
                | "切到浅色模式"
                | "换成浅色模式"
                | "light mode"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.color_scheme.set".into(),
                arguments: json!({ "scheme": "prefer-light" }),
                summary: "切换为浅色模式".into(),
            });
        }

        // Accent Color ("强调色改成蓝色" / "强调色 blue")
        if t.contains("强调色") {
            let color_map = [
                ("蓝", "blue"),
                ("blue", "blue"),
                ("青", "teal"),
                ("teal", "teal"),
                ("绿", "green"),
                ("green", "green"),
                ("黄", "yellow"),
                ("yellow", "yellow"),
                ("橙", "orange"),
                ("橘", "orange"),
                ("orange", "orange"),
                ("红", "red"),
                ("red", "red"),
                ("粉", "pink"),
                ("pink", "pink"),
                ("紫", "purple"),
                ("purple", "purple"),
                ("灰", "slate"),
                ("slate", "slate"),
            ];
            for (kw, val) in color_map {
                if lc.contains(kw) {
                    return Some(RoutedIntent::ExecuteL0 {
                        capability_id: "appearance.accent_color.set".into(),
                        arguments: json!({ "color": val }),
                        summary: format!("设置系统强调色为 {}", val),
                    });
                }
            }
        }

        // Do Not Disturb
        if matches!(
            lc.as_str(),
            "关闭勿扰"
                | "取消勿扰"
                | "关掉勿扰"
                | "关闭勿扰模式"
                | "取消免打扰"
                | "退出勿扰模式"
                | "dnd off"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "notify.dnd.set".into(),
                arguments: json!({ "enabled": false }),
                summary: "关闭勿扰模式".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "勿扰"
                | "勿扰模式"
                | "开启勿扰"
                | "打开勿扰"
                | "打开勿扰模式"
                | "开勿扰"
                | "免打扰"
                | "开启免打扰"
                | "dnd"
                | "dnd on"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "notify.dnd.set".into(),
                arguments: json!({ "enabled": true }),
                summary: "开启勿扰模式".into(),
            });
        }

        // Microphone Mute & Volume
        if matches!(
            lc.as_str(),
            "闭麦" | "关麦" | "麦克风静音" | "把麦克风静音" | "关闭麦克风" | "mute mic"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.mic.mute.set".into(),
                arguments: json!({ "state": "on" }),
                summary: "开启麦克风静音（闭麦）".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "开麦" | "取消闭麦" | "取消麦克风静音" | "打开麦克风" | "恢复麦克风" | "unmute mic"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.mic.mute.set".into(),
                arguments: json!({ "state": "off" }),
                summary: "取消麦克风静音（开麦）".into(),
            });
        }
        if t.contains("麦克风") {
            if let Some(num) = extract_first_number(t) {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "sound.mic.volume.set".into(),
                    arguments: json!({ "value": num }),
                    summary: format!("将麦克风音量设为 {}%", num),
                });
            }
            let t_mic_dir = t.replace("大小", "").replace("高低", "");
            if t_mic_dir.contains("大")
                || t_mic_dir.contains("高")
                || t_mic_dir.contains("升")
                || t_mic_dir.contains("加")
                || t_mic_dir.contains("小")
                || t_mic_dir.contains("低")
                || t_mic_dir.contains("降")
                || t_mic_dir.contains("减")
            {
                let dir = if t_mic_dir.contains("小")
                    || t_mic_dir.contains("低")
                    || t_mic_dir.contains("降")
                    || t_mic_dir.contains("减")
                {
                    "down"
                } else {
                    "up"
                };
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "sound.mic.volume.set".into(),
                    arguments: json!({ "relative": dir }),
                    summary: format!("调整麦克风音量 ({})", dir),
                });
            }
        }

        // Audio Output List & Switch
        if matches!(
            t,
            "音频输出设备" | "查看音频输出" | "有哪些音响" | "声音输出列表"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.output.list".into(),
                arguments: json!({}),
                summary: "列出可用音频输出设备".into(),
            });
        }
        let out_re = Regex::new(
            r"^(?:把)?(?:声音|音频|音频输出)?(?:切到|切换到|改到)\s*(耳机|扬声器|外放|音响|HDMI)$",
        )
        .unwrap();
        if let Some(caps) = out_re.captures(t) {
            let dev = caps[1].trim();
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.output.set".into(),
                arguments: json!({ "device": dev }),
                summary: format!("切换音频输出至「{}」", dev),
            });
        }

        // Mute / Unmute
        if matches!(
            lc.as_str(),
            "取消静音" | "关闭静音" | "解除静音" | "恢复声音" | "打开声音" | "unmute"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.mute.set".into(),
                arguments: json!({ "mode": "off" }),
                summary: "取消静音".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "静音" | "开启静音" | "把声音关掉" | "关声音" | "mute"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.mute.set".into(),
                arguments: json!({ "mode": "on" }),
                summary: "开启静音".into(),
            });
        }

        // Volume Get / Relative / Numeric
        if matches!(
            lc.as_str(),
            "音量" | "当前音量" | "查音量" | "音量多少" | "音量是多少" | "查看音量"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.volume.get".into(),
                arguments: json!({}),
                summary: "查询当前音量".into(),
            });
        }
        let t_vol_dir = t.replace("大小", "").replace("高低", "");
        if ((t.contains("音量") || t.contains("声音") || lc.starts_with("vol"))
            && (t_vol_dir.contains("小")
                || t_vol_dir.contains("低")
                || t_vol_dir.contains("降")
                || t_vol_dir.contains("减")
                || lc.contains("down"))
            && !t_vol_dir.contains("太小")
            && !t_vol_dir.contains("太低")
            && extract_first_number(t).is_none())
            || matches!(t, "小声点" | "调小一点" | "声音轻一点")
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.volume.set".into(),
                arguments: json!({ "relative": "down" }),
                summary: "相对调整音量 (-10%)".into(),
            });
        }
        if ((t.contains("音量") || t.contains("声音") || lc.starts_with("vol"))
            && (t_vol_dir.contains("大")
                || t_vol_dir.contains("高")
                || t_vol_dir.contains("升")
                || t_vol_dir.contains("提")
                || t_vol_dir.contains("加")
                || lc.contains("up"))
            && !t_vol_dir.contains("太大")
            && !t_vol_dir.contains("太高")
            && extract_first_number(t).is_none())
            || t == "大声点"
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.volume.set".into(),
                arguments: json!({ "relative": "up" }),
                summary: "调高音量 (+10%)".into(),
            });
        }
        let vol_num_re = Regex::new(
            r"^(?:把)?(?:音量|声音|volume|vol)\s*(?:调到|设为|改成|调成|设置到|[:=])?\s*(-?\d+(?:\.\d+)?)\s*%?$",
        )
        .unwrap();
        if let Some(caps) = vol_num_re.captures(&lc)
            && let Ok(val) = caps[1].parse::<f64>()
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "sound.volume.set".into(),
                arguments: json!({ "value": val }),
                summary: format!("将音量设为 {}%", val),
            });
        }

        // Night Light & Temperature
        if matches!(
            lc.as_str(),
            "开夜灯" | "打开夜灯" | "开启夜灯" | "夜灯模式" | "开启护眼灯" | "night light on"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.night_light.set".into(),
                arguments: json!({ "state": "on" }),
                summary: "开启夜灯护眼".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "关夜灯" | "关闭夜灯" | "关掉夜灯" | "关闭护眼灯" | "night light off"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.night_light.set".into(),
                arguments: json!({ "state": "off" }),
                summary: "关闭夜灯护眼".into(),
            });
        }
        if matches!(
            t,
            "暖一点"
                | "屏幕暖一点"
                | "色温暖一点"
                | "黄一点"
                | "冷一点"
                | "屏幕冷一点"
                | "色温冷一点"
        ) {
            let rel = if t.contains("暖") || t.contains("黄") {
                "warmer"
            } else {
                "cooler"
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.night_light.temperature".into(),
                arguments: json!({ "relative": rel }),
                summary: format!(
                    "调整夜灯色温（{}）",
                    if rel == "warmer" { "更暖" } else { "更冷" }
                ),
            });
        }
        let temp_re =
            Regex::new(r"^(?:把)?(?:夜灯)?色温\s*(?:调到|设为|改成)?\s*(\d{3,4})\s*[kK]?$")
                .unwrap();
        if let Some(caps) = temp_re.captures(t)
            && let Ok(k) = caps[1].parse::<f64>()
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.night_light.temperature".into(),
                arguments: json!({ "value": k }),
                summary: format!("设置夜灯色温为 {}K", k as i64),
            });
        }

        // Idle Delay ("不熄屏" / "10分钟后熄屏")
        if matches!(
            t,
            "不熄屏" | "从不熄屏" | "禁止熄屏" | "禁止自动熄屏" | "保持亮屏"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.idle_delay.set".into(),
                arguments: json!({ "seconds": 0 }),
                summary: "设置屏幕从不自动熄屏".into(),
            });
        }
        let idle_min_re = Regex::new(r"^(\d+)\s*分钟(?:后)?(?:自动)?熄屏$").unwrap();
        if let Some(caps) = idle_min_re.captures(t)
            && let Ok(mins) = caps[1].parse::<u64>()
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.idle_delay.set".into(),
                arguments: json!({ "seconds": mins * 60 }),
                summary: format!("设置 {} 分钟无操作后自动熄屏", mins),
            });
        }

        // Brightness Get / Relative / Numeric
        if matches!(
            lc.as_str(),
            "亮度" | "当前亮度" | "查亮度" | "亮度多少" | "亮度是多少" | "屏幕亮度"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.brightness.get".into(),
                arguments: json!({}),
                summary: "查询当前屏幕亮度".into(),
            });
        }
        let t_no_bright_noun = t.replace("亮度", "").replace("亮屏", "");
        let has_bright_down = t_no_bright_noun.contains("暗")
            || t_no_bright_noun.contains("低")
            || t_no_bright_noun.contains("小")
            || t_no_bright_noun.contains("降")
            || t_no_bright_noun.contains("减")
            || lc.contains("down");
        let has_bright_up = t_no_bright_noun.contains("亮")
            || t_no_bright_noun.contains("高")
            || t_no_bright_noun.contains("大")
            || t_no_bright_noun.contains("升")
            || t_no_bright_noun.contains("加")
            || t_no_bright_noun.contains("提")
            || lc.contains("up");
        if matches!(
            t,
            "暗一点" | "亮一点" | "调暗一点" | "调亮一点" | "再暗一点" | "再亮一点"
        ) || ((t.contains("亮度") || t.contains("屏幕") || lc.contains("brightness"))
            && (has_bright_down || has_bright_up)
            && extract_first_number(t).is_none())
        {
            let up = if has_bright_down
                && !t_no_bright_noun.contains("太暗")
                && !t_no_bright_noun.contains("太低")
            {
                false
            } else if has_bright_up
                && !t_no_bright_noun.contains("太亮")
                && !t_no_bright_noun.contains("太高")
            {
                true
            } else {
                t_no_bright_noun.contains("太暗") || t_no_bright_noun.contains("太低")
            };
            let dir = if up { "up" } else { "down" };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.brightness.set".into(),
                arguments: json!({ "relative": dir }),
                summary: format!("相对调整屏幕亮度 ({})", if up { "+10%" } else { "-10%" }),
            });
        }
        let bright_num_re = Regex::new(
            r"^(?:把)?(?:屏幕)?(?:亮度|brightness)\s*(?:调到|设为|改成|调成|设置到|[:=])?\s*(-?\d+(?:\.\d+)?)\s*%?$",
        )
        .unwrap();
        if let Some(caps) = bright_num_re.captures(&lc)
            && let Ok(val) = caps[1].parse::<f64>()
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "display.brightness.set".into(),
                arguments: json!({ "value": val }),
                summary: format!("将屏幕亮度设为 {}%", val),
            });
        }

        // Fonts (`appearance.font.*`, A11c) BEFORE generic text_scale!
        if matches!(
            t,
            "列出字体" | "查看已安装字体" | "有哪些字体" | "有哪些等宽字体" | "字体列表"
        ) {
            let q = if t.contains("等宽") {
                json!({ "query": "Mono" })
            } else {
                json!({})
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.font.list".into(),
                arguments: q,
                summary: "列出本机已安装字体".into(),
            });
        }
        let font_fam_re = Regex::new(
            r"^(?:把)?(等宽字体|代码字体|终端字体|界面字体|系统字体|文档字体)\s*(?:换成|设为|改成|调成)\s*(.+)$",
        )
        .unwrap();
        if let Some(caps) = font_fam_re.captures(t) {
            let kind = &caps[1];
            let fam_or_sz = caps[2].trim();
            let cap_id = if kind.contains("等宽") || kind.contains("代码") || kind.contains("终端")
            {
                "appearance.font.monospace.set"
            } else if kind.contains("文档") {
                "appearance.font.document.set"
            } else {
                "appearance.font.interface.set"
            };
            if let Ok(sz) = fam_or_sz.trim_end_matches("pt").trim().parse::<f64>() {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: cap_id.into(),
                    arguments: json!({ "size": sz }),
                    summary: format!("设置{}字号为 {}", kind, sz),
                });
            }
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: cap_id.into(),
                arguments: json!({ "family": fam_or_sz }),
                summary: format!("设置{}为 {}", kind, fam_or_sz),
            });
        }
        let font_sz_re = Regex::new(
            r"^(?:把)?(等宽字号|终端字号|界面字号|系统字号|文档字号)\s*(?:调成|设为|改成|调到)?\s*(\d+(?:\.\d+)?)\s*(?:pt|号)?$",
        )
        .unwrap();
        if let Some(caps) = font_sz_re.captures(t)
            && let Ok(sz) = caps[2].parse::<f64>()
        {
            let kind = &caps[1];
            let cap_id = if kind.contains("等宽") || kind.contains("终端") {
                "appearance.font.monospace.set"
            } else if kind.contains("文档") {
                "appearance.font.document.set"
            } else {
                "appearance.font.interface.set"
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: cap_id.into(),
                arguments: json!({ "size": sz }),
                summary: format!("设置{}为 {}pt", kind, sz),
            });
        }

        // Text Scale (Font scaling)
        let t_scale_dir = t.replace("大小", "");
        if (t.contains("字体") || t.contains("文字") || t.contains("字号") || t.starts_with("字"))
            && (t_scale_dir.contains("大一点")
                || t_scale_dir.contains("小一点")
                || t_scale_dir.contains("放大")
                || t_scale_dir.contains("缩小")
                || t_scale_dir.contains("调大")
                || t_scale_dir.contains("调小"))
            && extract_first_number(t).is_none()
        {
            let up = t_scale_dir.contains("放大")
                || t_scale_dir.contains("调大")
                || t_scale_dir.contains("大一点");
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.text_scale.set".into(),
                arguments: json!({ "relative": if up { "up" } else { "down" } }),
                summary: format!("{}界面文字缩放一档", if up { "放大" } else { "缩小" }),
            });
        }
        let scale_num_re = Regex::new(
            r"^(?:把)?(?:字体|文字|界面文字|字号|text\s*scale)\s*(?:缩放|大小|放大到|缩小到|设为|调到|改成|[:=])?\s*(\d+(?:\.\d+)?)\s*%?$",
        )
        .unwrap();
        if let Some(caps) = scale_num_re.captures(&lc)
            && let Ok(val) = caps[1].parse::<f64>()
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.text_scale.set".into(),
                arguments: json!({ "value": val }),
                summary: format!("设置界面文字缩放为 {}", val),
            });
        }

        // Cursor Size, Animations, Wallpaper, Clock
        if t.contains("光标") || t.contains("鼠标指针") {
            if let Some(sz) = extract_first_number(t) {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "appearance.cursor_size.set".into(),
                    arguments: json!({ "size": sz as i64 }),
                    summary: format!("设置鼠标指针大小为 {}", sz as i64),
                });
            }
            let t_cur_dir = t.replace("大小", "");
            if t_cur_dir.contains("大") || t_cur_dir.contains("小") {
                let rel = if t_cur_dir.contains("小") {
                    "down"
                } else {
                    "up"
                };
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "appearance.cursor_size.set".into(),
                    arguments: json!({ "relative": rel }),
                    summary: "调整鼠标指针大小".into(),
                });
            }
        }
        if matches!(
            t,
            "关闭动画"
                | "关掉动画"
                | "关闭桌面动画"
                | "减少动画"
                | "开启动画"
                | "打开动画"
                | "开启桌面动画"
        ) {
            let st = if t.contains("关") || t.contains("减") {
                "off"
            } else {
                "on"
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.animations.set".into(),
                arguments: json!({ "state": st }),
                summary: format!("{}桌面动画", if st == "on" { "开启" } else { "关闭" }),
            });
        }
        let wall_re = Regex::new(r"^(?:把\s*(.+?)\s*设为壁纸|壁纸(?:换成|设为)\s*(.+))$").unwrap();
        if let Some(caps) = wall_re.captures(t) {
            let raw = caps.get(1).or_else(|| caps.get(2))?.as_str().trim();
            let path = self
                .resolve_single_file_hint(raw)
                .unwrap_or_else(|| raw.to_string());
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.wallpaper.set".into(),
                arguments: json!({ "path": path }),
                summary: "更换桌面壁纸".into(),
            });
        }
        if matches!(t, "24小时制" | "改为24小时制" | "切换24小时制") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.clock.set".into(),
                arguments: json!({ "format": "24h" }),
                summary: "切换顶栏时钟为 24 小时制".into(),
            });
        }
        if matches!(t, "12小时制" | "改为12小时制" | "切换12小时制") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.clock.set".into(),
                arguments: json!({ "format": "12h" }),
                summary: "切换顶栏时钟为 12 小时制".into(),
            });
        }
        if matches!(t, "顶栏显示秒数" | "时钟显示秒数" | "显示秒数") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.clock.set".into(),
                arguments: json!({ "show_seconds": true }),
                summary: "开启顶栏时钟秒数显示".into(),
            });
        }
        if matches!(t, "隐藏时钟秒数" | "关闭时钟秒数") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "appearance.clock.set".into(),
                arguments: json!({ "show_seconds": false }),
                summary: "隐藏顶栏时钟秒数".into(),
            });
        }

        // Screen Lock & Autolock
        if matches!(
            lc.as_str(),
            "锁屏" | "锁定屏幕" | "立刻锁屏" | "lock screen"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "screen.lock".into(),
                arguments: json!({}),
                summary: "锁定当前桌面屏幕".into(),
            });
        }
        if matches!(
            t,
            "开启自动锁屏" | "打开自动锁屏" | "关闭自动锁屏" | "禁止自动锁屏"
        ) {
            let st = if t.contains("关") || t.contains("禁") {
                "off"
            } else {
                "on"
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "screen.autolock.set".into(),
                arguments: json!({ "state": st }),
                summary: format!("{}自动锁屏", if st == "on" { "开启" } else { "关闭" }),
            });
        }

        // Wi-Fi, Bluetooth, Airplane Mode
        if matches!(
            lc.as_str(),
            "开 wifi"
                | "开wifi"
                | "打开 wifi"
                | "开启 wifi"
                | "开 wi-fi"
                | "打开 wi-fi"
                | "打开无线网"
                | "开启无线网"
                | "wifi on"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "network.wifi.power".into(),
                arguments: json!({ "state": "on" }),
                summary: "开启 Wi-Fi 无线网络".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "关 wifi"
                | "关wifi"
                | "关闭 wifi"
                | "关掉 wifi"
                | "关 wi-fi"
                | "关闭 wi-fi"
                | "关闭无线网"
                | "wifi off"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "network.wifi.power".into(),
                arguments: json!({ "state": "off" }),
                summary: "关闭 Wi-Fi 无线网络".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "扫描 wifi" | "扫描 wi-fi" | "查看 wifi 列表" | "有哪些 wifi" | "有哪些无线网"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "network.wifi.list".into(),
                arguments: json!({}),
                summary: "扫描可见 Wi-Fi 网络列表".into(),
            });
        }
        let wifi_conn_re = Regex::new(
            r"^(?:连接|连上|切到)\s*(?:Wi-Fi|wifi|无线网)?\s*([A-Za-z0-9_\-\u4e00-\u9fa5]+?)(?:\s*(?:Wi-Fi|wifi|网络))?$",
        )
        .unwrap();
        if (lc.contains("wifi") || lc.contains("wi-fi") || t.contains("无线") || t.contains("网络"))
            && !t.contains("蓝牙")
            && let Some(caps) = wifi_conn_re.captures(t)
        {
            let ssid = caps[1].trim();
            if !ssid.is_empty() && ssid != "网络" && ssid != "状态" {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "network.wifi.connect".into(),
                    arguments: json!({ "ssid": ssid }),
                    summary: format!("连接 Wi-Fi 网络「{}」", ssid),
                });
            }
        }
        if matches!(t, "网络状态" | "当前网络状态" | "查看网络连接") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "network.status".into(),
                arguments: json!({}),
                summary: "查询当前网络连接状态".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "开蓝牙" | "打开蓝牙" | "开启蓝牙" | "bluetooth on"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "bluetooth.power".into(),
                arguments: json!({ "state": "on" }),
                summary: "开启系统蓝牙".into(),
            });
        }
        if matches!(
            lc.as_str(),
            "关蓝牙" | "关闭蓝牙" | "关掉蓝牙" | "bluetooth off"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "bluetooth.power".into(),
                arguments: json!({ "state": "off" }),
                summary: "关闭系统蓝牙".into(),
            });
        }
        if let Some(dev) = t
            .strip_prefix("连接蓝牙")
            .or_else(|| t.strip_prefix("蓝牙连接"))
        {
            let d = dev.trim();
            let target = if d.is_empty() { "蓝牙耳机" } else { d };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "bluetooth.connect".into(),
                arguments: json!({ "device": target }),
                summary: format!("连接蓝牙设备「{}」", target),
            });
        }
        if let Some(dev) = t.strip_prefix("断开蓝牙") {
            let d = dev.trim();
            let target = if d.is_empty() { "蓝牙耳机" } else { d };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "bluetooth.disconnect".into(),
                arguments: json!({ "device": target }),
                summary: format!("断开蓝牙设备「{}」", target),
            });
        }
        if matches!(
            t,
            "飞行模式" | "开启飞行模式" | "打开飞行模式" | "关闭飞行模式" | "退出飞行模式"
        ) {
            let st = if t.contains("关") || t.contains("退") {
                "off"
            } else {
                "on"
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "network.airplane.set".into(),
                arguments: json!({ "state": st }),
                summary: format!("{}飞行模式", if st == "on" { "开启" } else { "关闭" }),
            });
        }

        // Power & Battery
        if matches!(
            t,
            "电池电量" | "查看电量" | "电量多少" | "还有多少电" | "电池状态"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.battery.status".into(),
                arguments: json!({}),
                summary: "查询电池电量与充电状态".into(),
            });
        }
        if matches!(t, "当前电源模式" | "查看电源模式" | "电源模式") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.profile.get".into(),
                arguments: json!({}),
                summary: "查询当前电源模式".into(),
            });
        }
        if matches!(
            t,
            "省电模式" | "开启省电模式" | "切到省电模式" | "开启省电续航" | "省电续航"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.profile.set".into(),
                arguments: json!({ "profile": "power-saver" }),
                summary: "切换电源模式为省电模式".into(),
            });
        }
        if matches!(t, "性能模式" | "高性能模式" | "开启性能模式") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.profile.set".into(),
                arguments: json!({ "profile": "performance" }),
                summary: "切换电源模式为性能模式".into(),
            });
        }
        if matches!(t, "平衡模式" | "开启平衡模式" | "切回平衡模式") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.profile.set".into(),
                arguments: json!({ "profile": "balanced" }),
                summary: "切换电源模式为平衡模式".into(),
            });
        }
        if matches!(t, "睡眠" | "待机" | "挂起电脑" | "电脑睡眠") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.session".into(),
                arguments: json!({ "action": "suspend" }),
                summary: "挂起电脑进入睡眠（需确认）".into(),
            });
        }
        if matches!(t, "重启电脑" | "重启系统") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.session".into(),
                arguments: json!({ "action": "reboot" }),
                summary: "重启计算机（需确认）".into(),
            });
        }
        if matches!(t, "关机" | "关闭电脑") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.session".into(),
                arguments: json!({ "action": "poweroff" }),
                summary: "关闭计算机（需确认）".into(),
            });
        }
        if matches!(t, "注销登录" | "退出桌面会话") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "power.session".into(),
                arguments: json!({ "action": "logout" }),
                summary: "注销当前桌面会话（需确认）".into(),
            });
        }

        // Input: Mouse, Touchpad, Keyboard, Input Source
        if t.contains("鼠标") && (t.contains("快") || t.contains("慢") || t.contains("灵敏"))
        {
            let rel = if t.contains("慢") { "down" } else { "up" };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "input.mouse.speed".into(),
                arguments: json!({ "relative": rel }),
                summary: "调整鼠标指针速度".into(),
            });
        }
        if (t.contains("触控板") || t.contains("触摸板")) && (t.contains("快") || t.contains("慢"))
        {
            let rel = if t.contains("慢") { "down" } else { "up" };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "input.touchpad.speed".into(),
                arguments: json!({ "relative": rel }),
                summary: "调整触控板指针速度".into(),
            });
        }
        if t.contains("自然滚动") {
            let st = if t.contains("关") { "off" } else { "on" };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "input.touchpad.natural_scroll".into(),
                arguments: json!({ "state": st }),
                summary: format!("{}触控板自然滚动", if st == "on" { "开启" } else { "关闭" }),
            });
        }
        if t.contains("轻触点击") {
            let st = if t.contains("关") { "off" } else { "on" };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "input.touchpad.tap_to_click".into(),
                arguments: json!({ "state": st }),
                summary: format!("{}触控板轻触点击", if st == "on" { "开启" } else { "关闭" }),
            });
        }
        if (t.contains("键盘连发") || t.contains("按键重复"))
            && (t.contains("快") || t.contains("慢") || t.contains("默认"))
        {
            let preset = if t.contains("快") {
                "fast"
            } else if t.contains("慢") {
                "slow"
            } else {
                "normal"
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "input.keyboard.repeat".into(),
                arguments: json!({ "preset": preset }),
                summary: format!("设置键盘按键重复速度 ({})", preset),
            });
        }
        if matches!(
            t,
            "切换输入法" | "切输入法" | "切到中文输入法" | "切到英文输入法"
        ) {
            let src = if t.contains("中文") {
                "zh"
            } else if t.contains("英文") {
                "en"
            } else {
                "next"
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "input.source.switch".into(),
                arguments: json!({ "source": src }),
                summary: "切换系统输入源/输入法".into(),
            });
        }

        // Media & Screenshot
        if matches!(t, "暂停播放" | "暂停音乐" | "暂停歌曲") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "media.control".into(),
                arguments: json!({ "action": "pause" }),
                summary: "暂停当前媒体播放".into(),
            });
        }
        if matches!(t, "继续播放" | "播放暂停" | "播放音乐" | "恢复播放") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "media.control".into(),
                arguments: json!({ "action": "play-pause" }),
                summary: "播放/暂停当前媒体".into(),
            });
        }
        if matches!(
            t,
            "下一首" | "下一首歌" | "切歌" | "下一曲" | "切下一首" | "换首歌"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "media.control".into(),
                arguments: json!({ "action": "next" }),
                summary: "切换到下一首媒体".into(),
            });
        }
        if matches!(t, "上一首" | "上一首歌" | "上一曲" | "切上一首") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "media.control".into(),
                arguments: json!({ "action": "previous" }),
                summary: "切换到上一首媒体".into(),
            });
        }
        if matches!(t, "截图" | "截屏" | "区域截图" | "全屏截图" | "窗口截图") {
            let mode = if t == "全屏截图" {
                "fullscreen"
            } else if t == "窗口截图" {
                "window"
            } else {
                "area"
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "screenshot.take".into(),
                arguments: json!({ "mode": mode }),
                summary: format!("调用系统截图（{}）", mode),
            });
        }

        None
    }

    fn try_route_devtools(&self, text: &str) -> Option<RoutedIntent> {
        let t = text.trim();
        if t.starts_with("怎么") || t.starts_with("如何") || t.contains("命令是什么") {
            return None;
        }
        let lc = t.to_ascii_lowercase();

        if t.contains("磁盘还剩多少")
            || t.contains("磁盘空间")
            || t.contains("硬盘还剩多少")
            || t.contains("硬盘空间")
            || t.contains("磁盘剩余")
            || lc == "disk free"
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "disk.free".into(),
                arguments: json!({}),
                summary: "查看本机磁盘剩余空间".into(),
            });
        }

        if t.contains("目录大小") || t.contains("占了多少空间") || t.contains("占用空间")
        {
            let dir_opt = self.resources.resolve_named_directory(t);
            let args = match dir_opt {
                Some(d) => json!({ "path": d.to_string_lossy().to_string() }),
                None => json!({}),
            };
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "disk.usage".into(),
                arguments: args,
                summary: "统计授权目录磁盘占用".into(),
            });
        }

        if matches!(
            lc.as_str(),
            "我的 ip"
                | "我的ip"
                | "本机 ip"
                | "本机ip"
                | "查看 ip"
                | "查看ip"
                | "查看ip地址"
                | "查看 ip 地址"
                | "局域网 ip"
                | "局域网ip"
                | "内网 ip"
                | "内网ip"
                | "查看内网ip"
                | "查看内网 ip"
                | "查看局域网ip"
                | "查看局域网 ip"
                | "查一下内网地址"
                | "查一下局域网地址"
                | "查一下内网ip"
                | "查一下内网 ip"
                | "查一下本机ip"
                | "查一下本机 ip"
                | "查一下ip"
                | "查一下 ip"
                | "查一下ip地址"
                | "内网地址"
                | "局域网地址"
                | "本机地址"
                | "my ip"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "network.ip".into(),
                arguments: json!({}),
                summary: "查询本机网络接口与 IP 地址".into(),
            });
        }

        if t.contains("占内存最多的进程")
            || t.contains("最占内存的进程")
            || matches!(t, "查看进程" | "进程列表" | "查看高占用进程")
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "process.list".into(),
                arguments: json!({ "sort_by": "memory", "limit": 10 }),
                summary: "采样内存占用最高的前 10 个进程".into(),
            });
        }

        let kill_pid_re =
            Regex::new(r"^(?:结束进程|终止进程|杀掉进程)\s*(?:PID\s*)?(\d+)$").unwrap();
        if let Some(caps) = kill_pid_re.captures(t)
            && let Ok(pid) = caps[1].parse::<u32>()
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "process.terminate".into(),
                arguments: json!({ "pid": pid }),
                summary: format!("请求终止进程 PID {}（需确认）", pid),
            });
        }

        let term_at_re = Regex::new(r"^在\s*(.+?)\s*(?:打开|启动)终端$").unwrap();
        if let Some(caps) = term_at_re.captures(t)
            && let Some(dir) = self.resources.resolve_named_directory(&caps[1])
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "terminal.open_at".into(),
                arguments: json!({ "path": dir.to_string_lossy().to_string() }),
                summary: format!("在 {} 打开系统终端", dir.display()),
            });
        }

        let pkg_re =
            Regex::new(r"^(?:搜索软件包|查找软件包|apt\s*搜索)\s+([a-zA-Z0-9._+\-]+)$").unwrap();
        if let Some(caps) = pkg_re.captures(t) {
            let q = &caps[1];
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "package.search".into(),
                arguments: json!({ "query": q }),
                summary: format!("只读检索系统软件包 {}", q),
            });
        }

        let port_re = Regex::new(r"(?:端口\s*(\d{2,5})|(\d{2,5})\s*端口)").unwrap();
        if let Some(caps) = port_re.captures(t) {
            let p_str = caps.get(1).or_else(|| caps.get(2)).unwrap().as_str();
            if let Ok(port) = p_str.parse::<u16>() {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "port.inspect".into(),
                    arguments: json!({ "port": port }),
                    summary: format!("查询 {} 端口占用进程", port),
                });
            }
        }
        if matches!(t, "查看端口占用" | "监听端口" | "哪些端口在监听") {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "port.inspect".into(),
                arguments: json!({}),
                summary: "列出本机监听端口".into(),
            });
        }

        if matches!(
            t,
            "系统状态" | "系统负载" | "查看系统状态" | "内存使用情况" | "电脑状态" | "看看负载"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "system.inspect".into(),
                arguments: json!({}),
                summary: "采样当前系统负载与内存状态".into(),
            });
        }

        if matches!(
            lc.as_str(),
            "git 状态" | "git status" | "看看仓库状态" | "仓库状态"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "git.status".into(),
                arguments: json!({}),
                summary: "查看当前目录 Git 状态".into(),
            });
        }

        if matches!(
            lc.as_str(),
            "git log" | "最近 git 提交" | "查看 git 提交" | "最近提交记录" | "git 提交记录"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "git.log".into(),
                arguments: json!({ "limit": 10 }),
                summary: "查看最近 10 条 Git 提交记录".into(),
            });
        }

        if matches!(
            lc.as_str(),
            "git diff" | "查看 git diff" | "git 差异" | "git 改了什么" | "未提交差异"
        ) {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "git.diff".into(),
                arguments: json!({}),
                summary: "查看当前 Git 仓库未暂存改动统计".into(),
            });
        }

        if let Some(proj) = t
            .strip_prefix("打开项目")
            .or_else(|| t.strip_prefix("用编辑器打开项目"))
        {
            let hint = proj.trim();
            let resolved = self
                .resources
                .resolve_named_directory(if hint.is_empty() { "代码" } else { hint })
                .map(|p| p.to_string_lossy().to_string());
            if let Some(p) = resolved {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "project.open".into(),
                    arguments: json!({ "path": p }),
                    summary: format!("在代码编辑器中打开项目 {}", p),
                });
            }
        }

        None
    }

    fn try_route_web_search(&self, text: &str) -> Option<RoutedIntent> {
        let t = text.trim();

        // 1. "在 <Site> (上)?搜(索)? <Query>"
        let in_site_re = Regex::new(
            r"^(?:在|去|用)\s*([A-Za-z0-9\.\u4e00-\u9fa5]+?)\s*(?:上|里|中)?(?:搜一下|搜索|搜|查一下|查)\s+(.+)$",
        )
        .unwrap();
        if let Some(caps) = in_site_re.captures(t) {
            let site_raw = caps[1].trim();
            let query = caps[2].trim();
            if self.resources.find_site(site_raw).is_some() && !query.is_empty() {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "web.search_site".into(),
                    arguments: json!({ "site": site_raw, "query": query }),
                    summary: format!("在 {} 搜索 “{}”", site_raw, query),
                });
            }
        }

        // 2. Site prefix shorthand: "gh tokio select", "bili rust", "so borrow checker"
        if let Some((first, rest)) = t.split_once(char::is_whitespace) {
            let q = rest.trim();
            let shorthand_ids = [
                "gh", "bili", "so", "crates", "docsrs", "mdn", "npm", "arxiv", "hn",
            ];
            if !q.is_empty()
                && shorthand_ids
                    .iter()
                    .any(|alias| first.eq_ignore_ascii_case(alias))
            {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "web.search_site".into(),
                    arguments: json!({ "site": first, "query": q }),
                    summary: format!("在 {} 搜索 “{}”", first, q),
                });
            }
        }

        // 3. General search verbs ("搜 xxx", "搜一下 xxx", "搜索 xxx", "谷歌 xxx")
        let search_prefixes: &[(&str, Option<&str>)] = &[
            ("谷歌搜索", Some("google")),
            ("谷歌一下", Some("google")),
            ("谷歌 ", Some("google")),
            ("google ", Some("google")),
            ("百度一下", Some("baidu")),
            ("百度搜索", Some("baidu")),
            ("百度 ", Some("baidu")),
            ("必应搜索", Some("bing")),
            ("必应 ", Some("bing")),
            ("bing ", Some("bing")),
            ("搜一下", None),
            ("搜索", None),
            ("查一下", None),
            ("上网搜", None),
            ("搜 ", None),
            ("s ", None),
        ];

        let lc = t.to_ascii_lowercase();
        for (prefix, engine_opt) in search_prefixes {
            if lc.starts_with(prefix) {
                let query = t[prefix.len()..].trim();
                if *prefix == "查一下" {
                    let qlc = query.to_ascii_lowercase();
                    let is_local_net_query = (query.contains("内网")
                        || query.contains("局域网")
                        || query.contains("本机"))
                        && (query.contains("地址") || qlc.contains("ip"));
                    if is_local_net_query {
                        continue;
                    }
                }
                if !query.is_empty() {
                    let eng = engine_opt
                        .unwrap_or(&self.resources.app_config().web.default_search)
                        .to_string();
                    return Some(RoutedIntent::ExecuteL0 {
                        capability_id: "web.search".into(),
                        arguments: json!({ "query": query, "engine": eng }),
                        summary: format!("使用 {} 搜索 “{}”", eng, query),
                    });
                }
            }
        }
        if t.starts_with('搜') && !t.starts_with("搜文件") && t.chars().count() > 2 {
            let query = t.trim_start_matches('搜').trim();
            if !query.is_empty() {
                let eng = self.resources.app_config().web.default_search.clone();
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "web.search".into(),
                    arguments: json!({ "query": query, "engine": eng }),
                    summary: format!("使用 {} 搜索 “{}”", eng, query),
                });
            }
        }

        None
    }

    fn try_route_file_move(&self, text: &str) -> Option<RoutedIntent> {
        let re = Regex::new(r"^把\s*(.+?)\s*(?:移动到|挪到|移到|归档到)\s*(.+)$").unwrap();
        let caps = re.captures(text.trim())?;
        let src_raw = caps[1].trim();
        let dst_raw = caps[2].trim();
        if dst_raw == "回收站" {
            return None;
        }

        let src_path = self.resolve_single_file_hint(src_raw)?;
        let dst_dir = if dst_raw.starts_with('/') {
            std::path::PathBuf::from(dst_raw)
        } else {
            self.resources.resolve_named_directory(dst_raw)?
        };
        let leaf = Path::new(&src_path).file_name()?;
        let final_dst = if dst_dir.extension().is_some() {
            dst_dir
        } else {
            dst_dir.join(leaf)
        };

        Some(RoutedIntent::ExecuteL0 {
            capability_id: "file.move".into(),
            arguments: json!({
                "source": src_path,
                "target": final_dst.to_string_lossy().to_string()
            }),
            summary: format!("移动文件至 {}", final_dst.display()),
        })
    }

    fn try_route_open_with(&self, text: &str) -> Option<RoutedIntent> {
        let re = Regex::new(r"^用\s*(.+?)\s*打开\s*(.+)$").unwrap();
        let caps = re.captures(text.trim())?;
        let app_hint = caps[1].trim();
        let file_hint = caps[2].trim();

        let Some(app_rec) = self.resources.resolve_best_app(app_hint) else {
            return Some(RoutedIntent::Rejected {
                reason: format!("未找到指定的应用：“{}”", app_hint),
            });
        };

        let mut filter = parse_file_conditions(file_hint, &self.resources);
        filter.limit = 5;
        let file_hits = self.resources.search_files(&filter);
        match file_hits.len() {
            0 => Some(RoutedIntent::Rejected {
                reason: format!("在授权目录中未找到匹配文件：“{}”", file_hint),
            }),
            1 => Some(RoutedIntent::ExecuteL0 {
                capability_id: "file.open_with".into(),
                arguments: json!({
                    "app": app_rec.app_id,
                    "path": file_hits[0].0.path
                }),
                summary: format!("用 {} 打开 {}", app_rec.name, file_hits[0].0.name),
            }),
            _ if file_hits[0].1 - file_hits[1].1 >= 12.0 => Some(RoutedIntent::ExecuteL0 {
                capability_id: "file.open_with".into(),
                arguments: json!({
                    "app": app_rec.app_id,
                    "path": file_hits[0].0.path
                }),
                summary: format!("用 {} 打开 {}", app_rec.name, file_hits[0].0.name),
            }),
            _ => {
                let cands = file_hits
                    .into_iter()
                    .map(|(f, sc)| CandidateItem {
                        id: format!("openwith:{}", f.path),
                        kind: CandidateKind::File,
                        title: format!("用 {} 打开 {}", app_rec.name, f.name),
                        subtitle: f.path.clone(),
                        badge: "文件".into(),
                        score: sc,
                        capability_id: Some("file.open_with".into()),
                        arguments: json!({ "app": app_rec.app_id, "path": f.path }),
                        resource_uri: Some(format!("file://{}", f.path)),
                    })
                    .collect();
                Some(RoutedIntent::Disambiguate {
                    prompt: format!("找到多个与“{}”匹配的文件，请选择：", file_hint),
                    candidates: cands,
                })
            }
        }
    }

    fn try_route_file_grep(&self, text: &str) -> Option<RoutedIntent> {
        let patterns = [
            r"^(?:哪个|哪些)文件(?:里|中)?(?:写了|包含|有)\s*['\x22“”]?(.+?)['\x22“”]?$",
            r"^(?:找|查找|搜|搜索)?(?:内容)?(?:里写了|包含)\s*['\x22“”]?(.+?)['\x22“”]?\s*的文件$",
        ];
        for pat in patterns {
            let re = Regex::new(pat).unwrap();
            if let Some(caps) = re.captures(text.trim()) {
                let needle = caps[1].trim();
                if !needle.is_empty() {
                    return Some(RoutedIntent::ExecuteL0 {
                        capability_id: "file.grep".into(),
                        arguments: json!({ "pattern": needle }),
                        summary: format!("搜索包含 “{}” 的文件与行号", needle),
                    });
                }
            }
        }
        None
    }

    fn try_route_file_search(&self, text: &str) -> Option<RoutedIntent> {
        let t = text.trim();
        if t.starts_with("怎么") || t.starts_with("如何") {
            return None;
        }
        let lc = t.to_ascii_lowercase();

        let explicit_find = [
            "找一下",
            "查找文件",
            "查找",
            "搜文件",
            "哪里有",
            "找 ",
            "find ",
            "f ",
        ]
        .iter()
        .find_map(|p| {
            if lc.starts_with(p) {
                Some(t[p.len()..].trim())
            } else {
                None
            }
        })
        .or_else(|| {
            if t.starts_with('找') && !t.starts_with("找软件") && t.chars().count() > 1 {
                Some(t.trim_start_matches('找').trim())
            } else {
                None
            }
        });

        let condition_phrase = has_structured_file_condition(t) && !is_open_verb(t);
        let target_expr = if let Some(expr) = explicit_find {
            expr
        } else if condition_phrase {
            t
        } else {
            return None;
        };

        if target_expr.is_empty() {
            return None;
        }

        let filter = parse_file_conditions(target_expr, &self.resources);
        let mut args = serde_json::Map::new();
        if let Some(q) = filter.query {
            args.insert("query".into(), json!(q));
        }
        if !filter.extensions.is_empty() {
            args.insert("extensions".into(), json!(filter.extensions));
        }
        if let Some(cat) = filter.category {
            args.insert("category".into(), json!(cat));
        }
        if let Some(dir) = filter.directory_prefix {
            args.insert("directory".into(), json!(dir));
        }
        if let Some(min_b) = filter.min_size_bytes {
            args.insert("min_size_bytes".into(), json!(min_b));
        }
        if let Some(max_b) = filter.max_size_bytes {
            args.insert("max_size_bytes".into(), json!(max_b));
        }
        if let Some(after) = filter.modified_after_secs {
            args.insert("modified_since_secs".into(), json!(after));
        }
        args.insert(
            "sort_by".into(),
            serde_json::to_value(filter.sort_by).unwrap_or(json!("relevance_and_recent")),
        );

        Some(RoutedIntent::ExecuteL0 {
            capability_id: "file.search".into(),
            arguments: Value::Object(args),
            summary: format!("按条件检索文件：{}", target_expr),
        })
    }

    fn build_file_open_intent(&self, path: &str, name: &str, ext: &str) -> RoutedIntent {
        // Check explicit user preference memory `open_with.<ext>` (`A22` & §11.2)!
        if !ext.is_empty()
            && let Some(ref db) = self.state_db
            && let Some(pref_app) =
                db.get_memory_value(&format!("open_with.{}", ext.to_ascii_lowercase()))
        {
            return RoutedIntent::ExecuteL0 {
                capability_id: "file.open_with".into(),
                arguments: json!({ "app": pref_app, "path": path }),
                summary: format!("按已保存偏好用 {} 打开 {}", pref_app, name),
            };
        }
        RoutedIntent::ExecuteL0 {
            capability_id: "file.open".into(),
            arguments: json!({ "path": path }),
            summary: format!("打开文件 {}", name),
        }
    }

    fn try_route_open_target(&self, text: &str) -> Option<RoutedIntent> {
        let t = text.trim();
        let explicit_open = strip_open_verb(t);
        let target = explicit_open.unwrap_or(t).trim();
        if target.is_empty() {
            return None;
        }

        // Named XDG folder ("打开下载", "打开文档", "打开桌面")
        if matches!(
            target,
            "下载" | "下载目录" | "下载文件夹" | "文档" | "文档目录" | "桌面" | "代码目录"
        ) && let Some(dir) = self.resources.resolve_named_directory(target)
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "file.open".into(),
                arguments: json!({ "path": dir.to_string_lossy().to_string() }),
                summary: format!("打开目录 {}", dir.display()),
            });
        }

        // Check URL / Site resolution first for dangerous schemes or exact sites/URLs!
        match self.resources.resolve_web_target(target) {
            Err(bad_scheme_reason) => {
                return Some(RoutedIntent::Rejected {
                    reason: bad_scheme_reason,
                });
            }
            Ok(Some(web_hit)) => {
                let app_exact = self
                    .resources
                    .search_apps(target, 1)
                    .into_iter()
                    .find(|(_, sc)| *sc >= 96.0);
                if app_exact.is_none()
                    || t.starts_with("去")
                    || t.starts_with("上")
                    || t.starts_with("访问")
                {
                    return Some(RoutedIntent::ExecuteL0 {
                        capability_id: "web.open".into(),
                        arguments: json!({ "url": web_hit.url, "title": web_hit.title }),
                        summary: format!("打开网站 {}", web_hit.title),
                    });
                }
            }
            Ok(None) => {}
        }

        // Check Application match (D1: "打开 VS Code", "打开汽水音乐", "启动飞书", "打开轻笺", "开 vsc", "vsc", "wbbjq")
        let app_hits = self.resources.search_apps(target, 3);
        if let Some((top_app, top_score)) = app_hits.first() {
            let threshold = if explicit_open.is_some() { 80.0 } else { 90.0 };
            if *top_score >= threshold && !has_structured_file_condition(target) {
                return Some(RoutedIntent::ExecuteL0 {
                    capability_id: "app.launch".into(),
                    arguments: json!({
                        "app_id": top_app.app_id,
                        "app_name": top_app.name,
                        "query": target
                    }),
                    summary: format!("启动应用 {}", top_app.name),
                });
            }
        }
        if explicit_open.is_some()
            && !has_structured_file_condition(target)
            && target.to_ascii_lowercase().ends_with(".desktop")
            && let Some(app_rec) = self.resources.resolve_best_app(target)
        {
            return Some(RoutedIntent::ExecuteL0 {
                capability_id: "app.launch".into(),
                arguments: json!({
                    "app_id": app_rec.app_id,
                    "app_name": app_rec.name,
                    "query": target
                }),
                summary: format!("启动应用 {}", app_rec.name),
            });
        }

        // File Search-and-Open when explicit open verb was used ("打开昨天的周报", "打开最近的 PDF", "打开 /abs/path")
        if explicit_open.is_some() {
            // Defer chapter-specific document requests ("打开我的硕士论文第四章") to Smart Chapter Open in Core/L2
            if crate::memory_hub::extract_chapter_number_hint(target).is_some() {
                return None;
            }
            let clean_path = target.trim_matches(['"', '\'', '`', '“', '”']);
            let expanded_path_opt = if clean_path.starts_with('/') {
                Some(std::path::PathBuf::from(clean_path))
            } else if let Some(rest) = clean_path.strip_prefix("~/") {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
                Some(std::path::PathBuf::from(home).join(rest))
            } else {
                None
            };
            if let Some(ref exp_p) = expanded_path_opt
                && (exp_p.exists() || clean_path.contains("/.ssh/") || clean_path == "/etc/shadow")
            {
                let p_str = exp_p.to_string_lossy().to_string();
                let name = exp_p.file_name().and_then(|s| s.to_str()).unwrap_or(&p_str);
                let ext = exp_p.extension().and_then(|s| s.to_str()).unwrap_or("");
                return Some(self.build_file_open_intent(&p_str, name, ext));
            }
            let mut filter = parse_file_conditions(target, &self.resources);
            filter.limit = 6;
            let file_hits = self.resources.search_files(&filter);
            return match file_hits.len() {
                0 => {
                    if !has_structured_file_condition(target) {
                        if let Some(app_rec) = self.resources.resolve_best_app(target) {
                            return Some(RoutedIntent::ExecuteL0 {
                                capability_id: "app.launch".into(),
                                arguments: json!({
                                    "app_id": app_rec.app_id,
                                    "app_name": app_rec.name
                                }),
                                summary: format!("启动应用 {}", app_rec.name),
                            });
                        }
                        if t.starts_with("打开应用")
                            || t.starts_with("打开软件")
                            || t.starts_with("启动")
                            || target.contains("软件")
                            || target.contains("应用")
                            || target.to_ascii_lowercase().ends_with(".desktop")
                        {
                            return Some(RoutedIntent::ExecuteL0 {
                                capability_id: "app.launch".into(),
                                arguments: json!({
                                    "app_id": target,
                                    "app_name": target
                                }),
                                summary: format!("启动应用 {}", target),
                            });
                        }
                    }
                    None
                }
                1 => {
                    let f = &file_hits[0].0;
                    Some(self.build_file_open_intent(&f.path, &f.name, &f.ext))
                }
                _ => {
                    if filter.sort_by == FileSortOrder::RecentFirst
                        || filter.sort_by == FileSortOrder::LargestFirst
                        || (file_hits[0].1 - file_hits[1].1 >= 12.0)
                    {
                        let f = &file_hits[0].0;
                        Some(self.build_file_open_intent(&f.path, &f.name, &f.ext))
                    } else {
                        let cands = file_hits
                            .into_iter()
                            .map(|(f, sc)| CandidateItem {
                                id: format!("file:{}", f.path),
                                kind: CandidateKind::File,
                                title: f.name.clone(),
                                subtitle: format!(
                                    "{} · {}",
                                    f.parent_dir,
                                    human_bytes(f.size_bytes)
                                ),
                                badge: "文件".into(),
                                score: sc,
                                capability_id: Some("file.open".into()),
                                arguments: json!({ "path": f.path }),
                                resource_uri: Some(format!("file://{}", f.path)),
                            })
                            .collect();
                        Some(RoutedIntent::Disambiguate {
                            prompt: format!("找到多个匹配“{}”的文件，请选择要打开的一项：", target),
                            candidates: cands,
                        })
                    }
                }
            };
        }

        None
    }
}

/// Deterministic file condition parser (§4.5): time, type/ext, size, folder, sort, and remaining filename token!
pub fn parse_file_conditions(expr: &str, resources: &ResourceEngine) -> FileSearchFilter {
    let mut filter = FileSearchFilter {
        limit: 20,
        ..Default::default()
    };
    let mut work = expr.to_string();

    for (kw, order) in [
        ("最近的", FileSortOrder::RecentFirst),
        ("最新的", FileSortOrder::RecentFirst),
        ("刚改的", FileSortOrder::RecentFirst),
        ("最大的", FileSortOrder::LargestFirst),
    ] {
        if work.contains(kw) {
            filter.sort_by = order;
            work = work.replace(kw, " ");
        }
    }

    let now_local = Local::now();
    let today_midnight = Local
        .with_ymd_and_hms(
            now_local.year(),
            now_local.month(),
            now_local.day(),
            0,
            0,
            0,
        )
        .single()
        .unwrap_or(now_local)
        .with_timezone(&Utc)
        .timestamp();

    if work.contains("今天") {
        filter.modified_after_secs = Some(today_midnight);
        work = work.replace("今天", " ");
    } else if work.contains("昨天") {
        filter.modified_after_secs = Some(today_midnight - 86_400);
        filter.modified_before_secs = Some(today_midnight + 86_400);
        work = work.replace("昨天", " ");
    } else if work.contains("前天") {
        filter.modified_after_secs = Some(today_midnight - 2 * 86_400);
        filter.modified_before_secs = Some(today_midnight - 86_400);
        work = work.replace("前天", " ");
    } else if work.contains("上周") || work.contains("最近一周") {
        filter.modified_after_secs = Some((Utc::now() - Duration::days(14)).timestamp());
        work = work.replace("上周", " ").replace("最近一周", " ");
    } else {
        let recent_days_re = Regex::new(r"最近\s*(\d+)\s*天").unwrap();
        if let Some(caps) = recent_days_re.captures(&work)
            && let Ok(days) = caps[1].parse::<i64>()
        {
            filter.modified_after_secs = Some((Utc::now() - Duration::days(days)).timestamp());
            work = recent_days_re.replace(&work, " ").to_string();
        }
    }
    for verb_noise in ["改过的", "修改过的", "下载的", "新建的"] {
        work = work.replace(verb_noise, " ");
    }

    let size_gt_re =
        Regex::new(r"(?i)(?:大于|超过|高于|>)\s*(\d+(?:\.\d+)?)\s*([kmgt])b?").unwrap();
    if let Some(caps) = size_gt_re.captures(&work)
        && let Some(bytes) = parse_size_unit(&caps[1], &caps[2])
    {
        filter.min_size_bytes = Some(bytes);
        work = size_gt_re.replace(&work, " ").to_string();
    }
    let size_lt_re =
        Regex::new(r"(?i)(?:小于|低于|不超过|<)\s*(\d+(?:\.\d+)?)\s*([kmgt])b?").unwrap();
    if let Some(caps) = size_lt_re.captures(&work)
        && let Some(bytes) = parse_size_unit(&caps[1], &caps[2])
    {
        filter.max_size_bytes = Some(bytes);
        work = size_lt_re.replace(&work, " ").to_string();
    }

    for (loc_pat, hint) in [
        ("下载目录里", "下载"),
        ("下载文件夹里", "下载"),
        ("下载里", "下载"),
        ("在下载", "下载"),
        ("文档目录里", "文档"),
        ("文档里", "文档"),
        ("桌面上", "桌面"),
        ("桌面里", "桌面"),
    ] {
        if work.contains(loc_pat) {
            if let Some(dir) = resources.resolve_named_directory(hint) {
                filter.directory_prefix = Some(dir.to_string_lossy().to_string());
            }
            work = work.replace(loc_pat, " ");
        }
    }

    let glob_re = Regex::new(r"\*\.([a-zA-Z0-9]+)").unwrap();
    if let Some(caps) = glob_re.captures(&work) {
        filter.extensions.push(caps[1].to_ascii_lowercase());
        work = glob_re.replace(&work, " ").to_string();
    }

    let type_tokens: &[(&[&str], Option<&str>, &[&str])] = &[
        (&["pdf", "PDF"], Some("pdf"), &["pdf"]),
        (&["word", "Word", "docx"], Some("word"), &["docx", "doc"]),
        (
            &["表格", "excel", "xlsx"],
            Some("spreadsheet"),
            &["xlsx", "xls", "csv"],
        ),
        (
            &["图片", "照片"],
            Some("image"),
            &["png", "jpg", "jpeg", "webp", "svg"],
        ),
        (&["视频"], Some("video"), &["mp4", "mkv", "mov", "webm"]),
        (&["压缩包"], Some("archive"), &["zip", "tar", "gz", "7z"]),
        (&["markdown", "md"], None, &["md"]),
    ];

    for (words, cat_opt, exts) in type_tokens {
        for &w in *words {
            let attached_filename = work.contains(&format!(".{}", w.to_ascii_lowercase()));
            if !attached_filename && contains_standalone_token(&work, w) {
                if let Some(cat) = cat_opt {
                    filter.category = Some((*cat).to_string());
                }
                for &e in *exts {
                    if !filter.extensions.iter().any(|x| x == e) {
                        filter.extensions.push(e.to_string());
                    }
                }
                work = remove_token_once(&work, w);
                break;
            }
        }
    }

    for filler in ["的", "文件", "文档", "那个", "一下"] {
        if work.trim() == filler {
            work.clear();
        }
    }
    let cleaned = work
        .trim()
        .trim_matches(|c: char| c.is_whitespace() || c == '的')
        .trim_end_matches("文件")
        .trim();

    if !cleaned.is_empty() && cleaned != "文件" {
        filter.query = Some(cleaned.to_string());
    }
    filter
}

fn contains_standalone_token(haystack: &str, token: &str) -> bool {
    if token.is_ascii() {
        let pattern = format!(
            r"(?i)(?:^|[^a-zA-Z0-9_\.])({})(?:$|[^a-zA-Z0-9_\.])",
            regex::escape(token)
        );
        Regex::new(&pattern)
            .map(|re| re.is_match(haystack))
            .unwrap_or(false)
    } else {
        haystack.contains(token)
    }
}

fn remove_token_once(haystack: &str, token: &str) -> String {
    if token.is_ascii() {
        let pattern = format!(
            r"(?i)(^|[^a-zA-Z0-9_\.]){}(?:$|([^a-zA-Z0-9_\.]))",
            regex::escape(token)
        );
        if let Ok(re) = Regex::new(&pattern) {
            return re.replace(haystack, "$1 $2").to_string();
        }
    }
    haystack.replacen(token, " ", 1)
}

fn parse_size_unit(num_s: &str, unit_s: &str) -> Option<u64> {
    let n: f64 = num_s.parse().ok()?;
    let mult: f64 = match unit_s.to_ascii_uppercase().as_str() {
        "K" => 1024.0,
        "M" => 1024.0 * 1024.0,
        "G" => 1024.0 * 1024.0 * 1024.0,
        "T" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((n * mult) as u64)
}

fn has_structured_file_condition(s: &str) -> bool {
    let indicators = [
        "下载里",
        "文档里",
        "桌面上",
        "大于",
        "小于",
        "超过",
        "昨天",
        "今天",
        "上周",
        "改过的",
        "最近的",
        "最大的",
        "*.",
    ];
    indicators.iter().any(|k| s.contains(k))
}

fn is_open_verb(s: &str) -> bool {
    strip_open_verb(s).is_some()
}

fn strip_open_verb(s: &str) -> Option<&str> {
    for p in [
        "打开应用",
        "打开软件",
        "启动应用",
        "启动软件",
        "运行应用",
        "运行软件",
    ] {
        if let Some(rest) = s.strip_prefix(p) {
            let trimmed = rest.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with("中心")
                && !trimmed.starts_with("商店")
                && !trimmed.starts_with("市场")
                && !trimmed.starts_with("管理器")
                && !trimmed.starts_with("更新")
            {
                return Some(trimmed);
            }
        }
    }
    let prefixes = [
        "打开文件 ",
        "打开网站 ",
        "打开",
        "启动",
        "运行",
        "访问",
        "open ",
        "o ",
        "去 ",
        "去",
        "开 ",
        "开",
    ];
    for p in prefixes {
        if let Some(rest) = s.strip_prefix(p) {
            let trimmed = rest.trim();
            if (p == "开" || p == "开 ")
                && (trimmed.starts_with('始')
                    || trimmed.starts_with('会')
                    || trimmed.starts_with("组会"))
            {
                continue;
            }
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

fn extract_first_number(s: &str) -> Option<f64> {
    let re = Regex::new(r"-?\d+(?:\.\d+)?").unwrap();
    re.find(s)?.as_str().parse().ok()
}

fn looks_multi_step_complex(s: &str) -> bool {
    let step_markers = [
        "然后",
        "接着",
        "并且把",
        "再提醒我",
        "转成 PDF",
        "整理下载目录",
        "按类型整理",
    ];
    step_markers.iter().any(|m| s.contains(m))
}

fn classify_candidate_kind(cap_id: &str) -> CandidateKind {
    if cap_id.starts_with("app.") || cap_id.starts_with("window.") {
        CandidateKind::App
    } else if cap_id.starts_with("file.") || cap_id.starts_with("archive.") {
        CandidateKind::File
    } else if cap_id == "web.search" || cap_id == "web.search_site" {
        CandidateKind::WebSearch
    } else if cap_id.starts_with("web.") {
        CandidateKind::Web
    } else if cap_id.starts_with("settings.")
        || cap_id.starts_with("sound.")
        || cap_id.starts_with("display.")
        || cap_id.starts_with("appearance.")
        || cap_id.starts_with("notify.")
        || cap_id.starts_with("network.wifi")
        || cap_id.starts_with("network.airplane")
        || cap_id.starts_with("bluetooth.")
        || cap_id.starts_with("power.")
        || cap_id.starts_with("screen.")
        || cap_id.starts_with("input.")
        || cap_id.starts_with("scene.")
        || cap_id.starts_with("media.")
        || cap_id.starts_with("screenshot.")
    {
        CandidateKind::Setting
    } else {
        CandidateKind::Capability
    }
}

fn human_bytes(b: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let bf = b as f64;
    if bf >= GB {
        format!("{:.1} GB", bf / GB)
    } else if bf >= MB {
        format!("{:.1} MB", bf / MB)
    } else if bf >= KB {
        format!("{:.1} KB", bf / KB)
    } else {
        format!("{} B", b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::db::IndexDb;
    use crate::resource::{builtin_app_aliases, parse_desktop_entry};
    use intentos_fsops::SafeFsEngine;
    use rusqlite::params;
    use std::fs;

    #[test]
    fn domestic_desktop_apps_and_missing_app_route_deterministically() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entries = [
            (
                "sodam.desktop",
                "[Desktop Entry]\nType=Application\nName=SodaM\nExec=/usr/bin/sodam\nKeywords=music;qishui;soda;sodam;\n",
            ),
            (
                "bytedance-feishu.desktop",
                "[Desktop Entry]\nType=Application\nName=Feishu\nName[zh_CN]=飞书\nExec=/opt/bytedance/feishu/bytedance-feishu %U\n",
            ),
            (
                "com.github.paperhead.BetterNotes.desktop",
                "[Desktop Entry]\nType=Application\nName=BetterNotes\nExec=betternotes %U\nStartupWMClass=betternotes\n",
            ),
        ];
        let aliases = builtin_app_aliases();
        let idx = Arc::new(IndexDb::open_or_rebuild(&tmp.path().join("idx.db")).unwrap());
        {
            let conn = idx.conn.lock().unwrap();
            for (fname, content) in entries {
                let p = tmp.path().join(fname);
                fs::write(&p, content).unwrap();
                let rec = parse_desktop_entry(&p, &aliases).unwrap();
                conn.execute(
                    "INSERT INTO apps (app_id, name, generic_name, exec_cmd, keywords, pinyin_full, pinyin_init, aliases, source)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        rec.app_id,
                        rec.name,
                        rec.generic_name,
                        rec.exec_cmd,
                        rec.keywords,
                        rec.pinyin_full,
                        rec.pinyin_init,
                        rec.aliases,
                        rec.source,
                    ],
                )
                .unwrap();
            }
        }
        let fs_eng = Arc::new(
            SafeFsEngine::new(
                vec![tmp.path().to_path_buf()],
                vec![],
                tmp.path().join("undo"),
                tmp.path().join("trash"),
            )
            .unwrap(),
        );
        let res = Arc::new(ResourceEngine::new(idx, fs_eng, AppConfig::default()));
        let router = IntentRouter::new(res);

        for (query, expected_app_id) in [
            ("打开汽水音乐", "sodam.desktop"),
            ("打开 SodaM", "sodam.desktop"),
            ("启动飞书", "bytedance-feishu.desktop"),
            ("打开轻笺", "com.github.paperhead.BetterNotes.desktop"),
            ("打开不存在的宇宙飞船软件XYZ", "不存在的宇宙飞船软件XYZ"),
        ] {
            match router.route_text(query, false) {
                RoutedIntent::ExecuteL0 {
                    capability_id,
                    arguments,
                    ..
                } => {
                    assert_eq!(capability_id, "app.launch", "query={query}");
                    assert_eq!(arguments["app_id"], expected_app_id, "query={query}");
                }
                other => panic!("expected ExecuteL0 app.launch for {query}, got {other:?}"),
            }
        }
    }

    #[test]
    fn eval_blind_spots_and_cognitive_goals_route_accurately() {
        let tmp = tempfile::TempDir::new().unwrap();
        let idx = Arc::new(IndexDb::open_or_rebuild(&tmp.path().join("idx.db")).unwrap());
        let fs_eng = Arc::new(
            SafeFsEngine::new(
                vec![tmp.path().to_path_buf()],
                vec![],
                tmp.path().join("undo"),
                tmp.path().join("trash"),
            )
            .unwrap(),
        );
        let res = Arc::new(ResourceEngine::new(idx, fs_eng, AppConfig::default()));
        let router = IntentRouter::new(res);

        // 1. Local LAN / intranet IP queries must route to `network.ip` L0, NEVER `web.search`
        for ip_query in ["查一下内网地址", "内网地址", "局域网地址", "查看内网IP"]
        {
            match router.route_text(ip_query, false) {
                RoutedIntent::ExecuteL0 { capability_id, .. } => {
                    assert_eq!(capability_id, "network.ip", "ip_query={ip_query}");
                }
                other => panic!("expected ExecuteL0 network.ip for {ip_query}, got {other:?}"),
            }
        }
        // While genuine web search with `查一下` still routes to `web.search`
        match router.route_text("查一下 Bubblewrap 沙箱参数", false) {
            RoutedIntent::ExecuteL0 { capability_id, .. } => {
                assert_eq!(capability_id, "web.search");
            }
            other => panic!("expected ExecuteL0 web.search, got {other:?}"),
        }

        // 2. Power-saver colloquial queries route cleanly to `power.profile.set` (`power-saver`)
        for pwr_query in ["开启省电续航", "省电续航"] {
            match router.route_text(pwr_query, false) {
                RoutedIntent::ExecuteL0 {
                    capability_id,
                    arguments,
                    ..
                } => {
                    assert_eq!(capability_id, "power.profile.set", "pwr_query={pwr_query}");
                    assert_eq!(arguments["profile"], "power-saver", "pwr_query={pwr_query}");
                }
                other => {
                    panic!("expected ExecuteL0 power.profile.set for {pwr_query}, got {other:?}")
                }
            }
        }

        // 3. Procedural how-to & goal-level utterances escalate to L2 with structured goal reason
        for l2_utterance in [
            "怎么批量查找最近7天修改过的日志",
            "怎么批量重命名图片",
            "如何批量压缩旧日志",
            "今天想专心写论文",
            "开始写论文",
            "进入论文写作状态",
            "我准备开组会了",
            "电脑最近有点卡",
            "系统好慢帮我查查",
            "我的软件怎么又启动不了了",
            "下载目录太乱了",
            "帮我整理下载文件夹",
            "帮我看下今天的天气，告诉我早上起床穿什么衣服，然后告诉我今天最应该完成哪些任务",
        ] {
            match router.route_text(l2_utterance, false) {
                RoutedIntent::EscalateL2 { reason } => {
                    assert!(
                        reason.contains("目标："),
                        "expected structured goal summary in reason for {l2_utterance}, got: {reason}"
                    );
                }
                other => panic!("expected EscalateL2 for {l2_utterance}, got {other:?}"),
            }
        }
    }
}
