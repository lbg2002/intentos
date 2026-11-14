#![forbid(unsafe_code)]

//! Declarative Software Adapter Registry (`registry.rs`):
//! - Defines `AdaptationChannel`, `SemanticAppAction`, and `AppAdapterProfile`
//! - Ships 24 rich built-in Linux desktop software adapter profiles
//! - Loads user-extensible `.json` and `.toml` adapter manifests from `${config_dir}/adapters/`

use crate::app_adapter::dynamic_profiler::{
    custom_software_to_adapter_profile, desktop_software_to_adapter_profile,
    discover_installed_desktop_apps, load_custom_apps_store, normalize_app_search_tokens,
};
use crate::resource::to_pinyin_pair;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Progressive adaptation channels for translating high-level intents into desktop software control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptationChannel {
    /// Session D-Bus `org.mpris.MediaPlayer2.Player` media playback & metadata control.
    DbusMpris,
    /// Session D-Bus `StatusNotifierItem` + `com.canonical.dbusmenu` system tray inspection & menu action.
    #[serde(alias = "tray", alias = "dbusmenu")]
    SniDbusMenu,
    /// Session D-Bus `org.freedesktop.FileManager1` / `org.freedesktop.Application` activation.
    DbusFreedesktop,
    /// Custom URI scheme deep-link (`vscode://`, `obsidian://`, `tg://`, `mailto:`, etc.).
    UriScheme,
    /// Freedesktop `.desktop` `[Desktop Action ...]` entry dispatch (e.g. `new-private-window`).
    DesktopAction,
    /// Silent background non-interactive transformation (`libreoffice --headless`, `pdftotext`, `ffmpeg`).
    #[serde(alias = "headless")]
    HeadlessCli,
    /// Window enumeration / focus & AT-SPI2 accessibility tree inspection / approval-gated UI action.
    GuiAtspi,
    /// Safe discrete non-shell CLI flag wrapper for hybrid GUI/CLI apps (`code --diff`, `gnome-control-center`).
    #[serde(alias = "cli")]
    CliWrapper,
    /// Verified process lifecycle management (launch, focus window, multi-stage verified graceful close).
    #[serde(alias = "process", alias = "quit")]
    ProcessLifecycle,
}

impl AdaptationChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DbusMpris => "dbus_mpris",
            Self::SniDbusMenu => "sni_dbusmenu",
            Self::DbusFreedesktop => "dbus_freedesktop",
            Self::UriScheme => "uri_scheme",
            Self::DesktopAction => "desktop_action",
            Self::HeadlessCli => "headless_cli",
            Self::GuiAtspi => "gui_atspi",
            Self::CliWrapper => "cli_wrapper",
            Self::ProcessLifecycle => "process_lifecycle",
        }
    }

    pub fn display_label(self) -> &'static str {
        match self {
            Self::DbusMpris => "MPRIS2 D-Bus 媒体总线",
            Self::SniDbusMenu => "SNI / DBusMenu 系统托盘接口",
            Self::DbusFreedesktop => "Freedesktop D-Bus 会话接口",
            Self::UriScheme => "URI Deep-Link 协议唤起",
            Self::DesktopAction => ".desktop 桌面快捷动作",
            Self::HeadlessCli => "Headless 后台静默转换",
            Self::GuiAtspi => "AT-SPI2 无障碍与窗口桥接",
            Self::CliWrapper => "受控非 Shell 参数封装",
            Self::ProcessLifecycle => "进程生命周期与验证关闭",
        }
    }
}

/// Declarative semantic action exposed by an `AppAdapterProfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticAppAction {
    pub action: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub channel: AdaptationChannel,
    pub summary: String,
    #[serde(default)]
    pub target_template: Option<String>,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default)]
    pub reversible: bool,
}

impl SemanticAppAction {
    pub fn quit_app(app_name: &str) -> Self {
        Self {
            action: "quit".into(),
            aliases: vec![
                "close".into(),
                "exit".into(),
                "关闭".into(),
                "退出".into(),
                "关掉".into(),
                "关闭软件".into(),
                "退出软件".into(),
            ],
            channel: AdaptationChannel::ProcessLifecycle,
            summary: format!("多阶段安全关闭「{}」并回读 /proc 验证进程退出", app_name),
            target_template: None,
            requires_approval: false,
            reversible: false,
        }
    }
}

/// Complete profile describing how IntentOS translates commands for a desktop application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAdapterProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub desktop_ids: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default = "default_adapter_category")]
    pub category: String,
    pub channels: Vec<AdaptationChannel>,
    #[serde(default)]
    pub mpris_bus_hints: Vec<String>,
    #[serde(default)]
    pub dbus_name: Option<String>,
    #[serde(default)]
    pub uri_schemes: Vec<String>,
    #[serde(default)]
    pub cli_executables: Vec<String>,
    #[serde(default)]
    pub supported_actions: Vec<SemanticAppAction>,
    #[serde(default = "default_adapter_source")]
    pub source: String,
    #[serde(default)]
    pub notes: String,
}

fn default_adapter_category() -> String {
    "desktop_app".to_string()
}

fn default_adapter_source() -> String {
    "builtin".to_string()
}

#[derive(Debug, Deserialize)]
struct CustomAdapterManifestList {
    adapters: Vec<AppAdapterProfile>,
}

/// Registry holding built-in + user-configured software command adapters.
#[derive(Debug, Clone)]
pub struct AdapterRegistry {
    profiles: Vec<AppAdapterProfile>,
}

impl AdapterRegistry {
    /// Load only the built-in curated adapter profiles (hermetic, without scanning host `.desktop` dirs).
    pub fn builtin_only() -> Self {
        let mut profiles = builtin_adapter_profiles();
        for profile in &mut profiles {
            if !profile.channels.contains(&AdaptationChannel::ProcessLifecycle) {
                profile.channels.push(AdaptationChannel::ProcessLifecycle);
            }
            if !profile.supported_actions.iter().any(|a| a.action == "quit") {
                profile
                    .supported_actions
                    .push(SemanticAppAction::quit_app(&profile.name));
            }
        }
        Self { profiles }
    }

    /// Load all built-in profiles + dynamically discovered `.desktop` software +
    /// custom `.json`/`.toml` manifests + `${config_dir}/adapters/custom_apps.json`.
    pub fn load(config_dir: Option<&Path>) -> Self {
        let mut by_id: BTreeMap<String, AppAdapterProfile> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();

        for mut profile in builtin_adapter_profiles() {
            if !profile.channels.contains(&AdaptationChannel::ProcessLifecycle) {
                profile.channels.push(AdaptationChannel::ProcessLifecycle);
            }
            if !profile.supported_actions.iter().any(|a| a.action == "quit") {
                profile
                    .supported_actions
                    .push(SemanticAppAction::quit_app(&profile.name));
            }
            order.push(profile.id.clone());
            by_id.insert(profile.id.clone(), profile);
        }

        // Merge dynamically profiled `.desktop` software (`sodam.desktop`, `QQ`, `BetterNotes`, etc.)
        for sw in discover_installed_desktop_apps(config_dir) {
            let matched_existing_id = by_id
                .values()
                .find(|existing| {
                    existing.id.eq_ignore_ascii_case(&sw.id)
                        || existing
                            .desktop_ids
                            .iter()
                            .any(|d| d.eq_ignore_ascii_case(&sw.desktop_id))
                        || sw.binary_name.as_ref().is_some_and(|bin| {
                            existing
                                .cli_executables
                                .iter()
                                .any(|exe| exe.eq_ignore_ascii_case(bin))
                        })
                })
                .map(|p| p.id.clone());

            if let Some(existing_id) = matched_existing_id {
                if let Some(existing) = by_id.get_mut(&existing_id) {
                    if !existing
                        .desktop_ids
                        .iter()
                        .any(|d| d.eq_ignore_ascii_case(&sw.desktop_id))
                    {
                        existing.desktop_ids.push(sw.desktop_id.clone());
                    }
                    for kw in &sw.keywords {
                        if !existing.aliases.iter().any(|a| a.eq_ignore_ascii_case(kw)) {
                            existing.aliases.push(kw.clone());
                        }
                    }
                    if let Some(ref bin) = sw.binary_name
                        && !existing
                            .cli_executables
                            .iter()
                            .any(|e| e.eq_ignore_ascii_case(bin))
                    {
                        existing.cli_executables.push(bin.clone());
                    }
                    for sch in &sw.uri_schemes {
                        if !existing
                            .uri_schemes
                            .iter()
                            .any(|s| s.eq_ignore_ascii_case(sch))
                        {
                            existing.uri_schemes.push(sch.clone());
                        }
                    }
                }
            } else {
                let dyn_prof = desktop_software_to_adapter_profile(&sw);
                if !by_id.contains_key(&dyn_prof.id) {
                    order.push(dyn_prof.id.clone());
                    by_id.insert(dyn_prof.id.clone(), dyn_prof);
                }
            }
        }

        if let Some(cfg_root) = config_dir {
            let adapters_dir = cfg_root.join("adapters");
            if adapters_dir.is_dir()
                && let Ok(entries) = fs::read_dir(&adapters_dir)
            {
                let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
                paths.sort();
                for path in paths {
                    if !path.is_file() {
                        continue;
                    }
                    let ext = path
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if ext != "json" && ext != "toml" {
                        continue;
                    }
                    let fname = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("custom")
                        .to_string();
                    if fname == "custom_apps.json" {
                        continue;
                    }
                    match load_custom_manifest_file(&path, &ext, &fname) {
                        Ok(loaded) => {
                            for mut item in loaded {
                                item.source = format!("user_custom:{}", fname);
                                if !item.channels.contains(&AdaptationChannel::ProcessLifecycle) {
                                    item.channels.push(AdaptationChannel::ProcessLifecycle);
                                }
                                if !item.supported_actions.iter().any(|a| a.action == "quit") {
                                    item.supported_actions
                                        .push(SemanticAppAction::quit_app(&item.name));
                                }
                                if !by_id.contains_key(&item.id) {
                                    order.push(item.id.clone());
                                }
                                by_id.insert(item.id.clone(), item);
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %err,
                                "Skipping invalid custom app adapter manifest"
                            );
                        }
                    }
                }
            }

            // Merge `${config_dir}/adapters/custom_apps.json` personalized software translations
            let custom_store = load_custom_apps_store(cfg_root);
            for custom in &custom_store.custom_apps {
                let item = custom_software_to_adapter_profile(custom);
                if !by_id.contains_key(&item.id) {
                    order.push(item.id.clone());
                }
                by_id.insert(item.id.clone(), item);
            }
        }

        let profiles = order
            .into_iter()
            .filter_map(|id| by_id.remove(&id))
            .collect();
        Self { profiles }
    }

    pub fn profiles(&self) -> &[AppAdapterProfile] {
        &self.profiles
    }

    pub fn all_profiles(&self) -> Vec<&AppAdapterProfile> {
        self.profiles.iter().collect()
    }

    /// Resolve a specific curated/custom `AppAdapterProfile` from `app_hint` without synthesizing a generic fallback.
    pub fn resolve_app(&self, app_hint: &str) -> Option<AppAdapterProfile> {
        let hint_lc = app_hint.trim().to_ascii_lowercase();
        if matches!(
            hint_lc.as_str(),
            "" | "*" | "auto" | "music" | "media" | "player" | "音乐" | "播放器"
        ) {
            return None;
        }
        let mut best: Option<(&AppAdapterProfile, f64)> = None;
        for prof in &self.profiles {
            if prof.id == "generic-gui-window" {
                continue;
            }
            let sc = score_profile_against_hint(prof, &hint_lc);
            if sc >= 70.0 {
                match best {
                    None => best = Some((prof, sc)),
                    Some((_, prev)) if sc > prev => best = Some((prof, sc)),
                    _ => {}
                }
            }
        }
        best.map(|(p, _)| p.clone())
    }

    pub fn builtin_count(&self) -> usize {
        self.profiles
            .iter()
            .filter(|p| p.source == "builtin")
            .count()
    }

    pub fn get_by_id(&self, id: &str) -> Option<&AppAdapterProfile> {
        self.profiles
            .iter()
            .find(|p| p.id.eq_ignore_ascii_case(id.trim()))
    }

    /// Filter adapters by free-text query, category (supporting both 9-category IDs and legacy short names), or adaptation channel.
    pub fn list_filtered(
        &self,
        query: Option<&str>,
        category: Option<&str>,
        channel: Option<&str>,
    ) -> Vec<AppAdapterProfile> {
        let q_norm = query
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let cat_norm = category
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let ch_norm = channel
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);

        let mut results: Vec<(AppAdapterProfile, f64)> = Vec::new();
        for profile in &self.profiles {
            if let Some(ref cat) = cat_norm
                && !profile.category.eq_ignore_ascii_case(cat)
                && !crate::app_adapter::local_scanner::categories_match(&profile.category, cat)
            {
                continue;
            }
            if let Some(ref ch) = ch_norm {
                let has_ch = profile.channels.iter().any(|c| {
                    c.as_str().eq_ignore_ascii_case(ch)
                        || (ch == "headless" && *c == AdaptationChannel::HeadlessCli)
                        || (ch == "cli" && *c == AdaptationChannel::CliWrapper)
                        || ((ch == "tray" || ch == "dbusmenu" || ch == "sni")
                            && *c == AdaptationChannel::SniDbusMenu)
                        || ((ch == "process" || ch == "quit")
                            && *c == AdaptationChannel::ProcessLifecycle)
                });
                if !has_ch {
                    continue;
                }
            }
            if let Some(ref q) = q_norm {
                let sc = score_profile_against_query(profile, q);
                if sc > 0.0 {
                    results.push((profile.clone(), sc));
                }
            } else {
                results.push((profile.clone(), 1.0));
            }
        }

        if q_norm.is_some() {
            results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        }
        results.into_iter().map(|(p, _)| p).collect()
    }

    /// Resolve `(AppAdapterProfile, SemanticAppAction)` from a user/LLM `app_hint` and `intent_action`.
    /// Falls back gracefully to category/action-matched profiles or a dynamic `GuiAtspi` profile for unknown GUI apps.
    pub fn resolve_adapter_and_action(
        &self,
        app_hint: &str,
        raw_action: &str,
    ) -> (AppAdapterProfile, SemanticAppAction) {
        let canonical_action = normalize_intent_action(raw_action);
        let hint = app_hint.trim();
        let hint_lc = hint.to_ascii_lowercase();

        // 1. Score all registered profiles against `app_hint` + `canonical_action`
        //    (Generic category words like `"music"` / `"音乐"` / `"播放器"` skip direct keyword scoring
        //     so `.desktop` `Keywords=music;player;` never hijacks generic category fallback!)
        let is_generic_category_word = matches!(
            hint_lc.as_str(),
            "" | "*" | "auto" | "music" | "media" | "player" | "音乐" | "播放器"
        );
        let mut best: Option<(&AppAdapterProfile, f64)> = None;
        if !is_generic_category_word {
            for prof in &self.profiles {
                if prof.id == "generic-gui-window" {
                    continue;
                }
                let mut sc = score_profile_against_hint(prof, &hint_lc);
                if sc > 0.0 && find_action_in_profile(prof, &canonical_action, raw_action).is_some()
                {
                    // Small tie-breaker (+3.0) so exact app matches (>=94.0) ALWAYS beat fuzzy/stripped wrong-app matches (<=88.0)
                    sc += 3.0;
                }
                if sc > 0.0 {
                    match best {
                        None => best = Some((prof, sc)),
                        Some((_, prev)) if sc > prev => best = Some((prof, sc)),
                        _ => {}
                    }
                }
            }
        }

        // 2. Generic category hints (e.g. "music" / "播放器", "file_manager" / "文件管理器", "browser", "office")
        if best.is_none() {
            let cat_guess = guess_category_from_hint_or_action(&hint_lc, &canonical_action);
            if let Some(cat) = cat_guess {
                for prof in &self.profiles {
                    if (prof.category == cat
                        || crate::app_adapter::local_scanner::categories_match(&prof.category, cat))
                        && find_action_in_profile(prof, &canonical_action, raw_action).is_some()
                    {
                        best = Some((prof, 60.0));
                        break;
                    }
                }
            }
        }

        // 3. If a profile matched, find the best semantic action on it (or synthesize a progressive fallback action)
        if let Some((prof, _)) = best {
            if let Some(act) = find_action_in_profile(prof, &canonical_action, raw_action) {
                return (prof.clone(), act.clone());
            }
            let fallback_act = synthesize_action_for_profile(prof, &canonical_action);
            return (prof.clone(), fallback_act);
        }

        // 4. Unknown pure-GUI software fallback (`GuiAtspi` / `ProcessLifecycle` / `.desktop` progressive bridge)
        let custom_name = if hint.is_empty() {
            "桌面 GUI 窗口".to_string()
        } else {
            hint.to_string()
        };
        let clean_id = sanitize_id_slug(hint);
        let mut fallback_actions = gui_atspi_standard_actions();
        fallback_actions.push(SemanticAppAction::quit_app(&custom_name));
        let fallback_prof = AppAdapterProfile {
            id: clean_id.clone(),
            name: custom_name,
            desktop_ids: vec![format!("{}.desktop", clean_id)],
            aliases: vec![hint.to_string()],
            category: "custom_gui".to_string(),
            channels: vec![
                AdaptationChannel::ProcessLifecycle,
                AdaptationChannel::GuiAtspi,
                AdaptationChannel::DesktopAction,
            ],
            mpris_bus_hints: Vec::new(),
            dbus_name: None,
            uri_schemes: Vec::new(),
            cli_executables: Vec::new(),
            supported_actions: fallback_actions,
            source: "dynamic_gui_fallback".to_string(),
            notes: "未注册专用 CLI/D-Bus 接口的纯 GUI 软件，自动降级至受验证生命周期控制与受审批 AT-SPI2 无障碍桥接".to_string(),
        };
        let act = find_action_in_profile(&fallback_prof, &canonical_action, raw_action)
            .cloned()
            .unwrap_or_else(|| synthesize_action_for_profile(&fallback_prof, &canonical_action));
        (fallback_prof, act)
    }
}

fn load_custom_manifest_file(
    path: &Path,
    ext: &str,
    fname: &str,
) -> anyhow::Result<Vec<AppAdapterProfile>> {
    let raw = fs::read_to_string(path)?;
    if ext == "json" {
        if let Ok(wrapper) = serde_json::from_str::<CustomAdapterManifestList>(&raw) {
            return Ok(wrapper.adapters);
        }
        if let Ok(arr) = serde_json::from_str::<Vec<AppAdapterProfile>>(&raw) {
            return Ok(arr);
        }
        let single: AppAdapterProfile = serde_json::from_str(&raw)?;
        Ok(vec![single])
    } else if ext == "toml" {
        if let Ok(wrapper) = toml::from_str::<CustomAdapterManifestList>(&raw) {
            return Ok(wrapper.adapters);
        }
        let single: AppAdapterProfile = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("failed to parse TOML adapter {}: {}", fname, e))?;
        Ok(vec![single])
    } else {
        anyhow::bail!("unsupported manifest extension: {}", ext)
    }
}

/// Normalize natural-language / colloquial / LLM action names into canonical semantic action IDs.
pub fn normalize_intent_action(raw: &str) -> String {
    let s = raw.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match s.as_str() {
        "quit" | "close" | "exit" | "quit_app" | "close_app" | "graceful_close"
        | "force_close" | "关闭" | "退出" | "关掉" | "优雅关闭" | "强制关闭" | "结束进程"
        | "关闭应用" | "关闭软件" | "退出应用" | "退出软件" => "quit".into(),
        "play" | "resume" | "播放" | "继续播放" | "开始播放" => "play".into(),
        "pause" | "暂停" | "暂停播放" => "pause".into(),
        "play_pause" | "playpause" | "toggle" | "toggle_play" | "播放暂停" | "切换播放" => {
            "play_pause".into()
        }
        "next" | "next_track" | "skip" | "下一首" | "切歌" | "下一曲" => "next".into(),
        "previous" | "prev" | "prev_track" | "上一首" | "上一曲" => "previous".into(),
        "stop" | "停止" | "停止播放" => "stop".into(),
        "get_now_playing" | "now_playing" | "current_track" | "status" | "当前播放"
        | "正在播放" | "什么歌" => "get_now_playing".into(),
        "set_volume" | "volume" | "音量" | "调节音量" | "调音量" => "set_volume".into(),
        "reveal_file" | "show_items" | "select_file" | "highlight_file" | "定位文件"
        | "在文件夹中显示" | "打开所在文件夹" => "reveal_file".into(),
        "open_folder" | "show_folders" | "打开目录" | "打开文件夹" => "open_folder".into(),
        "activate" | "dbus_activate" | "唤起" | "激活应用" => "activate".into(),
        "open_file_at_line" | "goto_line" | "open_file" | "打开代码行" | "跳转到行" => {
            "open_file_at_line".into()
        }
        "open_workspace" | "open_project" | "打开项目" | "打开工作区" => "open_workspace".into(),
        "new_private_window" | "incognito" | "private_window" | "无痕窗口" | "新建无痕窗口"
        | "隐私窗口" => "new_private_window".into(),
        "new_window" | "新建窗口" => "new_window".into(),
        "open_url" | "open_uri" | "deep_link" | "打开链接" => "open_uri".into(),
        "open_note" | "open_vault" | "打开笔记" | "打开知识库" => "open_note".into(),
        "new_note" | "create_note" | "新建笔记" => "new_note".into(),
        "search_notes" | "搜索笔记" => "search_notes".into(),
        "compose_email" | "mailto" | "send_email_draft" | "写邮件" | "发邮件" => {
            "compose_email".into()
        }
        "open_chat" | "open_contact" | "打开会话" | "打开聊天" => "open_chat".into(),
        "convert_to_pdf" | "export_pdf" | "to_pdf" | "转pdf" | "导出pdf" | "转换为pdf" => {
            "convert_to_pdf".into()
        }
        "convert_document" | "文档转换" => "convert_document".into(),
        "convert_image" | "transcode_image" | "图片转换" | "转换图片格式" => "convert_image".into(),
        "extract_text_preview" | "pdf_to_text" | "read_pdf_text" | "提取文本" | "提取pdf文本" => {
            "extract_text_preview".into()
        }
        "transcode_media" | "extract_audio" | "媒体转码" | "提取音频" => "transcode_media".into(),
        "list_windows" | "enumerate_windows" | "列出窗口" => "list_windows".into(),
        "focus_window" | "raise_window" | "activate_window" | "show_window" | "聚焦窗口"
        | "切换窗口" | "显示主窗口" | "打开主窗口" => "focus_window".into(),
        "click_tray_menu" | "tray_menu" | "trigger_tray_menu" | "点击托盘菜单" | "托盘菜单" => {
            "click_tray_menu".into()
        }
        "inspect_ui_tree" | "inspect_controls" | "atspi_inspect" | "查看控件" | "探测界面" => {
            "inspect_ui_tree".into()
        }
        "click_control" | "click" | "invoke_control" | "atspi_click" | "点击按钮" | "点击控件" => {
            "click_control".into()
        }
        "trigger_shortcut" | "send_shortcut" | "keystroke" | "send_keys" | "快捷键"
        | "发送快捷键" => "trigger_shortcut".into(),
        "type_text" | "fill_input" | "输入文本" => "type_text".into(),
        "open_settings_panel" | "打开设置面板" => "open_settings_panel".into(),
        // Wave 5 Rich Domain Translation Actions
        "open_pdf_page" | "jump_pdf_page" | "跳转pdf页码" | "打开pdf页" | "pdf跳页" => {
            "open_pdf_page".into()
        }
        "find_in_pdf" | "search_pdf" | "pdf搜索" | "在pdf中查找" => "find_in_pdf".into(),
        "open_pdf_arranger" | "merge_split_pdf" | "合并拆分pdf" | "整理pdf" => {
            "open_pdf_arranger".into()
        }
        "new_document" | "create_document" | "新建文档" | "新建文字文档" => {
            "new_document".into()
        }
        "new_spreadsheet" | "create_spreadsheet" | "新建表格" | "新建电子表格" => {
            "new_spreadsheet".into()
        }
        "new_presentation" | "create_presentation" | "新建演示" | "新建幻灯片" | "新建ppt" => {
            "new_presentation".into()
        }
        "wake_cloud_tray" | "唤醒云盘托盘" | "打开wps云盘" => "wake_cloud_tray".into(),
        "wake_notes" | "唤醒便签" | "打开轻笺" => "wake_notes".into(),
        "join_meeting" | "enter_meeting" | "加入会议" | "入会" | "进入会议" | "快速入会" => {
            "join_meeting".into()
        }
        "open_feishu_uri" | "feishu_link" | "打开飞书链接" | "打开飞书工作台" => {
            "open_feishu_uri".into()
        }
        "wake_main_window" | "wake_window" | "唤醒主窗口" | "唤醒窗口" => {
            "wake_main_window".into()
        }
        "open_media" | "play_file" | "打开媒体" | "播放本地媒体" => "open_media".into(),
        "send_file" | "lan_send_file" | "发送文件" | "局域网传文件" | "隔空投送" => {
            "send_file".into()
        }
        "wake_receiver" | "唤醒接收端" | "打开接收端" => "wake_receiver".into(),
        "wake_cloud_drive" | "唤醒网盘" | "打开网盘主窗口" => "wake_cloud_drive".into(),
        "open_download_folder" | "打开下载目录" | "打开网盘下载目录" => {
            "open_download_folder".into()
        }
        "wake_dashboard" | "打开代理面板" | "唤醒代理主界面" => "wake_dashboard".into(),
        "probe_proxy_status" | "proxy_status" | "探测代理状态" | "代理状态" | "查询代理" => {
            "probe_proxy_status".into()
        }
        "tailscale_status" | "vpn_status" | "组网状态" | "tailscale状态" => {
            "tailscale_status".into()
        }
        "open_incognito" | "无痕打开" | "无痕打开网址" => "open_incognito".into(),
        "open_new_window" | "新窗口打开网址" => "open_new_window".into(),
        "open_app_mode" | "pwa_mode" | "应用模式打开" | "独立窗口打开网页" => {
            "open_app_mode".into()
        }
        "goto_file_line" | "跳转文件行" | "定位代码行列" => "goto_file_line".into(),
        "diff_two_files" | "对比两个文件" => "diff_two_files".into(),
        "open_diagram" | "打开流程图" | "打开架构图" => "open_diagram".into(),
        "export_diagram" | "导出流程图" | "导出架构图" => "export_diagram".into(),
        "list_vms" | "列出虚拟机" | "虚拟机列表" | "查询虚拟机" => "list_vms".into(),
        "start_vm" | "boot_vm" | "启动虚拟机" | "开机虚拟机" => "start_vm".into(),
        "savestate_vm" | "suspend_vm" | "挂起虚拟机" | "保存虚拟机状态" => {
            "savestate_vm".into()
        }
        "get_device_id" | "rustdesk_id" | "获取设备号" | "本机远控码" | "查看设备id" => {
            "get_device_id".into()
        }
        "connect_peer" | "remote_connect" | "连接远程桌面" | "发起远控" => {
            "connect_peer".into()
        }
        "input_method_status" | "ime_status" | "输入法状态" | "查询输入法" => {
            "input_method_status".into()
        }
        "activate_chinese" | "enable_chinese" | "切换中文输入法" | "开启中文输入" => {
            "activate_chinese".into()
        }
        "deactivate_chinese" | "disable_chinese" | "切换英文输入法" | "关闭中文输入" => {
            "deactivate_chinese".into()
        }
        "open_fcitx_config" | "输入法设置" | "打开输入法配置" => "open_fcitx_config".into(),
        "query_gpu_telemetry" | "gpu_status" | "nvidia_smi" | "显卡状态" | "gpu状态"
        | "查询显存温度" => "query_gpu_telemetry".into(),
        "open_nvidia_settings" | "打开显卡设置" | "nvidia控制面板" => {
            "open_nvidia_settings".into()
        }
        "select_in_folder" | "nautilus_select" | "在文件管理器中选中" => {
            "select_in_folder".into()
        }
        "launch_app" | "launch" | "open_app" | "start_app" | "启动软件" | "打开软件"
        | "打开主程序" => "launch_app".into(),
        other
            if (other.contains("关闭") || other.contains("退出") || other.contains("关掉"))
                && !other.contains("登录")
                && !other.contains("账号")
                && !other.contains("中文") =>
        {
            "quit".into()
        }
        other => other.to_string(),
    }
}

fn find_action_in_profile<'a>(
    prof: &'a AppAdapterProfile,
    canonical_action: &str,
    raw_action: &str,
) -> Option<&'a SemanticAppAction> {
    let raw_lc = raw_action.trim().to_ascii_lowercase();
    prof.supported_actions.iter().find(|a| {
        a.action.eq_ignore_ascii_case(canonical_action)
            || a.action.eq_ignore_ascii_case(&raw_lc)
            || a.aliases.iter().any(|al| {
                al.eq_ignore_ascii_case(canonical_action) || al.eq_ignore_ascii_case(&raw_lc)
            })
    })
}

fn synthesize_action_for_profile(
    prof: &AppAdapterProfile,
    canonical_action: &str,
) -> SemanticAppAction {
    if canonical_action == "quit" {
        return SemanticAppAction::quit_app(&prof.name);
    }
    let requires_approval = matches!(
        canonical_action,
        "click_control" | "trigger_shortcut" | "type_text" | "start_vm" | "savestate_vm" | "connect_peer"
    );
    let channel = match canonical_action {
        "click_tray_menu" => AdaptationChannel::SniDbusMenu,
        "play" | "pause" | "play_pause" | "next" | "previous" | "stop" | "get_now_playing"
        | "set_volume"
            if prof.channels.contains(&AdaptationChannel::DbusMpris) =>
        {
            AdaptationChannel::DbusMpris
        }
        "play" | "pause" | "play_pause" | "next" | "previous" | "get_now_playing"
            if prof.channels.contains(&AdaptationChannel::SniDbusMenu) =>
        {
            AdaptationChannel::SniDbusMenu
        }
        "reveal_file" | "open_folder" | "activate"
            if prof.channels.contains(&AdaptationChannel::DbusFreedesktop) =>
        {
            AdaptationChannel::DbusFreedesktop
        }
        "convert_to_pdf" | "convert_document" | "convert_image" | "extract_text_preview"
        | "transcode_media" => AdaptationChannel::HeadlessCli,
        "new_window" | "new_private_window" => AdaptationChannel::DesktopAction,
        "open_uri" | "open_file_at_line" | "open_note" | "new_note" | "search_notes"
        | "compose_email" | "open_chat"
            if !prof.uri_schemes.is_empty() =>
        {
            AdaptationChannel::UriScheme
        }
        "list_windows" | "focus_window" | "inspect_ui_tree" | "click_control"
        | "trigger_shortcut" | "type_text" => AdaptationChannel::GuiAtspi,
        _ => prof
            .channels
            .first()
            .copied()
            .unwrap_or(AdaptationChannel::GuiAtspi),
    };

    SemanticAppAction {
        action: canonical_action.to_string(),
        aliases: Vec::new(),
        channel,
        summary: format!("对 {} 执行转译动作 {}", prof.name, canonical_action),
        target_template: None,
        requires_approval,
        reversible: canonical_action.starts_with("convert_"),
    }
}

fn token_fuzzy_contains(haystack_lc: &str, needle_lc: &str) -> bool {
    if needle_lc.is_empty() || haystack_lc.is_empty() {
        return false;
    }
    if !needle_lc.is_ascii() {
        return needle_lc.chars().count() >= 2 && haystack_lc.contains(needle_lc);
    }
    if needle_lc.len() >= 4 && haystack_lc.contains(needle_lc) {
        return true;
    }
    needle_lc.len() >= 2
        && haystack_lc
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|seg| seg == needle_lc)
}

fn score_profile_single_token(prof: &AppAdapterProfile, token_lc: &str) -> f64 {
    if token_lc.is_empty() {
        return 0.0;
    }
    if prof.id.eq_ignore_ascii_case(token_lc) || prof.name.to_ascii_lowercase() == token_lc {
        return 100.0;
    }
    for d_id in &prof.desktop_ids {
        let stem = d_id.trim_end_matches(".desktop").to_ascii_lowercase();
        if d_id.eq_ignore_ascii_case(token_lc) || stem == token_lc {
            return 98.0;
        }
    }
    for exe in &prof.cli_executables {
        let base = Path::new(exe)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(exe);
        if base.eq_ignore_ascii_case(token_lc) {
            return 97.0;
        }
    }
    for alias in &prof.aliases {
        if alias.to_ascii_lowercase() == token_lc {
            return 96.0;
        }
        let (ap_full, ap_init) = to_pinyin_pair(alias);
        if (!ap_full.is_empty() && ap_full == token_lc)
            || (ap_init.len() >= 2 && ap_init == token_lc)
        {
            return 94.0;
        }
    }
    for scheme in &prof.uri_schemes {
        if scheme.eq_ignore_ascii_case(token_lc.trim_end_matches("://").trim_end_matches(':')) {
            return 92.0;
        }
    }
    let (py_full, py_init) = to_pinyin_pair(&prof.name);
    if py_full == token_lc || py_init == token_lc {
        return 90.0;
    }
    let name_lc = prof.name.to_ascii_lowercase();
    if token_fuzzy_contains(&prof.id, token_lc)
        || token_fuzzy_contains(&name_lc, token_lc)
        || prof
            .cli_executables
            .iter()
            .any(|e| token_fuzzy_contains(&e.to_ascii_lowercase(), token_lc))
        || prof.aliases.iter().any(|a| {
            let al = a.to_ascii_lowercase();
            token_fuzzy_contains(&al, token_lc) || token_fuzzy_contains(token_lc, &al)
        })
    {
        return 75.0;
    }
    0.0
}

pub(crate) fn score_profile_against_hint(prof: &AppAdapterProfile, hint_lc: &str) -> f64 {
    let direct = score_profile_single_token(prof, hint_lc);
    if direct >= 90.0 {
        return direct;
    }
    let mut best = direct;
    for tok in normalize_app_search_tokens(hint_lc) {
        if tok == hint_lc {
            continue;
        }
        let sc = score_profile_single_token(prof, &tok);
        // Generic-word-stripped / Pinyin fallback tokens must never outscore an exact unstripped
        // alias/name/id match (`>= 90.0`), e.g. `"qq音乐"` -> `qqmusic` (96.0) vs stripped `"qq"` -> `qq` (<= 88.0).
        let discounted = (sc - 12.0).clamp(0.0, 88.0);
        if discounted > best {
            best = discounted;
        }
    }
    best
}

fn score_profile_against_query(prof: &AppAdapterProfile, q_lc: &str) -> f64 {
    let direct = score_profile_against_hint(prof, q_lc);
    if direct > 0.0 {
        return direct;
    }
    if prof.category.to_ascii_lowercase().contains(q_lc)
        || crate::app_adapter::local_scanner::categories_match(&prof.category, q_lc)
        || prof.notes.to_ascii_lowercase().contains(q_lc)
    {
        return 60.0;
    }
    if prof.channels.iter().any(|c| c.as_str().contains(q_lc)) {
        return 55.0;
    }
    if prof.supported_actions.iter().any(|a| {
        a.action.to_ascii_lowercase().contains(q_lc)
            || a.summary.to_ascii_lowercase().contains(q_lc)
            || a.aliases.iter().any(|al| al.to_ascii_lowercase().contains(q_lc))
    }) {
        return 50.0;
    }
    0.0
}

fn guess_category_from_hint_or_action(hint_lc: &str, canonical_action: &str) -> Option<&'static str> {
    if matches!(
        hint_lc,
        "music" | "player" | "media" | "audio" | "音乐" | "播放器" | "听歌"
    ) || matches!(
        canonical_action,
        "play" | "pause" | "play_pause" | "next" | "previous" | "stop" | "get_now_playing" | "set_volume"
    ) {
        return Some("media");
    }
    if matches!(
        hint_lc,
        "files" | "file_manager" | "folder" | "文件" | "文件管理器" | "文件夹"
    ) || matches!(canonical_action, "reveal_file" | "open_folder")
    {
        return Some("file_manager");
    }
    if matches!(hint_lc, "browser" | "web" | "浏览器")
        || canonical_action == "new_private_window"
    {
        return Some("browser");
    }
    if matches!(hint_lc, "office" | "word" | "doc" | "办公" | "文档")
        || matches!(canonical_action, "convert_to_pdf" | "convert_document")
    {
        return Some("office");
    }
    if matches!(hint_lc, "pdf" | "reader" | "阅读器")
        || canonical_action == "extract_text_preview"
    {
        return Some("document_viewer");
    }
    if matches!(hint_lc, "image" | "photo" | "图片") || canonical_action == "convert_image" {
        return Some("graphics");
    }
    if matches!(hint_lc, "mail" | "email" | "邮箱" | "邮件")
        || canonical_action == "compose_email"
    {
        return Some("communication");
    }
    None
}

fn sanitize_id_slug(raw: &str) -> String {
    let mut slug = String::new();
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if (ch == '-' || ch == '_' || ch == '.' || ch.is_whitespace())
            && !slug.ends_with('-')
            && !slug.is_empty()
        {
            slug.push('-');
        }
    }
    let trimmed = slug.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "generic-gui-window".to_string()
    } else {
        trimmed
    }
}

fn mpris_standard_actions() -> Vec<SemanticAppAction> {
    vec![
        SemanticAppAction {
            action: "play_pause".into(),
            aliases: vec!["播放暂停".into(), "toggle".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "切换音乐播放/暂停状态 (MPRIS2 PlayPause)".into(),
            target_template: Some("org.mpris.MediaPlayer2.Player.PlayPause".into()),
            requires_approval: false,
            reversible: true,
        },
        SemanticAppAction {
            action: "play".into(),
            aliases: vec!["播放".into(), "继续播放".into(), "resume".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "开始或恢复音乐播放 (MPRIS2 Play)".into(),
            target_template: Some("org.mpris.MediaPlayer2.Player.Play".into()),
            requires_approval: false,
            reversible: true,
        },
        SemanticAppAction {
            action: "pause".into(),
            aliases: vec!["暂停".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "暂停当前播放曲目 (MPRIS2 Pause)".into(),
            target_template: Some("org.mpris.MediaPlayer2.Player.Pause".into()),
            requires_approval: false,
            reversible: true,
        },
        SemanticAppAction {
            action: "next".into(),
            aliases: vec!["下一首".into(), "切歌".into(), "skip".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "切换到下一首曲目并回读标题 (MPRIS2 Next)".into(),
            target_template: Some("org.mpris.MediaPlayer2.Player.Next".into()),
            requires_approval: false,
            reversible: true,
        },
        SemanticAppAction {
            action: "previous".into(),
            aliases: vec!["上一首".into(), "prev".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "返回上一首曲目并回读标题 (MPRIS2 Previous)".into(),
            target_template: Some("org.mpris.MediaPlayer2.Player.Previous".into()),
            requires_approval: false,
            reversible: true,
        },
        SemanticAppAction {
            action: "stop".into(),
            aliases: vec!["停止".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "停止播放器输出 (MPRIS2 Stop)".into(),
            target_template: Some("org.mpris.MediaPlayer2.Player.Stop".into()),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "get_now_playing".into(),
            aliases: vec!["当前播放".into(), "正在播放".into(), "now_playing".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "读取当前播放曲目、歌手、专辑与状态 (xesam:title / PlaybackStatus)".into(),
            target_template: Some("org.freedesktop.DBus.Properties.GetAll".into()),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "set_volume".into(),
            aliases: vec!["音量".into(), "volume".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "调节该播放器独立应用音量 (MPRIS2 Volume 0.0~1.0)".into(),
            target_template: Some("org.mpris.MediaPlayer2.Player:Volume".into()),
            requires_approval: false,
            reversible: true,
        },
    ]
}

fn file_manager_standard_actions() -> Vec<SemanticAppAction> {
    vec![
        SemanticAppAction {
            action: "reveal_file".into(),
            aliases: vec!["定位文件".into(), "在文件夹中显示".into(), "show_items".into()],
            channel: AdaptationChannel::DbusFreedesktop,
            summary: "打开 GUI 文件管理器并高亮选中目标文件 (FileManager1.ShowItems)".into(),
            target_template: Some("org.freedesktop.FileManager1.ShowItems".into()),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "open_folder".into(),
            aliases: vec!["打开文件夹".into(), "show_folders".into()],
            channel: AdaptationChannel::DbusFreedesktop,
            summary: "在 GUI 文件管理器窗口打开目标目录 (FileManager1.ShowFolders)".into(),
            target_template: Some("org.freedesktop.FileManager1.ShowFolders".into()),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "new_window".into(),
            aliases: vec!["新建窗口".into()],
            channel: AdaptationChannel::DesktopAction,
            summary: "触发 .desktop [Desktop Action new-window] 打开新文件窗口".into(),
            target_template: Some("new-window".into()),
            requires_approval: false,
            reversible: false,
        },
    ]
}

fn ide_standard_actions(scheme: &str, cli_bin: &str) -> Vec<SemanticAppAction> {
    vec![
        SemanticAppAction {
            action: "open_file_at_line".into(),
            aliases: vec!["跳转到行".into(), "打开代码行".into(), "goto_line".into()],
            channel: AdaptationChannel::UriScheme,
            summary: format!(
                "通过 {}://file/{{path}}:{{line}}:{{col}} 深度链接精确定位源码行列",
                scheme
            ),
            target_template: Some(format!("{}://file/{{path}}:{{line}}:{{col}}", scheme)),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "open_workspace".into(),
            aliases: vec!["打开工作区".into(), "打开项目".into()],
            channel: AdaptationChannel::UriScheme,
            summary: format!("通过 {}://file/{{path}} 打开整个工程工作区", scheme),
            target_template: Some(format!("{}://file/{{path}}", scheme)),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "new_window".into(),
            aliases: vec!["新建窗口".into(), "new-empty-window".into()],
            channel: AdaptationChannel::DesktopAction,
            summary: "触发 .desktop 动作新建空白编辑器窗口".into(),
            target_template: Some("new-empty-window".into()),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "diff_files".into(),
            aliases: vec!["对比文件".into(), "文件差异对比".into()],
            channel: AdaptationChannel::CliWrapper,
            summary: format!("通过受控非 Shell 参数 `{} --diff <left> <right>` 打开可视化对比", cli_bin),
            target_template: Some(format!("{} --diff", cli_bin)),
            requires_approval: false,
            reversible: false,
        },
    ]
}

fn browser_standard_actions() -> Vec<SemanticAppAction> {
    vec![
        SemanticAppAction {
            action: "new_private_window".into(),
            aliases: vec!["新建无痕窗口".into(), "无痕模式".into(), "incognito".into()],
            channel: AdaptationChannel::DesktopAction,
            summary: "调用 .desktop [Desktop Action new-private-window] 打开隐私/无痕浏览窗口".into(),
            target_template: Some("new-private-window".into()),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "new_window".into(),
            aliases: vec!["新建窗口".into()],
            channel: AdaptationChannel::DesktopAction,
            summary: "调用 .desktop [Desktop Action new-window] 打开新浏览器窗口".into(),
            target_template: Some("new-window".into()),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "open_uri".into(),
            aliases: vec!["打开网址".into(), "open_url".into()],
            channel: AdaptationChannel::UriScheme,
            summary: "安全校验协议后打开 HTTP/HTTPS 页面（拦截 javascript:/data:/vbscript:）".into(),
            target_template: Some("{url}".into()),
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "play_pause".into(),
            aliases: vec!["暂停网页视频".into(), "播放网页媒体".into()],
            channel: AdaptationChannel::DbusMpris,
            summary: "通过浏览器内置 MPRIS2 接口控制网页音视频播放/暂停".into(),
            target_template: Some("org.mpris.MediaPlayer2.Player.PlayPause".into()),
            requires_approval: false,
            reversible: true,
        },
    ]
}

pub fn gui_atspi_standard_actions() -> Vec<SemanticAppAction> {
    vec![
        SemanticAppAction {
            action: "focus_window".into(),
            aliases: vec!["聚焦窗口".into(), "前置窗口".into()],
            channel: AdaptationChannel::GuiAtspi,
            summary: "枚举桌面窗口并将目标软件窗口切换至前台焦点".into(),
            target_template: None,
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "inspect_ui_tree".into(),
            aliases: vec!["查看控件".into(), "探测无障碍树".into()],
            channel: AdaptationChannel::GuiAtspi,
            summary: "只读探测 AT-SPI2 无障碍控件树（按钮、菜单、输入框列表）".into(),
            target_template: None,
            requires_approval: false,
            reversible: false,
        },
        SemanticAppAction {
            action: "click_control".into(),
            aliases: vec!["点击按钮".into(), "触发控件".into()],
            channel: AdaptationChannel::GuiAtspi,
            summary: "在目标应用窗口内触发指定 AT-SPI2 无障碍控件动作（需显式审批）".into(),
            target_template: None,
            requires_approval: true,
            reversible: false,
        },
        SemanticAppAction {
            action: "trigger_shortcut".into(),
            aliases: vec!["发送快捷键".into(), "快捷键".into()],
            channel: AdaptationChannel::GuiAtspi,
            summary: "向目标应用窗口注入受限应用内快捷键（需显式审批）".into(),
            target_template: None,
            requires_approval: true,
            reversible: false,
        },
    ]
}

/// Returns the 24 built-in Linux desktop software command adaptation profiles.
pub fn builtin_adapter_profiles() -> Vec<AppAdapterProfile> {
    vec![
        // 1. QQMusic
        AppAdapterProfile {
            id: "qqmusic".into(),
            name: "QQ音乐 (QQMusic)".into(),
            desktop_ids: vec!["qqmusic.desktop".into(), "com.qq.music.desktop".into()],
            aliases: vec!["qq音乐".into(), "qqmusic".into(), "腾讯音乐".into(), "qqyy".into()],
            category: "media".into(),
            channels: vec![
                AdaptationChannel::DbusMpris,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec!["qqmusic".into(), "chromium.instance".into()],
            dbus_name: Some("org.mpris.MediaPlayer2.qqmusic".into()),
            uri_schemes: vec![],
            cli_executables: vec![],
            supported_actions: mpris_standard_actions(),
            source: "builtin".into(),
            notes: "Electron 桌面音乐客户端无命令行控制参数，通过 Session D-Bus MPRIS2 协议转译播放/切歌/曲目读取".into(),
        },
        // 2. NetEase Cloud Music
        AppAdapterProfile {
            id: "netease-cloud-music".into(),
            name: "网易云音乐 (NetEase Cloud Music)".into(),
            desktop_ids: vec![
                "netease-cloud-music.desktop".into(),
                "com.163.music.desktop".into(),
            ],
            aliases: vec![
                "网易云音乐".into(),
                "网易云".into(),
                "netease".into(),
                "cloudmusic".into(),
                "wyy".into(),
            ],
            category: "media".into(),
            channels: vec![
                AdaptationChannel::DbusMpris,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec!["netease-cloud-music".into(), "NetEase".into()],
            dbus_name: Some("org.mpris.MediaPlayer2.netease-cloud-music".into()),
            uri_schemes: vec!["orpheus".into()],
            cli_executables: vec![],
            supported_actions: mpris_standard_actions(),
            source: "builtin".into(),
            notes: "无 CLI 控制参数，通过 MPRIS2 总线控制播放/暂停/上一下一首与读取 xesam 元数据".into(),
        },
        // 3. Spotify
        AppAdapterProfile {
            id: "spotify".into(),
            name: "Spotify".into(),
            desktop_ids: vec!["spotify.desktop".into(), "com.spotify.Client.desktop".into()],
            aliases: vec!["spotify".into(), "声破天".into()],
            category: "media".into(),
            channels: vec![
                AdaptationChannel::DbusMpris,
                AdaptationChannel::UriScheme,
                AdaptationChannel::DesktopAction,
            ],
            mpris_bus_hints: vec!["spotify".into()],
            dbus_name: Some("org.mpris.MediaPlayer2.spotify".into()),
            uri_schemes: vec!["spotify".into()],
            cli_executables: vec![],
            supported_actions: {
                let mut acts = mpris_standard_actions();
                acts.push(SemanticAppAction {
                    action: "open_uri".into(),
                    aliases: vec!["搜索曲库".into(), "spotify_uri".into()],
                    channel: AdaptationChannel::UriScheme,
                    summary: "通过 spotify:search:{query} URI 协议直达曲库搜索".into(),
                    target_template: Some("spotify:search:{query}".into()),
                    requires_approval: false,
                    reversible: false,
                });
                acts
            },
            source: "builtin".into(),
            notes: "通过 MPRIS2 驱动播放控制与曲目查询，并支持 spotify: 协议深度跳转".into(),
        },
        // 4. Rhythmbox
        AppAdapterProfile {
            id: "rhythmbox".into(),
            name: "Rhythmbox 音乐播放器".into(),
            desktop_ids: vec!["org.gnome.Rhythmbox3.desktop".into(), "rhythmbox.desktop".into()],
            aliases: vec!["rhythmbox".into(), "gnome音乐".into(), "本地音乐".into()],
            category: "media".into(),
            channels: vec![
                AdaptationChannel::DbusMpris,
                AdaptationChannel::DbusFreedesktop,
                AdaptationChannel::DesktopAction,
            ],
            mpris_bus_hints: vec!["rhythmbox".into(), "Rhythmbox3".into()],
            dbus_name: Some("org.mpris.MediaPlayer2.rhythmbox".into()),
            uri_schemes: vec![],
            cli_executables: vec!["rhythmbox-client".into()],
            supported_actions: mpris_standard_actions(),
            source: "builtin".into(),
            notes: "Ubuntu 默认音乐播放器，优先走标准 MPRIS2 D-Bus 总线控制".into(),
        },
        // 5. VLC
        AppAdapterProfile {
            id: "vlc".into(),
            name: "VLC 媒体播放器".into(),
            desktop_ids: vec!["vlc.desktop".into(), "org.videolan.VLC.desktop".into()],
            aliases: vec!["vlc".into(), "视频播放器".into(), "videolan".into()],
            category: "media".into(),
            channels: vec![
                AdaptationChannel::DbusMpris,
                AdaptationChannel::HeadlessCli,
                AdaptationChannel::DesktopAction,
            ],
            mpris_bus_hints: vec!["vlc".into()],
            dbus_name: Some("org.mpris.MediaPlayer2.vlc".into()),
            uri_schemes: vec![],
            cli_executables: vec!["vlc".into(), "cvlc".into(), "ffmpeg".into()],
            supported_actions: {
                let mut acts = mpris_standard_actions();
                acts.push(SemanticAppAction {
                    action: "transcode_media".into(),
                    aliases: vec!["媒体转码".into(), "提取音频".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "后台静默音视频转码/提取音频 (ffmpeg / cvlc)".into(),
                    target_template: Some("ffmpeg -nostdin -y -i {input} {output}".into()),
                    requires_approval: false,
                    reversible: true,
                });
                acts
            },
            source: "builtin".into(),
            notes: "前台播放控制走 MPRIS2，后台格式转码走 Headless 通道".into(),
        },
        // 6. GNOME Nautilus (Files)
        AppAdapterProfile {
            id: "nautilus".into(),
            name: "GNOME 文件管理器 (Nautilus)".into(),
            desktop_ids: vec!["org.gnome.Nautilus.desktop".into(), "nautilus.desktop".into()],
            aliases: vec![
                "nautilus".into(),
                "files".into(),
                "文件管理器".into(),
                "文件".into(),
                "资源管理器".into(),
            ],
            category: "file_manager".into(),
            channels: vec![
                AdaptationChannel::DbusFreedesktop,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::CliWrapper,
            ],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.freedesktop.FileManager1".into()),
            uri_schemes: vec![],
            cli_executables: vec!["nautilus".into()],
            supported_actions: file_manager_standard_actions(),
            source: "builtin".into(),
            notes: "通过 org.freedesktop.FileManager1.ShowItems 在已有 GUI 窗口精确高亮选中目标文件".into(),
        },
        // 7. KDE Dolphin
        AppAdapterProfile {
            id: "dolphin".into(),
            name: "KDE Dolphin 文件管理器".into(),
            desktop_ids: vec!["org.kde.dolphin.desktop".into(), "dolphin.desktop".into()],
            aliases: vec!["dolphin".into(), "kde文件管理器".into()],
            category: "file_manager".into(),
            channels: vec![
                AdaptationChannel::DbusFreedesktop,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::CliWrapper,
            ],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.freedesktop.FileManager1".into()),
            uri_schemes: vec![],
            cli_executables: vec!["dolphin".into()],
            supported_actions: file_manager_standard_actions(),
            source: "builtin".into(),
            notes: "通过 Freedesktop FileManager1 D-Bus 标准接口定位选中文件或打开目录".into(),
        },
        // 8. Visual Studio Code
        AppAdapterProfile {
            id: "vscode".into(),
            name: "Visual Studio Code".into(),
            desktop_ids: vec!["code.desktop".into(), "com.visualstudio.code.desktop".into()],
            aliases: vec!["vscode".into(), "code".into(), "vs code".into()],
            category: "ide".into(),
            channels: vec![
                AdaptationChannel::UriScheme,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::CliWrapper,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["vscode".into(), "vscode-insiders".into()],
            cli_executables: vec!["code".into()],
            supported_actions: ide_standard_actions("vscode", "code"),
            source: "builtin".into(),
            notes: "支持 vscode://file/{path}:{line}:{col} URI 深度唤起与 .desktop 新建空白窗口".into(),
        },
        // 9. ZCode
        AppAdapterProfile {
            id: "zcode".into(),
            name: "ZCode AI IDE".into(),
            desktop_ids: vec!["zcode.desktop".into()],
            aliases: vec!["zcode".into()],
            category: "ide".into(),
            channels: vec![
                AdaptationChannel::UriScheme,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::CliWrapper,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["zcode".into(), "vscode".into()],
            cli_executables: vec!["zcode".into()],
            supported_actions: ide_standard_actions("zcode", "zcode"),
            source: "builtin".into(),
            notes: "支持 zcode://file/{path}:{line}:{col} 源码定位与工作区打开".into(),
        },
        // 10. Cursor
        AppAdapterProfile {
            id: "cursor".into(),
            name: "Cursor AI Editor".into(),
            desktop_ids: vec!["cursor.desktop".into(), "co.anysphere.cursor.desktop".into()],
            aliases: vec!["cursor".into(), "cursor编辑器".into()],
            category: "ide".into(),
            channels: vec![
                AdaptationChannel::UriScheme,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::CliWrapper,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["cursor".into()],
            cli_executables: vec!["cursor".into()],
            supported_actions: ide_standard_actions("cursor", "cursor"),
            source: "builtin".into(),
            notes: "支持 cursor://file/{path}:{line}:{col} 协议直达与新建编辑器窗口".into(),
        },
        // 11. Google Chrome
        AppAdapterProfile {
            id: "google-chrome".into(),
            name: "Google Chrome".into(),
            desktop_ids: vec![
                "google-chrome.desktop".into(),
                "com.google.Chrome.desktop".into(),
                "chromium-browser.desktop".into(),
            ],
            aliases: vec!["chrome".into(), "google chrome".into(), "谷歌浏览器".into(), "chromium".into()],
            category: "browser".into(),
            channels: vec![
                AdaptationChannel::DesktopAction,
                AdaptationChannel::UriScheme,
                AdaptationChannel::DbusMpris,
            ],
            mpris_bus_hints: vec!["chromium".into(), "chrome".into()],
            dbus_name: None,
            uri_schemes: vec!["https".into(), "http".into()],
            cli_executables: vec!["google-chrome".into(), "chromium-browser".into()],
            supported_actions: browser_standard_actions(),
            source: "builtin".into(),
            notes: "通过 .desktop Desktop Action 打开新窗口/无痕窗口，通过 MPRIS2 控制网页音视频".into(),
        },
        // 12. Mozilla Firefox
        AppAdapterProfile {
            id: "firefox".into(),
            name: "Mozilla Firefox".into(),
            desktop_ids: vec![
                "firefox.desktop".into(),
                "firefox_firefox.desktop".into(),
                "org.mozilla.firefox.desktop".into(),
            ],
            aliases: vec!["firefox".into(), "火狐".into(), "火狐浏览器".into()],
            category: "browser".into(),
            channels: vec![
                AdaptationChannel::DesktopAction,
                AdaptationChannel::UriScheme,
                AdaptationChannel::DbusMpris,
            ],
            mpris_bus_hints: vec!["firefox".into()],
            dbus_name: None,
            uri_schemes: vec!["https".into(), "http".into()],
            cli_executables: vec!["firefox".into()],
            supported_actions: browser_standard_actions(),
            source: "builtin".into(),
            notes: "支持 [Desktop Action new-private-window] 隐私窗口唤起及网页媒体 MPRIS2 控制".into(),
        },
        // 13. Brave Browser
        AppAdapterProfile {
            id: "brave".into(),
            name: "Brave Browser".into(),
            desktop_ids: vec![
                "brave-browser.desktop".into(),
                "com.brave.Browser.desktop".into(),
            ],
            aliases: vec!["brave".into(), "brave浏览器".into()],
            category: "browser".into(),
            channels: vec![
                AdaptationChannel::DesktopAction,
                AdaptationChannel::UriScheme,
                AdaptationChannel::DbusMpris,
            ],
            mpris_bus_hints: vec!["brave".into()],
            dbus_name: None,
            uri_schemes: vec!["https".into(), "http".into()],
            cli_executables: vec!["brave-browser".into()],
            supported_actions: browser_standard_actions(),
            source: "builtin".into(),
            notes: "支持 .desktop 快捷动作新建窗口/隐私窗口与安全 HTTP(S) 链接打开".into(),
        },
        // 14. LibreOffice
        AppAdapterProfile {
            id: "libreoffice".into(),
            name: "LibreOffice 办公套件".into(),
            desktop_ids: vec![
                "libreoffice-writer.desktop".into(),
                "libreoffice-calc.desktop".into(),
                "libreoffice-impress.desktop".into(),
                "libreoffice-startcenter.desktop".into(),
            ],
            aliases: vec![
                "libreoffice".into(),
                "soffice".into(),
                "writer".into(),
                "calc".into(),
                "impress".into(),
                "办公软件".into(),
            ],
            category: "office".into(),
            channels: vec![
                AdaptationChannel::HeadlessCli,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::CliWrapper,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["libreoffice".into(), "soffice".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "convert_to_pdf".into(),
                    aliases: vec!["转pdf".into(), "导出pdf".into(), "export_pdf".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "后台无头静默将 Word/Excel/PPT/ODT 文档转换为 PDF 并记录可撤销变更集".into(),
                    target_template: Some(
                        "libreoffice --headless --convert-to pdf --outdir {outdir} {input}".into(),
                    ),
                    requires_approval: false,
                    reversible: true,
                },
                SemanticAppAction {
                    action: "convert_document".into(),
                    aliases: vec!["文档格式转换".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "后台无头转换文档格式 (docx/odt/html/txt/pdf)".into(),
                    target_template: Some(
                        "libreoffice --headless --convert-to {format} --outdir {outdir} {input}".into(),
                    ),
                    requires_approval: false,
                    reversible: true,
                },
                SemanticAppAction {
                    action: "new_window".into(),
                    aliases: vec!["新建文档".into(), "writer".into()],
                    channel: AdaptationChannel::DesktopAction,
                    summary: "启动 LibreOffice 新建文档界面".into(),
                    target_template: Some("writer".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "封装隐藏 --headless --convert-to 接口，无需弹窗即可完成批量办公文档转 PDF".into(),
        },
        // 15. WPS Office & WPS Cloud
        AppAdapterProfile {
            id: "wps-office".into(),
            name: "WPS Office / WPS 云盘".into(),
            desktop_ids: vec![
                "wps-office-prometheus.desktop".into(),
                "wps-office-wps.desktop".into(),
                "wps-office-et.desktop".into(),
                "wps-office-wpp.desktop".into(),
                "wps-office-pdf.desktop".into(),
                "com.kingsoft.Office.desktop".into(),
            ],
            aliases: vec![
                "wps".into(),
                "wps office".into(),
                "wps云盘".into(),
                "wpscloud".into(),
                "wpscloudsvr".into(),
                "qing".into(),
                "金山文档".into(),
                "wps文字".into(),
                "wps表格".into(),
                "wps演示".into(),
            ],
            category: "office".into(),
            channels: vec![
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::HeadlessCli,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["ksowebstartupwps".into()],
            cli_executables: vec![
                "wps".into(),
                "et".into(),
                "wpp".into(),
                "wpscloudsvr".into(),
                "libreoffice".into(),
            ],
            supported_actions: vec![
                SemanticAppAction {
                    action: "convert_to_pdf".into(),
                    aliases: vec!["转pdf".into(), "导出pdf".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "使用兼容无头办公引擎将 WPS/Office 文档静默导出为 PDF".into(),
                    target_template: Some(
                        "libreoffice --headless --convert-to pdf --outdir {outdir} {input}".into(),
                    ),
                    requires_approval: false,
                    reversible: true,
                },
                SemanticAppAction {
                    action: "new_window".into(),
                    aliases: vec!["新建窗口".into()],
                    channel: AdaptationChannel::DesktopAction,
                    summary: "通过 .desktop 打开 WPS 文字/表格/演示窗口".into(),
                    target_template: Some("new-window".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "click_tray_menu".into(),
                    aliases: vec!["托盘菜单".into(), "查看传输详情".into(), "启动 WPS 云盘".into()],
                    channel: AdaptationChannel::SniDbusMenu,
                    summary: "通过 wpscloudsvr 系统托盘 dbusmenu 执行云盘菜单项（如启动 WPS 云盘、查看传输详情、同步与设置）".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "支持 wpscloudsvr 系统托盘 dbusmenu 控制、.desktop 启动及无头 PDF 转换".into(),
        },
        // 16. Obsidian
        AppAdapterProfile {
            id: "obsidian".into(),
            name: "Obsidian 知识库".into(),
            desktop_ids: vec!["obsidian.desktop".into(), "md.obsidian.Obsidian.desktop".into()],
            aliases: vec!["obsidian".into(), "黑曜石".into(), "双链笔记".into()],
            category: "knowledge".into(),
            channels: vec![
                AdaptationChannel::UriScheme,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["obsidian".into()],
            cli_executables: vec![],
            supported_actions: vec![
                SemanticAppAction {
                    action: "open_note".into(),
                    aliases: vec!["打开笔记".into(), "open_vault".into()],
                    channel: AdaptationChannel::UriScheme,
                    summary: "通过 obsidian://open?vault={vault}&file={file} 深度链接直达笔记".into(),
                    target_template: Some("obsidian://open?vault={vault}&file={file}".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "new_note".into(),
                    aliases: vec!["新建笔记".into(), "create_note".into()],
                    channel: AdaptationChannel::UriScheme,
                    summary: "通过 obsidian://new?vault={vault}&name={name}&content={content} 创建笔记".into(),
                    target_template: Some(
                        "obsidian://new?vault={vault}&name={name}&content={content}".into(),
                    ),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "search_notes".into(),
                    aliases: vec!["搜索笔记".into(), "search".into()],
                    channel: AdaptationChannel::UriScheme,
                    summary: "通过 obsidian://search?vault={vault}&query={query} 唤起库内检索".into(),
                    target_template: Some("obsidian://search?vault={vault}&query={query}".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "Obsidian 无终端 CLI 接口，完全通过官方 obsidian:// URI 协议实现打开/新建/搜索笔记".into(),
        },
        // 17. Evince
        AppAdapterProfile {
            id: "evince".into(),
            name: "GNOME 文档查看器 (Evince)".into(),
            desktop_ids: vec!["org.gnome.Evince.desktop".into(), "evince.desktop".into()],
            aliases: vec!["evince".into(), "pdf查看器".into(), "文档查看器".into()],
            category: "document_viewer".into(),
            channels: vec![
                AdaptationChannel::HeadlessCli,
                AdaptationChannel::DbusFreedesktop,
                AdaptationChannel::CliWrapper,
            ],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.gnome.Evince".into()),
            uri_schemes: vec![],
            cli_executables: vec!["evince".into(), "pdftotext".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "extract_text_preview".into(),
                    aliases: vec!["提取pdf文本".into(), "提取文本".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "后台无头提取 PDF 文档正文预览 (pdftotext)".into(),
                    target_template: Some("pdftotext {input} -".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "activate".into(),
                    aliases: vec!["唤起阅读器".into()],
                    channel: AdaptationChannel::DbusFreedesktop,
                    summary: "通过 org.freedesktop.Application D-Bus 激活 Evince".into(),
                    target_template: Some("org.gnome.Evince".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "open_pdf_page".into(),
                    aliases: vec!["跳转pdf页码".into(), "打开pdf页".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `evince --page-index=<n> <path>` 直接跳转 PDF 指定页码".into(),
                    target_template: Some("evince --page-index={page} {path}".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "find_in_pdf".into(),
                    aliases: vec!["pdf搜索".into(), "在pdf中查找".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `evince --find=<keyword> <path>` 打开 PDF 并高亮检索关键词".into(),
                    target_template: Some("evince --find={keyword} {path}".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "结合 D-Bus 应用激活、页码跳转/全文定位与 pdftotext 后台静默文本预览".into(),
        },
        // 18. Okular
        AppAdapterProfile {
            id: "okular".into(),
            name: "Okular PDF 阅读器".into(),
            desktop_ids: vec!["org.kde.okular.desktop".into(), "okular.desktop".into()],
            aliases: vec!["okular".into(), "kde阅读器".into()],
            category: "document_viewer".into(),
            channels: vec![
                AdaptationChannel::HeadlessCli,
                AdaptationChannel::DbusFreedesktop,
                AdaptationChannel::CliWrapper,
            ],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.kde.okular".into()),
            uri_schemes: vec![],
            cli_executables: vec!["okular".into(), "pdftotext".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "extract_text_preview".into(),
                    aliases: vec!["提取pdf文本".into(), "提取文本".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "后台无头提取 PDF 文本摘要 (pdftotext)".into(),
                    target_template: Some("pdftotext {input} -".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "open_file_at_line".into(),
                    aliases: vec!["打开页码".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `okular -p <page> <path>` 直接跳转指定页码".into(),
                    target_template: Some("okular -p {page} {path}".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "支持页码直达封装与后台 PDF 文本提取".into(),
        },
        // 19. GIMP
        AppAdapterProfile {
            id: "gimp".into(),
            name: "GIMP 图像编辑器".into(),
            desktop_ids: vec!["gimp.desktop".into(), "org.gimp.GIMP.desktop".into()],
            aliases: vec!["gimp".into(), "修图软件".into(), "图像编辑".into()],
            category: "graphics".into(),
            channels: vec![
                AdaptationChannel::HeadlessCli,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["ffmpeg".into(), "convert".into(), "gimp".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "convert_image".into(),
                    aliases: vec!["图片转换".into(), "转换图片格式".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "后台静默转换图像格式/尺寸 (png/jpg/webp) 并生成可撤销变更集".into(),
                    target_template: Some("ffmpeg -nostdin -y -i {input} {output}".into()),
                    requires_approval: false,
                    reversible: true,
                },
                SemanticAppAction {
                    action: "focus_window".into(),
                    aliases: vec!["聚焦窗口".into()],
                    channel: AdaptationChannel::GuiAtspi,
                    summary: "聚焦 GIMP 图像编辑窗口".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "常规图像格式转换走无头静默通道避免启动重量级 GUI，交互修图走窗口桥接".into(),
        },
        // 20. Draw.io
        AppAdapterProfile {
            id: "drawio".into(),
            name: "Draw.io 流程图工具".into(),
            desktop_ids: vec!["drawio.desktop".into(), "com.jgraph.drawio.desktop.desktop".into()],
            aliases: vec!["drawio".into(), "draw.io".into(), "diagrams.net".into(), "流程图".into()],
            category: "graphics".into(),
            channels: vec![
                AdaptationChannel::HeadlessCli,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["drawio".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "convert_to_pdf".into(),
                    aliases: vec!["导出流程图pdf".into(), "转pdf".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "通过 `drawio --export --format pdf` 静默导出 .drawio 架构图".into(),
                    target_template: Some("drawio --export --format pdf --output {output} {input}".into()),
                    requires_approval: false,
                    reversible: true,
                },
                SemanticAppAction {
                    action: "new_window".into(),
                    aliases: vec!["新建流程图".into()],
                    channel: AdaptationChannel::DesktopAction,
                    summary: "打开 Draw.io 桌面窗口".into(),
                    target_template: Some("new-window".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "open_diagram".into(),
                    aliases: vec!["打开流程图".into(), "打开架构图".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `/opt/drawio/drawio <path>` 打开本地流程图文件".into(),
                    target_template: Some("/opt/drawio/drawio {path}".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "export_diagram".into(),
                    aliases: vec!["导出流程图".into(), "导出架构图".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "通过 `/opt/drawio/drawio -x -f <pdf|png|svg> -o <out> <in>` 导出并核验输出文件".into(),
                    target_template: Some("/opt/drawio/drawio -x -f {format} -o {output_path} {input_path}".into()),
                    requires_approval: false,
                    reversible: true,
                },
            ],
            source: "builtin".into(),
            notes: "封装 drawio Electron 导出参数与 GUI 窗口唤起".into(),
        },
        // 21. Telegram Desktop
        AppAdapterProfile {
            id: "telegram".into(),
            name: "Telegram Desktop".into(),
            desktop_ids: vec![
                "org.telegram.desktop.desktop".into(),
                "telegramdesktop.desktop".into(),
            ],
            aliases: vec!["telegram".into(), "tg".into(), "电报".into()],
            category: "communication".into(),
            channels: vec![
                AdaptationChannel::UriScheme,
                AdaptationChannel::DbusFreedesktop,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec!["telegram".into()],
            dbus_name: Some("org.telegram.desktop".into()),
            uri_schemes: vec!["tg".into()],
            cli_executables: vec![],
            supported_actions: vec![
                SemanticAppAction {
                    action: "open_chat".into(),
                    aliases: vec!["打开会话".into(), "打开频道".into(), "resolve".into()],
                    channel: AdaptationChannel::UriScheme,
                    summary: "通过 tg://resolve?domain={domain} 深度链接打开指定联系人或频道".into(),
                    target_template: Some("tg://resolve?domain={domain}".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "activate".into(),
                    aliases: vec!["唤起窗口".into()],
                    channel: AdaptationChannel::DbusFreedesktop,
                    summary: "通过 Freedesktop Application D-Bus 激活 Telegram 主窗口".into(),
                    target_template: Some("org.telegram.desktop".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "纯 GUI 即时通讯客户端，通过 tg:// 协议实现会话直达（绝不自动点发送）".into(),
        },
        // 22. Mail Client (Thunderbird / Geary / x-scheme-handler/mailto)
        AppAdapterProfile {
            id: "mail-client".into(),
            name: "桌面邮件客户端 (Thunderbird / Geary)".into(),
            desktop_ids: vec![
                "thunderbird.desktop".into(),
                "org.mozilla.Thunderbird.desktop".into(),
                "org.gnome.Geary.desktop".into(),
            ],
            aliases: vec![
                "thunderbird".into(),
                "geary".into(),
                "mail".into(),
                "email".into(),
                "邮箱".into(),
                "邮件客户端".into(),
            ],
            category: "communication".into(),
            channels: vec![AdaptationChannel::UriScheme, AdaptationChannel::DesktopAction],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["mailto".into()],
            cli_executables: vec!["thunderbird".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "compose_email".into(),
                    aliases: vec!["写邮件".into(), "发邮件".into(), "mailto".into()],
                    channel: AdaptationChannel::UriScheme,
                    summary: "通过 mailto:{to}?subject={subject}&body={body} 预填收件人与正文草稿（由用户确认发送）".into(),
                    target_template: Some("mailto:{to}?subject={subject}&body={body}".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "new_window".into(),
                    aliases: vec!["新建邮件窗口".into(), "ComposeMessage".into()],
                    channel: AdaptationChannel::DesktopAction,
                    summary: "调用 .desktop [Desktop Action ComposeMessage] 打开写信窗口".into(),
                    target_template: Some("ComposeMessage".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "使用标准 mailto: RFC6068 URL 编码预填草稿，严格遵守不自动外发原则".into(),
        },
        // 23. GNOME Control Center & Desktop Windows
        AppAdapterProfile {
            id: "gnome-settings".into(),
            name: "GNOME 系统设置与窗口中心".into(),
            desktop_ids: vec!["org.gnome.Settings.desktop".into(), "gnome-control-center.desktop".into()],
            aliases: vec![
                "gnome-settings".into(),
                "gnome-control-center".into(),
                "系统设置".into(),
                "控制面板".into(),
            ],
            category: "system".into(),
            channels: vec![
                AdaptationChannel::CliWrapper,
                AdaptationChannel::DbusFreedesktop,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.gnome.Settings".into()),
            uri_schemes: vec![],
            cli_executables: vec!["gnome-control-center".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "open_settings_panel".into(),
                    aliases: vec!["打开设置面板".into(), "跳转到设置页".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `gnome-control-center <panel>` 直达蓝牙/网络/显示/声音子面板".into(),
                    target_template: Some("gnome-control-center {panel}".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "activate".into(),
                    aliases: vec!["唤起设置".into()],
                    channel: AdaptationChannel::DbusFreedesktop,
                    summary: "通过 D-Bus 激活 GNOME 设置窗口".into(),
                    target_template: Some("org.gnome.Settings".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "封装 GNOME Control Center 子面板直达与 D-Bus 激活".into(),
        },
        // 24. SodaM (汽水音乐)
        AppAdapterProfile {
            id: "sodam".into(),
            name: "汽水音乐 (SodaM)".into(),
            desktop_ids: vec!["sodam.desktop".into()],
            aliases: vec![
                "汽水音乐".into(),
                "sodam".into(),
                "qishui".into(),
                "soda".into(),
            ],
            category: "media".into(),
            channels: vec![
                AdaptationChannel::DbusMpris,
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec!["sodam".into()],
            dbus_name: Some("org.mpris.MediaPlayer2.sodam".into()),
            uri_schemes: vec![],
            cli_executables: vec!["sodam".into()],
            supported_actions: {
                let mut acts = mpris_standard_actions();
                acts.push(SemanticAppAction {
                    action: "focus_window".into(),
                    aliases: vec!["显示主窗口".into(), "聚焦窗口".into()],
                    channel: AdaptationChannel::GuiAtspi,
                    summary: "通过 StatusNotifierItem 托盘菜单唤醒并前置汽水音乐主窗口".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                });
                acts.push(SemanticAppAction {
                    action: "click_tray_menu".into(),
                    aliases: vec!["托盘菜单".into()],
                    channel: AdaptationChannel::SniDbusMenu,
                    summary: "通过 StatusNotifierItem dbusmenu 控制汽水音乐（暂停/上一首/下一首/显示主窗口/退出）".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                });
                acts
            },
            source: "builtin".into(),
            notes: "支持 MPRIS2 与 org.kde.StatusNotifierItem /MenuBar 双通道实时曲目读取、切歌与唤醒主窗口".into(),
        },
        // 25. Linux QQ
        AppAdapterProfile {
            id: "qq".into(),
            name: "腾讯 QQ (Linux QQ)".into(),
            desktop_ids: vec!["qq.desktop".into(), "linuxqq.desktop".into()],
            aliases: vec!["qq".into(), "腾讯qq".into(), "linuxqq".into()],
            category: "social_collab".into(),
            channels: vec![
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::UriScheme,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["tencent".into()],
            cli_executables: vec!["qq".into(), "linuxqq".into()],
            supported_actions: {
                let mut acts = vec![
                    SemanticAppAction {
                        action: "wake_main_window".into(),
                        aliases: vec!["唤醒主窗口".into(), "显示主窗口".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "通过 StatusNotifierItem 托盘或纯净环境启动唤醒 QQ 主界面".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "click_tray_menu".into(),
                        aliases: vec!["托盘菜单".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "读取并点击 Linux QQ 实时托盘菜单项".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                ];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "Electron 托盘即时通讯客户端，支持 StatusNotifierItem 托盘唤醒、tencent:// 协议与验证退出".into(),
        },
        // 26. WeChat (微信)
        AppAdapterProfile {
            id: "wechat".into(),
            name: "微信 (WeChat)".into(),
            desktop_ids: vec!["wechat.desktop".into(), "com.tencent.WeChat.desktop".into()],
            aliases: vec!["微信".into(), "wechat".into(), "weixin".into()],
            category: "social_collab".into(),
            channels: vec![
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::UriScheme,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["weixin".into()],
            cli_executables: vec!["wechat".into()],
            supported_actions: {
                let mut acts = vec![
                    SemanticAppAction {
                        action: "wake_main_window".into(),
                        aliases: vec!["唤醒主窗口".into(), "显示微信".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "通过系统托盘 StatusNotifierItem 或纯净桌面启动唤醒微信主窗口".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "click_tray_menu".into(),
                        aliases: vec!["托盘菜单".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "触发微信实时系统托盘菜单项".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                ];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "支持系统托盘 StatusNotifierItem 唤醒主窗口、weixin:// 协议与进程级优雅退出".into(),
        },
        // 27. Feishu (飞书)
        AppAdapterProfile {
            id: "bytedance-feishu".into(),
            name: "飞书 (Feishu / Lark)".into(),
            desktop_ids: vec!["bytedance-feishu.desktop".into(), "feishu.desktop".into()],
            aliases: vec!["飞书".into(), "feishu".into(), "lark".into(), "bytedance-feishu".into()],
            category: "social_collab".into(),
            channels: vec![
                AdaptationChannel::UriScheme,
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["feishu".into(), "lark".into(), "applink.feishu".into(), "feishu-open".into()],
            cli_executables: vec!["bytedance-feishu".into()],
            supported_actions: {
                let mut acts = vec![
                    SemanticAppAction {
                        action: "open_feishu_uri".into(),
                        aliases: vec!["打开飞书链接".into(), "打开飞书工作台".into()],
                        channel: AdaptationChannel::UriScheme,
                        summary: "通过 feishu:// / lark:// 深度链接打开飞书云文档或会话".into(),
                        target_template: Some("feishu://client/open".into()),
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "wake_main_window".into(),
                        aliases: vec!["唤醒主窗口".into(), "打开飞书主界面".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "通过 SNI 托盘或纯净桌面环境唤醒飞书窗口".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                ];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "支持 feishu:// / lark:// / applink.feishu:// 协议及 StatusNotifierItem 托盘唤醒".into(),
        },
        // 28. Tencent Meeting (腾讯会议)
        AppAdapterProfile {
            id: "wemeetapp".into(),
            name: "腾讯会议 (WeMeet)".into(),
            desktop_ids: vec!["wemeetapp.desktop".into(), "com.tencent.wemeet.desktop".into()],
            aliases: vec!["腾讯会议".into(), "wemeet".into(), "wemeetapp".into(), "tengxunhuiyi".into()],
            category: "social_collab".into(),
            channels: vec![
                AdaptationChannel::UriScheme,
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["wemeet".into()],
            cli_executables: vec!["wemeetapp".into()],
            supported_actions: {
                let mut acts = vec![
                    SemanticAppAction {
                        action: "join_meeting".into(),
                        aliases: vec!["加入会议".into(), "入会".into(), "快速入会".into()],
                        channel: AdaptationChannel::UriScheme,
                        summary: "自动清洗 9~11 位会议号空格/连字符并通过 `wemeet://page/inmeeting?meeting_code=<digits>` 直达会议室".into(),
                        target_template: Some("wemeet://page/inmeeting?meeting_code={meeting_code}".into()),
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "wake_main_window".into(),
                        aliases: vec!["唤醒主窗口".into(), "打开腾讯会议".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "唤醒腾讯会议主界面".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                ];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "支持 wemeet://page/inmeeting?meeting_code= 协议快速入会及系统托盘主窗口唤醒".into(),
        },
        // 29. Baidu Netdisk (百度网盘)
        AppAdapterProfile {
            id: "baidunetdisk".into(),
            name: "百度网盘 (Baidu Netdisk)".into(),
            desktop_ids: vec!["baidunetdisk.desktop".into()],
            aliases: vec!["百度网盘".into(), "百度云".into(), "baidunetdisk".into()],
            category: "cloud_transfer".into(),
            channels: vec![
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::CliWrapper,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["baiduyunguanjia".into()],
            cli_executables: vec!["baidunetdisk".into()],
            supported_actions: {
                let mut acts = vec![
                    SemanticAppAction {
                        action: "wake_cloud_drive".into(),
                        aliases: vec!["唤醒网盘".into(), "显示主窗口".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "通过 SNI 托盘菜单「显示主窗口」或纯净桌面启动唤醒百度网盘".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "open_download_folder".into(),
                        aliases: vec!["打开下载目录".into(), "网盘下载目录".into()],
                        channel: AdaptationChannel::CliWrapper,
                        summary: "定位打开 `~/baidunetdiskdownload` 或 `~/Downloads` 网盘下载目录".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                ];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "支持系统托盘 StatusNotifierItem 菜单、下载目录定位与主窗口唤醒".into(),
        },
        // 30. China Mobile Cloud (移动云盘)
        AppAdapterProfile {
            id: "mcloud".into(),
            name: "中国移动云盘 (mCloud)".into(),
            desktop_ids: vec![
                "com.cmic.mcloud.desktop".into(),
                "mcloud.desktop".into(),
            ],
            aliases: vec!["移动云盘".into(), "中国移动云盘".into(), "mcloud".into()],
            category: "cloud_transfer".into(),
            channels: vec![
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::CliWrapper,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["mcloud".into()],
            supported_actions: {
                let mut acts = vec![
                    SemanticAppAction {
                        action: "wake_cloud_drive".into(),
                        aliases: vec!["唤醒网盘".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "唤醒中国移动云盘主窗口".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "open_download_folder".into(),
                        aliases: vec!["打开下载目录".into()],
                        channel: AdaptationChannel::CliWrapper,
                        summary: "打开云盘本地下载目录".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                ];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "支持系统托盘 StatusNotifierItem 唤醒、下载目录定位与优雅退出".into(),
        },
        // 31. BetterNotes (轻笺)
        AppAdapterProfile {
            id: "betternotes".into(),
            name: "轻笺 (BetterNotes)".into(),
            desktop_ids: vec![
                "com.github.paperhead.BetterNotes.desktop".into(),
                "betternotes.desktop".into(),
            ],
            aliases: vec!["轻笺".into(), "betternotes".into(), "pinplan".into(), "便签".into()],
            category: "office_notes_doc".into(),
            channels: vec![
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["betternotes".into(), "BetterNotes".into()],
            supported_actions: {
                let mut acts = vec![SemanticAppAction {
                    action: "wake_notes".into(),
                    aliases: vec!["唤醒便签".into(), "打开轻笺".into()],
                    channel: AdaptationChannel::SniDbusMenu,
                    summary: "通过系统托盘或桌面启动唤醒轻笺便签窗口".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                }];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "桌面便签笔记应用，支持托盘唤醒与窗口桥接控制".into(),
        },
        // 32. FlClash
        AppAdapterProfile {
            id: "flclash".into(),
            name: "FlClash 网络代理".into(),
            desktop_ids: vec![
                "FlClash.desktop".into(),
                "flclash.desktop".into(),
                "flclash-url-handler.desktop".into(),
            ],
            aliases: vec![
                "flclash".into(),
                "clash".into(),
                "代理".into(),
                "系统代理".into(),
                "科学上网".into(),
            ],
            category: "network_browser".into(),
            channels: vec![
                AdaptationChannel::SniDbusMenu,
                AdaptationChannel::CliWrapper,
                AdaptationChannel::UriScheme,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["clash".into(), "clashmeta".into(), "flclash".into()],
            cli_executables: vec!["FlClash".into(), "flclash".into()],
            supported_actions: {
                let mut acts = vec![
                    SemanticAppAction {
                        action: "probe_proxy_status".into(),
                        aliases: vec!["探测代理状态".into(), "代理状态".into(), "查询代理".into()],
                        channel: AdaptationChannel::CliWrapper,
                        summary: "联合探测 FlClash 运行 PID、本地 7890/7897/9090 端口监听与 SNI 托盘状态".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "wake_dashboard".into(),
                        aliases: vec!["打开代理面板".into(), "唤醒主界面".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "唤醒 FlClash 控制面板".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "click_tray_menu".into(),
                        aliases: vec!["切换系统代理".into(), "托盘菜单".into()],
                        channel: AdaptationChannel::SniDbusMenu,
                        summary: "通过实时 StatusNotifierItem dbusmenu 切换系统代理 / TUN / 规则/全局/直连模式".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: false,
                    },
                ];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "支持通过 StatusNotifierItem 托盘菜单切换代理开关、本地端口探针、URI 订阅与唤醒主界面".into(),
        },
        // 33. DiscForge (光铸)
        AppAdapterProfile {
            id: "discforge".into(),
            name: "光铸 (DiscForge)".into(),
            desktop_ids: vec![
                "io.github.discforge.native.desktop".into(),
                "discforge.desktop".into(),
            ],
            aliases: vec![
                "光铸".into(),
                "discforge".into(),
                "discforge-native".into(),
                "光盘刻录".into(),
            ],
            category: "creative_disc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["discforge-native".into(), "discforge".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持光铸桌面窗口焦点、启动与进程验证生命周期控制".into(),
        },
        // 34. Yozo Office (永中 Office)
        AppAdapterProfile {
            id: "yozo".into(),
            name: "永中 Office (Yozo Office)".into(),
            desktop_ids: vec![
                "yozo.desktop".into(),
                "yozo-writer.desktop".into(),
                "yozo-calc.desktop".into(),
                "yozo-impress.desktop".into(),
                "yozo-reader.desktop".into(),
                "yozo-office.desktop".into(),
                "yozo-office-word.desktop".into(),
                "yozo-office-excel.desktop".into(),
                "yozo-office-powerpoint.desktop".into(),
            ],
            aliases: vec![
                "永中".into(),
                "永中office".into(),
                "yozo".into(),
                "yozo-office".into(),
                "永中文字".into(),
                "永中表格".into(),
                "永中简报".into(),
            ],
            category: "office_notes_doc".into(),
            channels: vec![
                AdaptationChannel::CliWrapper,
                AdaptationChannel::HeadlessCli,
                AdaptationChannel::DesktopAction,
                AdaptationChannel::GuiAtspi,
            ],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec![
                "yozo".into(),
                "yozo-office".into(),
                "yozow".into(),
                "yozoc".into(),
                "yozoi".into(),
                "yozor".into(),
            ],
            supported_actions: {
                let mut acts = vec![
                    SemanticAppAction {
                        action: "new_document".into(),
                        aliases: vec!["新建文档".into()],
                        channel: AdaptationChannel::CliWrapper,
                        summary: "启动永中文字新建文档 (`yozow`)".into(),
                        target_template: Some("yozow".into()),
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "new_spreadsheet".into(),
                        aliases: vec!["新建表格".into()],
                        channel: AdaptationChannel::CliWrapper,
                        summary: "启动永中表格新建工作簿 (`yozoc`)".into(),
                        target_template: Some("yozoc".into()),
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "new_presentation".into(),
                        aliases: vec!["新建演示".into()],
                        channel: AdaptationChannel::CliWrapper,
                        summary: "启动永中简报新建幻灯片 (`yozoi`)".into(),
                        target_template: Some("yozoi".into()),
                        requires_approval: false,
                        reversible: false,
                    },
                    SemanticAppAction {
                        action: "convert_to_pdf".into(),
                        aliases: vec!["转pdf".into()],
                        channel: AdaptationChannel::HeadlessCli,
                        summary: "将永中/Office 文档静默导出为 PDF 并校验磁盘输出".into(),
                        target_template: None,
                        requires_approval: false,
                        reversible: true,
                    },
                ];
                acts.extend(gui_atspi_standard_actions());
                acts
            },
            source: "builtin".into(),
            notes: "国产办公套件 2024 全家桶，支持新建文字/表格/简报、PDF 转换与窗口桥接".into(),
        },
        // 35. Generic GUI Window & AT-SPI2 Bridge
        AppAdapterProfile {
            id: "generic-gui-window".into(),
            name: "通用桌面 GUI 窗口无障碍适配".into(),
            desktop_ids: vec![],
            aliases: vec![
                "gui".into(),
                "window".into(),
                "atspi".into(),
                "窗口".into(),
                "桌面窗口".into(),
            ],
            category: "hardware_system".into(),
            channels: vec![AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec![],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "面向无 CLI/无 D-Bus 的纯 GUI 软件：支持窗口枚举/聚焦、AT-SPI2 控件探测及分级审批 UI 注入".into(),
        },
        // ====================================================================
        // Wave 5 Deep Local Software Expansion (#36 - #70 across all 9 categories)
        // ====================================================================
        // 36. mpv Media Player
        AppAdapterProfile {
            id: "mpv".into(),
            name: "mpv 极简媒体播放器".into(),
            desktop_ids: vec!["mpv.desktop".into(), "io.mpv.Mpv.desktop".into()],
            aliases: vec!["mpv".into(), "mpv播放器".into()],
            category: "media_entertainment".into(),
            channels: vec![AdaptationChannel::DbusMpris, AdaptationChannel::CliWrapper],
            mpris_bus_hints: vec!["mpv".into()],
            dbus_name: Some("org.mpris.MediaPlayer2.mpv".into()),
            uri_schemes: vec![],
            cli_executables: vec!["mpv".into()],
            supported_actions: mpris_standard_actions(),
            source: "builtin".into(),
            notes: "支持 MPRIS2 控制及受控非 Shell 媒体文件播放".into(),
        },
        // 37. Douyin Chrome PWA (抖音)
        AppAdapterProfile {
            id: "douyin".into(),
            name: "抖音桌面版 (Douyin PWA)".into(),
            desktop_ids: vec!["douyin.desktop".into()],
            aliases: vec!["抖音".into(), "douyin".into(), "tiktok-cn".into()],
            category: "media_entertainment".into(),
            channels: vec![AdaptationChannel::DbusMpris, AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec!["chromium".into(), "chrome".into()],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec![],
            supported_actions: mpris_standard_actions(),
            source: "builtin".into(),
            notes: "抖音 Chrome PWA 应用，通过浏览器 MPRIS2 接口控制播放/暂停与窗口聚焦".into(),
        },
        // 38. Discord
        AppAdapterProfile {
            id: "discord".into(),
            name: "Discord 社区语音".into(),
            desktop_ids: vec!["discord.desktop".into(), "com.discordapp.Discord.desktop".into()],
            aliases: vec!["discord".into()],
            category: "social_collab".into(),
            channels: vec![AdaptationChannel::UriScheme, AdaptationChannel::SniDbusMenu, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["discord".into()],
            cli_executables: vec!["discord".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持 discord:// 深度链接与托盘控制".into(),
        },
        // 39. Zoom Workplace
        AppAdapterProfile {
            id: "zoom".into(),
            name: "Zoom 视频会议".into(),
            desktop_ids: vec!["Zoom.desktop".into(), "us.zoom.Zoom.desktop".into()],
            aliases: vec!["zoom".into(), "zoom会议".into()],
            category: "social_collab".into(),
            channels: vec![AdaptationChannel::UriScheme, AdaptationChannel::SniDbusMenu, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["zoommtg".into(), "zoomus".into()],
            cli_executables: vec!["zoom".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持 zoommtg:// 入会协议与托盘窗口唤醒".into(),
        },
        // 40. Slack
        AppAdapterProfile {
            id: "slack".into(),
            name: "Slack 团队协作".into(),
            desktop_ids: vec!["slack.desktop".into(), "com.slack.Slack.desktop".into()],
            aliases: vec!["slack".into()],
            category: "social_collab".into(),
            channels: vec![AdaptationChannel::UriScheme, AdaptationChannel::SniDbusMenu, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["slack".into()],
            cli_executables: vec!["slack".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持 slack:// 协议与托盘唤醒".into(),
        },
        // 41. GNOME Papers (PDF Document Viewer)
        AppAdapterProfile {
            id: "gnome-papers".into(),
            name: "GNOME Papers 文档阅读器".into(),
            desktop_ids: vec!["org.gnome.Papers.desktop".into()],
            aliases: vec!["papers".into(), "gnome papers".into()],
            category: "office_notes_doc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::HeadlessCli, AdaptationChannel::DbusFreedesktop],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.gnome.Papers".into()),
            uri_schemes: vec![],
            cli_executables: vec!["papers".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "open_pdf_page".into(),
                    aliases: vec!["打开pdf页".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "使用 Papers / Evince 打开指定 PDF 文档".into(),
                    target_template: Some("papers {path}".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "extract_text_preview".into(),
                    aliases: vec!["提取pdf文本".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "后台提取 PDF 文本摘要".into(),
                    target_template: Some("pdftotext {input} -".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "Ubuntu 现代 GNOME Papers 阅读器适配".into(),
        },
        // 42. PDF Arranger
        AppAdapterProfile {
            id: "pdfarranger".into(),
            name: "PDF Arranger 页面合并拆分器".into(),
            desktop_ids: vec![
                "pdfarranger.desktop".into(),
                "com.github.jeromerobert.pdfarranger.desktop".into(),
            ],
            aliases: vec!["pdfarranger".into(), "pdf合并".into(), "pdf拆分".into()],
            category: "office_notes_doc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["pdfarranger".into()],
            supported_actions: vec![SemanticAppAction {
                action: "open_pdf_arranger".into(),
                aliases: vec!["合并拆分pdf".into(), "整理pdf".into()],
                channel: AdaptationChannel::CliWrapper,
                summary: "在 PDF Arranger 中打开一个或多个 PDF 进行合并/拆分/重排".into(),
                target_template: Some("pdfarranger {paths}".into()),
                requires_approval: false,
                reversible: false,
            }],
            source: "builtin".into(),
            notes: "支持单文件或多文件数组传入 PDF Arranger".into(),
        },
        // 43. ONLYOFFICE Desktop Editors
        AppAdapterProfile {
            id: "onlyoffice".into(),
            name: "ONLYOFFICE 桌面编辑器".into(),
            desktop_ids: vec![
                "onlyoffice-desktopeditors.desktop".into(),
                "org.onlyoffice.desktopeditors.desktop".into(),
            ],
            aliases: vec!["onlyoffice".into(), "onlyoffice编辑器".into()],
            category: "office_notes_doc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::HeadlessCli, AdaptationChannel::DesktopAction],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["onlyoffice-desktopeditors".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "new_document".into(),
                    aliases: vec!["新建文档".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "启动 ONLYOFFICE 新建办公文档".into(),
                    target_template: Some("onlyoffice-desktopeditors".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "convert_to_pdf".into(),
                    aliases: vec!["转pdf".into()],
                    channel: AdaptationChannel::HeadlessCli,
                    summary: "后台无头转换文档为 PDF".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: true,
                },
            ],
            source: "builtin".into(),
            notes: "支持 ONLYOFFICE 文档新建、打开及无头 PDF 转换".into(),
        },
        // 44. Typora Markdown Editor
        AppAdapterProfile {
            id: "typora".into(),
            name: "Typora Markdown 编辑器".into(),
            desktop_ids: vec!["typora.desktop".into(), "io.typora.Typora.desktop".into()],
            aliases: vec!["typora".into(), "markdown编辑器".into()],
            category: "office_notes_doc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["typora".into()],
            supported_actions: vec![SemanticAppAction {
                action: "new_document".into(),
                aliases: vec!["新建markdown".into(), "新建文档".into()],
                channel: AdaptationChannel::CliWrapper,
                summary: "启动 Typora 打开或新建 Markdown 笔记".into(),
                target_template: Some("typora {path}".into()),
                requires_approval: false,
                reversible: false,
            }],
            source: "builtin".into(),
            notes: "支持打开指定 Markdown 文件或目录".into(),
        },
        // 45. xCHM Viewer
        AppAdapterProfile {
            id: "xchm".into(),
            name: "xCHM 帮助文档阅读器".into(),
            desktop_ids: vec!["xchm.desktop".into()],
            aliases: vec!["xchm".into(), "chm阅读器".into()],
            category: "office_notes_doc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["xchm".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "CHM 电子书与离线技术手册阅读器适配".into(),
        },
        // 46. LocalSend (局域网互传)
        AppAdapterProfile {
            id: "localsend".into(),
            name: "LocalSend 局域网互传".into(),
            desktop_ids: vec![
                "localsend_app.desktop".into(),
                "org.localsend.localsend_app.desktop".into(),
            ],
            aliases: vec!["localsend".into(), "localsend_app".into(), "局域网互传".into(), "快传".into()],
            category: "cloud_transfer".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::SniDbusMenu, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["localsend_app".into(), "localsend".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "send_file".into(),
                    aliases: vec!["发送文件".into(), "局域网传文件".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `localsend_app <file_path>` 直接调起局域网文件投送".into(),
                    target_template: Some("localsend_app {path}".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "wake_receiver".into(),
                    aliases: vec!["唤醒接收端".into(), "打开接收端".into()],
                    channel: AdaptationChannel::SniDbusMenu,
                    summary: "唤醒 LocalSend 局域网接收窗口".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "支持单文件快速投送与系统托盘接收端唤醒".into(),
        },
        // 47. Nextcloud Desktop Sync
        AppAdapterProfile {
            id: "nextcloud".into(),
            name: "Nextcloud 私有云同步".into(),
            desktop_ids: vec!["com.nextcloud.desktopclient.nextcloud.desktop".into(), "nextcloud.desktop".into()],
            aliases: vec!["nextcloud".into(), "私有云同步".into()],
            category: "cloud_transfer".into(),
            channels: vec![AdaptationChannel::SniDbusMenu, AdaptationChannel::CliWrapper],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["nextcloud".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持系统托盘同步状态查看与唤醒".into(),
        },
        // 48. Tailscale Mesh VPN
        AppAdapterProfile {
            id: "tailscale".into(),
            name: "Tailscale 异地组网".into(),
            desktop_ids: vec!["tailscale.desktop".into()],
            aliases: vec!["tailscale".into(), "异地组网".into(), "内网穿透".into()],
            category: "network_browser".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["tailscale".into()],
            supported_actions: vec![SemanticAppAction {
                action: "tailscale_status".into(),
                aliases: vec!["组网状态".into(), "tailscale状态".into()],
                channel: AdaptationChannel::CliWrapper,
                summary: "执行 `tailscale status --json` 查询本机虚拟组网 IP 与在线节点数".into(),
                target_template: Some("tailscale status --json".into()),
                requires_approval: false,
                reversible: false,
            }],
            source: "builtin".into(),
            notes: "支持 CLI JSON 实时节点状态读取，无 CLI 时优雅回退打开管理台".into(),
        },
        // 49. NetworkManager Connection Editor
        AppAdapterProfile {
            id: "nm-connection-editor".into(),
            name: "高级网络连接配置 (NetworkManager)".into(),
            desktop_ids: vec!["nm-connection-editor.desktop".into()],
            aliases: vec!["nm-connection-editor".into(), "高级网络配置".into(), "网卡配置".into()],
            category: "network_browser".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["nm-connection-editor".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "Ubuntu 高级有线/Wi-Fi/VLAN/VPN 连接编辑器".into(),
        },
        // 50. Clash Verge Rev
        AppAdapterProfile {
            id: "clash-verge".into(),
            name: "Clash Verge 网络代理".into(),
            desktop_ids: vec!["clash-verge.desktop".into()],
            aliases: vec!["clash-verge".into(), "clash verge".into()],
            category: "network_browser".into(),
            channels: vec![AdaptationChannel::SniDbusMenu, AdaptationChannel::CliWrapper, AdaptationChannel::UriScheme],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["clash-verge".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "probe_proxy_status".into(),
                    aliases: vec!["探测代理状态".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "探测本地代理端口与运行状态".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "wake_dashboard".into(),
                    aliases: vec!["打开代理面板".into()],
                    channel: AdaptationChannel::SniDbusMenu,
                    summary: "唤醒 Clash Verge 主窗口".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "支持托盘控制与本地代理端口探针".into(),
        },
        // 51. Trae CN AI IDE
        AppAdapterProfile {
            id: "trae-cn".into(),
            name: "Trae CN AI 编程 IDE".into(),
            desktop_ids: vec!["trae-cn.desktop".into()],
            aliases: vec!["trae".into(), "trae-cn".into(), "trae cn".into()],
            category: "dev_ai_ide".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::UriScheme, AdaptationChannel::DesktopAction],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["trae-cn".into(), "trae".into()],
            cli_executables: vec!["trae-cn".into()],
            supported_actions: {
                let mut acts = ide_standard_actions("trae-cn", "trae-cn");
                acts.push(SemanticAppAction {
                    action: "goto_file_line".into(),
                    aliases: vec!["跳转文件行".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `trae-cn --goto <file>:<line>:<col>` 精确打开源码行".into(),
                    target_template: Some("trae-cn --goto {path}:{line}:{column}".into()),
                    requires_approval: false,
                    reversible: false,
                });
                acts.push(SemanticAppAction {
                    action: "diff_two_files".into(),
                    aliases: vec!["对比两个文件".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `trae-cn --diff <left> <right>` 可视化对比双文件".into(),
                    target_template: Some("trae-cn --diff {left} {right}".into()),
                    requires_approval: false,
                    reversible: false,
                });
                acts
            },
            source: "builtin".into(),
            notes: "支持打开工程、源码行列跳转、双文件对比与 trae-cn:// 协议".into(),
        },
        // 52. Antigravity IDE
        AppAdapterProfile {
            id: "antigravity-ide".into(),
            name: "Google Antigravity IDE".into(),
            desktop_ids: vec!["antigravity-ide.desktop".into(), "antigravity-app.desktop".into(), "antigravity.desktop".into()],
            aliases: vec!["antigravity".into(), "antigravity-ide".into(), "agy".into()],
            category: "dev_ai_ide".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::UriScheme, AdaptationChannel::DesktopAction],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["antigravity".into()],
            cli_executables: vec!["agy".into(), "antigravity".into()],
            supported_actions: ide_standard_actions("antigravity", "agy"),
            source: "builtin".into(),
            notes: "支持工程打开、`--goto` 行号定位与 `--diff` 文件对比".into(),
        },
        // 53. WorkBuddy AI IDE
        AppAdapterProfile {
            id: "workbuddy".into(),
            name: "WorkBuddy 智能开发助手".into(),
            desktop_ids: vec!["workbuddy.desktop".into()],
            aliases: vec!["workbuddy".into()],
            category: "dev_ai_ide".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::UriScheme, AdaptationChannel::DesktopAction],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["workbuddy".into()],
            cli_executables: vec!["workbuddy".into()],
            supported_actions: ide_standard_actions("workbuddy", "workbuddy"),
            source: "builtin".into(),
            notes: "支持工程打开、行列跳转与双文件对比".into(),
        },
        // 54. ChatGPT Desktop / PWA
        AppAdapterProfile {
            id: "chatgpt".into(),
            name: "ChatGPT 桌面助手".into(),
            desktop_ids: vec!["chatgpt.desktop".into()],
            aliases: vec!["chatgpt".into()],
            category: "dev_ai_ide".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["chatgpt".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持 ChatGPT 桌面端启动与窗口聚焦".into(),
        },
        // 55. Android Studio
        AppAdapterProfile {
            id: "android-studio".into(),
            name: "Android Studio".into(),
            desktop_ids: vec!["android-studio.desktop".into(), "jetbrains-studio.desktop".into()],
            aliases: vec!["android-studio".into(), "android studio".into(), "安卓开发".into()],
            category: "dev_ai_ide".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["studio.sh".into(), "android-studio".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持打开 Android 工程目录与窗口焦点切换".into(),
        },
        // 56. Hopper Disassembler
        AppAdapterProfile {
            id: "hopper".into(),
            name: "Hopper Disassembler 逆向反汇编器".into(),
            desktop_ids: vec!["crypticapps-com.hopperapp.Hopper.desktop".into(), "hopper.desktop".into()],
            aliases: vec!["hopper".into(), "逆向分析".into(), "反汇编".into()],
            category: "dev_ai_ide".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["Hopper".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持受控打开二进制分析样本与窗口聚焦".into(),
        },
        // 57. GNOME Ptyxis / Terminal
        AppAdapterProfile {
            id: "gnome-ptyxis".into(),
            name: "GNOME 终端 (Ptyxis / Terminal)".into(),
            desktop_ids: vec!["org.gnome.Ptyxis.desktop".into(), "org.gnome.Terminal.desktop".into()],
            aliases: vec!["ptyxis".into(), "gnome-terminal".into(), "终端".into()],
            category: "dev_ai_ide".into(),
            channels: vec![AdaptationChannel::DesktopAction, AdaptationChannel::CliWrapper, AdaptationChannel::DbusFreedesktop],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.gnome.Ptyxis".into()),
            uri_schemes: vec![],
            cli_executables: vec!["ptyxis".into(), "gnome-terminal".into()],
            supported_actions: vec![SemanticAppAction {
                action: "new_window".into(),
                aliases: vec!["新建终端窗口".into()],
                channel: AdaptationChannel::DesktopAction,
                summary: "打开新终端窗口".into(),
                target_template: Some("new-window".into()),
                requires_approval: false,
                reversible: false,
            }],
            source: "builtin".into(),
            notes: "支持 .desktop 新建终端窗口与 D-Bus 激活".into(),
        },
        // 58. Darktable RAW Photography
        AppAdapterProfile {
            id: "darktable".into(),
            name: "Darktable 数字暗房".into(),
            desktop_ids: vec!["org.darktable.darktable.desktop".into(), "darktable.desktop".into()],
            aliases: vec!["darktable".into(), "raw修图".into(), "数字暗房".into()],
            category: "creative_disc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["darktable".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "专业摄影 RAW 处理工作流软件适配".into(),
        },
        // 59. HydraPaper Multi-Monitor Wallpaper
        AppAdapterProfile {
            id: "hydrapaper".into(),
            name: "HydraPaper 多屏壁纸管理".into(),
            desktop_ids: vec!["org.gabmus.hydrapaper.desktop".into()],
            aliases: vec!["hydrapaper".into(), "多屏壁纸".into()],
            category: "creative_disc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::DbusFreedesktop],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.gabmus.hydrapaper".into()),
            uri_schemes: vec![],
            cli_executables: vec!["hydrapaper".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "多显示器独立壁纸管理工具适配".into(),
        },
        // 60. Brasero / Xfburn Disc Burner
        AppAdapterProfile {
            id: "brasero".into(),
            name: "Brasero / Xfburn 光盘刻录工具".into(),
            desktop_ids: vec![
                "brasero.desktop".into(),
                "brasero-fixed.desktop".into(),
                "xfburn.desktop".into(),
                "xfburn-audio.desktop".into(),
            ],
            aliases: vec!["brasero".into(), "xfburn".into(), "刻录镜像".into()],
            category: "creative_disc".into(),
            channels: vec![AdaptationChannel::DesktopAction, AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["brasero".into(), "xfburn".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持 ISO 镜像与音频光盘刻录入口".into(),
        },
        // 61. GNOME Loupe Image Viewer
        AppAdapterProfile {
            id: "gnome-loupe".into(),
            name: "GNOME 图像查看器 (Loupe)".into(),
            desktop_ids: vec!["org.gnome.Loupe.desktop".into()],
            aliases: vec!["loupe".into(), "看图".into(), "图片查看器".into()],
            category: "creative_disc".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::DbusFreedesktop],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.gnome.Loupe".into()),
            uri_schemes: vec![],
            cli_executables: vec!["loupe".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "Ubuntu 默认现代图片查看器适配".into(),
        },
        // 62. RustDesk Remote Desktop
        AppAdapterProfile {
            id: "rustdesk".into(),
            name: "RustDesk 远程桌面".into(),
            desktop_ids: vec!["rustdesk.desktop".into()],
            aliases: vec!["rustdesk".into(), "远程桌面".into(), "远控".into()],
            category: "remote_vm".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::SniDbusMenu, AdaptationChannel::UriScheme, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec!["rustdesk".into()],
            cli_executables: vec!["rustdesk".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "get_device_id".into(),
                    aliases: vec!["获取设备号".into(), "本机远控码".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `rustdesk --get-id` 读取本机远程控制设备 ID".into(),
                    target_template: Some("rustdesk --get-id".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "connect_peer".into(),
                    aliases: vec!["连接远程桌面".into(), "发起远控".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `rustdesk --connect <peer_id>` 发起外部远程桌面连接（需显式审批）".into(),
                    target_template: Some("rustdesk --connect {peer_id}".into()),
                    requires_approval: true,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "wake_main_window".into(),
                    aliases: vec!["唤醒窗口".into()],
                    channel: AdaptationChannel::SniDbusMenu,
                    summary: "唤醒 RustDesk 主界面".into(),
                    target_template: None,
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "只读读取设备 ID 免批直通；对外发起远控连接严格执行用户审批门禁".into(),
        },
        // 63. Oracle VirtualBox
        AppAdapterProfile {
            id: "virtualbox".into(),
            name: "Oracle VirtualBox 虚拟机管理器".into(),
            desktop_ids: vec!["virtualbox.desktop".into(), "org.virtualbox.VirtualBox.desktop".into()],
            aliases: vec!["virtualbox".into(), "vbox".into(), "虚拟机".into()],
            category: "remote_vm".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["VBoxManage".into(), "virtualbox".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "list_vms".into(),
                    aliases: vec!["列出虚拟机".into(), "虚拟机列表".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "执行 `VBoxManage list vms` 与 `list runningvms` 获取全部虚拟机及运行状态".into(),
                    target_template: Some("VBoxManage list vms".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "start_vm".into(),
                    aliases: vec!["启动虚拟机".into(), "开机虚拟机".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "执行 `VBoxManage startvm <vm> --type gui` 启动虚拟机（需显式审批）".into(),
                    target_template: Some("VBoxManage startvm {vm} --type gui".into()),
                    requires_approval: true,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "savestate_vm".into(),
                    aliases: vec!["挂起虚拟机".into(), "保存虚拟机状态".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "执行 `VBoxManage controlvm <vm> savestate` 保存状态休眠（需显式审批）".into(),
                    target_template: Some("VBoxManage controlvm {vm} savestate".into()),
                    requires_approval: true,
                    reversible: true,
                },
            ],
            source: "builtin".into(),
            notes: "封装 VBoxManage 虚拟机枚举与受审批启停生命周期控制".into(),
        },
        // 64. Fcitx5 Input Method Framework
        AppAdapterProfile {
            id: "fcitx5".into(),
            name: "Fcitx5 中文输入法引擎".into(),
            desktop_ids: vec![
                "org.fcitx.Fcitx5.desktop".into(),
                "fcitx5-configtool.desktop".into(),
                "org.fcitx.fcitx5-config-qt.desktop".into(),
            ],
            aliases: vec!["fcitx5".into(), "输入法".into(), "中文输入法".into(), "fcitx".into()],
            category: "hardware_system".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::SniDbusMenu],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.fcitx.Fcitx5".into()),
            uri_schemes: vec![],
            cli_executables: vec!["fcitx5-remote".into(), "fcitx5-configtool".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "input_method_status".into(),
                    aliases: vec!["输入法状态".into(), "查询输入法".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `fcitx5-remote` 查询当前中英文输入激活状态".into(),
                    target_template: Some("fcitx5-remote".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "activate_chinese".into(),
                    aliases: vec!["切换中文输入法".into(), "开启中文输入".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `fcitx5-remote -o` 激活中文输入法".into(),
                    target_template: Some("fcitx5-remote -o".into()),
                    requires_approval: false,
                    reversible: true,
                },
                SemanticAppAction {
                    action: "deactivate_chinese".into(),
                    aliases: vec!["切换英文输入法".into(), "关闭中文输入".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `fcitx5-remote -c` 切回英文键盘状态".into(),
                    target_template: Some("fcitx5-remote -c".into()),
                    requires_approval: false,
                    reversible: true,
                },
                SemanticAppAction {
                    action: "open_fcitx_config".into(),
                    aliases: vec!["输入法设置".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "打开 Fcitx5 输入法配置工具 (`fcitx5-configtool`)".into(),
                    target_template: Some("fcitx5-configtool".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "通过 fcitx5-remote 实现零延迟中英文输入状态查询与切换".into(),
        },
        // 65. NVIDIA GPU Settings & Telemetry
        AppAdapterProfile {
            id: "nvidia-settings".into(),
            name: "NVIDIA 显卡设置与遥测中心".into(),
            desktop_ids: vec!["nvidia-settings.desktop".into()],
            aliases: vec!["nvidia-settings".into(), "nvidia".into(), "显卡设置".into(), "gpu".into()],
            category: "hardware_system".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["nvidia-smi".into(), "nvidia-settings".into()],
            supported_actions: vec![
                SemanticAppAction {
                    action: "query_gpu_telemetry".into(),
                    aliases: vec!["显卡状态".into(), "gpu状态".into(), "查询显存温度".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "通过 `nvidia-smi --query-gpu=...` 实时读取 GPU 型号、温度、利用率与显存占用".into(),
                    target_template: Some("nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits".into()),
                    requires_approval: false,
                    reversible: false,
                },
                SemanticAppAction {
                    action: "open_nvidia_settings".into(),
                    aliases: vec!["打开显卡设置".into()],
                    channel: AdaptationChannel::CliWrapper,
                    summary: "启动 NVIDIA X Server Settings 图形控制面板".into(),
                    target_template: Some("nvidia-settings".into()),
                    requires_approval: false,
                    reversible: false,
                },
            ],
            source: "builtin".into(),
            notes: "集成 nvidia-smi 无头 CSV GPU 遥测与显卡面板启动".into(),
        },
        // 66. Omni Mouse Studio (多功能鼠标智控中心)
        AppAdapterProfile {
            id: "omni-mouse-studio".into(),
            name: "Omni Mouse 多功能鼠标智控中心".into(),
            desktop_ids: vec!["omni-mouse-studio.desktop".into()],
            aliases: vec!["omni-mouse-studio".into(), "omnimouse".into(), "鼠标智控中心".into(), "多功能鼠标".into()],
            category: "hardware_system".into(),
            channels: vec![AdaptationChannel::SniDbusMenu, AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["omni-mouse-studio".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "硬件外设鼠标宏与侧键智控中心适配".into(),
        },
        // 67. WowType Voice Input Config
        AppAdapterProfile {
            id: "wowtype".into(),
            name: "WowType 语音输入配置".into(),
            desktop_ids: vec!["io.github.Gloridust.WowType.Config.desktop".into()],
            aliases: vec!["wowtype".into(), "wowtype-config".into(), "语音输入配置".into()],
            category: "hardware_system".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: None,
            uri_schemes: vec![],
            cli_executables: vec!["wowtype-config".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "支持打开 WowType 语音识别快捷键与词库配置窗口".into(),
        },
        // 68. Nokyan Resources System Monitor
        AppAdapterProfile {
            id: "nokyan-resources".into(),
            name: "Resources 系统资源监控".into(),
            desktop_ids: vec!["net.nokyan.Resources.desktop".into()],
            aliases: vec!["resources".into(), "系统监控".into(), "任务管理器".into()],
            category: "hardware_system".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::DbusFreedesktop, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: Some("net.nokyan.Resources".into()),
            uri_schemes: vec![],
            cli_executables: vec!["resources".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "现代 GTK4 CPU/GPU/内存/磁盘监控面板适配".into(),
        },
        // 69. GNOME Disks & Baobab Disk Usage Analyzer
        AppAdapterProfile {
            id: "gnome-disks".into(),
            name: "GNOME 磁盘工具与空间分析 (Disks / Baobab)".into(),
            desktop_ids: vec!["org.gnome.DiskUtility.desktop".into(), "org.gnome.baobab.desktop".into()],
            aliases: vec!["gnome-disks".into(), "baobab".into(), "磁盘工具".into(), "磁盘分析".into()],
            category: "hardware_system".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::DbusFreedesktop, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: Some("org.gnome.DiskUtility".into()),
            uri_schemes: vec![],
            cli_executables: vec!["gnome-disks".into(), "baobab".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "分区管理与磁盘空间占用可视化分析工具适配".into(),
        },
        // 70. Desktop Security Center / Extension Manager / Font Manager
        AppAdapterProfile {
            id: "extension-manager".into(),
            name: "GNOME 扩展管理器 (Extension Manager)".into(),
            desktop_ids: vec!["com.mattjakeman.ExtensionManager.desktop".into()],
            aliases: vec!["extension-manager".into(), "扩展管理".into(), "gnome扩展".into()],
            category: "hardware_system".into(),
            channels: vec![AdaptationChannel::CliWrapper, AdaptationChannel::DbusFreedesktop, AdaptationChannel::GuiAtspi],
            mpris_bus_hints: vec![],
            dbus_name: Some("com.mattjakeman.ExtensionManager".into()),
            uri_schemes: vec![],
            cli_executables: vec!["extension-manager".into()],
            supported_actions: gui_atspi_standard_actions(),
            source: "builtin".into(),
            notes: "GNOME Shell 扩展浏览与开关管理工具适配".into(),
        },
    ]
}
