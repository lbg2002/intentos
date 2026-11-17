#![forbid(unsafe_code)]

//! XDG directory layout, `config.toml` & `brain.toml` configuration (no secrets, no grant semantics in TOML, §5.5, §16.1).

use intentos_protocol::{DataClass, ProviderTrust};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct XdgPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub repo_root: PathBuf,
    pub custom_base: Option<PathBuf>,
}

impl XdgPaths {
    pub fn resolve(custom_base: Option<&Path>, repo_root: PathBuf) -> Self {
        if let Some(base) = custom_base {
            return Self {
                config_dir: base.join("config"),
                data_dir: base.join("data"),
                state_dir: base.join("state"),
                cache_dir: base.join("cache"),
                runtime_dir: base.join("run"),
                repo_root,
                custom_base: Some(base.to_path_buf()),
            };
        }

        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let config_dir = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
            .join("intentos");
        let data_dir = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("intentos");
        let state_dir = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"))
            .join("intentos");
        let cache_dir = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"))
            .join("intentos");
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let uid = nix_uid();
                PathBuf::from(format!("/tmp/intentos-run-{}", uid))
            })
            .join("intentos");

        Self {
            config_dir,
            data_dir,
            state_dir,
            cache_dir,
            runtime_dir,
            repo_root,
            custom_base: None,
        }
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for dir in [
            &self.config_dir,
            &self.data_dir,
            &self.data_dir.join("undo"),
            &self.data_dir.join("skills/user"),
            &self.state_dir.join("logs"),
            &self.cache_dir,
            &self.runtime_dir,
            &self.runtime_dir.join("gateway"),
        ] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn state_db_path(&self) -> PathBuf {
        self.data_dir.join("state.db")
    }

    pub fn index_db_path(&self) -> PathBuf {
        self.cache_dir.join("index.db")
    }

    pub fn ui_socket_path(&self) -> PathBuf {
        self.runtime_dir.join("ui.sock")
    }

    pub fn gateway_socket_dir(&self) -> PathBuf {
        self.runtime_dir.join("gateway")
    }

    pub fn gateway_socket_path(&self) -> PathBuf {
        self.runtime_dir.join("gateway/gateway.sock")
    }

    pub fn builtin_modules_dir(&self) -> PathBuf {
        let repo_builtin = self.repo_root.join("modules/builtin");
        if repo_builtin.exists() {
            return repo_builtin;
        }
        {
            let user = self.data_dir.join("builtin-modules");
            if user.is_dir() { user } else { PathBuf::from("/usr/share/intentos/builtin-modules") }
        }
    }

    pub fn pi_adapter_script(&self) -> PathBuf {
        let repo_script = self.repo_root.join("agent/pi-adapter/dist/worker.js");
        if repo_script.exists() {
            return repo_script;
        }
        {
            let user = self.data_dir.join("pi-adapter/dist/worker.js");
            if user.is_file() { user } else { PathBuf::from("/usr/lib/intentos/intentos-agent/dist/worker.js") }
        }
    }
}

fn nix_uid() -> u32 {
    std::env::var("UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_hotkey")]
    pub hotkey: String,
    #[serde(default)]
    pub authorized_directories: Vec<String>,
    #[serde(default)]
    pub allow_simulated_hardware_fallback: bool,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub undo: UndoConfig,
}

fn default_hotkey() -> String {
    "<Super><Shift>space".to_string()
}

/// Parse `~/.config/user-dirs.dirs` (`XDG_*_DIR`) and discover Chinese/English user directories + `home` itself.
pub fn discover_user_xdg_and_home_dirs(home: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let push_unique = |list: &mut Vec<PathBuf>, p: PathBuf| {
        if !list.iter().any(|existing| existing == &p) {
            list.push(p);
        }
    };

    // 1. Parse `~/.config/user-dirs.dirs`
    let user_dirs_file = home.join(".config/user-dirs.dirs");
    if let Ok(raw) = std::fs::read_to_string(&user_dirs_file) {
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, val_raw)) = trimmed.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if !matches!(
                key,
                "XDG_DESKTOP_DIR"
                    | "XDG_DOCUMENTS_DIR"
                    | "XDG_DOWNLOAD_DIR"
                    | "XDG_PICTURES_DIR"
                    | "XDG_MUSIC_DIR"
                    | "XDG_VIDEOS_DIR"
            ) {
                continue;
            }
            let unquoted = val_raw
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .replace("\\\"", "\"");
            let resolved = if unquoted == "$HOME" || unquoted == "${HOME}" {
                Some(home.to_path_buf())
            } else if let Some(rest) = unquoted
                .strip_prefix("$HOME/")
                .or_else(|| unquoted.strip_prefix("${HOME}/"))
            {
                let clean = rest.trim_matches('/');
                if clean.is_empty() {
                    Some(home.to_path_buf())
                } else {
                    Some(home.join(clean))
                }
            } else if unquoted.starts_with('/') {
                Some(PathBuf::from(unquoted))
            } else {
                None
            };
            if let Some(p) = resolved
                && p != *home
            {
                push_unique(&mut out, p);
            }
        }
    }

    // 2. Include standard Chinese & English user directories
    for sub in [
        "桌面",
        "文档",
        "下载",
        "Desktop",
        "Documents",
        "Downloads",
        "pydoc",
        "code",
        "workspace",
        "intentos",
    ] {
        push_unique(&mut out, home.join(sub));
    }

    // 3. Include `home` itself last so specific XDG/project directories are indexed first,
    //    while granting global NormalUserSpace visibility across the entire user home!
    push_unique(&mut out, home.to_path_buf());
    out
}

fn merge_discovered_user_dirs(app_cfg: &mut AppConfig, home: &Path) -> bool {
    let discovered = discover_user_xdg_and_home_dirs(home);
    let home_str = home.to_string_lossy().to_string();
    let original = app_cfg.authorized_directories.clone();

    // Keep existing non-home directories first so user customizations stay prioritized
    let mut merged: Vec<String> = Vec::new();
    for existing in &app_cfg.authorized_directories {
        if existing != &home_str && !merged.iter().any(|x| x == existing) {
            merged.push(existing.clone());
        }
    }
    for dir in discovered {
        let s = dir.to_string_lossy().to_string();
        if s != home_str && !merged.iter().any(|x| x == &s) {
            merged.push(s);
        }
    }
    if !merged.iter().any(|x| x == &home_str) {
        merged.push(home_str);
    }

    let changed = merged != original;
    if changed {
        app_cfg.authorized_directories = merged;
    }
    changed
}

impl Default for AppConfig {
    fn default() -> Self {
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/home/user".into()));
        let dirs = discover_user_xdg_and_home_dirs(&home)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        Self {
            hotkey: default_hotkey(),
            authorized_directories: dirs,
            allow_simulated_hardware_fallback: true,
            web: WebConfig::default(),
            undo: UndoConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoConfig {
    #[serde(default = "default_quota_gb")]
    pub quota_gb: u64,
    #[serde(default = "default_retention_days")]
    pub retention_days: i64,
}

fn default_quota_gb() -> u64 {
    4
}
fn default_retention_days() -> i64 {
    30
}

impl Default for UndoConfig {
    fn default() -> Self {
        Self {
            quota_gb: 4,
            retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteEntry {
    pub id: String,
    pub names: Vec<String>,
    pub url: String,
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEngineEntry {
    pub id: String,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    /// Default search engine is Google (D21, §4.7).
    #[serde(default = "default_google")]
    pub default_search: String,
    #[serde(default = "default_browser")]
    pub open_with: String,
    #[serde(default = "builtin_search_engines")]
    pub search_engines: Vec<SearchEngineEntry>,
    #[serde(default = "builtin_sites")]
    pub sites: Vec<SiteEntry>,
}

fn default_google() -> String {
    "google".to_string()
}
fn default_browser() -> String {
    "default".to_string()
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            default_search: default_google(),
            open_with: default_browser(),
            search_engines: builtin_search_engines(),
            sites: builtin_sites(),
        }
    }
}

pub fn builtin_search_engines() -> Vec<SearchEngineEntry> {
    vec![
        SearchEngineEntry {
            id: "google".into(),
            name: "Google".into(),
            url: "https://www.google.com/search?q={query}".into(),
        },
        SearchEngineEntry {
            id: "bing".into(),
            name: "Bing".into(),
            url: "https://www.bing.com/search?q={query}".into(),
        },
        SearchEngineEntry {
            id: "baidu".into(),
            name: "百度".into(),
            url: "https://www.baidu.com/s?wd={query}".into(),
        },
        SearchEngineEntry {
            id: "duckduckgo".into(),
            name: "DuckDuckGo".into(),
            url: "https://duckduckgo.com/?q={query}".into(),
        },
    ]
}

pub fn builtin_sites() -> Vec<SiteEntry> {
    vec![
        SiteEntry {
            id: "github".into(),
            names: vec![
                "GitHub".into(),
                "github".into(),
                "gh".into(),
                "吉特哈布".into(),
            ],
            url: "https://github.com".into(),
            search: Some("https://github.com/search?q={query}".into()),
        },
        SiteEntry {
            id: "bilibili".into(),
            names: vec![
                "哔哩哔哩".into(),
                "B站".into(),
                "b站".into(),
                "bili".into(),
                "bilibili".into(),
            ],
            url: "https://www.bilibili.com".into(),
            search: Some("https://search.bilibili.com/all?keyword={query}".into()),
        },
        SiteEntry {
            id: "zhihu".into(),
            names: vec!["知乎".into(), "zhihu".into(), "zh".into()],
            url: "https://www.zhihu.com".into(),
            search: Some("https://www.zhihu.com/search?type=content&q={query}".into()),
        },
        SiteEntry {
            id: "stackoverflow".into(),
            names: vec!["Stack Overflow".into(), "stackoverflow".into(), "so".into()],
            url: "https://stackoverflow.com".into(),
            search: Some("https://stackoverflow.com/search?q={query}".into()),
        },
        SiteEntry {
            id: "crates".into(),
            names: vec!["crates.io".into(), "crates".into(), "crate".into()],
            url: "https://crates.io".into(),
            search: Some("https://crates.io/search?q={query}".into()),
        },
        SiteEntry {
            id: "docsrs".into(),
            names: vec!["docs.rs".into(), "docsrs".into(), "rustdocs".into()],
            url: "https://docs.rs".into(),
            search: Some("https://docs.rs/releases/search?query={query}".into()),
        },
        SiteEntry {
            id: "mdn".into(),
            names: vec!["MDN".into(), "mdn".into()],
            url: "https://developer.mozilla.org".into(),
            search: Some("https://developer.mozilla.org/search?q={query}".into()),
        },
        SiteEntry {
            id: "npm".into(),
            names: vec!["npm".into(), "npmjs".into()],
            url: "https://www.npmjs.com".into(),
            search: Some("https://www.npmjs.com/search?q={query}".into()),
        },
        SiteEntry {
            id: "arxiv".into(),
            names: vec!["arXiv".into(), "arxiv".into()],
            url: "https://arxiv.org".into(),
            search: Some("https://arxiv.org/search/?query={query}&searchtype=all".into()),
        },
        SiteEntry {
            id: "hackernews".into(),
            names: vec!["Hacker News".into(), "hn".into(), "hackernews".into()],
            url: "https://news.ycombinator.com".into(),
            search: Some("https://hn.algolia.com/?q={query}".into()),
        },
    ]
}

/// Brain Center & Model Gateway configuration (`brain.toml`, §5.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrainConfig {
    #[serde(default = "default_runtime_name")]
    pub runtime: String,
    #[serde(default = "default_main_profile")]
    pub default_profile: String,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default)]
    pub runtime_limits: RuntimeLimits,
}

fn default_runtime_name() -> String {
    "pi".to_string()
}
fn default_main_profile() -> String {
    "main".to_string()
}

impl Default for BrainConfig {
    fn default() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "main".to_string(),
            ProfileConfig {
                provider: "default-openai".to_string(),
                model: std::env::var("INTENTOS_MODEL")
                    .unwrap_or_else(|_| "gpt-4o-mini".to_string()),
                context_budget: 65536,
                max_output_tokens: 4096,
            },
        );
        Self {
            runtime: default_runtime_name(),
            default_profile: default_main_profile(),
            providers: vec![ProviderConfig {
                id: "default-openai".to_string(),
                kind: "openai-compatible".to_string(),
                base_url: std::env::var("OPENAI_BASE_URL")
                    .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
                credential_ref: "secret-service://intentos/default-openai".to_string(),
                trust: ProviderTrust::Standard,
                enabled: true,
            }],
            profiles,
            runtime_limits: RuntimeLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub id: String,
    pub kind: String,
    pub base_url: String,
    pub credential_ref: String,
    #[serde(default)]
    pub trust: ProviderTrust,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub provider: String,
    pub model: String,
    #[serde(default = "default_ctx_budget")]
    pub context_budget: usize,
    #[serde(default = "default_max_out")]
    pub max_output_tokens: usize,
}

fn default_ctx_budget() -> usize {
    65536
}
fn default_max_out() -> usize {
    4096
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeLimits {
    #[serde(default = "default_max_tools")]
    pub max_tool_calls: u32,
    #[serde(default = "default_max_secs")]
    pub max_runtime_seconds: u64,
    #[serde(default = "default_max_sessions")]
    pub max_concurrent_sessions: usize,
    #[serde(default = "default_idle_mins")]
    pub session_idle_timeout_minutes: u64,
    #[serde(default)]
    pub daily_cost_limit: f64,
}

fn default_max_tools() -> u32 {
    30
}
fn default_max_secs() -> u64 {
    180
}
fn default_max_sessions() -> usize {
    2
}
fn default_idle_mins() -> u64 {
    60
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_tool_calls: 30,
            max_runtime_seconds: 180,
            max_concurrent_sessions: 2,
            session_idle_timeout_minutes: 60,
            daily_cost_limit: 0.0,
        }
    }
}

/// Evaluate Egress Matrix (`DataClass × ProviderTrust`, §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressVerdict {
    Allow,
    RequireConfirmation,
    Deny,
}

pub fn check_egress_matrix(data_class: DataClass, trust: ProviderTrust) -> EgressVerdict {
    match (trust, data_class) {
        (_, DataClass::Forbidden) => EgressVerdict::Deny,
        (ProviderTrust::Trusted, DataClass::Public | DataClass::Personal) => EgressVerdict::Allow,
        (ProviderTrust::Trusted, DataClass::Sensitive) => EgressVerdict::RequireConfirmation,
        (ProviderTrust::Standard, DataClass::Public | DataClass::Personal) => EgressVerdict::Allow,
        (ProviderTrust::Standard, DataClass::Sensitive) => EgressVerdict::Deny,
        (ProviderTrust::Untrusted, DataClass::Public) => EgressVerdict::Allow,
        (ProviderTrust::Untrusted, DataClass::Personal) => EgressVerdict::RequireConfirmation,
        (ProviderTrust::Untrusted, DataClass::Sensitive) => EgressVerdict::Deny,
    }
}

pub fn load_or_create_configs(paths: &XdgPaths) -> anyhow::Result<(AppConfig, BrainConfig)> {
    paths.ensure_dirs()?;
    let app_cfg_path = paths.config_dir.join("config.toml");
    let app_cfg = if let Some(ref base) = paths.custom_base {
        // Hermetic custom_base mode (unit/E2E tests): NEVER pollute authorized_directories with real $HOME!
        if app_cfg_path.exists() {
            let raw = std::fs::read_to_string(&app_cfg_path)?;
            toml::from_str(&raw)?
        } else {
            let hermetic_dirs = ["Downloads", "Documents", "Desktop", "workspace"]
                .into_iter()
                .map(|sub| base.join(sub).to_string_lossy().to_string())
                .collect();
            let cfg = AppConfig {
                authorized_directories: hermetic_dirs,
                ..AppConfig::default()
            };
            std::fs::write(&app_cfg_path, toml::to_string_pretty(&cfg)?)?;
            cfg
        }
    } else {
        // Real user mode: merge XDG user-dirs + Chinese/English dirs + $HOME even if an older config.toml existed!
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        if app_cfg_path.exists() {
            let raw = std::fs::read_to_string(&app_cfg_path)?;
            let mut cfg: AppConfig = toml::from_str(&raw)?;
            if merge_discovered_user_dirs(&mut cfg, &home)
                && let Ok(serialized) = toml::to_string_pretty(&cfg)
            {
                let _ = std::fs::write(&app_cfg_path, serialized);
            }
            cfg
        } else {
            let mut cfg = AppConfig::default();
            merge_discovered_user_dirs(&mut cfg, &home);
            std::fs::write(&app_cfg_path, toml::to_string_pretty(&cfg)?)?;
            cfg
        }
    };

    let brain_cfg_path = paths.config_dir.join("brain.toml");
    let brain_cfg = if brain_cfg_path.exists() {
        let raw = std::fs::read_to_string(&brain_cfg_path)?;
        toml::from_str(&raw)?
    } else {
        let cfg = BrainConfig::default();
        std::fs::write(&brain_cfg_path, toml::to_string_pretty(&cfg)?)?;
        cfg
    };

    Ok((app_cfg, brain_cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn discover_xdg_user_dirs_parses_chinese_locale_and_preserves_hermetic_custom_base() {
        let tmp = TempDir::new().unwrap();
        let mock_home = tmp.path().join("mock_home");
        std::fs::create_dir_all(mock_home.join(".config")).unwrap();
        std::fs::write(
            mock_home.join(".config/user-dirs.dirs"),
            r#"# Written by xdg-user-dirs-update
XDG_DESKTOP_DIR="$HOME/桌面"
XDG_DOWNLOAD_DIR="$HOME/下载"
XDG_DOCUMENTS_DIR="$HOME/文档"
XDG_MUSIC_DIR="$HOME/音乐"
XDG_PICTURES_DIR="$HOME/图片"
XDG_VIDEOS_DIR="$HOME/视频"
"#,
        )
        .unwrap();

        let discovered = discover_user_xdg_and_home_dirs(&mock_home);
        assert!(discovered.contains(&mock_home.join("桌面")));
        assert!(discovered.contains(&mock_home.join("文档")));
        assert!(discovered.contains(&mock_home.join("下载")));
        assert!(discovered.contains(&mock_home.join("图片")));
        assert!(discovered.contains(&mock_home.join("音乐")));
        assert!(discovered.contains(&mock_home.join("视频")));
        assert!(discovered.contains(&mock_home.join("pydoc")));
        assert_eq!(discovered.last(), Some(&mock_home));

        // Merge into an older English-only config upgrades it with Chinese XDG dirs + home!
        let mut legacy_cfg = AppConfig {
            hotkey: default_hotkey(),
            authorized_directories: vec![
                mock_home.join("Downloads").to_string_lossy().to_string(),
                mock_home.join("Documents").to_string_lossy().to_string(),
            ],
            allow_simulated_hardware_fallback: true,
            web: WebConfig::default(),
            undo: UndoConfig::default(),
        };
        assert!(merge_discovered_user_dirs(&mut legacy_cfg, &mock_home));
        assert!(
            legacy_cfg
                .authorized_directories
                .contains(&mock_home.join("桌面").to_string_lossy().to_string())
        );
        assert_eq!(
            legacy_cfg.authorized_directories.last().map(String::as_str),
            Some(mock_home.to_string_lossy().as_ref())
        );

        // Hermetic custom_base mode MUST NOT leak real $HOME into test authorized_directories
        let isolated = TempDir::new().unwrap();
        let paths = XdgPaths::resolve(Some(isolated.path()), PathBuf::from("."));
        let (hermetic_cfg, _) = load_or_create_configs(&paths).unwrap();
        for dir in &hermetic_cfg.authorized_directories {
            assert!(
                Path::new(dir).starts_with(isolated.path()),
                "hermetic config leaked non-isolated path: {}",
                dir
            );
        }
    }
}
