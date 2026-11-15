#![forbid(unsafe_code)]

//! Configurable `DataClass × ProviderTrust` Egress Matrix, Sensitive Directories CRUD,
//! and Forbidden Path Rules Inspector (§5.4, B-10).
//!
//! Security Invariant: `DataClass::Forbidden` is ALWAYS locked to `"deny"` across all
//! provider trust levels (`trusted`, `standard`, `untrusted`) and can never be relaxed.

use intentos_protocol::{DataClass, ProviderTrust};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

/// Policy decision for a `(ProviderTrust, DataClass)` cell in the egress matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressPolicy {
    Allow,
    Confirm,
    Deny,
}

impl EgressPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Confirm => "confirm",
            Self::Deny => "deny",
        }
    }

    pub fn parse_str(raw: &str) -> anyhow::Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "confirm" | "require_confirmation" | "ask" => Ok(Self::Confirm),
            "deny" | "block" => Ok(Self::Deny),
            other => anyhow::bail!(
                "无效的外发策略值 '{}': 仅允许 allow / confirm / deny",
                other
            ),
        }
    }
}

/// Egress policy row for a single `ProviderTrust` tier across all 4 `DataClass` levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEgressRow {
    pub public: EgressPolicy,
    pub personal: EgressPolicy,
    pub sensitive: EgressPolicy,
    pub forbidden: EgressPolicy,
}

impl TrustEgressRow {
    pub fn enforce_forbidden_deny(&mut self) -> bool {
        if self.forbidden != EgressPolicy::Deny {
            self.forbidden = EgressPolicy::Deny;
            true
        } else {
            false
        }
    }

    pub fn get(&self, dc: DataClass) -> EgressPolicy {
        match dc {
            DataClass::Public => self.public,
            DataClass::Personal => self.personal,
            DataClass::Sensitive => self.sensitive,
            DataClass::Forbidden => EgressPolicy::Deny,
        }
    }
}

/// Complete `DataClass × ProviderTrust` Egress Matrix (§5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressMatrixConfig {
    pub trusted: TrustEgressRow,
    pub standard: TrustEgressRow,
    pub untrusted: TrustEgressRow,
}

impl Default for EgressMatrixConfig {
    fn default() -> Self {
        Self {
            trusted: TrustEgressRow {
                public: EgressPolicy::Allow,
                personal: EgressPolicy::Allow,
                sensitive: EgressPolicy::Confirm,
                forbidden: EgressPolicy::Deny,
            },
            standard: TrustEgressRow {
                public: EgressPolicy::Allow,
                personal: EgressPolicy::Allow,
                sensitive: EgressPolicy::Deny,
                forbidden: EgressPolicy::Deny,
            },
            untrusted: TrustEgressRow {
                public: EgressPolicy::Allow,
                personal: EgressPolicy::Confirm,
                sensitive: EgressPolicy::Deny,
                forbidden: EgressPolicy::Deny,
            },
        }
    }
}

impl EgressMatrixConfig {
    /// Enforce the security invariant that `forbidden` is always `deny`.
    /// Returns `true` if any `forbidden` cell was overridden back to `deny`.
    pub fn enforce_invariants(&mut self) -> bool {
        let a = self.trusted.enforce_forbidden_deny();
        let b = self.standard.enforce_forbidden_deny();
        let c = self.untrusted.enforce_forbidden_deny();
        a || b || c
    }

    /// Evaluate `(DataClass, ProviderTrust)` against the configured matrix,
    /// guaranteeing `DataClass::Forbidden` always yields `EgressPolicy::Deny`.
    pub fn evaluate(&self, data_class: DataClass, trust: ProviderTrust) -> EgressPolicy {
        if data_class == DataClass::Forbidden {
            return EgressPolicy::Deny;
        }
        match trust {
            ProviderTrust::Trusted => self.trusted.get(data_class),
            ProviderTrust::Standard => self.standard.get(data_class),
            ProviderTrust::Untrusted => self.untrusted.get(data_class),
        }
    }

    /// Strict validation that errors if the caller explicitly tried to relax `forbidden`
    /// when `reject_forbidden_relaxation` is true, and always locks `forbidden` to `deny`.
    pub fn apply_patch(
        &mut self,
        patch: &Value,
        strict_reject_forbidden: bool,
    ) -> anyhow::Result<bool> {
        let mut had_forbidden_violation = false;

        for (tier_name, row_ref) in [
            ("trusted", &mut self.trusted),
            ("standard", &mut self.standard),
            ("untrusted", &mut self.untrusted),
        ] {
            if let Some(tier_obj) = patch.get(tier_name).and_then(|v| v.as_object()) {
                if let Some(v) = tier_obj.get("public").and_then(|v| v.as_str()) {
                    row_ref.public = EgressPolicy::parse_str(v)?;
                }
                if let Some(v) = tier_obj.get("personal").and_then(|v| v.as_str()) {
                    row_ref.personal = EgressPolicy::parse_str(v)?;
                }
                if let Some(v) = tier_obj.get("sensitive").and_then(|v| v.as_str()) {
                    row_ref.sensitive = EgressPolicy::parse_str(v)?;
                }
                if let Some(v) = tier_obj.get("forbidden").and_then(|v| v.as_str()) {
                    let parsed = EgressPolicy::parse_str(v)?;
                    if parsed != EgressPolicy::Deny {
                        had_forbidden_violation = true;
                        if strict_reject_forbidden {
                            row_ref.forbidden = EgressPolicy::Deny;
                            anyhow::bail!(
                                "安全策略锁定：forbidden 数据分级在 '{}' 信任等级下必须为 deny，禁止放宽为 {}",
                                tier_name,
                                parsed.as_str()
                            );
                        }
                    }
                    row_ref.forbidden = EgressPolicy::Deny;
                }
            }
        }

        // Orientation B: `matrix[data_class][trust_level]` (used by GTK4 Settings grid)
        for dc_name in ["public", "personal", "sensitive", "forbidden"] {
            if let Some(dc_obj) = patch.get(dc_name).and_then(|v| v.as_object()) {
                for (tier_name, row_ref) in [
                    ("trusted", &mut self.trusted),
                    ("standard", &mut self.standard),
                    ("untrusted", &mut self.untrusted),
                ] {
                    if let Some(v) = dc_obj.get(tier_name).and_then(|v| v.as_str()) {
                        let parsed = EgressPolicy::parse_str(v)?;
                        match dc_name {
                            "public" => row_ref.public = parsed,
                            "personal" => row_ref.personal = parsed,
                            "sensitive" => row_ref.sensitive = parsed,
                            "forbidden" => {
                                if parsed != EgressPolicy::Deny {
                                    had_forbidden_violation = true;
                                    if strict_reject_forbidden {
                                        row_ref.forbidden = EgressPolicy::Deny;
                                        anyhow::bail!(
                                            "安全策略锁定：forbidden 数据分级在 '{}' 信任等级下必须为 deny，禁止放宽为 {}",
                                            tier_name,
                                            parsed.as_str()
                                        );
                                    }
                                }
                                row_ref.forbidden = EgressPolicy::Deny;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Also support flat keys like `"trusted.forbidden": "allow"` if passed
        if let Some(obj) = patch.as_object() {
            for (k, v) in obj {
                if let Some((tier, dc)) = k.split_once('.')
                    && let Some(s) = v.as_str()
                {
                    let parsed = EgressPolicy::parse_str(s)?;
                    let row = match tier {
                        "trusted" => &mut self.trusted,
                        "standard" => &mut self.standard,
                        "untrusted" => &mut self.untrusted,
                        _ => continue,
                    };
                    match dc {
                        "public" => row.public = parsed,
                        "personal" => row.personal = parsed,
                        "sensitive" => row.sensitive = parsed,
                        "forbidden" => {
                            if parsed != EgressPolicy::Deny {
                                had_forbidden_violation = true;
                                if strict_reject_forbidden {
                                    row.forbidden = EgressPolicy::Deny;
                                    anyhow::bail!(
                                        "安全策略锁定：forbidden 数据分级永远锁定为 deny，不可修改为 {}",
                                        parsed.as_str()
                                    );
                                }
                            }
                            row.forbidden = EgressPolicy::Deny;
                        }
                        _ => {}
                    }
                }
            }
        }

        let clamped = self.enforce_invariants();
        Ok(had_forbidden_violation || clamped)
    }
}

/// Built-in read-only Forbidden path rules (§5.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForbiddenPathRule {
    pub id: String,
    pub pattern: String,
    pub description: String,
    pub locked: bool,
}

pub fn builtin_forbidden_rules() -> Vec<ForbiddenPathRule> {
    vec![
        ForbiddenPathRule {
            id: "ssh_keys".into(),
            pattern: "~/.ssh/**".into(),
            description: "SSH 私钥、已知主机与授权密钥目录".into(),
            locked: true,
        },
        ForbiddenPathRule {
            id: "gnupg_keys".into(),
            pattern: "~/.gnupg/**".into(),
            description: "GPG 私钥环与签名凭据目录".into(),
            locked: true,
        },
        ForbiddenPathRule {
            id: "keyrings".into(),
            pattern: "~/.local/share/keyrings/**".into(),
            description: "GNOME Keyring / Secret Service 密钥环存储".into(),
            locked: true,
        },
        ForbiddenPathRule {
            id: "aws_kube_cloud".into(),
            pattern: "~/.aws/**, ~/.kube/**, ~/.config/gcloud/**".into(),
            description: "云平台与集群访问凭据目录".into(),
            locked: true,
        },
        ForbiddenPathRule {
            id: "browser_profiles".into(),
            pattern: "~/.mozilla/firefox/**, ~/.config/google-chrome/**, ~/.config/chromium/**"
                .into(),
            description: "浏览器 Cookie、保存的密码与会话存储".into(),
            locked: true,
        },
        ForbiddenPathRule {
            id: "intentos_internal".into(),
            pattern:
                "~/.config/intentos/**, ~/.local/share/intentos/**, ${XDG_RUNTIME_DIR}/intentos/**"
                    .into(),
            description: "IntentOS 核心配置、状态库、备份区与私有网关通道".into(),
            locked: true,
        },
    ]
}

/// Normalize and deduplicate a list of user-configured sensitive directories.
pub fn normalize_sensitive_directories(dirs: Vec<String>) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in dirs {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let expanded = if let Some(rest) = trimmed.strip_prefix("~/") {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
            format!("{}/{}", home.trim_end_matches('/'), rest)
        } else {
            trimmed.to_string()
        };
        if !out.contains(&expanded) {
            out.push(expanded);
        }
    }
    Ok(out)
}

/// Inspect a path against forbidden rules and user-configured sensitive directories (§5.4).
pub fn classify_path_sensitivity(path: &Path, sensitive_directories: &[String]) -> DataClass {
    let lossy = path.to_string_lossy();
    let lower = lossy.to_ascii_lowercase();

    if lower.contains("/.ssh")
        || lower.contains("/.gnupg")
        || lower.contains("/keyrings")
        || lower.contains("/.aws")
        || lower.contains("/.kube")
        || lower.ends_with("/id_rsa")
        || lower.ends_with("/id_ed25519")
    {
        return DataClass::Forbidden;
    }

    if lower.ends_with("/.env")
        || lower.contains("/.env.")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
    {
        return DataClass::Sensitive;
    }

    for sens in sensitive_directories {
        let clean = sens.trim_end_matches('/');
        if !clean.is_empty() && (lossy == clean || lossy.starts_with(&format!("{}/", clean))) {
            return DataClass::Sensitive;
        }
    }

    DataClass::Personal
}

pub fn egress_matrix_summary_json(
    matrix: &EgressMatrixConfig,
    sensitive_directories: &[String],
) -> Value {
    let mut clean = matrix.clone();
    clean.enforce_invariants();
    json!({
        "matrix": clean,
        "sensitive_directories": sensitive_directories,
        "forbidden_rules": builtin_forbidden_rules(),
        "forbidden_locked_to_deny": true,
    })
}
