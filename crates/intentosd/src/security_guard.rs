#![forbid(unsafe_code)]

//! Unified Security Guard, Three-Tier Privacy Session Policy, and Task State Machine (`security_guard.rs`).
//!
//! Enforces three core Milestone 1 P0 invariants across `core`, `db`, `runtime`, and `memory_hub`:
//! 1. **`SensitiveDataGuard`**: Pre-persistence secret detection & redaction so raw API keys, tokens,
//!    PEM private keys, and explicit user passwords/credentials NEVER land on disk in SQLite/WAL.
//! 2. **`PrivacySessionPolicy`**: Explicit three-tier memory & persistence isolation (`Standard`,
//!    `EphemeralReadOnly`, `StrictIsolated`), guaranteeing `incognito` (`StrictIsolated`) performs
//!    neither memory reads nor memory writes.
//! 3. **`UnifiedTaskStateMachine`**: Deterministic validator & transition helper unifying task states
//!    across `core` and `execution_hub`.

use chrono::Utc;
use intentos_protocol::{ChangeOp, ChangeSet, Task, TaskStatus};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

/// Canonical placeholder written in place of redacted credentials.
pub const REDACTED_SECRET_MARKER: &str = "[REDACTED_SECRET]";

struct CompiledSecretPatterns {
    pem_block: Regex,
    pem_header: Regex,
    sk_key: Regex,
    github_token: Regex,
    aws_access_key: Regex,
    google_api_key: Regex,
    bearer_token: Regex,
    zh_password_is: Regex,
    zh_password_kv: Regex,
    en_password: Regex,
    en_api_key: Regex,
    zh_api_key: Regex,
    en_secret: Regex,
    zh_private_key_kv: Regex,
    zh_private_key_val: Regex,
}

fn patterns() -> &'static CompiledSecretPatterns {
    static PATTERNS: OnceLock<CompiledSecretPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| CompiledSecretPatterns {
        pem_block: Regex::new(
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .expect("valid pem_block regex"),
        pem_header: Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\r\n]*")
            .expect("valid pem_header regex"),
        sk_key: Regex::new(r"(^|[^A-Za-z0-9_])(sk-[A-Za-z0-9_-]{16,})")
            .expect("valid sk_key regex"),
        github_token: Regex::new(
            r"(^|[^A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})",
        )
        .expect("valid github_token regex"),
        aws_access_key: Regex::new(r"(^|[^A-Za-z0-9_])(AKIA[0-9A-Z]{16})")
            .expect("valid aws_access_key regex"),
        google_api_key: Regex::new(r"(^|[^A-Za-z0-9_])(AIza[0-9A-Za-z_-]{25,})")
            .expect("valid google_api_key regex"),
        bearer_token: Regex::new(r"(?i)(^|[^A-Za-z0-9_])(Bearer\s+)([A-Za-z0-9._~+/=-]{12,})")
            .expect("valid bearer_token regex"),
        zh_password_is: Regex::new(
            r#"((?:密码|口令)\s*(?:是|为)\s*[:：=]?\s*)([^\s，,。；;！!？?"'`\]]+)"#,
        )
        .expect("valid zh_password_is regex"),
        zh_password_kv: Regex::new(
            r#"((?:密码|口令)\s*[:：=]\s*)([^\s，,。；;！!？?"'`\]]+)"#,
        )
        .expect("valid zh_password_kv regex"),
        en_password: Regex::new(
            r#"(?i)(^|[^A-Za-z0-9_])(password\s*(?:[=:]|\bis\b)\s*)([^\s，,。；;'"`\]]+)"#,
        )
        .expect("valid en_password regex"),
        en_api_key: Regex::new(
            r#"(?i)(^|[^A-Za-z0-9_])((?:api[_\s-]?key|access[_\s-]?token|auth[_\s-]?token)\s*(?:[=:]|\bis\b|是|为)\s*)([^\s，,。；;'"`\]]+)"#,
        )
        .expect("valid en_api_key regex"),
        zh_api_key: Regex::new(
            r#"((?:API\s*)?密钥\s*(?:是|为|[:：=])\s*)([^\s，,。；;！!？?"'`\]]+)"#,
        )
        .expect("valid zh_api_key regex"),
        en_secret: Regex::new(
            r#"(?i)(^|[^A-Za-z0-9_])(secret\s*(?:[=:]|\bis\b|是|为)\s*)([^\s，,。；;'"`\]]+)"#,
        )
        .expect("valid en_secret regex"),
        zh_private_key_kv: Regex::new(
            r#"(私钥\s*(?:是|为|[:：=])\s*)([^\s，,。；;！!？?"'`\]]+)"#,
        )
        .expect("valid zh_private_key_kv regex"),
        zh_private_key_val: Regex::new(r"(私钥\s+)([A-Za-z0-9+/=_-]{8,})")
            .expect("valid zh_private_key_val regex"),
    })
}

fn is_already_redacted_token(token: &str) -> bool {
    let trimmed = token.trim();
    trimmed.is_empty()
        || trimmed.contains("REDACTED")
        || trimmed == "****"
        || trimmed == "***"
}

/// Unified pre-persistence secret detection and redaction guard.
pub struct SensitiveDataGuard;

impl SensitiveDataGuard {
    /// Detect whether `text` contains a raw secret token, private key, or explicit credential phrase.
    /// Returns the static secret classification label when matched.
    pub fn contains_sensitive_secret(text: &str) -> Option<&'static str> {
        if text.is_empty() {
            return None;
        }
        let p = patterns();

        if p.pem_block.is_match(text) || p.pem_header.is_match(text) {
            return Some("pem_private_key");
        }
        if p.sk_key.is_match(text) {
            return Some("openai_or_sk_key");
        }
        if p.github_token.is_match(text) {
            return Some("github_token");
        }
        if p.aws_access_key.is_match(text) {
            return Some("aws_access_key");
        }
        if p.google_api_key.is_match(text) {
            return Some("google_api_key");
        }
        if let Some(caps) = p.bearer_token.captures(text)
            && !is_already_redacted_token(&caps[3])
        {
            return Some("bearer_token");
        }
        if let Some(caps) = p.zh_password_is.captures(text)
            && !is_already_redacted_token(&caps[2])
        {
            return Some("explicit_password");
        }
        if let Some(caps) = p.zh_password_kv.captures(text)
            && !is_already_redacted_token(&caps[2])
        {
            return Some("explicit_password");
        }
        if let Some(caps) = p.en_password.captures(text)
            && !is_already_redacted_token(&caps[3])
        {
            return Some("explicit_password");
        }
        if let Some(caps) = p.en_api_key.captures(text)
            && !is_already_redacted_token(&caps[3])
        {
            return Some("explicit_api_key");
        }
        if let Some(caps) = p.zh_api_key.captures(text)
            && !is_already_redacted_token(&caps[2])
        {
            return Some("explicit_api_key");
        }
        if let Some(caps) = p.en_secret.captures(text)
            && !is_already_redacted_token(&caps[3])
        {
            return Some("explicit_secret");
        }
        if let Some(caps) = p.zh_private_key_kv.captures(text)
            && !is_already_redacted_token(&caps[2])
        {
            return Some("explicit_private_key");
        }
        if let Some(caps) = p.zh_private_key_val.captures(text)
            && !is_already_redacted_token(&caps[2])
        {
            return Some("explicit_private_key");
        }

        None
    }

    /// Scrub all detected secrets and credential values in `text` to `[REDACTED_SECRET]`.
    /// Returns `(scrubbed_text, was_modified)`. Idempotent across repeated calls.
    pub fn redact_text(text: &str) -> (String, bool) {
        if text.is_empty() {
            return (String::new(), false);
        }
        let p = patterns();
        let mut out = text.to_string();
        let mut changed = false;

        if p.pem_block.is_match(&out) {
            out = p
                .pem_block
                .replace_all(&out, REDACTED_SECRET_MARKER)
                .into_owned();
            changed = true;
        }
        if p.pem_header.is_match(&out) {
            out = p
                .pem_header
                .replace_all(&out, REDACTED_SECRET_MARKER)
                .into_owned();
            changed = true;
        }

        for token_re in [&p.sk_key, &p.github_token, &p.aws_access_key, &p.google_api_key] {
            if token_re.is_match(&out) {
                let next = token_re
                    .replace_all(&out, |caps: &Captures<'_>| {
                        if is_already_redacted_token(&caps[2]) {
                            caps[0].to_string()
                        } else {
                            format!("{}{}", &caps[1], REDACTED_SECRET_MARKER)
                        }
                    })
                    .into_owned();
                if next != out {
                    out = next;
                    changed = true;
                }
            }
        }

        for three_group_re in [&p.bearer_token, &p.en_password, &p.en_api_key, &p.en_secret] {
            if three_group_re.is_match(&out) {
                let next = three_group_re
                    .replace_all(&out, |caps: &Captures<'_>| {
                        if is_already_redacted_token(&caps[3]) {
                            caps[0].to_string()
                        } else {
                            format!("{}{}{}", &caps[1], &caps[2], REDACTED_SECRET_MARKER)
                        }
                    })
                    .into_owned();
                if next != out {
                    out = next;
                    changed = true;
                }
            }
        }

        for two_group_re in [
            &p.zh_password_is,
            &p.zh_password_kv,
            &p.zh_api_key,
            &p.zh_private_key_kv,
            &p.zh_private_key_val,
        ] {
            if two_group_re.is_match(&out) {
                let next = two_group_re
                    .replace_all(&out, |caps: &Captures<'_>| {
                        if is_already_redacted_token(&caps[2]) {
                            caps[0].to_string()
                        } else {
                            format!("{}{}", &caps[1], REDACTED_SECRET_MARKER)
                        }
                    })
                    .into_owned();
                if next != out {
                    out = next;
                    changed = true;
                }
            }
        }

        (out, changed)
    }

    /// Recursively scrub sensitive values inside a mutable JSON `Value` in place.
    /// Returns `true` if any field or string value was redacted.
    pub fn redact_json(val: &mut Value) -> bool {
        match val {
            Value::String(s) => {
                let (clean, changed) = Self::redact_text(s);
                if changed {
                    *s = clean;
                }
                changed
            }
            Value::Array(arr) => {
                let mut changed = false;
                for item in arr {
                    if Self::redact_json(item) {
                        changed = true;
                    }
                }
                changed
            }
            Value::Object(map) => {
                let mut changed = false;
                for (k, v) in map.iter_mut() {
                    if is_explicit_secret_json_key(k) {
                        match v {
                            Value::String(s) if !is_already_redacted_token(s) => {
                                *s = REDACTED_SECRET_MARKER.to_string();
                                changed = true;
                            }
                            Value::Null => {}
                            other if !matches!(other, Value::String(_)) => {
                                *other = Value::String(REDACTED_SECRET_MARKER.to_string());
                                changed = true;
                            }
                            _ => {}
                        }
                    } else if Self::redact_json(v) {
                        changed = true;
                    }
                }
                changed
            }
            _ => false,
        }
    }

    /// Clone and scrub all textual/JSON payload fields of a `Task` prior to SQLite storage,
    /// preserving `id`, `status`, `route`, and `changeset_ids` intact.
    pub fn sanitize_task_for_storage(task: &Task) -> Task {
        let mut clean = task.clone();
        clean.goal = Self::redact_text(&clean.goal).0;

        if let Some(ref mut msg) = clean.assistant_message {
            *msg = Self::redact_text(msg).0;
        }
        if let Some(ref mut sum) = clean.result_summary {
            *sum = Self::redact_text(sum).0;
        }
        if let Some(ref mut cmd) = clean.handoff_command {
            *cmd = Self::redact_text(cmd).0;
        }

        for step in &mut clean.steps {
            if let Ok(mut parsed) = serde_json::from_str::<Value>(&step.arguments_summary) {
                if Self::redact_json(&mut parsed) {
                    step.arguments_summary = parsed.to_string();
                } else {
                    step.arguments_summary = Self::redact_text(&step.arguments_summary).0;
                }
            } else {
                step.arguments_summary = Self::redact_text(&step.arguments_summary).0;
            }
            step.message = Self::redact_text(&step.message).0;
            Self::redact_json(&mut step.data);
            if let Some(ref mut details) = step.verification.details {
                *details = Self::redact_text(details).0;
            }
        }

        if let Some(ref mut pa) = clean.pending_approval {
            Self::redact_json(&mut pa.arguments);
            pa.summary = Self::redact_text(&pa.summary).0;
            pa.diff_preview = Self::redact_text(&pa.diff_preview).0;
        }

        for cand in &mut clean.candidates_for_disambiguation {
            cand.title = Self::redact_text(&cand.title).0;
            cand.subtitle = Self::redact_text(&cand.subtitle).0;
            Self::redact_json(&mut cand.arguments);
        }

        clean
    }

    /// Clone and scrub `ChangeSet` metadata (`summary` and setting values) prior to SQLite storage.
    pub fn sanitize_changeset_for_storage(cs: &ChangeSet) -> ChangeSet {
        let mut clean = cs.clone();
        clean.summary = Self::redact_text(&clean.summary).0;
        for op in &mut clean.operations {
            if let ChangeOp::Setting { before, after, .. } = op {
                Self::redact_json(before);
                Self::redact_json(after);
            }
        }
        clean
    }
}

fn is_explicit_secret_json_key(key: &str) -> bool {
    let norm = key.trim().to_ascii_lowercase();
    matches!(
        norm.as_str(),
        "api_key"
            | "apikey"
            | "api-key"
            | "secret"
            | "client_secret"
            | "client-secret"
            | "access_token"
            | "accesstoken"
            | "auth_token"
            | "refresh_token"
            | "bearer_token"
            | "private_key"
            | "privatekey"
            | "password"
            | "passwd"
            | "passphrase"
            | "authorization"
    )
}

/// Three-tier privacy session memory & persistence isolation policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySessionPolicy {
    /// Normal persistent session: reads and writes personal memories & session history.
    #[default]
    Standard,
    /// Ephemeral read-only session: may consult existing user preferences, never writes new memories/history.
    EphemeralReadOnly,
    /// Strict isolated incognito session: ZERO memory reads and ZERO memory/task writes.
    StrictIsolated,
}

impl PrivacySessionPolicy {
    /// Map boolean `incognito` flag to `StrictIsolated` (`true`) or `Standard` (`false`).
    pub fn from_incognito(incognito: bool) -> Self {
        if incognito {
            Self::StrictIsolated
        } else {
            Self::Standard
        }
    }

    /// Resolve policy from both explicit `incognito` flag and `session_id` convention (`incog_*` / `ephemeral_ro_*`).
    pub fn from_session(incognito: bool, session_id: Option<&str>) -> Self {
        if incognito
            || session_id.is_some_and(|sid| sid.trim().starts_with("incog_"))
        {
            Self::StrictIsolated
        } else if session_id.is_some_and(|sid| sid.trim().starts_with("ephemeral_ro_")) {
            Self::EphemeralReadOnly
        } else {
            Self::Standard
        }
    }

    /// Whether long-term preferences (`StateDb`) and `MemoryHubDb` may be read into prompts/routing.
    pub fn allows_memory_read(self) -> bool {
        matches!(self, Self::Standard | Self::EphemeralReadOnly)
    }

    /// Whether conversation history, extracted entities, or explicit memories may be written to disk.
    pub fn allows_memory_write(self) -> bool {
        matches!(self, Self::Standard)
    }

    /// Whether tasks and audit entries should be persisted to `state.db`.
    pub fn allows_task_persistence(self) -> bool {
        matches!(self, Self::Standard)
    }
}

/// Unified Task Lifecycle State Machine across `core` and `execution_hub` (§13.2).
///
/// Protocol enum mapping:
/// - `WaitingApproval` -> [`TaskStatus::AwaitingApproval`]
/// - `Succeeded` -> [`TaskStatus::Completed`] (plus [`TaskStatus::PartiallyCompleted`])
pub struct UnifiedTaskStateMachine;

impl UnifiedTaskStateMachine {
    /// Alias for the waiting-approval state in `intentos_protocol::TaskStatus`.
    pub const WAITING_APPROVAL: TaskStatus = TaskStatus::AwaitingApproval;
    /// Alias for the succeeded state in `intentos_protocol::TaskStatus`.
    pub const SUCCEEDED: TaskStatus = TaskStatus::Completed;

    /// Returns `true` when `status` is a terminal lifecycle state.
    pub fn is_terminal(status: TaskStatus) -> bool {
        matches!(
            status,
            TaskStatus::Completed
                | TaskStatus::PartiallyCompleted
                | TaskStatus::Failed
                | TaskStatus::Cancelled
        )
    }

    /// Validate whether a task may legally transition from `from` to `to`.
    pub fn can_transition(from: TaskStatus, to: TaskStatus) -> bool {
        if Self::is_terminal(from) {
            return false;
        }
        if from == to {
            return true;
        }
        match from {
            TaskStatus::Created => matches!(
                to,
                TaskStatus::Planning
                    | TaskStatus::Running
                    | TaskStatus::AwaitingApproval
                    | TaskStatus::Paused
                    | TaskStatus::Completed
                    | TaskStatus::PartiallyCompleted
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
            ),
            TaskStatus::Planning => matches!(
                to,
                TaskStatus::Running
                    | TaskStatus::AwaitingApproval
                    | TaskStatus::Paused
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
                    | TaskStatus::RecoveryRequired
            ),
            TaskStatus::Running => matches!(
                to,
                TaskStatus::AwaitingApproval
                    | TaskStatus::Paused
                    | TaskStatus::Verifying
                    | TaskStatus::Completed
                    | TaskStatus::PartiallyCompleted
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
                    | TaskStatus::RecoveryRequired
            ),
            TaskStatus::AwaitingApproval => matches!(
                to,
                TaskStatus::Running
                    | TaskStatus::Verifying
                    | TaskStatus::Completed
                    | TaskStatus::PartiallyCompleted
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
            ),
            TaskStatus::Paused => matches!(
                to,
                TaskStatus::Planning
                    | TaskStatus::Running
                    | TaskStatus::AwaitingApproval
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
            ),
            TaskStatus::Verifying => matches!(
                to,
                TaskStatus::Completed
                    | TaskStatus::PartiallyCompleted
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
                    | TaskStatus::RecoveryRequired
            ),
            TaskStatus::RecoveryRequired => matches!(
                to,
                TaskStatus::Planning
                    | TaskStatus::Running
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
            ),
            TaskStatus::Completed
            | TaskStatus::PartiallyCompleted
            | TaskStatus::Failed
            | TaskStatus::Cancelled => false,
        }
    }

    /// Validate and apply a state transition on `task`, updating `updated_at` and optional summary reason.
    pub fn transition_task(
        task: &mut Task,
        to: TaskStatus,
        reason: Option<&str>,
    ) -> anyhow::Result<()> {
        if !Self::can_transition(task.status, to) {
            anyhow::bail!("非法任务状态迁移: {:?} -> {:?}", task.status, to);
        }
        task.status = to;
        task.updated_at = Utc::now();
        if to != TaskStatus::AwaitingApproval {
            task.pending_approval = None;
        }
        if let Some(raw_reason) = reason.map(str::trim).filter(|s| !s.is_empty()) {
            let (clean_reason, _) = SensitiveDataGuard::redact_text(raw_reason);
            if task.result_summary.is_none()
                || matches!(to, TaskStatus::Failed | TaskStatus::Cancelled)
            {
                task.result_summary = Some(clean_reason.clone());
            }
            if task.assistant_message.is_none() {
                task.assistant_message = Some(clean_reason);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_protocol::{
        DataClass, Effect, ExecutionStatus, PendingApproval, RouteLayer, TaskBudget, TaskStep,
        TaskTrigger, Taint, VerificationReport, VerificationState,
    };
    use serde_json::json;

    fn sample_task(status: TaskStatus) -> Task {
        let now = Utc::now();
        Task {
            id: "task_sec_01".into(),
            goal: "测试任务".into(),
            session_id: Some("ses_01".into()),
            project_id: None,
            trigger: TaskTrigger::User,
            route: RouteLayer::L0,
            status,
            steps: Vec::new(),
            changeset_ids: vec!["cs_keep_1".into()],
            pending_approval: None,
            candidates_for_disambiguation: Vec::new(),
            assistant_message: None,
            result_summary: None,
            handoff_command: None,
            taint: vec![Taint::User],
            data_class: DataClass::Personal,
            budget: TaskBudget::default(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_sensitive_data_guard_detects_and_redacts_all_secret_families() {
        let cases = [
            (
                "记住我的 OpenAI key 是 sk-1234567890abcdef123456",
                "sk-1234567890abcdef123456",
            ),
            (
                "无空格紧贴密钥是sk-99887766554433221100abcdef请保存",
                "sk-99887766554433221100abcdef",
            ),
            (
                "GitHub PAT: ghp_abcdefghijklmnopqrstuvwxyz1234",
                "ghp_abcdefghijklmnopqrstuvwxyz1234",
            ),
            (
                "AWS key AKIAIOSFODNN7EXAMPLE in config",
                "AKIAIOSFODNN7EXAMPLE",
            ),
            (
                "Google key AIzaSyDaGmWKa4JsXZ-0123456789abcdef",
                "AIzaSyDaGmWKa4JsXZ-0123456789abcdef",
            ),
            (
                "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            ),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n-----END OPENSSH PRIVATE KEY-----",
                "b3BlbnNzaC1rZXktdjE=",
            ),
            ("记住密码是 MySup3rS3cret!", "MySup3rS3cret!"),
            ("my password is correct-horse-battery", "correct-horse-battery"),
            ("api_key=custom_tok_889900", "custom_tok_889900"),
            ("secret: internal_signing_seed_42", "internal_signing_seed_42"),
            ("私钥: MIIEvgIBADANBgkqhkiG9w0BAQE", "MIIEvgIBADANBgkqhkiG9w0BAQE"),
        ];

        for (input, forbidden_substr) in cases {
            assert!(
                SensitiveDataGuard::contains_sensitive_secret(input).is_some(),
                "expected secret detection for: {input}"
            );
            let (scrubbed, modified) = SensitiveDataGuard::redact_text(input);
            assert!(modified, "expected modification for: {input}");
            assert!(
                !scrubbed.contains(forbidden_substr),
                "leaked '{forbidden_substr}' in '{scrubbed}'"
            );
            assert!(scrubbed.contains(REDACTED_SECRET_MARKER));

            // Idempotency check: second pass makes zero changes and detects zero raw secrets
            let (scrubbed_again, modified_again) = SensitiveDataGuard::redact_text(&scrubbed);
            assert!(!modified_again, "redact_text must be idempotent: {scrubbed}");
            assert_eq!(scrubbed, scrubbed_again);
            assert!(SensitiveDataGuard::contains_sensitive_secret(&scrubbed).is_none());
        }
    }

    #[test]
    fn test_sensitive_data_guard_preserves_benign_text_and_task_ids() {
        let benign_inputs = [
            "task-compound-550e8400-e29b-41d4-a716-446655440000",
            "怎么修改系统登录密码",
            "请在顶栏切换引擎或配置 API 密钥。",
            "尝试读取 SSH 私钥或系统敏感凭据阻断",
            "帮我在目录查找 secret_report_appendix 附件",
            "默认使用 WPS 打开文档",
        ];
        for text in benign_inputs {
            assert_eq!(
                SensitiveDataGuard::contains_sensitive_secret(text),
                None,
                "false positive on benign text: {text}"
            );
            let (out, changed) = SensitiveDataGuard::redact_text(text);
            assert!(!changed);
            assert_eq!(out, text);
        }

        // Benign `key_id` in settings JSON must not be redacted, whereas `api_key` must be
        let mut settings_json = json!({
            "key_id": "sound.volume",
            "api_key": "raw_provider_token_123",
            "nested": {
                "note": "Bearer secret_jwt_token_value_12345"
            }
        });
        assert!(SensitiveDataGuard::redact_json(&mut settings_json));
        assert_eq!(settings_json["key_id"], "sound.volume");
        assert_eq!(settings_json["api_key"], REDACTED_SECRET_MARKER);
        assert!(
            !settings_json["nested"]["note"]
                .as_str()
                .unwrap()
                .contains("secret_jwt_token_value_12345")
        );
    }

    #[test]
    fn test_sanitize_task_for_storage_preserves_metadata_and_scrubs_secrets() {
        let now = Utc::now();
        let mut task = sample_task(TaskStatus::Failed);
        task.route = RouteLayer::L2;
        task.goal = "记住我的 API 密钥是 sk-99887766554433221100abcdef".into();
        task.assistant_message = Some("拒绝保存 sk-99887766554433221100abcdef".into());
        task.result_summary = Some("password=topsecret999 rejected".into());
        task.steps.push(TaskStep {
            step_id: "step_1".into(),
            capability_id: "file.write".into(),
            arguments_summary: json!({
                "path": "/tmp/a.txt",
                "content": "ghp_1234567890abcdefghijklmno"
            })
            .to_string(),
            status: ExecutionStatus::Denied,
            verification: VerificationReport {
                state: VerificationState::VerificationFailed,
                method: "policy".into(),
                checks: vec![],
                details: Some("blocked AKIAIOSFODNN7EXAMPLE".into()),
            },
            changeset_id: Some("cs_keep_1".into()),
            message: "output had sk-99887766554433221100abcdef".into(),
            data: json!({ "password": "plain_password_123" }),
            duration_ms: 3,
        });
        task.pending_approval = Some(PendingApproval {
            approval_id: "apr_1".into(),
            task_id: task.id.clone(),
            capability_id: "file.write".into(),
            arguments: json!({ "secret": "my_raw_secret_val" }),
            summary: "写入含密码是 88888888 的配置".into(),
            diff_preview: "+ api_key = sk-99887766554433221100abcdef".into(),
            effects: vec![Effect::WriteReversible],
            reversible: true,
            nonce: "nonce_1".into(),
            digest: "sha256:abc".into(),
            created_at: now,
            expires_at: now,
        });

        let clean = SensitiveDataGuard::sanitize_task_for_storage(&task);
        assert_eq!(clean.id, "task_sec_01");
        assert_eq!(clean.status, TaskStatus::Failed);
        assert_eq!(clean.route, RouteLayer::L2);
        assert_eq!(clean.changeset_ids, vec!["cs_keep_1".to_string()]);

        let serialized = serde_json::to_string(&clean).unwrap();
        assert!(!serialized.contains("sk-99887766554433221100abcdef"));
        assert!(!serialized.contains("topsecret999"));
        assert!(!serialized.contains("ghp_1234567890abcdefghijklmno"));
        assert!(!serialized.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!serialized.contains("plain_password_123"));
        assert!(!serialized.contains("my_raw_secret_val"));
        assert!(!serialized.contains("88888888"));
        assert!(serialized.contains(REDACTED_SECRET_MARKER));
    }

    #[test]
    fn test_privacy_session_policy_tiers() {
        let std_pol = PrivacySessionPolicy::from_incognito(false);
        assert_eq!(std_pol, PrivacySessionPolicy::Standard);
        assert!(std_pol.allows_memory_read());
        assert!(std_pol.allows_memory_write());
        assert!(std_pol.allows_task_persistence());

        let eph_ro = PrivacySessionPolicy::EphemeralReadOnly;
        assert!(eph_ro.allows_memory_read());
        assert!(!eph_ro.allows_memory_write());
        assert!(!eph_ro.allows_task_persistence());

        let strict = PrivacySessionPolicy::from_incognito(true);
        assert_eq!(strict, PrivacySessionPolicy::StrictIsolated);
        assert!(!strict.allows_memory_read());
        assert!(!strict.allows_memory_write());
        assert!(!strict.allows_task_persistence());

        assert_eq!(
            PrivacySessionPolicy::from_session(false, Some("incog_abc123")),
            PrivacySessionPolicy::StrictIsolated
        );
        assert_eq!(
            PrivacySessionPolicy::from_session(false, Some("ephemeral_ro_01")),
            PrivacySessionPolicy::EphemeralReadOnly
        );
    }

    #[test]
    fn test_unified_task_state_machine_transitions() {
        let mut task = sample_task(TaskStatus::Created);
        UnifiedTaskStateMachine::transition_task(&mut task, TaskStatus::Planning, None).unwrap();
        assert_eq!(task.status, TaskStatus::Planning);

        UnifiedTaskStateMachine::transition_task(&mut task, TaskStatus::Running, None).unwrap();
        assert_eq!(task.status, TaskStatus::Running);

        UnifiedTaskStateMachine::transition_task(
            &mut task,
            UnifiedTaskStateMachine::WAITING_APPROVAL,
            Some("等待用户确认"),
        )
        .unwrap();
        assert_eq!(task.status, TaskStatus::AwaitingApproval);

        UnifiedTaskStateMachine::transition_task(&mut task, TaskStatus::Running, None).unwrap();
        UnifiedTaskStateMachine::transition_task(&mut task, TaskStatus::Verifying, None).unwrap();
        UnifiedTaskStateMachine::transition_task(
            &mut task,
            UnifiedTaskStateMachine::SUCCEEDED,
            Some("全部完成"),
        )
        .unwrap();
        assert_eq!(task.status, TaskStatus::Completed);

        // Terminal states cannot transition back to Running or Failed
        assert!(!UnifiedTaskStateMachine::can_transition(
            TaskStatus::Completed,
            TaskStatus::Running
        ));
        assert!(!UnifiedTaskStateMachine::can_transition(
            TaskStatus::Failed,
            TaskStatus::Completed
        ));
        assert!(!UnifiedTaskStateMachine::can_transition(
            TaskStatus::Cancelled,
            TaskStatus::Running
        ));
        assert!(!UnifiedTaskStateMachine::can_transition(
            TaskStatus::Created,
            TaskStatus::Verifying
        ));
        assert!(
            UnifiedTaskStateMachine::transition_task(&mut task, TaskStatus::Running, None).is_err()
        );

        // Crash recovery path: Running -> RecoveryRequired -> Running -> Failed (with secret redaction)
        let mut interrupted = sample_task(TaskStatus::Running);
        UnifiedTaskStateMachine::transition_task(
            &mut interrupted,
            TaskStatus::RecoveryRequired,
            None,
        )
        .unwrap();
        UnifiedTaskStateMachine::transition_task(&mut interrupted, TaskStatus::Running, None)
            .unwrap();
        UnifiedTaskStateMachine::transition_task(
            &mut interrupted,
            TaskStatus::Failed,
            Some("上游报错 sk-1234567890abcdef123456"),
        )
        .unwrap();
        assert_eq!(interrupted.status, TaskStatus::Failed);
        assert!(
            !interrupted
                .result_summary
                .as_deref()
                .unwrap_or("")
                .contains("sk-1234567890abcdef123456")
        );
    }

    #[tokio::test]
    async fn test_full_pipeline_sqlite_redaction_incognito_isolation_and_compound_honesty() {
        use crate::core::IntentOsCore;
        use crate::runtime::build_context_blocks_with_privacy;
        use intentos_protocol::IntentRequest;
        use std::path::PathBuf;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("temp dir");
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .to_path_buf();
        let core = IntentOsCore::initialize(Some(tmp.path()), repo_root).expect("init core");

        // 1. Seed a normal preference, then verify StrictIsolated context builder NEVER reads it
        let save_pref = core
            .submit_intent(
                IntentRequest {
                    protocol_version: 1,
                    text: "记住默认使用 WPS 打开文档".into(),
                    session_id: Some("ses_std_1".into()),
                    force_agent: false,
                    selected_candidate_id: None,
                    cwd: None,
                    incognito: false,
                },
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(save_pref.status, TaskStatus::Completed);

        let std_blocks = build_context_blocks_with_privacy(
            &core.state_db,
            &[],
            Vec::new(),
            PrivacySessionPolicy::Standard,
        );
        assert!(
            std_blocks
                .iter()
                .any(|b| b.label == "memories" && b.content.contains("默认使用 WPS 打开文档")),
            "Standard policy should include explicit memories"
        );

        let strict_blocks = build_context_blocks_with_privacy(
            &core.state_db,
            &[],
            Vec::new(),
            PrivacySessionPolicy::StrictIsolated,
        );
        assert!(
            !strict_blocks
                .iter()
                .any(|b| b.label == "memories" || b.content.contains("默认使用 WPS 打开文档")),
            "StrictIsolated MUST NOT leak active memories from StateDb"
        );

        // 2. Reject credential memorization and verify ZERO raw secret bytes anywhere on disk
        let raw_secret = "sk-99887766554433221100abcdef";
        let rej = core
            .submit_intent(
                IntentRequest {
                    protocol_version: 1,
                    text: format!("记住我的 API 密钥是 {raw_secret}"),
                    session_id: Some("ses_std_1".into()),
                    force_agent: false,
                    selected_candidate_id: None,
                    cwd: None,
                    incognito: false,
                },
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(rej.status, TaskStatus::Failed);
        assert_eq!(rej.route, RouteLayer::L0);
        assert!(!rej.goal.contains(raw_secret));

        for entry in walkdir::WalkDir::new(tmp.path()).into_iter().flatten() {
            if entry.file_type().is_file()
                && let Ok(bytes) = std::fs::read(entry.path())
            {
                let lossy = String::from_utf8_lossy(&bytes);
                assert!(
                    !lossy.contains(raw_secret),
                    "raw secret leaked on disk in {}",
                    entry.path().display()
                );
            }
        }

        // 3. Compound utterance with unresolved second clause NEVER claims 100% Completed offline
        let comp_task = core
            .submit_intent(
                IntentRequest {
                    protocol_version: 1,
                    text: "把音量调到35，然后帮我分析昨天实验日志报错原因".into(),
                    session_id: Some("ses_std_1".into()),
                    force_agent: false,
                    selected_candidate_id: None,
                    cwd: None,
                    incognito: false,
                },
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(comp_task.status, TaskStatus::PartiallyCompleted);
        assert_eq!(comp_task.route, RouteLayer::L2);
        let msg = comp_task.assistant_message.as_deref().unwrap_or("");
        assert!(
            msg.contains("帮我分析昨天实验日志报错原因"),
            "assistant_message must report unresolved sub-goal explicitly: {msg}"
        );
    }
}
