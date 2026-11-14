#![forbid(unsafe_code)]

//! Policy Engine, 4-Tier Path Sensitivity, Runtime Security Modes & Session Scope Grants (WP07, §10.2–10.7):
//! - Computes `PolicyDecision` from `PathSensitivity × Effect × Scale × Origin × Taints × SecurityMode × SessionGrants`
//! - Tier 0 (`Forbidden` paths like `~/.ssh`, `/etc/shadow`, IntentOS state/config, `sudo`, non-HTTP/S URLs): ALWAYS `Deny`
//! - Tier 2 (`SensitiveDotPath` like `~/.config`, `~/.bashrc`, `.env` & `OutsideScope` like `/opt`, `/etc/hosts`):
//!   Interactive `PreviewAndApprove` (NEVER hard-deny out-of-scope user requests; allows explicit user confirmation)
//! - Tier 1 (`NormalUserSpace` across XDG Chinese/English dirs & `$HOME`): `Allow` for `Observe/Ui`, `AllowWithUndo` for `UserExplicit` reversible writes
//! - Issues one-time `nonce` + canonical argument `digest` approvals over private UI channel only

use chrono::{DateTime, Duration, Utc};
use intentos_fsops::{PathSensitivity, SafeFsEngine};
use intentos_protocol::{
    CapabilityDescriptor, Effect, InvocationOrigin, PendingApproval, PolicyDecision, Taint,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionScopeGrant {
    pub id: String,
    pub scope_kind: String, // "directory" | "capability" | "app"
    pub scope_value: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub struct PolicyEngine {
    fs_engine: Arc<SafeFsEngine>,
    pending_approvals: Mutex<HashMap<String, PendingApproval>>,
    security_mode: Mutex<String>,
    session_grants: Mutex<Vec<SessionScopeGrant>>,
}

fn normalize_clean_path(path: PathBuf) -> PathBuf {
    let mut has_parent_traversal = false;
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            has_parent_traversal = true;
            break;
        }
    }
    if has_parent_traversal {
        return path;
    }
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::Normal(seg) => out.push(seg),
            Component::ParentDir => out.push(comp.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        path
    } else {
        out
    }
}

fn expand_tilde_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    let expanded = if trimmed == "~" {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        PathBuf::from(home)
    } else if let Some(rest) = trimmed.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(trimmed)
    };
    normalize_clean_path(expanded)
}

fn is_path_arg_key(key: &str) -> bool {
    matches!(
        key,
        "path"
            | "source"
            | "target"
            | "directory"
            | "repo_dir"
            | "output"
            | "archive"
            | "destination"
            | "repo"
            | "target_dir"
            | "dir"
            | "cwd"
            | "file"
            | "file_path"
            | "input"
    )
}

fn extract_arg_paths(args: &Value) -> Vec<(String, String, PathBuf)> {
    let mut out = Vec::new();
    let Some(obj) = args.as_object() else {
        return out;
    };
    for (key, val) in obj {
        if is_path_arg_key(key)
            && let Some(s) = val.as_str()
            && !s.trim().is_empty()
        {
            out.push((key.clone(), s.to_string(), expand_tilde_path(s)));
        } else if key == "sources"
            && let Some(arr) = val.as_array()
        {
            for item in arr {
                if let Some(s) = item.as_str()
                    && !s.trim().is_empty()
                {
                    out.push(("sources".to_string(), s.to_string(), expand_tilde_path(s)));
                }
            }
        } else if key == "params"
            && let Some(params_obj) = val.as_object()
        {
            for (pk, pv) in params_obj {
                if is_path_arg_key(pk)
                    && let Some(s) = pv.as_str()
                    && !s.trim().is_empty()
                {
                    let st = s.trim();
                    if st.starts_with('/') || st.starts_with('~') {
                        out.push((pk.clone(), s.to_string(), expand_tilde_path(st)));
                    }
                }
            }
        }
    }
    out
}

fn has_explicit_dot_segment(path: &Path) -> bool {
    for comp in path.components() {
        if let Component::Normal(seg) = comp
            && seg.to_string_lossy().starts_with('.')
        {
            return true;
        }
    }
    false
}

impl PolicyEngine {
    pub fn new(fs_engine: Arc<SafeFsEngine>) -> Self {
        Self {
            fs_engine,
            pending_approvals: Mutex::new(HashMap::new()),
            security_mode: Mutex::new("balanced".to_string()),
            session_grants: Mutex::new(Vec::new()),
        }
    }

    pub fn set_security_mode(&self, mode: &str) {
        let clean = mode.trim().to_ascii_lowercase();
        let normalized = match clean.as_str() {
            "strict" => "strict",
            "developer" | "dev" => "developer",
            "balanced" | "standard" => "balanced",
            _ => return,
        };
        *self.security_mode.lock().unwrap() = normalized.to_string();
    }

    pub fn security_mode(&self) -> String {
        self.security_mode.lock().unwrap().clone()
    }

    pub fn add_session_grant(&self, scope_kind: &str, scope_value: &str, ttl_minutes: i64) -> Value {
        let kind = match scope_kind.trim().to_ascii_lowercase().as_str() {
            "directory" | "dir" | "path" => "directory".to_string(),
            "capability" | "cap" => "capability".to_string(),
            "app" | "application" => "app".to_string(),
            other => other.to_string(),
        };

        let normalized_value = if kind == "directory" {
            let expanded = expand_tilde_path(scope_value);
            if expanded
                .components()
                .any(|c| matches!(c, Component::ParentDir))
                || self.fs_engine.is_forbidden(&expanded)
            {
                return json!({
                    "error": "forbidden_path",
                    "rejected": true,
                    "scope_value": scope_value,
                });
            }
            let use_parent = expanded.is_file()
                || (!expanded.exists()
                    && expanded.extension().is_some()
                    && !expanded
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with('.'))
                    && expanded
                        .parent()
                        .is_some_and(|p| p != Path::new("/") && p.is_dir()));
            let dir_path = if use_parent {
                expanded.parent().unwrap_or(&expanded).to_path_buf()
            } else {
                expanded
            };
            let dir_path = normalize_clean_path(dir_path);
            if self.fs_engine.is_forbidden(&dir_path) {
                return json!({
                    "error": "forbidden_path",
                    "rejected": true,
                    "scope_value": scope_value,
                });
            }
            if dir_path.is_dir() {
                let _ = self.fs_engine.approve_path_scope(&dir_path);
            }
            dir_path.to_string_lossy().to_string()
        } else {
            scope_value.trim().to_string()
        };

        let ttl = if ttl_minutes <= 0 {
            60
        } else {
            ttl_minutes.clamp(1, 24 * 60)
        };
        let now = Utc::now();
        let grant = SessionScopeGrant {
            id: format!("sgr_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]),
            scope_kind: kind.clone(),
            scope_value: normalized_value.clone(),
            created_at: now,
            expires_at: now + Duration::minutes(ttl),
        };

        let mut guard = self.session_grants.lock().unwrap();
        guard.retain(|g| {
            g.expires_at > now && !(g.scope_kind == kind && g.scope_value == normalized_value)
        });
        guard.push(grant.clone());
        serde_json::to_value(&grant).unwrap_or_else(|_| json!({}))
    }

    pub fn list_session_grants(&self) -> Vec<Value> {
        let mut guard = self.session_grants.lock().unwrap();
        let now = Utc::now();
        guard.retain(|g| g.expires_at > now);
        guard
            .iter()
            .filter_map(|g| serde_json::to_value(g).ok())
            .collect()
    }

    pub fn revoke_session_grant(&self, id: &str) -> bool {
        let mut guard = self.session_grants.lock().unwrap();
        let now = Utc::now();
        guard.retain(|g| g.expires_at > now);
        let mut removed_dirs = Vec::new();
        let before = guard.len();
        guard.retain(|g| {
            if g.id == id {
                if g.scope_kind == "directory" {
                    removed_dirs.push(expand_tilde_path(&g.scope_value));
                }
                false
            } else {
                true
            }
        });
        let remaining_dirs: Vec<PathBuf> = guard
            .iter()
            .filter(|g| g.scope_kind == "directory")
            .map(|g| expand_tilde_path(&g.scope_value))
            .collect();
        let removed_any = before > guard.len();
        drop(guard);

        for d in removed_dirs {
            let _ = self.fs_engine.revoke_approved_root(&d);
            for approved in self.fs_engine.list_approved_roots() {
                if approved.starts_with(&d)
                    && !remaining_dirs.iter().any(|rem| approved.starts_with(rem))
                {
                    let _ = self.fs_engine.revoke_approved_root(&approved);
                }
            }
        }
        removed_any
    }

    /// Check whether an active session grant covers this `(capability_id, args)` invocation.
    /// Never matches if any argument touches a `Forbidden` path. When matched, also registers
    /// non-forbidden target paths in `SafeFsEngine::approve_path_scope` so `openat2` succeeds.
    pub fn is_session_granted(&self, capability_id: &str, args: &Value) -> bool {
        let arg_paths = extract_arg_paths(args);
        if arg_paths.iter().any(|(_, _, p)| {
            p.components().any(|c| matches!(c, Component::ParentDir))
                || self.fs_engine.is_forbidden(p)
        }) {
            return false;
        }

        let active_grants: Vec<SessionScopeGrant> = {
            let mut guard = self.session_grants.lock().unwrap();
            let now = Utc::now();
            guard.retain(|g| g.expires_at > now);
            guard.clone()
        };
        if active_grants.is_empty() {
            return false;
        }

        // 1. Check capability scope grant
        let cap_granted = active_grants.iter().any(|g| {
            if g.scope_kind != "capability" {
                return false;
            }
            if g.scope_value == "*" || g.scope_value == capability_id {
                return true;
            }
            if let Some(prefix) = g.scope_value.strip_suffix(".*") {
                return capability_id.starts_with(prefix);
            }
            false
        });

        // 2. Check app scope grant
        let app_arg = args
            .get("app")
            .or_else(|| args.get("app_id"))
            .or_else(|| args.get("app_name"))
            .or_else(|| args.get("app_hint"))
            .or_else(|| args.get("target_app"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                args.get("params")
                    .and_then(|p| p.get("app"))
                    .and_then(|v| v.as_str())
            });
        let app_granted = if let Some(target_app) = app_arg {
            let t_lc = target_app.trim().to_ascii_lowercase();
            !t_lc.is_empty()
                && active_grants.iter().any(|g| {
                    g.scope_kind == "app"
                        && (g.scope_value == "*"
                            || g.scope_value.trim().to_ascii_lowercase() == t_lc)
                })
        } else {
            false
        };

        // 3. Check directory scope grant across extracted path arguments
        let dir_grants: Vec<PathBuf> = active_grants
            .iter()
            .filter(|g| g.scope_kind == "directory")
            .map(|g| expand_tilde_path(&g.scope_value))
            .filter(|dg| !self.fs_engine.is_forbidden(dg))
            .collect();

        let relevant_paths: Vec<&PathBuf> = arg_paths
            .iter()
            .filter(|(k, _, p)| k != "repo" || p.is_absolute() || has_explicit_dot_segment(p))
            .map(|(_, _, p)| p)
            .collect();

        let dir_granted = if !dir_grants.is_empty() && !relevant_paths.is_empty() {
            let any_matches_grant = relevant_paths
                .iter()
                .any(|p| dir_grants.iter().any(|dg| p.starts_with(dg)));
            let all_covered = relevant_paths.iter().all(|p| {
                dir_grants.iter().any(|dg| p.starts_with(dg))
                    || self.fs_engine.classify_path_sensitivity(p)
                        == PathSensitivity::NormalUserSpace
            });
            any_matches_grant && all_covered
        } else {
            false
        };

        if cap_granted || app_granted || dir_granted {
            for dg in &dir_grants {
                if dg.is_dir() && !self.fs_engine.is_forbidden(dg) {
                    let _ = self.fs_engine.approve_path_scope(dg);
                }
            }
            for (k, _, p) in &arg_paths {
                if (k != "repo" || p.is_absolute())
                    && p.is_absolute()
                    && !self.fs_engine.is_forbidden(p)
                {
                    if p.is_dir() {
                        let _ = self.fs_engine.approve_path_scope(p);
                    } else if let Some(parent) = p.parent()
                        && parent != Path::new("/")
                        && parent.is_dir()
                        && !self.fs_engine.is_forbidden(parent)
                    {
                        let _ = self.fs_engine.approve_path_scope(p);
                    }
                }
            }
            return true;
        }

        false
    }

    pub fn pending_count(&self) -> usize {
        let mut map = self.pending_approvals.lock().unwrap();
        let now = Utc::now();
        map.retain(|_, v| v.expires_at > now);
        map.len()
    }

    /// Evaluate a capability invocation against 4-tier sensitivity, effect, taint, security mode, and session grants (§10.2, §10.4).
    pub fn evaluate(
        &self,
        desc: &CapabilityDescriptor,
        args: &Value,
        origin: InvocationOrigin,
        taints: &[Taint],
        operation_count: usize,
        reversible_quota_ok: bool,
    ) -> PolicyDecision {
        // 1. Tier 0: Hard Denials — Forbidden paths, sudo/root attempts, or dangerous URL schemes (NEVER bypassed!)
        if let Some(reason) = self.scan_args_for_tier0_denials(&desc.id, args) {
            return PolicyDecision::Deny { reason };
        }

        let mut max_effect = desc.max_effect();
        if max_effect == Effect::WriteReversible && !reversible_quota_ok {
            // §9.2: Exceeding backup quota automatically escalates write.reversible -> write.destructive!
            max_effect = Effect::WriteDestructive;
        }

        let has_untrusted_taint = taints.iter().any(|t| t.is_untrusted());
        let has_sensitive_taint = taints.contains(&Taint::Sensitive);

        // 2. Taint escalation rules (§10.4 — untrusted context always requires human preview for writes/egress!)
        if has_untrusted_taint
            && matches!(
                max_effect,
                Effect::Setting
                    | Effect::WriteReversible
                    | Effect::WriteDestructive
                    | Effect::Egress
                    | Effect::ProcessControl
                    | Effect::ExternalCommit
                    | Effect::SystemAdmin
            )
        {
            return PolicyDecision::PreviewAndApprove {
                reason: "上下文包含外部/不可信内容（Taint: untrusted），写或外发操作必须经人工预览确认"
                    .into(),
            };
        }

        if has_sensitive_taint && max_effect == Effect::Egress {
            return PolicyDecision::ConfirmEach {
                reason: "上下文含敏感数据（sensitive），外发操作需逐次确认".into(),
            };
        }

        // 3. Tier 2: SensitiveDotPath (`~/.config`, `~/.bashrc`, `.env`) & OutsideScope (`/opt`, `/etc/hosts`)
        //    Triggers interactive `PreviewAndApprove` even on `Observe` / `Ui` (`file.open`) unless covered by session grant!
        if let Some(reason) = self.scan_args_for_tier2_approval(&desc.id, args) {
            return PolicyDecision::PreviewAndApprove { reason };
        }

        // 4. Tier 1 (`NormalUserSpace`) & Standard Effect × Scale × Origin × SecurityMode matrix (§10.2)
        let mode = self.security_mode();
        let session_granted = self.is_session_granted(&desc.id, args);

        match max_effect {
            Effect::Observe | Effect::Ui | Effect::ExecSandboxed => {
                if mode == "strict" && desc.id == "app.quit" && !session_granted {
                    PolicyDecision::PreviewAndApprove {
                        reason: "严格安全模式下关闭应用需确认".into(),
                    }
                } else {
                    PolicyDecision::Allow
                }
            }
            Effect::Setting => match origin {
                InvocationOrigin::UserExplicit | InvocationOrigin::L1Inferred => {
                    PolicyDecision::AllowWithUndo
                }
                InvocationOrigin::L2AgentPlan | InvocationOrigin::BackgroundAutomation => {
                    if session_granted || (mode == "developer" && !has_untrusted_taint) {
                        PolicyDecision::AllowWithUndo
                    } else {
                        PolicyDecision::PreviewAndApprove {
                            reason: "模型规划发起的系统设置修改需确认".into(),
                        }
                    }
                }
            },
            Effect::WriteReversible => {
                if operation_count > 20 {
                    return PolicyDecision::PreviewAndApprove {
                        reason: format!(
                            "批量修改 {} 个对象（超过自动阈值 20），请预览差异并确认",
                            operation_count
                        ),
                    };
                }
                match origin {
                    InvocationOrigin::UserExplicit => {
                        if !has_untrusted_taint && (mode != "strict" || session_granted) {
                            PolicyDecision::AllowWithUndo
                        } else {
                            PolicyDecision::PreviewAndApprove {
                                reason: "严格安全模式下文件修改需确认（执行后生成可逆变更集，支持一键撤销）"
                                    .into(),
                            }
                        }
                    }
                    InvocationOrigin::L2AgentPlan => {
                        if !has_untrusted_taint && (session_granted || mode == "developer") {
                            PolicyDecision::AllowWithUndo
                        } else {
                            PolicyDecision::PreviewAndApprove {
                                reason: "AI 发起的文件修改需确认（执行后生成可逆变更集，支持一键撤销）"
                                    .into(),
                            }
                        }
                    }
                    InvocationOrigin::L1Inferred | InvocationOrigin::BackgroundAutomation => {
                        if !has_untrusted_taint && session_granted {
                            PolicyDecision::AllowWithUndo
                        } else {
                            PolicyDecision::PreviewAndApprove {
                                reason: "AI 发起的文件修改需确认（执行后生成可逆变更集，支持一键撤销）"
                                    .into(),
                            }
                        }
                    }
                }
            }
            Effect::Egress
            | Effect::ProcessControl
            | Effect::WriteDestructive
            | Effect::ExternalCommit
            | Effect::SystemAdmin => PolicyDecision::ConfirmEach {
                reason: format!(
                    "高影响操作（效应 {}，不可自动撤销），需逐次确认",
                    max_effect.as_str()
                ),
            },
        }
    }

    fn scan_args_for_tier0_denials(&self, capability_id: &str, args: &Value) -> Option<String> {
        if capability_id.contains("sudo") {
            return Some("禁止访问系统敏感凭据或执行未授权 root 操作".into());
        }
        let obj = args.as_object()?;
        for (key, v) in obj {
            if let Some(s) = v.as_str() {
                let trimmed = s.trim();
                if matches!(trimmed, "/etc/shadow" | "/etc/gshadow" | "/etc/sudoers") {
                    return Some(format!(
                        "禁止访问系统敏感凭据或受保护配置（forbidden path）: {}",
                        s
                    ));
                }
                if key == "url" {
                    let lower = trimmed.to_ascii_lowercase();
                    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                        return Some(format!("拒绝打开非 HTTP/HTTPS URL: {}", s));
                    }
                }
            }
        }
        for (_key, raw_s, expanded_p) in extract_arg_paths(args) {
            if self.fs_engine.classify_path_sensitivity(&expanded_p) == PathSensitivity::Forbidden {
                return Some(format!(
                    "访问永不外发/受保护路径被拒绝（forbidden path）: {}",
                    raw_s
                ));
            }
        }
        None
    }

    fn scan_args_for_tier2_approval(&self, capability_id: &str, args: &Value) -> Option<String> {
        let arg_paths = extract_arg_paths(args);
        if arg_paths.is_empty() {
            return None;
        }

        for (key, raw_s, expanded_p) in &arg_paths {
            if key == "repo" && !expanded_p.is_absolute() && !has_explicit_dot_segment(expanded_p) {
                continue;
            }
            let sensitivity = self.fs_engine.classify_path_sensitivity(expanded_p);
            match sensitivity {
                PathSensitivity::SensitiveDotPath
                    if !self.is_session_granted(capability_id, args) =>
                {
                    return Some(format!(
                        "访问隐藏/敏感配置路径（{}），需人工确认授权",
                        raw_s
                    ));
                }
                PathSensitivity::OutsideScope
                    if expanded_p.is_absolute()
                        && key != "repo"
                        && !self.is_session_granted(capability_id, args) =>
                {
                    return Some(format!(
                        "访问常规用户目录外的系统或外部路径（{}），需人工确认授权",
                        raw_s
                    ));
                }
                _ => {}
            }
        }
        None
    }

    /// Issue a nonce-bound `PendingApproval` tied to canonical argument digest (§10.5).
    pub fn issue_pending_approval(
        &self,
        task_id: &str,
        desc: &CapabilityDescriptor,
        args: &Value,
        reason: &str,
        reversible: bool,
    ) -> PendingApproval {
        let approval_id = format!("apr_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let digest = PendingApproval::compute_digest(&desc.id, args);
        let now = Utc::now();
        let diff_preview = build_diff_preview(desc, args, reason, reversible);

        let pa = PendingApproval {
            approval_id: approval_id.clone(),
            task_id: task_id.to_string(),
            capability_id: desc.id.clone(),
            arguments: args.clone(),
            summary: format!("{}（{}）", desc.summary, reason),
            diff_preview,
            effects: desc.effects.clone(),
            reversible,
            nonce,
            digest,
            created_at: now,
            expires_at: now + Duration::minutes(10),
        };
        self.pending_approvals
            .lock()
            .unwrap()
            .insert(approval_id, pa.clone());
        pa
    }

    /// Verify and atomically consume a PendingApproval (prevents forgery, mismatch, expiry, and replay, §10.5, §19.2).
    pub fn verify_and_consume(
        &self,
        approval_id: &str,
        nonce: &str,
        digest: &str,
    ) -> Result<PendingApproval, String> {
        let mut map = self.pending_approvals.lock().unwrap();
        let Some(existing) = map.get(approval_id) else {
            return Err("审批单不存在或已被消费（拒绝重放）".into());
        };
        if Utc::now() > existing.expires_at {
            map.remove(approval_id);
            return Err("审批请求已过期".into());
        }
        if existing.nonce != nonce {
            return Err("审批 nonce 校验失败（拒绝伪造）".into());
        }
        if existing.digest != digest {
            return Err("审批参数摘要不一致（参数已被篡改）".into());
        }
        Ok(map.remove(approval_id).unwrap())
    }

    pub fn peek_pending_approval(&self, approval_id: &str) -> Option<PendingApproval> {
        let mut map = self.pending_approvals.lock().unwrap();
        let now = Utc::now();
        map.retain(|_, v| v.expires_at > now);
        map.get(approval_id).cloned()
    }

    pub fn deny_and_remove(&self, approval_id: &str) -> Option<PendingApproval> {
        self.pending_approvals.lock().unwrap().remove(approval_id)
    }
}

fn classify_risk_tier_tag(desc: &CapabilityDescriptor, reason: &str, reversible: bool) -> &'static str {
    let max_eff = desc.max_effect();
    if matches!(
        max_eff,
        Effect::WriteDestructive | Effect::ExternalCommit | Effect::SystemAdmin
    ) {
        "🚨 风险等级: R3 高危不可逆操作"
    } else if reason.contains("敏感配置路径")
        || reason.contains("系统或外部路径")
        || matches!(max_eff, Effect::ProcessControl | Effect::Egress)
        || desc.id == "app.quit"
        || !reversible
    {
        "⚠️ 风险等级: R2 敏感路径或进程控制"
    } else {
        "🛡️ 风险等级: R1 可逆变更"
    }
}

fn build_diff_preview(
    desc: &CapabilityDescriptor,
    args: &Value,
    reason: &str,
    reversible: bool,
) -> String {
    let cap_id = desc.id.as_str();
    let risk_tag = classify_risk_tier_tag(desc, reason, reversible);
    let undo_tag = if reversible {
        "✅ 可通过变更集一键撤销"
    } else {
        "⚠️ 不可自动撤销"
    };

    match cap_id {
        "file.open" | "file.open_with" | "file.reveal" => {
            let target_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            let app_line = args
                .get("app")
                .and_then(|v| v.as_str())
                .map(|a| format!("\n  打开应用: {}", a))
                .unwrap_or_default();
            format!(
                "{}\n操作: 打开/定位文件\n  目标路径: {}{}\n原因: {}\n撤销保障: {}",
                risk_tag, target_path, app_line, reason, undo_tag
            )
        }
        "file.move" | "file.copy" | "file.rename" => format!(
            "{}\n操作: {}\n- 源路径: {}\n+ 目标路径: {}\n原因: {}\n撤销保障: {}",
            risk_tag,
            desc.summary,
            args.get("source")
                .or_else(|| args.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            args.get("target")
                .or_else(|| args.get("destination"))
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            reason,
            undo_tag
        ),
        "file.trash" => format!(
            "{}\n操作: 移入回收站\n- 原路径: {}\n+ 回收站: freedesktop Trash\n原因: {}\n撤销保障: {}",
            risk_tag,
            args.get("path").and_then(|v| v.as_str()).unwrap_or("?"),
            reason,
            undo_tag
        ),
        "file.write" => format!(
            "{}\n操作: 写入文件\n~ 目标路径: {}\n  写入字节数: {}\n原因: {}\n撤销保障: {}",
            risk_tag,
            args.get("path").and_then(|v| v.as_str()).unwrap_or("?"),
            args.get("content")
                .and_then(|v| v.as_str())
                .map(|s| s.len())
                .unwrap_or(0),
            reason,
            undo_tag
        ),
        "app.quit" | "process.terminate" => format!(
            "{}\n操作: {}\n  目标应用/进程: {}\n原因: {}\n撤销保障: {}",
            risk_tag,
            desc.summary,
            args.get("app")
                .or_else(|| args.get("pid"))
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            reason,
            undo_tag
        ),
        _ => {
            let target_hint = args
                .get("path")
                .or_else(|| args.get("target"))
                .or_else(|| args.get("directory"))
                .or_else(|| args.get("app"))
                .and_then(|v| v.as_str())
                .map(|t| format!("\n目标对象: {}", t))
                .unwrap_or_default();
            format!(
                "{}\n能力: {}{}\n参数: {}\n原因: {}\n撤销保障: {}",
                risk_tag,
                cap_id,
                target_hint,
                serde_json::to_string_pretty(args).unwrap_or_default(),
                reason,
                undo_tag
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_capability_sdk::load_descriptors_from_dir;
    use serde_json::json;
    use tempfile::TempDir;

    fn setup_policy() -> (TempDir, Arc<SafeFsEngine>, PolicyEngine, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let auth = tmp.path().join("桌面");
        std::fs::create_dir_all(&auth).unwrap();
        let fs_eng = Arc::new(
            SafeFsEngine::new(
                vec![auth.clone()],
                vec![],
                tmp.path().join("undo"),
                tmp.path().join("trash"),
            )
            .unwrap(),
        );
        let policy = PolicyEngine::new(fs_eng.clone());
        (tmp, fs_eng, policy, auth)
    }

    #[test]
    fn untrusted_taint_escalates_write_and_nonce_blocks_replay_or_forgery() {
        let (_tmp, _fs_eng, policy, auth) = setup_policy();

        let fs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/filesystem");
        let descs = load_descriptors_from_dir(&fs_dir).unwrap();
        let move_desc = descs.iter().find(|d| d.id == "file.move").unwrap();

        let src = auth.join("a.pdf").to_string_lossy().to_string();
        let dst = auth.join("sub/a.pdf").to_string_lossy().to_string();
        let args = json!({"source": src, "target": dst});

        // Clean explicit user small move -> AllowWithUndo
        assert_eq!(
            policy.evaluate(
                move_desc,
                &args,
                InvocationOrigin::UserExplicit,
                &[Taint::User],
                1,
                true
            ),
            PolicyDecision::AllowWithUndo
        );

        // Same move when context contains local.untrusted (prompt injection guard!) -> PreviewAndApprove!
        let tainted = policy.evaluate(
            move_desc,
            &args,
            InvocationOrigin::UserExplicit,
            &[Taint::User, Taint::LocalUntrusted],
            1,
            true,
        );
        assert!(tainted.requires_approval());

        // Forbidden SSH key path -> hard Deny!
        let bad_args = json!({"source": "/home/user/.ssh/id_ed25519", "target": dst});
        assert!(
            policy
                .evaluate(
                    move_desc,
                    &bad_args,
                    InvocationOrigin::UserExplicit,
                    &[],
                    1,
                    true
                )
                .is_denied()
        );

        // Nonce approval verification & anti-replay
        let pa = policy.issue_pending_approval("task_99", move_desc, &args, "test", true);
        assert!(pa.diff_preview.contains("🛡️ 风险等级: R1 可逆变更"));
        assert!(
            policy
                .verify_and_consume(&pa.approval_id, "wrong_nonce", &pa.digest)
                .is_err()
        );
        assert!(
            policy
                .verify_and_consume(&pa.approval_id, &pa.nonce, "sha256:tampered")
                .is_err()
        );
        assert!(
            policy
                .verify_and_consume(&pa.approval_id, &pa.nonce, &pa.digest)
                .is_ok()
        );
        // Replay of already consumed approval MUST fail!
        assert!(
            policy
                .verify_and_consume(&pa.approval_id, &pa.nonce, &pa.digest)
                .is_err()
        );
    }

    #[test]
    fn four_tier_sensitivity_interactive_approval_and_session_scope_grants() {
        let (tmp, fs_eng, policy, auth) = setup_policy();

        let fs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/filesystem");
        let descs = load_descriptors_from_dir(&fs_dir).unwrap();
        let open_desc = descs.iter().find(|d| d.id == "file.open").unwrap();
        let write_desc = descs.iter().find(|d| d.id == "file.write").unwrap();

        // (d) NormalUserSpace (Chinese Desktop `桌面/paper_main.docx`) `file.open` -> Allow!
        let thesis_path = auth.join("paper_main.docx").to_string_lossy().to_string();
        assert_eq!(
            policy.evaluate(
                open_desc,
                &json!({ "path": thesis_path }),
                InvocationOrigin::UserExplicit,
                &[Taint::User],
                1,
                true,
            ),
            PolicyDecision::Allow
        );

        // (a) Forbidden paths (`~/.ssh/id_ed25519` and `/etc/shadow`) -> ALWAYS hard Deny!
        policy.set_security_mode("developer");
        let _ = policy.add_session_grant("directory", "~/.ssh", 60);
        for forbidden in ["~/.ssh/id_ed25519", "/home/user/.ssh/id_ed25519", "/etc/shadow"] {
            let dec = policy.evaluate(
                open_desc,
                &json!({ "path": forbidden }),
                InvocationOrigin::UserExplicit,
                &[Taint::User],
                1,
                true,
            );
            assert!(dec.is_denied(), "{} must be hard Deny, got {:?}", forbidden, dec);
        }
        policy.set_security_mode("balanced");

        // (b) OutsideScope (`/opt/demo/test.txt`) and SensitiveDotPath (`~/.config/demo.conf`)
        //     MUST return PreviewAndApprove (NOT Deny!), even for `file.open`!
        let outside_dec = policy.evaluate(
            open_desc,
            &json!({ "path": "/opt/demo/test.txt" }),
            InvocationOrigin::UserExplicit,
            &[Taint::User],
            1,
            true,
        );
        assert!(
            matches!(outside_dec, PolicyDecision::PreviewAndApprove { ref reason } if reason.contains("访问常规用户目录外的系统或外部路径")),
            "expected PreviewAndApprove for /opt/demo/test.txt, got {:?}",
            outside_dec
        );
        assert!(!outside_dec.is_denied());

        let dot_dec = policy.evaluate(
            open_desc,
            &json!({ "path": "~/.config/demo.conf" }),
            InvocationOrigin::UserExplicit,
            &[Taint::User],
            1,
            true,
        );
        assert!(
            matches!(dot_dec, PolicyDecision::PreviewAndApprove { ref reason } if reason.contains("访问隐藏/敏感配置路径")),
            "expected PreviewAndApprove for ~/.config/demo.conf, got {:?}",
            dot_dec
        );
        assert!(!dot_dec.is_denied());

        // Verify enriched R2 diff_preview on sensitive PendingApproval
        let pa = policy.issue_pending_approval(
            "task_dot",
            open_desc,
            &json!({ "path": "~/.config/demo.conf" }),
            "访问隐藏/敏感配置路径（~/.config/demo.conf），需人工确认授权",
            false,
        );
        assert!(pa.diff_preview.contains("⚠️ 风险等级: R2 敏感路径或进程控制"));

        // (c) Session Scope Grant allows OutsideScope directory & syncs `fs_engine.approve_path_scope`!
        let ext_dir = tmp.path().join("external_project");
        std::fs::create_dir_all(&ext_dir).unwrap();
        let ext_file = ext_dir.join("notes.txt").to_string_lossy().to_string();

        assert!(
            policy
                .evaluate(
                    open_desc,
                    &json!({ "path": ext_file }),
                    InvocationOrigin::UserExplicit,
                    &[Taint::User],
                    1,
                    true,
                )
                .requires_approval()
        );

        let grant = policy.add_session_grant("directory", &ext_dir.to_string_lossy(), 60);
        let grant_id = grant["id"].as_str().unwrap().to_string();
        assert_eq!(policy.list_session_grants().len(), 1);

        assert_eq!(
            policy.evaluate(
                open_desc,
                &json!({ "path": ext_file }),
                InvocationOrigin::UserExplicit,
                &[Taint::User],
                1,
                true,
            ),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(
                write_desc,
                &json!({ "path": ext_file, "content": "hi" }),
                InvocationOrigin::L2AgentPlan,
                &[Taint::User],
                1,
                true,
            ),
            PolicyDecision::AllowWithUndo
        );
        assert!(fs_eng.list_approved_roots().contains(&ext_dir));

        // Revoking session grant restores PreviewAndApprove requirement
        assert!(policy.revoke_session_grant(&grant_id));
        assert!(policy.list_session_grants().is_empty());
        assert!(
            policy
                .evaluate(
                    open_desc,
                    &json!({ "path": ext_file }),
                    InvocationOrigin::UserExplicit,
                    &[Taint::User],
                    1,
                    true,
                )
                .requires_approval()
        );
    }

    #[test]
    fn home_directory_session_grant_covers_search_and_dot_children_while_blocking_ssh() {
        let (_tmp, fs_eng, policy, auth) = setup_policy();

        let fs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../modules/builtin/filesystem");
        let descs = load_descriptors_from_dir(&fs_dir).unwrap();
        let search_desc = descs.iter().find(|d| d.id == "file.search").unwrap();
        let open_desc = descs.iter().find(|d| d.id == "file.open").unwrap();
        let copy_desc = descs.iter().find(|d| d.id == "file.copy").unwrap();

        let home_search_args = json!({ "directory": "/home", "query": "文档" });
        let child_dot_args = json!({ "path": "/home/alice/.config/foo" });

        // Before session grant: `/home` and `/home/alice/.config/foo` require interactive approval
        assert!(
            policy
                .evaluate(
                    search_desc,
                    &home_search_args,
                    InvocationOrigin::L2AgentPlan,
                    &[Taint::User],
                    1,
                    true,
                )
                .requires_approval()
        );
        assert!(
            policy
                .evaluate(
                    open_desc,
                    &child_dot_args,
                    InvocationOrigin::L2AgentPlan,
                    &[Taint::User],
                    1,
                    true,
                )
                .requires_approval()
        );

        // Grant `/home/` (with trailing slash to verify path normalization)
        let grant = policy.add_session_grant("directory", "/home/", 60);
        assert_eq!(grant["scope_kind"], "directory");
        assert_eq!(grant["scope_value"], "/home");
        assert!(fs_eng.list_approved_roots().contains(&PathBuf::from("/home")));

        // Subsequent turns in the same session MUST NOT re-prompt for `/home` or child dot-paths!
        assert!(policy.is_session_granted("file.search", &home_search_args));
        assert_eq!(
            policy.evaluate(
                search_desc,
                &home_search_args,
                InvocationOrigin::L2AgentPlan,
                &[Taint::User],
                1,
                true,
            ),
            PolicyDecision::Allow
        );

        assert!(policy.is_session_granted("file.open", &child_dot_args));
        assert_eq!(
            policy.evaluate(
                open_desc,
                &child_dot_args,
                InvocationOrigin::L2AgentPlan,
                &[Taint::User],
                1,
                true,
            ),
            PolicyDecision::Allow
        );

        // Mixed granted child path + NormalUserSpace target path is also covered without re-prompting
        let mixed_copy_args = json!({
            "source": "/home/alice/.config/foo",
            "target": auth.join("foo_backup").to_string_lossy().to_string(),
        });
        assert!(policy.is_session_granted("file.copy", &mixed_copy_args));
        assert_eq!(
            policy.evaluate(
                copy_desc,
                &mixed_copy_args,
                InvocationOrigin::L2AgentPlan,
                &[Taint::User],
                1,
                true,
            ),
            PolicyDecision::AllowWithUndo
        );

        // Forbidden `~/.ssh` paths MUST still be strictly blocked even under `/home` grant!
        for ssh_path in [
            "~/.ssh",
            "~/.ssh/id_ed25519",
            "/home/alice/.ssh/id_rsa",
            "/home/alice/.ssh/authorized_keys",
        ] {
            assert!(
                !policy.is_session_granted("file.open", &json!({ "path": ssh_path })),
                "is_session_granted must reject {}",
                ssh_path
            );
            assert!(
                policy
                    .evaluate(
                        open_desc,
                        &json!({ "path": ssh_path }),
                        InvocationOrigin::UserExplicit,
                        &[Taint::User],
                        1,
                        true,
                    )
                    .is_denied(),
                "evaluate must hard Deny {}",
                ssh_path
            );
            assert!(
                policy
                    .evaluate(
                        search_desc,
                        &json!({ "directory": ssh_path, "query": "key" }),
                        InvocationOrigin::L2AgentPlan,
                        &[Taint::User],
                        1,
                        true,
                    )
                    .is_denied(),
                "file.search must hard Deny {}",
                ssh_path
            );
        }
    }
}
