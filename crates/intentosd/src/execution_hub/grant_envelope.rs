#![forbid(unsafe_code)]

//! Grant Envelope Manager, Boundary Validator & Progressive Trust Engine (`docs/IntentOS_设计方案_v0.3.md` §10.3).
//!
//! Responsibilities:
//! 1. Multi-step `GrantEnvelope` lifecycle (`create_grant_envelope`, `check_within_envelope`, `revoke_grant_or_rule`).
//! 2. Boundary checks: `capabilities`, `resource_scope`, `max_effect`, `max_operations`, `network`, and `expires_at`.
//! 3. Progressive Trust (`RuleProposal`): after `>= 3` consecutive approvals for the same `(capability_id, resource_scope)`,
//!    proposes a narrow long-term rule (`max_effect <= Effect::WriteReversible`, never overriding `confirm_each` effects).
//! 4. Approval Fatigue Metrics: tracks total approvals, rejections, approval/rejection rates, average decision time (ms),
//!    and flags approval fatigue when decision time is very short and rejection rate is near zero.

use crate::core::IntentOsCore;
use chrono::{DateTime, Duration, Utc};
use intentos_protocol::{CapabilityCall, Effect, GrantEnvelope, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeRecord {
    pub envelope: GrantEnvelope,
    pub used_operations: u32,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EnvelopeCheckOutcome {
    Allowed {
        envelope_id: String,
        used_operations: u32,
        remaining_operations: u32,
    },
    OutOfBounds {
        reason: String,
        violation_kind: String,
    },
}

impl EnvelopeCheckOutcome {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProposal {
    pub proposal_id: String,
    pub capability_id: String,
    pub resource_scope: String,
    pub max_effect: Effect,
    pub max_operations: u32,
    pub consecutive_approvals: u32,
    pub summary: String,
    pub status: String, // "pending" | "confirmed" | "dismissed"
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedRule {
    pub rule_id: String,
    pub proposal_id: Option<String>,
    pub capability_id: String,
    pub resource_scope: String,
    pub max_effect: Effect,
    pub max_operations: u32,
    pub summary: String,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalFatigueMetrics {
    pub total_decisions: u64,
    pub approved_count: u64,
    pub rejected_count: u64,
    pub approval_rate: f64,
    pub rejection_rate: f64,
    pub total_decision_ms: u64,
    pub avg_decision_ms: u64,
    pub fatigue_warning: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GrantHubStore {
    envelopes: BTreeMap<String, EnvelopeRecord>,
    consecutive_streaks: BTreeMap<String, u32>,
    rule_proposals: BTreeMap<String, RuleProposal>,
    trusted_rules: BTreeMap<String, TrustedRule>,
    metrics: ApprovalFatigueMetrics,
}

static GRANT_STORE: OnceLock<Mutex<HashMap<PathBuf, GrantHubStore>>> = OnceLock::new();

fn store_map() -> &'static Mutex<HashMap<PathBuf, GrantHubStore>> {
    GRANT_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn store_file_path(core: &IntentOsCore) -> PathBuf {
    core.paths.data_dir.join("execution_hub_grants.json")
}

fn with_store<F, R>(core: &IntentOsCore, f: F) -> R
where
    F: FnOnce(&mut GrantHubStore) -> R,
{
    let mut map = store_map().lock().unwrap();
    let entry = map.entry(core.paths.data_dir.clone()).or_insert_with(|| {
        let p = store_file_path(core);
        if p.exists()
            && let Ok(raw) = std::fs::read_to_string(&p)
            && let Ok(parsed) = serde_json::from_str::<GrantHubStore>(&raw)
        {
            return parsed;
        }
        GrantHubStore::default()
    });
    let out = f(entry);
    let p = store_file_path(core);
    if let Ok(serialized) = serde_json::to_string_pretty(entry) {
        let _ = std::fs::write(p, serialized);
    }
    out
}

pub fn normalize_scope_path(raw: &str) -> String {
    let trimmed = raw.trim();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    if let Some(rest) = trimmed.strip_prefix("~/") {
        return PathBuf::from(home).join(rest).to_string_lossy().to_string();
    }
    if trimmed == "~" {
        return home;
    }
    if let Some(dir_tag) = trimmed.strip_prefix("resource://directory/") {
        let mapped = match dir_tag {
            "downloads" => PathBuf::from(&home).join("Downloads"),
            "documents" => PathBuf::from(&home).join("Documents"),
            "documents-papers" => PathBuf::from(&home).join("Documents/papers"),
            "desktop" => PathBuf::from(&home).join("Desktop"),
            "code" | "workspace" => PathBuf::from(&home).join(dir_tag),
            other => PathBuf::from(&home).join(other),
        };
        return mapped.to_string_lossy().to_string();
    }
    trimmed.to_string()
}

pub fn parse_effect_str(raw: &str) -> Effect {
    match raw.trim() {
        "observe" => Effect::Observe,
        "ui" => Effect::Ui,
        "setting" => Effect::Setting,
        "exec.sandboxed" => Effect::ExecSandboxed,
        "write.reversible" => Effect::WriteReversible,
        "egress" => Effect::Egress,
        "process.control" => Effect::ProcessControl,
        "write.destructive" => Effect::WriteDestructive,
        "external.commit" => Effect::ExternalCommit,
        "system.admin" => Effect::SystemAdmin,
        _ => Effect::WriteReversible,
    }
}

/// Returns true if an effect is in the `confirm_each` high-risk tier (§10.2, §10.3).
/// Long-term progressive trust rules MUST NEVER override `confirm_each` effects.
pub fn is_confirm_each_effect(effect: Effect) -> bool {
    matches!(
        effect,
        Effect::Egress
            | Effect::ProcessControl
            | Effect::WriteDestructive
            | Effect::ExternalCommit
            | Effect::SystemAdmin
    )
}

/// Create and activate a task `GrantEnvelope` (§10.3).
pub fn create_grant_envelope(
    core: &IntentOsCore,
    payload: &Value,
) -> anyhow::Result<EnvelopeRecord> {
    let task_id = payload
        .get("task_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("task_default")
        .to_string();

    let capabilities: Vec<String> = payload
        .get("capabilities")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|| vec!["file.search".to_string(), "file.move".to_string()]);

    if capabilities.is_empty() {
        anyhow::bail!("GrantEnvelope 必须至少声明一项允许的能力 (capabilities)");
    }
    // Never mint an envelope explicitly covering shell/terminal execution.
    // Historic wildcard grants are also blocked at the consume boundary.
    if capabilities.iter().any(|c| matches!(c.as_str(), "terminal.execute" | "terminal_execute" | "terminal.*")) {
        anyhow::bail!("terminal.execute 仅允许本次审批，不得创建会话/任务批量授权");
    }

    let raw_scopes: Vec<String> = payload
        .get("resource_scope")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(normalize_scope_path))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|| {
            core.fs_engine
                .authorized_roots()
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect()
        });

    for scope in &raw_scopes {
        if core.fs_engine.is_forbidden(Path::new(scope)) {
            anyhow::bail!("禁止将受保护路径 (forbidden) 纳入授权包络: {}", scope);
        }
    }

    let max_effect = payload
        .get("max_effect")
        .and_then(|v| v.as_str())
        .map(parse_effect_str)
        .unwrap_or(Effect::WriteReversible);

    if max_effect == Effect::SystemAdmin {
        anyhow::bail!("安全限制：system.admin 特权效应不可通过 GrantEnvelope 批量放行");
    }

    let max_operations = payload
        .get("max_operations")
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .clamp(1, 5000) as u32;

    let network = payload
        .get("network")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let ttl_minutes = payload
        .get("ttl_minutes")
        .and_then(|v| v.as_i64())
        .unwrap_or(30)
        .clamp(1, 24 * 60);

    let now = Utc::now();
    let envelope_id = format!("env_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let nonce = uuid::Uuid::new_v4().simple().to_string();

    let envelope = GrantEnvelope {
        envelope_id: envelope_id.clone(),
        task_id: task_id.clone(),
        capabilities: capabilities.clone(),
        resource_scope: raw_scopes.clone(),
        max_effect,
        max_operations,
        network,
        expires_at: now + Duration::minutes(ttl_minutes),
        nonce,
        policy_version: PROTOCOL_VERSION,
    };

    let record = EnvelopeRecord {
        envelope: envelope.clone(),
        used_operations: 0,
        created_at: now,
        revoked: false,
    };

    let decision_ms = payload
        .get("decision_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(2200);

    with_store(core, |store| {
        store.envelopes.insert(envelope_id.clone(), record.clone());
        // Record approval toward progressive trust for each (capability, scope)
        for cap in &capabilities {
            for sc in &raw_scopes {
                record_approval_in_store(store, cap, sc, max_effect, true, decision_ms);
            }
        }
    });

    let _ = core.state_db.record_audit(
        Some(&task_id),
        "grant.create_envelope",
        "user_explicit",
        max_effect.as_str(),
        "allow",
        "created",
        &json!({
            "envelope_id": envelope_id,
            "capabilities": capabilities,
            "resource_scope": raw_scopes,
            "max_operations": max_operations,
        }),
        Some("已创建任务级授权包络"),
    );

    Ok(record)
}

/// Validate whether a capability invocation falls strictly within an active `GrantEnvelope` (§10.3).
pub fn check_within_envelope(
    core: &IntentOsCore,
    envelope_id: &str,
    call: &CapabilityCall,
    call_effect: Effect,
    operation_count: u32,
    requires_network: bool,
) -> EnvelopeCheckOutcome {
    let op_count = operation_count.max(1);

    // SC-09 deny terminal even with historic wildcard envelopes or a
    // falsified low effect; real approval requires a unique nonce/digest.
    if matches!(call.capability_id.as_str(), "terminal.execute" | "terminal_execute") {
        return EnvelopeCheckOutcome::OutOfBounds {
            reason: "terminal.execute 必须逐次审批，禁止复用授权包络".into(),
            violation_kind: "terminal_requires_single_use_approval".into(),
        };
    }

    // 1. Check untrusted taint escalation (§10.4): untrusted context cannot silently bypass approval for writes/egress
    if call.taints.iter().any(|t| t.is_untrusted()) && call_effect >= Effect::WriteReversible {
        return EnvelopeCheckOutcome::OutOfBounds {
            reason:
                "上下文包含不可信来源 (untrusted taint)，写操作需独立预览审批，不能直接沿用包络"
                    .to_string(),
            violation_kind: "untrusted_taint".to_string(),
        };
    }

    with_store(core, |store| {
        let Some(rec) = store.envelopes.get_mut(envelope_id) else {
            return EnvelopeCheckOutcome::OutOfBounds {
                reason: format!("授权包络不存在: {}", envelope_id),
                violation_kind: "not_found".to_string(),
            };
        };

        if rec.revoked {
            return EnvelopeCheckOutcome::OutOfBounds {
                reason: format!("授权包络 {} 已被撤销", envelope_id),
                violation_kind: "revoked".to_string(),
            };
        }

        if Utc::now() > rec.envelope.expires_at {
            return EnvelopeCheckOutcome::OutOfBounds {
                reason: format!("授权包络 {} 已过期", envelope_id),
                violation_kind: "expired".to_string(),
            };
        }

        // 2. Check capability match
        let cap_matched = rec.envelope.capabilities.iter().any(|allowed| {
            if allowed == "*" || allowed == &call.capability_id {
                true
            } else if let Some(prefix) = allowed.strip_suffix(".*") {
                call.capability_id.starts_with(prefix)
            } else {
                false
            }
        });
        if !cap_matched {
            return EnvelopeCheckOutcome::OutOfBounds {
                reason: format!(
                    "能力 `{}` 不在授权包络允许列表 {:?} 内",
                    call.capability_id, rec.envelope.capabilities
                ),
                violation_kind: "capability_not_in_envelope".to_string(),
            };
        }

        // 3. Check effect ceiling & confirm_each restriction
        if is_confirm_each_effect(call_effect) {
            return EnvelopeCheckOutcome::OutOfBounds {
                reason: format!(
                    "高危效应 `{}` 属于逐次确认 (confirm_each) 等级，不可由包络自动放行",
                    call_effect.as_str()
                ),
                violation_kind: "effect_requires_confirm_each".to_string(),
            };
        }
        if call_effect > rec.envelope.max_effect {
            return EnvelopeCheckOutcome::OutOfBounds {
                reason: format!(
                    "调用效应 `{}` 超出包络最高效应上限 `{}`",
                    call_effect.as_str(),
                    rec.envelope.max_effect.as_str()
                ),
                violation_kind: "effect_exceeded".to_string(),
            };
        }

        // 4. Check network permission
        if requires_network && !rec.envelope.network {
            return EnvelopeCheckOutcome::OutOfBounds {
                reason: "该步骤需要访问网络，但当前授权包络禁止网络访问 (network=false)"
                    .to_string(),
                violation_kind: "network_not_allowed".to_string(),
            };
        }

        // 5. Check resource scope for all path arguments
        let extracted_paths = extract_paths_from_args(&call.arguments);
        for raw_p in &extracted_paths {
            let norm_p = normalize_scope_path(raw_p);
            let p_path = Path::new(&norm_p);
            if core.fs_engine.is_forbidden(p_path) {
                return EnvelopeCheckOutcome::OutOfBounds {
                    reason: format!("目标路径属于受保护禁止访问区域 (forbidden): {}", norm_p),
                    violation_kind: "forbidden_path".to_string(),
                };
            }
            let in_scope = rec.envelope.resource_scope.iter().any(|scope_str| {
                let norm_scope = normalize_scope_path(scope_str);
                p_path.starts_with(Path::new(&norm_scope))
            });
            if !in_scope {
                return EnvelopeCheckOutcome::OutOfBounds {
                    reason: format!(
                        "路径 `{}` 超出授权包络资源范围 {:?}",
                        norm_p, rec.envelope.resource_scope
                    ),
                    violation_kind: "scope_exceeded".to_string(),
                };
            }
        }

        // 6. Check max_operations quota
        if rec.used_operations.saturating_add(op_count) > rec.envelope.max_operations {
            return EnvelopeCheckOutcome::OutOfBounds {
                reason: format!(
                    "操作次数超出包络上限（已用 {} + 本次 {} > 上限 {}）",
                    rec.used_operations, op_count, rec.envelope.max_operations
                ),
                violation_kind: "max_operations_exceeded".to_string(),
            };
        }

        rec.used_operations += op_count;
        let remaining = rec
            .envelope
            .max_operations
            .saturating_sub(rec.used_operations);
        EnvelopeCheckOutcome::Allowed {
            envelope_id: rec.envelope.envelope_id.clone(),
            used_operations: rec.used_operations,
            remaining_operations: remaining,
        }
    })
}

fn extract_paths_from_args(args: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(obj) = args.as_object() else {
        return out;
    };
    for key in [
        "path",
        "source",
        "target",
        "directory",
        "repo_dir",
        "output",
        "destination",
        "target_dir",
    ] {
        if let Some(s) = obj.get(key).and_then(|v| v.as_str())
            && !s.trim().is_empty()
        {
            out.push(s.to_string());
        }
    }
    if let Some(arr) = obj.get("sources").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str()
                && !s.trim().is_empty()
            {
                out.push(s.to_string());
            }
        }
    }
    out
}

/// Record a user approval or rejection decision and trigger Progressive Trust rule proposals after >= 3 consecutive approvals (§10.3).
pub fn record_approval_decision(
    core: &IntentOsCore,
    capability_id: &str,
    resource_scope: &str,
    effect: Effect,
    approved: bool,
    decision_ms: u64,
) -> Option<RuleProposal> {
    let norm_scope = normalize_scope_path(resource_scope);
    with_store(core, |store| {
        record_approval_in_store(
            store,
            capability_id,
            &norm_scope,
            effect,
            approved,
            decision_ms,
        )
    })
}

fn record_approval_in_store(
    store: &mut GrantHubStore,
    capability_id: &str,
    norm_scope: &str,
    effect: Effect,
    approved: bool,
    decision_ms: u64,
) -> Option<RuleProposal> {
    store.metrics.total_decisions += 1;
    if approved {
        store.metrics.approved_count += 1;
    } else {
        store.metrics.rejected_count += 1;
    }
    store.metrics.total_decision_ms = store.metrics.total_decision_ms.saturating_add(decision_ms);
    store.metrics.avg_decision_ms =
        store.metrics.total_decision_ms / store.metrics.total_decisions.max(1);
    store.metrics.approval_rate =
        store.metrics.approved_count as f64 / store.metrics.total_decisions as f64;
    store.metrics.rejection_rate =
        store.metrics.rejected_count as f64 / store.metrics.total_decisions as f64;
    store.metrics.fatigue_warning = store.metrics.total_decisions >= 5
        && store.metrics.avg_decision_ms < 1500
        && store.metrics.rejection_rate < 0.05;

    let key = format!("{}@{}", capability_id.trim(), norm_scope);
    if !approved {
        store.consecutive_streaks.insert(key, 0);
        return None;
    }

    // Never propose progressive trust rules for `confirm_each` high-risk effects (§10.3)
    if is_confirm_each_effect(effect) {
        return None;
    }

    let count = store
        .consecutive_streaks
        .entry(key)
        .and_modify(|c| *c += 1)
        .or_insert(1);
    let current_streak = *count;

    if current_streak >= 3 {
        if let Some(existing) = store.rule_proposals.values_mut().find(|p| {
            p.capability_id == capability_id
                && p.resource_scope == norm_scope
                && p.status != "dismissed"
        }) {
            existing.consecutive_approvals = current_streak;
            return Some(existing.clone());
        }

        let capped_effect = effect.min(Effect::WriteReversible);
        let proposal_id = format!("prop_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        let summary = format!(
            "允许在 `{}` 内自动执行 `{}`（单次最多 50 个对象，最高效应 {}，支持一键撤销）",
            norm_scope,
            capability_id,
            capped_effect.as_str()
        );
        let proposal = RuleProposal {
            proposal_id: proposal_id.clone(),
            capability_id: capability_id.to_string(),
            resource_scope: norm_scope.to_string(),
            max_effect: capped_effect,
            max_operations: 50,
            consecutive_approvals: current_streak,
            summary,
            status: "pending".to_string(),
            created_at: Utc::now(),
        };
        store.rule_proposals.insert(proposal_id, proposal.clone());
        return Some(proposal);
    }

    None
}

/// Confirm a pending `RuleProposal` and convert it into an active long-term `TrustedRule` (§10.3).
pub fn confirm_rule_proposal(
    core: &IntentOsCore,
    proposal_id: &str,
) -> anyhow::Result<TrustedRule> {
    let rule = with_store(core, |store| -> anyhow::Result<TrustedRule> {
        let prop = store
            .rule_proposals
            .get_mut(proposal_id)
            .ok_or_else(|| anyhow::anyhow!("未找到渐进信任规则提议: {}", proposal_id))?;

        if is_confirm_each_effect(prop.max_effect) {
            anyhow::bail!(
                "安全违规：长期规则绝不允许覆盖 confirm_each 高危效应 ({})",
                prop.max_effect.as_str()
            );
        }

        prop.status = "confirmed".to_string();
        let rule_id = format!("rule_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        let rule = TrustedRule {
            rule_id: rule_id.clone(),
            proposal_id: Some(prop.proposal_id.clone()),
            capability_id: prop.capability_id.clone(),
            resource_scope: prop.resource_scope.clone(),
            max_effect: prop.max_effect.min(Effect::WriteReversible),
            max_operations: prop.max_operations,
            summary: prop.summary.clone(),
            created_at: Utc::now(),
            revoked: false,
        };
        store.trusted_rules.insert(rule_id, rule.clone());
        Ok(rule)
    })?;

    let _ = core.state_db.record_audit(
        None,
        "grant.confirm_rule",
        "user_explicit",
        rule.max_effect.as_str(),
        "allow",
        "confirmed",
        &json!({
            "rule_id": rule.rule_id,
            "proposal_id": proposal_id,
            "capability_id": rule.capability_id,
            "resource_scope": rule.resource_scope,
        }),
        Some(&rule.summary),
    );

    Ok(rule)
}

/// Revoke an active `GrantEnvelope`, a long-term `TrustedRule`, or dismiss a `RuleProposal`.
pub fn revoke_grant_or_rule(core: &IntentOsCore, id: &str) -> anyhow::Result<Value> {
    let outcome = with_store(core, |store| -> anyhow::Result<Value> {
        if let Some(env) = store.envelopes.get_mut(id) {
            env.revoked = true;
            return Ok(json!({
                "revoked": true,
                "id": id,
                "kind": "envelope",
                "message": format!("已撤销任务授权包络 {}", id),
            }));
        }
        if let Some(rule) = store.trusted_rules.get_mut(id) {
            rule.revoked = true;
            return Ok(json!({
                "revoked": true,
                "id": id,
                "kind": "rule",
                "message": format!("已撤销长期信任规则 {}", id),
            }));
        }
        if let Some(prop) = store.rule_proposals.get_mut(id) {
            prop.status = "dismissed".to_string();
            return Ok(json!({
                "revoked": true,
                "id": id,
                "kind": "proposal",
                "message": format!("已忽略渐进信任提议 {}", id),
            }));
        }
        anyhow::bail!("未找到指定的授权包络或信任规则 ID: {}", id)
    })?;

    let _ = core.state_db.record_audit(
        None,
        "grant.revoke",
        "user_explicit",
        "observe",
        "allow",
        "revoked",
        &json!({ "id": id }),
        Some("已撤销授权包络或信任规则"),
    );

    Ok(outcome)
}

/// List all active/recent envelopes, long-term rules, pending rule proposals, and approval fatigue metrics.
pub fn list_envelopes_and_rules(core: &IntentOsCore) -> Value {
    with_store(core, |store| {
        let envelopes: Vec<Value> = store
            .envelopes
            .values()
            .rev()
            .map(|r| {
                json!({
                    "envelope_id": r.envelope.envelope_id,
                    "task_id": r.envelope.task_id,
                    "capabilities": r.envelope.capabilities,
                    "resource_scope": r.envelope.resource_scope,
                    "max_effect": r.envelope.max_effect,
                    "max_operations": r.envelope.max_operations,
                    "used_operations": r.used_operations,
                    "remaining_operations": r.envelope.max_operations.saturating_sub(r.used_operations),
                    "network": r.envelope.network,
                    "expires_at": r.envelope.expires_at,
                    "created_at": r.created_at,
                    "revoked": r.revoked,
                    "active": !r.revoked && Utc::now() <= r.envelope.expires_at,
                })
            })
            .collect();

        let rules: Vec<&TrustedRule> = store.trusted_rules.values().rev().collect();
        let proposals: Vec<&RuleProposal> = store.rule_proposals.values().rev().collect();

        json!({
            "envelopes": envelopes,
            "rules": rules,
            "trusted_rules": rules,
            "rule_proposals": proposals,
            "proposals": proposals,
            "metrics": store.metrics,
            "fatigue_metrics": store.metrics,
        })
    })
}

/// Inspect current runtime security posture, global/approved roots, session grants, and pending approvals.
pub fn get_security_posture(core: &IntentOsCore) -> Value {
    let authorized_roots: Vec<String> = core
        .fs_engine
        .authorized_roots()
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    let approved_roots: Vec<String> = core
        .fs_engine
        .list_approved_roots()
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    let policy = core.broker.policy();

    json!({
        "security_mode": policy.security_mode(),
        "authorized_roots": authorized_roots,
        "approved_roots": approved_roots,
        "session_grants": policy.list_session_grants(),
        "pending_approvals_count": policy.pending_count(),
    })
}

/// Update runtime security mode (`"strict" | "balanced" | "developer"`).
pub fn set_security_mode(core: &IntentOsCore, mode: &str) -> anyhow::Result<Value> {
    let normalized = match mode.trim().to_ascii_lowercase().as_str() {
        "strict" => "strict",
        "balanced" | "standard" => "balanced",
        "developer" | "dev" => "developer",
        other => anyhow::bail!(
            "不支持的安全防护模式 '{}'（可选: strict | balanced | developer）",
            other
        ),
    };
    core.broker.policy().set_security_mode(normalized);
    let active = core.broker.policy().security_mode();

    let _ = core.state_db.record_audit(
        None,
        "security.set_mode",
        "user_explicit",
        "setting",
        "allow",
        "updated",
        &json!({ "security_mode": active }),
        Some(&format!("已切换安全防护模式为 {}", active)),
    );

    Ok(json!({
        "ok": true,
        "security_mode": active,
        "mode": active,
    }))
}

/// Grant a temporary session scope (`"directory" | "capability" | "app"`) and sync `SafeFsEngine` for directories.
pub fn grant_session_scope(
    core: &IntentOsCore,
    scope_kind: &str,
    scope_value: &str,
    ttl_minutes: i64,
) -> anyhow::Result<Value> {
    let kind = match scope_kind.trim().to_ascii_lowercase().as_str() {
        "directory" | "dir" | "path" => "directory",
        "capability" | "cap" => "capability",
        "app" | "application" => "app",
        other => anyhow::bail!(
            "不支持的会话授权范围类型 '{}'（可选: directory | capability | app）",
            other
        ),
    };
    let trimmed_val = scope_value.trim();
    if trimmed_val.is_empty() {
        anyhow::bail!("会话授权范围值 (scope_value) 不能为空");
    }

    let (grant, approved_root) = if kind == "directory" {
        let norm = normalize_scope_path(trimmed_val);
        let target_path = Path::new(&norm);
        if core.fs_engine.is_forbidden(target_path) {
            anyhow::bail!(
                "禁止将受保护敏感路径 (forbidden) 纳入会话放行范围: {}",
                norm
            );
        }
        let scope_root = core
            .fs_engine
            .approve_path_scope(target_path)
            .map_err(|e| anyhow::anyhow!("目录会话授权失败: {}", e))?;
        let scope_str = scope_root.to_string_lossy().to_string();
        let grant_val =
            core.broker
                .policy()
                .add_session_grant("directory", &scope_str, ttl_minutes);
        (grant_val, Some(scope_str))
    } else {
        let grant_val = core
            .broker
            .policy()
            .add_session_grant(kind, trimmed_val, ttl_minutes);
        (grant_val, None)
    };

    let _ = core.state_db.record_audit(
        None,
        "security.grant_session_scope",
        "user_explicit",
        "setting",
        "allow",
        "granted",
        &json!({
            "scope_kind": kind,
            "scope_value": trimmed_val,
            "approved_root": approved_root,
            "ttl_minutes": ttl_minutes,
        }),
        Some("已授予本会话临时权限范围"),
    );

    Ok(json!({
        "ok": true,
        "grant": grant,
        "approved_root": approved_root,
        "session_grants": core.broker.policy().list_session_grants(),
    }))
}

/// Revoke an active session scope grant (and its approved `SafeFsEngine` root if `directory`).
pub fn revoke_session_grant(core: &IntentOsCore, id: &str) -> anyhow::Result<Value> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        anyhow::bail!("缺少要撤销的会话授权 ID");
    }
    let mut revoked = core.broker.policy().revoke_session_grant(trimmed);
    if !revoked && trimmed.starts_with('/') {
        revoked = core.fs_engine.revoke_approved_root(Path::new(trimmed));
    }

    let _ = core.state_db.record_audit(
        None,
        "security.revoke_session_grant",
        "user_explicit",
        "observe",
        "allow",
        if revoked { "revoked" } else { "not_found" },
        &json!({ "id": trimmed }),
        Some("撤销会话临时权限范围"),
    );

    Ok(json!({
        "ok": true,
        "revoked": revoked,
        "id": trimmed,
        "session_grants": core.broker.policy().list_session_grants(),
        "approved_roots": core
            .fs_engine
            .list_approved_roots()
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
    }))
}
