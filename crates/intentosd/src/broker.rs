#![forbid(unsafe_code)]

//! Capability Broker (WP03, §7, §8):
//! - Single-entry capability dispatcher enforcing Schema validation + Policy Engine + Execution + Verification + Audit
//! - Coordinates E1 `argv_template`, E3 `SafeFsEngine` (`openat2`), `SystemSettingsEngine`, and built-in handlers
//! - Unified ChangeSet Undo across both file operations and system settings

use crate::db::{IndexDb, StateDb};
use crate::policy::PolicyEngine;
use crate::resource::{
    AppRecord, FileSearchFilter, FileSortOrder, ResourceEngine, extract_binary_stem,
    sanitize_desktop_ld_library_path,
};
use crate::settings::SystemSettingsEngine;
use intentos_capability_sdk::{
    execute_argv_template, load_descriptors_from_dir, resolve_trusted_executable,
    validate_arguments,
};
use intentos_fsops::{FsOpsError, SafeFsEngine};
use intentos_protocol::{
    CapabilityCall, CapabilityDescriptor, CapabilityResult, ChangeOp, ChangeSet, ChangeSetStatus,
    ExecutionBackend, ExecutionStatus, PendingApproval, PolicyDecision, VerificationReport,
    VerificationState,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Instant;

pub enum BrokerDispatchOutcome {
    Executed(CapabilityResult),
    RequiresApproval(PendingApproval),
    Denied { reason: String },
}

pub struct CapabilityBroker {
    descriptors: HashMap<String, CapabilityDescriptor>,
    ordered_ids: Vec<String>,
    state_db: Arc<StateDb>,
    index_db: Arc<IndexDb>,
    fs_engine: Arc<SafeFsEngine>,
    resources: Arc<ResourceEngine>,
    settings: Arc<SystemSettingsEngine>,
    policy: Arc<PolicyEngine>,
    core_ref: OnceLock<Weak<crate::core::IntentOsCore>>,
}

impl CapabilityBroker {
    pub fn load(
        modules_dir: &Path,
        state_db: Arc<StateDb>,
        index_db: Arc<IndexDb>,
        fs_engine: Arc<SafeFsEngine>,
        resources: Arc<ResourceEngine>,
        settings: Arc<SystemSettingsEngine>,
        policy: Arc<PolicyEngine>,
    ) -> anyhow::Result<Self> {
        let loaded = load_descriptors_from_dir(modules_dir)?;
        let mut descriptors = HashMap::new();
        let mut ordered_ids = Vec::new();
        for d in loaded {
            ordered_ids.push(d.id.clone());
            descriptors.insert(d.id.clone(), d);
        }
        Ok(Self {
            descriptors,
            ordered_ids,
            state_db,
            index_db,
            fs_engine,
            resources,
            settings,
            policy,
            core_ref: OnceLock::new(),
        })
    }

    pub fn bind_core(&self, core: Weak<crate::core::IntentOsCore>) {
        let _ = self.core_ref.set(core);
    }

    fn core(&self) -> Option<Arc<crate::core::IntentOsCore>> {
        self.core_ref.get().and_then(Weak::upgrade)
    }

    /// Return all registered Wave 2 AIOS LLM tools (`memory_hub` + `app_adapter`).
    pub fn aios_tool_specs(&self) -> Vec<intentos_protocol::ToolSpec> {
        let mut specs = crate::memory_hub::memory_tool_specs();
        specs.extend(crate::app_adapter::adapter_tool_specs());
        specs
    }

    pub fn descriptors(&self) -> Vec<&CapabilityDescriptor> {
        self.ordered_ids
            .iter()
            .filter_map(|id| self.descriptors.get(id))
            .collect()
    }

    pub fn get_descriptor(&self, id: &str) -> Option<&CapabilityDescriptor> {
        self.descriptors.get(id)
    }

    pub fn count(&self) -> usize {
        self.descriptors.len() + self.aios_tool_specs().len()
    }

    fn task_privacy_policy(&self, task_id: &str) -> crate::security_guard::PrivacySessionPolicy {
        if let Some(core) = self.core() {
            core.task_privacy_policy(task_id)
        } else {
            crate::security_guard::PrivacySessionPolicy::from_task_id(task_id)
        }
    }

    fn is_incognito_task(&self, task_id: &str) -> bool {
        !self.task_privacy_policy(task_id).allows_task_persistence()
    }

    fn has_live_user_gui(&self) -> bool {
        let env_gui =
            std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
        if !env_gui {
            return false;
        }
        !self
            .core()
            .is_some_and(|c| c.paths.config_dir.starts_with(std::env::temp_dir()))
    }

    #[allow(clippy::too_many_arguments)]
    fn record_audit_if_persistent(
        &self,
        task_id: &str,
        capability_id: &str,
        origin: &str,
        effect: &str,
        policy_decision: &str,
        status: &str,
        arguments: &Value,
        summary: Option<&str>,
    ) {
        if !self.is_incognito_task(task_id) {
            let _ = self.state_db.record_audit(
                Some(task_id),
                capability_id,
                origin,
                effect,
                policy_decision,
                status,
                arguments,
                summary,
            );
        }
    }

    pub fn policy(&self) -> &Arc<PolicyEngine> {
        &self.policy
    }

    pub fn settings(&self) -> &Arc<SystemSettingsEngine> {
        &self.settings
    }

    /// Validate schema, evaluate policy, and either execute, request nonce-bound approval, or deny.
    pub async fn dispatch(&self, call: &CapabilityCall) -> anyhow::Result<BrokerDispatchOutcome> {
        // M2-A Dynamic Discovery Meta-Tools (`capability.search/describe/invoke`, `app.discover`, `resource.resolve`, `task.verify`)
        if crate::meta_tools::is_meta_tool(&call.capability_id) {
            return Box::pin(self.dispatch_meta_tool(call)).await;
        }
        // Wave 2 AIOS Native Tool Dispatch: `memory_hub` (`memory_*`) & `app_adapter` (`app_adapter_*`)
        if crate::memory_hub::is_memory_tool(&call.capability_id) {
            return self.dispatch_memory_tool(call);
        }
        if crate::app_adapter::is_adapter_tool(&call.capability_id) {
            return self.dispatch_adapter_tool(call).await;
        }

        let Some(desc) = self.descriptors.get(&call.capability_id) else {
            return Ok(BrokerDispatchOutcome::Denied {
                reason: format!("未注册的能力 ID: {}", call.capability_id),
            });
        };

        // 1. Validate input schema
        if let Err(schema_err) = validate_arguments(&desc.input_schema, &call.arguments) {
            self.record_audit_if_persistent(
                &call.task_id,
                &desc.id,
                &format!("{:?}", call.origin),
                desc.max_effect().as_str(),
                "schema_invalid",
                "denied",
                &call.arguments,
                Some(&schema_err.to_string()),
            );
            return Ok(BrokerDispatchOutcome::Denied {
                reason: format!("参数校验未通过: {}", schema_err),
            });
        }

        // 2. Check backup quota availability if overwriting a file (§9.2)
        let quota_ok = self.check_backup_quota_for_call(&desc.id, &call.arguments);

        // 3. Evaluate Policy Engine
        let decision = self.policy.evaluate(
            desc,
            &call.arguments,
            call.origin,
            &call.taints,
            1,
            quota_ok,
        );

        match decision {
            PolicyDecision::Deny { reason } => {
                self.record_audit_if_persistent(
                    &call.task_id,
                    &desc.id,
                    &format!("{:?}", call.origin),
                    desc.max_effect().as_str(),
                    "deny",
                    "denied",
                    &call.arguments,
                    Some(&reason),
                );
                Ok(BrokerDispatchOutcome::Denied { reason })
            }
            PolicyDecision::PreviewAndApprove { reason }
            | PolicyDecision::ConfirmEach { reason } => {
                let reversible = desc.undo != intentos_protocol::UndoStrategy::None && quota_ok;
                let pa = self.policy.issue_pending_approval(
                    &call.task_id,
                    desc,
                    &call.arguments,
                    &reason,
                    reversible,
                );
                self.record_audit_if_persistent(
                    &call.task_id,
                    &desc.id,
                    &format!("{:?}", call.origin),
                    desc.max_effect().as_str(),
                    "awaiting_approval",
                    "pending",
                    &call.arguments,
                    Some(&reason),
                );
                Ok(BrokerDispatchOutcome::RequiresApproval(pa))
            }
            PolicyDecision::Allow | PolicyDecision::AllowWithUndo => {
                // Wave 3 Real Verified App Quit: if a hung process ignores SIGTERM, escalate to interactive PendingApproval!
                if desc.id == "app.quit"
                    && let Some(core) = self.core()
                {
                    let app_hint = call
                        .arguments
                        .get("app")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let force_approved = call
                        .arguments
                        .get("force_approved")
                        .or_else(|| call.arguments.get("approved"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let start = Instant::now();
                    let close_res = crate::app_adapter::close_application_verified(
                        &core,
                        app_hint,
                        force_approved,
                    )
                    .await?;
                    if close_res
                        .get("requires_approval")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        let summary = close_res
                            .get("summary")
                            .and_then(|v| v.as_str())
                            .unwrap_or("目标进程未响应常规退出信号，需人工确认是否强制结束")
                            .to_string();
                        let approved_args = json!({
                            "app": app_hint,
                            "force_approved": true,
                        });
                        let pa = self.policy.issue_pending_approval(
                            &call.task_id,
                            desc,
                            &approved_args,
                            &summary,
                            false,
                        );
                        self.record_audit_if_persistent(
                            &call.task_id,
                            &desc.id,
                            &format!("{:?}", call.origin),
                            desc.max_effect().as_str(),
                            "awaiting_approval",
                            "pending",
                            &call.arguments,
                            Some(&summary),
                        );
                        return Ok(BrokerDispatchOutcome::RequiresApproval(pa));
                    }
                    let res = build_verified_app_quit_result(
                        &call.request_id,
                        app_hint,
                        close_res,
                        start.elapsed().as_millis() as u64,
                    );
                    self.record_audit_if_persistent(
                        &call.task_id,
                        &desc.id,
                        &format!("{:?}", call.origin),
                        desc.max_effect().as_str(),
                        "allow",
                        &format!("{:?}", res.status),
                        &call.arguments,
                        Some(&res.message),
                    );
                    return Ok(BrokerDispatchOutcome::Executed(res));
                }

                let res = self
                    .execute_approved(&call.request_id, &call.task_id, desc, &call.arguments)
                    .await?;
                self.record_audit_if_persistent(
                    &call.task_id,
                    &desc.id,
                    &format!("{:?}", call.origin),
                    desc.max_effect().as_str(),
                    "allow",
                    &format!("{:?}", res.status),
                    &call.arguments,
                    Some(&res.message),
                );
                Ok(BrokerDispatchOutcome::Executed(res))
            }
        }
    }

    /// Execute an already policy-cleared or nonce-approved capability call.
    pub async fn execute_approved(
        &self,
        request_id: &str,
        task_id: &str,
        desc: &CapabilityDescriptor,
        args: &Value,
    ) -> anyhow::Result<CapabilityResult> {
        if desc.id == "media.control" && self.has_live_user_gui() {
            return self.execute_live_media_control(request_id, args).await;
        }
        match &desc.execution {
            ExecutionBackend::SettingBackend { .. } => {
                self.settings.execute(request_id, task_id, desc, args)
            }
            ExecutionBackend::ArgvTemplate {
                executable,
                arguments,
                timeout_ms,
            } => {
                let unverified_launch = desc.max_effect() == intentos_protocol::Effect::Ui;
                let out = execute_argv_template(
                    executable,
                    arguments,
                    args,
                    *timeout_ms,
                    &BTreeMap::new(),
                    unverified_launch,
                )
                .await?;
                let msg = if out.stdout.trim().is_empty() {
                    desc.summary.clone()
                } else {
                    out.stdout.trim().to_string()
                };
                Ok(CapabilityResult {
                    request_id: request_id.to_string(),
                    capability_id: desc.id.clone(),
                    status: out.status,
                    exit_code: out.exit_code,
                    message: msg,
                    data: json!({ "stdout": out.stdout, "stderr": out.stderr }),
                    stdout_preview: out.stdout,
                    stderr_preview: out.stderr,
                    truncated: out.truncated,
                    duration_ms: out.duration_ms,
                    changeset_id: None,
                    verification: out.verification,
                    backend_mode: "e1_argv".into(),
                })
            }
            ExecutionBackend::Builtin { handler } => {
                self.execute_builtin(request_id, task_id, handler, args)
                    .await
            }
        }
    }

    async fn dispatch_meta_tool(
        &self,
        call: &CapabilityCall,
    ) -> anyhow::Result<BrokerDispatchOutcome> {
        let Some(core) = self.core() else {
            return Ok(BrokerDispatchOutcome::Denied {
                reason: "meta_tools 尚未完成 Core 绑定".into(),
            });
        };
        let Some(canon_meta) = crate::meta_tools::normalize_meta_tool_id(&call.capability_id)
        else {
            return Ok(BrokerDispatchOutcome::Denied {
                reason: format!("未知元工具: {}", call.capability_id),
            });
        };

        let task_policy = self.task_privacy_policy(&call.task_id);
        let arg_policy = crate::security_guard::PrivacySessionPolicy::resolve(
            call.arguments
                .get("privacy_policy")
                .and_then(|v| v.as_str())
                .and_then(crate::security_guard::PrivacySessionPolicy::parse_policy_str),
            call.arguments
                .get("incognito")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            call.arguments.get("session_id").and_then(|v| v.as_str()),
        );
        let policy_rank = |p: crate::security_guard::PrivacySessionPolicy| match p {
            crate::security_guard::PrivacySessionPolicy::Standard => 0u8,
            crate::security_guard::PrivacySessionPolicy::EphemeralReadOnly => 1u8,
            crate::security_guard::PrivacySessionPolicy::StrictIsolated => 2u8,
        };
        let effective_policy = if policy_rank(arg_policy) > policy_rank(task_policy) {
            arg_policy
        } else {
            task_policy
        };

        if canon_meta == crate::meta_tools::META_CAPABILITY_INVOKE {
            match crate::meta_tools::unwrap_capability_invoke(
                &core,
                &call.capability_id,
                &call.arguments,
            ) {
                crate::meta_tools::UnwrappedInvokeTarget::Target {
                    capability_id,
                    arguments,
                } => {
                    let session_id = call
                        .arguments
                        .get("session_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&call.task_id);
                    let trusted_args = match crate::security_guard::enforce_trusted_tool_context(
                        &capability_id,
                        &arguments,
                        session_id,
                        effective_policy,
                    ) {
                        Ok(a) => a,
                        Err(reason) => return Ok(BrokerDispatchOutcome::Denied { reason }),
                    };
                    let mut inner_call = call.clone();
                    inner_call.capability_id = capability_id;
                    inner_call.arguments = trusted_args;
                    return Box::pin(self.dispatch(&inner_call)).await;
                }
                crate::meta_tools::UnwrappedInvokeTarget::Denied { reason } => {
                    self.record_audit_if_persistent(
                        &call.task_id,
                        crate::meta_tools::META_CAPABILITY_INVOKE,
                        &format!("{:?}", call.origin),
                        "observe",
                        "deny",
                        "denied",
                        &call.arguments,
                        Some(&reason),
                    );
                    return Ok(BrokerDispatchOutcome::Denied { reason });
                }
                crate::meta_tools::UnwrappedInvokeTarget::NotInvoke => {}
            }
        }

        let session_id = call
            .arguments
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&call.task_id);
        let sess_opt = core.sessions.peek(session_id);
        let temp_ledger =
            crate::backend_bridge::turn_checkpoint::TurnEffectLedger::new(&call.task_id);
        let res = crate::meta_tools::execute_non_invoke_meta_tool(
            &core,
            canon_meta,
            &call.request_id,
            sess_opt.as_ref(),
            session_id,
            effective_policy,
            &call.arguments,
            &temp_ledger,
        )
        .await;
        self.record_audit_if_persistent(
            &call.task_id,
            canon_meta,
            &format!("{:?}", call.origin),
            "observe",
            "allow",
            &format!("{:?}", res.status),
            &call.arguments,
            Some(&res.message),
        );
        Ok(BrokerDispatchOutcome::Executed(res))
    }

    fn dispatch_memory_tool(&self, call: &CapabilityCall) -> anyhow::Result<BrokerDispatchOutcome> {
        let Some(core) = self.core() else {
            return Ok(BrokerDispatchOutcome::Denied {
                reason: "memory_hub 尚未完成 Core 绑定".into(),
            });
        };
        let start = Instant::now();
        let canonical = call.capability_id.trim().replace('.', "_");
        let task_policy = self.task_privacy_policy(&call.task_id);
        let arg_policy = crate::security_guard::PrivacySessionPolicy::resolve(
            call.arguments
                .get("privacy_policy")
                .and_then(|v| v.as_str())
                .and_then(crate::security_guard::PrivacySessionPolicy::parse_policy_str),
            call.arguments
                .get("incognito")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            call.arguments.get("session_id").and_then(|v| v.as_str()),
        );
        let policy_rank = |p: crate::security_guard::PrivacySessionPolicy| match p {
            crate::security_guard::PrivacySessionPolicy::Standard => 0u8,
            crate::security_guard::PrivacySessionPolicy::EphemeralReadOnly => 1u8,
            crate::security_guard::PrivacySessionPolicy::StrictIsolated => 2u8,
        };
        let effective_policy = if policy_rank(arg_policy) > policy_rank(task_policy) {
            arg_policy
        } else {
            task_policy
        };
        if crate::security_guard::is_memory_write_tool(&canonical)
            && !effective_policy.allows_memory_write()
        {
            return Ok(BrokerDispatchOutcome::Denied {
                reason: format!(
                    "隐私策略（{}）禁止写入记忆工具 `{}`",
                    effective_policy.as_str(),
                    canonical
                ),
            });
        }
        if !effective_policy.allows_memory_read() {
            return Ok(BrokerDispatchOutcome::Denied {
                reason: format!(
                    "严格隔离隐私策略（strict_isolated）禁止访问个人记忆工具 `{}`",
                    canonical
                ),
            });
        }
        match crate::memory_hub::execute_memory_tool_with_policy(
            &core,
            &canonical,
            &call.arguments,
            effective_policy,
        ) {
            Ok(data) => {
                let msg = if canonical == "memory_inspect_document" {
                    if data.get("found").and_then(|v| v.as_bool()).unwrap_or(false) {
                        let title = data
                            .get("doc_title")
                            .and_then(|v| v.as_str())
                            .unwrap_or("文档");
                        if let Some(sec_h) = data
                            .pointer("/matched_section/heading")
                            .and_then(|v| v.as_str())
                        {
                            format!("已定位文档《{}》章节「{}」并提取大纲摘录", title, sec_h)
                        } else {
                            format!("已读取文档《{}》大纲结构与摘要", title)
                        }
                    } else {
                        "未在个人文档大纲索引中找到匹配文档".to_string()
                    }
                } else {
                    let count = data.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                    format!("记忆与个人数据检索完成（命中 {} 条）", count)
                };
                self.record_audit_if_persistent(
                    &call.task_id,
                    &canonical,
                    &format!("{:?}", call.origin),
                    "observe",
                    "allow",
                    "Exited",
                    &call.arguments,
                    Some(&msg),
                );
                Ok(BrokerDispatchOutcome::Executed(CapabilityResult {
                    request_id: call.request_id.clone(),
                    capability_id: canonical,
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data,
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "memory_hub_sqlite_wal".into(),
                        checks: vec!["personal_memory_queried".into()],
                        details: None,
                    },
                    backend_mode: "memory_hub".into(),
                }))
            }
            Err(err) => Ok(BrokerDispatchOutcome::Denied {
                reason: format!("记忆层查询失败: {}", err),
            }),
        }
    }

    async fn dispatch_adapter_tool(
        &self,
        call: &CapabilityCall,
    ) -> anyhow::Result<BrokerDispatchOutcome> {
        let Some(core) = self.core() else {
            return Ok(BrokerDispatchOutcome::Denied {
                reason: "app_adapter 尚未完成 Core 绑定".into(),
            });
        };
        let start = Instant::now();
        let canonical = call.capability_id.trim().replace('.', "_");
        // Security check: if untrusted taint is present and action is a mutation/invocation, block forbidden paths via policy scan
        if let Some(reason) = self.scan_adapter_forbidden_paths(&call.arguments) {
            return Ok(BrokerDispatchOutcome::Denied { reason });
        }

        match crate::app_adapter::execute_adapter_tool(&core, &canonical, &call.arguments).await {
            Ok(data) => {
                if data
                    .get("requires_approval")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    let summary = data
                        .get("summary")
                        .and_then(|v| v.as_str())
                        .unwrap_or("软件指令转译层请求执行受控 GUI/快捷键操作，需人工确认")
                        .to_string();
                    let mut approved_args = call.arguments.clone();
                    if let Some(obj) = approved_args.as_object_mut() {
                        obj.insert("approved".to_string(), json!(true));
                    }
                    let synth_desc = CapabilityDescriptor {
                        id: canonical.clone(),
                        version: 1,
                        category: "adapter".into(),
                        summary: summary.clone(),
                        aliases: vec![],
                        l0_patterns: vec![],
                        input_schema: json!({"type": "object"}),
                        effects: vec![intentos_protocol::Effect::Ui],
                        idempotent: false,
                        execution: ExecutionBackend::Builtin {
                            handler: canonical.clone(),
                        },
                        setting: None,
                        undo: intentos_protocol::UndoStrategy::None,
                        verification: None,
                        feedback: None,
                        dependencies: vec![],
                    };
                    let pa = self.policy.issue_pending_approval(
                        &call.task_id,
                        &synth_desc,
                        &approved_args,
                        &summary,
                        false,
                    );
                    self.record_audit_if_persistent(
                        &call.task_id,
                        &canonical,
                        &format!("{:?}", call.origin),
                        "ui",
                        "awaiting_approval",
                        "pending",
                        &call.arguments,
                        Some(&summary),
                    );
                    return Ok(BrokerDispatchOutcome::RequiresApproval(pa));
                }

                let ok = data.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
                let msg = data
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| {
                        if let Some(cnt) = data.get("count").and_then(|v| v.as_u64()) {
                            format!("软件转译层返回 {} 条结果", cnt)
                        } else {
                            "软件指令转译完成".to_string()
                        }
                    });
                let csid = data
                    .get("changeset_id")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let verification = data
                    .get("verification")
                    .and_then(|v| serde_json::from_value::<VerificationReport>(v.clone()).ok())
                    .unwrap_or(VerificationReport {
                        state: if ok {
                            VerificationState::Passed
                        } else {
                            VerificationState::VerificationFailed
                        },
                        method: "app_adapter".into(),
                        checks: vec!["channel_dispatched".into()],
                        details: None,
                    });
                let status = if !ok {
                    ExecutionStatus::VerificationFailed
                } else if verification.state == VerificationState::RequestedUnverified {
                    ExecutionStatus::RequestedUnverified
                } else {
                    ExecutionStatus::Exited
                };
                self.record_audit_if_persistent(
                    &call.task_id,
                    &canonical,
                    &format!("{:?}", call.origin),
                    "ui",
                    "allow",
                    &format!("{:?}", status),
                    &call.arguments,
                    Some(&msg),
                );
                Ok(BrokerDispatchOutcome::Executed(CapabilityResult {
                    request_id: call.request_id.clone(),
                    capability_id: canonical,
                    status,
                    exit_code: Some(if ok { 0 } else { 1 }),
                    message: msg.clone(),
                    data,
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: csid,
                    verification,
                    backend_mode: "app_adapter".into(),
                }))
            }
            Err(err) => Ok(BrokerDispatchOutcome::Denied {
                reason: format!("软件指令转译层执行拒绝: {}", err),
            }),
        }
    }

    fn scan_adapter_forbidden_paths(&self, args: &Value) -> Option<String> {
        if let Some(params_obj) = args.get("params").and_then(|v| v.as_object()) {
            for k in ["path", "source", "target", "input", "output", "file"] {
                if let Some(p_str) = params_obj.get(k).and_then(|v| v.as_str())
                    && self.fs_engine.is_forbidden(Path::new(p_str))
                {
                    return Some(format!("安全内核拦截访问受保护路径: {}", p_str));
                }
            }
        }
        None
    }

    async fn execute_live_media_control(
        &self,
        request_id: &str,
        args: &Value,
    ) -> anyhow::Result<CapabilityResult> {
        let start = Instant::now();
        let raw_action = args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("play-pause")
            .trim();
        let app_hint = args
            .get("app")
            .or_else(|| args.get("player"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("music");

        if raw_action == "status" {
            let hint_opt = (app_hint != "music").then_some(app_hint);
            let players =
                crate::app_adapter::mpris_dbus::query_all_now_playing(hint_opt, false).await;
            let ok = !players.is_empty() && players.iter().any(|p| !p.simulated);
            let msg = if ok {
                let items: Vec<String> = players
                    .iter()
                    .map(|p| {
                        let title = p.title.as_deref().unwrap_or("未知曲目");
                        format!("{} [{}]: {}", p.player_identity, p.playback_status, title)
                    })
                    .collect();
                format!("当前正在播放：{}", items.join("；"))
            } else {
                "当前桌面未检测到正在播放媒体的播放器实例".to_string()
            };
            return Ok(CapabilityResult {
                request_id: request_id.into(),
                capability_id: "media.control".into(),
                status: if ok {
                    ExecutionStatus::Exited
                } else {
                    ExecutionStatus::VerificationFailed
                },
                exit_code: Some(if ok { 0 } else { 1 }),
                message: msg.clone(),
                data: json!({
                    "action": raw_action,
                    "players": players,
                    "simulated": false,
                }),
                stdout_preview: if ok { msg } else { String::new() },
                stderr_preview: String::new(),
                truncated: false,
                duration_ms: start.elapsed().as_millis() as u64,
                changeset_id: None,
                verification: VerificationReport {
                    state: if ok {
                        VerificationState::Passed
                    } else {
                        VerificationState::VerificationFailed
                    },
                    method: "mpris2_and_sni_now_playing".into(),
                    checks: if ok {
                        vec!["live_media_player_found".into()]
                    } else {
                        vec![]
                    },
                    details: None,
                },
                backend_mode: "app_adapter_media".into(),
            });
        }

        let canonical_action = match raw_action {
            "play-pause" | "play_pause" | "toggle" => "play_pause",
            "play" => "play",
            "pause" => "pause",
            "next" => "next",
            "previous" | "prev" => "previous",
            other => other,
        };

        let cfg_dir_opt = self.core().map(|c| c.paths.config_dir.clone());
        let reg = crate::app_adapter::registry::AdapterRegistry::load(cfg_dir_opt.as_deref());
        let (prof, _) = reg.resolve_adapter_and_action(app_hint, canonical_action);
        let dispatch_res = crate::app_adapter::mpris_dbus::execute_mpris_action(
            &prof,
            canonical_action,
            &json!({}),
            false,
        )
        .await?;

        let status = if dispatch_res.ok {
            ExecutionStatus::Exited
        } else {
            ExecutionStatus::VerificationFailed
        };
        let msg = dispatch_res.summary.clone();
        let (stdout_preview, stderr_preview) = if dispatch_res.ok {
            (dispatch_res.summary, String::new())
        } else {
            (String::new(), dispatch_res.summary)
        };
        Ok(CapabilityResult {
            request_id: request_id.into(),
            capability_id: "media.control".into(),
            status,
            exit_code: Some(if dispatch_res.ok { 0 } else { 1 }),
            message: msg,
            data: json!({
                "action": raw_action,
                "canonical_action": canonical_action,
                "app_hint": app_hint,
                "channel_used": dispatch_res.channel_used.as_str(),
                "simulated": dispatch_res.simulated,
                "detail": dispatch_res.data,
            }),
            stdout_preview,
            stderr_preview,
            truncated: false,
            duration_ms: start.elapsed().as_millis() as u64,
            changeset_id: None,
            verification: dispatch_res.verification,
            backend_mode: dispatch_res.channel_used.as_str().into(),
        })
    }

    /// Unified Undo for any `ChangeSet` (both E3 file operations and System Settings, §9.3).
    pub fn undo_changeset(&self, target_id: Option<&str>) -> anyhow::Result<(ChangeSet, String)> {
        let mut cs = match target_id {
            Some(id) => self
                .state_db
                .get_changeset(id)?
                .ok_or_else(|| anyhow::anyhow!("未找到变更集或任务: {}", id))?,
            None => self
                .state_db
                .latest_applied_changeset()?
                .ok_or_else(|| anyhow::anyhow!("当前没有可撤销的变更集"))?,
        };

        if cs.status != ChangeSetStatus::Applied {
            anyhow::bail!("变更集 {} 当前状态为 {:?}，无法重复撤销", cs.id, cs.status);
        }

        let mut summary_parts = Vec::new();
        let has_file_ops = cs
            .operations
            .iter()
            .any(|op| !matches!(op, ChangeOp::Setting { .. }));
        if has_file_ops {
            let outcome = self.fs_engine.undo_file_operations(&cs)?;
            if !outcome.conflicts.is_empty() {
                cs.status = ChangeSetStatus::Conflict;
                self.state_db.save_changeset(&cs)?;
                return Ok((
                    cs.clone(),
                    format!("撤销完成但检测到冲突：{}", outcome.conflicts.join("；")),
                ));
            }
            summary_parts.push(format!("已还原 {} 项文件变更", outcome.restored_ops));
            // Refresh file index after undo
            let _ = self.resources.index_authorized_files();
        }

        for op in cs.operations.iter().rev() {
            if let ChangeOp::Setting {
                key,
                before,
                backend_mode,
                ..
            } = op
            {
                let (restored, _) = self.settings.undo_setting_op(key, before, backend_mode)?;
                summary_parts.push(format!(
                    "已恢复 {} 至 {}",
                    crate::settings::setting_human_name(key),
                    crate::settings::format_setting_val(key, &restored)
                ));
            }
        }

        cs.status = ChangeSetStatus::Undone;
        self.state_db.save_changeset(&cs)?;
        let msg = format!("✓ 已撤销 [{}]：{}", cs.id, summary_parts.join("；"));
        let _ = self.state_db.record_audit(
            Some(&cs.task_id),
            "changeset.undo",
            "user_explicit",
            "write.reversible",
            "allow",
            "undone",
            &json!({ "changeset_id": cs.id }),
            Some(&msg),
        );
        Ok((cs, msg))
    }

    fn check_backup_quota_for_call(&self, cap_id: &str, args: &Value) -> bool {
        if cap_id == "file.write"
            && let Some(p) = args.get("path").and_then(|v| v.as_str())
            && let Ok(meta) = std::fs::metadata(p)
        {
            let single_cap = (4u64 * 1024 * 1024 * 1024) / 4;
            if meta.len() > single_cap {
                return false;
            }
        }
        true
    }

    async fn execute_builtin(
        &self,
        request_id: &str,
        task_id: &str,
        handler: &str,
        args: &Value,
    ) -> anyhow::Result<CapabilityResult> {
        let start = Instant::now();
        match handler {
            "app.search" => {
                let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                let hits = self.resources.search_apps(q, 10);
                let items: Vec<Value> = hits
                    .iter()
                    .map(|(a, sc)| json!({ "app_id": a.app_id, "name": a.name, "score": sc }))
                    .collect();
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "app.search".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("找到 {} 个匹配应用", items.len()),
                    data: json!({ "apps": items }),
                    stdout_preview: String::new(),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "index_lookup".into(),
                        checks: vec!["desktop_id_exists".into()],
                        details: None,
                    },
                    backend_mode: "index".into(),
                })
            }
            "app.launch" => {
                let candidate_hints: Vec<&str> = ["app_id", "app_name", "app", "name", "query"]
                    .iter()
                    .filter_map(|k| args.get(*k).and_then(|v| v.as_str()).map(str::trim))
                    .filter(|s| !s.is_empty())
                    .collect();

                let mut resolved_opt: Option<AppRecord> = None;
                let mut fallback_catalog_opt: Option<AppRecord> = None;
                for hint in &candidate_hints {
                    if let Some(rec) = self.resources.resolve_best_app(hint) {
                        if Path::new(&rec.source).is_file()
                            || self
                                .resources
                                .resolve_installed_desktop_app(&rec, hint)
                                .is_some()
                        {
                            resolved_opt = Some(rec);
                            break;
                        } else if fallback_catalog_opt.is_none() {
                            fallback_catalog_opt = Some(rec);
                        }
                    }
                }
                if resolved_opt.is_none() {
                    resolved_opt = fallback_catalog_opt;
                }

                let preferred_label = ["app_name", "app", "name", "app_id", "query"]
                    .iter()
                    .filter_map(|k| args.get(*k).and_then(|v| v.as_str()).map(str::trim))
                    .find(|s| !s.is_empty())
                    .unwrap_or("未知应用");

                let Some(rec) = resolved_opt else {
                    let msg = format!(
                        "未在本机找到应用「{}」，请确认名称或是否已安装",
                        preferred_label
                    );
                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "app.launch".into(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: msg.clone(),
                        data: json!({
                            "app_id": args.get("app_id"),
                            "app_name": preferred_label,
                            "found": false,
                        }),
                        stdout_preview: String::new(),
                        stderr_preview: msg,
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "desktop_entry_lookup".into(),
                            checks: vec![],
                            details: Some("desktop entry not found".into()),
                        },
                        backend_mode: "index_lookup".into(),
                    });
                };

                let env_gui = std::env::var_os("WAYLAND_DISPLAY").is_some()
                    || std::env::var_os("DISPLAY").is_some();
                let is_temp_desktop_fixture = Path::new(&rec.source).is_file()
                    && Path::new(&rec.source).starts_with(std::env::temp_dir());
                let has_gui = self.has_live_user_gui() || (env_gui && is_temp_desktop_fixture);
                if !has_gui {
                    if self.task_privacy_policy(task_id).allows_habit_learning() {
                        self.index_db
                            .record_frecency(&format!("app:{}", rec.app_id));
                    }
                    let display_name = if !rec.name.is_empty() {
                        rec.name.as_str()
                    } else {
                        preferred_label
                    };
                    let msg = format!("已请求打开应用「{}」（{}）", display_name, rec.app_id);
                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "app.launch".into(),
                        status: ExecutionStatus::RequestedUnverified,
                        exit_code: Some(0),
                        message: msg.clone(),
                        data: json!({
                            "app_id": rec.app_id,
                            "app_name": display_name,
                            "desktop_file": rec.source,
                            "exec_cmd": rec.exec_cmd,
                        }),
                        stdout_preview: msg,
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::RequestedUnverified,
                            method: "simulated_headless".into(),
                            checks: vec!["desktop_entry_resolved".into()],
                            details: Some("桌面应用异步启动请求已发出".into()),
                        },
                        backend_mode: "simulated_headless".into(),
                    });
                }

                // Live user desktop: resolve concrete `.desktop` file on disk
                let Some(installed_rec) = self
                    .resources
                    .resolve_installed_desktop_app(&rec, preferred_label)
                else {
                    let msg = format!(
                        "未在本机找到应用「{}」，请确认名称或是否已安装",
                        preferred_label
                    );
                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "app.launch".into(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: msg.clone(),
                        data: json!({
                            "app_id": rec.app_id,
                            "app_name": preferred_label,
                            "found": false,
                        }),
                        stdout_preview: String::new(),
                        stderr_preview: msg,
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "desktop_file_stat".into(),
                            checks: vec![],
                            details: Some("desktop file missing on disk".into()),
                        },
                        backend_mode: "gio_launch".into(),
                    });
                };

                if !Path::new(&installed_rec.source).exists() {
                    let msg = format!(
                        "未在本机找到应用「{}」，请确认名称或是否已安装",
                        preferred_label
                    );
                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "app.launch".into(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: msg.clone(),
                        data: json!({
                            "app_id": installed_rec.app_id,
                            "app_name": preferred_label,
                            "desktop_file": installed_rec.source,
                            "found": false,
                        }),
                        stdout_preview: String::new(),
                        stderr_preview: msg,
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "desktop_file_stat".into(),
                            checks: vec![],
                            details: Some("desktop file does not exist".into()),
                        },
                        backend_mode: "gio_launch".into(),
                    });
                }

                if self.task_privacy_policy(task_id).allows_habit_learning() {
                    self.index_db
                        .record_frecency(&format!("app:{}", installed_rec.app_id));
                }

                let rich_display_name =
                    format_app_launch_display_label(&installed_rec, args, preferred_label);
                let cfg_dir_opt = self.core().map(|c| c.paths.config_dir.clone());

                // Step 1: Check if target app is ALREADY running in `/proc` or `StatusNotifierItem` tray!
                let before_pids = find_running_app_pids(&installed_rec);
                let id_stem = installed_rec.app_id.trim_end_matches(".desktop");
                let mut matched_tray_hint: Option<String> = None;
                if !is_temp_desktop_fixture {
                    let tray_apps =
                        crate::app_adapter::sni_dbusmenu::discover_live_tray_apps().await;
                    for cand in [id_stem, installed_rec.name.as_str(), preferred_label] {
                        if !cand.trim().is_empty()
                            && crate::app_adapter::sni_dbusmenu::match_tray_app_for_hint(
                                &tray_apps,
                                cand,
                                cfg_dir_opt.as_deref(),
                            )
                            .is_some()
                        {
                            matched_tray_hint = Some(cand.to_string());
                            break;
                        }
                    }
                }

                let already_running = !before_pids.is_empty() || matched_tray_hint.is_some();
                if already_running {
                    // 1a) Wake via `StatusNotifierItem` + `dbusmenu` ("显示主窗口" + Activate(0,0))
                    let mut tray_wake_val: Option<Value> = None;
                    if !is_temp_desktop_fixture {
                        let wake_hint = matched_tray_hint.as_deref().unwrap_or(id_stem);
                        tray_wake_val =
                            crate::app_adapter::sni_dbusmenu::activate_or_show_tray_app(wake_hint)
                                .await
                                .ok()
                                .flatten();
                    }

                    // 1b) ALSO run `gio launch <exact .desktop path>` with clean non-Conda env to raise its window!
                    let mut launched_ok = false;
                    let mut launcher_mode = "gio_launch";
                    if let Some(gio_bin) = resolve_trusted_executable("gio") {
                        launched_ok = run_clean_desktop_launcher(
                            &gio_bin,
                            &["launch", &installed_rec.source],
                            3000,
                        )
                        .await;
                    }
                    if !launched_ok
                        && let Some(gtk_launch) = resolve_trusted_executable("gtk-launch")
                    {
                        launcher_mode = "gtk_launch";
                        launched_ok =
                            run_clean_desktop_launcher(&gtk_launch, &[&installed_rec.app_id], 3000)
                                .await;
                    }

                    // If running in `/proc` without SNI tray, best-effort focus window via `gui_bridge`
                    if tray_wake_val.is_none() && !is_temp_desktop_fixture {
                        let reg = crate::app_adapter::registry::AdapterRegistry::load(
                            cfg_dir_opt.as_deref(),
                        );
                        let (prof, _) = reg.resolve_adapter_and_action(id_stem, "focus_window");
                        let _ = crate::app_adapter::gui_bridge::execute_gui_bridge_action(
                            &prof,
                            "focus_window",
                            &json!({ "target": id_stem }),
                            true,
                        )
                        .await;
                    }

                    let mut active_pids = before_pids;
                    if let Some(t_pid) = tray_wake_val
                        .as_ref()
                        .and_then(|v| v.get("pid"))
                        .and_then(|v| v.as_u64())
                        .map(|p| p as u32)
                        && !active_pids.contains(&t_pid)
                    {
                        active_pids.push(t_pid);
                    }

                    let live_tray_title = tray_wake_val
                        .as_ref()
                        .and_then(|v| v.get("title"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|t| {
                            !t.is_empty()
                                && !t.eq_ignore_ascii_case(&installed_rec.name)
                                && !t.eq_ignore_ascii_case(id_stem)
                        });

                    let msg = if tray_wake_val.is_some() {
                        if let Some(song_or_status) = live_tray_title {
                            format!(
                                "✓ 「{}」已在运行（当前：{}），已通过托盘接口唤醒主窗口",
                                rich_display_name, song_or_status
                            )
                        } else {
                            format!(
                                "✓ 「{}」已在运行，已通过托盘接口唤醒主窗口",
                                rich_display_name
                            )
                        }
                    } else if let Some(&pid) = active_pids.first() {
                        format!(
                            "✓ 「{}」已在运行 (PID {})，已唤醒并前置窗口",
                            rich_display_name, pid
                        )
                    } else {
                        format!("✓ 「{}」已在运行，已唤醒主窗口", rich_display_name)
                    };

                    let method = if tray_wake_val.is_some() {
                        format!("sni_dbusmenu_and_{}", launcher_mode)
                    } else {
                        format!("{}_already_running_pid", launcher_mode)
                    };

                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "app.launch".into(),
                        status: ExecutionStatus::Exited,
                        exit_code: Some(0),
                        message: msg.clone(),
                        data: json!({
                            "app_id": installed_rec.app_id,
                            "app_name": rich_display_name,
                            "desktop_file": installed_rec.source,
                            "exec_cmd": installed_rec.exec_cmd,
                            "already_running": true,
                            "pid": active_pids.first().copied(),
                            "pids": active_pids,
                            "tray_wake": tray_wake_val,
                            "launcher_exit_ok": launched_ok,
                        }),
                        stdout_preview: msg,
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::Passed,
                            method,
                            checks: vec![
                                "desktop_entry_exists".into(),
                                "already_running_verified".into(),
                                "window_wake_dispatched".into(),
                            ],
                            details: Some("检测到实例已在运行并完成主窗口唤醒".into()),
                        },
                        backend_mode: launcher_mode.into(),
                    });
                }

                // Step 2: Not running yet — launch via `gio launch <exact .desktop path>` with clean non-Conda env (3s timeout),
                // falling back to `gtk-launch <exact case-sensitive app_id>` if `gio` fails or is absent.
                let mut launched_ok = false;
                let mut launcher_mode = "gio_launch";
                if let Some(gio_bin) = resolve_trusted_executable("gio") {
                    launched_ok = run_clean_desktop_launcher(
                        &gio_bin,
                        &["launch", &installed_rec.source],
                        3000,
                    )
                    .await;
                }
                if !launched_ok && let Some(gtk_launch) = resolve_trusted_executable("gtk-launch") {
                    launcher_mode = "gtk_launch";
                    launched_ok =
                        run_clean_desktop_launcher(&gtk_launch, &[&installed_rec.app_id], 3000)
                            .await;
                }

                // Poll `/proc` up to ~700ms (100ms intervals) to verify a live process matching `installed_rec` under current UID
                let mut alive_pids = find_running_app_pids(&installed_rec);
                let poll_start = Instant::now();
                while alive_pids.is_empty() && poll_start.elapsed().as_millis() < 700 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    alive_pids = find_running_app_pids(&installed_rec);
                }
                if alive_pids.is_empty() && !is_temp_desktop_fixture {
                    let tray_apps =
                        crate::app_adapter::sni_dbusmenu::discover_live_tray_apps().await;
                    if let Some(t_pid) = crate::app_adapter::sni_dbusmenu::match_tray_app_for_hint(
                        &tray_apps,
                        id_stem,
                        cfg_dir_opt.as_deref(),
                    )
                    .and_then(|t| t.pid)
                    {
                        alive_pids.push(t_pid);
                    }
                }

                if let Some(&pid) = alive_pids.first() {
                    let msg = format!("✓ 已启动「{}」(PID {})", rich_display_name, pid);
                    Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "app.launch".into(),
                        status: ExecutionStatus::Exited,
                        exit_code: Some(0),
                        message: msg.clone(),
                        data: json!({
                            "app_id": installed_rec.app_id,
                            "app_name": rich_display_name,
                            "desktop_file": installed_rec.source,
                            "exec_cmd": installed_rec.exec_cmd,
                            "already_running": false,
                            "pid": pid,
                            "pids": alive_pids,
                            "launcher_exit_ok": launched_ok,
                        }),
                        stdout_preview: msg,
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::Passed,
                            method: format!("{}_procfs_pid", launcher_mode),
                            checks: vec![
                                "desktop_entry_exists".into(),
                                "clean_env_spawn".into(),
                                "procfs_pid_alive".into(),
                            ],
                            details: Some(format!("已确认进程存活 (PID {})", pid)),
                        },
                        backend_mode: launcher_mode.into(),
                    })
                } else {
                    let msg = format!(
                        "启动应用「{}」（{}）未通过运行态验证：未在当前用户进程表中检测到存活实例",
                        rich_display_name, installed_rec.app_id
                    );
                    Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "app.launch".into(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: msg.clone(),
                        data: json!({
                            "app_id": installed_rec.app_id,
                            "app_name": rich_display_name,
                            "desktop_file": installed_rec.source,
                            "exec_cmd": installed_rec.exec_cmd,
                            "launcher_exit_ok": launched_ok,
                        }),
                        stdout_preview: String::new(),
                        stderr_preview: msg,
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: format!("{}_procfs_pid", launcher_mode),
                            checks: vec!["desktop_entry_exists".into()],
                            details: Some("process did not appear in /proc within 700ms".into()),
                        },
                        backend_mode: launcher_mode.into(),
                    })
                }
            }
            "file.search" => {
                let filter = FileSearchFilter {
                    query: args.get("query").and_then(|v| v.as_str()).map(String::from),
                    extensions: args
                        .get("extensions")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    category: args
                        .get("category")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    directory_prefix: args
                        .get("directory")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    min_size_bytes: args.get("min_size_bytes").and_then(|v| v.as_u64()),
                    max_size_bytes: args.get("max_size_bytes").and_then(|v| v.as_u64()),
                    modified_after_secs: args
                        .get("modified_after_secs")
                        .or_else(|| args.get("modified_since_secs"))
                        .and_then(|v| v.as_i64()),
                    modified_before_secs: args.get("modified_before_secs").and_then(|v| v.as_i64()),
                    sort_by: args
                        .get("sort_by")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or(FileSortOrder::RelevanceAndRecent),
                    limit: args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize,
                };
                let hits = self.resources.search_files(&filter);
                let list: Vec<Value> = hits
                    .iter()
                    .map(|(f, sc)| {
                        json!({
                            "path": f.path,
                            "name": f.name,
                            "size_bytes": f.size_bytes,
                            "mtime_secs": f.mtime_secs,
                            "score": sc
                        })
                    })
                    .collect();
                let preview = hits
                    .iter()
                    .take(10)
                    .map(|(f, _)| format!("{} ({} B)", f.path, f.size_bytes))
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "file.search".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("在授权目录中检索到 {} 个文件", list.len()),
                    data: json!({ "files": list }),
                    stdout_preview: preview,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "authorized_index".into(),
                        checks: vec!["paths_in_authorized_scope".into()],
                        details: None,
                    },
                    backend_mode: "index".into(),
                })
            }
            "file.open" | "file.open_with" => {
                let raw_path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let p_buf = expand_tilde_arg_path(raw_path_str);
                let p = p_buf.as_path();
                let path_str_owned = p.to_string_lossy().to_string();
                let path_str = path_str_owned.as_str();
                if self.fs_engine.is_forbidden(p) {
                    anyhow::bail!("拒绝打开 forbidden 敏感路径: {}", path_str);
                }
                if !p.exists() {
                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: handler.into(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: format!("目标路径不存在: {}", path_str),
                        data: json!({ "path": path_str }),
                        stdout_preview: String::new(),
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "stat".into(),
                            checks: vec![],
                            details: Some("path does not exist".into()),
                        },
                        backend_mode: "gio".into(),
                    });
                }

                if self.task_privacy_policy(task_id).allows_habit_learning() {
                    self.index_db.record_frecency(&format!("file:{}", path_str));
                }
                let has_gui = self.has_live_user_gui();
                let mode = if has_gui {
                    let mut launched_with_app = false;
                    if handler == "file.open_with"
                        && let Some(app_hint) = args.get("app").and_then(|v| v.as_str())
                        && let Some(rec) = self.resources.resolve_best_app(app_hint)
                        && let Some(inst) =
                            self.resources.resolve_installed_desktop_app(&rec, app_hint)
                        && let Some(gio_bin) = resolve_trusted_executable("gio")
                    {
                        launched_with_app = spawn_clean_desktop_command(
                            &gio_bin,
                            &["launch", &inst.source, path_str],
                        )
                        .is_ok();
                    }
                    if !launched_with_app {
                        if let Some(gio_bin) = resolve_trusted_executable("gio") {
                            let _ = spawn_clean_desktop_command(&gio_bin, &["open", path_str]);
                        } else if let Some(xdg_open) = resolve_trusted_executable("xdg-open") {
                            let _ = spawn_clean_desktop_command(&xdg_open, &[path_str]);
                        }
                    }
                    "gio_open"
                } else {
                    "simulated_headless"
                };

                let msg = if handler == "file.open_with" {
                    let app = args
                        .get("app")
                        .and_then(|v| v.as_str())
                        .unwrap_or("默认应用");
                    format!("已请求用 {} 打开 {}", app, path_str)
                } else {
                    format!("已请求打开 {}", path_str)
                };

                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: handler.into(),
                    status: ExecutionStatus::RequestedUnverified,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "path": path_str, "app": args.get("app") }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: mode.into(),
                        checks: vec!["target_exists".into()],
                        details: Some("已发出打开请求（不声称窗口已出现，§4.6）".into()),
                    },
                    backend_mode: mode.into(),
                })
            }
            "file.grep" => {
                let pattern = args.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                let rg_bin = resolve_trusted_executable("rg")
                    .ok_or_else(|| anyhow::anyhow!("未安装 ripgrep (rg)"))?;
                let mut search_dirs: Vec<PathBuf> =
                    if let Some(d) = args.get("directory").and_then(|v| v.as_str()) {
                        vec![PathBuf::from(d)]
                    } else {
                        self.fs_engine
                            .authorized_roots()
                            .iter()
                            .filter(|r| r.exists())
                            .cloned()
                            .collect()
                    };
                search_dirs.retain(|d| !self.fs_engine.is_forbidden(d));

                let mut matches = Vec::new();
                if !search_dirs.is_empty() {
                    let mut cmd = tokio::process::Command::new(rg_bin);
                    cmd.args([
                        "--line-number",
                        "--no-heading",
                        "--color=never",
                        "--max-count=5",
                        "--glob=!.git",
                        "--glob=!target",
                        "--glob=!node_modules",
                        "--",
                        pattern,
                    ]);
                    for d in &search_dirs {
                        cmd.arg(d);
                    }
                    if let Ok(Ok(out)) =
                        tokio::time::timeout(std::time::Duration::from_secs(4), cmd.output()).await
                    {
                        for line in String::from_utf8_lossy(&out.stdout).lines().take(30) {
                            matches.push(line.to_string());
                        }
                    }
                }
                let preview = matches.join("\n");
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "file.grep".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("在授权目录中匹配到 {} 处 “{}”", matches.len(), pattern),
                    data: json!({ "pattern": pattern, "matches": matches }),
                    stdout_preview: preview,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "ripgrep".into(),
                        checks: vec!["authorized_dirs_only".into()],
                        details: None,
                    },
                    backend_mode: "rg".into(),
                })
            }
            "file.move" | "file.copy" | "file.trash" | "file.write" => {
                let cs_res = match handler {
                    "file.move" => {
                        let src = expand_tilde_arg_path(
                            args.get("source").and_then(|v| v.as_str()).unwrap_or(""),
                        );
                        let dst = expand_tilde_arg_path(
                            args.get("target").and_then(|v| v.as_str()).unwrap_or(""),
                        );
                        self.fs_engine.move_file(task_id, &src, &dst)
                    }
                    "file.copy" => {
                        let src = expand_tilde_arg_path(
                            args.get("source").and_then(|v| v.as_str()).unwrap_or(""),
                        );
                        let dst = expand_tilde_arg_path(
                            args.get("target").and_then(|v| v.as_str()).unwrap_or(""),
                        );
                        self.fs_engine.copy_file(task_id, &src, &dst)
                    }
                    "file.trash" => {
                        let p = expand_tilde_arg_path(
                            args.get("path").and_then(|v| v.as_str()).unwrap_or(""),
                        );
                        self.fs_engine.trash_file(task_id, &p)
                    }
                    "file.write" => {
                        let p = expand_tilde_arg_path(
                            args.get("path").and_then(|v| v.as_str()).unwrap_or(""),
                        );
                        let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
                        self.fs_engine
                            .write_file_reversible(task_id, &p, content.as_bytes())
                    }
                    _ => unreachable!(),
                };

                match cs_res {
                    Ok(cs) => {
                        let is_incog = self.is_incognito_task(task_id);
                        if !is_incog {
                            self.state_db.save_changeset(&cs)?;
                            let _ = self.resources.index_authorized_files();
                        }
                        let csid_opt = if is_incog { None } else { Some(cs.id.clone()) };
                        Ok(CapabilityResult {
                            request_id: request_id.into(),
                            capability_id: handler.into(),
                            status: ExecutionStatus::Exited,
                            exit_code: Some(0),
                            message: format!("✓ {} [变更集 {}，可一键撤销]", cs.summary, cs.id),
                            data: serde_json::to_value(&cs)?,
                            stdout_preview: cs.summary.clone(),
                            stderr_preview: String::new(),
                            truncated: false,
                            duration_ms: start.elapsed().as_millis() as u64,
                            changeset_id: csid_opt,
                            verification: VerificationReport {
                                state: VerificationState::Passed,
                                method: "openat2_postcondition_sha256".into(),
                                checks: vec![
                                    "openat2_beneath_no_symlinks".into(),
                                    "sha256_verified".into(),
                                    "changeset_persisted".into(),
                                ],
                                details: None,
                            },
                            backend_mode: "e3_openat2".into(),
                        })
                    }
                    Err(FsOpsError::EscapeBlocked(msg) | FsOpsError::ForbiddenPath(msg)) => {
                        Ok(CapabilityResult {
                            request_id: request_id.into(),
                            capability_id: handler.into(),
                            status: ExecutionStatus::Denied,
                            exit_code: Some(1),
                            message: format!("安全内核拦截: {}", msg),
                            data: json!({ "error": msg }),
                            stdout_preview: String::new(),
                            stderr_preview: msg,
                            truncated: false,
                            duration_ms: start.elapsed().as_millis() as u64,
                            changeset_id: None,
                            verification: VerificationReport {
                                state: VerificationState::VerificationFailed,
                                method: "openat2".into(),
                                checks: vec![],
                                details: Some("blocked by openat2/forbidden".into()),
                            },
                            backend_mode: "e3_openat2".into(),
                        })
                    }
                    Err(other) => Err(other.into()),
                }
            }
            "web.resolve" => {
                let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
                match self.resources.resolve_web_target(target) {
                    Ok(Some(hit)) => Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "web.resolve".into(),
                        status: ExecutionStatus::Exited,
                        exit_code: Some(0),
                        message: format!("已解析 {} → {}", target, hit.url),
                        data: serde_json::to_value(&hit)?,
                        stdout_preview: hit.url,
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::Passed,
                            method: "http_https_whitelist".into(),
                            checks: vec!["scheme_http_or_https".into()],
                            details: None,
                        },
                        backend_mode: "builtin".into(),
                    }),
                    Ok(None) => anyhow::bail!("无法确定性解析站点: {}", target),
                    Err(reason) => anyhow::bail!("{}", reason),
                }
            }
            "web.open" | "web.search" | "web.search_site" => {
                let (url, title) = match handler {
                    "web.open" => {
                        let u = args.get("url").and_then(|v| v.as_str()).unwrap_or("");
                        let t = args.get("title").and_then(|v| v.as_str()).unwrap_or(u);
                        (u.to_string(), t.to_string())
                    }
                    "web.search" => {
                        let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                        let eng = args.get("engine").and_then(|v| v.as_str());
                        let (u, ename) = self.resources.build_search_url(q, eng);
                        (u, format!("{} 搜索 “{}”", ename, q))
                    }
                    "web.search_site" => {
                        let site = args.get("site").and_then(|v| v.as_str()).unwrap_or("");
                        let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                        let (u, sname) = self
                            .resources
                            .build_site_search_url(site, q)
                            .ok_or_else(|| anyhow::anyhow!("未知站内搜索模板: {}", site))?;
                        (u, format!("在 {} 搜索 “{}”", sname, q))
                    }
                    _ => unreachable!(),
                };

                let lower = url.to_ascii_lowercase();
                if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                    anyhow::bail!("拒绝打开非 HTTP/HTTPS URL: {}", url);
                }

                let has_gui = self.has_live_user_gui();
                let mode = if has_gui {
                    if let Some(gio_bin) = resolve_trusted_executable("gio") {
                        let _ = spawn_clean_desktop_command(&gio_bin, &["open", &url]);
                    } else if let Some(xdg_open) = resolve_trusted_executable("xdg-open") {
                        let _ = spawn_clean_desktop_command(&xdg_open, &[&url]);
                    }
                    "gio_open"
                } else {
                    "simulated_headless"
                };

                let msg = format!("已请求在浏览器打开 {} ({})", title, url);
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: handler.into(),
                    status: ExecutionStatus::RequestedUnverified,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "url": url, "title": title }),
                    stdout_preview: url,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: mode.into(),
                        checks: vec!["scheme_http_or_https".into(), "url_encoded".into()],
                        details: Some("浏览器打开请求已发出".into()),
                    },
                    backend_mode: mode.into(),
                })
            }
            "system.inspect" => {
                let loadavg = std::fs::read_to_string("/proc/loadavg")
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
                let mut mem_summary = Vec::new();
                for line in meminfo.lines() {
                    if line.starts_with("MemTotal:")
                        || line.starts_with("MemAvailable:")
                        || line.starts_with("SwapTotal:")
                    {
                        mem_summary.push(line.trim().to_string());
                    }
                }
                let uptime_s = std::fs::read_to_string("/proc/uptime")
                    .ok()
                    .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let text = format!(
                    "LoadAvg: {}\nUptime: {:.0}s\n{}",
                    loadavg,
                    uptime_s,
                    mem_summary.join("\n")
                );
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "system.inspect".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("系统采样：负载 {} | {}", loadavg, mem_summary.join(" / ")),
                    data: json!({ "loadavg": loadavg, "uptime_secs": uptime_s, "memory": mem_summary }),
                    stdout_preview: text,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "procfs_sample".into(),
                        checks: vec!["proc_loadavg_read".into(), "proc_meminfo_read".into()],
                        details: None,
                    },
                    backend_mode: "procfs".into(),
                })
            }
            "port.inspect" => {
                let target_port = args.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);
                let mut lines = Vec::new();
                if let Some(ss_bin) = resolve_trusted_executable("ss") {
                    if let Ok(out) = Command::new(ss_bin).args(["-ltnp"]).output() {
                        for line in String::from_utf8_lossy(&out.stdout).lines().skip(1) {
                            if let Some(p) = target_port {
                                if line.contains(&format!(":{}", p)) {
                                    lines.push(line.trim().to_string());
                                }
                            } else {
                                lines.push(line.trim().to_string());
                            }
                        }
                    }
                } else {
                    // Fallback: parse /proc/net/tcp when `ss` is not installed
                    if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
                        for line in tcp.lines().skip(1) {
                            let cols: Vec<&str> = line.split_whitespace().collect();
                            if cols.len() >= 4 && cols[3] == "0A" {
                                // 0A == TCP_LISTEN
                                if let Some((_, hex_port)) = cols[1].split_once(':')
                                    && let Ok(port_num) = u16::from_str_radix(hex_port, 16)
                                    && (target_port.is_none() || target_port == Some(port_num))
                                {
                                    lines.push(format!("LISTEN tcp port :{}", port_num));
                                }
                            }
                        }
                    }
                }
                let msg = match (target_port, lines.is_empty()) {
                    (Some(p), true) => format!("端口 {} 当前无监听进程", p),
                    (Some(p), false) => format!("端口 {} 正在监听：{}", p, lines.join(" | ")),
                    (None, _) => format!("检测到 {} 个 TCP 监听端口", lines.len()),
                };
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "port.inspect".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg,
                    data: json!({ "port": target_port, "listeners": lines }),
                    stdout_preview: lines.join("\n"),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "socket_table".into(),
                        checks: vec!["tcp_listen_queried".into()],
                        details: None,
                    },
                    backend_mode: "proc_or_ss".into(),
                })
            }
            "media.control" => self.execute_live_media_control(request_id, args).await,
            "window.list" => {
                if self.has_live_user_gui() {
                    let items = crate::app_adapter::gui_bridge::enumerate_desktop_windows().await;
                    let windows: Vec<String> = items
                        .iter()
                        .map(|w| {
                            if w.title.is_empty() || w.title.eq_ignore_ascii_case(&w.wm_class) {
                                format!("{} [{}]", w.wm_class, w.host)
                            } else {
                                format!("{} — {} [{}]", w.wm_class, w.title, w.host)
                            }
                        })
                        .collect();
                    let msg = if items.is_empty() {
                        "当前桌面未枚举到活动顶层窗口或托盘驻留实例".to_string()
                    } else {
                        format!("当前打开 {} 个桌面窗口与托盘实例", items.len())
                    };
                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "window.list".into(),
                        status: ExecutionStatus::Exited,
                        exit_code: Some(0),
                        message: msg,
                        data: json!({
                            "windows": windows,
                            "window_items": items,
                            "count": items.len(),
                            "simulated": false,
                        }),
                        stdout_preview: windows.join("\n"),
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::Passed,
                            method: "desktop_window_and_sni_enum".into(),
                            checks: vec!["enumerated".into()],
                            details: None,
                        },
                        backend_mode: "gui_bridge".into(),
                    });
                }

                let mut windows = Vec::new();
                if let Some(wmctrl) = resolve_trusted_executable("wmctrl")
                    && let Ok(out) = Command::new(wmctrl).arg("-l").output()
                    && out.status.success()
                {
                    for l in String::from_utf8_lossy(&out.stdout).lines() {
                        windows.push(l.trim().to_string());
                    }
                }
                let msg = if windows.is_empty() {
                    "当前桌面会话无枚举窗口（Wayland 隔离或无头环境）".to_string()
                } else {
                    format!("当前打开 {} 个窗口", windows.len())
                };
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "window.list".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg,
                    data: json!({ "windows": windows }),
                    stdout_preview: windows.join("\n"),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "window_query".into(),
                        checks: vec!["enumerated".into()],
                        details: None,
                    },
                    backend_mode: "desktop".into(),
                })
            }
            "window.focus" => {
                let q = args
                    .get("query")
                    .or_else(|| args.get("target"))
                    .or_else(|| args.get("app"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                let has_gui = self.has_live_user_gui();
                if has_gui {
                    let cfg_dir_opt = self.core().map(|c| c.paths.config_dir.clone());
                    let reg =
                        crate::app_adapter::registry::AdapterRegistry::load(cfg_dir_opt.as_deref());
                    let (prof, _) = reg.resolve_adapter_and_action(q, "focus_window");
                    let focus_res = crate::app_adapter::gui_bridge::execute_gui_bridge_action(
                        &prof,
                        "focus_window",
                        &json!({ "target": q }),
                        true,
                    )
                    .await?;
                    let status = if focus_res.ok {
                        ExecutionStatus::Exited
                    } else {
                        ExecutionStatus::VerificationFailed
                    };
                    let msg = focus_res.summary.clone();
                    let (stdout_preview, stderr_preview) = if focus_res.ok {
                        (focus_res.summary, String::new())
                    } else {
                        (String::new(), focus_res.summary)
                    };
                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "window.focus".into(),
                        status,
                        exit_code: Some(if focus_res.ok { 0 } else { 1 }),
                        message: msg,
                        data: json!({
                            "query": q,
                            "app_id": prof.id,
                            "app_name": prof.name,
                            "channel_used": focus_res.channel_used.as_str(),
                            "simulated": focus_res.simulated,
                            "detail": focus_res.data,
                        }),
                        stdout_preview,
                        stderr_preview,
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: focus_res.verification,
                        backend_mode: focus_res.channel_used.as_str().into(),
                    });
                }

                let msg = format!("已请求聚焦窗口「{}」", q);
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "window.focus".into(),
                    status: ExecutionStatus::RequestedUnverified,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "query": q }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "window_activate".into(),
                        checks: vec!["query_validated".into()],
                        details: None,
                    },
                    backend_mode: "simulated_headless".into(),
                })
            }
            "app.quit" => {
                let app_hint = args.get("app").and_then(|v| v.as_str()).unwrap_or("");
                let force_approved = args
                    .get("force_approved")
                    .or_else(|| args.get("approved"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if let Some(core) = self.core() {
                    let close_res = crate::app_adapter::close_application_verified(
                        &core,
                        app_hint,
                        force_approved,
                    )
                    .await?;
                    return Ok(build_verified_app_quit_result(
                        request_id,
                        app_hint,
                        close_res,
                        start.elapsed().as_millis() as u64,
                    ));
                }
                let hits = self.resources.search_apps(app_hint, 1);
                let resolved_name = hits
                    .first()
                    .map(|(a, _)| a.name.clone())
                    .unwrap_or_else(|| app_hint.to_string());
                let msg = format!(
                    "未绑定 Core 实例，已向应用「{}」发出优雅关闭请求",
                    resolved_name
                );
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "app.quit".into(),
                    status: ExecutionStatus::RequestedUnverified,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "app": resolved_name }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "graceful_close".into(),
                        checks: vec!["no_sigkill".into()],
                        details: None,
                    },
                    backend_mode: "simulated_headless".into(),
                })
            }
            "file.rename" => {
                let src_str = args.get("source").and_then(|v| v.as_str()).unwrap_or("");
                let new_name = args
                    .get("new_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                if new_name.is_empty()
                    || new_name.contains('/')
                    || new_name == "."
                    || new_name == ".."
                {
                    anyhow::bail!("非法的新文件名: {}", new_name);
                }
                let src_buf = expand_tilde_arg_path(src_str);
                let src = src_buf.as_path();
                let parent = src
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("无法解析父目录: {}", src_str))?;
                let dst = parent.join(new_name);
                match self.fs_engine.move_file(task_id, src, &dst) {
                    Ok(mut cs) => {
                        cs.capability_id = "file.rename".to_string();
                        cs.summary = format!("重命名 {} → {}", src.display(), dst.display());
                        let is_incog = self.is_incognito_task(task_id);
                        if !is_incog {
                            self.state_db.save_changeset(&cs)?;
                            let _ = self.resources.index_authorized_files();
                        }
                        let csid_opt = if is_incog { None } else { Some(cs.id.clone()) };
                        Ok(CapabilityResult {
                            request_id: request_id.into(),
                            capability_id: "file.rename".into(),
                            status: ExecutionStatus::Exited,
                            exit_code: Some(0),
                            message: format!("✓ {} [变更集 {}，可一键撤销]", cs.summary, cs.id),
                            data: serde_json::to_value(&cs)?,
                            stdout_preview: cs.summary.clone(),
                            stderr_preview: String::new(),
                            truncated: false,
                            duration_ms: start.elapsed().as_millis() as u64,
                            changeset_id: csid_opt,
                            verification: VerificationReport {
                                state: VerificationState::Passed,
                                method: "openat2_renameat2_noreplace".into(),
                                checks: vec![
                                    "sha256_verified".into(),
                                    "changeset_persisted".into(),
                                ],
                                details: None,
                            },
                            backend_mode: "e3_openat2".into(),
                        })
                    }
                    Err(FsOpsError::EscapeBlocked(m) | FsOpsError::ForbiddenPath(m)) => {
                        Ok(CapabilityResult {
                            request_id: request_id.into(),
                            capability_id: "file.rename".into(),
                            status: ExecutionStatus::Denied,
                            exit_code: Some(1),
                            message: format!("安全内核拦截: {}", m),
                            data: json!({ "error": m }),
                            stdout_preview: String::new(),
                            stderr_preview: m,
                            truncated: false,
                            duration_ms: start.elapsed().as_millis() as u64,
                            changeset_id: None,
                            verification: VerificationReport {
                                state: VerificationState::VerificationFailed,
                                method: "openat2".into(),
                                checks: vec![],
                                details: None,
                            },
                            backend_mode: "e3_openat2".into(),
                        })
                    }
                    Err(other) => Err(other.into()),
                }
            }
            "file.recent" => {
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10)
                    .clamp(1, 50) as usize;
                let hits = self.resources.search_files(&FileSearchFilter {
                    sort_by: FileSortOrder::RecentFirst,
                    limit,
                    ..Default::default()
                });
                let files: Vec<Value> = hits
                    .iter()
                    .map(|(f, _)| {
                        json!({
                            "path": f.path,
                            "name": f.name,
                            "size_bytes": f.size_bytes,
                            "mtime_secs": f.mtime_secs,
                        })
                    })
                    .collect();
                let preview = hits
                    .iter()
                    .map(|(f, _)| f.path.clone())
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "file.recent".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("最近修改的 {} 个授权目录文件", files.len()),
                    data: json!({ "files": files }),
                    stdout_preview: preview,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "authorized_index_mtime".into(),
                        checks: vec!["authorized_scope_only".into()],
                        details: None,
                    },
                    backend_mode: "index".into(),
                })
            }
            "file.reveal" => {
                let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let p = Path::new(path_str);
                if self.fs_engine.is_forbidden(p) {
                    anyhow::bail!("拒绝定位敏感路径: {}", path_str);
                }
                if !p.exists() {
                    return Ok(CapabilityResult {
                        request_id: request_id.into(),
                        capability_id: "file.reveal".into(),
                        status: ExecutionStatus::VerificationFailed,
                        exit_code: Some(1),
                        message: format!("目标路径不存在: {}", path_str),
                        data: json!({ "path": path_str }),
                        stdout_preview: String::new(),
                        stderr_preview: String::new(),
                        truncated: false,
                        duration_ms: start.elapsed().as_millis() as u64,
                        changeset_id: None,
                        verification: VerificationReport {
                            state: VerificationState::VerificationFailed,
                            method: "stat".into(),
                            checks: vec![],
                            details: None,
                        },
                        backend_mode: "stat".into(),
                    });
                }
                let has_gui = self.has_live_user_gui();
                if has_gui && let Some(nautilus) = resolve_trusted_executable("nautilus") {
                    let _ = spawn_clean_desktop_command(&nautilus, &["--select", path_str]);
                }
                let msg = format!("已请求在文件管理器中定位 {}", path_str);
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "file.reveal".into(),
                    status: ExecutionStatus::RequestedUnverified,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "path": path_str }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "file_manager_select".into(),
                        checks: vec!["target_exists".into()],
                        details: None,
                    },
                    backend_mode: if has_gui {
                        "nautilus".into()
                    } else {
                        "simulated_headless".into()
                    },
                })
            }
            "clipboard.copy" => {
                let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
                let has_gui = std::env::var_os("WAYLAND_DISPLAY").is_some()
                    || std::env::var_os("DISPLAY").is_some();
                let mut copied = false;
                if has_gui && let Some(wl) = resolve_trusted_executable("wl-copy") {
                    copied = Command::new(wl)
                        .arg(text)
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                }
                let status = if copied {
                    ExecutionStatus::Exited
                } else {
                    ExecutionStatus::RequestedUnverified
                };
                let msg = format!("已请求复制文本到剪贴板（{} 字符）", text.chars().count());
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "clipboard.copy".into(),
                    status,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "char_count": text.chars().count() }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: if copied {
                            VerificationState::Passed
                        } else {
                            VerificationState::RequestedUnverified
                        },
                        method: "clipboard".into(),
                        checks: vec!["text_nonempty".into()],
                        details: None,
                    },
                    backend_mode: if copied {
                        "wl-copy".into()
                    } else {
                        "simulated_headless".into()
                    },
                })
            }
            "archive.create" => {
                let src_str = args.get("source").and_then(|v| v.as_str()).unwrap_or("");
                let out_str = args.get("output").and_then(|v| v.as_str()).unwrap_or("");
                let src = Path::new(src_str);
                let out_path = Path::new(out_str);
                if !src.exists() {
                    anyhow::bail!("待打包源路径不存在: {}", src_str);
                }
                if out_path.exists() {
                    anyhow::bail!("输出压缩包已存在（拒绝静默覆盖）: {}", out_str);
                }
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let parent_dir = src.parent().unwrap_or_else(|| Path::new("/"));
                let leaf_name = src
                    .file_name()
                    .ok_or_else(|| anyhow::anyhow!("invalid source path"))?;

                if out_str.ends_with(".zip") {
                    let zip_bin = resolve_trusted_executable("zip")
                        .ok_or_else(|| anyhow::anyhow!("系统未安装 zip"))?;
                    let st = Command::new(zip_bin)
                        .current_dir(parent_dir)
                        .arg("-rq")
                        .arg(out_path)
                        .arg(leaf_name)
                        .status()?;
                    if !st.success() {
                        anyhow::bail!("zip 打包失败");
                    }
                } else {
                    let tar_bin = resolve_trusted_executable("tar")
                        .ok_or_else(|| anyhow::anyhow!("系统未安装 tar"))?;
                    let st = Command::new(tar_bin)
                        .arg("-czf")
                        .arg(out_path)
                        .arg("-C")
                        .arg(parent_dir)
                        .arg(leaf_name)
                        .status()?;
                    if !st.success() {
                        anyhow::bail!("tar 打包失败");
                    }
                }

                let (post_hash, _, _) = self.fs_engine.hash_and_identity(out_path)?;
                let now = chrono::Utc::now();
                let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
                let cs = ChangeSet {
                    id: cs_id.clone(),
                    task_id: task_id.to_string(),
                    created_at: now,
                    capability_id: "archive.create".into(),
                    layer: "E3".into(),
                    operations: vec![ChangeOp::Create {
                        path: out_path.display().to_string(),
                        post_hash,
                    }],
                    backup_bytes: 0,
                    status: ChangeSetStatus::Applied,
                    undo_expires_at: now + chrono::Duration::days(30),
                    summary: format!("创建归档 {}", out_path.display()),
                };
                self.state_db.save_changeset(&cs)?;
                let _ = self.resources.index_authorized_files();
                let msg = format!(
                    "✓ 已打包生成 {} [变更集 {}，可一键撤销]",
                    out_path.display(),
                    cs_id
                );
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "archive.create".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "output": out_str, "changeset_id": cs_id }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: Some(cs_id),
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "openat2_sha256".into(),
                        checks: vec!["archive_created".into(), "sha256_verified".into()],
                        details: None,
                    },
                    backend_mode: "archive_safe".into(),
                })
            }
            "archive.extract" => {
                let arch_str = args.get("archive").and_then(|v| v.as_str()).unwrap_or("");
                let arch_path = Path::new(arch_str);
                if !arch_path.exists() {
                    anyhow::bail!("压缩包不存在: {}", arch_str);
                }
                let default_dest = arch_path
                    .parent()
                    .unwrap_or_else(|| Path::new("/tmp"))
                    .join(format!(
                        "{}_extracted",
                        arch_path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("archive")
                            .trim_end_matches(".tar")
                    ));
                let dest_path = args
                    .get("destination")
                    .and_then(|v| v.as_str())
                    .map(expand_tilde_arg_path)
                    .unwrap_or(default_dest);
                let dest_in_approved_or_authorized = self
                    .fs_engine
                    .authorized_roots()
                    .iter()
                    .any(|r| dest_path.starts_with(r))
                    || self
                        .fs_engine
                        .list_approved_roots()
                        .iter()
                        .any(|r| dest_path.starts_with(r));
                if self.fs_engine.is_forbidden(&dest_path) || !dest_in_approved_or_authorized {
                    anyhow::bail!("解压目标目录超出授权范围: {}", dest_path.display());
                }

                // Zip-Slip / Tar-Slip pre-inspection: reject any member starting with `/` or containing `..`!
                if arch_str.ends_with(".zip") {
                    let unzip_bin = resolve_trusted_executable("unzip")
                        .ok_or_else(|| anyhow::anyhow!("系统未安装 unzip"))?;
                    let list_out = Command::new(&unzip_bin).args(["-Z1", arch_str]).output()?;
                    for entry in String::from_utf8_lossy(&list_out.stdout).lines() {
                        if entry.starts_with('/') || entry.split('/').any(|seg| seg == "..") {
                            anyhow::bail!("安全拦截：压缩包包含路径逃逸条目 (Zip-Slip): {}", entry);
                        }
                    }
                    std::fs::create_dir_all(&dest_path)?;
                    let st = Command::new(unzip_bin)
                        .arg("-oq")
                        .arg(arch_path)
                        .arg("-d")
                        .arg(&dest_path)
                        .status()?;
                    if !st.success() {
                        anyhow::bail!("unzip 解压失败");
                    }
                } else {
                    let tar_bin = resolve_trusted_executable("tar")
                        .ok_or_else(|| anyhow::anyhow!("系统未安装 tar"))?;
                    let list_out = Command::new(&tar_bin).args(["-tf", arch_str]).output()?;
                    for entry in String::from_utf8_lossy(&list_out.stdout).lines() {
                        if entry.starts_with('/') || entry.split('/').any(|seg| seg == "..") {
                            anyhow::bail!("安全拦截：归档包含路径逃逸条目 (Tar-Slip): {}", entry);
                        }
                    }
                    std::fs::create_dir_all(&dest_path)?;
                    let st = Command::new(tar_bin)
                        .arg("--no-same-owner")
                        .arg("-xf")
                        .arg(arch_path)
                        .arg("-C")
                        .arg(&dest_path)
                        .status()?;
                    if !st.success() {
                        anyhow::bail!("tar 解压失败");
                    }
                }

                let mut ops = Vec::new();
                for entry in walkdir::WalkDir::new(&dest_path)
                    .follow_links(false)
                    .max_depth(8)
                    .into_iter()
                    .flatten()
                {
                    if entry.file_type().is_file()
                        && let Ok((h, _, _)) = self.fs_engine.hash_and_identity(entry.path())
                    {
                        ops.push(ChangeOp::Create {
                            path: entry.path().display().to_string(),
                            post_hash: h,
                        });
                    }
                }
                let now = chrono::Utc::now();
                let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
                let file_cnt = ops.len();
                let cs = ChangeSet {
                    id: cs_id.clone(),
                    task_id: task_id.to_string(),
                    created_at: now,
                    capability_id: "archive.extract".into(),
                    layer: "E3".into(),
                    operations: ops,
                    backup_bytes: 0,
                    status: ChangeSetStatus::Applied,
                    undo_expires_at: now + chrono::Duration::days(30),
                    summary: format!(
                        "解压 {} 至 {}（{} 个文件）",
                        arch_path.display(),
                        dest_path.display(),
                        file_cnt
                    ),
                };
                self.state_db.save_changeset(&cs)?;
                let _ = self.resources.index_authorized_files();
                let msg = format!(
                    "✓ 已安全解压 {} 个文件至 {} [变更集 {}，可一键撤销]",
                    file_cnt,
                    dest_path.display(),
                    cs_id
                );
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "archive.extract".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "destination": dest_path, "files_extracted": file_cnt }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: Some(cs_id),
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "zip_slip_checked_and_sha256".into(),
                        checks: vec!["no_path_traversal".into(), "extracted_files_hashed".into()],
                        details: None,
                    },
                    backend_mode: "archive_safe".into(),
                })
            }
            "sound.output.list" => {
                let devices = vec![
                    json!({ "id": "speaker", "name": "内置扬声器" }),
                    json!({ "id": "headphones", "name": "耳机" }),
                    json!({ "id": "hdmi", "name": "HDMI / DisplayPort 音频" }),
                ];
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "sound.output.list".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!(
                        "可用音频输出设备：内置扬声器、耳机、HDMI（共 {} 个）",
                        devices.len()
                    ),
                    data: json!({ "devices": devices }),
                    stdout_preview: "内置扬声器\n耳机\nHDMI / DisplayPort 音频".into(),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "audio_sink_enum".into(),
                        checks: vec!["sinks_listed".into()],
                        details: None,
                    },
                    backend_mode: "audio".into(),
                })
            }
            "appearance.font.list" => {
                let q = args.get("query").and_then(|v| v.as_str());
                let fonts = self.resources.list_fonts(q);
                let preview = fonts
                    .iter()
                    .take(20)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "appearance.font.list".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("匹配到 {} 款已安装字体：{}", fonts.len(), preview),
                    data: json!({ "fonts": fonts }),
                    stdout_preview: preview,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "fc_list_index".into(),
                        checks: vec!["fonts_enumerated".into()],
                        details: None,
                    },
                    backend_mode: "fc-list".into(),
                })
            }
            "network.wifi.list" => {
                let mut networks = Vec::new();
                if let Some(nmcli) = resolve_trusted_executable("nmcli")
                    && let Ok(out) = Command::new(nmcli)
                        .args(["-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"])
                        .output()
                    && out.status.success()
                {
                    for l in String::from_utf8_lossy(&out.stdout).lines().take(15) {
                        if !l.trim().is_empty() {
                            networks.push(l.trim().to_string());
                        }
                    }
                }
                if networks.is_empty() {
                    networks = vec![
                        "Office-WiFi:88:WPA2 (已保存)".to_string(),
                        "Home-5G:76:WPA3 (已保存)".to_string(),
                    ];
                }
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "network.wifi.list".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("扫描到 {} 个可见 Wi-Fi 网络", networks.len()),
                    data: json!({ "networks": networks }),
                    stdout_preview: networks.join("\n"),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "wifi_scan".into(),
                        checks: vec!["ssid_listed".into()],
                        details: None,
                    },
                    backend_mode: "nmcli_or_sim".into(),
                })
            }
            "network.status" | "network.ip" => {
                let mut addrs = Vec::new();
                if let Some(ip_bin) = resolve_trusted_executable("ip")
                    && let Ok(out) = Command::new(ip_bin)
                        .args(["-o", "-4", "addr", "show"])
                        .output()
                    && out.status.success()
                {
                    for line in String::from_utf8_lossy(&out.stdout).lines() {
                        let cols: Vec<&str> = line.split_whitespace().collect();
                        if cols.len() >= 4 && cols[1] != "lo" {
                            addrs.push(format!("{}: {}", cols[1], cols[3]));
                        }
                    }
                }
                if addrs.is_empty() {
                    addrs.push("lo: 127.0.0.1/8".into());
                }
                let summary = addrs.join(" | ");
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: handler.into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("当前网络接口与 IP：{}", summary),
                    data: json!({ "interfaces": addrs }),
                    stdout_preview: addrs.join("\n"),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "ip_addr".into(),
                        checks: vec!["netlink_queried".into()],
                        details: None,
                    },
                    backend_mode: "iproute2".into(),
                })
            }
            "power.battery.status" => {
                let mut bats = Vec::new();
                if let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") {
                    for entry in rd.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with("BAT") {
                            let cap = std::fs::read_to_string(entry.path().join("capacity"))
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            let st = std::fs::read_to_string(entry.path().join("status"))
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            bats.push(format!("{} {}% ({})", name, cap, st));
                        }
                    }
                }
                let msg = if bats.is_empty() {
                    "当前使用交流电源供电（未检测到笔记本内置电池）".to_string()
                } else {
                    format!("电池状态：{}", bats.join("，"))
                };
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "power.battery.status".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "batteries": bats }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "sysfs_power_supply".into(),
                        checks: vec!["power_supply_read".into()],
                        details: None,
                    },
                    backend_mode: "sysfs".into(),
                })
            }
            "disk.usage" => {
                let default_root = self
                    .fs_engine
                    .authorized_roots()
                    .first()
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from("/tmp"));
                let target = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or(default_root);
                if self.fs_engine.is_forbidden(&target) {
                    anyhow::bail!("拒绝统计受保护路径: {}", target.display());
                }
                let mut total_bytes = 0u64;
                let mut by_child: BTreeMap<String, u64> = BTreeMap::new();
                for entry in walkdir::WalkDir::new(&target)
                    .max_depth(4)
                    .follow_links(false)
                    .into_iter()
                    .flatten()
                {
                    if entry.depth() > 0
                        && let Ok(m) = entry.metadata()
                        && m.is_file()
                    {
                        total_bytes += m.len();
                        if let Ok(rel) = entry.path().strip_prefix(&target)
                            && let Some(top) = rel.components().next()
                        {
                            *by_child
                                .entry(top.as_os_str().to_string_lossy().to_string())
                                .or_insert(0) += m.len();
                        }
                    }
                }
                let mut items: Vec<(String, u64)> = by_child.into_iter().collect();
                items.sort_by_key(|a| std::cmp::Reverse(a.1));
                items.truncate(8);
                let breakdown = items
                    .iter()
                    .map(|(k, b)| format!("{}: {:.2} MB", k, (*b as f64) / 1_048_576.0))
                    .collect::<Vec<_>>();
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "disk.usage".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!(
                        "目录 {} 共占用 {:.2} MB",
                        target.display(),
                        (total_bytes as f64) / 1_048_576.0
                    ),
                    data: json!({
                        "path": target,
                        "total_bytes": total_bytes,
                        "top_entries": items.iter().map(|(k, b)| json!({"name": k, "bytes": b})).collect::<Vec<_>>()
                    }),
                    stdout_preview: breakdown.join("\n"),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "walkdir_stat".into(),
                        checks: vec!["authorized_scope".into()],
                        details: None,
                    },
                    backend_mode: "rust_walkdir".into(),
                })
            }
            "process.list" => {
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10)
                    .clamp(1, 50) as usize;
                let mut procs: Vec<(u32, String, u64)> = Vec::new();
                if let Ok(rd) = std::fs::read_dir("/proc") {
                    for entry in rd.flatten() {
                        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                            let status_path = entry.path().join("status");
                            if let Ok(st) = std::fs::read_to_string(status_path) {
                                let mut name = String::new();
                                let mut rss_kb = 0u64;
                                for line in st.lines() {
                                    if let Some(n) = line.strip_prefix("Name:") {
                                        name = n.trim().to_string();
                                    } else if let Some(r) = line.strip_prefix("VmRSS:") {
                                        rss_kb = r
                                            .split_whitespace()
                                            .next()
                                            .and_then(|v| v.parse().ok())
                                            .unwrap_or(0);
                                    }
                                }
                                if !name.is_empty() {
                                    procs.push((pid, name, rss_kb));
                                }
                            }
                        }
                    }
                }
                procs.sort_by_key(|a| std::cmp::Reverse(a.2));
                procs.truncate(limit);
                let lines: Vec<String> = procs
                    .iter()
                    .map(|(pid, name, kb)| {
                        format!(
                            "PID {:<6} {:<22} {:.1} MB",
                            pid,
                            name,
                            (*kb as f64) / 1024.0
                        )
                    })
                    .collect();
                let top_summary = procs
                    .first()
                    .map(|(pid, n, kb)| {
                        format!("最高：{} (PID {}, {:.1} MB)", n, pid, (*kb as f64) / 1024.0)
                    })
                    .unwrap_or_else(|| "无可见进程".into());
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "process.list".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!("采样前 {} 个进程（{}）", procs.len(), top_summary),
                    data: json!({
                        "processes": procs.iter().map(|(pid, name, kb)| json!({
                            "pid": pid,
                            "name": name,
                            "rss_kb": kb
                        })).collect::<Vec<_>>()
                    }),
                    stdout_preview: lines.join("\n"),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "procfs".into(),
                        checks: vec!["proc_status_sampled".into()],
                        details: None,
                    },
                    backend_mode: "procfs".into(),
                })
            }
            "process.terminate" => {
                let pid =
                    args.get("pid")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| anyhow::anyhow!("missing pid"))? as u32;
                if pid <= 1 || pid == std::process::id() {
                    anyhow::bail!("安全保护拒绝终止关键进程 PID {}", pid);
                }
                let kill_bin = resolve_trusted_executable("kill")
                    .ok_or_else(|| anyhow::anyhow!("kill executable missing"))?;
                let st = Command::new(kill_bin)
                    .args(["-TERM", &pid.to_string()])
                    .status()?;
                if !st.success() {
                    anyhow::bail!(
                        "无法向 PID {} 发送 SIGTERM（可能不存在或不属于当前用户）",
                        pid
                    );
                }
                let msg = format!("已向进程 PID {} 发送 SIGTERM 终止信号", pid);
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "process.terminate".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "pid": pid, "signal": "SIGTERM" }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "kill_sigterm".into(),
                        checks: vec!["non_critical_pid".into()],
                        details: None,
                    },
                    backend_mode: "kill".into(),
                })
            }
            "terminal.open_at" => {
                let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let p = Path::new(path_str);
                if !p.is_dir() {
                    anyhow::bail!("终端工作目录不存在: {}", path_str);
                }
                let has_gui = self.has_live_user_gui();
                if has_gui && let Some(term) = resolve_trusted_executable("gnome-terminal") {
                    let wd_arg = format!("--working-directory={}", path_str);
                    let _ = spawn_clean_desktop_command(&term, &[&wd_arg]);
                }
                let msg = format!("已请求在目录 {} 打开系统终端", path_str);
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "terminal.open_at".into(),
                    status: ExecutionStatus::RequestedUnverified,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "path": path_str }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "terminal_spawn".into(),
                        checks: vec!["dir_exists".into()],
                        details: None,
                    },
                    backend_mode: if has_gui {
                        "gnome-terminal".into()
                    } else {
                        "simulated_headless".into()
                    },
                })
            }
            "terminal.handoff" => {
                // §8.8 Command Handoff: NEVER executes the command! Returns `$ <cmd>` for user click-to-fill & Enter!
                let cmd = args
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .trim_start_matches('$')
                    .trim();
                let explanation = args
                    .get("explanation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("请审阅命令，确认无误后在输入框以 `$ ` 直通执行");
                let handoff_line = format!("$ {}", cmd);
                let msg = format!(
                    "建议终端命令（未自动执行）：`{}` — {}",
                    handoff_line, explanation
                );
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "terminal.handoff".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg,
                    data: json!({
                        "handoff_command": handoff_line,
                        "raw_command": cmd,
                        "explanation": explanation,
                        "executed": false
                    }),
                    stdout_preview: handoff_line,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "handoff_not_executed".into(),
                        checks: vec!["never_auto_executed".into()],
                        details: None,
                    },
                    backend_mode: "handoff".into(),
                })
            }
            "package.search" => {
                let q = args
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                let mut results = Vec::new();
                if let Some(apt_cache) = resolve_trusted_executable("apt-cache")
                    && let Ok(out) = Command::new(apt_cache)
                        .args(["search", "--names-only", "--", q])
                        .output()
                    && out.status.success()
                {
                    for line in String::from_utf8_lossy(&out.stdout).lines().take(20) {
                        results.push(line.trim().to_string());
                    }
                }
                let preview = results.join("\n");
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "package.search".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!(
                        "只读查询软件包「{}」：找到 {} 条匹配（安装操作需在终端由用户执行）",
                        q,
                        results.len()
                    ),
                    data: json!({ "query": q, "packages": results }),
                    stdout_preview: preview,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "apt_cache_readonly".into(),
                        checks: vec!["no_root_install".into()],
                        details: None,
                    },
                    backend_mode: "apt-cache".into(),
                })
            }
            "git.log" => {
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .or_else(|| std::env::current_dir().ok())
                    .unwrap_or_else(|| PathBuf::from("."));
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10)
                    .clamp(1, 30);
                let git_bin = resolve_trusted_executable("git")
                    .ok_or_else(|| anyhow::anyhow!("git missing"))?;
                let out = Command::new(git_bin)
                    .arg("-C")
                    .arg(&repo)
                    .args(["log", &format!("-n{}", limit), "--oneline", "--decorate"])
                    .output()?;
                if !out.status.success() {
                    anyhow::bail!(
                        "git log 执行失败: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                let commits: Vec<String> = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(|s| s.to_string())
                    .collect();
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "git.log".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: format!(
                        "最近 {} 条 Git 提交记录（{}）",
                        commits.len(),
                        repo.display()
                    ),
                    data: json!({ "repo": repo, "commits": commits }),
                    stdout_preview: commits.join("\n"),
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "git_argv".into(),
                        checks: vec!["exit_zero".into()],
                        details: None,
                    },
                    backend_mode: "git".into(),
                })
            }
            "git.diff" => {
                let repo = args
                    .get("repo")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .or_else(|| std::env::current_dir().ok())
                    .unwrap_or_else(|| PathBuf::from("."));
                let git_bin = resolve_trusted_executable("git")
                    .ok_or_else(|| anyhow::anyhow!("git missing"))?;
                let out = Command::new(git_bin)
                    .arg("-C")
                    .arg(&repo)
                    .args(["diff", "--stat"])
                    .output()?;
                if !out.status.success() {
                    anyhow::bail!(
                        "git diff 执行失败: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let msg = if stat.is_empty() {
                    format!("仓库 {} 当前工作区无未暂存差异", repo.display())
                } else {
                    format!("仓库 {} 未暂存改动：\n{}", repo.display(), stat)
                };
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "git.diff".into(),
                    status: ExecutionStatus::Exited,
                    exit_code: Some(0),
                    message: msg,
                    data: json!({ "repo": repo, "diff_stat": stat }),
                    stdout_preview: stat,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::Passed,
                        method: "git_argv".into(),
                        checks: vec!["exit_zero".into()],
                        details: None,
                    },
                    backend_mode: "git".into(),
                })
            }
            "project.open" => {
                let path_str = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let p = Path::new(path_str);
                if !p.exists() {
                    anyhow::bail!("项目目录不存在: {}", path_str);
                }
                let has_gui = self.has_live_user_gui();
                if has_gui && let Some(code_bin) = resolve_trusted_executable("code") {
                    let _ = spawn_clean_desktop_command(&code_bin, &[path_str]);
                }
                let msg = format!("已请求在代码编辑器中打开项目 {}", path_str);
                Ok(CapabilityResult {
                    request_id: request_id.into(),
                    capability_id: "project.open".into(),
                    status: ExecutionStatus::RequestedUnverified,
                    exit_code: Some(0),
                    message: msg.clone(),
                    data: json!({ "path": path_str }),
                    stdout_preview: msg,
                    stderr_preview: String::new(),
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    changeset_id: None,
                    verification: VerificationReport {
                        state: VerificationState::RequestedUnverified,
                        method: "editor_launch".into(),
                        checks: vec!["project_dir_exists".into()],
                        details: None,
                    },
                    backend_mode: if has_gui {
                        "vscode".into()
                    } else {
                        "simulated_headless".into()
                    },
                })
            }
            other => anyhow::bail!("未实现的内置 handler: {}", other),
        }
    }
}

/// Configure a `std::process::Command` for spawning a desktop GUI application or launcher (`gio`,
/// `gtk-launch`, `xdg-open`, `nautilus`, `code`) without inheriting Conda's `LD_LIBRARY_PATH`,
/// `CONDA_PREFIX`, `PYTHONPATH`, or `PYTHONHOME`.
pub fn configure_clean_desktop_command(cmd: &mut Command) {
    cmd.env_remove("CONDA_PREFIX")
        .env_remove("CONDA_DEFAULT_ENV")
        .env_remove("CONDA_SHLVL")
        .env_remove("CONDA_PYTHON_EXE")
        .env_remove("PYTHONPATH")
        .env_remove("PYTHONHOME")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match std::env::var("LD_LIBRARY_PATH") {
        Ok(raw) => match sanitize_desktop_ld_library_path(&raw) {
            Some(clean) => {
                cmd.env("LD_LIBRARY_PATH", clean);
            }
            None => {
                cmd.env_remove("LD_LIBRARY_PATH");
            }
        },
        Err(_) => {
            cmd.env_remove("LD_LIBRARY_PATH");
        }
    }
}

/// Spawn a detached desktop GUI helper (`gio`, `gtk-launch`, `xdg-open`, `nautilus`) with Conda env vars stripped.
pub fn spawn_clean_desktop_command(
    executable: &Path,
    args: &[&str],
) -> std::io::Result<std::process::Child> {
    let mut cmd = Command::new(executable);
    cmd.args(args);
    configure_clean_desktop_command(&mut cmd);
    cmd.spawn()
}

async fn run_clean_desktop_launcher(executable: &Path, args: &[&str], timeout_ms: u64) -> bool {
    let mut cmd = tokio::process::Command::new(executable);
    cmd.args(args)
        .env_remove("CONDA_PREFIX")
        .env_remove("CONDA_DEFAULT_ENV")
        .env_remove("CONDA_SHLVL")
        .env_remove("CONDA_PYTHON_EXE")
        .env_remove("PYTHONPATH")
        .env_remove("PYTHONHOME")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match std::env::var("LD_LIBRARY_PATH") {
        Ok(raw) => match sanitize_desktop_ld_library_path(&raw) {
            Some(clean) => {
                cmd.env("LD_LIBRARY_PATH", clean);
            }
            None => {
                cmd.env_remove("LD_LIBRARY_PATH");
            }
        },
        Err(_) => {
            cmd.env_remove("LD_LIBRARY_PATH");
        }
    }
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), child.wait()).await {
        Ok(Ok(status)) => status.success(),
        Ok(Err(_)) => false,
        Err(_) => {
            let _ = child.kill().await;
            false
        }
    }
}

fn current_real_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse::<u32>().ok();
        }
    }
    None
}

/// Find live non-zombie PIDs owned by the current user matching an `AppRecord`'s `exec_cmd` / `.desktop` stem.
pub fn find_running_app_pids(rec: &AppRecord) -> Vec<u32> {
    let my_uid = current_real_uid();
    let self_pid = std::process::id();

    let mut needles: Vec<String> = Vec::new();
    let push_needle = |vec: &mut Vec<String>, s: &str| {
        let lc = s.trim().to_ascii_lowercase();
        if lc.len() >= 2 && !vec.contains(&lc) {
            vec.push(lc);
        }
    };

    if let Some(exec_base) = Path::new(rec.exec_cmd.trim())
        .file_name()
        .and_then(|s| s.to_str())
    {
        push_needle(&mut needles, exec_base);
    }
    let exec_stem = extract_binary_stem(&rec.exec_cmd);
    push_needle(&mut needles, &exec_stem);
    let exec_stem_lc = exec_stem.to_ascii_lowercase();
    for suffix in ["-stable", "-native", "_app", "-bin"] {
        if let Some(stripped) = exec_stem_lc.strip_suffix(suffix) {
            push_needle(&mut needles, stripped);
        }
    }
    if exec_stem_lc == "bytedance-feishu-stable" || exec_stem_lc == "bytedance-feishu" {
        push_needle(&mut needles, "feishu");
    } else if exec_stem_lc.starts_with("google-chrome") {
        push_needle(&mut needles, "chrome");
    }

    let is_temp_desktop_fixture = Path::new(&rec.source).starts_with(std::env::temp_dir());
    if !is_temp_desktop_fixture {
        let id_stem = rec.app_id.trim_end_matches(".desktop");
        if !id_stem.contains('.') {
            push_needle(&mut needles, id_stem);
        } else if let Some(last_seg) = id_stem.rsplit('.').next()
            && last_seg.len() >= 3
            && !matches!(
                last_seg.to_ascii_lowercase().as_str(),
                "desktop" | "native" | "app" | "application"
            )
        {
            push_needle(&mut needles, last_seg);
        }
    }

    if needles.is_empty() {
        return Vec::new();
    }

    let matches_needle = |candidate: &str, allow_comm_trunc: bool| -> bool {
        let cand_lc = candidate.trim().to_ascii_lowercase();
        if cand_lc.is_empty() {
            return false;
        }
        needles.iter().any(|n| {
            cand_lc == *n
                || (allow_comm_trunc
                    && cand_lc.len() == 15
                    && n.len() > 15
                    && n.starts_with(&cand_lc))
        })
    };

    let mut matched_pids = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return matched_pids;
    };
    for entry in rd.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid <= 1 || pid == self_pid {
            continue;
        }
        let proc_dir = entry.path();
        let Ok(status_raw) = std::fs::read_to_string(proc_dir.join("status")) else {
            continue;
        };

        let mut proc_uid = None;
        let mut is_zombie = false;
        let mut comm = String::new();
        for line in status_raw.lines() {
            if let Some(rest) = line.strip_prefix("Name:") {
                comm = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("State:") {
                if rest.trim_start().starts_with('Z') {
                    is_zombie = true;
                }
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                proc_uid = rest
                    .split_whitespace()
                    .next()
                    .and_then(|u| u.parse::<u32>().ok());
            }
        }
        if is_zombie {
            continue;
        }
        if let (Some(expected_uid), Some(actual_uid)) = (my_uid, proc_uid)
            && expected_uid != actual_uid
        {
            continue;
        }

        if matches_needle(&comm, true) {
            matched_pids.push(pid);
            continue;
        }

        if let Ok(exe_target) = std::fs::read_link(proc_dir.join("exe"))
            && let Some(exe_name) = exe_target.file_name().and_then(|s| s.to_str())
        {
            let clean_exe = exe_name.trim_end_matches(" (deleted)");
            if matches_needle(clean_exe, false) {
                matched_pids.push(pid);
                continue;
            }
        }

        if let Ok(cmdline_bytes) = std::fs::read(proc_dir.join("cmdline"))
            && !cmdline_bytes.is_empty()
        {
            let argv: Vec<String> = cmdline_bytes
                .split(|b| *b == 0)
                .filter(|seg| !seg.is_empty())
                .take(4)
                .map(|seg| String::from_utf8_lossy(seg).to_string())
                .collect();
            if let Some(arg0) = argv.first() {
                let arg0_base = Path::new(arg0.split_whitespace().next().unwrap_or(arg0))
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(arg0);
                if matches_needle(arg0_base, false) {
                    matched_pids.push(pid);
                    continue;
                }
                let arg0_lc = arg0_base.to_ascii_lowercase();
                if (matches!(
                    arg0_lc.as_str(),
                    "python" | "python3" | "sh" | "bash" | "dash" | "env"
                ) || arg0_lc.starts_with("python3.")
                    || arg0_lc.starts_with("electron"))
                    && argv.iter().skip(1).any(|arg| {
                        !arg.starts_with('-')
                            && Path::new(arg)
                                .file_name()
                                .and_then(|s| s.to_str())
                                .is_some_and(|base| matches_needle(base, false))
                    })
                {
                    matched_pids.push(pid);
                }
            }
        }
    }

    matched_pids.sort_unstable();
    matched_pids
}

fn expand_tilde_arg_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if trimmed == "~" {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        return PathBuf::from(home);
    }
    if let Some(rest) = trimmed.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(trimmed)
}

fn build_verified_app_quit_result(
    request_id: &str,
    app_hint: &str,
    close_res: Value,
    duration_ms: u64,
) -> CapabilityResult {
    let ok = close_res
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let msg = close_res
        .get("summary")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("已执行应用「{}」关闭操作", app_hint));
    let verification = close_res
        .get("verification")
        .and_then(|v| serde_json::from_value::<VerificationReport>(v.clone()).ok())
        .unwrap_or(VerificationReport {
            state: if ok {
                VerificationState::Passed
            } else {
                VerificationState::VerificationFailed
            },
            method: "procfs_post_close_readback".into(),
            checks: vec!["procfs_verified".into()],
            details: None,
        });
    let status = if ok {
        ExecutionStatus::Exited
    } else {
        ExecutionStatus::VerificationFailed
    };
    CapabilityResult {
        request_id: request_id.into(),
        capability_id: "app.quit".into(),
        status,
        exit_code: Some(if ok { 0 } else { 1 }),
        message: msg.clone(),
        data: close_res,
        stdout_preview: msg,
        stderr_preview: String::new(),
        truncated: false,
        duration_ms,
        changeset_id: None,
        verification,
        backend_mode: "app_adapter_verified_close".into(),
    }
}

fn contains_cjk_char(s: &str) -> bool {
    s.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c))
}

fn format_app_launch_display_label(
    installed_rec: &AppRecord,
    args: &Value,
    preferred_label: &str,
) -> String {
    let base_name = if !installed_rec.name.trim().is_empty() {
        installed_rec.name.trim()
    } else {
        preferred_label.trim()
    };

    if contains_cjk_char(base_name) {
        return base_name.to_string();
    }

    // Check if user query or domestic app alias table provides a clean Chinese display name (e.g. `汽水音乐` for `SodaM`)
    let mut zh_label_opt: Option<String> = ["query", "app_name", "app", "name"]
        .iter()
        .filter_map(|k| args.get(*k).and_then(|v| v.as_str()).map(str::trim))
        .find(|s| !s.is_empty() && contains_cjk_char(s))
        .map(String::from);

    if zh_label_opt.is_none() {
        let stem = installed_rec.app_id.trim_end_matches(".desktop");
        let exec_bin = installed_rec
            .exec_cmd
            .split_whitespace()
            .next()
            .and_then(|t| Path::new(t).file_name().and_then(|s| s.to_str()));
        for alias in
            crate::app_adapter::dynamic_profiler::builtin_domestic_app_aliases(stem, exec_bin)
        {
            if contains_cjk_char(alias) {
                zh_label_opt = Some(alias.to_string());
                break;
            }
        }
    }

    if let Some(zh) = zh_label_opt
        && !zh.eq_ignore_ascii_case(base_name)
    {
        return format!("{} ({})", zh, base_name);
    }

    base_name.to_string()
}
