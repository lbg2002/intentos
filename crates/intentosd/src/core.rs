#![forbid(unsafe_code)]

//! Central `IntentOsCore` facade tying together Router (L0), Decision Adapter (L1),
//! Agent Runtime (L2), Broker, Policy, Gateway, Privacy Sessions (`M-01`),
//! Command Passthrough (§8.8), Settings Center (§14.2), and Task Lifecycle (§13).

use crate::broker::{BrokerDispatchOutcome, CapabilityBroker};
use crate::config::{AppConfig, BrainConfig, ProfileConfig, XdgPaths, load_or_create_configs};
use crate::db::{IndexDb, StateDb};
use crate::decision::{DecisionAdapter, L1DecisionOutcome};
use crate::gateway::ModelGateway;
use crate::policy::PolicyEngine;
use crate::resource::ResourceEngine;
use crate::router::{IntentRouter, RoutedIntent};
use crate::runtime::{AgentCoordinator, SessionBuffer, SessionState};
use crate::security_guard::{
    ExecutionContext, PrivacySessionPolicy, SensitiveDataGuard, UnifiedTaskStateMachine,
};
use crate::settings::SystemSettingsEngine;
use chrono::Utc;
use intentos_fsops::SafeFsEngine;
use intentos_protocol::{
    CandidateResponse, CapabilityCall, ChangeSet, ContextBlock, DaemonStatus, DataClass,
    ExecutionStatus, IntentRequest, InvocationOrigin, PROTOCOL_VERSION, RouteLayer, Taint, Task,
    TaskBudget, TaskStatus, TaskStep, TaskTrigger, UiRpcRequest, UiRpcResponse,
};
use intentos_sandbox::probe_sandbox;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassthroughResponse {
    pub status: String,
    pub command: String,
    pub cwd: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub message: String,
    pub requires_confirmation: bool,
    pub suggest_external_terminal: bool,
}

pub struct IntentOsCore {
    pub paths: XdgPaths,
    pub app_config: AppConfig,
    pub brain_config: BrainConfig,
    pub live_configs: Mutex<(AppConfig, BrainConfig)>,
    pub state_db: Arc<StateDb>,
    ephemeral_state_db: Arc<StateDb>,
    pub index_db: Arc<IndexDb>,
    pub fs_engine: Arc<SafeFsEngine>,
    pub resources: Arc<ResourceEngine>,
    pub settings: Arc<SystemSettingsEngine>,
    pub policy: Arc<PolicyEngine>,
    pub broker: Arc<CapabilityBroker>,
    pub router: Arc<IntentRouter>,
    pub gateway: Arc<ModelGateway>,
    pub decision: Arc<DecisionAdapter>,
    pub sessions: Arc<SessionBuffer>,
    pub agent: Arc<AgentCoordinator>,
    incognito_tasks: Mutex<HashMap<String, Task>>,
    task_privacy_policies: Mutex<HashMap<String, PrivacySessionPolicy>>,
    passthrough_cwd: Mutex<PathBuf>,
    started_at: Instant,
}

impl IntentOsCore {
    pub fn initialize(
        custom_base: Option<&std::path::Path>,
        repo_root: PathBuf,
    ) -> anyhow::Result<Arc<Self>> {
        let paths = XdgPaths::resolve(custom_base, repo_root);
        let (app_config, brain_config) = load_or_create_configs(&paths)?;

        let state_db = Arc::new(StateDb::open(&paths.state_db_path())?);
        let ephemeral_state_db = Arc::new(StateDb::open_in_memory()?);
        let index_db = Arc::new(IndexDb::open_or_rebuild(&paths.index_db_path())?);

        let mut auth_roots: Vec<PathBuf> = app_config
            .authorized_directories
            .iter()
            .map(PathBuf::from)
            .collect();
        for r in &auth_roots {
            let _ = std::fs::create_dir_all(r);
        }
        if auth_roots.is_empty() {
            let fallback = paths.data_dir.join("workspace");
            std::fs::create_dir_all(&fallback)?;
            auth_roots.push(fallback);
        }

        let forbidden = vec![
            paths.config_dir.clone(),
            paths.data_dir.clone(),
            paths.state_dir.clone(),
            paths.runtime_dir.clone(),
        ];
        let trash_dir = paths.data_dir.join("trash");
        let fs_engine = Arc::new(
            SafeFsEngine::new(
                auth_roots,
                forbidden,
                paths.data_dir.join("undo"),
                trash_dir,
            )?
            .with_quota(
                app_config.undo.quota_gb * 1024 * 1024 * 1024,
                app_config.undo.retention_days,
            ),
        );

        let resources = Arc::new(ResourceEngine::new(
            index_db.clone(),
            fs_engine.clone(),
            app_config.clone(),
        ));
        let _ = resources.refresh_all();

        let settings = Arc::new(
            SystemSettingsEngine::new(
                state_db.clone(),
                app_config.allow_simulated_hardware_fallback,
            )
            .with_resources(resources.clone(), fs_engine.clone()),
        );
        let policy = Arc::new(PolicyEngine::new(fs_engine.clone()));
        let broker = Arc::new(CapabilityBroker::load(
            &paths.builtin_modules_dir(),
            state_db.clone(),
            index_db.clone(),
            fs_engine.clone(),
            resources.clone(),
            settings.clone(),
            policy.clone(),
        )?);
        let router = Arc::new(IntentRouter::new(resources.clone()).with_state_db(state_db.clone()));
        let gateway = Arc::new(ModelGateway::new(brain_config.clone(), state_db.clone())?);
        gateway.set_paths(paths.clone());
        let decision = Arc::new(DecisionAdapter::new(gateway.clone(), state_db.clone()));
        let sessions = Arc::new(SessionBuffer::new(
            brain_config.runtime_limits.session_idle_timeout_minutes,
        ));
        let agent = Arc::new(AgentCoordinator::new(
            paths.clone(),
            brain_config.runtime.clone(),
            gateway.clone(),
            broker.clone(),
            state_db.clone(),
        ));

        let init_cwd = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));

        let core = Arc::new(Self {
            paths,
            live_configs: Mutex::new((app_config.clone(), brain_config.clone())),
            app_config,
            brain_config,
            state_db,
            ephemeral_state_db,
            index_db,
            fs_engine,
            resources,
            settings,
            policy,
            broker,
            router,
            gateway,
            decision,
            sessions,
            agent,
            incognito_tasks: Mutex::new(HashMap::new()),
            task_privacy_policies: Mutex::new(HashMap::new()),
            passthrough_cwd: Mutex::new(init_cwd),
            started_at: Instant::now(),
        });
        core.broker.bind_core(Arc::downgrade(&core));
        core.agent.bind_core(Arc::downgrade(&core));
        Ok(core)
    }

    pub fn query_candidates(&self, query: &str) -> CandidateResponse {
        self.router.query_candidates(query)
    }

    /// Handle an RPC request arriving over the trusted private UI socket (`ui.sock` or local preview).
    pub async fn handle_trusted_ui_rpc(&self, id: String, req: UiRpcRequest) -> UiRpcResponse {
        let res: anyhow::Result<Value> = async {
            match req {
                UiRpcRequest::QueryCandidates { query } => {
                    Ok(serde_json::to_value(self.query_candidates(&query))?)
                }
                UiRpcRequest::SubmitIntent(intent_req) => {
                    // If user typed `$ ...` in trusted UI, route to user-authored Passthrough (§8.8)!
                    if let Some(cmd) = intent_req.text.trim().strip_prefix('$') {
                        let out = self
                            .run_passthrough_with_privacy(
                                cmd.trim(),
                                intent_req.cwd.as_deref(),
                                false,
                                intent_req.effective_privacy().allows_habit_learning(),
                            )
                            .await?;
                        return Ok(json!({
                            "kind": "passthrough",
                            "passthrough": out,
                        }));
                    }
                    let task = self.submit_intent(intent_req, Vec::new()).await?;
                    Ok(serde_json::to_value(task)?)
                }
                UiRpcRequest::Approve {
                    approval_id,
                    nonce,
                    digest,
                } => {
                    let task = self.approve_pending(&approval_id, &nonce, &digest).await?;
                    Ok(serde_json::to_value(task)?)
                }
                UiRpcRequest::Deny { approval_id } => {
                    let task = self.deny_pending(&approval_id)?;
                    Ok(serde_json::to_value(task)?)
                }
                UiRpcRequest::Undo { target_id } => {
                    let (cs, msg) = self.undo(target_id.as_deref())?;
                    Ok(json!({ "changeset": cs, "message": msg }))
                }
                UiRpcRequest::RunPassthrough {
                    command,
                    cwd,
                    confirmed_risky,
                } => {
                    let out = self
                        .run_passthrough(&command, cwd.as_deref(), confirmed_risky)
                        .await?;
                    Ok(serde_json::to_value(out)?)
                }
                UiRpcRequest::ListTasks { limit } => {
                    Ok(serde_json::to_value(self.state_db.list_tasks(limit)?)?)
                }
                UiRpcRequest::GetTask { task_id } => {
                    Ok(serde_json::to_value(self.state_db.get_task(&task_id)?)?)
                }
                UiRpcRequest::ListChangesets { limit } => {
                    Ok(serde_json::to_value(self.state_db.list_changesets(limit)?)?)
                }
                UiRpcRequest::ListMemories => {
                    Ok(serde_json::to_value(self.state_db.list_memory_entries()?)?)
                }
                UiRpcRequest::UpsertMemory { subject, value } => {
                    let mem_id = self.state_db.save_explicit_memory(&subject, &value, None)?;
                    Ok(json!({ "id": mem_id, "subject": subject, "value": value }))
                }
                UiRpcRequest::DeleteMemory { id } => {
                    let deleted = self.state_db.delete_memory(&id)?;
                    Ok(json!({ "id": id, "deleted": deleted }))
                }
                UiRpcRequest::ListScenes => Ok(json!(self.settings.list_all_scenes())),
                UiRpcRequest::SaveScene { name } => {
                    let message = self.settings.snapshot_current_scene(&name)?;
                    Ok(json!({ "name": name, "message": message }))
                }
                UiRpcRequest::ListPassthroughHistory { limit } => {
                    Ok(json!(self.index_db.list_passthrough_history(limit)))
                }
                UiRpcRequest::ClearPassthroughHistory => {
                    let cleared = self.index_db.clear_passthrough_history();
                    Ok(json!({ "cleared": cleared }))
                }
                UiRpcRequest::GetSettingsOverview => Ok(self.settings_overview()?),
                UiRpcRequest::UpdateAuthorizedDirectories { directories } => {
                    let cleaned: Vec<String> = directories
                        .into_iter()
                        .map(|d| d.trim().to_string())
                        .filter(|d| !d.is_empty())
                        .collect();
                    let mut guard = self.live_configs.lock().unwrap();
                    guard.0.authorized_directories = cleaned.clone();
                    let cfg_toml = toml::to_string_pretty(&guard.0)?;
                    drop(guard);
                    std::fs::write(self.paths.config_dir.join("config.toml"), cfg_toml)?;
                    Ok(json!({
                        "authorized_directories": cleaned,
                        "message": "已保存授权目录列表（重启守护进程后新内核句柄将完全生效）"
                    }))
                }
                UiRpcRequest::UpdateWebSettings { default_search } => {
                    let clean = default_search.trim().to_ascii_lowercase();
                    if !matches!(clean.as_str(), "google" | "bing" | "baidu" | "duckduckgo") {
                        anyhow::bail!("不支持的默认搜索引擎 ID: {}", clean);
                    }
                    let mut guard = self.live_configs.lock().unwrap();
                    guard.0.web.default_search = clean.clone();
                    let cfg_toml = toml::to_string_pretty(&guard.0)?;
                    drop(guard);
                    std::fs::write(self.paths.config_dir.join("config.toml"), cfg_toml)?;
                    Ok(json!({ "default_search": clean, "saved": true }))
                }
                UiRpcRequest::UpdateBrainSettings {
                    runtime,
                    main_provider,
                    main_model,
                } => {
                    let rt = if runtime.trim() == "native" {
                        "native".to_string()
                    } else {
                        "pi".to_string()
                    };
                    let mut guard = self.live_configs.lock().unwrap();
                    guard.1.runtime = rt.clone();
                    let entry = guard
                        .1
                        .profiles
                        .entry("main".to_string())
                        .or_insert_with(|| ProfileConfig {
                            provider: main_provider.clone(),
                            model: main_model.clone(),
                            context_budget: 65536,
                            max_output_tokens: 4096,
                        });
                    if !main_provider.trim().is_empty() {
                        entry.provider = main_provider.trim().to_string();
                    }
                    if !main_model.trim().is_empty() {
                        entry.model = main_model.trim().to_string();
                    }
                    let updated_brain = guard.1.clone();
                    let brain_toml = toml::to_string_pretty(&updated_brain)?;
                    drop(guard);
                    self.gateway.update_brain_config(updated_brain);
                    std::fs::write(self.paths.config_dir.join("brain.toml"), brain_toml)?;
                    Ok(json!({
                        "runtime": rt,
                        "main_provider": main_provider,
                        "main_model": main_model,
                        "saved": true
                    }))
                }
                UiRpcRequest::GetStatus => Ok(serde_json::to_value(self.status())?),
                UiRpcRequest::ProbeCapabilities => Ok(self.probe_summary()),
                UiRpcRequest::StopAll => {
                    self.stop_all()?;
                    Ok(json!({ "stopped": true }))
                }
                UiRpcRequest::ReindexResources => {
                    let (apps, files) = self.resources.refresh_all()?;
                    Ok(json!({ "apps": apps, "files": files }))
                }
                UiRpcRequest::ModuleRpc {
                    domain,
                    action,
                    payload,
                } => match domain.as_str() {
                    "intent_engine" => {
                        crate::intent_engine::handle_module_rpc(self, &action, payload).await
                    }
                    "config_center" => {
                        crate::config_center::handle_module_rpc(self, &action, payload).await
                    }
                    "execution_hub" => {
                        crate::execution_hub::handle_module_rpc(self, &action, payload).await
                    }
                    "memory_hub" => {
                        crate::memory_hub::handle_module_rpc(self, &action, payload).await
                    }
                    "app_adapter" => {
                        crate::app_adapter::handle_module_rpc(self, &action, payload).await
                    }
                    "backend_bridge" => {
                        crate::backend_bridge::handle_module_rpc(self, &action, payload).await
                    }
                    "speech_hub" => {
                        crate::speech_hub::handle_module_rpc(self, &action, payload).await
                    }
                    "web_ui" => crate::web_ui::handle_module_rpc(self, &action, payload).await,
                    other => anyhow::bail!("未知的功能模块域 (domain): {}", other),
                },
            }
        }
        .await;

        match res {
            Ok(val) => UiRpcResponse {
                id,
                ok: true,
                result: Some(val),
                error: None,
            },
            Err(err) => UiRpcResponse {
                id,
                ok: false,
                result: None,
                error: Some(err.to_string()),
            },
        }
    }

    pub(crate) fn register_task_privacy_policy(&self, task_id: &str, policy: PrivacySessionPolicy) {
        self.task_privacy_policies
            .lock()
            .unwrap()
            .insert(task_id.to_string(), policy);
    }

    pub(crate) fn task_privacy_policy(&self, task_id: &str) -> PrivacySessionPolicy {
        if let Some(p) = self
            .task_privacy_policies
            .lock()
            .unwrap()
            .get(task_id)
            .copied()
        {
            return p;
        }
        if self.incognito_tasks.lock().unwrap().contains_key(task_id)
            && !task_id.starts_with("ephemeral_ro_")
        {
            return PrivacySessionPolicy::StrictIsolated;
        }
        PrivacySessionPolicy::from_task_id(task_id)
    }

    pub(crate) fn persist_or_ephemeral_with_privacy(
        &self,
        task: &Task,
        privacy: PrivacySessionPolicy,
    ) -> anyhow::Result<()> {
        self.register_task_privacy_policy(&task.id, privacy);
        if !privacy.allows_task_persistence() {
            if task.status == TaskStatus::AwaitingApproval {
                self.incognito_tasks.lock().unwrap().insert(
                    task.id.clone(),
                    SensitiveDataGuard::sanitize_task_for_storage(task),
                );
            }
            Ok(())
        } else {
            self.state_db.upsert_task(task)
        }
    }

    pub(crate) fn persist_or_ephemeral(&self, task: &Task, incognito: bool) -> anyhow::Result<()> {
        let privacy = if incognito {
            PrivacySessionPolicy::StrictIsolated
        } else {
            self.task_privacy_policy(&task.id)
        };
        self.persist_or_ephemeral_with_privacy(task, privacy)
    }

    /// Submit an Intent (Note: public/untrusted callers NEVER trigger `$` passthrough here! §19.2).
    pub async fn submit_intent(
        &self,
        req: IntentRequest,
        injected_context: Vec<ContextBlock>,
    ) -> anyhow::Result<Task> {
        self.submit_intent_internal(req, injected_context, true)
            .await
    }

    /// Internal intent entry point allowing callers such as `backend_bridge::send_quick_chat_turn`
    /// to avoid double-recording conversation turns in `memory_hub`.
    pub(crate) async fn submit_intent_internal(
        &self,
        req: IntentRequest,
        injected_context: Vec<ContextBlock>,
        record_in_memory_hub: bool,
    ) -> anyhow::Result<Task> {
        let privacy = req.effective_privacy();
        let original_user_text = req.text.clone();
        let is_passthrough_attempt = original_user_text.trim().starts_with('$');

        let task = self.submit_intent_inner(req, injected_context).await?;

        if record_in_memory_hub
            && privacy.allows_memory_write()
            && !is_passthrough_attempt
            && task.data_class != DataClass::Forbidden
        {
            let assistant_text = task
                .assistant_message
                .as_deref()
                .or(task.result_summary.as_deref())
                .unwrap_or("")
                .to_string();
            let tool_steps: Vec<Value> = task
                .steps
                .iter()
                .map(|s| {
                    json!({
                        "capability_id": s.capability_id,
                        "arguments_summary": s.arguments_summary,
                        "status": s.status,
                        "duration_ms": s.duration_ms,
                        "changeset_id": s.changeset_id,
                        "message": s.message,
                        "data": s.data,
                    })
                })
                .collect();
            let _ = crate::memory_hub::record_conversation_turn_with_policy(
                self,
                &crate::memory_hub::RecordTurnInput {
                    session_id: task.session_id.clone(),
                    user_text: SensitiveDataGuard::redact_text(&original_user_text).0,
                    assistant_text: SensitiveDataGuard::redact_text(&assistant_text).0,
                    thinking: None,
                    tool_steps,
                    trace_dots: Vec::new(),
                    incognito: !privacy.allows_memory_write(),
                },
                privacy,
            );
        }

        Ok(task)
    }

    async fn submit_intent_inner(
        &self,
        req: IntentRequest,
        mut injected_context: Vec<ContextBlock>,
    ) -> anyhow::Result<Task> {
        let privacy = req.effective_privacy();
        let incognito = privacy == PrivacySessionPolicy::StrictIsolated;
        if !privacy.allows_memory_read() {
            injected_context.retain(|b| {
                b.taint != Taint::Memory && b.label != "memories" && b.label != "personal_os_memory"
            });
        }
        let session = match privacy {
            PrivacySessionPolicy::StrictIsolated => SessionState {
                session_id: ExecutionContext::fallback_session_id(
                    PrivacySessionPolicy::StrictIsolated,
                ),
                messages: Vec::new(),
                last_resource_path: None,
                updated_at: Utc::now(),
            },
            PrivacySessionPolicy::EphemeralReadOnly => {
                let target_sid = req
                    .session_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.starts_with("incog_"))
                    .map(String::from)
                    .unwrap_or_else(|| {
                        ExecutionContext::fallback_session_id(
                            PrivacySessionPolicy::EphemeralReadOnly,
                        )
                    });
                if let Some(existing) = self.sessions.peek(&target_sid) {
                    existing
                } else {
                    let hydrated_turns = crate::memory_hub::hydrate_session_qa_turns_with_policy(
                        self,
                        None,
                        &target_sid,
                        PrivacySessionPolicy::EphemeralReadOnly,
                    );
                    let mut hydrated_msgs = Vec::with_capacity(hydrated_turns.len() * 2);
                    for t in hydrated_turns
                        .into_iter()
                        .rev()
                        .take(8)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                    {
                        hydrated_msgs.push(intentos_protocol::ChatMessage {
                            role: "user".into(),
                            content: t.user_question,
                        });
                        hydrated_msgs.push(intentos_protocol::ChatMessage {
                            role: "assistant".into(),
                            content: t.clean_assistant_answer,
                        });
                    }
                    SessionState {
                        session_id: target_sid,
                        messages: hydrated_msgs,
                        last_resource_path: None,
                        updated_at: Utc::now(),
                    }
                }
            }
            PrivacySessionPolicy::Standard => {
                self.sessions.get_or_create(req.session_id.as_deref())
            }
        };
        let task_id = ExecutionContext::new_task_id(privacy);
        self.register_task_privacy_policy(&task_id, privacy);
        let now = Utc::now();

        let mut taints = vec![Taint::User];
        let mut data_class = DataClass::Public;
        for blk in &injected_context {
            if !taints.contains(&blk.taint) {
                taints.push(blk.taint);
            }
            if blk.data_class > data_class {
                data_class = blk.data_class;
            }
        }

        // Security rule (§19.2): `$ ...` arriving via `submit_intent` (e.g. public D-Bus or model text)
        // MUST NOT execute passthrough! Reject cleanly.
        if req.text.trim().starts_with('$') {
            let task = Task {
                id: task_id,
                goal: req.text.clone(),
                session_id: Some(session.session_id),
                project_id: None,
                trigger: TaskTrigger::User,
                route: RouteLayer::L0,
                status: TaskStatus::Failed,
                steps: Vec::new(),
                changeset_ids: Vec::new(),
                pending_approval: None,
                candidates_for_disambiguation: Vec::new(),
                assistant_message: Some(
                    "安全拦截：命令直通（`$`）仅接受可信 UI 私有通道的键盘输入，外部接口或模型文本不可触发"
                        .into(),
                ),
                result_summary: Some("blocked_untrusted_passthrough".into()),
                handoff_command: None,
                taint: taints,
                data_class,
                budget: TaskBudget::default(),
                created_at: now,
                updated_at: now,
            };
            self.persist_or_ephemeral(&task, incognito)?;
            return Ok(task);
        }

        // Multi-turn pronoun resolution ("把它移到..." / "打开它所在文件夹" -> substitute session.last_resource_path, A20 + v0.3 intent_engine)
        let mut resolved_text = if let Some(last_p) = session.last_resource_path.as_deref() {
            if req.text.contains("把它") || req.text.contains("将它") {
                req.text
                    .replace("把它", &format!("把 {}", last_p))
                    .replace("将它", &format!("把 {}", last_p))
            } else if req.text.contains("它所在文件夹") || req.text.contains("它所在目录")
            {
                format!("打开 {} 所在文件夹", last_p)
            } else if req.text == "打开它" {
                format!("打开 {}", last_p)
            } else {
                req.text.clone()
            }
        } else {
            req.text.clone()
        };
        if resolved_text == req.text {
            let ctx_state_db = if privacy.allows_memory_read() {
                Some(self.state_db.as_ref())
            } else {
                None
            };
            let ctx_out = crate::intent_engine::resolve_context_references(
                &req.text,
                Some(&session),
                ctx_state_db,
                None,
            );
            if ctx_out.is_resolved() {
                resolved_text = ctx_out.effective_text().to_string();
            }
        }
        // Wave 2 Personal Memory Hub multi-turn entity resolution ("打开我之前说的那个文件" / "把刚才提到的那个文件移到下载")
        if privacy.allows_memory_read()
            && resolved_text == req.text
            && let Some(mem_resolved) =
                resolve_conversational_memory_entity(self, &req.text, &session.session_id)
        {
            resolved_text = mem_resolved;
        }

        // If user explicitly picked a candidate from the disambiguation / launcher list, run it directly!
        if let Some(ref sel_id) = req.selected_candidate_id {
            let cands = self.query_candidates(&resolved_text);
            if let Some(chosen) = cands.items.into_iter().find(|c| &c.id == sel_id)
                && let Some(cap_id) = chosen.capability_id
            {
                return self
                    .execute_single_capability_task(
                        task_id,
                        &session.session_id,
                        &resolved_text,
                        RouteLayer::L0,
                        &cap_id,
                        chosen.arguments,
                        InvocationOrigin::UserExplicit,
                        taints,
                        data_class,
                        incognito,
                    )
                    .await;
            }
        }

        let effective_force_agent = req.force_agent && self.gateway.has_usable_credentials();
        let is_multi_clause_input =
            crate::intent_engine::split_into_clauses(&resolved_text).len() >= 2;
        let is_aios_memory_or_adapter_query =
            !is_multi_clause_input && is_explicit_personal_memory_or_adapter_query(&resolved_text);
        let is_doc_chapter_query =
            !is_multi_clause_input && is_smart_document_chapter_query(&resolved_text);

        // When no cloud LLM credentials exist, answer personal-memory, document chapter-open, and software-adapter queries directly!
        if !effective_force_agent
            && !self.gateway.has_usable_credentials()
            && (is_aios_memory_or_adapter_query || is_doc_chapter_query)
            && let Some(task) = self
                .try_complete_aios_deterministic_task(
                    &task_id,
                    &session,
                    &resolved_text,
                    taints.clone(),
                    data_class,
                    privacy,
                    now,
                )
                .await?
        {
            return Ok(task);
        }

        let stage0_speech = crate::intent_engine::parse_structured_intent(&resolved_text, &[]);
        let is_procedural_question = stage0_speech.speech_act
            == crate::intent_engine::goal_schema::SpeechActModality::ProceduralOrExplanatory;

        let routed = if is_aios_memory_or_adapter_query || is_doc_chapter_query {
            RoutedIntent::EscalateL2 {
                reason: "AIOS 个人记忆、文档章节大纲定位或软件指令转译查询升级至 L2 智能体".into(),
            }
        } else if is_procedural_question {
            RoutedIntent::EscalateL2 {
                reason: stage0_speech.escalation_summary(),
            }
        } else if privacy.allows_memory_read() {
            self.router
                .route_text(&resolved_text, effective_force_agent)
        } else {
            IntentRouter::new(self.resources.clone())
                .route_text(&resolved_text, effective_force_agent)
        };

        match routed {
            RoutedIntent::ExecuteL0 {
                capability_id,
                mut arguments,
                ..
            } => {
                if matches!(
                    capability_id.as_str(),
                    "git.status" | "git.log" | "git.diff"
                ) && let Some(ref caller_cwd) = req.cwd
                    && let Some(obj) = arguments.as_object_mut()
                {
                    obj.entry("repo_dir".to_string())
                        .or_insert_with(|| json!(caller_cwd));
                }
                self.execute_single_capability_task(
                    task_id,
                    &session.session_id,
                    &resolved_text,
                    RouteLayer::L0,
                    &capability_id,
                    arguments,
                    InvocationOrigin::UserExplicit,
                    taints,
                    data_class,
                    incognito,
                )
                .await
            }
            RoutedIntent::UndoLatest => {
                let (status, msg, cs_ids) = match self.undo(None) {
                    Ok((cs, m)) => (TaskStatus::Completed, m, vec![cs.id]),
                    Err(e) => (TaskStatus::Failed, e.to_string(), Vec::new()),
                };
                let task = Task {
                    id: task_id,
                    goal: resolved_text.clone(),
                    session_id: Some(session.session_id.clone()),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L0,
                    status,
                    steps: Vec::new(),
                    changeset_ids: cs_ids,
                    pending_approval: None,
                    candidates_for_disambiguation: Vec::new(),
                    assistant_message: Some(msg.clone()),
                    result_summary: Some(msg.clone()),
                    handoff_command: None,
                    taint: taints,
                    data_class,
                    budget: TaskBudget::default(),
                    created_at: now,
                    updated_at: Utc::now(),
                };
                self.persist_or_ephemeral_with_privacy(&task, privacy)?;
                if privacy.allows_memory_write() {
                    self.sessions
                        .append_turn(&session.session_id, &resolved_text, &msg, None);
                }
                Ok(task)
            }
            RoutedIntent::SaveExplicitMemory { subject, value } => {
                if !privacy.allows_memory_write() {
                    let msg = format!(
                        "当前处于隐私会话（{}）模式：不保存任何持久化记忆或历史记录",
                        privacy.as_str()
                    );
                    let clean_goal = SensitiveDataGuard::redact_text(&resolved_text).0;
                    return Ok(Task {
                        id: task_id,
                        goal: clean_goal,
                        session_id: Some(session.session_id),
                        project_id: None,
                        trigger: TaskTrigger::User,
                        route: RouteLayer::L0,
                        status: TaskStatus::Failed,
                        steps: Vec::new(),
                        changeset_ids: Vec::new(),
                        pending_approval: None,
                        candidates_for_disambiguation: Vec::new(),
                        assistant_message: Some(msg.clone()),
                        result_summary: Some(msg),
                        handoff_command: None,
                        taint: taints,
                        data_class: DataClass::Personal,
                        budget: TaskBudget::default(),
                        created_at: now,
                        updated_at: Utc::now(),
                    });
                }
                let raw_secret_detected =
                    SensitiveDataGuard::contains_sensitive_secret(&resolved_text).is_some()
                        || SensitiveDataGuard::contains_sensitive_secret(&subject).is_some()
                        || SensitiveDataGuard::contains_sensitive_secret(&value).is_some();
                let save_res = if raw_secret_detected {
                    Err(anyhow::anyhow!(
                        "出于安全策略，禁止在记忆中心保存密钥、口令或认证凭据"
                    ))
                } else {
                    self.state_db
                        .save_explicit_memory(&subject, &value, Some(&task_id))
                };
                match save_res {
                    Ok(mem_id) => {
                        let msg = format!("✓ 已记住偏好 [{}]：{} = {}", mem_id, subject, value);
                        let task = Task {
                            id: task_id,
                            goal: resolved_text.clone(),
                            session_id: Some(session.session_id.clone()),
                            project_id: None,
                            trigger: TaskTrigger::User,
                            route: RouteLayer::L0,
                            status: TaskStatus::Completed,
                            steps: Vec::new(),
                            changeset_ids: Vec::new(),
                            pending_approval: None,
                            candidates_for_disambiguation: Vec::new(),
                            assistant_message: Some(msg.clone()),
                            result_summary: Some(msg.clone()),
                            handoff_command: None,
                            taint: taints,
                            data_class: DataClass::Personal,
                            budget: TaskBudget::default(),
                            created_at: now,
                            updated_at: Utc::now(),
                        };
                        self.state_db.upsert_task(&task)?;
                        self.sessions
                            .append_turn(&session.session_id, &resolved_text, &msg, None);
                        Ok(task)
                    }
                    Err(err) => {
                        let (msg, _) = SensitiveDataGuard::redact_text(&err.to_string());
                        let (clean_goal, _) = SensitiveDataGuard::redact_text(&resolved_text);
                        let task = SensitiveDataGuard::sanitize_task_for_storage(&Task {
                            id: task_id,
                            goal: clean_goal,
                            session_id: Some(session.session_id),
                            project_id: None,
                            trigger: TaskTrigger::User,
                            route: RouteLayer::L0,
                            status: TaskStatus::Failed,
                            steps: Vec::new(),
                            changeset_ids: Vec::new(),
                            pending_approval: None,
                            candidates_for_disambiguation: Vec::new(),
                            assistant_message: Some(msg.clone()),
                            result_summary: Some(msg),
                            handoff_command: None,
                            taint: taints,
                            data_class: DataClass::Forbidden,
                            budget: TaskBudget::default(),
                            created_at: now,
                            updated_at: Utc::now(),
                        });
                        self.state_db.upsert_task(&task)?;
                        Ok(task)
                    }
                }
            }
            RoutedIntent::SaveCurrentScene { name } => {
                if !privacy.allows_memory_write() {
                    let msg = format!(
                        "当前处于隐私会话（{}）模式：不保存持久化场景快照",
                        privacy.as_str()
                    );
                    let task = Task {
                        id: task_id,
                        goal: resolved_text.clone(),
                        session_id: Some(session.session_id.clone()),
                        project_id: None,
                        trigger: TaskTrigger::User,
                        route: RouteLayer::L0,
                        status: TaskStatus::Failed,
                        steps: Vec::new(),
                        changeset_ids: Vec::new(),
                        pending_approval: None,
                        candidates_for_disambiguation: Vec::new(),
                        assistant_message: Some(msg.clone()),
                        result_summary: Some(msg),
                        handoff_command: None,
                        taint: taints,
                        data_class,
                        budget: TaskBudget::default(),
                        created_at: now,
                        updated_at: Utc::now(),
                    };
                    return Ok(task);
                }
                let (status, msg) = match self.settings.snapshot_current_scene(&name) {
                    Ok(m) => (TaskStatus::Completed, m),
                    Err(e) => (TaskStatus::Failed, e.to_string()),
                };
                let task = Task {
                    id: task_id,
                    goal: resolved_text.clone(),
                    session_id: Some(session.session_id.clone()),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L0,
                    status,
                    steps: Vec::new(),
                    changeset_ids: Vec::new(),
                    pending_approval: None,
                    candidates_for_disambiguation: Vec::new(),
                    assistant_message: Some(msg.clone()),
                    result_summary: Some(msg.clone()),
                    handoff_command: None,
                    taint: taints,
                    data_class,
                    budget: TaskBudget::default(),
                    created_at: now,
                    updated_at: Utc::now(),
                };
                self.persist_or_ephemeral_with_privacy(&task, privacy)?;
                if privacy.allows_memory_write() {
                    self.sessions
                        .append_turn(&session.session_id, &resolved_text, &msg, None);
                }
                Ok(task)
            }
            RoutedIntent::Disambiguate { prompt, candidates } => {
                let task = Task {
                    id: task_id,
                    goal: resolved_text,
                    session_id: Some(session.session_id),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L0,
                    status: TaskStatus::Paused,
                    steps: Vec::new(),
                    changeset_ids: Vec::new(),
                    pending_approval: None,
                    candidates_for_disambiguation: candidates,
                    assistant_message: Some(prompt),
                    result_summary: Some("needs_clarification".into()),
                    handoff_command: None,
                    taint: taints,
                    data_class,
                    budget: TaskBudget::default(),
                    created_at: now,
                    updated_at: Utc::now(),
                };
                self.persist_or_ephemeral(&task, incognito)?;
                Ok(task)
            }
            RoutedIntent::Rejected { reason } => {
                let task = Task {
                    id: task_id,
                    goal: resolved_text,
                    session_id: Some(session.session_id),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L0,
                    status: TaskStatus::Failed,
                    steps: Vec::new(),
                    changeset_ids: Vec::new(),
                    pending_approval: None,
                    candidates_for_disambiguation: Vec::new(),
                    assistant_message: Some(reason.clone()),
                    result_summary: Some(reason),
                    handoff_command: None,
                    taint: taints,
                    data_class,
                    budget: TaskBudget::default(),
                    created_at: now,
                    updated_at: Utc::now(),
                };
                self.persist_or_ephemeral(&task, incognito)?;
                Ok(task)
            }
            RoutedIntent::EscalateL2 { .. } => {
                let mut progressive_goal: Option<crate::intent_engine::StructuredIntent> = None;
                // Stage 2 (`v0.1` + `H08` + `H09`): Run Progressive L1 Typed Decision Adapter before escalating to L2 unless `effective_force_agent` or AIOS memory/chapter/adapter query!
                if !effective_force_agent
                    && !is_aios_memory_or_adapter_query
                    && !is_doc_chapter_query
                {
                    let descriptors = self.broker.descriptors();
                    let l1_outcome = if is_multi_clause_input {
                        let extra_taint =
                            if crate::decision::score_prompt_injection_risk(&resolved_text) >= 0.65
                            {
                                Some(Taint::LocalUntrusted)
                            } else {
                                None
                            };
                        L1DecisionOutcome::EscalateL2 {
                            reason: "检测到多子句复合意图，交由复合意图拆解器与 L2 智能体协同处理"
                                .into(),
                            extra_taint,
                        }
                    } else if privacy.allows_memory_write() {
                        let (out, prog) = self
                            .decision
                            .classify_colloquial_intent_progressive_with_privacy(
                                &resolved_text,
                                &descriptors,
                                req.cwd.as_deref(),
                                privacy,
                            )
                            .await;
                        progressive_goal = Some(prog);
                        out
                    } else {
                        let (out, prog) = DecisionAdapter::new(
                            self.gateway.clone(),
                            self.ephemeral_state_db.clone(),
                        )
                        .classify_colloquial_intent_progressive_with_privacy(
                            &resolved_text,
                            &descriptors,
                            req.cwd.as_deref(),
                            privacy,
                        )
                        .await;
                        progressive_goal = Some(prog);
                        out
                    };
                    match l1_outcome {
                        L1DecisionOutcome::Execute {
                            capability_id,
                            arguments,
                            extra_taint,
                            ..
                        } => {
                            if let Some(et) = extra_taint
                                && !taints.contains(&et)
                            {
                                taints.push(et);
                            }
                            let prereq_obs = progressive_goal
                                .as_ref()
                                .and_then(|g| g.prerequisite_observe_capability.as_deref());
                            return self
                                .execute_single_capability_task_with_observe(
                                    task_id,
                                    &session.session_id,
                                    &resolved_text,
                                    RouteLayer::L1,
                                    &capability_id,
                                    arguments,
                                    prereq_obs,
                                    InvocationOrigin::L1Inferred,
                                    taints,
                                    data_class,
                                    incognito,
                                )
                                .await;
                        }
                        L1DecisionOutcome::Clarify {
                            prompt,
                            candidates,
                            extra_taint,
                        } => {
                            if let Some(et) = extra_taint
                                && !taints.contains(&et)
                            {
                                taints.push(et);
                            }
                            let mut task = Task {
                                id: task_id,
                                goal: resolved_text,
                                session_id: Some(session.session_id),
                                project_id: None,
                                trigger: TaskTrigger::User,
                                route: RouteLayer::L1,
                                status: TaskStatus::Created,
                                steps: Vec::new(),
                                changeset_ids: Vec::new(),
                                pending_approval: None,
                                candidates_for_disambiguation: candidates,
                                assistant_message: Some(prompt),
                                result_summary: Some("l1_needs_clarification".into()),
                                handoff_command: None,
                                taint: taints,
                                data_class,
                                budget: TaskBudget::default(),
                                created_at: now,
                                updated_at: Utc::now(),
                            };
                            UnifiedTaskStateMachine::transition_task(
                                &mut task,
                                TaskStatus::Paused,
                                None,
                            )?;
                            self.persist_or_ephemeral(&task, incognito)?;
                            return Ok(task);
                        }
                        L1DecisionOutcome::EscalateL2 { extra_taint, .. } => {
                            if let Some(et) = extra_taint
                                && !taints.contains(&et)
                            {
                                taints.push(et);
                            }

                            // v0.3 + M1 P0 `intent_engine` compound clause integrity & Pinyin/fuzzy evaluation:
                            // 1) All-resolved compound system steps execute deterministically.
                            // 2) Partially-resolved compound intents (`total_clauses >= 2 && has_unresolved_clauses()`)
                            //    NEVER silently drop unresolved sub-goals: escalate to L2 with a plan ContextBlock
                            //    when online, or report unresolved sub-goals explicitly with `PartiallyCompleted` offline.
                            // 3) Single-clause utterances (`total_clauses <= 1`) preserve exact Pinyin/fuzzy fallback.
                            if !taints.contains(&Taint::LocalUntrusted)
                                && !taints.contains(&Taint::RemoteUntrusted)
                            {
                                let cap_snap =
                                    crate::capability_snapshot::capability_snapshot_for_core(self);
                                let compiler = cap_snap.pattern_compiler.clone();
                                let compound = crate::intent_engine::split_compound_intent(
                                    self,
                                    &resolved_text,
                                    &compiler,
                                );

                                if compound.total_clauses >= 2
                                    && compound.all_clauses_resolved
                                    && compound.is_compound
                                    && compound.steps.len() >= 2
                                    && !resolved_text.contains("怎么")
                                    && !resolved_text.contains("如何")
                                    && (!resolved_text.contains("帮我")
                                        || !self.gateway.has_usable_credentials())
                                    && !compound.requires_confirmation
                                    && compound.steps.iter().all(|s| {
                                        s.confidence >= 0.85 && !s.depends_on_previous_output
                                    })
                                {
                                    let rep = crate::intent_engine::execute_compound_with_policy(
                                        self,
                                        &resolved_text,
                                        Some(compound.steps),
                                        Some(&session.session_id),
                                        privacy,
                                        &compiler,
                                    )
                                    .await?;
                                    let status = if rep.all_succeeded {
                                        TaskStatus::Completed
                                    } else {
                                        TaskStatus::Failed
                                    };
                                    let mut task = Task {
                                        id: task_id,
                                        goal: resolved_text,
                                        session_id: Some(session.session_id),
                                        project_id: None,
                                        trigger: TaskTrigger::User,
                                        route: RouteLayer::L1,
                                        status: TaskStatus::Created,
                                        steps: Vec::new(),
                                        changeset_ids: rep.changeset_ids,
                                        pending_approval: None,
                                        candidates_for_disambiguation: Vec::new(),
                                        assistant_message: Some(rep.summary_message.clone()),
                                        result_summary: Some(rep.summary_message),
                                        handoff_command: None,
                                        taint: taints,
                                        data_class,
                                        budget: TaskBudget::default(),
                                        created_at: now,
                                        updated_at: Utc::now(),
                                    };
                                    UnifiedTaskStateMachine::transition_task(
                                        &mut task, status, None,
                                    )?;
                                    self.persist_or_ephemeral(&task, incognito)?;
                                    return Ok(task);
                                }

                                if compound.total_clauses >= 2
                                    && compound.has_unresolved_clauses()
                                    && !compound.steps.is_empty()
                                {
                                    if self.gateway.has_usable_credentials() {
                                        let resolved_lines = compound
                                            .steps
                                            .iter()
                                            .map(|s| {
                                                format!(
                                                    "- 子句#{}: `{}` -> 候选能力 `{}` (args={})",
                                                    s.step_index,
                                                    s.raw_segment,
                                                    s.capability_id,
                                                    s.arguments
                                                )
                                            })
                                            .collect::<Vec<_>>()
                                            .join("\n");
                                        let unresolved_lines = compound
                                            .unresolved_clauses
                                            .iter()
                                            .map(|u| {
                                                format!(
                                                    "- 子句#{} [{}]: `{}` — {}",
                                                    u.clause_index, u.kind, u.raw_clause, u.reason
                                                )
                                            })
                                            .collect::<Vec<_>>()
                                            .join("\n");
                                        injected_context.push(ContextBlock {
                                            id: "compound_plan_hint".into(),
                                            label: "compound_intent_plan".into(),
                                            content: format!(
                                                "复合意图预拆解结果（共 {} 个子目标，请完整执行所有已解析步骤与未解析子目标，禁止遗漏任何子句）：\n已识别确定性子步骤：\n{}\n需智能体继续完成的子目标：\n{}",
                                                compound.total_clauses,
                                                resolved_lines,
                                                unresolved_lines
                                            ),
                                            taint: Taint::System,
                                            data_class: DataClass::Public,
                                        });
                                    } else {
                                        let unresolved_desc = compound
                                            .unresolved_clauses
                                            .iter()
                                            .map(|u| {
                                                format!("「{}」（{}）", u.raw_clause, u.reason)
                                            })
                                            .collect::<Vec<_>>()
                                            .join("；");

                                        if compound.requires_confirmation
                                            || !compound.steps.iter().all(|s| {
                                                s.confidence >= 0.75
                                                    && !s.depends_on_previous_output
                                            })
                                        {
                                            let planned_desc = compound
                                                .steps
                                                .iter()
                                                .map(|s| {
                                                    format!(
                                                        "「{}」-> `{}`",
                                                        s.raw_segment, s.capability_id
                                                    )
                                                })
                                                .collect::<Vec<_>>()
                                                .join("；");
                                            let msg = format!(
                                                "复合意图包含未解析子目标，离线模式下已生成安全预览（未自动跳过任何子句）：待确认步骤 {}；暂未执行的子目标：{}。请配置大模型凭据或分别确认执行。",
                                                planned_desc, unresolved_desc
                                            );
                                            let mut task = Task {
                                                id: task_id,
                                                goal: resolved_text,
                                                session_id: Some(session.session_id),
                                                project_id: None,
                                                trigger: TaskTrigger::User,
                                                route: RouteLayer::L2,
                                                status: TaskStatus::Created,
                                                steps: Vec::new(),
                                                changeset_ids: Vec::new(),
                                                pending_approval: None,
                                                candidates_for_disambiguation: Vec::new(),
                                                assistant_message: Some(msg.clone()),
                                                result_summary: Some(msg),
                                                handoff_command: None,
                                                taint: taints,
                                                data_class,
                                                budget: TaskBudget::default(),
                                                created_at: now,
                                                updated_at: Utc::now(),
                                            };
                                            UnifiedTaskStateMachine::transition_task(
                                                &mut task,
                                                TaskStatus::Paused,
                                                None,
                                            )?;
                                            self.persist_or_ephemeral(&task, incognito)?;
                                            return Ok(task);
                                        }

                                        let rep =
                                            crate::intent_engine::execute_compound_with_policy(
                                                self,
                                                &resolved_text,
                                                Some(compound.steps),
                                                Some(&session.session_id),
                                                privacy,
                                                &compiler,
                                            )
                                            .await?;

                                        let (target_status, full_msg) = if rep.completed_steps > 0 {
                                            (
                                                TaskStatus::PartiallyCompleted,
                                                format!(
                                                    "已完成确定性子步骤：{}；但以下子目标在离线模式下暂未完成（未静默跳过）：{}。如需开放式推理分析，请配置远程模型凭据后继续处理。",
                                                    rep.summary_message, unresolved_desc
                                                ),
                                            )
                                        } else {
                                            (
                                                TaskStatus::Failed,
                                                format!(
                                                    "复合意图子步骤执行失败：{}；另有未解析子目标：{}",
                                                    rep.summary_message, unresolved_desc
                                                ),
                                            )
                                        };

                                        let mut task = Task {
                                            id: task_id,
                                            goal: resolved_text,
                                            session_id: Some(session.session_id),
                                            project_id: None,
                                            trigger: TaskTrigger::User,
                                            route: RouteLayer::L2,
                                            status: TaskStatus::Created,
                                            steps: Vec::new(),
                                            changeset_ids: rep.changeset_ids,
                                            pending_approval: None,
                                            candidates_for_disambiguation: Vec::new(),
                                            assistant_message: Some(full_msg.clone()),
                                            result_summary: Some(full_msg),
                                            handoff_command: None,
                                            taint: taints,
                                            data_class,
                                            budget: TaskBudget::default(),
                                            created_at: now,
                                            updated_at: Utc::now(),
                                        };
                                        UnifiedTaskStateMachine::transition_task(
                                            &mut task,
                                            target_status,
                                            None,
                                        )?;
                                        self.persist_or_ephemeral(&task, incognito)?;
                                        return Ok(task);
                                    }
                                }

                                if compound.total_clauses <= 1
                                    && !resolved_text.contains("怎么")
                                    && !resolved_text.contains("如何")
                                    && !resolved_text.contains("帮我")
                                {
                                    let ranked = crate::intent_engine::rank_capabilities(
                                        &resolved_text,
                                        &compiler,
                                        Some(&self.index_db),
                                        1,
                                    );
                                    if let Some(top) = ranked.first()
                                        && top.confidence >= 0.88
                                        && let Some(desc) =
                                            self.broker.get_descriptor(&top.capability_id)
                                    {
                                        let args =
                                            crate::intent_engine::extract_slots_for_descriptor(
                                                desc,
                                                &resolved_text,
                                                &top.captured_slots,
                                                &self.resources,
                                            );
                                        // If `file.open` could not resolve a literal filename (e.g. `"打开我的硕士论文"` -> `paper_main.docx`),
                                        // consult `memory_hub` semantic document outlines before attempting an unresolved raw path!
                                        if top.capability_id == "file.open"
                                            && privacy.allows_memory_read()
                                            && args
                                                .get("path")
                                                .and_then(|v| v.as_str())
                                                .is_some_and(|p| {
                                                    !p.starts_with('/') && !p.starts_with("~/")
                                                })
                                            && !self.gateway.has_usable_credentials()
                                            && let Some(doc_task) = self
                                                .try_execute_smart_document_open(
                                                    &task_id,
                                                    &session,
                                                    &resolved_text,
                                                    taints.clone(),
                                                    data_class,
                                                    privacy,
                                                    now,
                                                    false,
                                                )
                                                .await?
                                        {
                                            return Ok(doc_task);
                                        }
                                        return self
                                            .execute_single_capability_task(
                                                task_id,
                                                &session.session_id,
                                                &resolved_text,
                                                RouteLayer::L1,
                                                &top.capability_id,
                                                args,
                                                InvocationOrigin::L1Inferred,
                                                taints,
                                                data_class,
                                                incognito,
                                            )
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                }

                let structured_for_l2 = match progressive_goal {
                    Some(g) => g,
                    None => {
                        let cap_snap =
                            crate::capability_snapshot::capability_snapshot_for_core(self);
                        let mut g = crate::intent_engine::parse_structured_intent(
                            &resolved_text,
                            cap_snap.descriptors_slice(),
                        );
                        if privacy.allows_memory_read() {
                            crate::decision::apply_empirical_calibration_to_intent(
                                &self.state_db,
                                &mut g,
                            );
                        }
                        g
                    }
                };
                if (matches!(
                    structured_for_l2.intent_type,
                    crate::intent_engine::CognitiveIntentKind::GoalWorkspace
                        | crate::intent_engine::CognitiveIntentKind::SystemDiagnosis
                        | crate::intent_engine::CognitiveIntentKind::CompoundTask
                        | crate::intent_engine::CognitiveIntentKind::ProceduralOrKnowledge
                ) || structured_for_l2.requires_context_resolution)
                    && !injected_context
                        .iter()
                        .any(|b| b.label == "cognitive_goal_analysis")
                {
                    injected_context.push(ContextBlock {
                        id: "cognitive_goal_hint".into(),
                        label: "cognitive_goal_analysis".into(),
                        content: structured_for_l2.to_agent_prompt_hint(),
                        taint: Taint::System,
                        data_class: DataClass::Public,
                    });
                }

                // Automatically inject Personal OS Memory RAG context before L2 LLM inference (when privacy policy permits)
                if privacy.allows_memory_read()
                    && self.gateway.has_usable_credentials()
                    && !injected_context
                        .iter()
                        .any(|b| b.label == "personal_os_memory")
                {
                    let (mem_md, _hits) =
                        crate::memory_hub::build_personal_memory_prompt_with_policy(
                            self,
                            &resolved_text,
                            Some(session.session_id.as_str()),
                            privacy,
                        );
                    if !mem_md.trim().is_empty() {
                        if !taints.contains(&Taint::Memory) {
                            taints.push(Taint::Memory);
                        }
                        if DataClass::Personal > data_class {
                            data_class = DataClass::Personal;
                        }
                        injected_context.push(ContextBlock {
                            id: "memory_hub_rag".into(),
                            label: "personal_os_memory".into(),
                            content: mem_md,
                            taint: Taint::Memory,
                            data_class: DataClass::Personal,
                        });
                    }
                }

                let budget = TaskBudget {
                    max_tool_calls: self.brain_config.runtime_limits.max_tool_calls,
                    max_runtime_seconds: self.brain_config.runtime_limits.max_runtime_seconds,
                    max_wall_time_ms: self
                        .brain_config
                        .runtime_limits
                        .max_runtime_seconds
                        .saturating_mul(1_000),
                    ..TaskBudget::default()
                };
                let exec_ctx = ExecutionContext::new(
                    session.session_id.clone(),
                    task_id.clone(),
                    None,
                    privacy,
                    taints.clone(),
                    data_class,
                    budget.clone(),
                );
                let mut task = Task {
                    id: task_id.clone(),
                    goal: resolved_text.clone(),
                    session_id: Some(session.session_id.clone()),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L2,
                    status: TaskStatus::Created,
                    steps: Vec::new(),
                    changeset_ids: Vec::new(),
                    pending_approval: None,
                    candidates_for_disambiguation: Vec::new(),
                    assistant_message: None,
                    result_summary: None,
                    handoff_command: None,
                    taint: taints.clone(),
                    data_class,
                    budget: budget.clone(),
                    created_at: now,
                    updated_at: now,
                };
                UnifiedTaskStateMachine::transition_task(&mut task, TaskStatus::Running, None)?;
                self.persist_or_ephemeral_with_privacy(&task, privacy)?;

                let mut l2_ledger = crate::backend_bridge::turn_checkpoint::TurnEffectLedger::new(
                    format!("l2_turn_{}", task_id),
                )
                .with_privacy(privacy);
                l2_ledger.bind_persistence(
                    self.state_db.clone(),
                    task_id.clone(),
                    session.session_id.clone(),
                    privacy,
                );

                match self
                    .agent
                    .run_l2_with_context(
                        &exec_ctx,
                        &session,
                        &resolved_text,
                        injected_context,
                        &mut l2_ledger,
                    )
                    .await
                {
                    Ok(run_out) => {
                        task.steps = run_out.steps;
                        task.changeset_ids = run_out.changeset_ids;
                        task.handoff_command = run_out.handoff_command;
                        if let Some(pa) = run_out.pending_approval {
                            UnifiedTaskStateMachine::transition_task(
                                &mut task,
                                TaskStatus::AwaitingApproval,
                                None,
                            )?;
                            task.assistant_message = Some(pa.summary.clone());
                            task.pending_approval = Some(pa);
                        } else if run_out.status_override == Some(TaskStatus::RecoveryRequired)
                            || l2_ledger.has_uncertain_side_effects()
                        {
                            UnifiedTaskStateMachine::transition_task(
                                &mut task,
                                TaskStatus::RecoveryRequired,
                                Some(&run_out.final_message),
                            )?;
                            task.assistant_message = Some(run_out.final_message.clone());
                            task.result_summary = Some(run_out.final_message);
                        } else {
                            let enriched_msg =
                                enrich_l2_chapter_open_message(&run_out.final_message, &task.steps);
                            UnifiedTaskStateMachine::transition_task(
                                &mut task,
                                TaskStatus::Completed,
                                None,
                            )?;
                            task.assistant_message = Some(enriched_msg.clone());
                            task.result_summary = Some(enriched_msg.clone());
                            if privacy.allows_memory_write() {
                                self.sessions.append_turn(
                                    &session.session_id,
                                    &resolved_text,
                                    &enriched_msg,
                                    None,
                                );
                            }
                        }
                        self.persist_or_ephemeral_with_privacy(&task, privacy)?;
                        Ok(task)
                    }
                    Err(err) => {
                        if l2_ledger.has_uncertain_or_committed_side_effects() {
                            let rec_msg = format!(
                                "智能体执行在已产生系统变更或未确认副作用后中断（{}），已阻止回退重放并进入恢复保护状态（recovery_required）。",
                                err
                            );
                            task.steps = l2_ledger.task_steps.clone();
                            task.changeset_ids = l2_ledger.committed_changeset_ids();
                            UnifiedTaskStateMachine::transition_task(
                                &mut task,
                                TaskStatus::RecoveryRequired,
                                Some(&rec_msg),
                            )?;
                            task.assistant_message = Some(rec_msg.clone());
                            task.result_summary = Some(rec_msg);
                            self.persist_or_ephemeral_with_privacy(&task, privacy)?;
                            return Ok(task);
                        }

                        // Even if a configured cloud API key is unreachable, personal-memory & adapter queries
                        // still return rich, real local answers!
                        if let Some(fallback_task) = self
                            .try_complete_aios_deterministic_task(
                                &task_id,
                                &session,
                                &resolved_text,
                                taints,
                                data_class,
                                privacy,
                                now,
                            )
                            .await?
                        {
                            return Ok(fallback_task);
                        }
                        let err_msg = err.to_string();
                        UnifiedTaskStateMachine::transition_task(
                            &mut task,
                            TaskStatus::Failed,
                            Some(&err_msg),
                        )?;
                        self.persist_or_ephemeral_with_privacy(&task, privacy)?;
                        Ok(task)
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_single_capability_task(
        &self,
        task_id: String,
        session_id: &str,
        goal: &str,
        route: RouteLayer,
        capability_id: &str,
        arguments: Value,
        origin: InvocationOrigin,
        taints: Vec<Taint>,
        data_class: DataClass,
        incognito: bool,
    ) -> anyhow::Result<Task> {
        self.execute_single_capability_task_with_observe(
            task_id,
            session_id,
            goal,
            route,
            capability_id,
            arguments,
            None,
            origin,
            taints,
            data_class,
            incognito,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_single_capability_task_with_observe(
        &self,
        task_id: String,
        session_id: &str,
        goal: &str,
        route: RouteLayer,
        capability_id: &str,
        mut arguments: Value,
        prerequisite_observe_capability: Option<&str>,
        origin: InvocationOrigin,
        taints: Vec<Taint>,
        data_class: DataClass,
        incognito: bool,
    ) -> anyhow::Result<Task> {
        let now = Utc::now();
        let task_privacy = if incognito {
            PrivacySessionPolicy::StrictIsolated
        } else {
            self.task_privacy_policy(&task_id)
        };
        let mut task = Task {
            id: task_id.clone(),
            goal: goal.to_string(),
            session_id: Some(session_id.to_string()),
            project_id: None,
            trigger: TaskTrigger::User,
            route,
            status: TaskStatus::Created,
            steps: Vec::new(),
            changeset_ids: Vec::new(),
            pending_approval: None,
            candidates_for_disambiguation: Vec::new(),
            assistant_message: None,
            result_summary: None,
            handoff_command: None,
            taint: taints.clone(),
            data_class,
            budget: TaskBudget::default(),
            created_at: now,
            updated_at: now,
        };
        UnifiedTaskStateMachine::transition_task(&mut task, TaskStatus::Running, None)?;
        self.persist_or_ephemeral_with_privacy(&task, task_privacy)?;

        let mut step_ledger = crate::backend_bridge::turn_checkpoint::TurnEffectLedger::new(
            format!("turn_{}", task_id),
        )
        .with_privacy(task_privacy);
        step_ledger.bind_persistence(
            self.state_db.clone(),
            task_id.clone(),
            session_id.to_string(),
            task_privacy,
        );

        let mut observed_summary: Option<String> = None;
        if let Some(obs_cap) = prerequisite_observe_capability
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != capability_id)
            && self
                .broker
                .get_descriptor(obs_cap)
                .is_some_and(|d| d.max_effect() == intentos_protocol::Effect::Observe)
        {
            let obs_call_id = format!(
                "step_obs_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            let obs_call = CapabilityCall {
                request_id: obs_call_id.clone(),
                task_id: task_id.clone(),
                capability_id: obs_cap.to_string(),
                arguments: json!({}),
                origin,
                taints: taints.clone(),
            };
            if let Ok(BrokerDispatchOutcome::Executed(obs_res)) =
                crate::backend_bridge::broker_bridge::dispatch_broker_call_transactional(
                    self,
                    session_id,
                    task_privacy,
                    crate::backend_bridge::turn_checkpoint::StepInvocationContext::new_call(
                        &obs_call_id,
                    ),
                    &obs_call,
                    &mut step_ledger,
                )
                .await
            {
                let observed_val = obs_res
                    .data
                    .get("value")
                    .or_else(|| obs_res.data.get("current"))
                    .or_else(|| obs_res.data.get("after"))
                    .and_then(|v| v.as_f64());
                if let Some(curr) = observed_val
                    && arguments.get("value").is_none()
                    && let Some(rel) = arguments.get("relative").and_then(|v| v.as_str())
                {
                    if rel == "down" && curr >= 80.0 {
                        let target = (curr * 0.75).round().clamp(10.0, 100.0);
                        arguments = json!({ "value": target });
                    } else if rel == "up" && curr <= 25.0 {
                        let min_floor = if capability_id.starts_with("display.") {
                            35.0
                        } else {
                            45.0
                        };
                        let target = (curr + 20.0).max(min_floor).clamp(1.0, 100.0);
                        arguments = json!({ "value": target });
                    }
                }
                observed_summary = Some(obs_res.message.clone());
                task.steps.push(TaskStep {
                    step_id: obs_call_id,
                    capability_id: obs_cap.to_string(),
                    arguments_summary: "{}".to_string(),
                    status: obs_res.status,
                    verification: obs_res.verification,
                    changeset_id: obs_res.changeset_id,
                    message: obs_res.message,
                    data: obs_res.data,
                    duration_ms: obs_res.duration_ms,
                });
            }
        }

        let call_id = format!("step_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let call = CapabilityCall {
            request_id: call_id.clone(),
            task_id: task_id.clone(),
            capability_id: capability_id.to_string(),
            arguments: arguments.clone(),
            origin,
            taints,
        };

        let dispatch_outcome =
            match crate::backend_bridge::broker_bridge::dispatch_broker_call_transactional(
                self,
                session_id,
                task_privacy,
                crate::backend_bridge::turn_checkpoint::StepInvocationContext::new_call(&call_id),
                &call,
                &mut step_ledger,
            )
            .await
            {
                Ok(o) => o,
                Err(err) => {
                    if step_ledger.has_uncertain_side_effects() {
                        let rec_msg = format!(
                            "能力 `{}` 执行期间中断（{}），实际副作用未确认；任务已标记为 recovery_required。",
                            capability_id, err
                        );
                        UnifiedTaskStateMachine::transition_task(
                            &mut task,
                            TaskStatus::RecoveryRequired,
                            Some(&rec_msg),
                        )?;
                        task.assistant_message = Some(rec_msg.clone());
                        task.result_summary = Some(rec_msg);
                        self.persist_or_ephemeral_with_privacy(&task, task_privacy)?;
                        return Ok(task);
                    }
                    return Err(err);
                }
            };

        match dispatch_outcome {
            BrokerDispatchOutcome::Executed(res) => {
                let last_res = arguments
                    .get("target")
                    .or_else(|| arguments.get("path"))
                    .or_else(|| arguments.get("source"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| {
                        res.data
                            .get("files")
                            .and_then(|f| f.as_array())
                            .and_then(|a| a.first())
                            .and_then(|x| x.get("path"))
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    });

                if let Some(ref csid) = res.changeset_id {
                    task.changeset_ids.push(csid.clone());
                }
                task.handoff_command = res
                    .data
                    .get("handoff_command")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let ok_status = matches!(
                    res.status,
                    ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
                );
                let final_status = if step_ledger.has_uncertain_side_effects() {
                    TaskStatus::RecoveryRequired
                } else if ok_status {
                    TaskStatus::Completed
                } else {
                    TaskStatus::Failed
                };
                let final_msg = match observed_summary {
                    Some(obs) if !obs.trim().is_empty() => {
                        format!("（已先读取状态：{}）{}", obs, res.message)
                    }
                    _ => res.message.clone(),
                };
                UnifiedTaskStateMachine::transition_task(
                    &mut task,
                    final_status,
                    Some(&final_msg),
                )?;
                task.assistant_message = Some(final_msg.clone());
                task.result_summary = Some(final_msg);
                task.steps.push(TaskStep {
                    step_id: call_id,
                    capability_id: capability_id.to_string(),
                    arguments_summary: arguments.to_string(),
                    status: res.status,
                    verification: res.verification,
                    changeset_id: res.changeset_id,
                    message: res.message.clone(),
                    data: res.data,
                    duration_ms: res.duration_ms,
                });
                task.updated_at = Utc::now();
                self.persist_or_ephemeral_with_privacy(&task, task_privacy)?;
                if task_privacy.allows_memory_write() && final_status == TaskStatus::Completed {
                    self.sessions
                        .append_turn(session_id, goal, &res.message, last_res);
                }
                Ok(task)
            }
            BrokerDispatchOutcome::RequiresApproval(pa) => {
                UnifiedTaskStateMachine::transition_task(
                    &mut task,
                    TaskStatus::AwaitingApproval,
                    None,
                )?;
                task.assistant_message = Some(pa.summary.clone());
                task.pending_approval = Some(pa);
                task.updated_at = Utc::now();
                self.persist_or_ephemeral_with_privacy(&task, task_privacy)?;
                Ok(task)
            }
            BrokerDispatchOutcome::Denied { reason } => {
                UnifiedTaskStateMachine::transition_task(
                    &mut task,
                    TaskStatus::Failed,
                    Some(&reason),
                )?;
                task.assistant_message = Some(format!("策略拒绝：{}", reason));
                task.result_summary = Some(reason);
                task.updated_at = Utc::now();
                self.persist_or_ephemeral_with_privacy(&task, task_privacy)?;
                Ok(task)
            }
        }
    }

    /// Verify nonce + digest over private UI channel and execute the approved operation (§10.5).
    pub async fn approve_pending(
        &self,
        approval_id: &str,
        nonce: &str,
        digest: &str,
    ) -> anyhow::Result<Task> {
        self.approve_pending_internal(approval_id, nonce, digest, true)
            .await
    }

    /// Execute an approved pending capability (`approve_task`) while preserving complete `TaskStep`
    /// output (`message`, `data`, `changeset_id`) for `backend_bridge::resume_approved_turn`,
    /// avoiding duplicate intermediate `"确认执行：..."` turn entries in `memory_hub` / `sessions`.
    pub async fn approve_task(
        &self,
        approval_id: &str,
        nonce: &str,
        digest: &str,
    ) -> anyhow::Result<Task> {
        self.approve_pending_internal(approval_id, nonce, digest, false)
            .await
    }

    async fn approve_pending_internal(
        &self,
        approval_id: &str,
        nonce: &str,
        digest: &str,
        record_standalone_turn: bool,
    ) -> anyhow::Result<Task> {
        let pa = self
            .policy
            .verify_and_consume(approval_id, nonce, digest)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let mut task_privacy = self.task_privacy_policy(&pa.task_id);
        let mut persist_task = false;
        let mut task = if let Some(t) = self.incognito_tasks.lock().unwrap().remove(&pa.task_id) {
            if task_privacy == PrivacySessionPolicy::Standard {
                task_privacy = PrivacySessionPolicy::StrictIsolated;
            }
            t
        } else if let Some(t) = self.state_db.get_task(&pa.task_id)? {
            persist_task = task_privacy.allows_task_persistence();
            t
        } else {
            // Support approvals created in Quick-Chat turns (`qc_...` / `incog_...`) or direct broker calls
            let now = Utc::now();
            Task {
                id: pa.task_id.clone(),
                goal: pa.summary.clone(),
                session_id: None,
                project_id: None,
                trigger: TaskTrigger::User,
                route: RouteLayer::L0,
                status: TaskStatus::AwaitingApproval,
                steps: Vec::new(),
                changeset_ids: Vec::new(),
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
        };

        // Wave 3 Sensitive Path Approval Execution: grant user-approved non-forbidden path scopes in `SafeFsEngine`
        // BEFORE calling `broker.execute_approved(...)` so `openat2` immediately permits the approved path!
        self.approve_non_forbidden_paths_in_args(&pa.arguments);

        let prepared_step_row = if record_standalone_turn && task_privacy.allows_task_persistence()
        {
            self.state_db
                .list_step_execution_logs_for_task(&task.id)
                .ok()
                .and_then(|rows| {
                    rows.into_iter().rev().find(|r| {
                        r.exec_state == crate::db::StepExecState::Prepared
                            && r.capability_id == pa.capability_id
                    })
                })
        } else {
            None
        };
        if let Some(mut exec_row) = prepared_step_row.clone() {
            exec_row.exec_state = crate::db::StepExecState::Executing;
            exec_row.verification_status = "ExecutingApproved".to_string();
            exec_row.updated_at = Utc::now();
            let _ = self
                .state_db
                .upsert_step_execution_log(&exec_row, task_privacy);
        }

        let exec_res = if crate::app_adapter::is_adapter_tool(&pa.capability_id) {
            let call = CapabilityCall {
                request_id: pa.approval_id.clone(),
                task_id: task.id.clone(),
                capability_id: pa.capability_id.clone(),
                arguments: pa.arguments.clone(),
                origin: InvocationOrigin::UserExplicit,
                taints: vec![Taint::User],
            };
            match self.broker.dispatch(&call).await {
                Ok(BrokerDispatchOutcome::Executed(r)) => Ok(r),
                Ok(BrokerDispatchOutcome::Denied { reason }) => {
                    Err(anyhow::anyhow!("转译层执行被拒绝: {}", reason))
                }
                Ok(BrokerDispatchOutcome::RequiresApproval(_)) => {
                    Err(anyhow::anyhow!("转译层在已确认状态下仍请求重复确认"))
                }
                Err(e) => Err(e),
            }
        } else {
            let desc = self
                .broker
                .get_descriptor(&pa.capability_id)
                .ok_or_else(|| anyhow::anyhow!("未找到能力: {}", pa.capability_id))?;

            self.broker
                .execute_approved(&pa.approval_id, &task.id, desc, &pa.arguments)
                .await
        };

        let res = match exec_res {
            Ok(r) => {
                if let Some(mut done_row) = prepared_step_row {
                    done_row.exec_state = match r.status {
                        ExecutionStatus::Exited => crate::db::StepExecState::Verified,
                        ExecutionStatus::RequestedUnverified => crate::db::StepExecState::Applied,
                        ExecutionStatus::Denied => crate::db::StepExecState::Denied,
                        _ => crate::db::StepExecState::Unknown,
                    };
                    done_row.changeset_id = r.changeset_id.clone();
                    done_row.verification_status = format!("{:?}", r.verification.state);
                    done_row.updated_at = Utc::now();
                    let _ = self
                        .state_db
                        .upsert_step_execution_log(&done_row, task_privacy);
                }
                r
            }
            Err(err) => {
                if let Some(mut rec_row) = prepared_step_row {
                    rec_row.exec_state = crate::db::StepExecState::RecoveryRequired;
                    rec_row.verification_status = "ErrorDuringApprovedExecution".to_string();
                    rec_row.recovery_hint = Some(err.to_string());
                    rec_row.updated_at = Utc::now();
                    let _ = self
                        .state_db
                        .upsert_step_execution_log(&rec_row, task_privacy);
                }
                return Err(err);
            }
        };

        let discovered_first_file = res
            .data
            .get("files")
            .or_else(|| res.data.get("candidates"))
            .and_then(|f| f.as_array())
            .and_then(|a| a.first())
            .and_then(|x| x.get("path").or(Some(x)))
            .and_then(|v| v.as_str())
            .map(String::from);

        let last_res = if pa.capability_id == "file.search" {
            discovered_first_file.or_else(|| {
                pa.arguments
                    .get("directory")
                    .or_else(|| pa.arguments.get("path"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
        } else {
            pa.arguments
                .get("target")
                .or_else(|| pa.arguments.get("path"))
                .or_else(|| pa.arguments.get("source"))
                .or_else(|| pa.arguments.get("directory"))
                .and_then(|v| v.as_str())
                .map(String::from)
                .or(discovered_first_file)
        };

        if task_privacy.allows_memory_write()
            && let (Some(sid), Some(rp)) = (task.session_id.as_deref(), last_res.as_ref())
        {
            self.sessions.set_last_resource_path(sid, rp.clone());
        }

        if task_privacy.allows_task_persistence()
            && let Some(ref csid) = res.changeset_id
        {
            task.changeset_ids.push(csid.clone());
        }
        let target_status = if matches!(
            res.status,
            ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
        ) {
            TaskStatus::Completed
        } else {
            TaskStatus::Failed
        };
        if UnifiedTaskStateMachine::can_transition(task.status, target_status) {
            UnifiedTaskStateMachine::transition_task(&mut task, target_status, None)?;
        } else {
            task.pending_approval = None;
            task.status = target_status;
        }
        task.assistant_message = Some(res.message.clone());
        task.result_summary = Some(res.message.clone());
        let step = TaskStep {
            step_id: pa.approval_id,
            capability_id: pa.capability_id,
            arguments_summary: pa.arguments.to_string(),
            status: res.status,
            verification: res.verification,
            changeset_id: if !task_privacy.allows_task_persistence() {
                None
            } else {
                res.changeset_id
            },
            message: res.message.clone(),
            data: res.data,
            duration_ms: res.duration_ms,
        };
        let step_json = json!({
            "capability_id": step.capability_id,
            "arguments_summary": step.arguments_summary,
            "status": step.status,
            "duration_ms": step.duration_ms,
            "changeset_id": step.changeset_id,
            "message": step.message,
            "data": step.data,
        });
        task.steps.push(step);
        task.updated_at = Utc::now();
        if persist_task && task_privacy.allows_task_persistence() {
            self.state_db.upsert_task(&task)?;
            if record_standalone_turn && task_privacy.allows_memory_write() {
                if let Some(ref sid) = task.session_id {
                    self.sessions.append_turn(
                        sid,
                        &format!("确认执行：{}", task.goal),
                        &res.message,
                        last_res,
                    );
                }
                let _ = crate::memory_hub::record_conversation_turn_with_policy(
                    self,
                    &crate::memory_hub::RecordTurnInput {
                        session_id: task.session_id.clone(),
                        user_text: format!("确认执行：{}", task.goal),
                        assistant_text: res.message,
                        thinking: None,
                        tool_steps: vec![step_json],
                        trace_dots: Vec::new(),
                        incognito: !task_privacy.allows_memory_write(),
                    },
                    task_privacy,
                );
            }
        }
        Ok(task)
    }

    fn approve_non_forbidden_paths_in_args(&self, args: &Value) {
        let Some(obj) = args.as_object() else {
            return;
        };
        let path_keys = [
            "path",
            "source",
            "target",
            "directory",
            "repo_dir",
            "output",
            "archive",
            "destination",
            "repo",
            "target_dir",
        ];
        for key in path_keys {
            if let Some(raw) = obj.get(key).and_then(|v| v.as_str())
                && !raw.trim().is_empty()
            {
                let expanded = expand_tilde_core_path(raw);
                if !self.fs_engine.is_forbidden(&expanded) {
                    let _ = self.fs_engine.approve_path_scope(&expanded);
                }
            }
        }
        if let Some(arr) = obj.get("sources").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(raw) = item.as_str()
                    && !raw.trim().is_empty()
                {
                    let expanded = expand_tilde_core_path(raw);
                    if !self.fs_engine.is_forbidden(&expanded) {
                        let _ = self.fs_engine.approve_path_scope(&expanded);
                    }
                }
            }
        }
        if let Some(params_obj) = obj.get("params").and_then(|v| v.as_object()) {
            for key in ["path", "source", "target", "input", "output", "file"] {
                if let Some(raw) = params_obj.get(key).and_then(|v| v.as_str())
                    && !raw.trim().is_empty()
                {
                    let expanded = expand_tilde_core_path(raw);
                    if !self.fs_engine.is_forbidden(&expanded) {
                        let _ = self.fs_engine.approve_path_scope(&expanded);
                    }
                }
            }
        }
    }

    pub fn deny_pending(&self, approval_id: &str) -> anyhow::Result<Task> {
        let pa = self
            .policy
            .deny_and_remove(approval_id)
            .ok_or_else(|| anyhow::anyhow!("未找到挂起的审批: {}", approval_id))?;
        let mut persist_denied = self
            .task_privacy_policy(&pa.task_id)
            .allows_task_persistence();
        let mut task = if let Some(t) = self.incognito_tasks.lock().unwrap().remove(&pa.task_id) {
            persist_denied = false;
            t
        } else if let Some(t) = self.state_db.get_task(&pa.task_id)? {
            t
        } else {
            persist_denied = false;
            let now = Utc::now();
            Task {
                id: pa.task_id.clone(),
                goal: pa.summary.clone(),
                session_id: None,
                project_id: None,
                trigger: TaskTrigger::User,
                route: RouteLayer::L0,
                status: TaskStatus::AwaitingApproval,
                steps: Vec::new(),
                changeset_ids: Vec::new(),
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
        };
        if UnifiedTaskStateMachine::can_transition(task.status, TaskStatus::Cancelled) {
            UnifiedTaskStateMachine::transition_task(&mut task, TaskStatus::Cancelled, None)?;
        } else {
            task.pending_approval = None;
            task.status = TaskStatus::Cancelled;
            task.updated_at = Utc::now();
        }
        task.assistant_message = Some("用户拒绝了该操作，未产生修改".into());
        if persist_denied {
            let policy = self.task_privacy_policy(&task.id);
            if let Ok(rows) = self.state_db.list_step_execution_logs_for_task(&task.id) {
                for mut row in rows {
                    if row.exec_state == crate::db::StepExecState::Prepared
                        && row.capability_id == pa.capability_id
                    {
                        row.exec_state = crate::db::StepExecState::Denied;
                        row.verification_status = "UserDeniedApproval".to_string();
                        row.updated_at = Utc::now();
                        let _ = self.state_db.upsert_step_execution_log(&row, policy);
                    }
                }
            }
            self.state_db.upsert_task(&task)?;
        }
        Ok(task)
    }

    pub fn undo(&self, target_id: Option<&str>) -> anyhow::Result<(ChangeSet, String)> {
        // Support passing either `cs_xxx` OR `task_xxx` (§9.3)!
        if let Some(id) = target_id
            && id.starts_with("task_")
            && let Some(task) = self.state_db.get_task(id)?
            && let Some(last_cs) = task.changeset_ids.last()
        {
            return self.broker.undo_changeset(Some(last_cs));
        }
        self.broker.undo_changeset(target_id)
    }

    /// User-authored `$` Command Passthrough (§8.8, A14, A15).
    pub async fn run_passthrough(
        &self,
        raw_cmd: &str,
        cwd_override: Option<&str>,
        confirmed_risky: bool,
    ) -> anyhow::Result<PassthroughResponse> {
        self.run_passthrough_with_privacy(raw_cmd, cwd_override, confirmed_risky, true)
            .await
    }

    pub async fn run_passthrough_with_privacy(
        &self,
        raw_cmd: &str,
        cwd_override: Option<&str>,
        confirmed_risky: bool,
        record_history: bool,
    ) -> anyhow::Result<PassthroughResponse> {
        let cmd_str = raw_cmd.trim();
        let active_cwd = match cwd_override {
            Some(c) if !c.trim().is_empty() => PathBuf::from(c),
            _ => self.passthrough_cwd.lock().unwrap().clone(),
        };

        // 1. Detect interactive / password-requiring programs (§8.8, A15)
        let first_tok = cmd_str
            .split_whitespace()
            .next()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap_or("");
        if matches!(
            first_tok,
            "sudo"
                | "su"
                | "vim"
                | "nvim"
                | "vi"
                | "nano"
                | "top"
                | "htop"
                | "less"
                | "more"
                | "ssh"
                | "tmux"
        ) {
            return Ok(PassthroughResponse {
                status: "suggest_terminal".into(),
                command: cmd_str.to_string(),
                cwd: active_cwd.to_string_lossy().to_string(),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                message: format!(
                    "命令 `{}` 需要交互式终端或口令输入，建议在系统终端中打开运行",
                    first_tok
                ),
                requires_confirmation: false,
                suggest_external_terminal: true,
            });
        }

        // 2. Soft confirmation for high-risk typo patterns (§8.8)
        let is_risky = cmd_str.contains("rm -rf")
            || cmd_str.starts_with("dd ")
            || cmd_str.starts_with("mkfs")
            || cmd_str.contains("chmod -R");
        if is_risky && !confirmed_risky {
            return Ok(PassthroughResponse {
                status: "confirm_risky".into(),
                command: cmd_str.to_string(),
                cwd: active_cwd.to_string_lossy().to_string(),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                message: "检测到高危命令模式（直通操作无法撤销），请再次确认后执行".into(),
                requires_confirmation: true,
                suggest_external_terminal: false,
            });
        }

        // 3. Execute in user shell and capture updated working directory (`pwd` sentinel so `cd` persists across commands! A14)
        let pwd_marker = "__INTENTOS_PWD_SENTINEL__";
        let wrapped = format!(
            "{} ; __ec=$?; printf '\\n{}:%s\\n' \"$PWD\"; exit $__ec",
            cmd_str, pwd_marker
        );

        let out = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Command::new("/bin/bash")
                .arg("-c")
                .arg(&wrapped)
                .current_dir(&active_cwd)
                .stdin(Stdio::null())
                .output(),
        )
        .await??;

        let raw_stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let mut clean_lines = Vec::new();
        let mut final_cwd = active_cwd.clone();
        for line in raw_stdout.lines() {
            if let Some(new_pwd) = line.strip_prefix(&format!("{}:", pwd_marker)) {
                let pb = PathBuf::from(new_pwd.trim());
                if pb.is_dir() {
                    final_cwd = pb;
                }
            } else {
                clean_lines.push(line);
            }
        }
        if record_history {
            *self.passthrough_cwd.lock().unwrap() = final_cwd.clone();
            self.index_db
                .record_passthrough_command(cmd_str, &final_cwd.to_string_lossy());
        }

        let stdout_clean = clean_lines.join("\n");
        let stderr_clean = String::from_utf8_lossy(&out.stderr).to_string();
        Ok(PassthroughResponse {
            status: if out.status.success() { "ok" } else { "failed" }.into(),
            command: cmd_str.to_string(),
            cwd: final_cwd.to_string_lossy().to_string(),
            exit_code: out.status.code(),
            stdout: stdout_clean,
            stderr: stderr_clean,
            message: format!(
                "命令直通执行完成（exit={:?}, cwd={}，直通命令不进入变更集、不可撤销）",
                out.status.code(),
                final_cwd.display()
            ),
            requires_confirmation: false,
            suggest_external_terminal: false,
        })
    }

    pub fn settings_overview(&self) -> anyhow::Result<Value> {
        let (app_cfg, brain_cfg) = self.live_configs.lock().unwrap().clone();
        let (apps, files, sites) = self.resources.counts();
        let fonts = self.index_db.list_fonts();
        let backup_bytes = self.fs_engine.current_backup_usage_bytes().unwrap_or(0);

        Ok(json!({
            "brain": {
                "runtime": brain_cfg.runtime,
                "active_runtime": self.agent.active_runtime_label(),
                "default_profile": brain_cfg.default_profile,
                "providers": brain_cfg.providers,
                "profiles": brain_cfg.profiles,
                "runtime_limits": brain_cfg.runtime_limits,
                "main_model_configured": self.gateway.has_usable_credentials(),
                "gateway_metrics": self.gateway.metrics(),
            },
            "resources": {
                "hotkey": app_cfg.hotkey,
                "authorized_directories": app_cfg.authorized_directories,
                "indexed_apps": apps,
                "indexed_files": files,
                "indexed_sites": sites,
                "indexed_fonts": fonts.len(),
            },
            "web": {
                "default_search": app_cfg.web.default_search,
                "open_with": app_cfg.web.open_with,
                "search_engines": app_cfg.web.search_engines,
                "sites": app_cfg.web.sites,
            },
            "permissions_and_undo": {
                "undo_quota_gb": app_cfg.undo.quota_gb,
                "undo_retention_days": app_cfg.undo.retention_days,
                "undo_backup_bytes": backup_bytes,
                "undo_changesets_available": self.state_db.count_applied_changesets(),
                "recent_changesets": self.state_db.list_changesets(20)?,
                "recent_audit": self.state_db.list_recent_audit(25),
                "memories": self.state_db.list_memory_entries()?,
                "scenes": self.settings.list_all_scenes(),
            },
            "v03_modules": [
                "intent_engine",
                "config_center",
                "execution_hub",
                "memory_hub",
                "app_adapter",
                "backend_bridge",
                "speech_hub",
                "web_ui"
            ],
            "speech": {
                "config": crate::speech_hub::load_speech_config(self),
                "models": crate::speech_hub::model_manager::list_models_with_status(self),
                "downloads": crate::speech_hub::model_manager::get_all_downloads_map(self),
            },
            "speech_hub": {
                "config": crate::speech_hub::load_speech_config(self),
                "models": crate::speech_hub::model_manager::list_models_with_status(self),
                "downloads": crate::speech_hub::model_manager::get_all_downloads_map(self),
            },
            "domains": crate::config_center::store::load_domains_config(self)
                .ok()
                .map(|cfg| crate::config_center::store::serialize_all_domains_response(&cfg)),
        }))
    }

    pub fn status(&self) -> DaemonStatus {
        let (apps, files, sites) = self.resources.counts();
        let backup_bytes = self.fs_engine.current_backup_usage_bytes().unwrap_or(0);
        let default_search = self
            .live_configs
            .lock()
            .map(|g| g.0.web.default_search.clone())
            .unwrap_or_else(|_| self.app_config.web.default_search.clone());
        DaemonStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
            pid: std::process::id(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
            indexed_apps: apps,
            indexed_files: files,
            indexed_sites: sites,
            registered_capabilities: self.broker.count(),
            active_sessions: self.sessions.active_count(),
            pending_approvals: self.policy.pending_count(),
            undo_changesets_available: self.state_db.count_applied_changesets(),
            undo_backup_bytes: backup_bytes,
            runtime_mode: self.agent.active_runtime_label(),
            main_model_configured: self.gateway.has_usable_credentials(),
            default_search_engine: default_search,
        }
    }

    pub fn probe_summary(&self) -> Value {
        let sb = probe_sandbox();
        json!({
            "sandbox": sb,
            "settings_backends": self.settings.probe_status(),
            "gateway_metrics": self.gateway.metrics(),
            "authorized_roots": self.fs_engine.authorized_roots(),
            "aios_tools": self.broker.aios_tool_specs().iter().map(|t| json!({
                "name": t.name,
                "description": t.description,
            })).collect::<Vec<_>>(),
            "capabilities": self.broker.descriptors().iter().map(|d| json!({
                "id": d.id,
                "category": d.category,
                "effects": d.effects,
                "risk": d.max_effect().risk_badge(),
                "undo": d.undo,
                "summary": d.summary,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn stop_all(&self) -> anyhow::Result<()> {
        for t in self.state_db.list_tasks(50)? {
            if matches!(
                t.status,
                TaskStatus::Running | TaskStatus::Planning | TaskStatus::AwaitingApproval
            ) && UnifiedTaskStateMachine::can_transition(t.status, TaskStatus::Cancelled)
            {
                self.gateway.cancel_task_leases(&t.id);
                let mut cancelled = t;
                UnifiedTaskStateMachine::transition_task(
                    &mut cancelled,
                    TaskStatus::Cancelled,
                    None,
                )?;
                self.state_db.upsert_task(&cancelled)?;
            }
        }
        self.incognito_tasks.lock().unwrap().clear();
        self.task_privacy_policies.lock().unwrap().clear();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_complete_aios_deterministic_task(
        &self,
        task_id: &str,
        session: &SessionState,
        resolved_text: &str,
        mut taints: Vec<Taint>,
        mut data_class: DataClass,
        privacy: PrivacySessionPolicy,
        now: chrono::DateTime<Utc>,
    ) -> anyhow::Result<Option<Task>> {
        if privacy.allows_memory_read()
            && is_smart_document_chapter_query(resolved_text)
            && let Some(doc_task) = self
                .try_execute_smart_document_open(
                    task_id,
                    session,
                    resolved_text,
                    taints.clone(),
                    data_class,
                    privacy,
                    now,
                    true,
                )
                .await?
        {
            return Ok(Some(doc_task));
        }

        if privacy.allows_memory_read()
            && let Some((answer_md, hits)) =
                crate::memory_hub::try_answer_memory_query_deterministically_with_policy(
                    self,
                    resolved_text,
                    Some(session.session_id.as_str()),
                    privacy,
                )
        {
            if !taints.contains(&Taint::Memory) {
                taints.push(Taint::Memory);
            }
            if DataClass::Personal > data_class {
                data_class = DataClass::Personal;
            }
            let step = TaskStep {
                step_id: format!("mem_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
                capability_id: "memory_hub.query".into(),
                arguments_summary: json!({ "query": resolved_text }).to_string(),
                status: ExecutionStatus::Exited,
                verification: intentos_protocol::VerificationReport {
                    state: intentos_protocol::VerificationState::Passed,
                    method: "memory_hub_sqlite_wal".into(),
                    checks: vec!["personal_memory_recalled".into()],
                    details: None,
                },
                changeset_id: None,
                message: format!("已从个人记忆与数据层召回 {} 项记录", hits.len()),
                data: json!({ "hits": hits }),
                duration_ms: 1,
            };
            let task = Task {
                id: task_id.to_string(),
                goal: resolved_text.to_string(),
                session_id: Some(session.session_id.clone()),
                project_id: None,
                trigger: TaskTrigger::User,
                route: RouteLayer::L2,
                status: TaskStatus::Completed,
                steps: vec![step],
                changeset_ids: Vec::new(),
                pending_approval: None,
                candidates_for_disambiguation: Vec::new(),
                assistant_message: Some(answer_md.clone()),
                result_summary: Some(answer_md.clone()),
                handoff_command: None,
                taint: taints,
                data_class,
                budget: TaskBudget::default(),
                created_at: now,
                updated_at: Utc::now(),
            };
            self.persist_or_ephemeral_with_privacy(&task, privacy)?;
            if privacy.allows_memory_write() {
                self.sessions
                    .append_turn(&session.session_id, resolved_text, &answer_md, None);
            }
            return Ok(Some(task));
        }

        if let Some(adapter_out) =
            try_execute_deterministic_adapter_intent(self, task_id, resolved_text).await
        {
            let task = Task {
                id: task_id.to_string(),
                goal: resolved_text.to_string(),
                session_id: Some(session.session_id.clone()),
                project_id: None,
                trigger: TaskTrigger::User,
                route: RouteLayer::L2,
                status: TaskStatus::Completed,
                steps: adapter_out.steps,
                changeset_ids: adapter_out.changeset_ids,
                pending_approval: adapter_out.pending_approval,
                candidates_for_disambiguation: Vec::new(),
                assistant_message: Some(adapter_out.final_message.clone()),
                result_summary: Some(adapter_out.final_message.clone()),
                handoff_command: adapter_out.handoff_command,
                taint: taints,
                data_class,
                budget: TaskBudget::default(),
                created_at: now,
                updated_at: Utc::now(),
            };
            self.persist_or_ephemeral_with_privacy(&task, privacy)?;
            if privacy.allows_memory_write() {
                self.sessions.append_turn(
                    &session.session_id,
                    resolved_text,
                    &adapter_out.final_message,
                    None,
                );
            }
            return Ok(Some(task));
        }

        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_execute_smart_document_open(
        &self,
        task_id: &str,
        session: &SessionState,
        resolved_text: &str,
        mut taints: Vec<Taint>,
        mut data_class: DataClass,
        privacy: PrivacySessionPolicy,
        now: chrono::DateTime<Utc>,
        require_chapter: bool,
    ) -> anyhow::Result<Option<Task>> {
        if !privacy.allows_memory_read() {
            return Ok(None);
        }
        let chap_num_opt = crate::memory_hub::extract_chapter_number_hint(resolved_text);
        if require_chapter && chap_num_opt.is_none() {
            return Ok(None);
        }
        let section_hint = chap_num_opt.map(|n| format!("第{}章", n));
        let inspect_t0 = Instant::now();
        let inspected = match crate::memory_hub::inspect_document_with_sync(
            self,
            resolved_text,
            section_hint.as_deref(),
            privacy.allows_memory_write(),
        ) {
            Ok(val) => val,
            Err(_) => return Ok(None),
        };
        if !inspected
            .get("found")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let Some(doc_path) = inspected
            .get("path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
        else {
            return Ok(None);
        };
        if self.fs_engine.is_forbidden(std::path::Path::new(&doc_path)) {
            return Ok(None);
        }

        if !taints.contains(&Taint::Memory) {
            taints.push(Taint::Memory);
        }
        if DataClass::Personal > data_class {
            data_class = DataClass::Personal;
        }

        let doc_title = inspected
            .get("doc_title")
            .and_then(|v| v.as_str())
            .unwrap_or("文档")
            .to_string();
        let matched_heading = inspected
            .pointer("/matched_section/heading")
            .and_then(|v| v.as_str())
            .map(String::from);
        let matched_excerpt = inspected
            .pointer("/matched_section/excerpt")
            .and_then(|v| v.as_str())
            .map(String::from);
        let doc_summary = inspected
            .get("doc_summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let inspect_args = match section_hint {
            Some(ref sec) => json!({ "query": resolved_text, "section": sec }),
            None => json!({ "query": resolved_text }),
        };
        let inspect_step = TaskStep {
            step_id: format!(
                "mem_doc_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            ),
            capability_id: "memory_inspect_document".into(),
            arguments_summary: inspect_args.to_string(),
            status: ExecutionStatus::Exited,
            verification: intentos_protocol::VerificationReport {
                state: intentos_protocol::VerificationState::Passed,
                method: "memory_hub_document_outline".into(),
                checks: vec!["document_outline_resolved".into()],
                details: None,
            },
            changeset_id: None,
            message: format!("已定位文档《{}》 -> {}", doc_title, doc_path),
            data: inspected.clone(),
            duration_ms: inspect_t0.elapsed().as_millis() as u64,
        };

        // Check user's explicit file-association preference (`open_with.<ext>`) just like `router`
        let ext = std::path::Path::new(&doc_path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let (open_cap_id, open_args) = if !ext.is_empty()
            && let Some(pref_app) = self
                .state_db
                .get_memory_value(&format!("open_with.{}", ext))
        {
            (
                "file.open_with".to_string(),
                json!({ "app": pref_app, "path": doc_path }),
            )
        } else {
            ("file.open".to_string(), json!({ "path": doc_path }))
        };

        let open_call_id = format!("step_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let open_call = CapabilityCall {
            request_id: open_call_id.clone(),
            task_id: task_id.to_string(),
            capability_id: open_cap_id.clone(),
            arguments: open_args.clone(),
            origin: InvocationOrigin::UserExplicit,
            taints: taints.clone(),
        };

        match self.broker.dispatch(&open_call).await? {
            BrokerDispatchOutcome::Executed(open_res) => {
                let open_ok = matches!(
                    open_res.status,
                    ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
                );
                let mut md = format!("{}\n\n📖 **文档**：《{}》", open_res.message, doc_title);
                if let Some(ref heading) = matched_heading {
                    md.push_str(&format!("\n📑 **定位章节**：**{}**", heading));
                    if let Some(ref exc) = matched_excerpt
                        && !exc.trim().is_empty()
                    {
                        md.push_str(&format!("\n> {}", exc.trim()));
                    }
                } else if !doc_summary.trim().is_empty() {
                    md.push_str(&format!("\n> {}", doc_summary.trim()));
                }

                let open_step = TaskStep {
                    step_id: open_call_id,
                    capability_id: open_cap_id,
                    arguments_summary: open_args.to_string(),
                    status: open_res.status,
                    verification: open_res.verification,
                    changeset_id: open_res.changeset_id,
                    message: open_res.message,
                    data: open_res.data,
                    duration_ms: open_res.duration_ms,
                };

                let task = Task {
                    id: task_id.to_string(),
                    goal: resolved_text.to_string(),
                    session_id: Some(session.session_id.clone()),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L0,
                    status: if open_ok {
                        TaskStatus::Completed
                    } else {
                        TaskStatus::Failed
                    },
                    steps: vec![inspect_step, open_step],
                    changeset_ids: Vec::new(),
                    pending_approval: None,
                    candidates_for_disambiguation: Vec::new(),
                    assistant_message: Some(md.clone()),
                    result_summary: Some(md.clone()),
                    handoff_command: None,
                    taint: taints,
                    data_class,
                    budget: TaskBudget::default(),
                    created_at: now,
                    updated_at: Utc::now(),
                };
                self.persist_or_ephemeral_with_privacy(&task, privacy)?;
                if privacy.allows_memory_write() {
                    self.sessions.append_turn(
                        &session.session_id,
                        resolved_text,
                        &md,
                        Some(doc_path),
                    );
                }
                Ok(Some(task))
            }
            BrokerDispatchOutcome::RequiresApproval(pa) => {
                let task = Task {
                    id: task_id.to_string(),
                    goal: resolved_text.to_string(),
                    session_id: Some(session.session_id.clone()),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L0,
                    status: TaskStatus::AwaitingApproval,
                    steps: vec![inspect_step],
                    changeset_ids: Vec::new(),
                    pending_approval: Some(pa.clone()),
                    candidates_for_disambiguation: Vec::new(),
                    assistant_message: Some(pa.summary.clone()),
                    result_summary: Some(pa.summary),
                    handoff_command: None,
                    taint: taints,
                    data_class,
                    budget: TaskBudget::default(),
                    created_at: now,
                    updated_at: Utc::now(),
                };
                self.persist_or_ephemeral_with_privacy(&task, privacy)?;
                Ok(Some(task))
            }
            BrokerDispatchOutcome::Denied { reason } => {
                let msg = format!("策略拒绝：{}", reason);
                let task = Task {
                    id: task_id.to_string(),
                    goal: resolved_text.to_string(),
                    session_id: Some(session.session_id.clone()),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L0,
                    status: TaskStatus::Failed,
                    steps: vec![inspect_step],
                    changeset_ids: Vec::new(),
                    pending_approval: None,
                    candidates_for_disambiguation: Vec::new(),
                    assistant_message: Some(msg.clone()),
                    result_summary: Some(reason),
                    handoff_command: None,
                    taint: taints,
                    data_class,
                    budget: TaskBudget::default(),
                    created_at: now,
                    updated_at: Utc::now(),
                };
                self.persist_or_ephemeral_with_privacy(&task, privacy)?;
                Ok(Some(task))
            }
        }
    }
}

fn expand_tilde_core_path(raw: &str) -> PathBuf {
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

/// Detect Smart Chapter Open / Inspect queries such as `"打开我的硕士论文第四章"` or `"查看<文档>第X章"`.
fn is_smart_document_chapter_query(text: &str) -> bool {
    let q = text.trim();
    if q.is_empty() || crate::memory_hub::extract_chapter_number_hint(q).is_none() {
        return false;
    }
    let is_destructive_or_move = q.starts_with("移动")
        || q.starts_with("复制")
        || q.starts_with("删除")
        || q.starts_with("重命名")
        || (q.starts_with("把")
            && (q.contains("移")
                || q.contains("复制")
                || q.contains("删")
                || q.contains("改")
                || q.contains("压")));
    if is_destructive_or_move {
        return false;
    }
    q.contains("打开")
        || q.contains("查看")
        || q.contains("看看")
        || q.contains("阅读")
        || q.contains("翻到")
        || q.contains("定位")
}

/// Ensure L2 LLM replies after `memory_inspect_document` always surface the matched chapter heading & excerpt if omitted.
fn enrich_l2_chapter_open_message(final_message: &str, steps: &[TaskStep]) -> String {
    let Some(inspect_step) = steps
        .iter()
        .find(|s| s.capability_id == "memory_inspect_document")
    else {
        return final_message.to_string();
    };
    let Some(heading) = inspect_step
        .data
        .pointer("/matched_section/heading")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return final_message.to_string();
    };
    let excerpt = inspect_step
        .data
        .pointer("/matched_section/excerpt")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if final_message.contains(heading) {
        return final_message.to_string();
    }
    if excerpt.trim().is_empty() {
        format!(
            "{}\n\n📑 **定位章节**：**{}**",
            final_message.trim(),
            heading
        )
    } else {
        format!(
            "{}\n\n📑 **定位章节**：**{}**\n> {}",
            final_message.trim(),
            heading,
            excerpt.trim()
        )
    }
}

/// Detect unambiguous Personal Memory Hub questions or Software Translation Layer queries
/// so they are never hijacked by L0 file mtime filters or L1 clarification pauses.
fn is_explicit_personal_memory_or_adapter_query(text: &str) -> bool {
    let q = text.trim();
    if q.is_empty() {
        return false;
    }
    let is_imperative_mutation = q.starts_with("打开")
        || q.starts_with("移动")
        || q.starts_with("复制")
        || q.starts_with("删除")
        || q.starts_with("重命名")
        || (q.starts_with("把")
            && (q.contains("移")
                || q.contains("复制")
                || q.contains("删")
                || q.contains("改")
                || q.contains("压")));
    if is_imperative_mutation {
        return false;
    }

    let asks_what_or_list = q.contains("哪些")
        || q.contains("什么")
        || q.contains("哪个")
        || q.contains("哪份")
        || q.contains("列表")
        || q.contains("清单")
        || q.contains("看看")
        || q.contains("查看")
        || q.contains("列出");

    let asks_mentioned =
        crate::memory_hub::is_conversational_entity_reference(q) && asks_what_or_list;
    let asks_frequent_files = (q.contains("长期")
        || q.contains("常用")
        || q.contains("高频")
        || q.contains("经常打开")
        || q.contains("最近和长期"))
        && q.contains("文件")
        && asks_what_or_list;
    let asks_software = (q.contains("软件") || q.contains("应用") || q.contains("程序"))
        && (q.contains("电脑上")
            || q.contains("本机")
            || q.contains("已安装")
            || q.contains("装了")
            || q.contains("常用")
            || q.contains("经常用")
            || q.contains("有哪些")
            || q.contains("清单")
            || q.contains("列表"));
    let asks_adapter = q.contains("转译层")
        || q.contains("软件适配器")
        || q.contains("适配器列表")
        || q.contains("托盘菜单")
        || q.contains("怎么还没有打开")
        || q.contains("为什么没打开")
        || q.contains("正在播放什么")
        || q.contains("当前正在播放")
        || q.contains("当前播放什么")
        || q.contains("现在放的什么歌");

    asks_mentioned || asks_frequent_files || asks_software || asks_adapter
}

/// Resolve natural-language references like `"打开我之前说的那个文件"` or `"把刚才提到的文件复制到下载"`
/// against `memory_hub` entity mentions across turns and sessions.
fn resolve_conversational_memory_entity(
    core: &IntentOsCore,
    text: &str,
    session_id: &str,
) -> Option<String> {
    let q = text.trim();
    if !crate::memory_hub::is_conversational_entity_reference(q) {
        return None;
    }
    let question_words = [
        "有哪些",
        "有什么",
        "是什么",
        "哪些文件",
        "列表",
        "清单",
        "汇总",
        "统计",
    ];
    if question_words.iter().any(|w| q.contains(w)) {
        return None;
    }
    let action_verbs = [
        "打开",
        "查看",
        "定位",
        "把",
        "将",
        "重命名",
        "改名",
        "复制",
        "拷贝",
        "移动",
        "移到",
        "删除",
        "移入回收站",
        "压缩",
        "解压",
    ];
    if !action_verbs.iter().any(|v| q.contains(v)) {
        return None;
    }
    if !crate::memory_hub::MemoryHubDb::path_for_core(core).exists() {
        return None;
    }
    let db = crate::memory_hub::MemoryHubDb::open_for_core(core).ok()?;
    let mut recalled: Vec<crate::memory_hub::EntityMention> =
        crate::memory_hub::recall_mentioned_entities(&db, q, Some("file"), Some(session_id), 5)
            .unwrap_or_default()
            .into_iter()
            .map(|(ent, _)| ent)
            .collect();
    if recalled.is_empty() {
        recalled = crate::memory_hub::list_recent_mentions(&db, true, None, 5).unwrap_or_default();
    }
    let top = recalled.into_iter().find(|e| {
        e.canonical_value.starts_with('/')
            && !core
                .fs_engine
                .is_forbidden(std::path::Path::new(&e.canonical_value))
    })?;

    // Replace longest matching conversational reference phrase first
    let ref_phrases = [
        "我之前提到的那个文件",
        "我之前说的那个文件",
        "之前提到的那个文件",
        "之前说的那个文件",
        "我刚才提到的那个文件",
        "我刚才说的那个文件",
        "刚才提到的那个文件",
        "刚才说的那个文件",
        "上次提到的那个文件",
        "上次说的那个文件",
        "之前提过的那个文件",
        "我之前提到的文件",
        "我之前说的文件",
        "之前提到的文件",
        "之前说的文件",
        "刚才提到的文件",
        "刚才说的文件",
        "上次提到的文件",
        "上次说的文件",
        "之前提过的文件",
        "那个文档",
        "那份文档",
        "那个文件",
        "那份文件",
    ];
    for phrase in ref_phrases {
        if q.contains(phrase) {
            return Some(q.replacen(phrase, &top.canonical_value, 1));
        }
    }
    None
}

/// Deterministic Software Command Translation Layer (`app_adapter`) handler for explicit adapter / MPRIS2 queries
/// when no cloud LLM key is configured or reachable.
pub(crate) async fn try_execute_deterministic_adapter_intent(
    core: &IntentOsCore,
    _task_id: &str,
    text: &str,
) -> Option<crate::runtime::AgentRunResult> {
    let q = text.trim();
    let asks_music_via_adapter = (q.contains("转译层")
        && (q.contains("音乐") || q.contains("播放")))
        || q.contains("正在播放什么")
        || q.contains("当前正在播放")
        || q.contains("当前播放什么")
        || q.contains("现在放的什么歌");
    let asks_adapter_catalog =
        q.contains("转译层") || q.contains("软件适配器") || q.contains("适配器列表");
    let asks_live_inspect =
        q.contains("托盘菜单") || q.contains("怎么还没有打开") || q.contains("为什么没打开");

    if !asks_music_via_adapter && !asks_adapter_catalog && !asks_live_inspect {
        return None;
    }

    let t0 = Instant::now();
    if asks_live_inspect && !asks_music_via_adapter {
        let mut target_app = q
            .replace("查看", "")
            .replace("看看", "")
            .replace("探测", "")
            .replace("托盘菜单", "")
            .replace("怎么还没有打开", "")
            .replace("为什么没打开", "")
            .replace("的", "")
            .trim()
            .trim_matches(['？', '?', '。', '！', '!'])
            .trim()
            .to_string();
        if target_app.is_empty() {
            target_app = "汽水音乐".to_string();
        }
        let args = json!({ "app": target_app });
        let inspect_res =
            crate::app_adapter::execute_adapter_tool(core, "app_adapter_inspect_app", &args)
                .await
                .ok()?;
        let dur = t0.elapsed().as_millis() as u64;
        let summary = inspect_res
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("已完成应用实时运行态与托盘探测")
            .to_string();
        let step = TaskStep {
            step_id: format!("adp_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
            capability_id: "app_adapter_inspect_app".into(),
            arguments_summary: args.to_string(),
            status: ExecutionStatus::Exited,
            verification: intentos_protocol::VerificationReport {
                state: intentos_protocol::VerificationState::Passed,
                method: "app_adapter_inspect_app".into(),
                checks: vec!["live_app_inspected".into()],
                details: None,
            },
            changeset_id: None,
            message: summary.clone(),
            data: inspect_res,
            duration_ms: dur,
        };
        return Some(crate::runtime::AgentRunResult {
            final_message: format!("### 个性化软件实时探测\n- {}", summary),
            steps: vec![step],
            changeset_ids: Vec::new(),
            pending_approval: None,
            handoff_command: None,
            status_override: None,
            side_effect_replay_prevented: false,
        });
    }

    if asks_music_via_adapter {
        let wants_pause_toggle =
            (q.contains("暂停") || q.contains("继续")) && !q.contains("查看或");
        let tool_name = if wants_pause_toggle {
            "app_adapter_invoke"
        } else {
            "app_adapter_now_playing"
        };
        let args = if wants_pause_toggle {
            json!({
                "app_hint": "music",
                "intent_action": "play_pause",
                "params": {}
            })
        } else {
            json!({})
        };
        let now_res = crate::app_adapter::execute_adapter_tool(core, tool_name, &args)
            .await
            .unwrap_or_else(|e| json!({ "ok": false, "summary": e.to_string() }));
        let media_list = crate::app_adapter::execute_adapter_tool(
            core,
            "app_adapter_list",
            &json!({ "category": "media" }),
        )
        .await
        .unwrap_or_else(|_| json!({}));
        let dur = t0.elapsed().as_millis() as u64;

        let active_players = now_res
            .get("players")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut md =
            String::from("### 软件指令转译层 · 媒体播放控制 (MPRIS2 / StatusNotifierItem 托盘)\n");
        if !active_players.is_empty() {
            for p in &active_players {
                let name = p
                    .get("player_identity")
                    .or_else(|| p.get("identity"))
                    .or_else(|| p.get("bus_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Media Player");
                let status = p
                    .get("playback_status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let title = p
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("未知曲目");
                let artist = p.get("artist").and_then(|v| v.as_str()).unwrap_or("");
                if artist.is_empty() {
                    md.push_str(&format!(
                        "- **{}** [{}]：正在播放《{}》\n",
                        name, status, title
                    ));
                } else {
                    md.push_str(&format!(
                        "- **{}** [{}]：《{}》 — {}\n",
                        name, status, title, artist
                    ));
                }
            }
        } else {
            let summary = now_res
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("当前会话总线上未检测到正在运行的活跃 MPRIS2 播放器实例");
            md.push_str(&format!("- 实时探测：{}\n", summary));
        }

        if let Some(adapters) = media_list.get("adapters").and_then(|v| v.as_array())
            && !adapters.is_empty()
        {
            let names: Vec<&str> = adapters
                .iter()
                .take(8)
                .filter_map(|a| a.get("display_name").and_then(|v| v.as_str()))
                .collect();
            md.push_str(&format!(
                "- 已就绪媒体转译适配器（共 {} 款）：{}（支持免 CLI 直接通过 `MPRIS2 / D-Bus` 执行播放/暂停、上一首/下一首、曲目读取与音量调节）",
                adapters.len(),
                names.join("、")
            ));
        }

        let step = TaskStep {
            step_id: format!("adp_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
            capability_id: tool_name.into(),
            arguments_summary: args.to_string(),
            status: ExecutionStatus::Exited,
            verification: intentos_protocol::VerificationReport {
                state: intentos_protocol::VerificationState::Passed,
                method: "app_adapter_mpris2".into(),
                checks: vec!["mpris2_probed".into()],
                details: None,
            },
            changeset_id: None,
            message: "已通过软件指令转译层探测 MPRIS2 媒体状态".into(),
            data: now_res,
            duration_ms: dur,
        };
        return Some(crate::runtime::AgentRunResult {
            final_message: md,
            steps: vec![step],
            changeset_ids: Vec::new(),
            pending_approval: None,
            handoff_command: None,
            status_override: None,
            side_effect_replay_prevented: false,
        });
    }

    let list_res = crate::app_adapter::execute_adapter_tool(core, "app_adapter_list", &json!({}))
        .await
        .ok()?;
    let dur = t0.elapsed().as_millis() as u64;
    let adapters = list_res
        .get("adapters")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut md = format!(
        "### 软件指令转译层（共内置 {} 款 Linux 桌面软件适配器）\n",
        adapters.len()
    );
    for a in adapters.iter().take(12) {
        let name = a
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or("App");
        let cat = a
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("general");
        let chans = a
            .get("channels")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .unwrap_or_default();
        md.push_str(&format!("- **{}** (`{}`) — 通道: `{}`\n", name, cat, chans));
    }
    let step = TaskStep {
        step_id: format!("adp_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        capability_id: "app_adapter_list".into(),
        arguments_summary: "{}".into(),
        status: ExecutionStatus::Exited,
        verification: intentos_protocol::VerificationReport {
            state: intentos_protocol::VerificationState::Passed,
            method: "app_adapter_registry".into(),
            checks: vec!["adapter_registry_listed".into()],
            details: None,
        },
        changeset_id: None,
        message: format!("已列出 {} 款软件指令转译适配器", adapters.len()),
        data: list_res,
        duration_ms: dur,
    };
    Some(crate::runtime::AgentRunResult {
        final_message: md,
        steps: vec![step],
        changeset_ids: Vec::new(),
        pending_approval: None,
        handoff_command: None,
        status_override: None,
        side_effect_replay_prevented: false,
    })
}
