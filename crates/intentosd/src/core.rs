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
use crate::settings::SystemSettingsEngine;
use chrono::Utc;
use intentos_fsops::SafeFsEngine;
use intentos_protocol::{
    CandidateResponse, CapabilityCall, ChangeSet, ContextBlock, DaemonStatus, DataClass,
    ExecutionStatus, IntentRequest, InvocationOrigin, PROTOCOL_VERSION, RouteLayer, Task,
    TaskBudget, TaskStatus, TaskStep, TaskTrigger, Taint, UiRpcRequest, UiRpcResponse,
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
            SystemSettingsEngine::new(state_db.clone(), app_config.allow_simulated_hardware_fallback)
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
                                !intent_req.incognito,
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
                    let mem_id = self
                        .state_db
                        .save_explicit_memory(&subject, &value, None)?;
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

    pub(crate) fn is_incognito_task(&self, task_id: &str) -> bool {
        task_id.starts_with("incog_") || self.incognito_tasks.lock().unwrap().contains_key(task_id)
    }

    pub(crate) fn persist_or_ephemeral(&self, task: &Task, incognito: bool) -> anyhow::Result<()> {
        if incognito {
            if task.status == TaskStatus::AwaitingApproval {
                self.incognito_tasks
                    .lock()
                    .unwrap()
                    .insert(task.id.clone(), task.clone());
            }
            Ok(())
        } else {
            self.state_db.upsert_task(task)
        }
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
        let is_incognito = req.incognito;
        let original_user_text = req.text.clone();
        let is_passthrough_attempt = original_user_text.trim().starts_with('$');

        let task = self.submit_intent_inner(req, injected_context).await?;

        if record_in_memory_hub && !is_incognito && !is_passthrough_attempt {
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
            let _ = crate::memory_hub::record_conversation_turn(
                self,
                &crate::memory_hub::RecordTurnInput {
                    session_id: task.session_id.clone(),
                    user_text: original_user_text,
                    assistant_text,
                    thinking: None,
                    tool_steps,
                    trace_dots: Vec::new(),
                    incognito: false,
                },
            );
        }

        Ok(task)
    }

    async fn submit_intent_inner(
        &self,
        req: IntentRequest,
        mut injected_context: Vec<ContextBlock>,
    ) -> anyhow::Result<Task> {
        let incognito = req.incognito;
        let session = if incognito {
            SessionState {
                session_id: format!(
                    "incog_{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..8]
                ),
                messages: Vec::new(),
                last_resource_path: None,
                updated_at: Utc::now(),
            }
        } else {
            self.sessions.get_or_create(req.session_id.as_deref())
        };
        let task_id = if incognito {
            format!(
                "incog_task_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..10]
            )
        } else {
            format!("task_{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
        };
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
            } else if req.text.contains("它所在文件夹") || req.text.contains("它所在目录") {
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
            let ctx_out = crate::intent_engine::resolve_context_references(
                &req.text,
                Some(&session),
                Some(&self.state_db),
                None,
            );
            if ctx_out.is_resolved() {
                resolved_text = ctx_out.effective_text().to_string();
            }
        }
        // Wave 2 Personal Memory Hub multi-turn entity resolution ("打开我之前说的那个文件" / "把刚才提到的那个文件移到下载")
        if !incognito
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
        let is_aios_memory_or_adapter_query =
            is_explicit_personal_memory_or_adapter_query(&resolved_text);
        let is_doc_chapter_query = is_smart_document_chapter_query(&resolved_text);

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
                    incognito,
                    now,
                )
                .await?
        {
            return Ok(task);
        }

        let routed = if is_aios_memory_or_adapter_query || is_doc_chapter_query {
            RoutedIntent::EscalateL2 {
                reason: "AIOS 个人记忆、文档章节大纲定位或软件指令转译查询升级至 L2 智能体".into(),
            }
        } else {
            self.router.route_text(&resolved_text, effective_force_agent)
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
                self.persist_or_ephemeral(&task, incognito)?;
                if !incognito {
                    self.sessions
                        .append_turn(&session.session_id, &resolved_text, &msg, None);
                }
                Ok(task)
            }
            RoutedIntent::SaveExplicitMemory { subject, value } => {
                if incognito {
                    let msg = "当前处于隐私会话（Incognito）模式：不保存任何持久化记忆或历史记录".to_string();
                    return Ok(Task {
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
                match self
                    .state_db
                    .save_explicit_memory(&subject, &value, Some(&task_id))
                {
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
                        let msg = err.to_string();
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
                            assistant_message: Some(msg.clone()),
                            result_summary: Some(msg),
                            handoff_command: None,
                            taint: taints,
                            data_class: DataClass::Forbidden,
                            budget: TaskBudget::default(),
                            created_at: now,
                            updated_at: Utc::now(),
                        };
                        self.state_db.upsert_task(&task)?;
                        Ok(task)
                    }
                }
            }
            RoutedIntent::SaveCurrentScene { name } => {
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
                self.persist_or_ephemeral(&task, incognito)?;
                if !incognito {
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
                // Stage 2 (`v0.1`): Run L1 Typed Decision Adapter before escalating to L2 unless `effective_force_agent` or AIOS memory/chapter/adapter query!
                if !effective_force_agent
                    && !is_aios_memory_or_adapter_query
                    && !is_doc_chapter_query
                {
                    let descriptors = self.broker.descriptors();
                    match self
                        .decision
                        .classify_colloquial_intent(&resolved_text, &descriptors)
                    {
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
                            return self
                                .execute_single_capability_task(
                                    task_id,
                                    &session.session_id,
                                    &resolved_text,
                                    RouteLayer::L1,
                                    &capability_id,
                                    arguments,
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
                            let task = Task {
                                id: task_id,
                                goal: resolved_text,
                                session_id: Some(session.session_id),
                                project_id: None,
                                trigger: TaskTrigger::User,
                                route: RouteLayer::L1,
                                status: TaskStatus::Paused,
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
                            self.persist_or_ephemeral(&task, incognito)?;
                            return Ok(task);
                        }
                        L1DecisionOutcome::EscalateL2 { extra_taint, .. } => {
                            if let Some(et) = extra_taint
                                && !taints.contains(&et)
                            {
                                taints.push(et);
                            }

                            // v0.3 `intent_engine` fallback: check compound deterministic steps or Pinyin/fuzzy match
                            // before escalating to L2 (when input is untainted and not a "怎么/如何" how-to query;
                            // offline mode also decomposes polite "帮我..." compound system intents).
                            if !taints.contains(&Taint::LocalUntrusted)
                                && !taints.contains(&Taint::RemoteUntrusted)
                                && !resolved_text.contains("怎么")
                                && !resolved_text.contains("如何")
                                && (!resolved_text.contains("帮我")
                                    || !self.gateway.has_usable_credentials())
                            {
                                let compiler =
                                    crate::intent_engine::PatternCompiler::compile_from_descriptors(
                                        &descriptors,
                                    );
                                let compound = crate::intent_engine::split_compound_intent(
                                    self,
                                    &resolved_text,
                                    &compiler,
                                );
                                if compound.is_compound
                                    && compound.steps.len() >= 2
                                    && compound.steps.iter().all(|s| {
                                        s.confidence >= 0.85 && !s.depends_on_previous_output
                                    })
                                {
                                    let rep = crate::intent_engine::execute_compound(
                                        self,
                                        &resolved_text,
                                        Some(compound.steps),
                                        Some(&session.session_id),
                                        incognito,
                                        &compiler,
                                    )
                                    .await?;
                                    let status = if rep.all_succeeded {
                                        TaskStatus::Completed
                                    } else {
                                        TaskStatus::Failed
                                    };
                                    let task = Task {
                                        id: task_id,
                                        goal: resolved_text,
                                        session_id: Some(session.session_id),
                                        project_id: None,
                                        trigger: TaskTrigger::User,
                                        route: RouteLayer::L1,
                                        status,
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
                                    self.persist_or_ephemeral(&task, incognito)?;
                                    return Ok(task);
                                }

                                if !resolved_text.contains("帮我") {
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
                                                    incognito,
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

                // Automatically inject Personal OS Memory RAG context before L2 LLM inference (when not incognito)
                if !incognito
                    && self.gateway.has_usable_credentials()
                    && !injected_context
                        .iter()
                        .any(|b| b.label == "personal_os_memory")
                {
                    let (mem_md, _hits) = crate::memory_hub::build_personal_memory_prompt(
                        self,
                        &resolved_text,
                        Some(session.session_id.as_str()),
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
                    max_cost: None,
                };
                let mut task = Task {
                    id: task_id.clone(),
                    goal: resolved_text.clone(),
                    session_id: Some(session.session_id.clone()),
                    project_id: None,
                    trigger: TaskTrigger::User,
                    route: RouteLayer::L2,
                    status: TaskStatus::Running,
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
                self.persist_or_ephemeral(&task, incognito)?;

                match self
                    .agent
                    .run_l2(&task_id, &session, &resolved_text, injected_context, budget)
                    .await
                {
                    Ok(run_out) => {
                        task.steps = run_out.steps;
                        task.changeset_ids = run_out.changeset_ids;
                        task.handoff_command = run_out.handoff_command;
                        task.updated_at = Utc::now();
                        if let Some(pa) = run_out.pending_approval {
                            task.status = TaskStatus::AwaitingApproval;
                            task.assistant_message = Some(pa.summary.clone());
                            task.pending_approval = Some(pa);
                        } else {
                            let enriched_msg = enrich_l2_chapter_open_message(
                                &run_out.final_message,
                                &task.steps,
                            );
                            task.status = TaskStatus::Completed;
                            task.assistant_message = Some(enriched_msg.clone());
                            task.result_summary = Some(enriched_msg.clone());
                            if !incognito {
                                self.sessions.append_turn(
                                    &session.session_id,
                                    &resolved_text,
                                    &enriched_msg,
                                    None,
                                );
                            }
                        }
                        self.persist_or_ephemeral(&task, incognito)?;
                        Ok(task)
                    }
                    Err(err) => {
                        // Even if a configured cloud API key is unreachable, personal-memory & adapter queries
                        // still return rich, real local answers!
                        if let Some(fallback_task) = self
                            .try_complete_aios_deterministic_task(
                                &task_id,
                                &session,
                                &resolved_text,
                                taints,
                                data_class,
                                incognito,
                                now,
                            )
                            .await?
                        {
                            return Ok(fallback_task);
                        }
                        task.status = TaskStatus::Failed;
                        task.assistant_message = Some(err.to_string());
                        task.result_summary = Some(err.to_string());
                        task.updated_at = Utc::now();
                        self.persist_or_ephemeral(&task, incognito)?;
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
        let now = Utc::now();
        let call_id = format!("step_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let call = CapabilityCall {
            request_id: call_id.clone(),
            task_id: task_id.clone(),
            capability_id: capability_id.to_string(),
            arguments: arguments.clone(),
            origin,
            taints: taints.clone(),
        };

        let mut task = Task {
            id: task_id.clone(),
            goal: goal.to_string(),
            session_id: Some(session_id.to_string()),
            project_id: None,
            trigger: TaskTrigger::User,
            route,
            status: TaskStatus::Running,
            steps: Vec::new(),
            changeset_ids: Vec::new(),
            pending_approval: None,
            candidates_for_disambiguation: Vec::new(),
            assistant_message: None,
            result_summary: None,
            handoff_command: None,
            taint: taints,
            data_class,
            budget: TaskBudget::default(),
            created_at: now,
            updated_at: now,
        };

        match self.broker.dispatch(&call).await? {
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
                task.status = if ok_status {
                    TaskStatus::Completed
                } else {
                    TaskStatus::Failed
                };
                task.assistant_message = Some(res.message.clone());
                task.result_summary = Some(res.message.clone());
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
                self.persist_or_ephemeral(&task, incognito)?;
                if !incognito {
                    self.sessions
                        .append_turn(session_id, goal, &res.message, last_res);
                }
                Ok(task)
            }
            BrokerDispatchOutcome::RequiresApproval(pa) => {
                task.status = TaskStatus::AwaitingApproval;
                task.assistant_message = Some(pa.summary.clone());
                task.pending_approval = Some(pa);
                task.updated_at = Utc::now();
                self.persist_or_ephemeral(&task, incognito)?;
                Ok(task)
            }
            BrokerDispatchOutcome::Denied { reason } => {
                task.status = TaskStatus::Failed;
                task.assistant_message = Some(format!("策略拒绝：{}", reason));
                task.result_summary = Some(reason);
                task.updated_at = Utc::now();
                self.persist_or_ephemeral(&task, incognito)?;
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
        let mut really_incognito = pa.task_id.starts_with("incog_");
        let mut persist_task = false;
        let mut task = if let Some(t) = self.incognito_tasks.lock().unwrap().remove(&pa.task_id) {
            really_incognito = true;
            t
        } else if let Some(t) = self.state_db.get_task(&pa.task_id)? {
            persist_task = true;
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

        let res = if crate::app_adapter::is_adapter_tool(&pa.capability_id) {
            let call = CapabilityCall {
                request_id: pa.approval_id.clone(),
                task_id: task.id.clone(),
                capability_id: pa.capability_id.clone(),
                arguments: pa.arguments.clone(),
                origin: InvocationOrigin::UserExplicit,
                taints: vec![Taint::User],
            };
            match self.broker.dispatch(&call).await? {
                BrokerDispatchOutcome::Executed(r) => r,
                BrokerDispatchOutcome::Denied { reason } => {
                    anyhow::bail!("转译层执行被拒绝: {}", reason);
                }
                BrokerDispatchOutcome::RequiresApproval(_) => {
                    anyhow::bail!("转译层在已确认状态下仍请求重复确认");
                }
            }
        } else {
            let desc = self
                .broker
                .get_descriptor(&pa.capability_id)
                .ok_or_else(|| anyhow::anyhow!("未找到能力: {}", pa.capability_id))?;

            self.broker
                .execute_approved(&pa.approval_id, &task.id, desc, &pa.arguments)
                .await?
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

        if !really_incognito
            && let (Some(sid), Some(rp)) = (task.session_id.as_deref(), last_res.as_ref())
        {
            self.sessions.set_last_resource_path(sid, rp.clone());
        }

        if !really_incognito && let Some(ref csid) = res.changeset_id {
            task.changeset_ids.push(csid.clone());
        }
        task.pending_approval = None;
        task.status = if matches!(
            res.status,
            ExecutionStatus::Exited | ExecutionStatus::RequestedUnverified
        ) {
            TaskStatus::Completed
        } else {
            TaskStatus::Failed
        };
        task.assistant_message = Some(res.message.clone());
        task.result_summary = Some(res.message.clone());
        let step = TaskStep {
            step_id: pa.approval_id,
            capability_id: pa.capability_id,
            arguments_summary: pa.arguments.to_string(),
            status: res.status,
            verification: res.verification,
            changeset_id: if really_incognito {
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
        if persist_task && !really_incognito {
            self.state_db.upsert_task(&task)?;
            if record_standalone_turn {
                if let Some(ref sid) = task.session_id {
                    self.sessions.append_turn(
                        sid,
                        &format!("确认执行：{}", task.goal),
                        &res.message,
                        last_res,
                    );
                }
                let _ = crate::memory_hub::record_conversation_turn(
                    self,
                    &crate::memory_hub::RecordTurnInput {
                        session_id: task.session_id.clone(),
                        user_text: format!("确认执行：{}", task.goal),
                        assistant_text: res.message,
                        thinking: None,
                        tool_steps: vec![step_json],
                        trace_dots: Vec::new(),
                        incognito: false,
                    },
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
        let mut is_incognito = pa.task_id.starts_with("incog_");
        let mut task = if let Some(t) = self.incognito_tasks.lock().unwrap().remove(&pa.task_id) {
            is_incognito = true;
            t
        } else if let Some(t) = self.state_db.get_task(&pa.task_id)? {
            t
        } else {
            is_incognito = true;
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
        task.pending_approval = None;
        task.status = TaskStatus::Cancelled;
        task.assistant_message = Some("用户拒绝了该操作，未产生修改".into());
        task.updated_at = Utc::now();
        if !is_incognito {
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
            ) {
                self.gateway.cancel_task_leases(&t.id);
                let mut cancelled = t;
                cancelled.status = TaskStatus::Cancelled;
                cancelled.pending_approval = None;
                cancelled.updated_at = Utc::now();
                self.state_db.upsert_task(&cancelled)?;
            }
        }
        self.incognito_tasks.lock().unwrap().clear();
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
        incognito: bool,
        now: chrono::DateTime<Utc>,
    ) -> anyhow::Result<Option<Task>> {
        if is_smart_document_chapter_query(resolved_text)
            && let Some(doc_task) = self
                .try_execute_smart_document_open(
                    task_id,
                    session,
                    resolved_text,
                    taints.clone(),
                    data_class,
                    incognito,
                    now,
                    true,
                )
                .await?
        {
            return Ok(Some(doc_task));
        }

        if !incognito || crate::memory_hub::MemoryHubDb::path_for_core(self).exists() {
            let sid_opt = if incognito {
                None
            } else {
                Some(session.session_id.as_str())
            };
            if let Some((answer_md, hits)) =
                crate::memory_hub::try_answer_memory_query_deterministically(
                    self,
                    resolved_text,
                    sid_opt,
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
                self.persist_or_ephemeral(&task, incognito)?;
                if !incognito {
                    self.sessions
                        .append_turn(&session.session_id, resolved_text, &answer_md, None);
                }
                return Ok(Some(task));
            }
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
            self.persist_or_ephemeral(&task, incognito)?;
            if !incognito {
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
        incognito: bool,
        now: chrono::DateTime<Utc>,
        require_chapter: bool,
    ) -> anyhow::Result<Option<Task>> {
        let chap_num_opt = crate::memory_hub::extract_chapter_number_hint(resolved_text);
        if require_chapter && chap_num_opt.is_none() {
            return Ok(None);
        }
        let section_hint = chap_num_opt.map(|n| format!("第{}章", n));
        let inspect_t0 = Instant::now();
        let inspected =
            match crate::memory_hub::inspect_document(self, resolved_text, section_hint.as_deref())
            {
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
            step_id: format!("mem_doc_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
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
                self.persist_or_ephemeral(&task, incognito)?;
                if !incognito {
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
                self.persist_or_ephemeral(&task, incognito)?;
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
                self.persist_or_ephemeral(&task, incognito)?;
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
        format!("{}\n\n📑 **定位章节**：**{}**", final_message.trim(), heading)
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

    let asks_mentioned = crate::memory_hub::is_conversational_entity_reference(q) && asks_what_or_list;
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
        "有哪些", "有什么", "是什么", "哪些文件", "列表", "清单", "汇总", "统计",
    ];
    if question_words.iter().any(|w| q.contains(w)) {
        return None;
    }
    let action_verbs = [
        "打开", "查看", "定位", "把", "将", "重命名", "改名", "复制", "拷贝", "移动", "移到",
        "删除", "移入回收站", "压缩", "解压",
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
    let asks_music_via_adapter = (q.contains("转译层") && (q.contains("音乐") || q.contains("播放")))
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
                let artist = p
                    .get("artist")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if artist.is_empty() {
                    md.push_str(&format!("- **{}** [{}]：正在播放《{}》\n", name, status, title));
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
        });
    }

    let list_res =
        crate::app_adapter::execute_adapter_tool(core, "app_adapter_list", &json!({}))
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
        let cat = a.get("category").and_then(|v| v.as_str()).unwrap_or("general");
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
    })
}
