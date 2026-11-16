#![forbid(unsafe_code)]

//! Dynamic Capability Discovery Meta-Tools & Progressive Schema Exposure (`M2-A`, Issue `#6`).
//!
//! Provides the 6 canonical progressive discovery & verification meta-tools:
//! 1. `capability.search` (`capability_search`)
//! 2. `capability.describe` (`capability_describe`)
//! 3. `capability.invoke` (`capability_invoke`) — strictly routed 100% through `CapabilityBroker`
//!    transactional spine (`PolicyEngine`, `PendingApproval`, `TurnEffectLedger`, `ChangeSet`)
//! 4. `app.discover` (`app_discover`)
//! 5. `resource.resolve` (`resource_resolve`)
//! 6. `task.verify` (`task_verify`)

use crate::app_adapter::{
    AdapterRegistry, LocalScanOptions, SoftwareCapabilityProvider, deep_scan_local_software,
    inspect_live_app, is_adapter_tool, provider_tool_specs,
};
use crate::backend_bridge::broker_bridge::classify_capability_idempotency;
use crate::backend_bridge::turn_checkpoint::TurnEffectLedger;
use crate::broker::CapabilityBroker;
use crate::capability_snapshot::{
    CapabilitySnapshot, capability_snapshot_for_broker, capability_snapshot_for_core,
};
use crate::core::IntentOsCore;
use crate::memory_hub::{
    MemoryHubDb, ensure_lazy_synced, is_memory_tool, query_frequent_files,
    recall_mentioned_entities, search_document_outlines, sync_document_outlines,
};
use crate::resource::{FileSearchFilter, FileSortOrder};
use crate::runtime::SessionState;
use crate::security_guard::{PrivacySessionPolicy, SensitiveDataGuard, is_memory_write_tool};
use intentos_protocol::{
    CapabilityDescriptor, CapabilityResult, Effect, ExecutionStatus, ToolSpec, UndoStrategy,
    VerificationReport, VerificationState,
};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Instant, UNIX_EPOCH};

pub const META_CAPABILITY_SEARCH: &str = "capability.search";
pub const META_CAPABILITY_DESCRIBE: &str = "capability.describe";
pub const META_CAPABILITY_INVOKE: &str = "capability.invoke";
pub const META_APP_DISCOVER: &str = "app.discover";
pub const META_RESOURCE_RESOLVE: &str = "resource.resolve";
pub const META_TASK_VERIFY: &str = "task.verify";

pub const FN_CAPABILITY_SEARCH: &str = "capability_search";
pub const FN_CAPABILITY_DESCRIBE: &str = "capability_describe";
pub const FN_CAPABILITY_INVOKE: &str = "capability_invoke";
pub const FN_APP_DISCOVER: &str = "app_discover";
pub const FN_RESOURCE_RESOLVE: &str = "resource_resolve";
pub const FN_TASK_VERIFY: &str = "task_verify";

/// Hard upper bound on Round-0 serialized OpenAI `tools` JSON bytes (`<= 6,800 B`,
/// `> 56%` drop vs `15,672 B` Quick-Chat baseline and `> 82%` drop vs `38,351 B` Core L2 baseline).
pub const MAX_INITIAL_OPENAI_TOOLS_BYTES: usize = 6_800;

/// Normalize either underscored function name (`capability_search`) or dotted canonical ID
/// (`capability.search`) to its canonical meta-tool ID.
pub fn normalize_meta_tool_id(name: &str) -> Option<&'static str> {
    match name.trim() {
        META_CAPABILITY_SEARCH | FN_CAPABILITY_SEARCH => Some(META_CAPABILITY_SEARCH),
        META_CAPABILITY_DESCRIBE | FN_CAPABILITY_DESCRIBE => Some(META_CAPABILITY_DESCRIBE),
        META_CAPABILITY_INVOKE | FN_CAPABILITY_INVOKE => Some(META_CAPABILITY_INVOKE),
        META_APP_DISCOVER | FN_APP_DISCOVER => Some(META_APP_DISCOVER),
        META_RESOURCE_RESOLVE | FN_RESOURCE_RESOLVE => Some(META_RESOURCE_RESOLVE),
        META_TASK_VERIFY | FN_TASK_VERIFY => Some(META_TASK_VERIFY),
        _ => None,
    }
}

/// Map canonical or underscored meta-tool identifier to its underscored LLM function name.
pub fn meta_tool_fn_name(name: &str) -> Option<&'static str> {
    match normalize_meta_tool_id(name)? {
        META_CAPABILITY_SEARCH => Some(FN_CAPABILITY_SEARCH),
        META_CAPABILITY_DESCRIBE => Some(FN_CAPABILITY_DESCRIBE),
        META_CAPABILITY_INVOKE => Some(FN_CAPABILITY_INVOKE),
        META_APP_DISCOVER => Some(FN_APP_DISCOVER),
        META_RESOURCE_RESOLVE => Some(FN_RESOURCE_RESOLVE),
        META_TASK_VERIFY => Some(FN_TASK_VERIFY),
        _ => None,
    }
}

/// Returns `true` if `name` matches any of the 6 canonical meta-tools (underscored or dotted).
pub fn is_meta_tool(name: &str) -> bool {
    normalize_meta_tool_id(name).is_some()
}

/// Returns `true` if `name` is a pure schema-discovery meta-tool (`capability.search` / `capability.describe`)
/// that does not itself execute a domain goal step.
pub fn is_discovery_only_meta_tool(name: &str) -> bool {
    matches!(
        normalize_meta_tool_id(name),
        Some(META_CAPABILITY_SEARCH | META_CAPABILITY_DESCRIBE)
    )
}

/// Build the 6 canonical compact `ToolSpec`s respecting [`PrivacySessionPolicy`].
pub fn meta_tool_specs(privacy: PrivacySessionPolicy) -> Vec<ToolSpec> {
    let resolve_desc = if privacy.allows_memory_read() {
        "解析自然语言指代的文件/文档/软件/项目为结构化候选(多匹配时返回消歧提示)"
    } else {
        "解析授权目录内的文件/软件/项目指代(无痕隔离态不读取个人记忆)"
    };

    vec![
        ToolSpec {
            name: FN_CAPABILITY_SEARCH.to_string(),
            description: "检索系统能力与软件能力目录摘要并动态解锁匹配工具".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "domain": { "type": "string" },
                    "max_effect": { "type": "string" },
                    "include_apps": { "type": "boolean" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 15 }
                },
                "required": ["query"]
            }),
        },
        ToolSpec {
            name: FN_CAPABILITY_DESCRIBE.to_string(),
            description: "查看指定能力的完整参数Schema、权限等级、幂等与撤销语义并解锁本轮调用"
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "capability_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "maxItems": 8
                    }
                },
                "required": ["capability_ids"]
            }),
        },
        ToolSpec {
            name: FN_CAPABILITY_INVOKE.to_string(),
            description: "按规范capability_id经CapabilityBroker安全策略与审计账本执行已注册能力"
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "capability_id": { "type": "string" },
                    "arguments": { "type": "object" }
                },
                "required": ["capability_id", "arguments"]
            }),
        },
        ToolSpec {
            name: FN_APP_DISCOVER.to_string(),
            description: "发现本机软件及可用转译通道(CLI/MPRIS/托盘SNI/无头文档API/AT-SPI)"
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "live_probe": { "type": "boolean" }
                },
                "required": ["query"]
            }),
        },
        ToolSpec {
            name: FN_RESOURCE_RESOLVE.to_string(),
            description: resolve_desc.to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "kind": {
                        "type": "string",
                        "enum": ["file", "document", "app", "project", "any"]
                    }
                },
                "required": ["query"]
            }),
        },
        ToolSpec {
            name: FN_TASK_VERIFY.to_string(),
            description: "校验主机真实状态(授权路径文件存在/非空/进程与账本已验证步骤)".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "goal": { "type": "string" },
                    "expected_files": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "expected_apps": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "check_ledger": { "type": "boolean" }
                },
                "required": ["goal"]
            }),
        },
    ]
}

fn specs_to_openai_values(specs: &[ToolSpec]) -> Vec<Value> {
    specs
        .iter()
        .map(|s| {
            json!({
                "type": "function",
                "function": {
                    "name": s.name,
                    "description": s.description,
                    "parameters": s.parameters,
                }
            })
        })
        .collect()
}

/// Pre-cached OpenAI function schema `Value`s for the 6 meta-tools (`< 5 µs` warm).
pub fn meta_tool_openai_schemas(privacy: PrivacySessionPolicy) -> Vec<Value> {
    static STANDARD_META_OPENAI: OnceLock<Vec<Value>> = OnceLock::new();
    static ISOLATED_META_OPENAI: OnceLock<Vec<Value>> = OnceLock::new();

    if privacy.allows_memory_read() {
        STANDARD_META_OPENAI
            .get_or_init(|| {
                specs_to_openai_values(&meta_tool_specs(PrivacySessionPolicy::Standard))
            })
            .clone()
    } else {
        ISOLATED_META_OPENAI
            .get_or_init(|| {
                specs_to_openai_values(&meta_tool_specs(PrivacySessionPolicy::StrictIsolated))
            })
            .clone()
    }
}

fn compact_description_text(raw: &str, max_chars: usize) -> String {
    let first_line = raw.lines().next().unwrap_or("").trim();
    let base = first_line
        .split(['（', '(', '。', '；'])
        .next()
        .unwrap_or(first_line)
        .trim();
    let target = if base.is_empty() { first_line } else { base };
    target.chars().take(max_chars).collect()
}

fn compact_json_property_schema(prop: &Value) -> Value {
    let Some(obj) = prop.as_object() else {
        return json!({});
    };
    let mut out = Map::new();
    if let Some(ty) = obj.get("type") {
        out.insert("type".to_string(), ty.clone());
    }
    if let Some(en) = obj.get("enum").and_then(Value::as_array)
        && en.len() <= 8
    {
        out.insert("enum".to_string(), Value::Array(en.clone()));
    }
    if let Some(items) = obj.get("items") {
        if let Some(item_ty) = items.get("type") {
            out.insert("items".to_string(), json!({ "type": item_ty }));
        } else {
            out.insert("items".to_string(), json!({}));
        }
    }
    if let Some(min) = obj.get("minimum") {
        out.insert("minimum".to_string(), min.clone());
    }
    if let Some(max) = obj.get("maximum") {
        out.insert("maximum".to_string(), max.clone());
    }
    Value::Object(out)
}

fn compact_parameters_schema(params: &Value) -> Value {
    let Some(obj) = params.as_object() else {
        return json!({ "type": "object", "properties": {} });
    };
    let mut out = Map::new();
    out.insert(
        "type".to_string(),
        obj.get("type")
            .cloned()
            .unwrap_or_else(|| Value::String("object".to_string())),
    );
    let mut compact_props = Map::new();
    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        for (k, v) in props {
            compact_props.insert(k.clone(), compact_json_property_schema(v));
        }
    }
    out.insert("properties".to_string(), Value::Object(compact_props));
    if let Some(req) = obj.get("required").and_then(Value::as_array)
        && !req.is_empty()
    {
        out.insert("required".to_string(), Value::Array(req.clone()));
    }
    Value::Object(out)
}

/// Produce a compact Round-0 [`ToolSpec`] that preserves the exact function `name`, property names,
/// property types/bounds, and `required` list while trimming verbose multi-sentence prose.
/// Full documentation & schemas remain available via `capability.describe` and mid-turn unlocking.
pub fn compact_tool_spec_for_round0(spec: &ToolSpec) -> ToolSpec {
    ToolSpec {
        name: spec.name.clone(),
        description: compact_description_text(&spec.description, 38),
        parameters: compact_parameters_schema(&spec.parameters),
    }
}

/// Convert a [`ToolSpec`] into a compact Round-0 OpenAI function `Value`.
pub fn compact_openai_schema_from_spec(spec: &ToolSpec) -> Value {
    let c = compact_tool_spec_for_round0(spec);
    json!({
        "type": "function",
        "function": {
            "name": c.name,
            "description": c.description,
            "parameters": c.parameters,
        }
    })
}

/// Result of unwrapping a `capability.invoke` (`capability_invoke`) call before Broker execution.
#[derive(Debug, Clone)]
pub enum UnwrappedInvokeTarget {
    /// The tool call is NOT `capability.invoke`.
    NotInvoke,
    /// `capability.invoke` was rejected pre-flight (recursion attempt, missing ID, or unregistered target).
    Denied { reason: String },
    /// Validated concrete capability target and arguments ready for the real `CapabilityBroker` spine.
    Target {
        capability_id: String,
        arguments: Value,
    },
}

/// Build the complete list of dynamically discoverable & mid-turn unlockable AIOS + M2-D
/// `SoftwareCapabilityProvider` + `system.bottleneck` `ToolSpec`s (while keeping
/// `CapabilityBroker::aios_tool_specs()` at its 9 core Wave-4 tools).
pub fn discoverable_aios_and_provider_specs(broker: &CapabilityBroker) -> Vec<ToolSpec> {
    let mut specs = broker.aios_tool_specs();
    let mut seen: HashSet<String> = specs.iter().map(|s| s.name.clone()).collect();
    for pspec in provider_tool_specs() {
        if seen.insert(pspec.name.clone()) {
            specs.push(pspec);
        }
    }
    for cap in SoftwareCapabilityProvider::list_capabilities(None, None) {
        if cap.capability_id == "media.control"
            || broker.get_descriptor(&cap.capability_id).is_some()
        {
            continue;
        }
        let fn_name = cap.capability_id.replace('.', "_");
        if seen.insert(fn_name.clone()) {
            specs.push(ToolSpec {
                name: fn_name,
                description: cap.summary,
                parameters: cap.input_schema,
            });
        }
    }
    if seen.insert("system_bottleneck".to_string()) {
        specs.push(ToolSpec {
            name: "system_bottleneck".to_string(),
            description: "只读采样 /proc 内存压力、CPU 负载、Swap 抖动、磁盘空间与高占用进程瓶颈诊断（绝不自动杀进程）".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 25 }
                }
            }),
        });
    }
    specs
}

/// Resolve a concrete capability or AIOS tool identifier registered on `broker` / `snap`.
pub fn resolve_registered_concrete_capability(
    raw_id: &str,
    snap: &CapabilitySnapshot,
    broker: &CapabilityBroker,
) -> Option<String> {
    let trimmed = raw_id.trim();
    if trimmed.is_empty() || is_meta_tool(trimmed) {
        return None;
    }
    if let Some(cid) = snap.resolve_canonical_id(trimmed) {
        return Some(cid.to_string());
    }
    let dotted = trimmed.replace('_', ".");
    if let Some(d) = broker.get_descriptor(&dotted) {
        return Some(d.id.clone());
    }
    if crate::diagnostics::is_diagnostic_capability(trimmed) {
        return Some(dotted);
    }
    let underscored = trimmed.replace('.', "_");
    if is_memory_tool(trimmed) || is_adapter_tool(trimmed) {
        return Some(underscored);
    }
    for spec in discoverable_aios_and_provider_specs(broker) {
        if spec.name == trimmed || spec.name == underscored || spec.name.replace('_', ".") == dotted
        {
            return Some(spec.name);
        }
    }
    None
}

/// Unwrap and validate `capability.invoke` (`capability_invoke`), strictly blocking recursive
/// `capability.invoke` -> `capability.invoke` (or any meta-tool) and unregistered capability IDs.
pub fn unwrap_capability_invoke(
    core: &IntentOsCore,
    fn_or_cap_name: &str,
    raw_args: &Value,
) -> UnwrappedInvokeTarget {
    if normalize_meta_tool_id(fn_or_cap_name) != Some(META_CAPABILITY_INVOKE) {
        return UnwrappedInvokeTarget::NotInvoke;
    }

    let Some(obj) = raw_args.as_object() else {
        return UnwrappedInvokeTarget::Denied {
            reason: "安全拒绝：capability.invoke 参数必须是 JSON 对象".to_string(),
        };
    };

    let target_raw = obj
        .get("capability_id")
        .or_else(|| obj.get("id"))
        .or_else(|| obj.get("tool_name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");

    if target_raw.is_empty() {
        return UnwrappedInvokeTarget::Denied {
            reason: "安全拒绝：capability.invoke 缺少必填参数 capability_id".to_string(),
        };
    }

    if is_meta_tool(target_raw) {
        return UnwrappedInvokeTarget::Denied {
            reason: format!(
                "安全拒绝：严禁通过 capability.invoke 递归或间接调用元工具 '{}'",
                target_raw
            ),
        };
    }

    let snap = capability_snapshot_for_core(core);
    let Some(canonical_target) =
        resolve_registered_concrete_capability(target_raw, &snap, &core.broker)
    else {
        return UnwrappedInvokeTarget::Denied {
            reason: format!(
                "安全拒绝：能力 '{}' 未在 CapabilityBroker 注册，请先通过 capability.search 检索有效能力 ID",
                target_raw
            ),
        };
    };

    let inner_args = match obj.get("arguments") {
        None | Some(Value::Null) => json!({}),
        Some(v @ Value::Object(_)) => v.clone(),
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(v @ Value::Object(_)) => v,
            _ => {
                return UnwrappedInvokeTarget::Denied {
                    reason: "安全拒绝：capability.invoke 的 arguments 字符串未能解析为 JSON 对象"
                        .to_string(),
                };
            }
        },
        Some(_) => {
            return UnwrappedInvokeTarget::Denied {
                reason: "安全拒绝：capability.invoke 的 arguments 字段必须是 JSON 对象".to_string(),
            };
        }
    };

    UnwrappedInvokeTarget::Target {
        capability_id: canonical_target,
        arguments: inner_args,
    }
}

/// Extract inner `arguments` when `fn_name` is `capability_invoke`, otherwise return `parsed_args` as-is.
/// Used when saving `SuspendedTurnCheckpoint.paused_parsed_args` so approval resumption records the real
/// target capability's arguments cleanly.
pub fn effective_checkpoint_tool_args(fn_name: &str, parsed_args: &Value) -> Value {
    if normalize_meta_tool_id(fn_name) == Some(META_CAPABILITY_INVOKE)
        && let Some(inner) = parsed_args.get("arguments")
    {
        if inner.is_object() {
            return inner.clone();
        }
        if let Some(s) = inner.as_str()
            && let Ok(v @ Value::Object(_)) = serde_json::from_str::<Value>(s)
        {
            return v;
        }
    }
    parsed_args.clone()
}

fn parse_effect_filter(raw: &str) -> Option<Effect> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "observe" | "read" | "readonly" | "read_only" | "r0" => Some(Effect::Observe),
        "ui" => Some(Effect::Ui),
        "setting" | "settings" | "r1" => Some(Effect::Setting),
        "exec.sandboxed" | "exec_sandboxed" | "sandboxed" => Some(Effect::ExecSandboxed),
        "write.reversible" | "write_reversible" | "write_scoped" | "write" | "r2" => {
            Some(Effect::WriteReversible)
        }
        "egress" | "network" | "net" => Some(Effect::Egress),
        "process.control" | "process_control" | "process" => Some(Effect::ProcessControl),
        "write.destructive" | "write_destructive" | "destructive" => Some(Effect::WriteDestructive),
        "external.commit" | "external_commit" => Some(Effect::ExternalCommit),
        "system.admin" | "system_admin" | "system_exec" | "exec" | "r3" => {
            Some(Effect::SystemAdmin)
        }
        _ => None,
    }
}

fn infer_aios_tool_domain_and_effect(name: &str) -> (&'static str, Effect, bool) {
    let dotted = name.trim().replace('_', ".");
    match dotted.as_str() {
        "document.replace.section" => return ("document", Effect::WriteReversible, true),
        "document.compile.bibliography" => return ("bibliography", Effect::WriteReversible, true),
        "document.convert.headless" => return ("document", Effect::WriteReversible, true),
        "document.read.section" | "document.inspect.format" | "pdf.extract.text" => {
            return ("document", Effect::Observe, true);
        }
        "workspace.organize.apply" => return ("workspace", Effect::WriteReversible, true),
        "workspace.organize.plan" | "cloud.rclone.status" => {
            return ("workspace", Effect::Observe, true);
        }
        "git.inspect.repo" => return ("vcs", Effect::Observe, true),
        "ide.goto.or.diff" | "file.manager.reveal" => return ("desktop_gui", Effect::Ui, true),
        "gui.semantic.inspect" => return ("desktop_gui", Effect::Observe, true),
        "closed.app.internal.action" => return ("closed_app", Effect::Observe, true),
        "system.bottleneck" => return ("diagnostics", Effect::Observe, true),
        "app.provider.execute" => return ("software_provider", Effect::WriteReversible, true),
        "app.provider.capabilities" => return ("software_provider", Effect::Observe, true),
        _ => {}
    }
    if is_memory_write_tool(name) {
        ("memory", Effect::Setting, false)
    } else if is_memory_tool(name) {
        ("memory", Effect::Observe, false)
    } else if name == "app_adapter_invoke" || name == "app_adapter.invoke" {
        ("app_adapter", Effect::Ui, false)
    } else if is_adapter_tool(name) {
        ("app_adapter", Effect::Observe, false)
    } else if name.starts_with("doc") || name.contains("docx") || name.contains("document") {
        ("document", Effect::WriteReversible, true)
    } else if name.starts_with("bib") || name.contains("bibliography") {
        ("bibliography", Effect::WriteReversible, true)
    } else if name.starts_with("diag") || name.starts_with("repair") {
        ("diagnostics", Effect::Observe, false)
    } else {
        ("software_provider", Effect::Observe, false)
    }
}

fn permission_tier_for_effect(effect: Effect) -> &'static str {
    match effect {
        Effect::Observe => "auto_allow_scoped",
        Effect::Ui => "scoped_ui_or_approval",
        Effect::Setting => "auto_allow_reversible_setting",
        Effect::ExecSandboxed | Effect::WriteReversible => "authorized_workspace_or_approval",
        Effect::Egress => "egress_policy_gated",
        Effect::ProcessControl
        | Effect::WriteDestructive
        | Effect::ExternalCommit
        | Effect::SystemAdmin => "explicit_user_approval",
    }
}

fn undo_strategy_label(undo: &UndoStrategy) -> &'static str {
    match undo {
        UndoStrategy::None => "none",
        UndoStrategy::Changeset => "changeset",
        UndoStrategy::RestorePreviousValue => "restore_previous_value",
    }
}

/// Execute one of the 5 non-`invoke` meta-tools (`capability.search`, `capability.describe`,
/// `app.discover`, `resource.resolve`, `task.verify`), scrubbing outputs through [`SensitiveDataGuard`].
#[allow(clippy::too_many_arguments)]
pub async fn execute_non_invoke_meta_tool(
    core: &IntentOsCore,
    canonical_meta_id: &str,
    request_id: &str,
    session: Option<&SessionState>,
    session_id: &str,
    privacy: PrivacySessionPolicy,
    args: &Value,
    effect_ledger: &TurnEffectLedger,
) -> CapabilityResult {
    let started = Instant::now();
    let (status, message, mut data, method, checks) = match canonical_meta_id {
        META_CAPABILITY_SEARCH => execute_capability_search(core, privacy, args),
        META_CAPABILITY_DESCRIBE => execute_capability_describe(core, privacy, args),
        META_APP_DISCOVER => execute_app_discover(core, args).await,
        META_RESOURCE_RESOLVE => {
            execute_resource_resolve(core, session, session_id, privacy, args, effect_ledger)
        }
        META_TASK_VERIFY => execute_task_verify(core, session_id, args, effect_ledger),
        other => (
            ExecutionStatus::VerificationFailed,
            format!("未知元工具: {}", other),
            json!({ "error": format!("unknown meta-tool: {}", other) }),
            "meta_tool_dispatch",
            vec!["unknown_meta_tool".to_string()],
        ),
    };

    SensitiveDataGuard::redact_json(&mut data);
    let duration_ms = started.elapsed().as_millis() as u64;
    let verif_state = if status == ExecutionStatus::Exited {
        VerificationState::Passed
    } else {
        VerificationState::VerificationFailed
    };

    CapabilityResult {
        request_id: request_id.to_string(),
        capability_id: canonical_meta_id.to_string(),
        status,
        exit_code: Some(if status == ExecutionStatus::Exited {
            0
        } else {
            1
        }),
        message: SensitiveDataGuard::redact_text(&message).0,
        data,
        stdout_preview: String::new(),
        stderr_preview: String::new(),
        truncated: false,
        duration_ms,
        changeset_id: None,
        verification: VerificationReport {
            state: verif_state,
            method: method.to_string(),
            checks,
            details: None,
        },
        backend_mode: "meta_tools".to_string(),
    }
}

fn execute_capability_search(
    core: &IntentOsCore,
    privacy: PrivacySessionPolicy,
    args: &Value,
) -> (ExecutionStatus, String, Value, &'static str, Vec<String>) {
    let snap = capability_snapshot_for_core(core);
    let raw_query = args
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let effective_query = if raw_query == "*" || raw_query.eq_ignore_ascii_case("all") {
        ""
    } else {
        raw_query
    };
    let domain_filter = args
        .get("domain")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "*" && !s.eq_ignore_ascii_case("all"));
    let max_effect = args
        .get("max_effect")
        .and_then(Value::as_str)
        .and_then(parse_effect_filter);
    let include_apps = args
        .get("include_apps")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, 15) as usize;

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut entries: Vec<(f64, Value, Option<String>)> = Vec::new();

    // 1. Search registered YAML capabilities in `CapabilitySnapshot` (zero private user data)
    let mut snap_hits = snap.search_filtered(effective_query, domain_filter, max_effect, limit * 2);
    if snap_hits.len() < limit && effective_query.contains(char::is_whitespace) {
        let mut hit_by_id: HashMap<String, usize> = snap_hits
            .iter()
            .enumerate()
            .map(|(i, h)| (h.capability_id.clone(), i))
            .collect();
        for tok in effective_query
            .split_whitespace()
            .map(str::trim)
            .filter(|t| t.chars().count() >= 2)
        {
            for sub_hit in snap.search_filtered(tok, domain_filter, max_effect, limit) {
                if let Some(&idx) = hit_by_id.get(&sub_hit.capability_id) {
                    snap_hits[idx].score += sub_hit.score * 0.5;
                } else {
                    hit_by_id.insert(sub_hit.capability_id.clone(), snap_hits.len());
                    snap_hits.push(sub_hit);
                }
            }
        }
    }

    for hit in snap_hits {
        if !privacy.allows_memory_write() && is_memory_write_tool(&hit.capability_id) {
            continue;
        }
        if !seen_ids.insert(hit.capability_id.clone()) {
            continue;
        }
        entries.push((
            hit.score,
            json!({
                "id": hit.capability_id,
                "tool_name": hit.tool_name,
                "summary": compact_description_text(&hit.summary, 64),
                "domain": hit.domain,
                "effect": hit.max_effect.as_str(),
                "reversible": hit.undoable,
                "availability": "available",
            }),
            Some(hit.capability_id),
        ));
    }

    // 2. Search registered AIOS / Provider `ToolSpec`s (memory_hub, app_adapter, SoftwareCapabilityProvider)
    let provider_caps_map: HashMap<String, crate::app_adapter::ProviderCapabilitySpec> =
        SoftwareCapabilityProvider::list_capabilities(None, None)
            .into_iter()
            .map(|c| (c.capability_id.replace('.', "_"), c))
            .collect();
    let q_lc = effective_query.to_lowercase();
    let q_tokens: Vec<&str> = q_lc.split_whitespace().filter(|t| !t.is_empty()).collect();
    for spec in discoverable_aios_and_provider_specs(&core.broker) {
        if !privacy.allows_memory_read() && is_memory_tool(&spec.name) {
            continue;
        }
        if !privacy.allows_memory_write() && is_memory_write_tool(&spec.name) {
            continue;
        }
        if !include_apps
            && is_adapter_tool(&spec.name)
            && !provider_caps_map.contains_key(&spec.name)
        {
            continue;
        }
        let prov_meta = provider_caps_map.get(&spec.name);
        let (dom, eff, reversible) = if let Some(pm) = prov_meta {
            (pm.domain.as_str(), pm.effect, pm.reversible)
        } else {
            infer_aios_tool_domain_and_effect(&spec.name)
        };
        if let Some(df) = domain_filter
            && !dom.eq_ignore_ascii_case(df)
            && !spec
                .name
                .to_ascii_lowercase()
                .contains(&df.to_ascii_lowercase())
        {
            continue;
        }
        if let Some(me) = max_effect
            && eff > me
        {
            continue;
        }
        let canonical_id = prov_meta
            .map(|pm| pm.capability_id.clone())
            .unwrap_or_else(|| spec.name.clone());
        let name_lc = spec.name.to_lowercase();
        let cid_lc = canonical_id.to_lowercase();
        let desc_lc = spec.description.to_lowercase();
        let mut sc = 0.0;
        if q_lc.is_empty() {
            sc = 15.0;
        } else {
            if name_lc == q_lc || cid_lc == q_lc || name_lc.replace('_', ".") == q_lc {
                sc += 115.0;
            } else if name_lc.contains(&q_lc) || cid_lc.contains(&q_lc) {
                sc += 75.0;
            }
            if desc_lc.contains(&q_lc) {
                sc += 48.0;
            }
            for tok in &q_tokens {
                if name_lc.contains(tok) || cid_lc.contains(tok) {
                    sc += 34.0;
                } else if desc_lc.contains(tok) {
                    sc += 20.0;
                }
            }
        }
        let availability_str = prov_meta
            .map(|pm| match pm.availability.state {
                crate::app_adapter::AvailabilityState::Available => "available",
                crate::app_adapter::AvailabilityState::DegradedGuidanceOnly => {
                    "degraded_guidance_only"
                }
                crate::app_adapter::AvailabilityState::Unavailable => "unavailable",
            })
            .unwrap_or("available");
        if sc > 0.0 && seen_ids.insert(canonical_id.clone()) {
            seen_ids.insert(spec.name.clone());
            entries.push((
                sc,
                json!({
                    "id": canonical_id,
                    "tool_name": spec.name.replace('.', "_"),
                    "summary": compact_description_text(&spec.description, 64),
                    "domain": dom,
                    "effect": eff.as_str(),
                    "reversible": reversible,
                    "availability": availability_str,
                }),
                Some(canonical_id),
            ));
        }
    }

    // 3. Search declarative built-in `AdapterRegistry` software capabilities (strictly built-in profiles only,
    //    zero user custom file paths or personal memory!)
    if include_apps
        && max_effect.is_none_or(|me| me >= Effect::Ui)
        && domain_filter.is_none_or(|df| {
            let dlc = df.to_ascii_lowercase();
            matches!(
                dlc.as_str(),
                "app"
                    | "apps"
                    | "app_adapter"
                    | "adapter"
                    | "software"
                    | "media"
                    | "office"
                    | "dev"
            )
        })
    {
        let reg = AdapterRegistry::builtin_only();
        let prof_q = if effective_query.is_empty() {
            None
        } else {
            Some(effective_query)
        };
        for prof in reg.list_filtered(prof_q, None, None).into_iter().take(4) {
            let entry_id = format!("app_adapter:{}", prof.id);
            if !seen_ids.insert(entry_id.clone()) {
                continue;
            }
            let actions_preview: Vec<&str> = prof
                .supported_actions
                .iter()
                .take(4)
                .map(|a| a.action.as_str())
                .collect();
            let unlock_target =
                if privacy.allows_memory_write() || !is_memory_write_tool("app_adapter_invoke") {
                    Some("app_adapter_invoke".to_string())
                } else {
                    None
                };
            entries.push((
                42.0,
                json!({
                    "id": entry_id,
                    "tool_name": "app_adapter_invoke",
                    "summary": format!("{} ({}): 支持动作 {}", prof.name, prof.category, actions_preview.join("/")),
                    "domain": "app_adapter",
                    "effect": Effect::Ui.as_str(),
                    "reversible": false,
                    "availability": "available_via_adapter",
                }),
                unlock_target,
            ));
        }
    }

    entries.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    entries.truncate(limit);

    let mut unlocked_capability_ids: Vec<String> = Vec::new();
    let mut results: Vec<Value> = Vec::with_capacity(entries.len());
    for (_, val, maybe_unlock) in entries {
        if let Some(uid) = maybe_unlock
            && unlocked_capability_ids.len() < 5
            && !unlocked_capability_ids.contains(&uid)
        {
            unlocked_capability_ids.push(uid);
        }
        results.push(val);
    }

    let msg = format!(
        "capability.search 检索到 {} 项匹配能力 (snapshot v{})",
        results.len(),
        snap.version
    );
    let data = json!({
        "snapshot_version": snap.version,
        "snapshot_fingerprint": format!("{:016x}", snap.fingerprint),
        "query": raw_query,
        "count": results.len(),
        "results": results,
        "unlocked_capability_ids": unlocked_capability_ids,
    });
    (
        ExecutionStatus::Exited,
        msg,
        data,
        "capability_snapshot_search",
        vec![
            "catalog_searched".to_string(),
            "zero_private_data".to_string(),
        ],
    )
}

fn describe_yaml_capability(desc: &CapabilityDescriptor, spec: &ToolSpec) -> Value {
    let max_eff = desc.max_effect();
    let idem = classify_capability_idempotency(&desc.id, max_eff, &json!({}));
    let undoable = !matches!(desc.undo, UndoStrategy::None);
    let domain = desc.id.split('.').next().unwrap_or(&desc.category);
    let verif_method = desc
        .verification
        .as_ref()
        .map(|v| v.kind.as_str())
        .unwrap_or("runtime_status");
    let verif_tolerance = desc.verification.as_ref().and_then(|v| v.tolerance);

    json!({
        "id": desc.id,
        "version": desc.version,
        "tool_name": spec.name,
        "summary": desc.summary,
        "description": spec.description,
        "domain": domain,
        "category": desc.category,
        "effect": max_eff.as_str(),
        "effects": desc.effects.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
        "permission_tier": permission_tier_for_effect(max_eff),
        "idempotency_policy": idem,
        "idempotent_descriptor": desc.idempotent,
        "reversible": undoable,
        "undo_semantics": {
            "undoable": undoable,
            "strategy": undo_strategy_label(&desc.undo),
            "creates_changeset": undoable,
        },
        "input_schema": spec.parameters,
        "output_semantics": {
            "envelope": "{ message: string, data: object, exec_state?: string, was_denied?: bool }",
            "verification_method": verif_method,
            "verification_tolerance": verif_tolerance,
        },
        "availability": "available",
    })
}

fn execute_capability_describe(
    core: &IntentOsCore,
    privacy: PrivacySessionPolicy,
    args: &Value,
) -> (ExecutionStatus, String, Value, &'static str, Vec<String>) {
    let snap = capability_snapshot_for_core(core);
    let mut requested: Vec<String> = args
        .get("capability_ids")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    if requested.is_empty()
        && let Some(single) = args
            .get("capability_id")
            .or_else(|| args.get("id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    {
        requested.push(single.to_string());
    }

    let mut deduped: Vec<String> = Vec::new();
    for r in requested {
        if deduped.len() >= 8 {
            break;
        }
        if !deduped.contains(&r) {
            deduped.push(r);
        }
    }

    let aios_specs = discoverable_aios_and_provider_specs(&core.broker);
    let provider_caps = SoftwareCapabilityProvider::list_capabilities(None, None);
    let meta_specs = meta_tool_specs(privacy);
    let mut described: Vec<Value> = Vec::new();
    let mut not_found: Vec<String> = Vec::new();
    let mut unlocked_capability_ids: Vec<String> = Vec::new();

    for req_id in &deduped {
        if let Some(app_suffix) = req_id.strip_prefix("app_adapter:") {
            let reg = AdapterRegistry::builtin_only();
            if let Some(prof) = reg.get_by_id(app_suffix).cloned().or_else(|| {
                reg.list_filtered(Some(app_suffix), None, None)
                    .into_iter()
                    .next()
            }) {
                let actions: Vec<Value> = prof
                    .supported_actions
                    .iter()
                    .map(|a| {
                        json!({
                            "intent_action": a.action,
                            "channel": format!("{:?}", a.channel),
                            "description": a.summary,
                            "requires_approval": a.requires_approval,
                            "reversible": a.reversible,
                        })
                    })
                    .collect();
                let idem =
                    classify_capability_idempotency("app_adapter_invoke", Effect::Ui, &json!({}));
                described.push(json!({
                    "id": req_id,
                    "tool_name": "app_adapter_invoke",
                    "summary": format!("{} 转译器能力档案", prof.name),
                    "domain": "app_adapter",
                    "effect": Effect::Ui.as_str(),
                    "permission_tier": permission_tier_for_effect(Effect::Ui),
                    "idempotency_policy": idem,
                    "reversible": false,
                    "actions": actions,
                    "availability": "available_via_adapter",
                }));
                if !unlocked_capability_ids.contains(&"app_adapter_invoke".to_string()) {
                    unlocked_capability_ids.push("app_adapter_invoke".to_string());
                }
                continue;
            }
        }

        if let Some(desc) = snap.get_descriptor(req_id)
            && let Some(spec) = snap.get_tool_spec(&desc.id)
        {
            if !privacy.allows_memory_write() && is_memory_write_tool(&desc.id) {
                described.push(json!({
                    "id": desc.id,
                    "tool_name": spec.name,
                    "availability": "denied_by_privacy_policy",
                    "reason": format!("当前会话隐私策略 ({}) 禁止记忆写入类能力", privacy.as_str()),
                }));
                continue;
            }
            described.push(describe_yaml_capability(desc, spec));
            if !unlocked_capability_ids.contains(&desc.id) {
                unlocked_capability_ids.push(desc.id.clone());
            }
            continue;
        }

        let norm_us = req_id.replace('.', "_");
        let norm_dot = req_id.replace('_', ".");
        if let Some(pcap) = provider_caps.iter().find(|c| {
            c.capability_id == *req_id
                || c.capability_id.replace('.', "_") == norm_us
                || c.capability_id.replace('_', ".") == norm_dot
        }) {
            let idem =
                classify_capability_idempotency(&pcap.capability_id, pcap.effect, &json!({}));
            described.push(json!({
                "id": pcap.capability_id,
                "version": 1,
                "tool_name": pcap.capability_id.replace('.', "_"),
                "summary": compact_description_text(&pcap.summary, 80),
                "description": pcap.summary,
                "domain": pcap.domain,
                "category": pcap.domain,
                "channels": pcap.channels,
                "effect": pcap.effect.as_str(),
                "effects": [pcap.effect.as_str()],
                "permission_tier": permission_tier_for_effect(pcap.effect),
                "requires_approval": pcap.requires_approval,
                "idempotency_policy": idem,
                "reversible": pcap.reversible,
                "preconditions": pcap.preconditions,
                "undo_semantics": {
                    "undoable": pcap.reversible,
                    "strategy": if pcap.reversible && pcap.effect > Effect::Observe { "changeset" } else { "none" },
                    "creates_changeset": pcap.reversible && pcap.effect > Effect::Observe,
                },
                "input_schema": pcap.input_schema,
                "output_semantics": {
                    "envelope": "{ message: string, data: object }",
                    "verification_method": pcap.verification_method,
                },
                "availability": pcap.availability,
            }));
            if !unlocked_capability_ids.contains(&pcap.capability_id) {
                unlocked_capability_ids.push(pcap.capability_id.clone());
            }
            continue;
        }

        if let Some(spec) = aios_specs.iter().find(|s| {
            s.name == *req_id || s.name == norm_us || s.name.replace('_', ".") == norm_dot
        }) {
            if (!privacy.allows_memory_read() && is_memory_tool(&spec.name))
                || (!privacy.allows_memory_write() && is_memory_write_tool(&spec.name))
            {
                described.push(json!({
                    "id": spec.name,
                    "tool_name": spec.name.replace('.', "_"),
                    "availability": "denied_by_privacy_policy",
                    "reason": format!("当前会话隐私策略 ({}) 限制访问该工具", privacy.as_str()),
                }));
                continue;
            }
            let (dom, eff, rev) = infer_aios_tool_domain_and_effect(&spec.name);
            let idem = classify_capability_idempotency(&spec.name, eff, &json!({}));
            described.push(json!({
                "id": spec.name,
                "version": 1,
                "tool_name": spec.name.replace('.', "_"),
                "summary": compact_description_text(&spec.description, 80),
                "description": spec.description,
                "domain": dom,
                "category": dom,
                "effect": eff.as_str(),
                "effects": [eff.as_str()],
                "permission_tier": permission_tier_for_effect(eff),
                "idempotency_policy": idem,
                "reversible": rev,
                "undo_semantics": {
                    "undoable": rev,
                    "strategy": if rev { "backup_file" } else { "none" },
                    "creates_changeset": rev,
                },
                "input_schema": spec.parameters,
                "output_semantics": {
                    "envelope": "{ message: string, data: object }",
                    "verification_method": "provider_post_check",
                },
                "availability": "available",
            }));
            if !unlocked_capability_ids.contains(&spec.name) {
                unlocked_capability_ids.push(spec.name.clone());
            }
            continue;
        }

        if let Some(canon_meta) = normalize_meta_tool_id(req_id)
            && let Some(fn_meta) = meta_tool_fn_name(canon_meta)
            && let Some(mspec) = meta_specs.iter().find(|m| m.name == fn_meta)
        {
            described.push(json!({
                "id": canon_meta,
                "version": 1,
                "tool_name": mspec.name,
                "summary": mspec.description,
                "description": mspec.description,
                "domain": "meta",
                "effect": Effect::Observe.as_str(),
                "permission_tier": "meta_protocol",
                "reversible": false,
                "input_schema": mspec.parameters,
                "availability": "always_exposed",
            }));
            continue;
        }

        not_found.push(req_id.clone());
    }

    let msg = format!(
        "已返回 {} 项能力的完整 Schema 描述并解锁 {} 项工具",
        described.len(),
        unlocked_capability_ids.len()
    );
    let data = json!({
        "snapshot_version": snap.version,
        "capabilities": described,
        "not_found": not_found,
        "unlocked_capability_ids": unlocked_capability_ids,
    });
    (
        ExecutionStatus::Exited,
        msg,
        data,
        "capability_snapshot_describe",
        vec!["schemas_described".to_string()],
    )
}

async fn execute_app_discover(
    core: &IntentOsCore,
    args: &Value,
) -> (ExecutionStatus, String, Value, &'static str, Vec<String>) {
    let raw_query = args
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let live_probe = args
        .get("live_probe")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_wildcard =
        raw_query.is_empty() || raw_query == "*" || raw_query.eq_ignore_ascii_case("all");

    let installed_apps: Vec<Value> = if is_wildcard {
        Vec::new()
    } else {
        core.resources
            .search_apps(raw_query, 8)
            .into_iter()
            .map(|(rec, sc)| {
                json!({
                    "app_id": rec.app_id,
                    "name": rec.name,
                    "generic_name": rec.generic_name,
                    "exec_cmd": rec.exec_cmd,
                    "keywords": rec.keywords,
                    "score": (sc * 100.0).round() / 100.0,
                })
            })
            .collect()
    };

    let reg = AdapterRegistry::load(Some(&core.paths.config_dir));
    let filter_q = if is_wildcard { None } else { Some(raw_query) };
    let adapter_profiles: Vec<Value> = reg
        .list_filtered(filter_q, None, None)
        .into_iter()
        .take(8)
        .map(|prof| {
            let channels: Vec<String> = prof.channels.iter().map(|c| format!("{:?}", c)).collect();
            let actions: Vec<Value> = prof
                .supported_actions
                .iter()
                .take(8)
                .map(|a| {
                    json!({
                        "intent_action": a.action,
                        "channel": format!("{:?}", a.channel),
                        "requires_approval": a.requires_approval,
                        "reversible": a.reversible,
                        "description": compact_description_text(&a.summary, 52),
                    })
                })
                .collect();
            json!({
                "app_id": prof.id,
                "display_name": prof.name,
                "category": prof.category,
                "channels": channels,
                "actions": actions,
            })
        })
        .collect();

    let scan_catalog = deep_scan_local_software(
        Some(&core.paths.config_dir),
        &reg,
        &LocalScanOptions {
            query: filter_q.map(String::from),
            ..Default::default()
        },
    )
    .await;
    let scanned_software: Vec<Value> = scan_catalog
        .apps
        .into_iter()
        .take(8)
        .map(|entry| {
            json!({
                "app_id": entry.id,
                "desktop_id": entry.desktop_id,
                "name": entry.name,
                "category": entry.category,
                "install_source": entry.install_source,
                "is_running": entry.is_running,
                "supported_channels": entry.channels,
            })
        })
        .collect();

    let live_inspection: Option<Value> = if live_probe && !is_wildcard {
        Some(match inspect_live_app(core, raw_query).await {
            Ok(v) => v,
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        })
    } else {
        None
    };

    let msg = format!(
        "app.discover 发现 {} 个桌面入口、{} 个转译档案、{} 项本机扫描软件",
        installed_apps.len(),
        adapter_profiles.len(),
        scanned_software.len()
    );
    let data = json!({
        "query": raw_query,
        "live_probe": live_probe,
        "installed_apps": installed_apps,
        "adapter_profiles": adapter_profiles,
        "scanned_software": scanned_software,
        "live_inspection": live_inspection,
        "supported_channels_architecture": [
            "cli_headless",
            "mpris2_dbus",
            "sni_dbusmenu_tray",
            "uri_desktop_action",
            "document_provider_api",
            "atspi2_gui_bridge"
        ],
    });
    (
        ExecutionStatus::Exited,
        msg,
        data,
        "app_discover_scan",
        vec!["desktop_and_adapter_scanned".to_string()],
    )
}

fn extract_clean_resource_query(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    for prefix in [
        "帮我打开",
        "帮我查看",
        "帮我找",
        "请打开",
        "打开我的",
        "查看我的",
        "之前提到的",
        "上次提到的",
        "刚才提到的",
        "我的",
        "那个",
        "这个",
        "打开",
        "查看",
        "检索",
        "查找",
    ] {
        if let Some(rest) = s.strip_prefix(prefix)
            && !rest.trim().is_empty()
        {
            s = rest.trim().to_string();
        }
    }
    s
}

fn is_deictic_reference(q: &str) -> bool {
    let lc = q.trim().to_lowercase();
    matches!(
        lc.as_str(),
        "它" | "这个"
            | "那个"
            | "刚才那个"
            | "刚才的文件"
            | "上面的文件"
            | "it"
            | "this"
            | "that"
    ) || lc.contains("刚才")
        || lc.contains("上面那个")
        || lc.contains("刚打开")
}

#[derive(Debug, Clone)]
struct ResolvedCandidateEntry {
    key: String,
    kind: String,
    name: String,
    path_or_id: String,
    confidence: f64,
    sources: Vec<String>,
    metadata: Value,
}

#[allow(clippy::too_many_arguments)]
fn upsert_candidate(
    list: &mut Vec<ResolvedCandidateEntry>,
    key: String,
    kind: &str,
    name: String,
    path_or_id: String,
    confidence: f64,
    source: &str,
    metadata: Value,
) {
    let clamped = confidence.clamp(0.05, 0.99);
    if let Some(existing) = list.iter_mut().find(|c| c.key == key) {
        if clamped > existing.confidence {
            existing.confidence = (clamped + 0.03).min(0.99);
        } else {
            existing.confidence = (existing.confidence + 0.02).min(0.99);
        }
        if !existing.sources.iter().any(|s| s == source) {
            existing.sources.push(source.to_string());
        }
        return;
    }
    list.push(ResolvedCandidateEntry {
        key,
        kind: kind.to_string(),
        name,
        path_or_id,
        confidence: clamped,
        sources: vec![source.to_string()],
        metadata,
    });
}

fn execute_resource_resolve(
    core: &IntentOsCore,
    session: Option<&SessionState>,
    session_id: &str,
    privacy: PrivacySessionPolicy,
    args: &Value,
    effect_ledger: &TurnEffectLedger,
) -> (ExecutionStatus, String, Value, &'static str, Vec<String>) {
    let raw_query = args
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let kind_filter = args
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("any")
        .trim()
        .to_ascii_lowercase();
    let allow_files = matches!(
        kind_filter.as_str(),
        "any" | "file" | "files" | "document" | "doc"
    );
    let allow_apps = matches!(kind_filter.as_str(), "any" | "app" | "apps" | "software");
    let allow_projects = matches!(
        kind_filter.as_str(),
        "any" | "project" | "projects" | "repo"
    );

    let clean_q = extract_clean_resource_query(raw_query);
    let search_q = if clean_q.is_empty() {
        raw_query
    } else {
        clean_q.as_str()
    };
    let deictic = is_deictic_reference(raw_query);
    let mut candidates: Vec<ResolvedCandidateEntry> = Vec::new();

    // 1. Turn & Session active resource context (`effect_ledger.last_resource_path` / `session.last_resource_path`)
    if allow_files {
        for (src_label, maybe_last) in [
            ("turn_context", effect_ledger.last_resource_path.as_deref()),
            (
                "session_context",
                session.and_then(|s| s.last_resource_path.as_deref()),
            ),
        ] {
            if let Some(last_p) = maybe_last {
                let p = Path::new(last_p);
                if !core.fs_engine.is_forbidden(p) && p.exists() {
                    let fname = p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| last_p.to_string());
                    let matches_lex = !search_q.is_empty()
                        && fname.to_lowercase().contains(&search_q.to_lowercase());
                    if deictic || matches_lex {
                        let conf = if deictic { 0.94 } else { 0.86 };
                        upsert_candidate(
                            &mut candidates,
                            format!("path:{}", last_p),
                            if p.is_dir() { "project" } else { "file" },
                            fname,
                            last_p.to_string(),
                            conf,
                            src_label,
                            json!({ "exists": true }),
                        );
                    }
                }
            }
        }
    }

    // 2. Authorized File Index (`core.resources.search_files`) + bounded live authorized workspace scan fallback
    if allow_files && !search_q.is_empty() {
        let mut filter = FileSearchFilter {
            query: Some(search_q.to_string()),
            sort_by: FileSortOrder::RelevanceAndRecent,
            limit: 8,
            ..Default::default()
        };
        if kind_filter == "document" || kind_filter == "doc" {
            filter.category = Some("document".to_string());
        }
        let mut file_hits = core.resources.search_files(&filter);
        if file_hits.is_empty() && search_q != raw_query {
            filter.query = Some(raw_query.to_string());
            file_hits = core.resources.search_files(&filter);
        }

        for (rec, sc) in &file_hits {
            let p = Path::new(&rec.path);
            if core.fs_engine.is_forbidden(p) {
                continue;
            }
            let norm_conf = (sc / 115.0).clamp(0.35, 0.95);
            upsert_candidate(
                &mut candidates,
                format!("path:{}", rec.path),
                if rec.category == "document" {
                    "document"
                } else {
                    "file"
                },
                rec.name.clone(),
                rec.path.clone(),
                norm_conf,
                "resource_index",
                json!({
                    "ext": rec.ext,
                    "category": rec.category,
                    "size_bytes": rec.size_bytes,
                    "mtime_secs": rec.mtime_secs,
                }),
            );
        }

        // Live authorized root scan fallback for freshly created files not yet synced into `IndexDb`
        if file_hits.is_empty() {
            let q_lc = search_q.to_lowercase();
            let q_toks: Vec<&str> = q_lc
                .split(|c: char| c.is_whitespace() || matches!(c, '、' | '，' | ',' | '/' | '_'))
                .filter(|t| t.chars().count() >= 2)
                .collect();
            let mut scanned = 0usize;
            for root_str in &core.app_config.authorized_directories {
                let root = expand_tilde_path(root_str);
                if !root.is_dir() || core.fs_engine.is_forbidden(&root) {
                    continue;
                }
                for entry in walkdir::WalkDir::new(&root)
                    .max_depth(4)
                    .follow_links(false)
                    .into_iter()
                    .filter_entry(|e| {
                        !e.path_is_symlink() && !core.fs_engine.is_forbidden(e.path())
                    })
                    .flatten()
                {
                    if scanned >= 800 {
                        break;
                    }
                    scanned += 1;
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    let fname = entry.file_name().to_string_lossy().to_string();
                    let fname_lc = fname.to_lowercase();
                    let matched_conf = if fname_lc == q_lc {
                        Some(0.93)
                    } else if fname_lc.contains(&q_lc) {
                        Some(0.84)
                    } else if !q_toks.is_empty() && q_toks.iter().any(|t| fname_lc.contains(t)) {
                        let hit_cnt = q_toks.iter().filter(|t| fname_lc.contains(**t)).count();
                        Some(0.62 + 0.10 * (hit_cnt as f64).min(2.0))
                    } else {
                        None
                    };
                    if let Some(conf) = matched_conf {
                        let p_str = entry.path().to_string_lossy().to_string();
                        let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                        upsert_candidate(
                            &mut candidates,
                            format!("path:{}", p_str),
                            "file",
                            fname,
                            p_str,
                            conf,
                            "authorized_workspace_live",
                            json!({ "size_bytes": size_bytes }),
                        );
                    }
                }
            }
        }
    }

    // 3. Personal Memory Hub (`memory_hub`) — STRICTLY gated on `privacy.allows_memory_read()`!
    if privacy.allows_memory_read() && allow_files && !search_q.is_empty() {
        let allow_sync = privacy.allows_memory_write() && privacy.allows_habit_learning();
        if (allow_sync || MemoryHubDb::path_for_core(core).exists())
            && let Ok(mem_db) = MemoryHubDb::open_for_core(core)
        {
            if allow_sync {
                ensure_lazy_synced(core, &mem_db);
                let _ = sync_document_outlines(core, &mem_db);
            }

            if let Ok(outlines) = search_document_outlines(&mem_db, raw_query, None, 5) {
                for o in outlines {
                    if o.score < 40.0 {
                        continue;
                    }
                    let p = Path::new(&o.record.path);
                    if core.fs_engine.is_forbidden(p) {
                        continue;
                    }
                    let conf = (o.score / 120.0).clamp(0.45, 0.96);
                    upsert_candidate(
                        &mut candidates,
                        format!("path:{}", o.record.path),
                        "document",
                        o.record.doc_title.clone(),
                        o.record.path.clone(),
                        conf,
                        "memory_document_outline",
                        json!({
                            "matched_section": o.matched_section,
                            "toc_preview": o.toc_preview,
                        }),
                    );
                }
            }

            let sid_opt = if session_id.trim().is_empty() {
                session.map(|s| s.session_id.as_str())
            } else {
                Some(session_id)
            };
            if let Ok(mentioned) = recall_mentioned_entities(&mem_db, search_q, None, sid_opt, 5) {
                for (ent, sc) in mentioned {
                    let p = Path::new(&ent.canonical_value);
                    if core.fs_engine.is_forbidden(p) {
                        continue;
                    }
                    let conf = (sc / 110.0).clamp(0.40, 0.92);
                    upsert_candidate(
                        &mut candidates,
                        format!("path:{}", ent.canonical_value),
                        "file",
                        ent.display_name,
                        ent.canonical_value,
                        conf,
                        "memory_mentioned",
                        json!({ "mention_count": ent.mention_count }),
                    );
                }
            }

            if let Ok(freqs) = query_frequent_files(&mem_db, Some(search_q), None, 4) {
                for f in freqs {
                    let p = Path::new(&f.path);
                    if core.fs_engine.is_forbidden(p) {
                        continue;
                    }
                    let conf = (f.frecency_score / 100.0).clamp(0.35, 0.88);
                    upsert_candidate(
                        &mut candidates,
                        format!("path:{}", f.path),
                        "file",
                        f.title,
                        f.path,
                        conf,
                        "memory_frequent_files",
                        json!({ "open_count": f.open_count }),
                    );
                }
            }
        }
    }

    // 4. Desktop Applications (`core.resources.search_apps`)
    if allow_apps && !search_q.is_empty() {
        for (app, sc) in core.resources.search_apps(search_q, 5) {
            if sc < 45.0 {
                continue;
            }
            let conf = (sc / 120.0).clamp(0.35, 0.93);
            upsert_candidate(
                &mut candidates,
                format!("app:{}", app.app_id),
                "app",
                app.name,
                app.app_id.clone(),
                conf,
                "desktop_app_index",
                json!({
                    "exec_cmd": app.exec_cmd,
                    "keywords": app.keywords,
                }),
            );
        }
    }

    // 5. Project workspaces inside `authorized_directories`
    if allow_projects && !search_q.is_empty() {
        let q_lc = search_q.to_lowercase();
        for root_str in &core.app_config.authorized_directories {
            let root = expand_tilde_path(root_str);
            if !root.is_dir() || core.fs_engine.is_forbidden(&root) {
                continue;
            }
            let mut dirs_to_check = vec![root.clone()];
            if let Ok(rd) = std::fs::read_dir(&root) {
                for ent in rd.flatten().take(40) {
                    let p = ent.path();
                    if p.is_dir() && !core.fs_engine.is_forbidden(&p) {
                        dirs_to_check.push(p);
                    }
                }
            }
            for dir in dirs_to_check {
                let dname = dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let is_proj = dir.join(".git").exists()
                    || dir.join("Cargo.toml").exists()
                    || dir.join("pyproject.toml").exists()
                    || dir.join("package.json").exists();
                if is_proj && dname.to_lowercase().contains(&q_lc) {
                    let p_str = dir.to_string_lossy().to_string();
                    upsert_candidate(
                        &mut candidates,
                        format!("path:{}", p_str),
                        "project",
                        dname,
                        p_str,
                        0.89,
                        "authorized_project_dir",
                        json!({ "is_project_root": true }),
                    );
                }
            }
        }
    }

    let ws_kind = crate::world_state::ResourceKind::from_hint(&kind_filter);
    let mut effective_session_buf: Option<SessionState> = session.cloned();
    if let Some(ref last_turn_p) = effect_ledger.last_resource_path {
        let mut sb = effective_session_buf
            .take()
            .unwrap_or_else(|| SessionState {
                session_id: session_id.to_string(),
                messages: Vec::new(),
                last_resource_path: None,
                updated_at: chrono::Utc::now(),
            });
        if sb.last_resource_path.is_none() {
            sb.last_resource_path = Some(last_turn_p.clone());
        }
        effective_session_buf = Some(sb);
    }
    let ws_resolution = crate::world_state::resolve_resource_for_core(
        core,
        raw_query,
        ws_kind,
        effective_session_buf.as_ref(),
        privacy,
    );

    if let crate::world_state::ResourceResolution::MultipleComparative(ref refs) = ws_resolution {
        for r in refs {
            let target = r
                .path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| r.uri.clone());
            upsert_candidate(
                &mut candidates,
                format!("ws:{}", r.id),
                r.kind.as_str(),
                r.display_name.clone(),
                target,
                r.confidence,
                &r.source,
                r.metadata.clone(),
            );
        }
    } else if candidates.is_empty() {
        match &ws_resolution {
            crate::world_state::ResourceResolution::Single(r) => {
                let target = r
                    .path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| r.uri.clone());
                upsert_candidate(
                    &mut candidates,
                    format!("ws:{}", r.id),
                    r.kind.as_str(),
                    r.display_name.clone(),
                    target,
                    r.confidence,
                    &r.source,
                    r.metadata.clone(),
                );
            }
            crate::world_state::ResourceResolution::Ambiguous {
                candidates: ws_cands,
                ..
            } => {
                for r in ws_cands {
                    let target = r
                        .path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| r.uri.clone());
                    upsert_candidate(
                        &mut candidates,
                        format!("ws:{}", r.id),
                        r.kind.as_str(),
                        r.display_name.clone(),
                        target,
                        r.confidence,
                        &r.source,
                        r.metadata.clone(),
                    );
                }
            }
            _ => {}
        }
    }

    candidates.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates.truncate(8);

    let candidates_json: Vec<Value> = candidates
        .iter()
        .map(|c| {
            json!({
                "kind": c.kind,
                "name": c.name,
                "target": c.path_or_id,
                "confidence": (c.confidence * 100.0).round() / 100.0,
                "sources": c.sources,
                "metadata": c.metadata,
            })
        })
        .collect();

    let (status_label, ambiguous, resolved_val, clarification_prompt) = match &ws_resolution {
        crate::world_state::ResourceResolution::MultipleComparative(refs) if refs.len() >= 2 => {
            let items: Vec<Value> = refs
                .iter()
                .map(|r| {
                    let target = r
                        .path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| r.uri.clone());
                    json!({
                        "id": r.id,
                        "kind": r.kind.as_str(),
                        "name": r.display_name,
                        "target": target,
                        "confidence": r.confidence,
                        "source": r.source,
                        "metadata": r.metadata,
                    })
                })
                .collect();
            (
                "multiple_comparative",
                false,
                Value::Array(items),
                Value::Null,
            )
        }
        crate::world_state::ResourceResolution::Unavailable { reason, .. }
            if candidates.is_empty() =>
        {
            (
                "unavailable",
                false,
                Value::Null,
                Value::String(format!(
                    "当前环境状态不可用（{}），请明确指定目标名称或路径。",
                    reason
                )),
            )
        }
        crate::world_state::ResourceResolution::Ambiguous {
            clarification_prompt: ws_prompt,
            ..
        } if candidates.len() >= 2
            && (candidates[0].confidence - candidates[1].confidence).abs()
                < crate::world_state::AMBIGUITY_CONFIDENCE_MARGIN =>
        {
            (
                "ambiguous",
                true,
                Value::Null,
                Value::String(ws_prompt.clone()),
            )
        }
        _ => {
            if candidates.is_empty() {
                ("not_found", false, Value::Null, Value::Null)
            } else if candidates.len() >= 2
                && (candidates[0].confidence - candidates[1].confidence).abs() < 0.08
            {
                let prompt = format!(
                    "针对「{}」找到多个相近候选：1) {} ({})；2) {} ({})。若任务需对比多项可同时使用，若仅针对单个目标请确认具体对象。",
                    raw_query,
                    candidates[0].name,
                    candidates[0].path_or_id,
                    candidates[1].name,
                    candidates[1].path_or_id
                );
                ("ambiguous", true, Value::Null, Value::String(prompt))
            } else {
                ("resolved", false, candidates_json[0].clone(), Value::Null)
            }
        }
    };

    let msg = format!(
        "resource.resolve 解析状态: {} (候选数: {})",
        status_label,
        candidates_json.len()
    );
    let data = json!({
        "query": raw_query,
        "kind": kind_filter,
        "status": status_label,
        "ambiguous": ambiguous,
        "memory_isolated": !privacy.allows_memory_read(),
        "resolved": resolved_val,
        "clarification_prompt": clarification_prompt,
        "candidates": candidates_json,
        "world_state_resolution": serde_json::to_value(&ws_resolution).unwrap_or(Value::Null),
    });
    (
        ExecutionStatus::Exited,
        msg,
        data,
        "resource_resolver",
        vec![format!("status:{}", status_label)],
    )
}

fn expand_tilde_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if trimmed == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    } else if let Some(rest) = trimmed.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(trimmed)
}

fn is_path_within_authorized_or_session_scope(
    core: &IntentOsCore,
    session_id: &str,
    path: &Path,
) -> bool {
    if core.fs_engine.is_forbidden(path) {
        return false;
    }
    let check_target = if path.exists() {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    } else if let Some(parent) = path.parent() {
        if parent.exists() {
            std::fs::canonicalize(parent)
                .map(|cp| {
                    if let Some(name) = path.file_name() {
                        cp.join(name)
                    } else {
                        cp
                    }
                })
                .unwrap_or_else(|_| path.to_path_buf())
        } else {
            path.to_path_buf()
        }
    } else {
        path.to_path_buf()
    };

    if core.fs_engine.is_forbidden(&check_target) {
        return false;
    }

    for auth in &core.app_config.authorized_directories {
        let root = expand_tilde_path(auth);
        let canon_root = std::fs::canonicalize(&root).unwrap_or(root);
        if check_target.starts_with(&canon_root) {
            return true;
        }
    }

    for approved in core.fs_engine.list_approved_roots() {
        let canon_approved = std::fs::canonicalize(&approved).unwrap_or(approved);
        if check_target.starts_with(&canon_approved) {
            return true;
        }
    }

    let _ = session_id;
    core.policy.is_session_granted(
        "file.read",
        &json!({ "path": check_target.to_string_lossy() }),
    )
}

fn is_process_running_by_hint(hint: &str) -> Vec<u32> {
    let needle = hint.trim().to_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }
    let mut pids = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for ent in rd.flatten() {
        let fname = ent.file_name();
        let Some(pid_str) = fname.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let comm_path = ent.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(comm_path)
            && comm.trim().to_lowercase().contains(&needle)
        {
            pids.push(pid);
            if pids.len() >= 8 {
                break;
            }
        }
    }
    pids
}

fn execute_task_verify(
    core: &IntentOsCore,
    session_id: &str,
    args: &Value,
    effect_ledger: &TurnEffectLedger,
) -> (ExecutionStatus, String, Value, &'static str, Vec<String>) {
    let goal = args
        .get("goal")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let expected_files: Vec<String> = args
        .get("expected_files")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let expected_apps: Vec<String> = args
        .get("expected_apps")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let check_ledger = args
        .get("check_ledger")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let mut passed: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();

    // 1. Host filesystem verification (strictly within authorized / session-granted roots and non-forbidden!)
    for raw_file in &expected_files {
        let expanded = expand_tilde_path(raw_file);
        if core.fs_engine.is_forbidden(&expanded) {
            failed.push(json!({
                "check": "expected_file",
                "target": raw_file,
                "reason": "forbidden_credential_or_system_path",
            }));
            continue;
        }
        if !is_path_within_authorized_or_session_scope(core, session_id, &expanded) {
            failed.push(json!({
                "check": "expected_file",
                "target": raw_file,
                "reason": "outside_authorized_roots",
            }));
            continue;
        }
        match std::fs::symlink_metadata(&expanded) {
            Err(_) => {
                failed.push(json!({
                    "check": "expected_file",
                    "target": raw_file,
                    "reason": "file_not_found",
                }));
            }
            Ok(sym_meta) => {
                if sym_meta.file_type().is_symlink() {
                    match std::fs::canonicalize(&expanded) {
                        Ok(real_target)
                            if is_path_within_authorized_or_session_scope(
                                core,
                                session_id,
                                &real_target,
                            ) => {}
                        _ => {
                            failed.push(json!({
                                "check": "expected_file",
                                "target": raw_file,
                                "reason": "dangling_or_unauthorized_symlink",
                            }));
                            continue;
                        }
                    }
                }
                match std::fs::metadata(&expanded) {
                    Err(_) => {
                        failed.push(json!({
                            "check": "expected_file",
                            "target": raw_file,
                            "reason": "metadata_unreadable",
                        }));
                    }
                    Ok(meta) => {
                        let mtime_secs = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        if meta.is_dir() {
                            passed.push(json!({
                                "check": "expected_directory",
                                "target": raw_file,
                                "exists": true,
                                "mtime_secs": mtime_secs,
                            }));
                        } else {
                            let size_bytes = meta.len();
                            if size_bytes == 0 {
                                failed.push(json!({
                                    "check": "expected_file_non_empty",
                                    "target": raw_file,
                                    "size_bytes": 0,
                                    "reason": "file_is_empty",
                                }));
                            } else {
                                passed.push(json!({
                                    "check": "expected_file",
                                    "target": raw_file,
                                    "exists": true,
                                    "size_bytes": size_bytes,
                                    "mtime_secs": mtime_secs,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Application / process state verification
    for app_hint in &expected_apps {
        let mut pids = is_process_running_by_hint(app_hint);
        let desktop_matches = core.resources.search_apps(app_hint, 3);
        if pids.is_empty()
            && let Some((top_app, _)) = desktop_matches.first()
            && let (_, Some(bin_name)) =
                crate::app_adapter::dynamic_profiler::extract_exec_binary(&top_app.exec_cmd)
        {
            pids = is_process_running_by_hint(&bin_name);
        }
        let launched_in_ledger = effect_ledger.records().iter().any(|r| {
            r.succeeded
                && (r.capability_id == "app.launch" || r.capability_id == "app_adapter_invoke")
                && r.canonical_args_json
                    .to_lowercase()
                    .contains(&app_hint.to_lowercase())
        });
        if !pids.is_empty() {
            passed.push(json!({
                "check": "expected_app",
                "target": app_hint,
                "running": true,
                "pids": pids,
            }));
        } else {
            failed.push(json!({
                "check": "expected_app",
                "target": app_hint,
                "running": false,
                "launch_step_recorded_in_ledger": launched_in_ledger,
                "installed": !desktop_matches.is_empty(),
                "reason": "process_not_observed",
            }));
        }
    }

    // 3. `TurnEffectLedger` step & unresolved state verification
    let records = effect_ledger.records();
    let mut verified_domain_steps: Vec<String> = Vec::new();
    if check_ledger {
        if effect_ledger.has_uncertain_side_effects() {
            failed.push(json!({
                "check": "effect_ledger_integrity",
                "reason": "uncertain_or_recovery_required_side_effects",
            }));
        }
        if !effect_ledger.budget_skipped_steps.is_empty() {
            failed.push(json!({
                "check": "budget_skipped_steps",
                "skipped": effect_ledger.budget_skipped_steps,
                "reason": "steps_skipped_due_to_budget",
            }));
        }
        for (idx, rec) in records.iter().enumerate() {
            if is_discovery_only_meta_tool(&rec.capability_id)
                || normalize_meta_tool_id(&rec.capability_id) == Some(META_TASK_VERIFY)
            {
                continue;
            }
            let is_verified = |r: &crate::backend_bridge::turn_checkpoint::StepExecutionRecord| {
                r.succeeded && r.verification_status.eq_ignore_ascii_case("passed")
            };
            if is_verified(rec) {
                verified_domain_steps.push(format!("{}:{}", rec.step_id, rec.capability_id));
            } else {
                let recovered_later = records[idx + 1..].iter().any(|later| {
                    later.capability_id == rec.capability_id
                        && later.canonical_args_json == rec.canonical_args_json
                        && is_verified(later)
                });
                if !recovered_later {
                    failed.push(json!({
                        "check": "ledger_step",
                        "step_id": rec.step_id,
                        "capability_id": rec.capability_id,
                        "verification_status": rec.verification_status,
                        "reason": if rec.was_denied() { "step_denied" } else if rec.succeeded { "step_not_verified" } else { "step_failed" },
                    }));
                }
            }
        }
        if !verified_domain_steps.is_empty() {
            passed.push(json!({
                "check": "ledger_verified_steps",
                "count": verified_domain_steps.len(),
                "steps": verified_domain_steps,
                "changeset_ids": effect_ledger.committed_changeset_ids(),
            }));
        } else if expected_files.is_empty() && expected_apps.is_empty() {
            failed.push(json!({
                "check": "execution_evidence",
                "reason": "no_verified_steps_or_host_targets",
            }));
        }
    }

    if passed.is_empty() && failed.is_empty() {
        failed.push(json!({
            "check": "execution_evidence",
            "reason": "no_verified_steps_or_host_targets",
        }));
    }
    let verified = failed.is_empty() && !passed.is_empty();
    let msg = if verified {
        format!("task.verify 校验通过（{} 项检查全部通过）", passed.len())
    } else {
        format!(
            "task.verify 发现 {} 项未通过检查（已通过 {} 项）",
            failed.len(),
            passed.len()
        )
    };
    let data = json!({
        "goal": goal,
        "verified": verified,
        "passed": passed,
        "failed": failed,
        "changeset_ids": effect_ledger.committed_changeset_ids(),
    });
    (
        if verified {
            ExecutionStatus::Exited
        } else {
            ExecutionStatus::VerificationFailed
        },
        msg,
        data,
        "host_and_ledger_verify",
        vec![format!("verified:{}", verified)],
    )
}

/// Extract `unlocked_capability_ids` from a JSON `Value` (either directly in `data` or nested under `data.unlocked_capability_ids`).
pub fn extract_unlocked_capability_ids_from_value(val: &Value) -> Vec<String> {
    let arr_opt = val
        .get("unlocked_capability_ids")
        .and_then(Value::as_array)
        .or_else(|| {
            val.pointer("/data/unlocked_capability_ids")
                .and_then(Value::as_array)
        });
    let Some(arr) = arr_opt else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Extract `unlocked_capability_ids` from a serialized tool message string when `fn_name` is
/// `capability_search` or `capability_describe`.
pub fn extract_unlocked_capability_ids_from_tool_message(
    fn_name: &str,
    tool_message_json: &str,
) -> Vec<String> {
    if !is_discovery_only_meta_tool(fn_name) {
        return Vec::new();
    }
    let Ok(val) = serde_json::from_str::<Value>(tool_message_json) else {
        return Vec::new();
    };
    extract_unlocked_capability_ids_from_value(&val)
}

fn resolve_full_openai_tool_schema(
    broker: &CapabilityBroker,
    snap: &CapabilitySnapshot,
    privacy: PrivacySessionPolicy,
    raw_id: &str,
) -> Option<(String, Value)> {
    if let Some(cid) = snap.resolve_canonical_id(raw_id) {
        if !privacy.allows_memory_write() && is_memory_write_tool(cid) {
            return None;
        }
        let schema = snap.get_openai_schema(cid)?.clone();
        let fn_name = schema
            .pointer("/function/name")
            .and_then(Value::as_str)?
            .to_string();
        return Some((fn_name, schema));
    }

    let norm_us = raw_id.replace('.', "_");
    let norm_dot = raw_id.replace('_', ".");
    for spec in discoverable_aios_and_provider_specs(broker) {
        if spec.name == raw_id || spec.name == norm_us || spec.name.replace('_', ".") == norm_dot {
            if (!privacy.allows_memory_read() && is_memory_tool(&spec.name))
                || (!privacy.allows_memory_write() && is_memory_write_tool(&spec.name))
            {
                return None;
            }
            let fn_name = spec.name.replace('.', "_");
            let val = json!({
                "type": "function",
                "function": {
                    "name": fn_name,
                    "description": spec.description,
                    "parameters": spec.parameters,
                }
            });
            return Some((fn_name, val));
        }
    }
    None
}

/// Dynamically merge or upgrade unlocked concrete tool schemas into an active OpenAI `tools` array
/// for subsequent model rounds (`k + 1`). Returns the number of newly appended or upgraded schemas.
pub fn merge_unlocked_openai_tools(
    broker: &CapabilityBroker,
    privacy: PrivacySessionPolicy,
    unlocked_ids: &[String],
    openai_tools: &mut Vec<Value>,
) -> usize {
    if unlocked_ids.is_empty() {
        return 0;
    }
    let snap = capability_snapshot_for_broker(broker);
    let mut merged = 0usize;

    for raw_id in unlocked_ids {
        let Some((fn_name, full_schema)) =
            resolve_full_openai_tool_schema(broker, &snap, privacy, raw_id)
        else {
            continue;
        };
        if let Some(pos) = openai_tools.iter().position(|t| {
            t.pointer("/function/name").and_then(Value::as_str) == Some(fn_name.as_str())
        }) {
            if openai_tools[pos] != full_schema {
                openai_tools[pos] = full_schema;
                merged += 1;
            }
        } else {
            openai_tools.push(full_schema);
            merged += 1;
        }
    }
    merged
}

/// Dynamically merge or upgrade unlocked concrete tool schemas into an active Anthropic `tools` array
/// for subsequent model rounds (`k + 1`). Returns the number of newly appended or upgraded schemas.
pub fn merge_unlocked_anthropic_tools(
    broker: &CapabilityBroker,
    privacy: PrivacySessionPolicy,
    unlocked_ids: &[String],
    anthropic_tools: &mut Vec<Value>,
) -> usize {
    if unlocked_ids.is_empty() {
        return 0;
    }
    let snap = capability_snapshot_for_broker(broker);
    let mut merged = 0usize;

    for raw_id in unlocked_ids {
        let Some((fn_name, full_openai)) =
            resolve_full_openai_tool_schema(broker, &snap, privacy, raw_id)
        else {
            continue;
        };
        let Some(f) = full_openai.get("function") else {
            continue;
        };
        let anth_val = json!({
            "name": fn_name,
            "description": f.get("description").and_then(Value::as_str).unwrap_or(""),
            "input_schema": f.get("parameters").cloned().unwrap_or_else(|| json!({"type": "object", "properties": {}})),
        });

        if let Some(pos) = anthropic_tools
            .iter()
            .position(|t| t.get("name").and_then(Value::as_str) == Some(fn_name.as_str()))
        {
            if anthropic_tools[pos] != anth_val {
                anthropic_tools[pos] = anth_val;
                merged += 1;
            }
        } else {
            anthropic_tools.push(anth_val);
            merged += 1;
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend_bridge::broker_bridge::{
        BackendExecutionMode, QuickChatToolExecOutcome, build_quick_chat_openai_tools_with_policy,
        execute_quick_chat_tool_call_with_step,
    };
    use crate::backend_bridge::detector::ActiveBackendSelection;
    use crate::backend_bridge::turn_checkpoint::StepInvocationContext;
    use crate::backend_bridge::{
        DiscoveryOptions, resume_approved_turn_with_options, send_quick_chat_turn_with_options,
        set_active_backend_with_options,
    };
    use crate::config::{AppConfig, BrainConfig, XdgPaths};
    use axum::{Json, Router, extract::State, routing::post};
    use intentos_protocol::{DataClass, Taint};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    fn test_repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .parent()
            .expect("repo root")
            .to_path_buf()
    }

    fn init_m2a_test_core(base: &Path, ws: &Path) -> Arc<IntentOsCore> {
        let repo_root = test_repo_root();
        let xdg = XdgPaths::resolve(Some(base), repo_root.clone());
        xdg.ensure_dirs().unwrap();
        let cfg = AppConfig {
            authorized_directories: vec![ws.to_string_lossy().to_string()],
            allow_simulated_hardware_fallback: true,
            ..AppConfig::default()
        };
        let brain = BrainConfig {
            runtime: "native".to_string(),
            ..BrainConfig::default()
        };
        std::fs::write(
            xdg.config_dir.join("config.toml"),
            toml::to_string_pretty(&cfg).unwrap(),
        )
        .unwrap();
        std::fs::write(
            xdg.config_dir.join("brain.toml"),
            toml::to_string_pretty(&brain).unwrap(),
        )
        .unwrap();
        IntentOsCore::initialize(Some(base), repo_root).expect("init m2a test core")
    }

    fn verification_record(
        step: &str,
        capability: &str,
        args: Value,
        status: &str,
    ) -> crate::backend_bridge::turn_checkpoint::StepExecutionRecord {
        crate::backend_bridge::turn_checkpoint::StepExecutionRecord {
            step_id: step.into(),
            idempotency_key: step.into(),
            capability_id: capability.into(),
            canonical_args_json: args.to_string(),
            effect: Effect::Observe,
            mutated_state: false,
            succeeded: status != "VerificationFailed",
            changeset_id: None,
            verification_status: status.into(),
            cached_output: json!({}),
        }
    }

    #[tokio::test]
    async fn task_verify_reports_failed_evidence_in_protocol_and_data() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let core = init_m2a_test_core(tmp.path(), &ws);
        for args in [
            json!({"goal":"missing output", "expected_files":[ws.join("missing.txt")]}),
            json!({"goal":"no evidence", "check_ledger": false}),
        ] {
            let result = execute_non_invoke_meta_tool(
                &core,
                META_TASK_VERIFY,
                "verify-test",
                None,
                "test",
                PrivacySessionPolicy::Standard,
                &args,
                &TurnEffectLedger::new("verify-test"),
            )
            .await;
            assert_eq!(result.status, ExecutionStatus::VerificationFailed);
            assert_eq!(
                result.verification.state,
                VerificationState::VerificationFailed
            );
            assert_eq!(result.exit_code, Some(1));
            assert_eq!(result.data["verified"], false);
            assert!(!result.data["failed"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn task_verify_requires_observed_app_and_verified_same_target_retry() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let core = init_m2a_test_core(tmp.path(), &ws);
        let mut ledger = TurnEffectLedger::new("verify-test");
        // A successful launch receipt is not evidence of a currently running app.
        let app = "intentos_nonexistent_app_for_verification_test";
        ledger.record_step(verification_record(
            "launch",
            "app.launch",
            json!({"app":app}),
            "Passed",
        ));
        let (_, _, data, _, _) = execute_task_verify(
            &core,
            "test",
            &json!({"goal":"open app", "expected_apps":[app]}),
            &ledger,
        );
        assert_eq!(data["verified"], false);
        assert_eq!(data["failed"][0]["launch_step_recorded_in_ledger"], true);

        let mut ledger = TurnEffectLedger::new("retry-test");
        ledger.record_step(verification_record(
            "failed",
            "file.search",
            json!({"query":"A"}),
            "VerificationFailed",
        ));
        ledger.record_step(verification_record(
            "different",
            "file.search",
            json!({"query":"B"}),
            "Passed",
        ));
        let args = json!({"goal":"find A and B"});
        assert_eq!(
            execute_task_verify(&core, "test", &args, &ledger).2["verified"],
            false
        );
        ledger.record_step(verification_record(
            "retry",
            "file.search",
            json!({"query":"A"}),
            "Passed",
        ));
        assert_eq!(
            execute_task_verify(&core, "test", &args, &ledger).2["verified"],
            true
        );

        let mut ledger = TurnEffectLedger::new("unverified-test");
        ledger.record_step(verification_record(
            "requested",
            "app.launch",
            json!({"app":app}),
            "RequestedUnverified",
        ));
        let data = execute_task_verify(&core, "test", &args, &ledger).2;
        assert_eq!(data["verified"], false);
        assert_eq!(data["failed"][0]["reason"], "step_not_verified");
    }

    #[test]
    fn m2a_progressive_initial_schema_bytes_under_6800_and_over_55pct_reduction() {
        // 1. Both underscore function names and dot canonical IDs are recognized as meta-tools
        for name in [
            "capability_search",
            "capability.search",
            "capability_describe",
            "capability.describe",
            "capability_invoke",
            "capability.invoke",
            "app_discover",
            "app.discover",
            "resource_resolve",
            "resource.resolve",
            "task_verify",
            "task.verify",
        ] {
            assert!(
                is_meta_tool(name),
                "{} must be recognized as meta-tool",
                name
            );
        }
        assert!(!is_meta_tool("file_search"));
        assert!(!is_meta_tool("archive.create"));

        let tmp = tempfile::Builder::new()
            .prefix("intentos_m2a_t1_")
            .tempdir()
            .unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let secret_marker = "secret_private_salary_2026_confidential_only_user";
        std::fs::write(
            ws.join(format!("{}.xlsx", secret_marker)),
            "private user spreadsheet content",
        )
        .unwrap();

        let core = init_m2a_test_core(tmp.path(), &ws);
        let _ = core.resources.index_authorized_files();
        core.policy
            .add_session_grant("directory", &ws.to_string_lossy(), 60);
        if let Ok(mem_db) = MemoryHubDb::open_for_core(&core) {
            let _ = mem_db.set_meta("secret_pref", secret_marker);
            let _ =
                crate::memory_hub::create_session(&mem_db, Some("ses_secret"), Some(secret_marker));
        }

        // Baselines recorded at commit cf9e649:
        // - Quick-Chat initial tools (29 tools): 15,672 B (3,918 B/4 tokens)
        // - Core L2 AgentCoordinator (96 tools): 38,351 B (9,588 B/4 tokens)
        const QUICK_CHAT_BASELINE_BYTES: usize = 15_672;
        const CORE_L2_BASELINE_BYTES: usize = 38_351;

        let representative_queries = [
            "",
            "你好，今天天气怎么样",
            "把音量调到 40%",
            "帮我搜索实验目录里的日志文件",
            "打开我的硕士论文第四章",
            "结合我的个人记忆看看之前提到的预算文件，并列出媒体转译器",
            "汽水音乐怎么还没有打开？帮我看看状态",
            "帮我把报告导出成 PDF 并打包成压缩包然后验证",
        ];

        for q in representative_queries {
            for policy in [
                PrivacySessionPolicy::Standard,
                PrivacySessionPolicy::EphemeralReadOnly,
                PrivacySessionPolicy::StrictIsolated,
            ] {
                let qc_tools = build_quick_chat_openai_tools_with_policy(&core, q, policy);
                let qc_json = serde_json::to_string(&qc_tools).unwrap();
                let qc_bytes = qc_json.len();
                assert!(
                    qc_bytes <= MAX_INITIAL_OPENAI_TOOLS_BYTES,
                    "Quick-Chat Round-0 tools JSON exceeded 6,800 B ceiling on query {:?} ({:?}): {} B",
                    q,
                    policy,
                    qc_bytes
                );
                let qc_reduction = 1.0 - (qc_bytes as f64 / QUICK_CHAT_BASELINE_BYTES as f64);
                assert!(
                    qc_reduction >= 0.56,
                    "Quick-Chat reduction must be >= 56% vs 15,672 B baseline, got {:.1}% ({} B) on {:?}",
                    qc_reduction * 100.0,
                    qc_bytes,
                    q
                );

                // Verify all 6 meta-tools are always present on Round 0
                let fn_names: Vec<&str> = qc_tools
                    .iter()
                    .filter_map(|t| t.pointer("/function/name").and_then(Value::as_str))
                    .collect();
                for expected_meta in [
                    FN_CAPABILITY_SEARCH,
                    FN_CAPABILITY_DESCRIBE,
                    FN_CAPABILITY_INVOKE,
                    FN_APP_DISCOVER,
                    FN_RESOURCE_RESOLVE,
                    FN_TASK_VERIFY,
                ] {
                    assert!(
                        fn_names.contains(&expected_meta),
                        "Round-0 tools missing meta-tool {} on query {:?}",
                        expected_meta,
                        q
                    );
                }

                // Core L2 AgentCoordinator progressive Round-0 tools check
                let l2_specs = core.agent.build_initial_l2_tools(q, policy);
                let l2_openai: Vec<Value> = l2_specs
                    .iter()
                    .map(|t| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": t.name,
                                "description": t.description,
                                "parameters": t.parameters,
                            }
                        })
                    })
                    .collect();
                let l2_bytes = serde_json::to_string(&l2_openai).unwrap().len();
                assert!(
                    l2_bytes <= MAX_INITIAL_OPENAI_TOOLS_BYTES,
                    "Core L2 Round-0 tools JSON exceeded 6,800 B ceiling on query {:?}: {} B",
                    q,
                    l2_bytes
                );
                let l2_reduction = 1.0 - (l2_bytes as f64 / CORE_L2_BASELINE_BYTES as f64);
                assert!(
                    l2_reduction >= 0.82,
                    "Core L2 reduction must be >= 82% vs 38,351 B baseline, got {:.1}% ({} B)",
                    l2_reduction * 100.0,
                    l2_bytes
                );
            }
        }

        // Sweep full 325-utterance evaluation corpus to prove universal <= 6,800 B compliance
        let corpus_path = test_repo_root().join("eval/intents/v0_1_shell_300.json");
        if corpus_path.exists() {
            let corpus_val: Value =
                serde_json::from_str(&std::fs::read_to_string(&corpus_path).unwrap()).unwrap();
            if let Some(items) = corpus_val.as_array() {
                let mut total_bytes = 0usize;
                let mut max_bytes = 0usize;
                let mut min_bytes = usize::MAX;
                let mut checked_count = 0usize;
                for item in items {
                    if let Some(utt) = item
                        .get("intent")
                        .or_else(|| item.get("utterance"))
                        .and_then(Value::as_str)
                    {
                        let tools = build_quick_chat_openai_tools_with_policy(
                            &core,
                            utt,
                            PrivacySessionPolicy::Standard,
                        );
                        let b = serde_json::to_string(&tools).unwrap().len();
                        assert!(
                            b <= MAX_INITIAL_OPENAI_TOOLS_BYTES,
                            "Corpus utterance {:?} exceeded 6,800 B: {} B",
                            utt,
                            b
                        );
                        total_bytes += b;
                        max_bytes = max_bytes.max(b);
                        min_bytes = min_bytes.min(b);
                        checked_count += 1;
                    }
                }
                assert!(checked_count >= 300, "expected >= 300 corpus intents");
                let avg_bytes = total_bytes / checked_count;
                println!(
                    "[M2-A metrics] {}-corpus Quick-Chat Round-0 OpenAI tools: min={} B, avg={} B ({} B/4 tok, -{:.1}% vs 15,672 B), max={} B ({} B/4 tok, -{:.1}% vs 15,672 B, -{:.1}% vs 38,351 B L2)",
                    checked_count,
                    min_bytes,
                    avg_bytes,
                    avg_bytes.div_ceil(4),
                    (1.0 - avg_bytes as f64 / QUICK_CHAT_BASELINE_BYTES as f64) * 100.0,
                    max_bytes,
                    max_bytes.div_ceil(4),
                    (1.0 - max_bytes as f64 / QUICK_CHAT_BASELINE_BYTES as f64) * 100.0,
                    (1.0 - max_bytes as f64 / CORE_L2_BASELINE_BYTES as f64) * 100.0,
                );
                assert!(
                    avg_bytes <= 4_500,
                    "Average corpus Round-0 tool bytes should be well below 4,500 B, got {} B",
                    avg_bytes
                );
            }
        }

        // Verify capability.search NEVER leaks private user filenames or personal memory data
        for probe_q in ["*", "file", "memory", "salary", "confidential", "xlsx"] {
            let (_, msg, data, _, _) = execute_capability_search(
                &core,
                PrivacySessionPolicy::Standard,
                &json!({ "query": probe_q, "limit": 15 }),
            );
            let serialized = format!("{} {}", msg, serde_json::to_string(&data).unwrap());
            assert!(
                !serialized.contains(secret_marker),
                "SECURITY VIOLATION: capability.search leaked private user filename/memory on query {:?}: {}",
                probe_q,
                serialized
            );
        }
    }

    #[derive(Clone)]
    struct M2AMultiRoundMockState {
        recorded_requests: Arc<Mutex<Vec<Value>>>,
        summary_path: String,
        archive_path: String,
    }

    async fn mock_m2a_multi_round_completions(
        State(st): State<M2AMultiRoundMockState>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let round_idx = {
            let mut guard = st.recorded_requests.lock().unwrap();
            let idx = guard.len();
            guard.push(body);
            idx
        };

        match round_idx {
            0 => Json(json!({
                "id": "chatcmpl_m2a_r0",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "<think>先检索实验目录，再通过 capability_search 和 capability_describe 动态解锁文件写入与归档打包工具。</think>",
                        "tool_calls": [
                            {
                                "id": "call_m2a_r0_fsearch",
                                "type": "function",
                                "function": {
                                    "name": "file_search",
                                    "arguments": serde_json::to_string(&json!({ "query": "exp_run" })).unwrap()
                                }
                            },
                            {
                                "id": "call_m2a_r0_csearch",
                                "type": "function",
                                "function": {
                                    "name": "capability_search",
                                    "arguments": serde_json::to_string(&json!({ "query": "archive", "limit": 5 })).unwrap()
                                }
                            },
                            {
                                "id": "call_m2a_r0_cdescribe",
                                "type": "function",
                                "function": {
                                    "name": "capability_describe",
                                    "arguments": serde_json::to_string(&json!({
                                        "capability_ids": ["archive.create", "file.write"]
                                    })).unwrap()
                                }
                            }
                        ]
                    }
                }]
            })),
            1 => Json(json!({
                "id": "chatcmpl_m2a_r1",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "<think>工具已动态解锁，现在直接调用解锁的 file_write 写入总结，并通过 capability_invoke 执行 archive.create。</think>",
                        "tool_calls": [
                            {
                                "id": "call_m2a_r1_fwrite",
                                "type": "function",
                                "function": {
                                    "name": "file_write",
                                    "arguments": serde_json::to_string(&json!({
                                        "path": st.summary_path,
                                        "content": "# Experiment Summary\n- exp_run_01: accuracy 98.4%\n"
                                    })).unwrap()
                                }
                            },
                            {
                                "id": "call_m2a_r1_cinvoke_archive",
                                "type": "function",
                                "function": {
                                    "name": "capability_invoke",
                                    "arguments": serde_json::to_string(&json!({
                                        "capability_id": "archive.create",
                                        "arguments": {
                                            "source": st.summary_path,
                                            "output": st.archive_path
                                        }
                                    })).unwrap()
                                }
                            }
                        ]
                    }
                }]
            })),
            2 => Json(json!({
                "id": "chatcmpl_m2a_r2",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "<think>调用 task_verify 对宿主机的真实文件落盘与事务账本进行终态校验。</think>",
                        "tool_calls": [
                            {
                                "id": "call_m2a_r2_verify",
                                "type": "function",
                                "function": {
                                    "name": "task_verify",
                                    "arguments": serde_json::to_string(&json!({
                                        "goal": "生成实验总结并创建压缩归档包",
                                        "expected_files": [st.summary_path, st.archive_path],
                                        "check_ledger": true
                                    })).unwrap()
                                }
                            }
                        ]
                    }
                }]
            })),
            _ => Json(json!({
                "id": "chatcmpl_m2a_r3",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "已完成实验日志检索、总结写入（`exp_summary.md`）、归档打包（`exp_bundle.tar.gz`），并通过 `task_verify` 验证全部文件与可逆变更集落盘无误。"
                    }
                }]
            })),
        }
    }

    #[tokio::test]
    async fn m2a_multi_round_mid_turn_search_describe_unlock_invoke_changeset_and_task_verify() {
        let tmp = tempfile::Builder::new()
            .prefix("intentos_m2a_t1_")
            .tempdir()
            .unwrap();
        let ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("exp_run_01.log"), "step=100 acc=0.984 loss=0.041\n").unwrap();

        let core = init_m2a_test_core(tmp.path(), &ws);
        let _ = core.resources.index_authorized_files();
        core.policy
            .add_session_grant("directory", &ws.to_string_lossy(), 60);

        let summary_path = ws.join("exp_summary.md");
        let archive_path = ws.join("exp_bundle.tar.gz");
        let recorded_requests = Arc::new(Mutex::new(Vec::new()));

        let state = M2AMultiRoundMockState {
            recorded_requests: recorded_requests.clone(),
            summary_path: summary_path.to_string_lossy().to_string(),
            archive_path: archive_path.to_string_lossy().to_string(),
        };
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                post(mock_m2a_multi_round_completions),
            )
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mock_home = tmp.path().join("mock_home");
        std::fs::create_dir_all(&mock_home).unwrap();
        let opts = DiscoveryOptions::isolated_for_test(mock_home);

        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "openai",
                "provider": "m2a-mock-openai",
                "model": "gpt-5.4",
                "base_url": format!("http://{}/v1", addr),
                "api_key": "sk-m2a-progressive-test-key-123456"
            }),
            &opts,
        )
        .await
        .unwrap();

        // Start with a search-focused utterance so `archive_create` and `file_write` are NOT in Round 0!
        let turn_res = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": "ses_m2a_progressive_e2e",
                "text": "帮我搜索实验目录里的 exp_run 日志文件并按需完成后续整理",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(turn_res["status"], "completed");
        assert_eq!(turn_res["task_status"], "succeeded");

        let reqs = recorded_requests.lock().unwrap();
        assert_eq!(reqs.len(), 4, "expected 4 HTTP model rounds (0..=3)");

        // Verify Round 0 progressive exposure: <= 6,800 B, contains file_search + 6 meta-tools, WITHOUT archive_create / file_write
        let r0_tools = reqs[0]["tools"].as_array().expect("r0 tools array");
        let r0_bytes = serde_json::to_string(r0_tools).unwrap().len();
        assert!(
            r0_bytes <= MAX_INITIAL_OPENAI_TOOLS_BYTES,
            "Round-0 tools JSON must be <= 6,800 B, got {} B",
            r0_bytes
        );
        let r0_names: Vec<&str> = r0_tools
            .iter()
            .filter_map(|t| t.pointer("/function/name").and_then(Value::as_str))
            .collect();
        assert!(r0_names.contains(&"capability_search"));
        assert!(r0_names.contains(&"capability_describe"));
        assert!(r0_names.contains(&"capability_invoke"));
        assert!(r0_names.contains(&"task_verify"));
        assert!(r0_names.contains(&"file_search"));
        assert!(
            !r0_names.contains(&"archive_create"),
            "archive_create MUST NOT be in initial Round-0 tools for a log-search prompt!"
        );
        assert!(
            !r0_names.contains(&"file_write"),
            "file_write MUST NOT be in initial Round-0 tools for a log-search prompt!"
        );

        // Verify Round 1 dynamically unlocked BOTH `archive_create` and `file_write` with full concrete schemas!
        let r1_tools = reqs[1]["tools"].as_array().expect("r1 tools array");
        let r1_names: Vec<&str> = r1_tools
            .iter()
            .filter_map(|t| t.pointer("/function/name").and_then(Value::as_str))
            .collect();
        assert!(
            r1_names.contains(&"archive_create"),
            "archive_create MUST be dynamically unlocked in Round 1 after capability_search + capability_describe! Got: {:?}",
            r1_names
        );
        assert!(
            r1_names.contains(&"file_write"),
            "file_write MUST be dynamically unlocked in Round 1 after capability_describe! Got: {:?}",
            r1_names
        );
        let fw_schema = r1_tools
            .iter()
            .find(|t| t.pointer("/function/name").and_then(Value::as_str) == Some("file_write"))
            .unwrap();
        assert!(
            fw_schema
                .pointer("/function/parameters/properties/content")
                .is_some(),
            "unlocked file_write must expose its full input_schema properties!"
        );

        // Verify Round 3 received `task_verify` tool message with `verified == true`
        let r3_msgs = reqs[3]["messages"].as_array().expect("r3 messages");
        let verify_tool_msg = r3_msgs
            .iter()
            .rev()
            .find(|m| {
                m.get("role").and_then(Value::as_str) == Some("tool")
                    && m.get("tool_call_id").and_then(Value::as_str) == Some("call_m2a_r2_verify")
            })
            .expect("task_verify tool output in round 3");
        let verify_payload: Value =
            serde_json::from_str(verify_tool_msg["content"].as_str().unwrap()).unwrap();
        assert_eq!(
            verify_payload["data"]["verified"], true,
            "task_verify must report verified=true: {}",
            verify_payload
        );
        assert_eq!(
            verify_payload["data"]["failed"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(99),
            0
        );

        // Verify both unlocked `file_write` AND `capability_invoke("archive.create")` recorded real reversible ChangeSets!
        assert!(summary_path.exists());
        assert!(archive_path.exists());
        let cs_ids: Vec<String> = turn_res["changeset_ids"]
            .as_array()
            .expect("changeset_ids array")
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect();
        assert_eq!(
            cs_ids.len(),
            2,
            "both file_write and capability_invoke(archive.create) must emit ChangeSets, got {:?}",
            cs_ids
        );

        // Undo the archive ChangeSet and confirm rollback works cleanly
        core.broker
            .undo_changeset(Some(&cs_ids[1]))
            .expect("undo archive changeset");
        assert!(
            !archive_path.exists(),
            "undoing archive.create changeset must remove created archive!"
        );
    }

    #[derive(Clone)]
    struct M2AApprovalInvokeMockState {
        calls: Arc<Mutex<usize>>,
        outside_file: String,
    }

    async fn mock_m2a_approval_invoke_completions(
        State(st): State<M2AApprovalInvokeMockState>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let _idx = {
            let mut g = st.calls.lock().unwrap();
            let c = *g;
            *g += 1;
            c
        };
        let has_tool_result = body["messages"]
            .as_array()
            .is_some_and(|arr| arr.iter().any(|m| m["role"] == "tool"));
        if !has_tool_result {
            Json(json!({
                "id": "chatcmpl_m2a_appr_1",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "<think>尝试通过 capability_invoke 写入未授权外部目录文件，验证审批拦截。</think>",
                        "tool_calls": [{
                            "id": "call_m2a_cinvoke_outside",
                            "type": "function",
                            "function": {
                                "name": "capability_invoke",
                                "arguments": serde_json::to_string(&json!({
                                    "capability_id": "file.write",
                                    "arguments": {
                                        "path": st.outside_file,
                                        "content": "approved via capability_invoke!\n"
                                    }
                                })).unwrap()
                            }
                        }]
                    }
                }]
            }))
        } else {
            Json(json!({
                "id": "chatcmpl_m2a_appr_2",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "外部路径写入已获用户审批并成功落盘。"
                    }
                }]
            }))
        }
    }

    #[tokio::test]
    async fn m2a_capability_invoke_enforces_approval_denial_privacy_and_blocks_recursion() {
        let tmp = tempfile::Builder::new()
            .prefix("intentos_m2a_t1_")
            .tempdir()
            .unwrap();
        let ws = tmp.path().join("workspace");
        let outside_dir = tmp.path().join("outside_unapproved_vault");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&outside_dir).unwrap();
        // Seed two sibling files with close relevance for resource.resolve disambiguation test
        std::fs::write(ws.join("benchmark_alpha_2026.md"), "# Alpha\n").unwrap();
        std::fs::write(ws.join("benchmark_beta_2026.md"), "# Beta\n").unwrap();

        let core = init_m2a_test_core(tmp.path(), &ws);
        let _ = core.resources.index_authorized_files();
        core.policy
            .add_session_grant("directory", &ws.to_string_lossy(), 60);
        let session = core.sessions.get_or_create(Some("ses_m2a_sec"));
        let active_sel = ActiveBackendSelection {
            backend: "openai".to_string(),
            provider: "mock".to_string(),
            model: "gpt-5.4".to_string(),
            reasoning_effort: "medium".to_string(),
            base_url: None,
            pinned: true,
            auto_selected: false,
            direct_http_capable: true,
            pill_label: "OpenAI · gpt-5.4".to_string(),
        };

        // 1. Recursive `capability_invoke` -> `capability_invoke` (and `capability.invoke` -> `capability.search`) MUST be Denied!
        for forbidden_inner in [
            "capability_invoke",
            "capability.invoke",
            "capability.search",
        ] {
            let mut ledger = TurnEffectLedger::new("turn_m2a_rec");

            let out = execute_quick_chat_tool_call_with_step(
                &core,
                &active_sel,
                BackendExecutionMode::ManagedBrokerTools,
                "task_m2a_rec",
                &session,
                "测试递归元工具拦截",
                false,
                &[Taint::User],
                DataClass::Personal,
                StepInvocationContext::new_call("call_rec_1"),
                "capability_invoke",
                &json!({
                    "capability_id": forbidden_inner,
                    "arguments": { "query": "file" }
                }),
                &mut ledger,
            )
            .await
            .unwrap();

            match out {
                QuickChatToolExecOutcome::ToolMessage {
                    content, is_error, ..
                } => {
                    assert!(
                        is_error,
                        "recursive capability_invoke -> {} MUST be denied as error!",
                        forbidden_inner
                    );
                    let parsed: Value = serde_json::from_str(&content).unwrap();
                    assert_eq!(parsed["was_denied"], true);
                }
                _ => panic!("expected Denied ToolMessage for recursive capability_invoke"),
            }
        }

        // 2. Forbidden credential path (`~/.ssh/id_ed25519`) via `capability_invoke` MUST be Denied identically to direct Broker call!
        {
            let mut ledger = TurnEffectLedger::new("turn_m2a_ssh");

            let out = execute_quick_chat_tool_call_with_step(
                &core,
                &active_sel,
                BackendExecutionMode::ManagedBrokerTools,
                "task_m2a_ssh",
                &session,
                "测试禁止路径拦截",
                false,
                &[Taint::User],
                DataClass::Personal,
                StepInvocationContext::new_call("call_ssh_1"),
                "capability_invoke",
                &json!({
                    "capability_id": "file.write",
                    "arguments": {
                        "path": "~/.ssh/id_ed25519",
                        "content": "never_allowed"
                    }
                }),
                &mut ledger,
            )
            .await
            .unwrap();

            match out {
                QuickChatToolExecOutcome::ToolMessage {
                    content, is_error, ..
                } => {
                    assert!(is_error, "capability_invoke on ~/.ssh MUST be hard Denied!");
                    let parsed: Value = serde_json::from_str(&content).unwrap();
                    assert_eq!(parsed["was_denied"], true);
                }
                _ => panic!("expected hard Denied ToolMessage on ~/.ssh"),
            }
        }

        // 3. `StrictIsolated` privacy policy (`incognito = true`) via `capability_invoke` -> `memory_recall_mentioned_files` MUST be Denied!
        {
            let mut ledger = TurnEffectLedger::new("turn_m2a_incog");

            let out = execute_quick_chat_tool_call_with_step(
                &core,
                &active_sel,
                BackendExecutionMode::ManagedBrokerTools,
                "task_m2a_incog",
                &session,
                "测试无痕模式记忆隔离",
                true,
                &[Taint::User],
                DataClass::Personal,
                StepInvocationContext::new_call("call_incog_1"),
                "capability_invoke",
                &json!({
                    "capability_id": "memory_recall_mentioned_files",
                    "arguments": { "query": "budget" }
                }),
                &mut ledger,
            )
            .await
            .unwrap();

            match out {
                QuickChatToolExecOutcome::ToolMessage { is_error, .. } => {
                    assert!(
                        is_error,
                        "capability_invoke on memory tool under StrictIsolated MUST be Denied!"
                    );
                }
                _ => panic!("expected Denied ToolMessage under StrictIsolated"),
            }
        }

        // 4. Outside-scope normal path via `capability_invoke` MUST trigger `RequiresApproval` (`PendingApproval`)
        //    AND seamlessly resume on `resume_approved_turn_with_options`!
        let outside_file = outside_dir.join("external_audit_note.md");
        let appr_state = M2AApprovalInvokeMockState {
            calls: Arc::new(Mutex::new(0)),
            outside_file: outside_file.to_string_lossy().to_string(),
        };
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                post(mock_m2a_approval_invoke_completions),
            )
            .with_state(appr_state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mock_home = tmp.path().join("mock_home_appr");
        std::fs::create_dir_all(&mock_home).unwrap();
        let opts = DiscoveryOptions::isolated_for_test(mock_home);
        set_active_backend_with_options(
            &core,
            &json!({
                "backend": "openai",
                "provider": "m2a-appr-openai",
                "model": "gpt-5.4",
                "base_url": format!("http://{}/v1", addr),
                "api_key": "sk-m2a-appr-test-key-123456"
            }),
            &opts,
        )
        .await
        .unwrap();

        let paused_res = send_quick_chat_turn_with_options(
            &core,
            &json!({
                "session_id": "ses_m2a_appr",
                "text": "请把审计记录写入外部目录文件",
            }),
            &opts,
        )
        .await
        .unwrap();

        assert_eq!(
            paused_res["status"], "awaiting_approval",
            "capability_invoke outside authorized_directories MUST pause for PendingApproval: {}",
            paused_res
        );
        assert!(
            !outside_file.exists(),
            "outside file MUST NOT be written before user approval!"
        );
        let approval_id = paused_res["pending_approval"]["approval_id"]
            .as_str()
            .expect("approval_id")
            .to_string();
        assert_eq!(
            paused_res["pending_approval"]["capability_id"], "file.write",
            "PendingApproval must surface unwrapped target capability_id!"
        );

        let resumed_res = resume_approved_turn_with_options(
            &core,
            &json!({
                "approval_id": approval_id,
                "decision": "once"
            }),
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(resumed_res["status"], "completed");
        assert!(
            outside_file.exists(),
            "outside file MUST exist after approving capability_invoke!"
        );

        // 5. Verify `resource.resolve` disambiguation + `StrictIsolated` memory isolation + `app.discover`
        let ledger = TurnEffectLedger::new("turn_m2a_resolve");
        let (_, _, res_ambig, _, _) = execute_resource_resolve(
            &core,
            Some(&session),
            &session.session_id,
            PrivacySessionPolicy::Standard,
            &json!({ "query": "benchmark", "kind": "file" }),
            &ledger,
        );
        assert_eq!(res_ambig["status"], "ambiguous");
        assert_eq!(res_ambig["ambiguous"], true);
        assert!(res_ambig["clarification_prompt"].is_string());

        let (_, _, res_incog, _, _) = execute_resource_resolve(
            &core,
            Some(&session),
            &session.session_id,
            PrivacySessionPolicy::StrictIsolated,
            &json!({ "query": "benchmark", "kind": "file" }),
            &ledger,
        );
        assert_eq!(res_incog["memory_isolated"], true);

        let (disc_status, _, disc_data, _, _) = execute_app_discover(
            &core,
            &json!({ "query": "LibreOffice", "live_probe": false }),
        )
        .await;
        assert_eq!(disc_status, ExecutionStatus::Exited);
        assert!(disc_data["adapter_profiles"].is_array());
        assert!(disc_data["supported_channels_architecture"].is_array());
    }
}
