#![forbid(unsafe_code)]

//! Intent Engine & Multi-Source Candidate Scorer (`intent_engine`, §3.1, §4.1–§4.7, §11.6).
//!
//! Submodules:
//! - `pattern_compiler`: Dynamic descriptor pattern compilation (`l0_patterns`, `aliases`, colloquial rules, Pinyin index)
//! - `fuzzy_scorer`: Multi-factor fuzzy scorer (`Exact > Prefix > Alias/Synonym > Pinyin > FuzzyEditBigram` + Frecency)
//! - `slot_extractor`: Universal schema-driven slot extraction (numbers, percentages, Chinese numerals, relative adjustments, time ranges, file sizes, extensions/categories, directories)
//! - `context_resolver`: Multi-turn pronoun (`它`, `刚才那个文件`, `这些文件`) & desktop context (`当前窗口`, `选中文本`, `剪贴板`) resolution with ambiguity clarification
//! - `grouped_candidates`: 7-group candidate generator (`direct_intent`, `apps`, `files`, `web`, `settings`, `skills`, `passthrough`) + `Alt+Enter` contextual action menu
//! - `compound_splitter`: Compound multi-step intent splitter & sequential executor via `core.broker.dispatch`

pub mod cognitive_parser;
pub mod compound_splitter;
pub mod context_resolver;
pub mod fuzzy_scorer;
pub mod goal_schema;
pub mod grouped_candidates;
pub mod pattern_compiler;
pub mod slot_extractor;

pub use cognitive_parser::{
    parse_structured_intent, parse_structured_intent_with_llm, resolve_progressive_intent,
};
pub use compound_splitter::{
    CompoundExecutionReport, CompoundPlan, PlannedStep, StepExecutionOutcome, execute_compound,
    execute_compound_with_policy, split_compound_intent, split_into_clauses,
};
pub use context_resolver::{ContextResolutionOutcome, DesktopContext, resolve_context_references};
pub use fuzzy_scorer::{
    FuzzyScoreBreakdown, MatchTier, ScoredCapabilityMatch, char_bigram_similarity,
    is_mixed_pinyin_match, jaro_winkler_similarity, levenshtein_distance, score_descriptor_entry,
    score_query_against_term,
};
pub use goal_schema::{CognitiveIntentKind, GoalContextHints, StructuredIntent};
pub use grouped_candidates::{
    CandidateAction, CandidateGroup, GroupedCandidateItem, GroupedCandidateResponse,
    get_candidate_actions, query_grouped_candidates,
};
pub use pattern_compiler::{
    ColloquialAnalysis, CompiledPattern, DescriptorLexiconEntry, PatternCompiler, PatternMatch,
    analyze_colloquial_input,
};
pub use slot_extractor::{
    FileTypeSlot, LocationSlot, NumericSlot, SizeRangeSlot, TimeRangeSlot, UniversalSlots,
    extract_slots_for_descriptor, extract_universal_slots, parse_chinese_or_arabic_number,
    parse_file_type_slot, parse_location_slots, parse_numeric_slot, parse_size_range_slot,
    parse_time_range_slot,
};

use crate::core::IntentOsCore;
use crate::db::IndexDb;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Cognitive-aware capability ranking: delegates to `fuzzy_scorer::rank_capabilities` while
/// capping single-capability confidence when the utterance is a higher-order cognitive goal,
/// system diagnosis, how-to question, or multi-goal compound task requiring L2 planning.
pub fn rank_capabilities(
    query: &str,
    compiler: &PatternCompiler,
    index_db: Option<&IndexDb>,
    limit: usize,
) -> Vec<ScoredCapabilityMatch> {
    let mut ranked = fuzzy_scorer::rank_capabilities(query, compiler, index_db, limit);
    let structured = parse_structured_intent(query, &[]);
    if structured.should_escalate_to_l2() {
        for item in &mut ranked {
            item.confidence = item.confidence.min(0.45);
        }
    }
    ranked
}

/// Comprehensive intent analysis report returned by `"analyze_intent"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentAnalysisReport {
    pub original_text: String,
    pub effective_text: String,
    pub colloquial: ColloquialAnalysis,
    pub context_resolution: ContextResolutionOutcome,
    pub universal_slots: UniversalSlots,
    pub compound_plan: CompoundPlan,
    pub structured_intent: StructuredIntent,
    pub top_capabilities: Vec<ScoredCapabilityMatch>,
    pub recommended_capability_id: Option<String>,
    pub recommended_arguments: Value,
    pub confidence: f64,
    pub routing_tier: String,
}

/// Perform full-pipeline intent analysis on `raw_text`.
pub fn analyze_intent_full(
    core: &IntentOsCore,
    raw_text: &str,
    session_id: Option<&str>,
    desktop_ctx: Option<&DesktopContext>,
    compiler: &PatternCompiler,
) -> IntentAnalysisReport {
    let session = session_id.map(|sid| core.sessions.get_or_create(Some(sid)));
    let context_resolution = resolve_context_references(
        raw_text,
        session.as_ref(),
        Some(&core.state_db),
        desktop_ctx,
    );
    let effective_text = context_resolution.effective_text().to_string();
    let colloquial = analyze_colloquial_input(&effective_text);
    let universal_slots = extract_universal_slots(&effective_text, &core.resources);
    let compound_plan = split_compound_intent(core, &effective_text, compiler);
    let snap = crate::capability_snapshot::capability_snapshot_for_core(core);
    let structured_intent = parse_structured_intent(&effective_text, snap.descriptors_slice());
    let top_capabilities = rank_capabilities(&effective_text, compiler, Some(&core.index_db), 5);

    let (recommended_capability_id, recommended_arguments, confidence, routing_tier) =
        if context_resolution.needs_clarification() {
            (None, json!({}), 0.0, "clarify".to_string())
        } else if structured_intent.should_escalate_to_l2() {
            (
                None,
                json!({}),
                structured_intent.confidence,
                "L2".to_string(),
            )
        } else if compound_plan.is_compound && !compound_plan.steps.is_empty() {
            let first = &compound_plan.steps[0];
            (
                Some(first.capability_id.clone()),
                first.arguments.clone(),
                first.confidence,
                "compound_l0".to_string(),
            )
        } else if let Some(top) = top_capabilities.first() {
            let args = core
                .broker
                .get_descriptor(&top.capability_id)
                .map(|desc| {
                    extract_slots_for_descriptor(
                        desc,
                        &effective_text,
                        &top.captured_slots,
                        &core.resources,
                    )
                })
                .unwrap_or_else(|| json!({}));
            let tier = if top.confidence >= 0.80 {
                "L0"
            } else if top.confidence >= 0.55 {
                "L1"
            } else {
                "L2"
            };
            (
                Some(top.capability_id.clone()),
                args,
                top.confidence,
                tier.to_string(),
            )
        } else if let Some(step) = compound_plan.steps.first() {
            (
                Some(step.capability_id.clone()),
                step.arguments.clone(),
                step.confidence,
                "L0".to_string(),
            )
        } else {
            (None, json!({}), 0.20, "L2".to_string())
        };

    IntentAnalysisReport {
        original_text: raw_text.to_string(),
        effective_text,
        colloquial,
        context_resolution,
        universal_slots,
        compound_plan,
        structured_intent,
        top_capabilities,
        recommended_capability_id,
        recommended_arguments,
        confidence,
        routing_tier,
    }
}

/// Unified RPC entry point for the `intent_engine` module.
///
/// Supported actions:
/// - `"ping"`
/// - `"query_grouped_candidates"`
/// - `"get_candidate_actions"`
/// - `"analyze_intent"`
/// - `"parse_structured_intent"`
/// - `"execute_compound"`
/// - `"record_candidate_feedback"`
pub async fn handle_module_rpc(
    core: &IntentOsCore,
    action: &str,
    payload: Value,
) -> anyhow::Result<Value> {
    let snap = crate::capability_snapshot::capability_snapshot_for_core(core);
    let compiler = snap.pattern_compiler.as_ref();

    match action {
        "ping" => {
            let pattern_count: usize = compiler
                .entries()
                .iter()
                .map(|e| e.compiled_patterns.len())
                .sum();
            Ok(json!({
                "ok": true,
                "module": "intent_engine",
                "status": "ready",
                "descriptor_count": snap.len(),
                "snapshot_version": snap.version,
                "compiled_pattern_count": pattern_count,
                "supported_actions": [
                    "ping",
                    "query_grouped_candidates",
                    "get_candidate_actions",
                    "analyze_intent",
                    "parse_structured_intent",
                    "resolve_progressive_intent",
                    "execute_compound",
                    "record_candidate_feedback"
                ]
            }))
        }

        "query_grouped_candidates" => {
            let raw_query = payload
                .get("query")
                .or_else(|| payload.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let category_filter = payload
                .get("category_filter")
                .or_else(|| payload.get("category"))
                .and_then(|v| v.as_str());
            let session_id = payload.get("session_id").and_then(|v| v.as_str());
            let desktop_ctx: Option<DesktopContext> = payload
                .get("desktop_context")
                .and_then(|v| serde_json::from_value(v.clone()).ok());

            let session = session_id.map(|sid| core.sessions.get_or_create(Some(sid)));
            let ctx_res = resolve_context_references(
                raw_query,
                session.as_ref(),
                Some(&core.state_db),
                desktop_ctx.as_ref(),
            );
            let effective_query = ctx_res.effective_text();

            let resp = query_grouped_candidates(core, effective_query, category_filter, compiler);
            let mut val = serde_json::to_value(resp)?;
            if let Some(obj) = val.as_object_mut() {
                obj.insert(
                    "context_resolution".to_string(),
                    serde_json::to_value(&ctx_res)?,
                );
            }
            Ok(val)
        }

        "get_candidate_actions" => {
            let candidate_id = payload
                .get("candidate_id")
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kind = payload
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("intent");
            let target = payload.get("target").and_then(|v| v.as_str());
            let capability_id = payload.get("capability_id").and_then(|v| v.as_str());
            let arguments = payload
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            let actions =
                get_candidate_actions(core, candidate_id, kind, target, capability_id, &arguments);
            Ok(json!({
                "candidate_id": candidate_id,
                "kind": kind,
                "actions": actions
            }))
        }

        "analyze_intent" => {
            let text = payload
                .get("text")
                .or_else(|| payload.get("query"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let session_id = payload.get("session_id").and_then(|v| v.as_str());
            let desktop_ctx: Option<DesktopContext> = payload
                .get("desktop_context")
                .and_then(|v| serde_json::from_value(v.clone()).ok());

            let report =
                analyze_intent_full(core, text, session_id, desktop_ctx.as_ref(), compiler);
            Ok(serde_json::to_value(report)?)
        }

        "parse_structured_intent" | "resolve_progressive_intent" => {
            let raw_text = payload
                .get("text")
                .or_else(|| payload.get("query"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let session_id = payload.get("session_id").and_then(|v| v.as_str());
            let desktop_ctx: Option<DesktopContext> = payload
                .get("desktop_context")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let desktop_state_hint = payload.get("desktop_state_hint").and_then(|v| v.as_str());
            let use_llm = payload
                .get("use_llm")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let use_progressive = action == "resolve_progressive_intent"
                || payload
                    .get("progressive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

            let session = session_id.map(|sid| core.sessions.get_or_create(Some(sid)));
            let ctx_res = resolve_context_references(
                raw_text,
                session.as_ref(),
                Some(&core.state_db),
                desktop_ctx.as_ref(),
            );
            let effective_text = ctx_res.effective_text();

            let structured = if use_progressive {
                resolve_progressive_intent(
                    &core.gateway,
                    Some(&core.state_db),
                    effective_text,
                    desktop_state_hint,
                    snap.descriptors_slice(),
                )
                .await
            } else if use_llm {
                parse_structured_intent_with_llm(
                    &core.gateway,
                    effective_text,
                    desktop_state_hint,
                    snap.descriptors_slice(),
                )
                .await
            } else {
                parse_structured_intent(effective_text, snap.descriptors_slice())
            };
            Ok(serde_json::to_value(structured)?)
        }

        "execute_compound" => {
            let raw_text = payload
                .get("text")
                .or_else(|| payload.get("query"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let session_id = payload.get("session_id").and_then(|v| v.as_str());
            let incognito = payload
                .get("incognito")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let desktop_ctx: Option<DesktopContext> = payload
                .get("desktop_context")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let steps_override: Option<Vec<PlannedStep>> = payload
                .get("steps")
                .and_then(|v| serde_json::from_value(v.clone()).ok());

            let session = session_id.map(|sid| core.sessions.get_or_create(Some(sid)));
            let ctx_res = resolve_context_references(
                raw_text,
                session.as_ref(),
                Some(&core.state_db),
                desktop_ctx.as_ref(),
            );
            let effective_text = ctx_res.effective_text();

            let report = execute_compound(
                core,
                effective_text,
                steps_override,
                session_id,
                incognito,
                compiler,
            )
            .await?;
            Ok(serde_json::to_value(report)?)
        }

        "record_candidate_feedback" => {
            let item_key = payload
                .get("candidate_id")
                .or_else(|| payload.get("item_key"))
                .or_else(|| payload.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let capability_id = payload.get("capability_id").and_then(|v| v.as_str());
            let query = payload.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let accepted = payload
                .get("accepted")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            if !item_key.is_empty() && accepted {
                core.index_db.record_frecency(item_key);
            }
            if let Some(cap) = capability_id
                && !cap.is_empty()
                && accepted
            {
                core.index_db.record_frecency(&format!("cap:{}", cap));
                core.state_db
                    .record_decision_calibration(query, "L0", 0.95, 0.45, 0.0, 0.0, "executed");
            }

            let new_boost = if !item_key.is_empty() {
                core.index_db.get_frecency_boost(item_key)
            } else {
                0.0
            };

            Ok(json!({
                "ok": true,
                "item_key": item_key,
                "frecency_boost": new_boost
            }))
        }

        other => anyhow::bail!("intent_engine: 未知的 RPC action '{}'", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn setup_test_core() -> (TempDir, Arc<IntentOsCore>) {
        let tmp = TempDir::new().expect("create temp dir");
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .to_path_buf();
        let core =
            IntentOsCore::initialize(Some(tmp.path()), repo_root).expect("initialize IntentOsCore");
        (tmp, core)
    }

    #[test]
    fn test_pattern_compiler_and_pinyin_colloquial_scoring() {
        let (_tmp, core) = setup_test_core();
        let descriptors = core.broker.descriptors();
        let compiler = PatternCompiler::compile_from_descriptors(&descriptors);

        // 1. Pinyin initials `hyms` -> 护眼模式 (`scene.apply`)
        let hyms_ranked = rank_capabilities("hyms", &compiler, Some(&core.index_db), 5);
        assert!(
            !hyms_ranked.is_empty(),
            "hyms should match capabilities via pinyin initials"
        );
        assert_eq!(hyms_ranked[0].capability_id, "scene.apply");

        // 2. Mixed pinyin `hymoshi` -> 护眼模式
        assert!(is_mixed_pinyin_match("hymoshi", "护眼模式"));
        let mixed_ranked = rank_capabilities("hymoshi", &compiler, Some(&core.index_db), 5);
        assert!(!mixed_ranked.is_empty());
        assert_eq!(mixed_ranked[0].capability_id, "scene.apply");

        // 3. Colloquial `声音小点` / `把声音搞小点` -> `sound.volume.set`
        let vol_ranked = rank_capabilities("声音小点", &compiler, Some(&core.index_db), 5);
        assert!(!vol_ranked.is_empty());
        assert_eq!(vol_ranked[0].capability_id, "sound.volume.set");

        // 4. Colloquial `暗一点` -> `display.brightness.set`
        let bright_ranked = rank_capabilities("屏幕暗一点", &compiler, Some(&core.index_db), 5);
        assert!(!bright_ranked.is_empty());
        assert_eq!(bright_ranked[0].capability_id, "display.brightness.set");
    }

    #[test]
    fn test_universal_slot_extraction() {
        let (_tmp, core) = setup_test_core();

        // 1. Numeric & relative adjustment slots
        let slot_abs = parse_numeric_slot("把音量调到 35%", Some(0.0), Some(100.0)).unwrap();
        assert_eq!(slot_abs.value, Some(35.0));
        assert!(slot_abs.is_percentage);

        let slot_cn = parse_numeric_slot("音量设为三十", Some(0.0), Some(100.0)).unwrap();
        assert_eq!(slot_cn.value, Some(30.0));

        let slot_max = parse_numeric_slot("把音量拉满", Some(0.0), Some(100.0)).unwrap();
        assert_eq!(slot_max.value, Some(100.0));

        let slot_rel = parse_numeric_slot("声音调小一点", Some(0.0), Some(100.0)).unwrap();
        assert_eq!(slot_rel.relative.as_deref(), Some("down"));

        let slot_delta = parse_numeric_slot("亮度 +15%", Some(1.0), Some(100.0)).unwrap();
        assert_eq!(slot_delta.relative.as_deref(), Some("up"));
        assert_eq!(slot_delta.delta, Some(15.0));

        // 2. Time range & size range & file type slots
        let tr = parse_time_range_slot("找上周修改的报告").unwrap();
        assert_eq!(tr.modified_within_days, Some(14));

        let tr_days = parse_time_range_slot("最近3天的日志").unwrap();
        assert_eq!(tr_days.modified_within_days, Some(3));

        let sr = parse_size_range_slot("查找大于 2G 且小于 10G 的视频").unwrap();
        assert_eq!(sr.min_size_bytes, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(sr.max_size_bytes, Some(10 * 1024 * 1024 * 1024));

        let ft = parse_file_type_slot("搜索所有的表格").unwrap();
        assert_eq!(ft.primary_ext.as_deref(), Some("xlsx"));

        // 3. Schema-driven slot extraction for `sound.volume.set` and `appearance.text_scale.set`
        let vol_desc = core.broker.get_descriptor("sound.volume.set").unwrap();
        let vol_args = extract_slots_for_descriptor(
            vol_desc,
            "声音小一点",
            &std::collections::HashMap::new(),
            &core.resources,
        );
        assert_eq!(
            vol_args.get("relative").and_then(|v| v.as_str()),
            Some("down")
        );

        let scale_desc = core
            .broker
            .get_descriptor("appearance.text_scale.set")
            .unwrap();
        let scale_args = extract_slots_for_descriptor(
            scale_desc,
            "缩放调到 125%",
            &std::collections::HashMap::new(),
            &core.resources,
        );
        assert_eq!(scale_args.get("value").and_then(|v| v.as_f64()), Some(1.25));
    }

    #[test]
    fn test_context_and_pronoun_resolution() {
        let (_tmp, core) = setup_test_core();

        // 1. Resolve singular pronoun `它` / `刚才那个文件` from session's `last_resource_path`
        let sess = core.sessions.get_or_create(Some("sess-ctx-1"));
        core.sessions.append_turn(
            &sess.session_id,
            "查找周报",
            "找到文件 /tmp/weekly_report.pdf",
            Some("/tmp/weekly_report.pdf".to_string()),
        );
        let updated_sess = core.sessions.get_or_create(Some("sess-ctx-1"));
        let res = resolve_context_references(
            "打开刚才那个文件",
            Some(&updated_sess),
            Some(&core.state_db),
            None,
        );
        assert!(res.is_resolved());
        assert_eq!(res.effective_text(), "打开/tmp/weekly_report.pdf");

        // 2. Desktop context resolution (`当前窗口`, `剪贴板`)
        let dctx = DesktopContext {
            active_window: Some("Firefox".to_string()),
            selected_text: Some("IntentOS Architecture".to_string()),
            clipboard_text: Some("https://example.com/spec".to_string()),
            selected_files: Vec::new(),
            cwd: None,
        };
        let win_res = resolve_context_references("关闭当前窗口", None, None, Some(&dctx));
        assert_eq!(win_res.effective_text(), "关闭Firefox");

        // 3. Ambiguity clarification when multiple files are selected and user says singular `它`
        let multi_dctx = DesktopContext {
            active_window: None,
            selected_text: None,
            clipboard_text: None,
            selected_files: vec!["/tmp/a.pdf".to_string(), "/tmp/b.pdf".to_string()],
            cwd: None,
        };
        let ambig_res = resolve_context_references("删除它", None, None, Some(&multi_dctx));
        assert!(ambig_res.needs_clarification());
    }

    #[tokio::test]
    async fn test_compound_intent_splitting_and_execution() {
        let (_tmp, core) = setup_test_core();
        let descriptors = core.broker.descriptors();
        let compiler = PatternCompiler::compile_from_descriptors(&descriptors);

        // 1. Split `静音并开启勿扰模式` into 2 ordered steps
        let plan = split_compound_intent(&core, "静音并开启勿扰模式", &compiler);
        assert!(plan.is_compound);
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].capability_id, "sound.mute.set");
        assert_eq!(plan.steps[1].capability_id, "notify.dnd.set");

        // 2. Split `把音量调到20然后开启护眼模式`
        let plan2 = split_compound_intent(&core, "把音量调到20然后开启护眼模式", &compiler);
        assert!(plan2.is_compound);
        assert_eq!(plan2.steps.len(), 2);
        assert_eq!(plan2.steps[0].capability_id, "sound.volume.set");
        assert_eq!(
            plan2.steps[0]
                .arguments
                .get("value")
                .and_then(|v| v.as_f64()),
            Some(20.0)
        );
        assert_eq!(plan2.steps[1].capability_id, "scene.apply");

        // 3. Execute compound intent via `execute_compound`
        let exec_report = execute_compound(
            &core,
            "静音并开启勿扰模式",
            None,
            Some("sess-compound-test"),
            false,
            &compiler,
        )
        .await
        .expect("execute compound");
        assert!(exec_report.is_compound);
        assert_eq!(exec_report.total_steps, 2);
        assert_eq!(exec_report.completed_steps, 2);
        assert!(exec_report.all_succeeded);
    }

    #[tokio::test]
    async fn test_handle_module_rpc_all_actions() {
        let (_tmp, core) = setup_test_core();

        // 1. ping
        let ping_res = handle_module_rpc(&core, "ping", json!({})).await.unwrap();
        assert_eq!(ping_res.get("ok").and_then(|v| v.as_bool()), Some(true));

        // 2. query_grouped_candidates
        let cand_res = handle_module_rpc(
            &core,
            "query_grouped_candidates",
            json!({ "query": "hyms", "category_filter": "all" }),
        )
        .await
        .unwrap();
        assert!(
            cand_res
                .get("total_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0
        );
        assert!(cand_res.get("groups").and_then(|v| v.as_array()).is_some());

        // 3. get_candidate_actions (`Alt+Enter` contextual actions for file, app, web, setting)
        let file_actions = handle_module_rpc(
            &core,
            "get_candidate_actions",
            json!({
                "candidate_id": "file:/tmp/report.pdf",
                "kind": "file",
                "target": "/tmp/report.pdf"
            }),
        )
        .await
        .unwrap();
        let action_ids: Vec<&str> = file_actions
            .get("actions")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|a| a.get("id").and_then(|x| x.as_str()))
            .collect();
        assert!(action_ids.contains(&"open"));
        assert!(action_ids.contains(&"open_with"));
        assert!(action_ids.contains(&"reveal"));
        assert!(action_ids.contains(&"copy_path"));
        assert!(action_ids.contains(&"rename"));
        assert!(action_ids.contains(&"trash"));

        // 4. analyze_intent
        let analysis = handle_module_rpc(
            &core,
            "analyze_intent",
            json!({ "text": "把音量调到 30% 然后开启护眼模式" }),
        )
        .await
        .unwrap();
        assert_eq!(
            analysis
                .get("compound_plan")
                .and_then(|p| p.get("is_compound"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        // 4b. parse_structured_intent RPC action
        let thesis_goal = handle_module_rpc(
            &core,
            "parse_structured_intent",
            json!({ "text": "今天想专心写论文" }),
        )
        .await
        .unwrap();
        assert_eq!(
            thesis_goal.get("intent_type").and_then(|v| v.as_str()),
            Some("goal_workspace")
        );
        assert_eq!(
            thesis_goal.get("goal").and_then(|v| v.as_str()),
            Some("进入论文写作专注状态")
        );
        assert_eq!(
            thesis_goal
                .get("requires_planning")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            thesis_goal
                .get("recommended_route")
                .and_then(|v| v.as_str()),
            Some("L2")
        );

        let diag_goal = handle_module_rpc(
            &core,
            "parse_structured_intent",
            json!({ "text": "电脑最近有点卡", "use_llm": true }),
        )
        .await
        .unwrap();
        assert_eq!(
            diag_goal.get("intent_type").and_then(|v| v.as_str()),
            Some("system_diagnosis")
        );
        assert_eq!(
            diag_goal.get("recommended_route").and_then(|v| v.as_str()),
            Some("L2")
        );

        let noisy_rel = handle_module_rpc(
            &core,
            "parse_structured_intent",
            json!({ "text": "声音有点吵" }),
        )
        .await
        .unwrap();
        assert_eq!(
            noisy_rel.get("intent_type").and_then(|v| v.as_str()),
            Some("relative_adjustment")
        );
        assert_eq!(
            noisy_rel
                .get("direct_capability")
                .and_then(|v| v.get(0))
                .and_then(|v| v.as_str()),
            Some("sound.volume.set")
        );

        // 5. execute_compound
        let exec_res = handle_module_rpc(
            &core,
            "execute_compound",
            json!({ "text": "把音量调到 40%" }),
        )
        .await
        .unwrap();
        assert_eq!(
            exec_res.get("all_succeeded").and_then(|v| v.as_bool()),
            Some(true)
        );

        // 6. record_candidate_feedback
        let fb_res = handle_module_rpc(
            &core,
            "record_candidate_feedback",
            json!({
                "candidate_id": "cap:scene.apply",
                "capability_id": "scene.apply",
                "query": "hyms",
                "accepted": true
            }),
        )
        .await
        .unwrap();
        assert_eq!(fb_res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(
            fb_res
                .get("frecency_boost")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                > 0.0
        );
    }
}
