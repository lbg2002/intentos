#![forbid(unsafe_code)]

//! Non-Linear Time-Decay Session Context Compressor (`memory_hub/context_compressor.rs`).
//!
//! Solves long-session context overflow using a 4-zone non-linear spatial + temporal decay curve:
//! - Strips all historical tool invocations (`role == "tool"`, `tool_calls`, `tool_steps`, `trace_dots`)
//!   and internal `<think>...</think>` blocks so multi-turn memory retains ONLY user questions
//!   and cleaned assistant answers (`drop_tool_records = true`).
//! - Zone 0 (`d < verbatim_recent_turns`): `w = 1.0`, full verbatim Q&A (safety cap `2800` chars/msg).
//! - Zone 1 (`w in [0.28, 1.0)`): non-linear char budget `2200 * w` (`58%` user question, `42%`
//!   structure-preserving Markdown answer with fenced code blocks folded to `[代码块已折叠]`).
//! - Zone 2 (`w in [0.08, 0.28)`): compact digest (`问：<core <= 110>` / `答（摘要）：<conclusion <= 140>`).
//! - Zone 3 (`w < 0.08` or token budget overflow): rolls up all older turns into a single anchor block
//!   `[早期会话非线性时间衰减摘要（共 K 轮早期问答）]` (`<= 600` chars), strictly guaranteeing
//!   `compressed_estimated_tokens <= max_context_tokens` even on 200+ turn sessions.

use crate::core::IntentOsCore;
use crate::memory_hub::schema_and_db::MemoryHubDb;
use crate::runtime::SessionState;
use crate::security_guard::PrivacySessionPolicy;
use chrono::Utc;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub const CONTEXT_DECAY_META_KEY: &str = "context_decay_config";
const VERBATIM_MSG_CHAR_CAP: usize = 2800;
const ANCIENT_ANCHOR_MAX_CHARS: usize = 600;

fn default_true() -> bool {
    true
}

fn default_max_context_tokens() -> usize {
    6000
}

fn default_verbatim_recent_turns() -> usize {
    3
}

fn default_decay_lambda() -> f64 {
    0.24
}

fn default_decay_gamma() -> f64 {
    1.35
}

/// Persistent configuration for non-linear time-decay context compression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextDecayConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub drop_tool_records: bool,
    #[serde(default = "default_max_context_tokens")]
    pub max_context_tokens: usize,
    #[serde(default = "default_verbatim_recent_turns")]
    pub verbatim_recent_turns: usize,
    #[serde(default = "default_decay_lambda")]
    pub decay_lambda: f64,
    #[serde(default = "default_decay_gamma")]
    pub decay_gamma: f64,
}

impl Default for ContextDecayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            drop_tool_records: true,
            max_context_tokens: 6000,
            verbatim_recent_turns: 3,
            decay_lambda: 0.24,
            decay_gamma: 1.35,
        }
    }
}

impl ContextDecayConfig {
    /// Clamp all numeric parameters into safe, validated operating bounds.
    pub fn sanitized(mut self) -> Self {
        self.max_context_tokens = self.max_context_tokens.clamp(1000, 64000);
        self.verbatim_recent_turns = self.verbatim_recent_turns.clamp(1, 12);
        self.decay_lambda = if self.decay_lambda.is_finite() {
            self.decay_lambda.clamp(0.05, 1.2)
        } else {
            0.24
        };
        self.decay_gamma = if self.decay_gamma.is_finite() {
            self.decay_gamma.clamp(1.0, 2.5)
        } else {
            1.35
        };
        self
    }
}

/// Telemetry & token savings statistics emitted by context compression.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ContextCompressionStats {
    pub enabled: bool,
    pub raw_qa_turns: usize,
    pub included_qa_turns: usize,
    pub rolled_up_ancient_turns: usize,
    pub dropped_tool_records: usize,
    pub raw_estimated_tokens: usize,
    pub compressed_estimated_tokens: usize,
    pub saved_pct: f64,
    pub verbatim_turns: usize,
    pub decayed_turns: usize,
}

/// Per-turn tier diagnostic item returned by `preview_session_compression`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedTurnTierPreview {
    pub turn_index: usize,
    pub distance: usize,
    pub zone: u8,
    pub zone_label: String,
    pub weight: f64,
    pub elapsed_minutes: f64,
    pub raw_chars: usize,
    pub retained_chars: usize,
    pub user_preview: String,
    pub assistant_preview: String,
}

/// Hydrated historical Q&A pair (chronological input to `compress_qa_turns`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HydratedQaTurn {
    pub user_question: String,
    pub clean_assistant_answer: String,
    pub raw_assistant_chars: usize,
    pub dropped_tool_records: usize,
    pub dropped_overhead_tokens: usize,
    pub created_epoch: Option<i64>,
    pub mentioned_entities: Vec<String>,
}

/// Full output for wiring compressed multi-turn history into LLM backends.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompressedSessionHistory {
    pub turns: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancient_summary_anchor: Option<String>,
    pub stats: ContextCompressionStats,
    pub tiers: Vec<CompressedTurnTierPreview>,
}

/// Load `ContextDecayConfig` from `MemoryHubDb` (`schema_meta` key `"context_decay_config"`).
pub fn load_context_decay_config(db: &MemoryHubDb) -> ContextDecayConfig {
    db.get_meta(CONTEXT_DECAY_META_KEY)
        .and_then(|raw| serde_json::from_str::<ContextDecayConfig>(&raw).ok())
        .map(ContextDecayConfig::sanitized)
        .unwrap_or_default()
}

/// Validate and persist `ContextDecayConfig` into `MemoryHubDb`.
pub fn save_context_decay_config(
    db: &MemoryHubDb,
    cfg: &ContextDecayConfig,
) -> anyhow::Result<ContextDecayConfig> {
    let clean = cfg.clone().sanitized();
    let encoded = serde_json::to_string(&clean)?;
    db.set_meta(CONTEXT_DECAY_META_KEY, &encoded)?;
    Ok(clean)
}

fn extract_usize_opt(obj: &serde_json::Map<String, Value>, key: &str) -> Option<usize> {
    let v = obj.get(key)?;
    if let Some(n) = v.as_u64() {
        Some(n as usize)
    } else if let Some(i) = v.as_i64() {
        Some(i.max(0) as usize)
    } else if let Some(f) = v.as_f64() {
        Some(f.max(0.0).round() as usize)
    } else {
        v.as_str().and_then(|s| s.trim().parse::<usize>().ok())
    }
}

fn extract_f64_opt(obj: &serde_json::Map<String, Value>, key: &str) -> Option<f64> {
    let v = obj.get(key)?;
    if let Some(f) = v.as_f64() {
        Some(f)
    } else {
        v.as_str().and_then(|s| s.trim().parse::<f64>().ok())
    }
}

/// Apply a partial or complete JSON config update onto an existing `ContextDecayConfig`.
pub fn apply_config_patch(base: &ContextDecayConfig, payload: &Value) -> ContextDecayConfig {
    let target = payload
        .get("config")
        .filter(|v| v.is_object())
        .unwrap_or(payload);
    let Some(obj) = target.as_object() else {
        return base.clone().sanitized();
    };

    let mut next = base.clone();
    if let Some(b) = obj.get("enabled").and_then(|v| v.as_bool()) {
        next.enabled = b;
    }
    if let Some(b) = obj.get("drop_tool_records").and_then(|v| v.as_bool()) {
        next.drop_tool_records = b;
    }
    if let Some(m) = extract_usize_opt(obj, "max_context_tokens") {
        next.max_context_tokens = m;
    }
    if let Some(v) = extract_usize_opt(obj, "verbatim_recent_turns") {
        next.verbatim_recent_turns = v;
    }
    if let Some(preset) = obj.get("preset").and_then(|v| v.as_str()) {
        match preset.trim() {
            "gentle" | "mild" | "温和" => {
                next.decay_lambda = 0.15;
                next.decay_gamma = 1.2;
            }
            "standard" | "balanced" | "标准" => {
                next.decay_lambda = 0.24;
                next.decay_gamma = 1.35;
            }
            "compact" | "aggressive" | "紧凑" => {
                next.decay_lambda = 0.38;
                next.decay_gamma = 1.55;
            }
            _ => {}
        }
    }
    if let Some(l) = extract_f64_opt(obj, "decay_lambda") {
        next.decay_lambda = l;
    }
    if let Some(g) = extract_f64_opt(obj, "decay_gamma") {
        next.decay_gamma = g;
    }
    next.sanitized()
}

/// Update & persist `ContextDecayConfig` from a ModuleRpc JSON payload.
pub fn update_context_decay_config_from_json(
    db: &MemoryHubDb,
    payload: &Value,
) -> anyhow::Result<ContextDecayConfig> {
    let current = load_context_decay_config(db);
    let updated = apply_config_patch(&current, payload);
    save_context_decay_config(db, &updated)
}

/// Estimate LLM token count accurately across mixed CJK and ASCII/code text.
pub fn estimate_text_tokens(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    let mut cjk_or_wide = 0usize;
    let mut ascii = 0usize;
    for ch in text.chars() {
        if ch.is_ascii() {
            ascii += 1;
        } else {
            cjk_or_wide += 1;
        }
    }
    // ~0.68 tokens per CJK char + ~0.28 tokens per ASCII char + framing overhead
    let est = (cjk_or_wide as f64) * 0.68 + (ascii as f64) * 0.28;
    est.ceil().max(1.0) as usize
}

fn estimate_pair_tokens(user_q: &str, asst_a: &str) -> usize {
    estimate_text_tokens(user_q) + estimate_text_tokens(asst_a) + 8
}

/// Strip `<think>...</think>` and `<thinking>...</thinking>` blocks (including unclosed trailing blocks).
pub fn strip_thinking_blocks(raw: &str) -> String {
    static CLOSED_THINK_RE: OnceLock<Regex> = OnceLock::new();
    static EXCESS_BLANK_RE: OnceLock<Regex> = OnceLock::new();

    let closed_re = CLOSED_THINK_RE.get_or_init(|| {
        Regex::new(r"(?is)<think(?:ing)?>(.*?)</think(?:ing)?>").expect("valid think regex")
    });
    let blank_re =
        EXCESS_BLANK_RE.get_or_init(|| Regex::new(r"\n{3,}").expect("valid blank regex"));

    let mut stripped = closed_re.replace_all(raw, "").to_string();
    let lower = stripped.to_ascii_lowercase();
    if let Some(open_idx) = lower.find("<think>").or_else(|| lower.find("<thinking>")) {
        stripped.truncate(open_idx);
    }
    blank_re
        .replace_all(stripped.trim(), "\n\n")
        .trim()
        .to_string()
}

/// Non-linear retention weight `w(d, delta_t)` for turn distance `d` (`0` = latest prior Q&A pair)
/// and optional elapsed minutes `delta_minutes >= 0`.
pub fn compute_retention_weight(
    d: usize,
    delta_minutes: Option<f64>,
    cfg: &ContextDecayConfig,
) -> f64 {
    if d < cfg.verbatim_recent_turns {
        return 1.0;
    }
    let spatial = (-cfg.decay_lambda * (d as f64).powf(cfg.decay_gamma)).exp();
    let dt = delta_minutes.unwrap_or(0.0).max(0.0);
    let temporal = 1.0 / (1.0 + 0.06 * (1.0 + dt / 30.0).ln());
    (spatial * temporal).clamp(0.0, 1.0)
}

fn truncate_chars_clean(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let trimmed = input.trim();
    let total = trimmed.chars().count();
    if total <= max_chars {
        return trimmed.to_string();
    }
    if max_chars <= 1 {
        return "…".to_string();
    }
    let kept: String = trimmed.chars().take(max_chars - 1).collect();
    format!("{}…", kept.trim_end())
}

fn fold_fenced_code_blocks(markdown: &str) -> String {
    static CODE_BLOCK_RE: OnceLock<Regex> = OnceLock::new();
    let re = CODE_BLOCK_RE
        .get_or_init(|| Regex::new(r"(?s)```[^\n]*\n.*?```").expect("valid codefence regex"));
    let folded = re.replace_all(markdown, "[代码块已折叠]").to_string();
    // Handle any unclosed trailing code fence
    if let Some(idx) = folded.find("```") {
        let mut s = folded[..idx].trim_end().to_string();
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str("[代码块已折叠]");
        return s;
    }
    folded
}

fn line_has_salient_structure_or_entity(line: &str) -> bool {
    let t = line.trim();
    if t.starts_with('#')
        || t.starts_with("- ")
        || t.starts_with("* ")
        || t.starts_with("• ")
        || t.contains("[代码块已折叠]")
        || t.contains('/')
        || t.contains("《")
        || t.contains(".desktop")
    {
        return true;
    }
    // Numbered list like `1. ...`
    let mut chars = t.chars();
    chars.next().is_some_and(|c| c.is_ascii_digit()) && chars.take(3).any(|c| c == '.' || c == '、')
}

/// Structure-aware Markdown answer compressor for Zone 1 (`w in [0.28, 1.0)`):
/// folds fenced code blocks into `[代码块已折叠]` and retains opening context, headings,
/// bullet points, `/path/...` entities, and closing conclusion within `char_budget`.
pub fn compress_markdown_answer(answer: &str, char_budget: usize) -> String {
    if char_budget == 0 {
        return String::new();
    }
    let cleaned = strip_thinking_blocks(answer);
    let folded = fold_fenced_code_blocks(&cleaned);
    if folded.chars().count() <= char_budget {
        return folded;
    }

    let lines: Vec<&str> = folded
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return truncate_chars_clean(&folded, char_budget);
    }
    if lines.len() == 1 {
        return truncate_chars_clean(lines[0], char_budget);
    }

    let first_line = lines[0];
    let last_line = *lines.last().unwrap_or(&"");
    let reserve_tail = if lines.len() >= 2 && last_line != first_line {
        last_line.chars().count().min(char_budget / 3) + 2
    } else {
        0
    };

    let head_budget = char_budget.saturating_sub(reserve_tail).max(24);
    let mut selected: Vec<String> = Vec::new();
    let mut used = 0usize;

    let first_clipped = truncate_chars_clean(first_line, (head_budget * 2 / 3).max(24));
    used += first_clipped.chars().count();
    selected.push(first_clipped);

    for line in lines.iter().skip(1).take(lines.len().saturating_sub(2)) {
        if !line_has_salient_structure_or_entity(line) {
            continue;
        }
        let rem = head_budget.saturating_sub(used + 1);
        if rem < 14 {
            break;
        }
        let clipped = truncate_chars_clean(line, rem.min(120));
        used += clipped.chars().count() + 1;
        selected.push(clipped);
    }

    if reserve_tail > 0 {
        let joined_head = selected.join("\n");
        let rem_for_tail = char_budget.saturating_sub(joined_head.chars().count() + 1);
        if rem_for_tail >= 10 {
            selected.push(truncate_chars_clean(last_line, rem_for_tail));
        }
    }

    truncate_chars_clean(&selected.join("\n"), char_budget)
}

fn compact_single_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_core_question_digest(question: &str, max_chars: usize) -> String {
    let single = compact_single_line(&strip_thinking_blocks(question));
    truncate_chars_clean(&single, max_chars)
}

fn extract_paths_and_titles(text: &str) -> Vec<String> {
    static PATH_RE: OnceLock<Regex> = OnceLock::new();
    static BOOK_RE: OnceLock<Regex> = OnceLock::new();

    let path_re = PATH_RE.get_or_init(|| {
        Regex::new(r"(?:~|/)[A-Za-z0-9._\-\u4e00-\u9fff/]{2,96}").expect("valid path regex")
    });
    let book_re =
        BOOK_RE.get_or_init(|| Regex::new(r"《[^》\n]{1,40}》").expect("valid book title regex"));

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for m in path_re.find_iter(text) {
        let p = m
            .as_str()
            .trim_end_matches(['.', ',', '，', '。', ')', '）', '`', '"', '\'']);
        if p.len() > 2 && seen.insert(p.to_string()) {
            out.push(p.to_string());
        }
    }
    for m in book_re.find_iter(text) {
        let b = m.as_str();
        if seen.insert(b.to_string()) {
            out.push(b.to_string());
        }
    }
    out
}

fn extract_answer_digest(answer: &str, max_chars: usize) -> String {
    let cleaned = fold_fenced_code_blocks(&strip_thinking_blocks(answer));
    let lines: Vec<&str> = cleaned
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "[代码块已折叠]")
        .collect();
    let conclusion = lines.first().copied().unwrap_or_else(|| cleaned.trim());
    let entities = extract_paths_and_titles(&cleaned);
    let base = compact_single_line(conclusion);
    if entities.is_empty() || base.contains(&entities[0]) {
        truncate_chars_clean(&base, max_chars)
    } else {
        let joined_ents = entities.into_iter().take(2).collect::<Vec<_>>().join(", ");
        let combined = format!("{} [涉及: {}]", base, joined_ents);
        truncate_chars_clean(&combined, max_chars)
    }
}

fn build_ancient_rollup_anchor(
    ancient_turns: &[&HydratedQaTurn],
    max_chars: usize,
) -> Option<String> {
    if ancient_turns.is_empty() || max_chars < 40 {
        return None;
    }
    let count = ancient_turns.len();
    let header = format!("[早期会话非线性时间衰减摘要（共 {} 轮早期问答）]", count);
    let body_budget = max_chars.saturating_sub(header.chars().count() + 1);
    if body_budget < 16 {
        return Some(truncate_chars_clean(&header, max_chars));
    }

    let mut topics: Vec<String> = Vec::new();
    let mut entities_set: BTreeSet<String> = BTreeSet::new();

    // Sample representative topics across ancient turns (most recent ancient turns first, plus earliest anchor)
    for t in ancient_turns.iter().rev().take(8) {
        let topic = extract_core_question_digest(&t.user_question, 28);
        if !topic.is_empty() && !topics.iter().any(|x| x == &topic) {
            topics.push(topic);
        }
        for e in &t.mentioned_entities {
            let clean_e = e.trim();
            if !clean_e.is_empty() && entities_set.len() < 8 {
                entities_set.insert(clean_e.to_string());
            }
        }
        for e in
            extract_paths_and_titles(&format!("{} {}", t.user_question, t.clean_assistant_answer))
        {
            if entities_set.len() < 8 {
                entities_set.insert(e);
            }
        }
    }
    if ancient_turns.len() > 8
        && let Some(oldest) = ancient_turns.first()
    {
        let oldest_topic = extract_core_question_digest(&oldest.user_question, 24);
        if !oldest_topic.is_empty() && !topics.iter().any(|x| x == &oldest_topic) {
            topics.push(oldest_topic);
        }
    }

    let mut lines = Vec::new();
    if !topics.is_empty() {
        lines.push(format!("早期主题：{}", topics.join("；")));
    }
    if !entities_set.is_empty() {
        let ents: Vec<String> = entities_set.into_iter().take(6).collect();
        lines.push(format!("关键实体：{}", ents.join("、")));
    }
    let body = truncate_chars_clean(&lines.join("\n"), body_budget);
    if body.is_empty() {
        Some(header)
    } else {
        Some(truncate_chars_clean(
            &format!("{}\n{}", header, body),
            max_chars.min(ANCIENT_ANCHOR_MAX_CHARS),
        ))
    }
}

/// Detailed compression result tuple `(turns, ancient_summary_anchor, stats, tiers)`.
pub type DetailedCompressionResult = (
    Vec<(String, String)>,
    Option<String>,
    ContextCompressionStats,
    Vec<CompressedTurnTierPreview>,
);

/// Core 4-zone non-linear time-decay compression engine over chronological `HydratedQaTurn`s.
pub fn compress_qa_turns_detailed(
    turns: &[HydratedQaTurn],
    raw_cfg: &ContextDecayConfig,
    now_epoch: i64,
) -> DetailedCompressionResult {
    let cfg = raw_cfg.clone().sanitized();
    let total_turns = turns.len();

    let mut dropped_tool_records = 0usize;
    let mut raw_estimated_tokens = 0usize;
    for t in turns {
        if cfg.drop_tool_records {
            dropped_tool_records += t.dropped_tool_records;
        }
        let raw_asst_tokens = if t.raw_assistant_chars > t.clean_assistant_answer.chars().count() {
            let extra_chars = t.raw_assistant_chars - t.clean_assistant_answer.chars().count();
            estimate_text_tokens(&t.clean_assistant_answer) + (extra_chars / 3).max(1)
        } else {
            estimate_text_tokens(&t.clean_assistant_answer)
        };
        raw_estimated_tokens += estimate_text_tokens(&t.user_question)
            + raw_asst_tokens
            + 8
            + t.dropped_overhead_tokens;
    }

    if total_turns == 0 {
        return (
            Vec::new(),
            None,
            ContextCompressionStats {
                enabled: cfg.enabled,
                raw_qa_turns: 0,
                included_qa_turns: 0,
                rolled_up_ancient_turns: 0,
                dropped_tool_records,
                raw_estimated_tokens: 0,
                compressed_estimated_tokens: 0,
                saved_pct: 0.0,
                verbatim_turns: 0,
                decayed_turns: 0,
            },
            Vec::new(),
        );
    }

    // Disabled mode: still strip `<think>` and (if `drop_tool_records`) drop tool steps, capping to `max_context_tokens`
    if !cfg.enabled {
        let mut kept_rev: Vec<(String, String)> = Vec::new();
        let mut used_tokens = 0usize;
        let mut tiers = Vec::with_capacity(total_turns);
        for (rev_idx, turn) in turns.iter().rev().enumerate() {
            let turn_idx = total_turns - 1 - rev_idx;
            let q = truncate_chars_clean(&turn.user_question, VERBATIM_MSG_CHAR_CAP);
            let a = truncate_chars_clean(&turn.clean_assistant_answer, VERBATIM_MSG_CHAR_CAP);
            let pair_toks = estimate_pair_tokens(&q, &a);
            let raw_chars = turn.user_question.chars().count() + turn.raw_assistant_chars;
            if used_tokens + pair_toks <= cfg.max_context_tokens {
                used_tokens += pair_toks;
                let retained_chars = q.chars().count() + a.chars().count();
                tiers.push(CompressedTurnTierPreview {
                    turn_index: turn_idx,
                    distance: rev_idx,
                    zone: 0,
                    zone_label: "verbatim".to_string(),
                    weight: 1.0,
                    elapsed_minutes: 0.0,
                    raw_chars,
                    retained_chars,
                    user_preview: truncate_chars_clean(&q, 80),
                    assistant_preview: truncate_chars_clean(&a, 100),
                });
                kept_rev.push((q, a));
            } else {
                tiers.push(CompressedTurnTierPreview {
                    turn_index: turn_idx,
                    distance: rev_idx,
                    zone: 3,
                    zone_label: "budget_trimmed".to_string(),
                    weight: 0.0,
                    elapsed_minutes: 0.0,
                    raw_chars,
                    retained_chars: 0,
                    user_preview: truncate_chars_clean(&turn.user_question, 60),
                    assistant_preview: String::new(),
                });
            }
        }
        kept_rev.reverse();
        let included = kept_rev.len();
        let saved_pct = if raw_estimated_tokens > used_tokens && raw_estimated_tokens > 0 {
            (((raw_estimated_tokens - used_tokens) as f64 / raw_estimated_tokens as f64) * 1000.0)
                .round()
                / 10.0
        } else {
            0.0
        };
        return (
            kept_rev,
            None,
            ContextCompressionStats {
                enabled: false,
                raw_qa_turns: total_turns,
                included_qa_turns: included,
                rolled_up_ancient_turns: total_turns.saturating_sub(included),
                dropped_tool_records,
                raw_estimated_tokens,
                compressed_estimated_tokens: used_tokens,
                saved_pct,
                verbatim_turns: included,
                decayed_turns: 0,
            },
            tiers,
        );
    }

    // Reserve token headroom if ancient turns will exist so `compressed + anchor <= max_context_tokens`
    let has_ancient_candidates = total_turns > cfg.verbatim_recent_turns;
    let reserved_anchor_tokens = if has_ancient_candidates {
        (cfg.max_context_tokens / 6).clamp(80, 260)
    } else {
        0
    };
    let pairs_token_cap = cfg
        .max_context_tokens
        .saturating_sub(reserved_anchor_tokens);

    let mut kept_newest_first: Vec<(String, String)> = Vec::new();
    let mut ancient_indices_newest_first: Vec<usize> = Vec::new();
    let mut tiers_newest_first: Vec<CompressedTurnTierPreview> = Vec::with_capacity(total_turns);

    let mut used_tokens = 0usize;
    let mut verbatim_turns = 0usize;
    let mut decayed_turns = 0usize;
    let mut force_rollup_remaining = false;

    for (d, turn) in turns.iter().rev().enumerate() {
        let turn_idx = total_turns - 1 - d;
        let elapsed_mins = turn
            .created_epoch
            .map(|ep| ((now_epoch - ep).max(0) as f64) / 60.0);
        let w = compute_retention_weight(d, elapsed_mins, &cfg);
        let raw_chars = turn.user_question.chars().count() + turn.raw_assistant_chars;

        if force_rollup_remaining || w < 0.08 {
            force_rollup_remaining = true;
            ancient_indices_newest_first.push(turn_idx);
            tiers_newest_first.push(CompressedTurnTierPreview {
                turn_index: turn_idx,
                distance: d,
                zone: 3,
                zone_label: "ancient_rollup".to_string(),
                weight: (w * 1000.0).round() / 1000.0,
                elapsed_minutes: elapsed_mins.unwrap_or(0.0),
                raw_chars,
                retained_chars: 0,
                user_preview: truncate_chars_clean(&turn.user_question, 60),
                assistant_preview: "[已折叠至早期会话摘要锚点]".to_string(),
            });
            continue;
        }

        let (zone, zone_label, mut q_out, mut a_out) = if d < cfg.verbatim_recent_turns {
            let q = truncate_chars_clean(&turn.user_question, VERBATIM_MSG_CHAR_CAP);
            let a = truncate_chars_clean(&turn.clean_assistant_answer, VERBATIM_MSG_CHAR_CAP);
            (0u8, "verbatim", q, a)
        } else if w >= 0.28 {
            let budget = ((2200.0 * w).round() as usize).clamp(260, 2200);
            let q_budget = ((budget as f64) * 0.58).round() as usize;
            let a_budget = budget.saturating_sub(q_budget).max(80);
            let q = truncate_chars_clean(&turn.user_question, q_budget);
            let a = compress_markdown_answer(&turn.clean_assistant_answer, a_budget);
            (1u8, "nonlinear_decay", q, a)
        } else {
            // Zone 2: `w in [0.08, 0.28)` — scale smoothly within `[72..=110]` and `[92..=140]`
            let ratio = ((w - 0.08) / 0.20).clamp(0.0, 1.0);
            let q_cap = (72.0 + 38.0 * ratio).round() as usize; // <= 110 total with `问：`
            let a_cap = (92.0 + 48.0 * ratio).round() as usize; // <= 140 total with `答（摘要）：`
            let q_core = extract_core_question_digest(&turn.user_question, q_cap.saturating_sub(2));
            let a_core =
                extract_answer_digest(&turn.clean_assistant_answer, a_cap.saturating_sub(6));
            let q = truncate_chars_clean(&format!("问：{}", q_core), 110);
            let a = truncate_chars_clean(&format!("答（摘要）：{}", a_core), 140);
            (2u8, "digest", q, a)
        };

        let mut pair_toks = estimate_pair_tokens(&q_out, &a_out);
        if used_tokens + pair_toks > pairs_token_cap {
            // Always try to fit at least `d == 0` (most recent prior turn) within `pairs_token_cap`
            if d == 0 && pairs_token_cap >= 80 {
                let emergency_chars = pairs_token_cap.saturating_sub(12);
                q_out = truncate_chars_clean(&q_out, (emergency_chars * 58 / 100).max(24));
                a_out = compress_markdown_answer(&a_out, (emergency_chars * 42 / 100).max(24));
                pair_toks = estimate_pair_tokens(&q_out, &a_out);
            }
            if used_tokens + pair_toks > pairs_token_cap {
                force_rollup_remaining = true;
                ancient_indices_newest_first.push(turn_idx);
                tiers_newest_first.push(CompressedTurnTierPreview {
                    turn_index: turn_idx,
                    distance: d,
                    zone: 3,
                    zone_label: "ancient_rollup".to_string(),
                    weight: (w * 1000.0).round() / 1000.0,
                    elapsed_minutes: elapsed_mins.unwrap_or(0.0),
                    raw_chars,
                    retained_chars: 0,
                    user_preview: truncate_chars_clean(&turn.user_question, 60),
                    assistant_preview: "[预算溢出，已折叠至早期会话摘要锚点]".to_string(),
                });
                continue;
            }
        }

        used_tokens += pair_toks;
        if zone == 0 {
            verbatim_turns += 1;
        } else {
            decayed_turns += 1;
        }

        let retained_chars = q_out.chars().count() + a_out.chars().count();
        tiers_newest_first.push(CompressedTurnTierPreview {
            turn_index: turn_idx,
            distance: d,
            zone,
            zone_label: zone_label.to_string(),
            weight: (w * 1000.0).round() / 1000.0,
            elapsed_minutes: elapsed_mins.unwrap_or(0.0),
            raw_chars,
            retained_chars,
            user_preview: truncate_chars_clean(&q_out, 90),
            assistant_preview: truncate_chars_clean(&a_out, 110),
        });
        kept_newest_first.push((q_out, a_out));
    }

    kept_newest_first.reverse();

    let rolled_up_ancient_turns = ancient_indices_newest_first.len();
    let mut ancient_summary_anchor = if rolled_up_ancient_turns > 0 {
        let chronological_ancient: Vec<&HydratedQaTurn> = ancient_indices_newest_first
            .iter()
            .rev()
            .filter_map(|&idx| turns.get(idx))
            .collect();
        if chronological_ancient.is_empty() {
            None
        } else {
            let rem_tokens = cfg.max_context_tokens.saturating_sub(used_tokens);
            let max_anchor_chars = (rem_tokens.saturating_sub(6)).min(ANCIENT_ANCHOR_MAX_CHARS);
            build_ancient_rollup_anchor(&chronological_ancient, max_anchor_chars)
        }
    } else {
        None
    };

    let mut anchor_tokens = ancient_summary_anchor
        .as_deref()
        .map(|a| estimate_text_tokens(a) + 4)
        .unwrap_or(0);

    // Final hard-guarantee clamp: never allow `used_tokens + anchor_tokens > cfg.max_context_tokens`
    if used_tokens + anchor_tokens > cfg.max_context_tokens
        && let Some(ref anchor_str) = ancient_summary_anchor
    {
        let avail = cfg.max_context_tokens.saturating_sub(used_tokens + 4);
        if avail < 24 {
            ancient_summary_anchor = None;
            anchor_tokens = 0;
        } else {
            let shrunk = truncate_chars_clean(anchor_str, avail);
            anchor_tokens = estimate_text_tokens(&shrunk) + 4;
            ancient_summary_anchor = Some(shrunk);
        }
    }

    let compressed_estimated_tokens = (used_tokens + anchor_tokens).min(cfg.max_context_tokens);
    let saved_pct =
        if raw_estimated_tokens > compressed_estimated_tokens && raw_estimated_tokens > 0 {
            (((raw_estimated_tokens - compressed_estimated_tokens) as f64
                / raw_estimated_tokens as f64)
                * 1000.0)
                .round()
                / 10.0
        } else {
            0.0
        };

    let stats = ContextCompressionStats {
        enabled: cfg.enabled,
        raw_qa_turns: total_turns,
        included_qa_turns: kept_newest_first.len(),
        rolled_up_ancient_turns,
        dropped_tool_records,
        raw_estimated_tokens,
        compressed_estimated_tokens,
        saved_pct,
        verbatim_turns,
        decayed_turns,
    };

    (
        kept_newest_first,
        ancient_summary_anchor,
        stats,
        tiers_newest_first,
    )
}

/// Public 3-tuple wrapper matching `(Vec<(String, String)>, Option<String>, ContextCompressionStats)`.
pub fn compress_qa_turns(
    turns: &[HydratedQaTurn],
    cfg: &ContextDecayConfig,
    now_epoch: i64,
) -> (
    Vec<(String, String)>,
    Option<String>,
    ContextCompressionStats,
) {
    let (pairs, anchor, stats, _) = compress_qa_turns_detailed(turns, cfg, now_epoch);
    (pairs, anchor, stats)
}

/// Hydrate historical Q&A turns for `session_id`:
/// prefers persistent `MemoryHubDb` `chat_messages` (which carries timestamps, `tool_steps_json`,
/// and survives daemon restarts / `SessionBuffer`'s 20-message ring cap) and merges/falls back to
/// in-memory `SessionState` when needed.
pub fn hydrate_session_qa_turns(
    core: &IntentOsCore,
    session: Option<&SessionState>,
    session_id: &str,
    incognito: bool,
) -> Vec<HydratedQaTurn> {
    let policy = PrivacySessionPolicy::from_session(incognito, Some(session_id));
    hydrate_session_qa_turns_with_policy(core, session, session_id, policy)
}

/// Three-state privacy-aware hydration (`H05`):
/// - `StrictIsolated`: returns empty immediately (`0` DB opens, `0` session buffer reads).
/// - `EphemeralReadOnly`: reads existing `memory_hub.db` (if present on disk, never creating it!)
///   and existing in-memory `SessionBuffer` (`peek`, never mutating it!).
/// - `Standard`: full persistent + in-memory hydration.
pub fn hydrate_session_qa_turns_with_policy(
    core: &IntentOsCore,
    session: Option<&SessionState>,
    session_id: &str,
    policy: PrivacySessionPolicy,
) -> Vec<HydratedQaTurn> {
    if !policy.allows_memory_read() {
        return Vec::new();
    }

    let mut db_turns: Vec<HydratedQaTurn> = Vec::new();
    let can_open_db = policy.allows_memory_write() || MemoryHubDb::path_for_core(core).exists();

    if can_open_db
        && !session_id.trim().is_empty()
        && !session_id.starts_with("incog_")
        && let Ok(db) = MemoryHubDb::open_for_core(core)
    {
        let conn = db.conn.lock().unwrap();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT role, content, thinking, trace_dots_json, tool_steps_json,
                    mentioned_entities_json, created_epoch
             FROM chat_messages
             WHERE session_id = ?1
             ORDER BY created_epoch ASC, rowid ASC
             LIMIT 600",
        ) && let Ok(rows) = stmt.query_map(params![session_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
            ))
        }) {
            let mut pending_user: Option<(String, i64, Vec<String>, usize, usize)> = None;
            for item in rows.flatten() {
                let (role, content, thinking, dots_s, tools_s, ents_s, ep) = item;
                let tool_count = serde_json::from_str::<Vec<Value>>(&tools_s)
                    .map(|v| v.len())
                    .unwrap_or(0);
                let dots_len = if dots_s != "[]" { dots_s.len() } else { 0 };
                let tools_len = if tools_s != "[]" { tools_s.len() } else { 0 };
                let think_len = thinking.as_deref().map(str::len).unwrap_or(0);
                let overhead_toks = (dots_len + tools_len + think_len) / 4;
                let ents: Vec<String> = serde_json::from_str(&ents_s).unwrap_or_default();

                match role.as_str() {
                    "user" => {
                        if !content.trim().is_empty() {
                            pending_user = Some((content, ep, ents, tool_count, overhead_toks));
                        }
                    }
                    "assistant" => {
                        let clean_a = strip_thinking_blocks(&content);
                        let raw_a_chars = content.chars().count() + think_len;
                        if let Some((u_q, u_ep, mut u_ents, u_tools, u_over)) = pending_user.take()
                        {
                            for e in ents {
                                if !u_ents.contains(&e) {
                                    u_ents.push(e);
                                }
                            }
                            if !clean_a.is_empty() {
                                db_turns.push(HydratedQaTurn {
                                    user_question: u_q,
                                    clean_assistant_answer: clean_a,
                                    raw_assistant_chars: raw_a_chars,
                                    dropped_tool_records: u_tools + tool_count,
                                    dropped_overhead_tokens: u_over + overhead_toks,
                                    created_epoch: Some(ep.max(u_ep)),
                                    mentioned_entities: u_ents,
                                });
                            }
                        }
                    }
                    "tool" => {
                        if let Some((_, _, _, ref mut tc, ref mut ov)) = pending_user {
                            *tc += 1;
                            *ov += (content.len() / 4).max(4);
                        } else if let Some(last) = db_turns.last_mut() {
                            last.dropped_tool_records += 1;
                            last.dropped_overhead_tokens += (content.len() / 4).max(4);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Fallback or tail-merge from in-memory `SessionState`
    let mut mem_turns: Vec<HydratedQaTurn> = Vec::new();
    let owned_fallback;
    let sess_ref = if let Some(s) = session {
        Some(s)
    } else if !session_id.trim().is_empty() {
        if policy.allows_memory_write() {
            owned_fallback = Some(core.sessions.get_or_create(Some(session_id)));
        } else {
            owned_fallback = core.sessions.peek(session_id);
        }
        owned_fallback.as_ref()
    } else {
        None
    };

    if let Some(sess) = sess_ref {
        let mut pending_u: Option<String> = None;
        let mut pending_dropped = 0usize;
        let mut pending_over = 0usize;
        for m in &sess.messages {
            match m.role.as_str() {
                "user" => {
                    if !m.content.trim().is_empty() {
                        pending_u = Some(m.content.clone());
                    }
                }
                "assistant" => {
                    let clean_a = strip_thinking_blocks(&m.content);
                    if let Some(uq) = pending_u.take()
                        && !clean_a.is_empty()
                    {
                        mem_turns.push(HydratedQaTurn {
                            user_question: uq,
                            raw_assistant_chars: m.content.chars().count(),
                            clean_assistant_answer: clean_a,
                            dropped_tool_records: pending_dropped,
                            dropped_overhead_tokens: pending_over,
                            created_epoch: None,
                            mentioned_entities: Vec::new(),
                        });
                        pending_dropped = 0;
                        pending_over = 0;
                    }
                }
                "tool" => {
                    pending_dropped += 1;
                    pending_over += (m.content.len() / 4).max(4);
                }
                _ => {}
            }
        }
    }

    if db_turns.is_empty() {
        return mem_turns;
    }

    // Append any brand-new in-memory turns that were not yet persisted to `MemoryHubDb`
    if let Some(last_db) = db_turns.last()
        && let Some(pos) = mem_turns
            .iter()
            .rposition(|m| m.user_question == last_db.user_question)
    {
        for extra in mem_turns.into_iter().skip(pos + 1) {
            db_turns.push(extra);
        }
    }

    db_turns
}

/// Build compressed session history for `turn_engine` (`OpenAI`, `Anthropic`, and CLI backends).
pub fn build_compressed_session_history(
    core: &IntentOsCore,
    session: &SessionState,
    incognito: bool,
) -> CompressedSessionHistory {
    let policy = PrivacySessionPolicy::from_session(incognito, Some(&session.session_id));
    build_compressed_session_history_with_policy(core, session, policy)
}

/// Three-state privacy-aware compressed session history builder (`H05`).
pub fn build_compressed_session_history_with_policy(
    core: &IntentOsCore,
    session: &SessionState,
    policy: PrivacySessionPolicy,
) -> CompressedSessionHistory {
    if !policy.allows_memory_read() {
        return CompressedSessionHistory::default();
    }

    let can_open_db = policy.allows_memory_write() || MemoryHubDb::path_for_core(core).exists();
    let cfg = if can_open_db && let Ok(db) = MemoryHubDb::open_for_core(core) {
        load_context_decay_config(&db)
    } else {
        ContextDecayConfig::default()
    };

    let hydrated =
        hydrate_session_qa_turns_with_policy(core, Some(session), &session.session_id, policy);
    let now_epoch = Utc::now().timestamp();
    let (turns, ancient_summary_anchor, stats, tiers) =
        compress_qa_turns_detailed(&hydrated, &cfg, now_epoch);

    CompressedSessionHistory {
        turns,
        ancient_summary_anchor,
        stats,
        tiers,
    }
}

/// Build live `preview_session_compression` JSON response for Settings & Quick-Chat `🧠` drawer.
pub fn preview_session_compression(
    core: &IntentOsCore,
    db: &MemoryHubDb,
    payload: &Value,
) -> anyhow::Result<Value> {
    let base_cfg = load_context_decay_config(db);
    let cfg = if payload.get("config").is_some()
        || payload.get("decay_lambda").is_some()
        || payload.get("max_context_tokens").is_some()
        || payload.get("verbatim_recent_turns").is_some()
    {
        apply_config_patch(&base_cfg, payload)
    } else {
        base_cfg
    };

    let requested_sid = payload
        .get("session_id")
        .or_else(|| payload.get("id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);

    let effective_sid = if let Some(sid) = requested_sid {
        sid
    } else {
        // Fallback to most recently updated session in `memory_hub.db` if omitted
        let conn = db.conn.lock().unwrap();
        conn.query_row(
            "SELECT session_id FROM chat_sessions ORDER BY updated_epoch DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default()
    };

    let hydrated = if effective_sid.is_empty() {
        Vec::new()
    } else {
        hydrate_session_qa_turns(core, None, &effective_sid, false)
    };
    let now_epoch = Utc::now().timestamp();
    let (pairs, anchor, stats, tiers) = compress_qa_turns_detailed(&hydrated, &cfg, now_epoch);

    let compressed_turns_json: Vec<Value> = pairs
        .iter()
        .map(|(u, a)| json!({ "user": u, "assistant": a }))
        .collect();

    Ok(json!({
        "session_id": effective_sid,
        "config": cfg,
        "stats": stats,
        "enabled": stats.enabled,
        "raw_qa_turns": stats.raw_qa_turns,
        "included_qa_turns": stats.included_qa_turns,
        "rolled_up_ancient_turns": stats.rolled_up_ancient_turns,
        "dropped_tool_records": stats.dropped_tool_records,
        "raw_estimated_tokens": stats.raw_estimated_tokens,
        "compressed_estimated_tokens": stats.compressed_estimated_tokens,
        "saved_pct": stats.saved_pct,
        "verbatim_turns": stats.verbatim_turns,
        "decayed_turns": stats.decayed_turns,
        "ancient_summary_anchor": anchor,
        "compressed_turns": compressed_turns_json,
        "tiers": tiers,
        "turn_previews": tiers,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonlinear_decay_curve_four_zones_code_folding_and_200_turn_budget_cap() {
        let cfg = ContextDecayConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.drop_tool_records);
        assert_eq!(cfg.max_context_tokens, 6000);
        assert_eq!(cfg.verbatim_recent_turns, 3);

        let now = 1_800_000_000i64;
        // Verify non-linear weight curve monotonically decreases with turn distance & time
        let w0 = compute_retention_weight(0, Some(0.0), &cfg);
        let w2 = compute_retention_weight(2, Some(1.0), &cfg);
        let w3 = compute_retention_weight(3, Some(5.0), &cfg);
        let w5 = compute_retention_weight(5, Some(20.0), &cfg);
        let w12 = compute_retention_weight(12, Some(120.0), &cfg);
        assert_eq!(w0, 1.0);
        assert_eq!(w2, 1.0);
        assert!(
            (0.28..1.0).contains(&w3),
            "d=3 should be Zone 1, got {}",
            w3
        );
        assert!(
            (0.08..0.28).contains(&w5),
            "d=5 should be Zone 2, got {}",
            w5
        );
        assert!(w12 < 0.08, "d=12 should be Zone 3, got {}", w12);

        // Verify 220-turn marathon session never exceeds `max_context_tokens`, strips `<think>`, and folds code
        let tight_cfg = ContextDecayConfig {
            enabled: true,
            drop_tool_records: true,
            max_context_tokens: 1800,
            verbatim_recent_turns: 3,
            decay_lambda: 0.24,
            decay_gamma: 1.35,
        }
        .sanitized();

        let mut turns = Vec::new();
        for idx in 0..220 {
            let raw_asst = format!(
                "<think>第 {} 轮内部长篇推理步骤，绝不应进入后续多轮上下文</think>\n### 第 {} 轮系统诊断结论\n- 关键配置文件：`/home/alice/project/config_{}.toml`\n```rust\nfn heavy_code_block_{}() {{\n    println!(\"very long code line 1\");\n    println!(\"very long code line 2\");\n}}\n```\n最终结论：配置项 {} 已校验通过并正常运行。",
                idx, idx, idx, idx, idx
            );
            let clean_a = strip_thinking_blocks(&raw_asst);
            assert!(!clean_a.contains("<think>"));
            turns.push(HydratedQaTurn {
                user_question: format!(
                    "请帮我检查第 {} 轮的 `/home/alice/project/config_{}.toml` 服务端口与性能参数为什么波动？",
                    idx, idx
                ),
                raw_assistant_chars: raw_asst.chars().count(),
                clean_assistant_answer: clean_a,
                dropped_tool_records: 2,
                dropped_overhead_tokens: 90,
                created_epoch: Some(now - ((220 - idx) as i64) * 180),
                mentioned_entities: vec![format!("/home/alice/project/config_{}.toml", idx)],
            });
        }

        let (pairs, anchor, stats, tiers) = compress_qa_turns_detailed(&turns, &tight_cfg, now);

        assert_eq!(stats.raw_qa_turns, 220);
        assert_eq!(stats.dropped_tool_records, 440);
        assert!(
            stats.compressed_estimated_tokens <= tight_cfg.max_context_tokens,
            "compressed {} must be <= max {}",
            stats.compressed_estimated_tokens,
            tight_cfg.max_context_tokens
        );
        assert!(stats.rolled_up_ancient_turns > 200);
        assert!(stats.saved_pct > 80.0);

        let anchor_str = anchor.expect("must emit ancient summary anchor");
        assert!(anchor_str.starts_with("[早期会话非线性时间衰减摘要（共 "));
        assert!(anchor_str.chars().count() <= ANCIENT_ANCHOR_MAX_CHARS);

        // Verify Zone 0 verbatim preservation & zero `<think>` leakage
        let last_pair = pairs.last().expect("latest turn kept");
        assert!(last_pair.0.contains("config_219.toml"));
        assert!(last_pair.1.contains("```rust"));
        for (u, a) in &pairs {
            assert!(!u.contains("<think>"));
            assert!(!a.contains("<think>"));
        }

        // Verify Zone 1 code block folding
        let d3_tier = tiers.iter().find(|t| t.distance == 3).unwrap();
        let d1_tier = tiers.iter().find(|t| t.distance == 1).unwrap();
        let d5_tier = tiers.iter().find(|t| t.distance == 5).unwrap();
        let d12_tier = tiers.iter().find(|t| t.distance == 12).unwrap();
        assert!(d1_tier.retained_chars >= d3_tier.retained_chars);
        assert!(d3_tier.retained_chars >= d5_tier.retained_chars);
        assert!(d5_tier.retained_chars >= d12_tier.retained_chars);
    }
}
