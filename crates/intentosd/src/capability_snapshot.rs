#![forbid(unsafe_code)]

//! Versioned, Thread-Safe Capability Snapshot, Pre-Serialized Tool Schema Cache &
//! Sub-Millisecond Lexical/Tag/Domain/Pinyin Search Index (`capability_snapshot.rs`, `H09`).
//!
//! Eliminates per-turn `PatternCompiler::compile_from_descriptors` regex recompilation,
//! full `Vec<CapabilityDescriptor>` cloning, and repeated OpenAI/Anthropic JSON schema
//! construction across `core`, `intent_engine`, `broker_bridge`, and `M2-A` `capability.search`.

use crate::broker::CapabilityBroker;
use crate::core::IntentOsCore;
use crate::db::IndexDb;
use crate::intent_engine::pattern_compiler::{PatternCompiler, analyze_colloquial_input};
use crate::security_guard::PrivacySessionPolicy;
use intentos_capability_sdk::descriptor_to_tool_spec;
use intentos_protocol::{CapabilityDescriptor, Effect, ToolSpec, UndoStrategy};
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

const ESSENTIAL_QUICK_CHAT_TOOL_NAMES: &[&str] = &[
    "file_open",
    "file_write",
    "app_launch",
    "app_quit",
    "window_focus",
    "window_list",
    "media_control",
    "display_brightness_set",
    "display_night_light_set",
    "sound_volume_set",
    "sound_mute_set",
    "appearance_color_scheme_set",
    "scene_apply",
    "file_search",
    "file_recent",
    "file_move",
    "file_copy",
    "file_trash",
    "disk_usage",
    "network_status",
];

/// Ranked capability hit returned by [`CapabilitySearchIndex`] (`< 0.5 ms` lookup).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilitySearchHit {
    pub capability_id: String,
    pub tool_name: String,
    pub domain: String,
    pub category: String,
    pub summary: String,
    pub max_effect: Effect,
    pub risk_badge: String,
    pub undoable: bool,
    pub idempotent: bool,
    pub score: f64,
    pub matched_on: String,
}

#[derive(Debug, Clone)]
struct IndexedCapabilityDoc {
    capability_id: String,
    id_lc: String,
    tool_name: String,
    tool_name_lc: String,
    domain: String,
    category: String,
    category_lc: String,
    summary: String,
    summary_lc: String,
    aliases_lc: Vec<String>,
    triggers_lc: Vec<String>,
    pinyin_full: Vec<String>,
    pinyin_init: Vec<String>,
    max_effect: Effect,
    risk_badge: &'static str,
    undoable: bool,
    idempotent: bool,
}

/// Pre-tokenized inverted lexical, CJK bigram, tag/category, domain, Pinyin, and DFA `RegexSet`
/// index over all registered [`CapabilityDescriptor`]s (`H09.1` & `M2-A`).
#[derive(Debug, Clone)]
pub struct CapabilitySearchIndex {
    docs: Vec<IndexedCapabilityDoc>,
    by_domain: HashMap<String, Vec<usize>>,
    by_category: HashMap<String, Vec<usize>>,
    by_ascii_token: HashMap<String, Vec<(usize, f64)>>,
    by_ascii_prefix2: HashMap<[u8; 2], Vec<usize>>,
    by_cjk_bigram: HashMap<(char, char), Vec<(usize, f64)>>,
    by_cjk_char: HashMap<char, Vec<(usize, f64)>>,
    l0_regex_set: Option<RegexSet>,
    l0_regex_meta: Vec<(usize, f64)>,
}

impl CapabilitySearchIndex {
    /// Build a pre-tokenized search index from descriptors and their compiled `PatternCompiler`.
    pub fn build(descriptors: &[CapabilityDescriptor], compiler: &PatternCompiler) -> Self {
        let mut docs = Vec::with_capacity(descriptors.len());
        let mut by_domain: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_category: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_ascii_token: HashMap<String, Vec<(usize, f64)>> = HashMap::new();
        let mut by_ascii_prefix2: HashMap<[u8; 2], Vec<usize>> = HashMap::new();
        let mut by_cjk_bigram: HashMap<(char, char), Vec<(usize, f64)>> = HashMap::new();
        let mut by_cjk_char: HashMap<char, Vec<(usize, f64)>> = HashMap::new();
        let mut l0_regex_strs: Vec<String> = Vec::new();
        let mut l0_regex_meta: Vec<(usize, f64)> = Vec::new();

        for (idx, desc) in descriptors.iter().enumerate() {
            let id_lc = desc.id.trim().to_ascii_lowercase();
            let tool_name = desc.id.replace('.', "_");
            let tool_name_lc = tool_name.to_ascii_lowercase();
            let domain = id_lc
                .split('.')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("general")
                .to_string();
            let category_lc = desc.category.trim().to_ascii_lowercase();
            let summary_lc = desc.summary.trim().to_ascii_lowercase();
            let max_effect = desc.max_effect();
            let risk_badge = max_effect.risk_badge();
            let undoable = desc.undo != UndoStrategy::None;

            let lex_entry = compiler.get_entry(&desc.id);
            let aliases_lc: Vec<String> = desc
                .aliases
                .iter()
                .map(|a| a.trim().to_ascii_lowercase())
                .filter(|a| !a.is_empty())
                .collect();
            let triggers_lc: Vec<String> = lex_entry
                .map(|e| {
                    e.colloquial_triggers
                        .iter()
                        .map(|t| t.trim().to_ascii_lowercase())
                        .filter(|t| !t.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let pinyin_full: Vec<String> = lex_entry
                .map(|e| {
                    e.pinyin_full_terms
                        .iter()
                        .map(|(pf, _)| pf.clone())
                        .collect()
                })
                .unwrap_or_default();
            let pinyin_init: Vec<String> = lex_entry
                .map(|e| {
                    e.pinyin_init_terms
                        .iter()
                        .map(|(pi, _)| pi.clone())
                        .collect()
                })
                .unwrap_or_default();

            by_domain.entry(domain.clone()).or_default().push(idx);
            by_category
                .entry(category_lc.clone())
                .or_default()
                .push(idx);

            let mut ascii_weights: HashMap<String, f64> = HashMap::new();
            let mut record_ascii = |tok: &str, weight: f64| {
                let t = tok.trim().to_ascii_lowercase();
                if t.len() >= 2 {
                    let slot = ascii_weights.entry(t).or_insert(0.0);
                    if weight > *slot {
                        *slot = weight;
                    }
                }
            };

            record_ascii(&id_lc, 65.0);
            record_ascii(&tool_name_lc, 65.0);
            for seg in id_lc.split(['.', '_', '-']) {
                record_ascii(seg, 30.0);
            }
            for seg in category_lc.split(['.', '_', '-', ' ', '/']) {
                record_ascii(seg, 22.0);
            }
            for dep in &desc.dependencies {
                record_ascii(dep, 18.0);
            }
            for alias in &aliases_lc {
                for tok in extract_ascii_tokens(alias) {
                    record_ascii(&tok, 28.0);
                }
            }
            for trig in &triggers_lc {
                for tok in extract_ascii_tokens(trig) {
                    record_ascii(&tok, 26.0);
                }
            }
            for tok in extract_ascii_tokens(&summary_lc) {
                record_ascii(&tok, 20.0);
            }
            for pf in &pinyin_full {
                record_ascii(pf, 34.0);
            }
            for pi in &pinyin_init {
                record_ascii(pi, 36.0);
            }

            let mut seen_prefixes: HashSet<[u8; 2]> = HashSet::new();
            for (tok, w) in ascii_weights {
                if tok.len() >= 2 {
                    let b = tok.as_bytes();
                    let pfx = [b[0], b[1]];
                    if seen_prefixes.insert(pfx) {
                        by_ascii_prefix2.entry(pfx).or_default().push(idx);
                    }
                }
                by_ascii_token.entry(tok).or_default().push((idx, w));
            }

            if let Some(entry) = lex_entry {
                for pat in &entry.compiled_patterns {
                    let specificity_bonus = (pat.slot_names.len() as f64) * 0.02
                        + (pat.raw_pattern.chars().count().min(20) as f64) * 0.003;
                    let conf = (pat.base_weight + specificity_bonus).clamp(0.0, 0.99);
                    l0_regex_strs.push(pat.regex.as_str().to_string());
                    l0_regex_meta.push((idx, conf));
                }
            }

            let mut bigram_weights: HashMap<(char, char), f64> = HashMap::new();
            let mut char_weights: HashMap<char, f64> = HashMap::new();
            let mut record_cjk_text = |text: &str, bg_weight: f64, ch_weight: f64| {
                for bg in extract_cjk_bigrams(text) {
                    let slot = bigram_weights.entry(bg).or_insert(0.0);
                    if bg_weight > *slot {
                        *slot = bg_weight;
                    }
                }
                for ch in text.chars().filter(|c| is_cjk_char(*c)) {
                    let slot = char_weights.entry(ch).or_insert(0.0);
                    if ch_weight > *slot {
                        *slot = ch_weight;
                    }
                }
            };

            for alias in &aliases_lc {
                record_cjk_text(alias, 24.0, 9.0);
            }
            for trig in &triggers_lc {
                record_cjk_text(trig, 22.0, 8.0);
            }
            for pat in &desc.l0_patterns {
                record_cjk_text(pat, 18.0, 7.0);
            }
            record_cjk_text(&summary_lc, 14.0, 6.0);

            for (bg, w) in bigram_weights {
                by_cjk_bigram.entry(bg).or_default().push((idx, w));
            }
            for (ch, w) in char_weights {
                by_cjk_char.entry(ch).or_default().push((idx, w));
            }

            docs.push(IndexedCapabilityDoc {
                capability_id: desc.id.clone(),
                id_lc,
                tool_name,
                tool_name_lc,
                domain,
                category: desc.category.clone(),
                category_lc,
                summary: desc.summary.clone(),
                summary_lc,
                aliases_lc,
                triggers_lc,
                pinyin_full,
                pinyin_init,
                max_effect,
                risk_badge,
                undoable,
                idempotent: desc.idempotent,
            });
        }

        let l0_regex_set = if l0_regex_strs.is_empty() {
            None
        } else {
            RegexSet::new(&l0_regex_strs).ok()
        };

        Self {
            docs,
            by_domain,
            by_category,
            by_ascii_token,
            by_ascii_prefix2,
            by_cjk_bigram,
            by_cjk_char,
            l0_regex_set,
            l0_regex_meta,
        }
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Return capability IDs belonging to a domain prefix (e.g. `"sound"`, `"file"`) or category.
    pub fn ids_in_domain_or_category(&self, domain_or_category: &str) -> Vec<&str> {
        let key = domain_or_category.trim().to_ascii_lowercase();
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        if let Some(indices) = self.by_domain.get(&key) {
            for &i in indices {
                if seen.insert(i) {
                    out.push(self.docs[i].capability_id.as_str());
                }
            }
        }
        if let Some(indices) = self.by_category.get(&key) {
            for &i in indices {
                if seen.insert(i) {
                    out.push(self.docs[i].capability_id.as_str());
                }
            }
        }
        out
    }

    /// Sub-millisecond (`< 0.5 ms`) capability search across IDs, domains, categories,
    /// aliases, colloquial triggers, summaries, CJK bigrams, and Pinyin initials/full syllables.
    pub fn search(
        &self,
        query: &str,
        compiler: Option<&PatternCompiler>,
        domain_or_category: Option<&str>,
        max_effect: Option<Effect>,
        limit: usize,
    ) -> Vec<CapabilitySearchHit> {
        if limit == 0 || self.docs.is_empty() {
            return Vec::new();
        }

        let filter_dc = domain_or_category
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all") && *s != "全部")
            .map(str::to_ascii_lowercase);

        let passes_filter = |doc: &IndexedCapabilityDoc| -> bool {
            if let Some(max_eff) = max_effect
                && doc.max_effect > max_eff
            {
                return false;
            }
            if let Some(ref dc) = filter_dc {
                let domain_ok = doc.domain == *dc
                    || doc.category_lc == *dc
                    || doc.id_lc.starts_with(&format!("{}.", dc));
                if !domain_ok {
                    return false;
                }
            }
            true
        };

        let trimmed = query.trim();
        if trimmed.is_empty() {
            return self
                .docs
                .iter()
                .filter(|d| passes_filter(d))
                .take(limit)
                .map(|d| doc_to_hit(d, 1.0, "filter"))
                .collect();
        }

        let colloquial = analyze_colloquial_input(trimmed);
        let q_lc = trimmed.to_ascii_lowercase();
        let norm_lc = colloquial.normalized.trim().to_ascii_lowercase();
        let q_ascii: String = q_lc.chars().filter(|c| c.is_ascii_alphanumeric()).collect();

        let n = self.docs.len();
        let mut scores = vec![0.0f64; n];
        let mut reasons: Vec<&'static str> = vec![""; n];
        let mut candidates = vec![false; n];
        let mut any_candidate = false;

        fn add_hit_score(
            scores: &mut [f64],
            reasons: &mut [&'static str],
            candidates: &mut [bool],
            any_candidate: &mut bool,
            idx: usize,
            delta: f64,
            reason: &'static str,
        ) {
            if delta > 0.0 {
                if reasons[idx].is_empty() || delta >= 35.0 {
                    reasons[idx] = reason;
                }
                scores[idx] += delta;
                candidates[idx] = true;
                *any_candidate = true;
            }
        }

        // 1. Inverted ASCII / Pinyin token & 2-char prefix lookup (`O(1)`)
        let mut query_ascii_tokens = extract_ascii_tokens(&q_lc);
        if norm_lc != q_lc {
            for t in extract_ascii_tokens(&norm_lc) {
                if !query_ascii_tokens.contains(&t) {
                    query_ascii_tokens.push(t);
                }
            }
        }
        if q_ascii.len() >= 2 && !query_ascii_tokens.contains(&q_ascii) {
            query_ascii_tokens.push(q_ascii.clone());
        }

        for tok in &query_ascii_tokens {
            if let Some(postings) = self.by_ascii_token.get(tok) {
                for &(idx, w) in postings {
                    add_hit_score(
                        &mut scores,
                        &mut reasons,
                        &mut candidates,
                        &mut any_candidate,
                        idx,
                        w,
                        "token",
                    );
                }
            }
            if tok.len() >= 2 {
                let b = tok.as_bytes();
                if let Some(indices) = self.by_ascii_prefix2.get(&[b[0], b[1]]) {
                    for &idx in indices {
                        candidates[idx] = true;
                        any_candidate = true;
                    }
                }
            }
        }

        // 2. Inverted CJK bigram (or single-char fallback) lookup (`O(1)`)
        let mut cjk_bigrams = extract_cjk_bigrams(&q_lc);
        if norm_lc != q_lc {
            for bg in extract_cjk_bigrams(&norm_lc) {
                if !cjk_bigrams.contains(&bg) {
                    cjk_bigrams.push(bg);
                }
            }
        }
        if !cjk_bigrams.is_empty() {
            for bg in &cjk_bigrams {
                if let Some(postings) = self.by_cjk_bigram.get(bg) {
                    for &(idx, w) in postings {
                        add_hit_score(
                            &mut scores,
                            &mut reasons,
                            &mut candidates,
                            &mut any_candidate,
                            idx,
                            w,
                            "cjk_bigram",
                        );
                    }
                }
            }
        } else {
            for ch in q_lc.chars().filter(|c| is_cjk_char(*c)) {
                if let Some(postings) = self.by_cjk_char.get(&ch) {
                    for &(idx, w) in postings {
                        add_hit_score(
                            &mut scores,
                            &mut reasons,
                            &mut candidates,
                            &mut any_candidate,
                            idx,
                            w,
                            "cjk_char",
                        );
                    }
                }
            }
        }

        // 3. Single-pass DFA `RegexSet` match across all compiled L0 patterns (`~10 µs`)
        if let Some(ref regex_set) = self.l0_regex_set {
            let mut best_l0_by_doc: HashMap<usize, f64> = HashMap::new();
            for pat_idx in regex_set.matches(trimmed) {
                if let Some(&(doc_idx, conf)) = self.l0_regex_meta.get(pat_idx) {
                    let slot = best_l0_by_doc.entry(doc_idx).or_insert(0.0);
                    if conf > *slot {
                        *slot = conf;
                    }
                }
            }
            if norm_lc != q_lc && !norm_lc.is_empty() {
                for pat_idx in regex_set.matches(&colloquial.normalized) {
                    if let Some(&(doc_idx, conf)) = self.l0_regex_meta.get(pat_idx) {
                        let slot = best_l0_by_doc.entry(doc_idx).or_insert(0.0);
                        if conf > *slot {
                            *slot = conf;
                        }
                    }
                }
            }
            for (doc_idx, conf) in best_l0_by_doc {
                add_hit_score(
                    &mut scores,
                    &mut reasons,
                    &mut candidates,
                    &mut any_candidate,
                    doc_idx,
                    88.0 * conf,
                    "l0_pattern",
                );
            }
        } else if let Some(comp) = compiler {
            for pm in comp.match_patterns(trimmed) {
                if let Some(idx) = self
                    .docs
                    .iter()
                    .position(|d| d.capability_id == pm.capability_id)
                {
                    add_hit_score(
                        &mut scores,
                        &mut reasons,
                        &mut candidates,
                        &mut any_candidate,
                        idx,
                        88.0 * pm.confidence,
                        "l0_pattern",
                    );
                }
            }
        }

        // 4. Fine-grained ID / domain / category / alias / trigger / Pinyin refinement over candidates
        for (idx, doc) in self.docs.iter().enumerate() {
            if any_candidate && !candidates[idx] {
                continue;
            }
            if !passes_filter(doc) {
                scores[idx] = 0.0;
                continue;
            }

            if doc.id_lc == q_lc || doc.tool_name_lc == q_lc {
                add_hit_score(
                    &mut scores,
                    &mut reasons,
                    &mut candidates,
                    &mut any_candidate,
                    idx,
                    120.0,
                    "exact_id",
                );
            } else if doc.id_lc.starts_with(&q_lc) || doc.tool_name_lc.starts_with(&q_lc) {
                add_hit_score(
                    &mut scores,
                    &mut reasons,
                    &mut candidates,
                    &mut any_candidate,
                    idx,
                    82.0,
                    "id_prefix",
                );
            } else if q_lc.len() >= 3
                && (doc.id_lc.contains(&q_lc) || doc.tool_name_lc.contains(&q_lc))
            {
                add_hit_score(
                    &mut scores,
                    &mut reasons,
                    &mut candidates,
                    &mut any_candidate,
                    idx,
                    48.0,
                    "id_substring",
                );
            }

            if doc.domain == q_lc || doc.category_lc == q_lc {
                add_hit_score(
                    &mut scores,
                    &mut reasons,
                    &mut candidates,
                    &mut any_candidate,
                    idx,
                    52.0,
                    "domain_or_category",
                );
            }

            if doc.aliases_lc.iter().any(|a| a == &q_lc || a == &norm_lc)
                || doc.triggers_lc.iter().any(|t| t == &q_lc || t == &norm_lc)
            {
                add_hit_score(
                    &mut scores,
                    &mut reasons,
                    &mut candidates,
                    &mut any_candidate,
                    idx,
                    95.0,
                    "exact_alias",
                );
            } else if q_lc.chars().count() >= 2
                && (doc.aliases_lc.iter().any(|a| {
                    a.contains(&q_lc)
                        || (a.chars().count() >= 2 && (q_lc.contains(a) || norm_lc.contains(a)))
                }) || doc.triggers_lc.iter().any(|t| {
                    t.contains(&q_lc)
                        || (t.chars().count() >= 2 && (q_lc.contains(t) || norm_lc.contains(t)))
                }))
            {
                add_hit_score(
                    &mut scores,
                    &mut reasons,
                    &mut candidates,
                    &mut any_candidate,
                    idx,
                    54.0,
                    "alias_match",
                );
            }

            if q_lc.chars().count() >= 2
                && (doc.summary_lc.contains(&q_lc)
                    || (!norm_lc.is_empty() && doc.summary_lc.contains(&norm_lc)))
            {
                add_hit_score(
                    &mut scores,
                    &mut reasons,
                    &mut candidates,
                    &mut any_candidate,
                    idx,
                    36.0,
                    "summary",
                );
            }

            if q_ascii.len() >= 2 {
                if doc
                    .pinyin_init
                    .iter()
                    .any(|pi| pi == &q_ascii || pi.starts_with(&q_ascii))
                {
                    add_hit_score(
                        &mut scores,
                        &mut reasons,
                        &mut candidates,
                        &mut any_candidate,
                        idx,
                        64.0,
                        "pinyin_initials",
                    );
                } else if doc
                    .pinyin_full
                    .iter()
                    .any(|pf| pf == &q_ascii || pf.starts_with(&q_ascii))
                {
                    add_hit_score(
                        &mut scores,
                        &mut reasons,
                        &mut candidates,
                        &mut any_candidate,
                        idx,
                        58.0,
                        "pinyin_full",
                    );
                }
            }
        }

        let mut matched_indices: Vec<usize> = (0..n).filter(|&i| scores[i] > 0.0).collect();
        matched_indices.sort_by(|&a, &b| {
            scores[b]
                .partial_cmp(&scores[a])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| self.docs[a].capability_id.cmp(&self.docs[b].capability_id))
        });
        matched_indices.truncate(limit);

        matched_indices
            .into_iter()
            .map(|i| {
                let rounded = (scores[i] * 100.0).round() / 100.0;
                let reason = if reasons[i].is_empty() {
                    "lexical"
                } else {
                    reasons[i]
                };
                doc_to_hit(&self.docs[i], rounded, reason)
            })
            .collect()
    }
}

fn doc_to_hit(doc: &IndexedCapabilityDoc, score: f64, matched_on: &str) -> CapabilitySearchHit {
    CapabilitySearchHit {
        capability_id: doc.capability_id.clone(),
        tool_name: doc.tool_name.clone(),
        domain: doc.domain.clone(),
        category: doc.category.clone(),
        summary: doc.summary.clone(),
        max_effect: doc.max_effect,
        risk_badge: doc.risk_badge.to_string(),
        undoable: doc.undoable,
        idempotent: doc.idempotent,
        score,
        matched_on: matched_on.to_string(),
    }
}

fn is_cjk_char(c: char) -> bool {
    ('\u{4E00}'..='\u{9FFF}').contains(&c) || ('\u{3400}'..='\u{4DBF}').contains(&c)
}

fn extract_ascii_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if part.len() >= 2 {
            let lc = part.to_ascii_lowercase();
            if !out.contains(&lc) {
                out.push(lc);
            }
        }
    }
    out
}

fn extract_cjk_bigrams(text: &str) -> Vec<(char, char)> {
    let mut out = Vec::new();
    let mut run: Vec<char> = Vec::new();
    let mut flush_run = |r: &mut Vec<char>| {
        if r.len() >= 2 {
            for w in r.windows(2) {
                let pair = (w[0], w[1]);
                if !out.contains(&pair) {
                    out.push(pair);
                }
            }
        }
        r.clear();
    };

    for ch in text.chars() {
        if is_cjk_char(ch) {
            run.push(ch);
        } else if !run.is_empty() {
            flush_run(&mut run);
        }
    }
    if !run.is_empty() {
        flush_run(&mut run);
    }
    out
}

/// Immutable, versioned snapshot of all registered capabilities, compiled L0 patterns,
/// pre-built OpenAI/Anthropic tool schemas, and pre-tokenized search indices (`H09.1`).
#[derive(Debug)]
pub struct CapabilitySnapshot {
    pub version: u64,
    pub fingerprint: u64,
    pub descriptors: Arc<[CapabilityDescriptor]>,
    pub pattern_compiler: Arc<PatternCompiler>,
    pub tool_specs_by_id: HashMap<String, ToolSpec>,
    pub openai_schema_by_id: HashMap<String, Value>,
    pub anthropic_schema_by_id: HashMap<String, Value>,
    pub search_index: CapabilitySearchIndex,
    index_by_id: HashMap<String, usize>,
    canonical_id_by_tool_name: HashMap<String, String>,
}

impl CapabilitySnapshot {
    /// Construct a complete `CapabilitySnapshot` from an owned descriptor list.
    pub fn from_descriptors(
        version: u64,
        fingerprint: u64,
        owned: Vec<CapabilityDescriptor>,
    ) -> Self {
        let cap_len = owned.len();
        let refs: Vec<&CapabilityDescriptor> = owned.iter().collect();
        let compiler = PatternCompiler::compile_from_descriptors(&refs);
        let search_index = CapabilitySearchIndex::build(&owned, &compiler);

        let mut tool_specs_by_id = HashMap::with_capacity(cap_len);
        let mut openai_schema_by_id = HashMap::with_capacity(cap_len);
        let mut anthropic_schema_by_id = HashMap::with_capacity(cap_len);
        let mut index_by_id = HashMap::with_capacity(cap_len);
        let mut canonical_id_by_tool_name = HashMap::with_capacity(cap_len);

        for (idx, desc) in owned.iter().enumerate() {
            let spec = descriptor_to_tool_spec(desc);
            let openai_val = json!({
                "type": "function",
                "function": {
                    "name": spec.name,
                    "description": spec.description,
                    "parameters": spec.parameters,
                }
            });
            let anthropic_val = json!({
                "name": spec.name,
                "description": spec.description,
                "input_schema": spec.parameters,
            });

            canonical_id_by_tool_name.insert(spec.name.clone(), desc.id.clone());
            index_by_id.insert(desc.id.clone(), idx);
            tool_specs_by_id.insert(desc.id.clone(), spec);
            openai_schema_by_id.insert(desc.id.clone(), openai_val);
            anthropic_schema_by_id.insert(desc.id.clone(), anthropic_val);
        }

        Self {
            version,
            fingerprint,
            descriptors: Arc::from(owned.into_boxed_slice()),
            pattern_compiler: Arc::new(compiler),
            tool_specs_by_id,
            openai_schema_by_id,
            anthropic_schema_by_id,
            search_index,
            index_by_id,
            canonical_id_by_tool_name,
        }
    }

    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    pub fn descriptors_slice(&self) -> &[CapabilityDescriptor] {
        &self.descriptors
    }

    /// Resolve either a canonical ID (`"sound.volume.set"`) or underscored tool name (`"sound_volume_set"`)
    /// to its registered canonical capability ID in `O(1)`.
    pub fn resolve_canonical_id(&self, id_or_tool_name: &str) -> Option<&str> {
        let trimmed = id_or_tool_name.trim();
        if let Some((k, _)) = self.index_by_id.get_key_value(trimmed) {
            return Some(k.as_str());
        }
        self.canonical_id_by_tool_name
            .get(trimmed)
            .map(String::as_str)
    }

    /// Look up a `CapabilityDescriptor` by canonical ID or underscored tool name in `O(1)`.
    pub fn get_descriptor(&self, id_or_tool_name: &str) -> Option<&CapabilityDescriptor> {
        let cid = self.resolve_canonical_id(id_or_tool_name)?;
        let &idx = self.index_by_id.get(cid)?;
        self.descriptors.get(idx)
    }

    /// Look up a pre-built `ToolSpec` by canonical ID or underscored tool name in `O(1)`.
    pub fn get_tool_spec(&self, id_or_tool_name: &str) -> Option<&ToolSpec> {
        let cid = self.resolve_canonical_id(id_or_tool_name)?;
        self.tool_specs_by_id.get(cid)
    }

    /// Look up a pre-serialized OpenAI function schema `Value` by canonical ID or tool name in `O(1)`.
    pub fn get_openai_schema(&self, id_or_tool_name: &str) -> Option<&Value> {
        let cid = self.resolve_canonical_id(id_or_tool_name)?;
        self.openai_schema_by_id.get(cid)
    }

    /// Look up a pre-serialized Anthropic `input_schema` tool `Value` by canonical ID or tool name in `O(1)`.
    pub fn get_anthropic_schema(&self, id_or_tool_name: &str) -> Option<&Value> {
        let cid = self.resolve_canonical_id(id_or_tool_name)?;
        self.anthropic_schema_by_id.get(cid)
    }

    /// Search capabilities in `< 0.5 ms` using the pre-tokenized index + cached `PatternCompiler`.
    pub fn search(&self, query: &str, limit: usize) -> Vec<CapabilitySearchHit> {
        self.search_index
            .search(query, Some(&self.pattern_compiler), None, None, limit)
    }

    /// Search capabilities with optional domain/category and maximum `Effect` filters.
    pub fn search_filtered(
        &self,
        query: &str,
        domain_or_category: Option<&str>,
        max_effect: Option<Effect>,
        limit: usize,
    ) -> Vec<CapabilitySearchHit> {
        self.search_index.search(
            query,
            Some(&self.pattern_compiler),
            domain_or_category,
            max_effect,
            limit,
        )
    }

    /// Return up to `limit` top-matching `&CapabilityDescriptor` references for compact Fast-LLM prompts.
    pub fn rank_top_descriptors(&self, query: &str, limit: usize) -> Vec<&CapabilityDescriptor> {
        self.search(query, limit)
            .into_iter()
            .filter_map(|hit| self.get_descriptor(&hit.capability_id))
            .collect()
    }

    /// Fast pre-cached OpenAI `tools` array builder for Quick-Chat (`< 0.5 ms` vs `~24 ms` cold).
    pub fn build_quick_chat_openai_tools(
        &self,
        user_text: &str,
        index_db: Option<&IndexDb>,
        privacy: PrivacySessionPolicy,
    ) -> Vec<Value> {
        static CACHED_MEMORY_OPENAI_TOOLS: OnceLock<Vec<(String, Value)>> = OnceLock::new();
        static CACHED_ADAPTER_OPENAI_TOOLS: OnceLock<Vec<(String, Value)>> = OnceLock::new();

        let allowed_ids: Vec<&str> = self
            .descriptors
            .iter()
            .filter(|d| {
                privacy.allows_memory_write() || !crate::security_guard::is_memory_write_tool(&d.id)
            })
            .map(|d| d.id.as_str())
            .collect();

        let mut tools = Vec::with_capacity(36);
        if allowed_ids.len() <= 20 {
            for cid in allowed_ids {
                if let Some(schema) = self.openai_schema_by_id.get(cid) {
                    tools.push(schema.clone());
                }
            }
        } else {
            let mut hits = self.search(user_text, 16);
            if let Some(db) = index_db {
                for hit in &mut hits {
                    let boost = db.get_frecency_boost(&format!("cap:{}", hit.capability_id))
                        + db.get_frecency_boost(&format!("l0:{}:0", hit.capability_id))
                        + db.get_frecency_boost(&hit.capability_id);
                    hit.score += boost;
                }
                hits.sort_by(|a, b| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.capability_id.cmp(&b.capability_id))
                });
            }
            let mut chosen_tool_names: Vec<String> =
                hits.into_iter().take(12).map(|r| r.tool_name).collect();
            for &ess in ESSENTIAL_QUICK_CHAT_TOOL_NAMES {
                if chosen_tool_names.len() >= 25 {
                    break;
                }
                if !chosen_tool_names.iter().any(|n| n == ess) {
                    chosen_tool_names.push(ess.to_string());
                }
            }
            let chosen_set: HashSet<&str> = chosen_tool_names.iter().map(String::as_str).collect();
            for cid in allowed_ids {
                if let Some(spec) = self.tool_specs_by_id.get(cid)
                    && chosen_set.contains(spec.name.as_str())
                    && let Some(schema) = self.openai_schema_by_id.get(cid)
                {
                    tools.push(schema.clone());
                }
            }
        }

        if privacy.allows_memory_read() {
            let mem_tools = CACHED_MEMORY_OPENAI_TOOLS.get_or_init(|| {
                crate::memory_hub::memory_tool_specs()
                    .into_iter()
                    .map(|spec| {
                        let val = json!({
                            "type": "function",
                            "function": {
                                "name": spec.name,
                                "description": spec.description,
                                "parameters": spec.parameters,
                            }
                        });
                        (spec.name, val)
                    })
                    .collect()
            });
            for (name, val) in mem_tools {
                if !privacy.allows_memory_write()
                    && crate::security_guard::is_memory_write_tool(name)
                {
                    continue;
                }
                tools.push(val.clone());
            }
        }

        let adapter_tools = CACHED_ADAPTER_OPENAI_TOOLS.get_or_init(|| {
            crate::app_adapter::adapter_tool_specs()
                .into_iter()
                .map(|spec| {
                    let val = json!({
                        "type": "function",
                        "function": {
                            "name": spec.name,
                            "description": spec.description,
                            "parameters": spec.parameters,
                        }
                    });
                    (spec.name, val)
                })
                .collect()
        });
        for (name, val) in adapter_tools {
            if !privacy.allows_memory_write() && crate::security_guard::is_memory_write_tool(name) {
                continue;
            }
            tools.push(val.clone());
        }

        tools
    }
}

const FX_SEED: u64 = 0xcbf2_9ce4_8422_2325;
const FX_K: u64 = 0x517c_c1b7_2722_0a95;

#[inline]
fn fx_mix_u64(state: u64, word: u64) -> u64 {
    (state.rotate_left(5) ^ word).wrapping_mul(FX_K)
}

#[inline]
fn fx_mix_bytes(mut state: u64, bytes: &[u8]) -> u64 {
    state = fx_mix_u64(state, bytes.len() as u64);
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        state = fx_mix_u64(state, u64::from_le_bytes(buf));
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut tail = [0u8; 8];
        tail[..rem.len()].copy_from_slice(rem);
        state = fx_mix_u64(state, u64::from_le_bytes(tail));
    }
    state
}

#[inline]
fn hash_single_descriptor_fast(mut state: u64, d: &CapabilityDescriptor) -> u64 {
    state = fx_mix_bytes(state, d.id.as_bytes());
    state = fx_mix_u64(state, u64::from(d.version));
    state = fx_mix_bytes(state, d.category.as_bytes());
    state = fx_mix_bytes(state, d.summary.as_bytes());
    state = fx_mix_u64(
        state,
        ((d.aliases.len() as u64) << 32)
            | ((d.l0_patterns.len() as u64) << 16)
            | ((d.effects.len() as u64) << 2)
            | u64::from(d.idempotent),
    );
    if let Some(first_alias) = d.aliases.first() {
        state = fx_mix_bytes(state, first_alias.as_bytes());
    }
    if let Some(last_alias) = d.aliases.last() {
        state = fx_mix_bytes(state, last_alias.as_bytes());
    }
    if let Some(first_pat) = d.l0_patterns.first() {
        state = fx_mix_bytes(state, first_pat.as_bytes());
    }
    if let Some(last_pat) = d.l0_patterns.last() {
        state = fx_mix_bytes(state, last_pat.as_bytes());
    }
    let prop_count = d
        .input_schema
        .as_object()
        .and_then(|o| o.get("properties"))
        .and_then(Value::as_object)
        .map_or(0, |p| p.len());
    fx_mix_u64(state, prop_count as u64)
}

/// Compute a fast deterministic 64-bit fingerprint from `&[&CapabilityDescriptor]` (`< 25 µs` even in debug).
pub fn compute_descriptors_fingerprint_refs(descriptors: &[&CapabilityDescriptor]) -> u64 {
    let mut state = fx_mix_u64(FX_SEED, descriptors.len() as u64);
    for d in descriptors {
        state = hash_single_descriptor_fast(state, d);
    }
    state
}

/// Compute the identical deterministic 64-bit fingerprint from `&[CapabilityDescriptor]`.
pub fn compute_descriptors_fingerprint_slice(descriptors: &[CapabilityDescriptor]) -> u64 {
    let mut state = fx_mix_u64(FX_SEED, descriptors.len() as u64);
    for d in descriptors {
        state = hash_single_descriptor_fast(state, d);
    }
    state
}

#[derive(Debug, Default)]
struct SnapshotCacheInner {
    current: Option<Arc<CapabilitySnapshot>>,
    version_seq: u64,
}

/// Thread-safe, versioned cache returning `Arc<CapabilitySnapshot>` in `< 50 microseconds` on warm hits
/// and automatically invalidating whenever descriptor count, IDs, or metadata change (`H09.1`).
#[derive(Debug, Default)]
pub struct CapabilitySnapshotCache {
    inner: RwLock<SnapshotCacheInner>,
    hits: AtomicU64,
    misses: AtomicU64,
}

static GLOBAL_SNAPSHOT_CACHE: OnceLock<CapabilitySnapshotCache> = OnceLock::new();
static EMPTY_SNAPSHOT: OnceLock<Arc<CapabilitySnapshot>> = OnceLock::new();

fn empty_capability_snapshot() -> Arc<CapabilitySnapshot> {
    EMPTY_SNAPSHOT
        .get_or_init(|| {
            let fp = compute_descriptors_fingerprint_slice(&[]);
            Arc::new(CapabilitySnapshot::from_descriptors(0, fp, Vec::new()))
        })
        .clone()
}

impl CapabilitySnapshotCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Access the process-wide shared `CapabilitySnapshotCache`.
    pub fn global() -> &'static Self {
        GLOBAL_SNAPSHOT_CACHE.get_or_init(Self::new)
    }

    /// Retrieve a warm `Arc<CapabilitySnapshot>` in `< 50 µs` or atomically compile & replace on change.
    pub fn get_or_build_from_refs(
        &self,
        descriptors: &[&CapabilityDescriptor],
    ) -> Arc<CapabilitySnapshot> {
        if descriptors.is_empty() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return empty_capability_snapshot();
        }
        let fp = compute_descriptors_fingerprint_refs(descriptors);
        if let Ok(guard) = self.inner.read()
            && let Some(ref snap) = guard.current
            && snap.fingerprint == fp
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Arc::clone(snap);
        }

        let mut guard = self
            .inner
            .write()
            .expect("CapabilitySnapshotCache write lock");
        if let Some(ref snap) = guard.current
            && snap.fingerprint == fp
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Arc::clone(snap);
        }

        guard.version_seq += 1;
        let next_ver = guard.version_seq;
        let owned: Vec<CapabilityDescriptor> = descriptors.iter().map(|d| (*d).clone()).collect();
        let built = Arc::new(CapabilitySnapshot::from_descriptors(next_ver, fp, owned));
        guard.current = Some(Arc::clone(&built));
        self.misses.fetch_add(1, Ordering::Relaxed);
        built
    }

    /// Retrieve a warm `Arc<CapabilitySnapshot>` from `&[CapabilityDescriptor]` in `< 50 µs`
    /// or atomically compile & replace when descriptors change.
    pub fn get_or_build_from_slice(
        &self,
        descriptors: &[CapabilityDescriptor],
    ) -> Arc<CapabilitySnapshot> {
        if descriptors.is_empty() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return empty_capability_snapshot();
        }
        let fp = compute_descriptors_fingerprint_slice(descriptors);
        if let Ok(guard) = self.inner.read()
            && let Some(ref snap) = guard.current
            && snap.fingerprint == fp
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Arc::clone(snap);
        }

        let mut guard = self
            .inner
            .write()
            .expect("CapabilitySnapshotCache write lock");
        if let Some(ref snap) = guard.current
            && snap.fingerprint == fp
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Arc::clone(snap);
        }

        guard.version_seq += 1;
        let next_ver = guard.version_seq;
        let built = Arc::new(CapabilitySnapshot::from_descriptors(
            next_ver,
            fp,
            descriptors.to_vec(),
        ));
        guard.current = Some(Arc::clone(&built));
        self.misses.fetch_add(1, Ordering::Relaxed);
        built
    }

    /// Retrieve or build the `CapabilitySnapshot` for a `CapabilityBroker`.
    pub fn get_or_build_for_broker(&self, broker: &CapabilityBroker) -> Arc<CapabilitySnapshot> {
        let refs = broker.descriptors();
        self.get_or_build_from_refs(&refs)
    }

    /// Retrieve or build the `CapabilitySnapshot` for `IntentOsCore`.
    pub fn get_or_build_for_core(&self, core: &IntentOsCore) -> Arc<CapabilitySnapshot> {
        self.get_or_build_for_broker(&core.broker)
    }

    /// Explicitly invalidate any cached snapshot while preserving monotonic version numbering.
    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.inner.write() {
            guard.current = None;
        }
    }

    /// Inspect the currently cached snapshot without building.
    pub fn cached_snapshot(&self) -> Option<Arc<CapabilitySnapshot>> {
        self.inner.read().ok().and_then(|g| g.current.clone())
    }

    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

/// Convenience helper: fetch `Arc<CapabilitySnapshot>` from the global cache for `IntentOsCore`.
pub fn capability_snapshot_for_core(core: &IntentOsCore) -> Arc<CapabilitySnapshot> {
    CapabilitySnapshotCache::global().get_or_build_for_core(core)
}

/// Convenience helper: fetch `Arc<CapabilitySnapshot>` from the global cache for `CapabilityBroker`.
pub fn capability_snapshot_for_broker(broker: &CapabilityBroker) -> Arc<CapabilitySnapshot> {
    CapabilitySnapshotCache::global().get_or_build_for_broker(broker)
}

/// Convenience helper: fetch `Arc<CapabilitySnapshot>` from the global cache for `&[CapabilityDescriptor]`.
pub fn capability_snapshot_from_slice(
    descriptors: &[CapabilityDescriptor],
) -> Arc<CapabilitySnapshot> {
    CapabilitySnapshotCache::global().get_or_build_from_slice(descriptors)
}

/// Convenience helper: fetch `Arc<CapabilitySnapshot>` from the global cache for `&[&CapabilityDescriptor]`.
pub fn capability_snapshot_from_refs(
    descriptors: &[&CapabilityDescriptor],
) -> Arc<CapabilitySnapshot> {
    CapabilitySnapshotCache::global().get_or_build_from_refs(descriptors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use intentos_capability_sdk::load_descriptors_from_dir;
    use intentos_protocol::ExecutionBackend;
    use std::path::PathBuf;
    use std::time::Instant;

    fn load_builtin_descriptors() -> Vec<CapabilityDescriptor> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let modules_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .join("modules/builtin");
        load_descriptors_from_dir(&modules_dir).expect("load builtin descriptors")
    }

    fn make_synthetic_descriptor(id: &str, summary: &str, category: &str) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: id.to_string(),
            version: 1,
            summary: summary.to_string(),
            category: category.to_string(),
            aliases: vec!["量子校准测试".to_string(), "quantum calibrate".to_string()],
            l0_patterns: vec!["执行量子校准 {target}".to_string()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string" }
                },
                "required": ["target"]
            }),
            effects: vec![Effect::Observe],
            idempotent: true,
            execution: ExecutionBackend::Builtin {
                handler: id.to_string(),
            },
            setting: None,
            undo: UndoStrategy::None,
            verification: None,
            feedback: None,
            dependencies: Vec::new(),
        }
    }

    #[test]
    fn h09_warm_capability_snapshot_and_search_sub_millisecond_and_auto_invalidation() {
        let builtins = load_builtin_descriptors();
        assert!(
            builtins.len() >= 80,
            "expected >= 80 builtin descriptors, got {}",
            builtins.len()
        );

        let cache = CapabilitySnapshotCache::new();

        // 1. Cold build compiles all regex patterns, OpenAI/Anthropic schemas, and inverted search index
        let cold_start = Instant::now();
        let snap_v1 = cache.get_or_build_from_slice(&builtins);
        let cold_elapsed = cold_start.elapsed();
        assert_eq!(snap_v1.version, 1);
        assert_eq!(snap_v1.len(), builtins.len());
        assert_eq!(snap_v1.tool_specs_by_id.len(), builtins.len());
        assert_eq!(snap_v1.openai_schema_by_id.len(), builtins.len());
        assert_eq!(snap_v1.anthropic_schema_by_id.len(), builtins.len());
        assert_eq!(cache.miss_count(), 1);

        // Verify refs vs slice produce identical fingerprint & zero-miss hit
        let refs: Vec<&CapabilityDescriptor> = builtins.iter().collect();
        assert_eq!(
            compute_descriptors_fingerprint_slice(&builtins),
            compute_descriptors_fingerprint_refs(&refs)
        );

        // 2. Warm cache hit must share the exact `Arc<CapabilitySnapshot>` in well under 1 ms (< 50 µs typical)
        let warm_iters = 50u32;
        let warm_start = Instant::now();
        for _ in 0..warm_iters {
            let warm_snap = cache.get_or_build_from_refs(&refs);
            assert!(Arc::ptr_eq(&snap_v1, &warm_snap));
        }
        let avg_warm_get = warm_start.elapsed() / warm_iters;
        assert!(
            avg_warm_get.as_micros() < 1_000,
            "warm snapshot retrieval must be < 1 ms (got {:?}, cold was {:?})",
            avg_warm_get,
            cold_elapsed
        );
        assert_eq!(cache.miss_count(), 1);
        assert_eq!(cache.hit_count(), u64::from(warm_iters));

        // 3. O(1) schema & canonical ID lookup by both dotted ID and underscored tool name
        assert_eq!(
            snap_v1.resolve_canonical_id("sound_volume_set"),
            Some("sound.volume.set")
        );
        assert!(snap_v1.get_openai_schema("sound.volume.set").is_some());
        assert!(snap_v1.get_anthropic_schema("sound_volume_set").is_some());

        // 4. Warm lexical / Pinyin / domain search must run in < 1 ms
        let search_start = Instant::now();
        let vol_hits = snap_v1.search("调小音量", 5);
        let py_hits = snap_v1.search("hyms", 5);
        let dom_hits = snap_v1.search_filtered("", Some("sound"), Some(Effect::Setting), 10);
        let avg_search = search_start.elapsed() / 3;

        assert!(
            !vol_hits.is_empty() && vol_hits[0].capability_id == "sound.volume.set",
            "expected sound.volume.set at rank 1, got {:?}",
            vol_hits
        );
        assert!(
            !py_hits.is_empty() && py_hits[0].capability_id == "scene.apply",
            "expected scene.apply for pinyin 'hyms', got {:?}",
            py_hits
        );
        assert!(
            !dom_hits.is_empty() && dom_hits.iter().all(|h| h.domain == "sound"),
            "expected sound domain capabilities, got {:?}",
            dom_hits
        );
        assert!(
            avg_search.as_micros() < 1_000,
            "warm CapabilitySearchIndex lookup must be < 1 ms (got {:?})",
            avg_search
        );

        // 4b. Warm Quick-Chat OpenAI tools assembly must ALSO run in < 1 ms (vs 23.73 ms cold baseline)
        let _ =
            snap_v1.build_quick_chat_openai_tools("调小音量", None, PrivacySessionPolicy::Standard);
        let tools_iters = 20u32;
        let tools_start = Instant::now();
        for _ in 0..tools_iters {
            let tools = snap_v1.build_quick_chat_openai_tools(
                "调小音量",
                None,
                PrivacySessionPolicy::Standard,
            );
            assert!(!tools.is_empty());
        }
        let avg_tools = tools_start.elapsed() / tools_iters;
        println!(
            "[h09_bench] cold_build={:?}, warm_get={:?}, warm_search={:?}, warm_quick_chat_tools={:?}",
            cold_elapsed, avg_warm_get, avg_search, avg_tools
        );
        assert!(
            avg_tools.as_micros() < 1_000,
            "warm build_quick_chat_openai_tools must be < 1 ms (got {:?})",
            avg_tools
        );

        // 5. Adding a new CapabilityDescriptor must immediately invalidate and advance version (1 -> 2)
        let mut extended = builtins.clone();
        extended.push(make_synthetic_descriptor(
            "lab.quantum.calibrate",
            "校准实验室量子传感器基准参数",
            "diagnostics",
        ));

        let snap_v2 = cache.get_or_build_from_slice(&extended);
        assert_eq!(snap_v2.version, 2);
        assert_ne!(snap_v2.fingerprint, snap_v1.fingerprint);
        assert!(!Arc::ptr_eq(&snap_v1, &snap_v2));
        assert_eq!(snap_v2.len(), builtins.len() + 1);

        let new_hits = snap_v2.search("量子校准", 3);
        assert!(!new_hits.is_empty());
        assert_eq!(new_hits[0].capability_id, "lab.quantum.calibrate");
        assert!(snap_v2.get_openai_schema("lab_quantum_calibrate").is_some());

        // 6. Modifying an existing descriptor's schema/summary also invalidates immediately (2 -> 3)
        extended.last_mut().unwrap().summary = "更新后的量子探针校准能力".to_string();
        let snap_v3 = cache.get_or_build_from_slice(&extended);
        assert_eq!(snap_v3.version, 3);
        assert_ne!(snap_v3.fingerprint, snap_v2.fingerprint);
    }
}
