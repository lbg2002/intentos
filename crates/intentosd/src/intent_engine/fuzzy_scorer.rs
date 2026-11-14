#![forbid(unsafe_code)]

//! Multi-Factor Fuzzy Scorer (`fuzzy_scorer.rs`, §3.1, §4.3, §4.6).
//!
//! Combines exact match, prefix match, colloquial alias/synonym match,
//! Chinese Pinyin (full & initials via `pinyin` crate), edit distance
//! (Levenshtein & Jaro-Winkler for 1–2 char typo tolerance), character bigrams,
//! and Frecency weights from `IndexDb`.

use crate::db::IndexDb;
use crate::intent_engine::pattern_compiler::{
    DescriptorLexiconEntry, PatternCompiler, analyze_colloquial_input,
};
use crate::resource::to_pinyin_pair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Match tier ordered according to §4.6:
/// `Exact > Prefix > AliasSynonym > Pinyin > FuzzyEditBigram`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchTier {
    None = 0,
    FuzzyEditBigram = 1,
    Pinyin = 2,
    AliasSynonym = 3,
    Prefix = 4,
    Exact = 5,
}

/// Detailed multi-factor score breakdown for a candidate or capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzyScoreBreakdown {
    pub tier: MatchTier,
    pub lexical_score: f64,   // [0.0, 1.0]
    pub pinyin_score: f64,    // [0.0, 1.0]
    pub edit_similarity: f64, // [0.0, 1.0]
    pub bigram_score: f64,    // [0.0, 1.0]
    pub frecency_boost: f64,  // additive/multiplicative boost from user history
    pub total_score: f64,     // combined score [0.0, 150.0]
    pub matched_term: String,
}

/// A scored capability match produced by `FuzzyScorer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredCapabilityMatch {
    pub capability_id: String,
    pub summary: String,
    pub category: String,
    pub confidence: f64, // normalized [0.0, 0.99]
    pub total_score: f64,
    pub breakdown: FuzzyScoreBreakdown,
    pub captured_slots: HashMap<String, String>,
}

/// Compute character-level Levenshtein edit distance between two strings.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];

    for (i, &ca) in a_chars.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Compute Jaro-Winkler similarity in `[0.0, 1.0]`.
pub fn jaro_winkler_similarity(a: &str, b: &str) -> f64 {
    let s1: Vec<char> = a.chars().collect();
    let s2: Vec<char> = b.chars().collect();
    let len1 = s1.len();
    let len2 = s2.len();

    if len1 == 0 && len2 == 0 {
        return 1.0;
    }
    if len1 == 0 || len2 == 0 {
        return 0.0;
    }
    if s1 == s2 {
        return 1.0;
    }

    let match_distance = (len1.max(len2) / 2).saturating_sub(1);
    let mut s1_matches = vec![false; len1];
    let mut s2_matches = vec![false; len2];

    let mut matches = 0usize;
    for i in 0..len1 {
        let start = i.saturating_sub(match_distance);
        let end = (i + match_distance + 1).min(len2);
        for j in start..end {
            if !s2_matches[j] && s1[i] == s2[j] {
                s1_matches[i] = true;
                s2_matches[j] = true;
                matches += 1;
                break;
            }
        }
    }

    if matches == 0 {
        return 0.0;
    }

    let mut transpositions = 0usize;
    let mut k = 0usize;
    for i in 0..len1 {
        if !s1_matches[i] {
            continue;
        }
        while !s2_matches[k] {
            k += 1;
        }
        if s1[i] != s2[k] {
            transpositions += 1;
        }
        k += 1;
    }

    let m = matches as f64;
    let jaro =
        (m / len1 as f64 + m / len2 as f64 + (m - (transpositions as f64 / 2.0)) / m) / 3.0;

    let prefix_len = s1
        .iter()
        .zip(s2.iter())
        .take(4)
        .take_while(|(c1, c2)| c1 == c2)
        .count() as f64;

    (jaro + prefix_len * 0.1 * (1.0 - jaro)).clamp(0.0, 1.0)
}

/// Compute character bigram Dice similarity in `[0.0, 1.0]`.
pub fn char_bigram_similarity(a: &str, b: &str) -> f64 {
    let bg_a = char_bigrams(a);
    let bg_b = char_bigrams(b);
    if bg_a.is_empty() || bg_b.is_empty() {
        return 0.0;
    }
    let inter = bg_a.iter().filter(|x| bg_b.contains(x)).count();
    ((2.0 * inter as f64) / (bg_a.len() + bg_b.len()) as f64).clamp(0.0, 1.0)
}

fn char_bigrams(s: &str) -> Vec<(char, char)> {
    let chars: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    chars.windows(2).map(|w| (w[0], w[1])).collect()
}

/// Score a query against a target string (e.g. app name, file name, alias, setting label)
/// using Exact > Prefix > Alias/Substring > Pinyin (full & initials + mixed) > Edit-distance/Bigram.
pub fn score_query_against_term(
    raw_query: &str,
    target_term: &str,
    is_alias_or_synonym: bool,
    frecency_boost: f64,
) -> FuzzyScoreBreakdown {
    let q = raw_query.trim().to_ascii_lowercase();
    let t = target_term.trim().to_ascii_lowercase();
    if q.is_empty() || t.is_empty() {
        return FuzzyScoreBreakdown {
            tier: MatchTier::None,
            lexical_score: 0.0,
            pinyin_score: 0.0,
            edit_similarity: 0.0,
            bigram_score: 0.0,
            frecency_boost: 0.0,
            total_score: 0.0,
            matched_term: String::new(),
        };
    }

    let (t_py_full, t_py_init) = to_pinyin_pair(&t);
    let (q_py_full, q_py_init) = to_pinyin_pair(&q);

    let mut tier = MatchTier::None;
    let mut lexical_score: f64 = 0.0;
    let mut pinyin_score: f64 = 0.0;

    // 1. Exact or Prefix or Substring match
    if q == t {
        tier = if is_alias_or_synonym {
            MatchTier::AliasSynonym
        } else {
            MatchTier::Exact
        };
        lexical_score = if is_alias_or_synonym { 0.96 } else { 1.0 };
    } else if t.starts_with(&q) {
        tier = if is_alias_or_synonym {
            MatchTier::AliasSynonym
        } else {
            MatchTier::Prefix
        };
        lexical_score = if is_alias_or_synonym { 0.91 } else { 0.93 };
    } else if q.contains(&t) && t.chars().count() >= 2 {
        tier = MatchTier::AliasSynonym;
        lexical_score = 0.90;
    } else if t.contains(&q) && q.chars().count() >= 2 {
        tier = MatchTier::AliasSynonym;
        lexical_score = 0.84;
    }

    // 2. Pinyin matching (full pinyin, initials, prefix, or mixed pinyin like `hymoshi` -> `huyanmoshi`)
    let q_clean: String = q.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if !q_clean.is_empty() && !t_py_full.is_empty() {
        if q_clean == t_py_init || q_clean == t_py_full {
            pinyin_score = 0.95;
        } else if t_py_init.starts_with(&q_clean) || t_py_full.starts_with(&q_clean) {
            pinyin_score = 0.86;
        } else if is_mixed_pinyin_match(&q_clean, &t) {
            pinyin_score = 0.90;
        } else if t_py_full.contains(&q_clean) && q_clean.len() >= 3 {
            pinyin_score = 0.78;
        } else if !q_py_full.is_empty() && q_py_full == t_py_full && q != t {
            // Homophone typo tolerance in Chinese (e.g. 护眼魔式 -> 护眼模式)
            pinyin_score = 0.88;
        } else if !q_py_init.is_empty()
            && q_py_init == t_py_init
            && q_py_init.len() >= 3
            && q != t
        {
            pinyin_score = 0.80;
        }

        if pinyin_score > 0.0 && tier < MatchTier::Pinyin {
            tier = MatchTier::Pinyin;
        }
    }

    // 3. Edit distance (1–2 character typo tolerance) & Bigram overlap
    let edit_dist = levenshtein_distance(&q, &t);
    let max_len = q.chars().count().max(t.chars().count());
    let jw = jaro_winkler_similarity(&q, &t);
    let edit_similarity = if max_len >= 3 && edit_dist <= 2 {
        let ratio = 1.0 - (edit_dist as f64 / max_len as f64);
        ratio.max(jw * 0.92)
    } else if q_clean.len() >= 4 && !t_py_full.is_empty() {
        let py_dist = levenshtein_distance(&q_clean, &t_py_full);
        if py_dist <= 2 {
            (1.0 - py_dist as f64 / t_py_full.len().max(1) as f64).clamp(0.0, 0.86)
        } else {
            0.0
        }
    } else {
        0.0
    };

    let bigram_score = char_bigram_similarity(&q, &t);
    if tier == MatchTier::None && (edit_similarity >= 0.62 || bigram_score >= 0.45) {
        tier = MatchTier::FuzzyEditBigram;
    }

    let base_0_to_100 = match tier {
        MatchTier::Exact => 100.0 * lexical_score,
        MatchTier::Prefix => 92.0 * lexical_score,
        MatchTier::AliasSynonym => 90.0 * lexical_score.max(pinyin_score),
        MatchTier::Pinyin => 86.0 * pinyin_score,
        MatchTier::FuzzyEditBigram => 72.0 * edit_similarity.max(bigram_score),
        MatchTier::None => 0.0,
    };

    let total_score = if base_0_to_100 > 0.0 {
        base_0_to_100 + frecency_boost
    } else {
        0.0
    };

    FuzzyScoreBreakdown {
        tier,
        lexical_score,
        pinyin_score,
        edit_similarity,
        bigram_score,
        frecency_boost,
        total_score,
        matched_term: target_term.to_string(),
    }
}

/// Check if an ASCII query is a mixed initial + full syllable pinyin match for a Chinese phrase
/// (e.g., `hymoshi` for `护眼模式` -> syllables `["hu", "yan", "mo", "shi"]`).
pub fn is_mixed_pinyin_match(ascii_query: &str, chinese_target: &str) -> bool {
    let mut syllables: Vec<String> = Vec::new();
    for ch in chinese_target.chars() {
        if let Some(py) = pinyin::ToPinyin::to_pinyin(&ch) {
            syllables.push(py.plain().to_ascii_lowercase());
        } else if ch.is_ascii_alphanumeric() {
            syllables.push(ch.to_ascii_lowercase().to_string());
        }
    }
    if syllables.len() < 2 {
        return false;
    }
    match_syllables_recursive(ascii_query.as_bytes(), &syllables, 0)
}

fn match_syllables_recursive(rem: &[u8], syllables: &[String], idx: usize) -> bool {
    if idx == syllables.len() {
        return rem.is_empty();
    }
    if rem.is_empty() {
        return false;
    }
    let syl = syllables[idx].as_bytes();
    if syl.is_empty() {
        return match_syllables_recursive(rem, syllables, idx + 1);
    }
    // Option A: consume full syllable
    if rem.starts_with(syl) && match_syllables_recursive(&rem[syl.len()..], syllables, idx + 1) {
        return true;
    }
    // Option B: consume initial letter of syllable
    if rem[0] == syl[0] && match_syllables_recursive(&rem[1..], syllables, idx + 1) {
        return true;
    }
    false
}

/// Score a single `DescriptorLexiconEntry` against a user query.
pub fn score_descriptor_entry(
    raw_query: &str,
    entry: &DescriptorLexiconEntry,
    frecency_boost: f64,
) -> Option<FuzzyScoreBreakdown> {
    let trimmed = raw_query.trim();
    if trimmed.is_empty() {
        return None;
    }
    let analysis = analyze_colloquial_input(trimmed);
    let queries_to_check = if analysis.normalized != trimmed && !analysis.normalized.is_empty() {
        vec![trimmed, analysis.normalized.as_str()]
    } else {
        vec![trimmed]
    };

    let mut best: Option<FuzzyScoreBreakdown> = None;
    let mut update_best = |cand: FuzzyScoreBreakdown| {
        if cand.total_score <= 0.0 {
            return;
        }
        match &best {
            None => best = Some(cand),
            Some(cur) if cand.total_score > cur.total_score => best = Some(cand),
            _ => {}
        }
    };

    for &q_var in &queries_to_check {
        // 1. Check capability ID directly
        if q_var.eq_ignore_ascii_case(&entry.capability_id) {
            update_best(FuzzyScoreBreakdown {
                tier: MatchTier::Exact,
                lexical_score: 1.0,
                pinyin_score: 0.0,
                edit_similarity: 1.0,
                bigram_score: 1.0,
                frecency_boost,
                total_score: 100.0 + frecency_boost,
                matched_term: entry.capability_id.clone(),
            });
        }

        // 2. Check aliases & colloquial triggers
        for alias in &entry.aliases {
            update_best(score_query_against_term(q_var, alias, false, frecency_boost));
        }
        for trig in &entry.colloquial_triggers {
            update_best(score_query_against_term(q_var, trig, true, frecency_boost));
        }

        // 3. Check summary bigram overlap for broader semantic recall
        let summary_head = entry
            .summary
            .split(['（', '('])
            .next()
            .unwrap_or(&entry.summary);
        let bg = char_bigram_similarity(q_var, summary_head);
        if bg >= 0.35 {
            update_best(FuzzyScoreBreakdown {
                tier: MatchTier::FuzzyEditBigram,
                lexical_score: 0.0,
                pinyin_score: 0.0,
                edit_similarity: 0.0,
                bigram_score: bg,
                frecency_boost,
                total_score: bg * 70.0 + frecency_boost,
                matched_term: summary_head.to_string(),
            });
        }
    }

    best
}

/// Rank all registered capabilities against `query`, combining compiled `l0_patterns`,
/// colloquial triggers, pinyin, edit distance, and `IndexDb` frecency weights.
pub fn rank_capabilities(
    query: &str,
    compiler: &PatternCompiler,
    index_db: Option<&IndexDb>,
    limit: usize,
) -> Vec<ScoredCapabilityMatch> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let pattern_hits = compiler.match_patterns(trimmed);
    let mut pattern_map: HashMap<String, (f64, HashMap<String, String>, String)> = HashMap::new();
    for hit in pattern_hits {
        pattern_map
            .entry(hit.capability_id.clone())
            .or_insert((hit.confidence, hit.captured_slots, hit.matched_pattern));
    }

    let mut results = Vec::new();
    for entry in compiler.entries() {
        let frecency_boost = index_db
            .map(|db| {
                db.get_frecency_boost(&format!("cap:{}", entry.capability_id))
                    + db.get_frecency_boost(&format!("l0:{}:0", entry.capability_id))
                    + db.get_frecency_boost(&entry.capability_id)
            })
            .unwrap_or(0.0);

        let mut captured_slots = HashMap::new();
        let mut breakdown_opt = score_descriptor_entry(trimmed, entry, frecency_boost);

        if let Some((pat_conf, slots, pat_str)) = pattern_map.get(&entry.capability_id) {
            captured_slots = slots.clone();
            let pat_score = pat_conf * 100.0 + frecency_boost;
            let should_replace = breakdown_opt
                .as_ref()
                .is_none_or(|b| pat_score > b.total_score);
            if should_replace {
                breakdown_opt = Some(FuzzyScoreBreakdown {
                    tier: MatchTier::Exact,
                    lexical_score: *pat_conf,
                    pinyin_score: 0.0,
                    edit_similarity: 1.0,
                    bigram_score: 1.0,
                    frecency_boost,
                    total_score: pat_score,
                    matched_term: pat_str.clone(),
                });
            }
        }

        if let Some(bd) = breakdown_opt
            && bd.total_score >= 28.0
        {
            let confidence = (bd.total_score / 100.0).clamp(0.10, 0.99);
            results.push(ScoredCapabilityMatch {
                capability_id: entry.capability_id.clone(),
                summary: entry.summary.clone(),
                category: entry.category.clone(),
                confidence,
                total_score: bd.total_score,
                breakdown: bd,
                captured_slots,
            });
        }
    }

    results.sort_by(|a, b| {
        b.total_score
            .partial_cmp(&a.total_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if limit > 0 {
        results.truncate(limit);
    }
    results
}
