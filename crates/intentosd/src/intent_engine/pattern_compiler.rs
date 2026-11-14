#![forbid(unsafe_code)]

//! Dynamic Descriptor Pattern Compiler (`pattern_compiler.rs`, §3.1, §4.3, §4.5).
//!
//! Dynamically compiles `CapabilityDescriptor` metadata (`id`, `summary`, `aliases`,
//! `l0_patterns`, `category`) into flexible regex templates, colloquial trigger tables,
//! and Chinese Pinyin (full + initials) indices.

use crate::resource::to_pinyin_pair;
use intentos_protocol::CapabilityDescriptor;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A compiled L0 pattern template derived from `CapabilityDescriptor.l0_patterns`.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub capability_id: String,
    pub raw_pattern: String,
    pub regex: Regex,
    pub slot_names: Vec<String>,
    pub base_weight: f64,
}

/// Lexicon & pattern index entry for a single registered `CapabilityDescriptor`.
#[derive(Debug, Clone)]
pub struct DescriptorLexiconEntry {
    pub capability_id: String,
    pub category: String,
    pub summary: String,
    pub aliases: Vec<String>,
    pub colloquial_triggers: Vec<String>,
    pub pinyin_full_terms: Vec<(String, String)>, // (pinyin_full, original_term)
    pub pinyin_init_terms: Vec<(String, String)>, // (pinyin_init, original_term)
    pub compiled_patterns: Vec<CompiledPattern>,
}

/// Result of matching user input against compiled descriptor patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub capability_id: String,
    pub matched_pattern: String,
    pub captured_slots: HashMap<String, String>,
    pub confidence: f64,
}

/// Colloquial normalization result containing canonicalized text and semantic hints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ColloquialAnalysis {
    pub original: String,
    pub normalized: String,
    pub detected_direction: Option<String>, // "up", "down", "warmer", "cooler", "max", "min"
    pub detected_toggle: Option<String>,    // "on", "off", "toggle"
    pub action_verbs: Vec<String>,
}

/// Dynamic pattern compiler and lexicon index over all registered capabilities.
#[derive(Debug, Clone)]
pub struct PatternCompiler {
    entries: Vec<DescriptorLexiconEntry>,
    by_id: HashMap<String, usize>,
}

impl PatternCompiler {
    /// Compile all `CapabilityDescriptor` items into a searchable pattern & pinyin index.
    pub fn compile_from_descriptors(descriptors: &[&CapabilityDescriptor]) -> Self {
        let mut entries = Vec::with_capacity(descriptors.len());
        let mut by_id = HashMap::with_capacity(descriptors.len());

        for desc in descriptors {
            let compiled_patterns = compile_descriptor_patterns(&desc.id, &desc.l0_patterns);
            let colloquial_triggers = build_colloquial_triggers(&desc.id, &desc.aliases, &desc.summary);

            let mut pinyin_full_terms = Vec::new();
            let mut pinyin_init_terms = Vec::new();

            let mut all_terms: Vec<String> = desc.aliases.clone();
            for trig in &colloquial_triggers {
                if !all_terms.iter().any(|t| t.eq_ignore_ascii_case(trig)) {
                    all_terms.push(trig.clone());
                }
            }
            // Also index short summary head before punctuation
            let summary_head = desc
                .summary
                .split(['（', '(', '，', ',', '；', ';'])
                .next()
                .unwrap_or(&desc.summary)
                .trim();
            if !summary_head.is_empty() && summary_head.chars().count() <= 14 {
                all_terms.push(summary_head.to_string());
            }

            for term in &all_terms {
                let (pf, pi) = to_pinyin_pair(term);
                if pf.len() >= 2 {
                    pinyin_full_terms.push((pf, term.clone()));
                }
                if pi.len() >= 2 {
                    pinyin_init_terms.push((pi, term.clone()));
                }
            }

            let idx = entries.len();
            by_id.insert(desc.id.clone(), idx);
            entries.push(DescriptorLexiconEntry {
                capability_id: desc.id.clone(),
                category: desc.category.clone(),
                summary: desc.summary.clone(),
                aliases: desc.aliases.clone(),
                colloquial_triggers,
                pinyin_full_terms,
                pinyin_init_terms,
                compiled_patterns,
            });
        }

        Self { entries, by_id }
    }

    pub fn entries(&self) -> &[DescriptorLexiconEntry] {
        &self.entries
    }

    pub fn get_entry(&self, capability_id: &str) -> Option<&DescriptorLexiconEntry> {
        self.by_id
            .get(capability_id)
            .and_then(|&idx| self.entries.get(idx))
    }

    /// Match input text against all compiled `l0_patterns` across descriptors.
    pub fn match_patterns(&self, raw_input: &str) -> Vec<PatternMatch> {
        let trimmed = raw_input.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        let analysis = analyze_colloquial_input(trimmed);
        let candidates_to_test = if analysis.normalized != trimmed && !analysis.normalized.is_empty()
        {
            vec![trimmed, analysis.normalized.as_str()]
        } else {
            vec![trimmed]
        };

        let mut matches = Vec::new();
        for entry in &self.entries {
            for pat in &entry.compiled_patterns {
                for &text_variant in &candidates_to_test {
                    if let Some(caps) = pat.regex.captures(text_variant) {
                        let mut slots = HashMap::new();
                        for slot_name in &pat.slot_names {
                            if let Some(m) = caps.name(slot_name) {
                                let val = m.as_str().trim();
                                if !val.is_empty() {
                                    slots.insert(slot_name.clone(), val.to_string());
                                }
                            }
                        }
                        let specificity_bonus = (pat.slot_names.len() as f64) * 0.02
                            + (pat.raw_pattern.chars().count().min(20) as f64) * 0.003;
                        let confidence = (pat.base_weight + specificity_bonus).clamp(0.0, 0.99);
                        matches.push(PatternMatch {
                            capability_id: entry.capability_id.clone(),
                            matched_pattern: pat.raw_pattern.clone(),
                            captured_slots: slots,
                            confidence,
                        });
                        break;
                    }
                }
            }
        }

        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        matches
    }
}

/// Analyze colloquial Chinese/English input, normalizing slang verbs/adjectives and extracting directional/toggle hints.
pub fn analyze_colloquial_input(input: &str) -> ColloquialAnalysis {
    let trimmed = input.trim();
    let mut normalized = trimmed.to_string();
    let mut detected_direction = None;
    let mut detected_toggle = None;
    let mut action_verbs = Vec::new();

    // Polite prefixes & filler words removal at boundaries
    for prefix in [
        "请帮我", "帮我把", "帮我", "麻烦帮我", "麻烦", "给我", "请", "立刻", "马上", "现在",
    ] {
        if let Some(rest) = normalized.strip_prefix(prefix) {
            let r = rest.trim();
            if !r.is_empty() {
                normalized = r.to_string();
                break;
            }
        }
    }
    for suffix in ["吧", "呀", "呗", "好吗", "可以吗", "一下吧"] {
        if let Some(rest) = normalized.strip_suffix(suffix) {
            let r = rest.trim();
            if !r.is_empty() {
                normalized = r.to_string();
                break;
            }
        }
    }

    // Colloquial verb & adjective replacements
    let colloquial_rewrites: &[(&str, &str)] = &[
        ("搞大点", "调大一点"),
        ("搞大一点", "调大一点"),
        ("弄大点", "调大一点"),
        ("弄大一点", "调大一点"),
        ("调高点", "调高一点"),
        ("大声点", "声音大一点"),
        ("声音大点", "声音大一点"),
        ("响一点", "声音大一点"),
        ("搞小点", "调小一点"),
        ("搞小一点", "调小一点"),
        ("弄小点", "调小一点"),
        ("弄小一点", "调小一点"),
        ("调低点", "调低一点"),
        ("小声点", "声音小一点"),
        ("声音小点", "声音小一点"),
        ("声音轻一点", "声音小一点"),
        ("轻一点", "声音小一点"),
        ("亮一点", "调亮一点"),
        ("暗一点", "调暗一点"),
        ("黑一点", "调暗一点"),
        ("瞅瞅", "查看"),
        ("看下", "查看"),
        ("看看", "查看"),
        ("查下", "查一下"),
        ("搜下", "搜一下"),
        ("找下", "找一下"),
        ("干掉", "关掉"),
        ("弄成", "设为"),
        ("搞成", "设为"),
        ("调成", "设为"),
        ("改成", "设为"),
        ("切到", "切换到"),
    ];

    for (from, to) in colloquial_rewrites {
        if normalized.contains(from) {
            normalized = normalized.replace(from, to);
        }
    }

    let lc = normalized.to_ascii_lowercase();

    // Detect relative direction
    if normalized.contains("拉满")
        || normalized.contains("调到最大")
        || normalized.contains("最大声")
        || normalized.contains("最亮")
        || normalized.contains("开到最大")
        || lc.contains("max")
    {
        detected_direction = Some("max".to_string());
    } else if normalized.contains("调到最小")
        || normalized.contains("最低")
        || normalized.contains("最暗")
        || normalized.contains("最小声")
    {
        detected_direction = Some("min".to_string());
    } else if normalized.contains("暖一点")
        || normalized.contains("更暖")
        || normalized.contains("黄一点")
    {
        detected_direction = Some("warmer".to_string());
    } else if normalized.contains("冷一点") || normalized.contains("更冷") {
        detected_direction = Some("cooler".to_string());
    } else if normalized.contains("大一点")
        || normalized.contains("高一点")
        || normalized.contains("亮一点")
        || normalized.contains("快一点")
        || normalized.contains("调大")
        || normalized.contains("调高")
        || normalized.contains("调亮")
        || normalized.contains("放大")
        || normalized.contains("增加")
        || lc.contains(" up")
        || normalized.contains('+')
    {
        detected_direction = Some("up".to_string());
    } else if normalized.contains("小一点")
        || normalized.contains("低一点")
        || normalized.contains("暗一点")
        || normalized.contains("慢一点")
        || normalized.contains("调小")
        || normalized.contains("调低")
        || normalized.contains("调暗")
        || normalized.contains("缩小")
        || normalized.contains("减小")
        || lc.contains(" down")
    {
        detected_direction = Some("down".to_string());
    }

    // Detect toggle state
    if normalized.contains("取消")
        || normalized.contains("关闭")
        || normalized.contains("关掉")
        || normalized.contains("禁用")
        || normalized.contains("退出")
        || normalized.starts_with('关')
        || lc.ends_with(" off")
        || lc.starts_with("unmute")
        || lc.starts_with("disable ")
    {
        detected_toggle = Some("off".to_string());
    } else if normalized.contains("开启")
        || normalized.contains("打开")
        || normalized.contains("启用")
        || normalized.contains("进入")
        || normalized.starts_with('开')
        || lc.ends_with(" on")
        || lc.starts_with("enable ")
    {
        detected_toggle = Some("on".to_string());
    } else if normalized.contains("切换") || lc.contains("toggle") {
        detected_toggle = Some("toggle".to_string());
    }

    for v in [
        "打开", "启动", "关闭", "退出", "查找", "找", "搜索", "搜", "移动", "复制", "重命名",
        "删除", "解压", "打包", "设置", "设为", "切换", "查看",
    ] {
        if normalized.contains(v) {
            action_verbs.push(v.to_string());
        }
    }

    ColloquialAnalysis {
        original: trimmed.to_string(),
        normalized,
        detected_direction,
        detected_toggle,
        action_verbs,
    }
}

/// Convert `l0_patterns` strings (with `{slot}` placeholders) into compiled `Regex` instances.
fn compile_descriptor_patterns(cap_id: &str, raw_patterns: &[String]) -> Vec<CompiledPattern> {
    let mut out = Vec::new();
    let placeholder_re = Regex::new(r"\{([a-zA-Z0-9_]+)\}").expect("valid placeholder regex");

    for raw in raw_patterns {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip purely generic placeholder-only templates like "{site_alias} {query}" that have no literal anchor keyword
        let literal_only = placeholder_re.replace_all(trimmed, "");
        let has_literal_anchor = literal_only
            .chars()
            .any(|c| !c.is_whitespace() && !matches!(c, '(' | ')' | '?' | '+' | '*' | '|'));
        if !has_literal_anchor {
            continue;
        }
        let mut slot_names = Vec::new();
        let mut regex_str = String::from("^\\s*");
        let mut last_end = 0;

        for caps in placeholder_re.captures_iter(trimmed) {
            let Some(full_match) = caps.get(0) else {
                continue;
            };
            let slot_name = caps[1].to_string();
            let prefix_segment = &trimmed[last_end..full_match.start()];
            regex_str.push_str(&flexible_pattern_segment(prefix_segment));
            regex_str.push_str(&format!("(?P<{}>.+?)", slot_name));
            slot_names.push(slot_name);
            last_end = full_match.end();
        }
        regex_str.push_str(&flexible_pattern_segment(&trimmed[last_end..]));
        regex_str.push_str("\\s*$");

        if let Ok(re) = Regex::new(&format!("(?i){}", regex_str)) {
            let base_weight = if slot_names.is_empty() { 0.96 } else { 0.86 };
            out.push(CompiledPattern {
                capability_id: cap_id.to_string(),
                raw_pattern: trimmed.to_string(),
                regex: re,
                slot_names,
                base_weight,
            });
        }
    }
    out
}

fn flexible_pattern_segment(segment: &str) -> String {
    // Replace spaces in pattern templates with `\s*` so Chinese/ASCII mixed inputs match with or without spaces
    let mut out = String::new();
    let mut prev_space = false;
    for ch in segment.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push_str(r"\s*");
                prev_space = true;
            }
        } else {
            prev_space = false;
            out.push(ch);
        }
    }
    out
}

/// Build rich colloquial Chinese/English/abbreviation triggers for a capability descriptor.
fn build_colloquial_triggers(cap_id: &str, aliases: &[String], summary: &str) -> Vec<String> {
    let mut triggers: Vec<String> = aliases.to_vec();

    let extra: &[&str] = match cap_id {
        "sound.volume.set" => &[
            "声音小点",
            "声音大点",
            "小声点",
            "大声点",
            "调大音量",
            "调小音量",
            "调高音量",
            "调低音量",
            "音量拉满",
            "声音拉满",
            "把声音搞大点",
            "把声音搞小点",
            "音量调小一点",
            "音量调大一点",
            "声音轻一点",
            "volume up",
            "volume down",
        ],
        "sound.volume.get" => &["音量多少", "现在音量", "查下音量", "瞅瞅音量"],
        "sound.mute.set" => &[
            "静音",
            "闭嘴",
            "别响",
            "没声音",
            "把声音关掉",
            "关掉声音",
            "取消静音",
            "恢复声音",
            "开声音",
            "出声",
        ],
        "sound.mic.mute.set" => &[
            "闭麦",
            "关麦",
            "把麦克风关掉",
            "麦克风静音",
            "开麦",
            "打开麦克风",
            "取消闭麦",
        ],
        "sound.mic.volume.set" => &["麦克风大声点", "麦克风小声点", "调大麦克风", "调小麦克风"],
        "sound.output.set" => &["切到耳机", "切到外放", "切到扬声器", "声音切到耳机"],
        "display.brightness.set" => &[
            "暗一点",
            "亮一点",
            "调暗一点",
            "调亮一点",
            "屏幕暗一点",
            "屏幕亮一点",
            "亮度拉满",
            "屏幕太亮了",
            "屏幕太暗了",
            "再暗一点",
            "再亮一点",
            "把亮度调低",
            "把亮度调高",
        ],
        "display.brightness.get" => &["亮度多少", "当前亮度", "查下亮度"],
        "display.night_light.set" => &[
            "开启夜灯",
            "打开夜灯",
            "关闭夜灯",
            "关掉夜灯",
            "护眼灯",
            "防蓝光",
            "开启护眼灯",
        ],
        "display.night_light.temperature" => &[
            "暖一点",
            "冷一点",
            "屏幕暖一点",
            "屏幕冷一点",
            "色温暖一点",
            "色温冷一点",
            "黄一点",
        ],
        "display.idle_delay.set" => &["不熄屏", "从不熄屏", "禁止熄屏", "保持亮屏"],
        "scene.apply" => &[
            "护眼模式",
            "开启护眼模式",
            "进入护眼模式",
            "打开护眼模式",
            "演示模式",
            "开启演示模式",
            "安静模式",
            "开启安静模式",
            "会议模式",
            "开启会议模式",
            "专注模式",
            "开启专注模式",
        ],
        "appearance.color_scheme.set" => &[
            "深色模式",
            "暗黑模式",
            "夜间模式",
            "暗色模式",
            "浅色模式",
            "亮色模式",
            "日间模式",
            "切换到深色模式",
            "切换到浅色模式",
        ],
        "appearance.text_scale.set" => &[
            "字体大一点",
            "字体小一点",
            "字大一点",
            "字小一点",
            "文字放大",
            "文字缩小",
            "字号调大",
            "字号调小",
        ],
        "notify.dnd.set" => &[
            "勿扰模式",
            "开启勿扰模式",
            "打开勿扰模式",
            "开启勿扰",
            "关闭勿扰",
            "取消勿扰",
            "免打扰",
            "开启免打扰",
            "别弹通知",
        ],
        "bluetooth.power" => &["开蓝牙", "关蓝牙", "打开蓝牙", "关闭蓝牙", "关掉蓝牙"],
        "network.wifi.power" => &[
            "开wifi",
            "关wifi",
            "打开wifi",
            "关闭wifi",
            "打开无线网",
            "关闭无线网",
        ],
        "network.ip" => &[
            "我的ip",
            "本机ip",
            "查下ip",
            "局域网地址",
            "内网地址",
            "ip是多少",
        ],
        "disk.free" => &[
            "磁盘还剩多少",
            "硬盘还剩多少",
            "磁盘空间",
            "空间够不够",
            "容量还剩多少",
        ],
        "disk.usage" => &["目录大小", "谁占空间最多", "占了多少空间"],
        "port.inspect" => &["端口谁在用", "查看端口占用", "监听端口"],
        "process.list" => &["占内存最多的进程", "最占内存的进程", "进程列表", "查看进程"],
        "system.inspect" => &["系统状态", "系统负载", "电脑状态", "内存使用情况", "看看负载"],
        "screen.lock" => &["锁屏", "锁定屏幕", "立刻锁屏", "锁一下电脑"],
        "screenshot.take" => &["截图", "截屏", "全屏截图", "窗口截图", "区域截图"],
        "power.battery.status" => &["电池电量", "还有多少电", "查看电量", "电量多少"],
        "power.profile.set" => &[
            "省电模式",
            "性能模式",
            "平衡模式",
            "满血性能",
            "省电续航",
        ],
        "settings.open_panel" => &[
            "蓝牙设置在哪",
            "显示设置在哪",
            "声音设置在哪",
            "网络设置在哪",
            "电源设置在哪",
        ],
        _ => &[],
    };

    for &item in extra {
        if !triggers.iter().any(|t| t.eq_ignore_ascii_case(item)) {
            triggers.push(item.to_string());
        }
    }

    // Also extract short quoted phrases from summary if present (e.g. 「字体大一点」)
    let quote_re = Regex::new(r"「([^」]{2,16})」").expect("valid quote regex");
    for caps in quote_re.captures_iter(summary) {
        let phrase = caps[1].trim();
        if !phrase.is_empty() && !triggers.iter().any(|t| t == phrase) {
            triggers.push(phrase.to_string());
        }
    }

    triggers
}
