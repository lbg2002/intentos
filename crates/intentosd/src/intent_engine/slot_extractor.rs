#![forbid(unsafe_code)]

//! Schema-Driven Universal Slot Extractor (`slot_extractor.rs`, §3.1, §4.1, §4.4, §11.6).
//!
//! Extracts structured slots from natural language input according to a capability's
//! `CapabilityDescriptor.input_schema` and `SettingMeta`:
//! - Numbers, percentages, Chinese numerals, and relative adjustments (`调大一点`, `暗一点`, `+15%`, `拉满`, `最低`)
//! - Time ranges (`今天`, `昨天`, `上周`, `最近3天`, `过去12小时`)
//! - File sizes (`大于1G`, `超过500M`, `小于100K`)
//! - File extensions & semantic MIME categories (`PDF`, `表格`, `图片`, `视频`, `压缩包`, `代码`, `*.rs`)
//! - XDG & project directories (`桌面`, `下载里`, `文档`, `当前目录`)

use crate::intent_engine::pattern_compiler::analyze_colloquial_input;
use crate::resource::ResourceEngine;
use intentos_protocol::CapabilityDescriptor;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

/// Extracted numeric or relative adjustment slot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NumericSlot {
    /// Absolute numeric value if explicitly specified or resolved from `拉满`/`最低`.
    pub value: Option<f64>,
    /// Whether the user wrote a percentage sign (`%` or `百分之`).
    pub is_percentage: bool,
    /// Relative direction: `"up"`, `"down"`, `"warmer"`, `"cooler"`.
    pub relative: Option<String>,
    /// Relative step delta if specified (e.g., `+15%` -> `Some(15.0)`).
    pub delta: Option<f64>,
}

/// Extracted time range filter slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRangeSlot {
    pub label: String,
    pub modified_within_days: Option<u64>,
    pub modified_within_hours: Option<u64>,
}

/// Extracted file size constraint slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeRangeSlot {
    pub min_size_bytes: Option<u64>,
    pub max_size_bytes: Option<u64>,
}

/// Extracted file extension / semantic type slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTypeSlot {
    pub category_label: Option<String>,
    pub extensions: Vec<String>,
    pub primary_ext: Option<String>,
}

/// Extracted directory / path location slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationSlot {
    pub raw_hint: String,
    pub resolved_path: String,
}

/// Universal bundle of all slots detected in an utterance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UniversalSlots {
    pub numeric: Option<NumericSlot>,
    pub time_range: Option<TimeRangeSlot>,
    pub size_range: Option<SizeRangeSlot>,
    pub file_type: Option<FileTypeSlot>,
    pub locations: Vec<LocationSlot>,
    pub booleans: Option<bool>,
}

/// Parse Chinese numerals (e.g., `三十`, `五十`, `一百`, `二十五`, `半`) or Arabic numbers into `f64`.
pub fn parse_chinese_or_arabic_number(s: &str) -> Option<f64> {
    let trimmed = s.trim().trim_end_matches('%');
    if let Ok(v) = trimmed.parse::<f64>() {
        return Some(v);
    }
    match trimmed {
        "半" | "一半" => return Some(50.0),
        "零" | "〇" => return Some(0.0),
        "一百" | "百" => return Some(100.0),
        _ => {}
    }

    let digit_val = |c: char| -> Option<f64> {
        match c {
            '零' | '〇' => Some(0.0),
            '一' | '壹' => Some(1.0),
            '二' | '两' | '贰' => Some(2.0),
            '三' | '叁' => Some(3.0),
            '四' | '肆' => Some(4.0),
            '五' | '伍' => Some(5.0),
            '六' | '陆' => Some(6.0),
            '七' | '柒' => Some(7.0),
            '八' | '捌' => Some(8.0),
            '九' | '玖' => Some(9.0),
            _ => None,
        }
    };

    let chars: Vec<char> = trimmed.chars().collect();
    if chars.is_empty() {
        return None;
    }
    if chars.len() == 1 {
        if chars[0] == '十' {
            return Some(10.0);
        }
        return digit_val(chars[0]);
    }
    // Handle `十X`, `X十`, `X十Y`
    if let Some(ten_pos) = chars.iter().position(|&c| c == '十' || c == '拾') {
        let tens = if ten_pos == 0 {
            1.0
        } else {
            digit_val(chars[ten_pos - 1])?
        };
        let ones = if ten_pos + 1 < chars.len() {
            digit_val(chars[ten_pos + 1]).unwrap_or(0.0)
        } else {
            0.0
        };
        return Some(tens * 10.0 + ones);
    }

    None
}

/// Extract numeric, percentage, and relative adjustment slots from user text.
pub fn parse_numeric_slot(
    text: &str,
    min_bound: Option<f64>,
    max_bound: Option<f64>,
) -> Option<NumericSlot> {
    let analysis = analyze_colloquial_input(text);
    let norm = &analysis.normalized;

    // 1. Check explicit signed delta like `+15%`, `-10%`, `+20`, `-5`
    let signed_re = Regex::new(r"([+\-])\s*(\d+(?:\.\d+)?)\s*(%)?").expect("valid regex");
    if let Some(caps) = signed_re.captures(norm) {
        let sign = &caps[1];
        if let Ok(num) = caps[2].parse::<f64>() {
            let is_pct = caps.get(3).is_some();
            let rel = if sign == "+" { "up" } else { "down" };
            return Some(NumericSlot {
                value: None,
                is_percentage: is_pct,
                relative: Some(rel.to_string()),
                delta: Some(num),
            });
        }
    }

    // 2. Check directional verb with explicit delta: `调大 15`, `调高 20%`, `调低 10`, `降低 15%`
    let rel_delta_re = Regex::new(
        r"(?:调大|调高|增加|提高|放大|调亮|调小|调低|减小|降低|缩小|调暗)\s*(\d+(?:\.\d+)?)\s*(%)?",
    )
    .expect("valid regex");
    if let Some(caps) = rel_delta_re.captures(norm)
        && !norm.contains("调到")
        && !norm.contains("设为")
        && let Ok(num) = caps[1].parse::<f64>()
    {
        let is_pct = caps.get(2).is_some();
        let dir = analysis
            .detected_direction
            .clone()
            .unwrap_or_else(|| "up".to_string());
        return Some(NumericSlot {
            value: None,
            is_percentage: is_pct,
            relative: Some(dir),
            delta: Some(num),
        });
    }

    // 3. Check `拉满` / `最大` / `最低` / `最小`
    if analysis.detected_direction.as_deref() == Some("max") {
        let val = max_bound.unwrap_or(100.0);
        return Some(NumericSlot {
            value: Some(val),
            is_percentage: false,
            relative: None,
            delta: None,
        });
    }
    if analysis.detected_direction.as_deref() == Some("min") {
        let val = min_bound.unwrap_or(0.0);
        return Some(NumericSlot {
            value: Some(val),
            is_percentage: false,
            relative: None,
            delta: None,
        });
    }

    // 4. Check explicit target number (`百分之30`, `50%`, `调到 30`, `设为 4500`, `三十`)
    let pct_cn_re =
        Regex::new(r"百分之\s*([0-9一二三四五六七八九十百]+(?:\.\d+)?)").expect("valid regex");
    if let Some(caps) = pct_cn_re.captures(norm)
        && let Some(val) = parse_chinese_or_arabic_number(&caps[1])
    {
        return Some(NumericSlot {
            value: Some(val),
            is_percentage: true,
            relative: None,
            delta: None,
        });
    }

    let num_re = Regex::new(r"(\d+(?:\.\d+)?)\s*(%)?").expect("valid regex");
    // Avoid mistaking time/size numbers (`最近3天`, `大于1G`, `8080端口` when looking for setting value)
    // unless it's clearly a number argument
    if let Some(caps) = num_re.captures(norm)
        && let Ok(val) = caps[1].parse::<f64>()
    {
        let is_pct = caps.get(2).is_some();
        return Some(NumericSlot {
            value: Some(val),
            is_percentage: is_pct,
            relative: None,
            delta: None,
        });
    }

    // Chinese numeral after `到`/`为`/`成` (e.g. `音量调到三十`, `音量调到一半`)
    let cn_num_re =
        Regex::new(r"(?:到|为|成)\s*([零一二两三四五六七八九十百半]+)").expect("valid regex");
    if let Some(caps) = cn_num_re.captures(norm)
        && let Some(val) = parse_chinese_or_arabic_number(&caps[1])
    {
        return Some(NumericSlot {
            value: Some(val),
            is_percentage: false,
            relative: None,
            delta: None,
        });
    }

    // 5. Pure relative adjustment (`调大一点`, `声音小点`, `暗一点`, `暖一点`, `冷一点`)
    if let Some(dir) = analysis.detected_direction {
        return Some(NumericSlot {
            value: None,
            is_percentage: false,
            relative: Some(dir),
            delta: None,
        });
    }

    None
}

/// Extract time range expressions (`今天`, `昨天`, `前天`, `本周`, `上周`, `最近3天`, `过去12小时`).
pub fn parse_time_range_slot(text: &str) -> Option<TimeRangeSlot> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    // `最近 N 小时` / `过去 N 小时` / `N 小时内`
    let hours_re =
        Regex::new(r"(?:最近|近|过去)?\s*([0-9一二两三四五六七八九十]+)\s*个?小时(?:内|以内|里)?")
            .expect("valid regex");
    if let Some(caps) = hours_re.captures(trimmed)
        && (trimmed.contains("最近")
            || trimmed.contains("过去")
            || trimmed.contains("小时内")
            || trimmed.contains("小时以内"))
        && let Some(h) = parse_chinese_or_arabic_number(&caps[1])
    {
        let hours = (h as u64).max(1);
        return Some(TimeRangeSlot {
            label: format!("最近{}小时", hours),
            modified_within_days: None,
            modified_within_hours: Some(hours),
        });
    }

    // `最近 N 天` / `近 N 天` / `过去 N 天` / `N 天内`
    let days_re =
        Regex::new(r"(?:最近|近|过去)\s*([0-9一二两三四五六七八九十]+)\s*天").expect("valid regex");
    if let Some(caps) = days_re.captures(trimmed)
        && let Some(d) = parse_chinese_or_arabic_number(&caps[1])
    {
        let days = (d as u64).max(1);
        return Some(TimeRangeSlot {
            label: format!("最近{}天", days),
            modified_within_days: Some(days),
            modified_within_hours: None,
        });
    }

    // `最近 N 周` / `过去 N 周`
    let weeks_re =
        Regex::new(r"(?:最近|近|过去)\s*([0-9一二两三四五六七八九十]+)\s*(?:周|星期|礼拜)")
            .expect("valid regex");
    if let Some(caps) = weeks_re.captures(trimmed)
        && let Some(w) = parse_chinese_or_arabic_number(&caps[1])
    {
        let days = ((w as u64) * 7).max(7);
        return Some(TimeRangeSlot {
            label: format!("最近{}周", w as u64),
            modified_within_days: Some(days),
            modified_within_hours: None,
        });
    }

    if trimmed.contains("今天") || trimmed.contains("今日") || trimmed.contains("刚才") {
        return Some(TimeRangeSlot {
            label: "今天".to_string(),
            modified_within_days: Some(1),
            modified_within_hours: Some(24),
        });
    }
    if trimmed.contains("昨天") || trimmed.contains("昨日") {
        return Some(TimeRangeSlot {
            label: "昨天".to_string(),
            modified_within_days: Some(2),
            modified_within_hours: None,
        });
    }
    if trimmed.contains("前天") {
        return Some(TimeRangeSlot {
            label: "前天".to_string(),
            modified_within_days: Some(3),
            modified_within_hours: None,
        });
    }
    if trimmed.contains("本周")
        || trimmed.contains("这周")
        || trimmed.contains("这个星期")
        || trimmed.contains("最近一周")
    {
        return Some(TimeRangeSlot {
            label: "本周".to_string(),
            modified_within_days: Some(7),
            modified_within_hours: None,
        });
    }
    if trimmed.contains("上周")
        || trimmed.contains("上星期")
        || trimmed.contains("上个星期")
        || trimmed.contains("上礼拜")
    {
        return Some(TimeRangeSlot {
            label: "上周".to_string(),
            modified_within_days: Some(14),
            modified_within_hours: None,
        });
    }
    if trimmed.contains("本月") || trimmed.contains("这个月") || trimmed.contains("最近一个月")
    {
        return Some(TimeRangeSlot {
            label: "本月".to_string(),
            modified_within_days: Some(31),
            modified_within_hours: None,
        });
    }
    if trimmed.contains("上个月") || trimmed.contains("上月") {
        return Some(TimeRangeSlot {
            label: "上个月".to_string(),
            modified_within_days: Some(62),
            modified_within_hours: None,
        });
    }
    if trimmed.contains("最近") || trimmed.contains("近期") {
        return Some(TimeRangeSlot {
            label: "最近7天".to_string(),
            modified_within_days: Some(7),
            modified_within_hours: None,
        });
    }

    None
}

/// Extract file size constraints (`大于 1G`, `超过 500M`, `小于 100K`).
pub fn parse_size_range_slot(text: &str) -> Option<SizeRangeSlot> {
    let mut min_size_bytes = None;
    let mut max_size_bytes = None;

    let min_re = Regex::new(
        r"(?i)(?:大于|超过|高于|不小于|至少|>|>=)\s*(\d+(?:\.\d+)?)\s*(kb|k|mb|m|gb|g|tb|t|b)\b",
    )
    .expect("valid regex");
    if let Some(caps) = min_re.captures(text)
        && let Ok(val) = caps[1].parse::<f64>()
    {
        min_size_bytes = Some(unit_to_bytes(val, &caps[2]));
    }

    let max_re = Regex::new(
        r"(?i)(?:小于|低于|不超过|少于|至多|<|<=)\s*(\d+(?:\.\d+)?)\s*(kb|k|mb|m|gb|g|tb|t|b)\b",
    )
    .expect("valid regex");
    if let Some(caps) = max_re.captures(text)
        && let Ok(val) = caps[1].parse::<f64>()
    {
        max_size_bytes = Some(unit_to_bytes(val, &caps[2]));
    }

    if min_size_bytes.is_some() || max_size_bytes.is_some() {
        Some(SizeRangeSlot {
            min_size_bytes,
            max_size_bytes,
        })
    } else {
        None
    }
}

fn unit_to_bytes(val: f64, unit: &str) -> u64 {
    let mult: f64 = match unit.to_ascii_lowercase().as_str() {
        "t" | "tb" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
        "m" | "mb" => 1024.0 * 1024.0,
        "k" | "kb" => 1024.0,
        _ => 1.0,
    };
    (val * mult) as u64
}

/// Extract file extension or semantic file type (`PDF`, `Word`, `表格`, `图片`, `视频`, `压缩包`, `代码`, `*.rs`).
pub fn parse_file_type_slot(text: &str) -> Option<FileTypeSlot> {
    let lc = text.to_ascii_lowercase();

    // 1. Check explicit glob or dot-extension (`*.pdf`, `.rs`, `pdf文件`, etc.)
    let explicit_exts = [
        "pdf", "docx", "doc", "xlsx", "xls", "csv", "pptx", "ppt", "md", "markdown", "txt", "json",
        "yaml", "yml", "toml", "rs", "py", "ts", "tsx", "js", "jsx", "go", "c", "cpp", "h", "sh",
        "zip", "tar", "gz", "tgz", "7z", "rar", "png", "jpg", "jpeg", "webp", "svg", "gif", "mp4",
        "mkv", "mov", "mp3", "wav", "flac", "log", "sql", "html", "css",
    ];

    for ext in explicit_exts {
        let pat = format!(
            r"(?i)(?:^|[^a-z0-9_])\*?\.?{}(?:$|[^a-z0-9_])",
            regex::escape(ext)
        );
        if let Ok(re) = Regex::new(&pat)
            && re.is_match(&lc)
        {
            let canonical = if ext == "markdown" { "md" } else { ext };
            return Some(FileTypeSlot {
                category_label: Some(canonical.to_uppercase()),
                extensions: vec![canonical.to_string()],
                primary_ext: Some(canonical.to_string()),
            });
        }
    }

    // 2. Semantic Chinese/English file categories
    if lc.contains("word") {
        return Some(FileTypeSlot {
            category_label: Some("Word文档".to_string()),
            extensions: vec!["docx".to_string(), "doc".to_string()],
            primary_ext: Some("docx".to_string()),
        });
    }
    if lc.contains("excel") || text.contains("表格") || text.contains("电子表格") {
        return Some(FileTypeSlot {
            category_label: Some("表格".to_string()),
            extensions: vec!["xlsx".to_string(), "xls".to_string(), "csv".to_string()],
            primary_ext: Some("xlsx".to_string()),
        });
    }
    if lc.contains("ppt") || text.contains("幻灯片") || text.contains("演示文稿") {
        return Some(FileTypeSlot {
            category_label: Some("演示文稿".to_string()),
            extensions: vec!["pptx".to_string(), "ppt".to_string()],
            primary_ext: Some("pptx".to_string()),
        });
    }
    if text.contains("图片")
        || text.contains("照片")
        || text.contains("图像")
        || text.contains("截图")
    {
        return Some(FileTypeSlot {
            category_label: Some("图片".to_string()),
            extensions: vec![
                "png".to_string(),
                "jpg".to_string(),
                "jpeg".to_string(),
                "webp".to_string(),
                "svg".to_string(),
            ],
            primary_ext: Some("png".to_string()),
        });
    }
    if text.contains("视频") || text.contains("录像") || text.contains("电影") {
        return Some(FileTypeSlot {
            category_label: Some("视频".to_string()),
            extensions: vec!["mp4".to_string(), "mkv".to_string(), "mov".to_string()],
            primary_ext: Some("mp4".to_string()),
        });
    }
    if text.contains("音频") || text.contains("音乐") || text.contains("录音") {
        return Some(FileTypeSlot {
            category_label: Some("音频".to_string()),
            extensions: vec!["mp3".to_string(), "wav".to_string(), "flac".to_string()],
            primary_ext: Some("mp3".to_string()),
        });
    }
    if text.contains("压缩包") || text.contains("归档") {
        return Some(FileTypeSlot {
            category_label: Some("压缩包".to_string()),
            extensions: vec![
                "zip".to_string(),
                "tar".to_string(),
                "gz".to_string(),
                "7z".to_string(),
            ],
            primary_ext: Some("zip".to_string()),
        });
    }
    if text.contains("代码") || text.contains("源码") || text.contains("脚本") {
        return Some(FileTypeSlot {
            category_label: Some("代码".to_string()),
            extensions: vec![
                "rs".to_string(),
                "py".to_string(),
                "ts".to_string(),
                "js".to_string(),
                "sh".to_string(),
            ],
            primary_ext: Some("rs".to_string()),
        });
    }

    None
}

/// Extract directory/location mentions (`下载里`, `桌面上`, `文档里`, `~/...`, `/...`) using `ResourceEngine`.
pub fn parse_location_slots(text: &str, resources: &ResourceEngine) -> Vec<LocationSlot> {
    let mut out = Vec::new();

    // 1. Check explicit absolute or tilde paths
    let path_re = Regex::new(r"(~[^\s，,。；;]+|/[^\s，,。；;]+)").expect("valid path regex");
    for caps in path_re.captures_iter(text) {
        let raw = caps[1].trim().to_string();
        let resolved = resources
            .resolve_named_directory(&raw)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| raw.clone());
        out.push(LocationSlot {
            raw_hint: raw,
            resolved_path: resolved,
        });
    }

    // 2. Check named directory hints (`下载`, `桌面`, `文档`, `图片`, `视频`, `音乐`, `主目录`, `当前目录`)
    let named_hints = [
        "下载目录",
        "下载文件夹",
        "下载里",
        "下载",
        "桌面上",
        "桌面",
        "文档目录",
        "文档里",
        "文档",
        "图片目录",
        "图片里",
        "视频目录",
        "音乐目录",
        "主目录",
        "家目录",
        "当前目录",
        "downloads",
        "desktop",
        "documents",
    ];
    for hint in named_hints {
        if text.to_ascii_lowercase().contains(hint) {
            let clean_hint = hint
                .trim_end_matches("目录")
                .trim_end_matches("文件夹")
                .trim_end_matches("里")
                .trim_end_matches("上");
            if let Some(p) = resources.resolve_named_directory(clean_hint) {
                let path_str = p.to_string_lossy().to_string();
                if !out.iter().any(|loc| loc.resolved_path == path_str) {
                    out.push(LocationSlot {
                        raw_hint: hint.to_string(),
                        resolved_path: path_str,
                    });
                }
            }
        }
    }

    out
}

/// Extract all universal slots from a user query.
pub fn extract_universal_slots(text: &str, resources: &ResourceEngine) -> UniversalSlots {
    let analysis = analyze_colloquial_input(text);
    let booleans = match analysis.detected_toggle.as_deref() {
        Some("on") => Some(true),
        Some("off") => Some(false),
        _ => None,
    };

    UniversalSlots {
        numeric: parse_numeric_slot(text, None, None),
        time_range: parse_time_range_slot(text),
        size_range: parse_size_range_slot(text),
        file_type: parse_file_type_slot(text),
        locations: parse_location_slots(text, resources),
        booleans,
    }
}

/// Schema-driven slot extraction for a specific `CapabilityDescriptor`.
///
/// Inspects `descriptor.input_schema` (`properties`, `required`, `oneOf`) and populates
/// a valid JSON object of arguments from `raw_text` and any `pattern_slots` captured by `PatternCompiler`.
pub fn extract_slots_for_descriptor(
    descriptor: &CapabilityDescriptor,
    raw_text: &str,
    pattern_slots: &HashMap<String, String>,
    resources: &ResourceEngine,
) -> Value {
    let mut args = Map::new();
    let cap_id = descriptor.id.as_str();
    let props = descriptor
        .input_schema
        .get("properties")
        .and_then(|v| v.as_object());

    let Some(props) = props else {
        return Value::Object(args);
    };

    let analysis = analyze_colloquial_input(raw_text);
    let universal = extract_universal_slots(raw_text, resources);

    // 1. Capabilities with `value` / `relative` (Settings: volume, brightness, text_scale, mouse/touchpad speed, night_light temp)
    if props.contains_key("value") || props.contains_key("relative") {
        let min_bound = props
            .get("value")
            .and_then(|v| v.get("minimum"))
            .and_then(|v| v.as_f64())
            .or_else(|| descriptor.setting.as_ref().and_then(|m| m.min));
        let max_bound = props
            .get("value")
            .and_then(|v| v.get("maximum"))
            .and_then(|v| v.as_f64())
            .or_else(|| descriptor.setting.as_ref().and_then(|m| m.max));

        let num_slot = pattern_slots
            .get("value")
            .and_then(|s| parse_numeric_slot(s, min_bound, max_bound))
            .or_else(|| parse_numeric_slot(raw_text, min_bound, max_bound));

        let allowed_rel: Vec<&str> = props
            .get("relative")
            .and_then(|v| v.get("enum"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();

        if let Some(ns) = num_slot {
            if let Some(mut v) = ns.value {
                // Special normalization for `appearance.text_scale.set` when user says `125%` -> `1.25`
                if cap_id == "appearance.text_scale.set" && v > 10.0 {
                    v /= 100.0;
                }
                if let Some(lo) = min_bound {
                    v = v.max(lo);
                }
                if let Some(hi) = max_bound {
                    v = v.min(hi);
                }
                // Check if schema expects integer or number
                let is_int = props
                    .get("value")
                    .and_then(|p| p.get("type"))
                    .and_then(|t| t.as_str())
                    == Some("integer");
                if is_int {
                    args.insert("value".to_string(), json!(v.round() as i64));
                } else {
                    args.insert("value".to_string(), json!(v));
                }
            } else if let Some(rel) = ns.relative {
                let mapped_rel = if allowed_rel.contains(&rel.as_str()) {
                    rel
                } else if rel == "up" && allowed_rel.contains(&"warmer") {
                    "warmer".to_string()
                } else if rel == "down" && allowed_rel.contains(&"cooler") {
                    "cooler".to_string()
                } else if !allowed_rel.is_empty() {
                    allowed_rel[0].to_string()
                } else {
                    rel
                };
                args.insert("relative".to_string(), json!(mapped_rel));
                if let Some(delta) = ns.delta
                    && props.contains_key("delta")
                {
                    args.insert("delta".to_string(), json!(delta));
                }
            }
        } else if props.contains_key("relative") {
            let fallback_rel = if allowed_rel.contains(&"warmer") {
                "warmer"
            } else {
                "up"
            };
            args.insert("relative".to_string(), json!(fallback_rel));
        }
    }

    // 2. Capabilities with `state` or `mode` (`on` / `off` / `toggle`) or `enabled` (`bool`)
    for mode_key in ["state", "mode"] {
        if let Some(state_prop) = props.get(mode_key) {
            let allowed: Vec<&str> = state_prop
                .get("enum")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();

            let state = if let Some(s) = analysis.detected_toggle.as_deref() {
                if allowed.contains(&s) { s } else { "on" }
            } else if raw_text.contains("取消")
                || raw_text.contains("恢复")
                || raw_text.contains("出声")
            {
                "off"
            } else {
                "on"
            };
            args.insert(mode_key.to_string(), json!(state));
        }
    }

    if let Some(enabled_prop) = props.get("enabled")
        && enabled_prop.get("type").and_then(|t| t.as_str()) == Some("boolean")
    {
        let is_enabled = !matches!(analysis.detected_toggle.as_deref(), Some("off"))
            && !raw_text.contains("取消")
            && !raw_text.contains("关闭")
            && !raw_text.contains("关掉");
        args.insert("enabled".to_string(), json!(is_enabled));
    }

    // 3. Capabilities with `scheme` (`appearance.color_scheme.set`)
    if props.contains_key("scheme") {
        let scheme = if raw_text.contains("浅色")
            || raw_text.contains("亮色")
            || raw_text.contains("日间")
            || raw_text.contains("白色")
            || raw_text.to_ascii_lowercase().contains("light")
        {
            "light"
        } else if raw_text.contains("切换") || raw_text.to_ascii_lowercase().contains("toggle") {
            "toggle"
        } else {
            "dark"
        };
        args.insert("scheme".to_string(), json!(scheme));
    }

    // 4. Capabilities with `profile` (`power.profile.set`)
    if props.contains_key("profile") {
        let profile = if raw_text.contains("省电")
            || raw_text.contains("续航")
            || raw_text.to_ascii_lowercase().contains("saver")
        {
            "power-saver"
        } else if raw_text.contains("性能")
            || raw_text.contains("满血")
            || raw_text.to_ascii_lowercase().contains("performance")
        {
            "performance"
        } else {
            "balanced"
        };
        args.insert("profile".to_string(), json!(profile));
    }

    // 5. Capabilities with `scene` (`scene.apply`)
    if props.contains_key("scene") {
        let scene = if let Some(s) = pattern_slots.get("scene") {
            s.trim_end_matches("模式").to_string()
        } else if raw_text.contains("护眼") || raw_text.to_ascii_lowercase().contains("hyms") {
            "护眼".to_string()
        } else if raw_text.contains("演示") || raw_text.contains("汇报") {
            "演示".to_string()
        } else if raw_text.contains("安静") || raw_text.contains("静音") {
            "安静".to_string()
        } else if raw_text.contains("会议") {
            "会议".to_string()
        } else if raw_text.contains("专注") {
            "专注".to_string()
        } else {
            "护眼".to_string()
        };
        args.insert("scene".to_string(), json!(scene));
    }

    // 6. Capabilities with `panel` (`settings.open_panel`)
    if props.contains_key("panel") {
        let panel =
            if raw_text.contains("蓝牙") || raw_text.to_ascii_lowercase().contains("bluetooth") {
                "bluetooth"
            } else if raw_text.contains("网络")
                || raw_text.contains("无线")
                || raw_text.to_ascii_lowercase().contains("wifi")
            {
                "network"
            } else if raw_text.contains("声音")
                || raw_text.contains("音频")
                || raw_text.contains("音量")
            {
                "sound"
            } else if raw_text.contains("电源") || raw_text.contains("电池") {
                "power"
            } else if raw_text.contains("外观") || raw_text.contains("主题") {
                "appearance"
            } else {
                "display"
            };
        args.insert("panel".to_string(), json!(panel));
    }

    // 7. Capabilities with `device` (`sound.output.set`)
    if props.contains_key("device") {
        let dev = if let Some(d) = pattern_slots.get("device") {
            d.clone()
        } else if raw_text.contains("耳机") || raw_text.to_ascii_lowercase().contains("headphone")
        {
            "headphones".to_string()
        } else if raw_text.contains("蓝牙") {
            "bluetooth".to_string()
        } else if raw_text.to_ascii_lowercase().contains("hdmi") {
            "hdmi".to_string()
        } else {
            "speakers".to_string()
        };
        args.insert("device".to_string(), json!(dev));
    }

    // 8. Capabilities with `seconds` (`display.idle_delay.set`)
    if props.contains_key("seconds") {
        let secs = if raw_text.contains("不熄屏")
            || raw_text.contains("从不")
            || raw_text.contains("禁止")
            || raw_text.contains("保持亮屏")
        {
            0u64
        } else if let Some(ns) = &universal.numeric
            && let Some(v) = ns.value
        {
            if raw_text.contains("分钟") || raw_text.contains("min") {
                (v as u64) * 60
            } else if raw_text.contains("小时") {
                (v as u64) * 3600
            } else {
                v as u64
            }
        } else {
            300u64
        };
        args.insert("seconds".to_string(), json!(secs));
    }

    // 9. File search (`fs.search`) slots: `query`, `path`, `ext`, `modified_within_days`, `modified_within_hours`, `min_size_bytes`, `max_size_bytes`
    if cap_id == "fs.search" {
        if let Some(tr) = &universal.time_range {
            if let Some(h) = tr.modified_within_hours {
                args.insert("modified_within_hours".to_string(), json!(h));
            }
            if let Some(d) = tr.modified_within_days {
                args.insert("modified_within_days".to_string(), json!(d));
            }
        }
        if let Some(sr) = &universal.size_range {
            if let Some(min_b) = sr.min_size_bytes {
                args.insert("min_size_bytes".to_string(), json!(min_b));
            }
            if let Some(max_b) = sr.max_size_bytes {
                args.insert("max_size_bytes".to_string(), json!(max_b));
            }
        }
        if let Some(ft) = &universal.file_type
            && let Some(ext) = &ft.primary_ext
        {
            args.insert("ext".to_string(), json!(ext));
        }
        if let Some(loc) = universal.locations.first() {
            args.insert("path".to_string(), json!(loc.resolved_path));
        }
        let cleaned_query = clean_file_search_query(raw_text, pattern_slots);
        if !cleaned_query.is_empty() {
            args.insert("query".to_string(), json!(cleaned_query));
        }
    }

    // 10. Generic slot propagation from `pattern_slots` for remaining properties
    for (k, v) in pattern_slots {
        if props.contains_key(k) && !args.contains_key(k) {
            args.insert(k.clone(), json!(v));
        }
    }

    // 11. Capabilities requiring `app` (`app.launch`, `app.quit`, `app.focus`)
    if props.contains_key("app") && !args.contains_key("app") {
        let app_name = extract_entity_after_verbs(
            raw_text,
            &[
                "打开应用",
                "启动",
                "打开",
                "运行",
                "关闭",
                "退出",
                "切换到",
                "聚焦",
            ],
        );
        if !app_name.is_empty() {
            args.insert("app".to_string(), json!(app_name));
        }
    }

    // 12. Capabilities requiring `port` (`port.inspect`)
    if props.contains_key("port")
        && !args.contains_key("port")
        && let Some(ns) = &universal.numeric
        && let Some(v) = ns.value
    {
        let p = (v as u64).clamp(1, 65535);
        args.insert("port".to_string(), json!(p));
    }

    Value::Object(args)
}

fn clean_file_search_query(raw_text: &str, pattern_slots: &HashMap<String, String>) -> String {
    let mut s = pattern_slots
        .get("query")
        .cloned()
        .unwrap_or_else(|| raw_text.to_string());

    for noise in [
        "帮我找一下",
        "帮我找",
        "搜索文件",
        "查找文件",
        "找文件",
        "搜文件",
        "找一下",
        "搜一下",
        "查找",
        "搜索",
        "找",
        "搜",
        "下载目录里",
        "下载目录",
        "下载里",
        "桌面上",
        "桌面里",
        "文档里",
        "文档目录",
        "今天",
        "昨天",
        "前天",
        "本周",
        "这周",
        "上周",
        "本月",
        "这个月",
        "上个月",
        "最近一周",
        "最近一个月",
        "修改过的",
        "修改的",
        "创建的",
        "下载的",
        "关于",
        "有关",
        "文件",
        "的",
    ] {
        s = s.replace(noise, " ");
    }

    // Strip size/time regex phrases
    if let Ok(re) = Regex::new(
        r"(?i)(?:最近|近|过去)\s*[0-9一二两三四五六七八九十]+\s*(?:天|个?小时|周|星期)|(?:大于|超过|小于|低于)\s*\d+(?:\.\d+)?\s*(?:kb|k|mb|m|gb|g|b)",
    ) {
        s = re.replace_all(&s, " ").to_string();
    }

    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_entity_after_verbs(text: &str, verbs: &[&str]) -> String {
    let trimmed = text.trim();
    for v in verbs {
        if let Some(idx) = trimmed.find(v) {
            let rest = trimmed[idx + v.len()..].trim();
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    trimmed.to_string()
}
