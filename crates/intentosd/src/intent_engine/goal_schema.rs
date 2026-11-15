#![forbid(unsafe_code)]

//! Structured Cognitive Goal Contract (`goal_schema.rs`, `v0.2-M1` / `M1.1-H08`).
//!
//! Transforms L1 from flat keyword/bigram matching into progressive structured goal understanding:
//! - Stage 0 (`SpeechActModality`): separates procedural/explanatory questions and fault diagnostics
//!   from imperative commands before any L0 mutation can misfire.
//! - Stage 1 (`prerequisite_observe_capability`, `requires_context_resolution`): attaches read-before-adjust
//!   observe capabilities to sensory complaints and dynamic context-continuity flags to continuation goals.
//! - Stage 2 (`needs_disambiguation_or_fast_llm`, `ConfidenceProvenance`): gates compact Fast-LLM
//!   disambiguation strictly on genuinely ambiguous L1 inputs and tracks honest score provenance.

use intentos_protocol::RouteLayer;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// High-level cognitive taxonomy of a user utterance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveIntentKind {
    /// Single-step deterministic OS/app/file/web/setting action (`打开计算器`, `音量调到20`, `查一下内网地址`).
    #[serde(alias = "DeterministicCommand", alias = "deterministic")]
    DeterministicCommand,
    /// Implicit state complaint or relative directional tweak (`声音有点吵` -> volume down, `屏幕有点刺眼` -> brightness down).
    #[serde(alias = "RelativeAdjustment", alias = "relative")]
    RelativeAdjustment,
    /// Goal-oriented workspace orchestration or session continuation (`今天想专心写论文`, `继续昨天的工作`, `下载目录太乱了`).
    #[serde(alias = "GoalWorkspace", alias = "goal")]
    GoalWorkspace,
    /// Multi-probe root-cause investigation or fault repair (`电脑最近有点卡`, `修复软件启动异常`, `我的软件怎么又启动不了了`).
    #[serde(alias = "SystemDiagnosis", alias = "diagnosis")]
    SystemDiagnosis,
    /// How-to / procedural / causal explanation or open knowledge query (`怎么批量查找最近7天修改过的日志`, `为什么...`, `是什么...`).
    #[serde(
        alias = "ProceduralOrKnowledge",
        alias = "procedural",
        alias = "knowledge"
    )]
    ProceduralOrKnowledge,
    /// Multi-goal or cross-domain sequential request (`帮我看下今天的天气，告诉我早上起床穿什么衣服，然后告诉我今天最应该完成哪些任务`).
    #[serde(alias = "CompoundTask", alias = "compound")]
    CompoundTask,
}

impl CognitiveIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicCommand => "deterministic_command",
            Self::RelativeAdjustment => "relative_adjustment",
            Self::GoalWorkspace => "goal_workspace",
            Self::SystemDiagnosis => "system_diagnosis",
            Self::ProceduralOrKnowledge => "procedural_or_knowledge",
            Self::CompoundTask => "compound_task",
        }
    }

    pub fn label_zh(self) -> &'static str {
        match self {
            Self::DeterministicCommand => "确定性单步指令",
            Self::RelativeAdjustment => "相对状态微调",
            Self::GoalWorkspace => "场景目标与工作区编排",
            Self::SystemDiagnosis => "系统故障与性能诊断",
            Self::ProceduralOrKnowledge => "方法指引与知识问答",
            Self::CompoundTask => "多目标复合任务",
        }
    }

    /// Returns `true` when the intent represents a higher-order goal, diagnosis, how-to query,
    /// or compound task that must escalate to L2 rather than forcing single-step L0/L1 execution.
    pub fn requires_agent_planning(self) -> bool {
        matches!(
            self,
            Self::GoalWorkspace
                | Self::SystemDiagnosis
                | Self::ProceduralOrKnowledge
                | Self::CompoundTask
        )
    }
}

/// Stage 0 Speech-Act & Modality classification (`H08`).
///
/// Evaluated prior to L0 command matching so procedural/knowledge questions (`怎么...`, `如何...`,
/// `为什么...`, `是什么...`) and fault investigations never misfire direct system mutations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeechActModality {
    /// Direct execution command or workspace/compound goal request (`执行请求/目标达成`).
    #[default]
    #[serde(alias = "ActionOrGoalRequest", alias = "action", alias = "command")]
    ActionOrGoalRequest,
    /// Implicit sensory complaint or directional relative tweak (`状态抱怨与相对调节`).
    #[serde(alias = "StateComplaintOrRelative", alias = "relative_complaint")]
    StateComplaintOrRelative,
    /// Active fault report or diagnostic/repair request (`故障诊断与修复请求`).
    #[serde(alias = "DiagnosticOrRepair", alias = "diagnostic")]
    DiagnosticOrRepair,
    /// Method inquiry, causal principle question, or concept explanation (`询问方法/解释原理`).
    #[serde(
        alias = "ProceduralOrExplanatory",
        alias = "procedural",
        alias = "knowledge_question"
    )]
    ProceduralOrExplanatory,
}

impl SpeechActModality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActionOrGoalRequest => "action_or_goal_request",
            Self::StateComplaintOrRelative => "state_complaint_or_relative",
            Self::DiagnosticOrRepair => "diagnostic_or_repair",
            Self::ProceduralOrExplanatory => "procedural_or_explanatory",
        }
    }

    pub fn label_zh(self) -> &'static str {
        match self {
            Self::ActionOrGoalRequest => "执行请求/目标达成",
            Self::StateComplaintOrRelative => "状态感知与相对调节",
            Self::DiagnosticOrRepair => "故障取证与诊断修复",
            Self::ProceduralOrExplanatory => "询问方法/解释原理",
        }
    }
}

/// Honest provenance of [`StructuredIntent::confidence`] (`H08`).
///
/// Prevents treating raw lexical/rule heuristic constants (e.g. `0.91`/`0.85`) or uncalibrated
/// Fast-LLM self-reported numbers as empirically calibrated probabilities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfidenceProvenance {
    /// Local lexical, pattern, or rule heuristic score (uncalibrated).
    #[default]
    HeuristicLexical,
    /// Uncalibrated score emitted by Fast LLM structured JSON output.
    FastLlmUnverified,
    /// Empirically calibrated confidence backed by `sample_count` historical execution/undo/rejection records.
    EmpiricalCalibrated { sample_count: u32 },
}

impl ConfidenceProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeuristicLexical => "heuristic_lexical",
            Self::FastLlmUnverified => "fast_llm_unverified",
            Self::EmpiricalCalibrated { .. } => "empirical_calibrated",
        }
    }

    pub fn is_calibrated(self) -> bool {
        matches!(self, Self::EmpiricalCalibrated { sample_count } if sample_count > 0)
    }

    pub fn sample_count(self) -> u32 {
        match self {
            Self::EmpiricalCalibrated { sample_count } => sample_count,
            Self::HeuristicLexical | Self::FastLlmUnverified => 0,
        }
    }
}

impl<'de> Deserialize<'de> for ConfidenceProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = Value::deserialize(deserializer)?;
        match val {
            Value::Null => Ok(Self::HeuristicLexical),
            Value::String(s) => match s.trim() {
                "fast_llm_unverified" | "FastLlmUnverified" | "fast_llm" => {
                    Ok(Self::FastLlmUnverified)
                }
                "empirical_calibrated" | "EmpiricalCalibrated" | "empirical" => {
                    Ok(Self::EmpiricalCalibrated { sample_count: 1 })
                }
                _ => Ok(Self::HeuristicLexical),
            },
            Value::Object(map) => {
                if let Some(kind) = map.get("kind").and_then(Value::as_str) {
                    return match kind.trim() {
                        "fast_llm_unverified" | "FastLlmUnverified" | "fast_llm" => {
                            Ok(Self::FastLlmUnverified)
                        }
                        "empirical_calibrated" | "EmpiricalCalibrated" | "empirical" => {
                            let n = map
                                .get("sample_count")
                                .and_then(Value::as_u64)
                                .unwrap_or(0)
                                .min(u32::MAX as u64) as u32;
                            Ok(Self::EmpiricalCalibrated { sample_count: n })
                        }
                        _ => Ok(Self::HeuristicLexical),
                    };
                }
                if let Some(inner) = map
                    .get("empirical_calibrated")
                    .or_else(|| map.get("EmpiricalCalibrated"))
                {
                    let n = inner
                        .get("sample_count")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .min(u32::MAX as u64) as u32;
                    return Ok(Self::EmpiricalCalibrated { sample_count: n });
                }
                if map.contains_key("fast_llm_unverified") || map.contains_key("FastLlmUnverified")
                {
                    return Ok(Self::FastLlmUnverified);
                }
                Ok(Self::HeuristicLexical)
            }
            _ => Ok(Self::HeuristicLexical),
        }
    }
}

/// Contextual workspace & safety hints extracted for goal-level intents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalContextHints {
    #[serde(default)]
    pub project_hint: Option<String>,
    #[serde(default)]
    pub preferred_apps: Vec<String>,
    #[serde(default)]
    pub restore_previous_workspace: bool,
    #[serde(default)]
    pub avoid_distraction: bool,
    #[serde(default)]
    pub preserve_running_critical_apps: bool,
}

/// Structured cognitive representation of user intent bridging L0/L1 routing and L2 planning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuredIntent {
    pub intent_type: CognitiveIntentKind,
    pub goal: String,
    #[serde(default)]
    pub sub_goals: Vec<String>,
    #[serde(default)]
    pub context: GoalContextHints,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    pub recommended_route: RouteLayer,
    pub requires_planning: bool,
    #[serde(default)]
    pub direct_capability: Option<(String, Value)>,
    pub confidence: f64,
    /// Stage 0 speech-act & modality tag (`H08`).
    #[serde(default)]
    pub speech_act: SpeechActModality,
    /// Read-only observe capability to inspect live state prior to proportional relative adjustment
    /// (e.g. `Some("sound.volume.get")` for `"声音有点吵"`, `Some("display.brightness.get")` for `"屏幕有点刺眼"`).
    #[serde(default)]
    pub prerequisite_observe_capability: Option<String>,
    /// True when goal continuation (`"继续昨天的工作"`, `"接着刚才的弄"`) requires dynamic resolution
    /// against session/project/memory state rather than hardcoded names.
    #[serde(default)]
    pub requires_context_resolution: bool,
    /// True only when Stage 0/1 sees an ambiguous or mid-confidence L1 utterance that warrants
    /// a compact Fast-LLM disambiguation pass (`H08` Stage 2).
    #[serde(default)]
    pub needs_disambiguation_or_fast_llm: bool,
    /// Provenance of `confidence` (`HeuristicLexical`, `FastLlmUnverified`, or `EmpiricalCalibrated`).
    #[serde(default)]
    pub confidence_provenance: ConfidenceProvenance,
}

impl StructuredIntent {
    /// Whether this structured intent should bypass single-setting matching and escalate to L2.
    pub fn should_escalate_to_l2(&self) -> bool {
        self.requires_planning
            || self.requires_context_resolution
            || self.recommended_route == RouteLayer::L2
            || self.intent_type.requires_agent_planning()
    }

    /// Concise structured escalation reason for `RoutedIntent::EscalateL2` and `L1DecisionOutcome::EscalateL2`.
    pub fn escalation_summary(&self) -> String {
        let mut parts = vec![format!(
            "[{}] 目标：{}",
            self.intent_type.label_zh(),
            self.goal
        )];
        if !self.sub_goals.is_empty() {
            parts.push(format!(
                "子目标({})：{}",
                self.sub_goals.len(),
                self.sub_goals.join("；")
            ));
        }
        if self.requires_context_resolution {
            parts.push("需解析近期工作上下文".to_string());
        }
        if let Some(ref obs) = self.prerequisite_observe_capability {
            parts.push(format!("前置读取：[{}]", obs));
        }
        if !self.constraints.is_empty() {
            parts.push(format!("约束：{}", self.constraints.join("、")));
        }
        if !self.required_capabilities.is_empty() {
            parts.push(format!(
                "建议能力：[{}]",
                self.required_capabilities.join(", ")
            ));
        }
        parts.join(" | ")
    }

    /// Compact system-prompt hint suitable for injecting into L2 Agent / Turn Engine context.
    pub fn to_agent_prompt_hint(&self) -> String {
        let mut lines = vec![
            format!("### 认知目标解析 ({})", self.intent_type.label_zh()),
            format!("- 核心目标: {}", self.goal),
        ];
        if !self.sub_goals.is_empty() {
            lines.push(format!("- 拆解子目标: {}", self.sub_goals.join(" -> ")));
        }
        if let Some(ref obs) = self.prerequisite_observe_capability {
            lines.push(format!(
                "- 前置状态读取能力: {}（先读取当前真实状态，再按比例微调）",
                obs
            ));
        }
        if self.requires_context_resolution {
            lines.push(
                "- 上下文延续解析: 需从近期会话、活跃项目与最近文件动态定位上下文，禁止臆造项目名"
                    .to_string(),
            );
        }
        if !self.constraints.is_empty() {
            lines.push(format!("- 执行约束: {}", self.constraints.join("；")));
        }
        if !self.required_capabilities.is_empty() {
            lines.push(format!(
                "- 推荐优先调用能力: {}",
                self.required_capabilities.join(", ")
            ));
        }
        if let Some(ref proj) = self.context.project_hint {
            lines.push(format!("- 关联项目/场景线索: {}", proj));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cognitive_intent_kind_serde_accepts_snake_and_pascal_case() {
        let k1: CognitiveIntentKind = serde_json::from_str("\"goal_workspace\"").unwrap();
        let k2: CognitiveIntentKind = serde_json::from_str("\"GoalWorkspace\"").unwrap();
        assert_eq!(k1, CognitiveIntentKind::GoalWorkspace);
        assert_eq!(k1, k2);
        assert!(k1.requires_agent_planning());

        let k_rel: CognitiveIntentKind = serde_json::from_str("\"RelativeAdjustment\"").unwrap();
        assert_eq!(k_rel, CognitiveIntentKind::RelativeAdjustment);
        assert!(!k_rel.requires_agent_planning());
    }

    #[test]
    fn confidence_provenance_serde_roundtrip_and_flexible_decoding() {
        let p_heur = ConfidenceProvenance::HeuristicLexical;
        let p_llm = ConfidenceProvenance::FastLlmUnverified;
        let p_emp = ConfidenceProvenance::EmpiricalCalibrated { sample_count: 7 };

        assert!(!p_heur.is_calibrated());
        assert!(!p_llm.is_calibrated());
        assert!(p_emp.is_calibrated());
        assert_eq!(p_emp.sample_count(), 7);

        for p in [p_heur, p_llm, p_emp] {
            let v = serde_json::to_value(p).unwrap();
            let back: ConfidenceProvenance = serde_json::from_value(v).unwrap();
            assert_eq!(back, p);
        }

        let from_str_llm: ConfidenceProvenance =
            serde_json::from_str("\"FastLlmUnverified\"").unwrap();
        assert_eq!(from_str_llm, ConfidenceProvenance::FastLlmUnverified);
        let from_null: ConfidenceProvenance = serde_json::from_str("null").unwrap();
        assert_eq!(from_null, ConfidenceProvenance::HeuristicLexical);
    }

    #[test]
    fn structured_intent_roundtrip_and_summary_formatting() {
        let intent = StructuredIntent {
            intent_type: CognitiveIntentKind::GoalWorkspace,
            goal: "进入论文写作专注状态".into(),
            sub_goals: vec!["打开论文草稿".into(), "开启勿扰模式".into()],
            context: GoalContextHints {
                project_hint: Some("论文写作".into()),
                preferred_apps: vec!["wps-office-prometheus.desktop".into()],
                restore_previous_workspace: true,
                avoid_distraction: true,
                preserve_running_critical_apps: true,
            },
            constraints: vec!["避免打扰".into(), "不关闭正在运行的重要程序".into()],
            required_capabilities: vec![
                "file.open".into(),
                "notify.dnd.set".into(),
                "app.launch".into(),
                "window.focus".into(),
            ],
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.94,
            speech_act: SpeechActModality::ActionOrGoalRequest,
            prerequisite_observe_capability: None,
            requires_context_resolution: false,
            needs_disambiguation_or_fast_llm: false,
            confidence_provenance: ConfidenceProvenance::EmpiricalCalibrated { sample_count: 4 },
        };

        assert!(intent.should_escalate_to_l2());
        let summary = intent.escalation_summary();
        assert!(summary.contains("进入论文写作专注状态"));
        assert!(summary.contains("避免打扰"));
        assert!(summary.contains("notify.dnd.set"));

        let hint = intent.to_agent_prompt_hint();
        assert!(hint.contains("论文写作"));

        let val = serde_json::to_value(&intent).unwrap();
        assert_eq!(val["intent_type"], json!("goal_workspace"));
        assert_eq!(val["recommended_route"], json!("L2"));
        assert_eq!(
            val["confidence_provenance"],
            json!({ "kind": "empirical_calibrated", "sample_count": 4 })
        );
        let decoded: StructuredIntent = serde_json::from_value(val).unwrap();
        assert_eq!(decoded, intent);
    }
}
