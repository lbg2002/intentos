#![forbid(unsafe_code)]

//! Structured Cognitive Goal Contract (`goal_schema.rs`, `v0.2-M1`).
//!
//! Transforms L1 from flat keyword/bigram matching into structured goal understanding:
//! distinguishing single-step deterministic commands and implicit state-complaint adjustments
//! from multi-step workspace setup goals, system diagnostics, procedural/how-to questions,
//! and multi-domain compound tasks that must be planned by the L2 Agent Runtime.

use intentos_protocol::RouteLayer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// High-level cognitive taxonomy of a user utterance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveIntentKind {
    /// Single-step deterministic OS/app/file/web/setting action (`打开 Firefox`, `查一下内网地址`, `开启省电续航`).
    #[serde(alias = "DeterministicCommand", alias = "deterministic")]
    DeterministicCommand,
    /// Implicit state complaint or relative directional tweak (`声音有点吵` -> volume down, `屏幕有点刺眼` -> brightness down).
    #[serde(alias = "RelativeAdjustment", alias = "relative")]
    RelativeAdjustment,
    /// Goal-oriented workspace orchestration (`今天想专心写论文`, `我准备开组会了`, `下载目录太乱了`).
    #[serde(alias = "GoalWorkspace", alias = "goal")]
    GoalWorkspace,
    /// Multi-probe root-cause investigation (`电脑最近有点卡`, `系统好慢帮我查查`, `我的软件怎么又启动不了了`).
    #[serde(alias = "SystemDiagnosis", alias = "diagnosis")]
    SystemDiagnosis,
    /// How-to / procedural / command-guidance or open knowledge query (`怎么批量查找最近7天修改过的日志`).
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
}

impl StructuredIntent {
    /// Whether this structured intent should bypass single-setting matching and escalate to L2.
    pub fn should_escalate_to_l2(&self) -> bool {
        self.requires_planning
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
        let decoded: StructuredIntent = serde_json::from_value(val).unwrap();
        assert_eq!(decoded, intent);
    }
}
