#![forbid(unsafe_code)]

//! Cognitive Goal & State-Intent Parser (`cognitive_parser.rs`, `v0.2-M1`).
//!
//! Provides two complementary entry points:
//! 1. [`parse_structured_intent`]: Zero-latency (<1ms) deterministic semantic goal & state-intent
//!    analyzer recognizing workspace goals, system diagnostics, procedural how-to queries,
//!    multi-goal compound tasks, implicit state-complaint relative adjustments, and direct commands.
//! 2. [`parse_structured_intent_with_llm`]: Fast LLM structured JSON schema refinement via
//!    [`ModelGateway`] (`profile: "fast"` fallback `"main"`) when credentials exist and the
//!    utterance is non-trivial or ambiguous, strictly validated against registered capabilities
//!    with One-Way Escalation safety and deterministic local fallback.

use crate::decision::score_prompt_injection_risk;
use crate::gateway::ModelGateway;
use crate::intent_engine::fuzzy_scorer;
use crate::intent_engine::goal_schema::{CognitiveIntentKind, GoalContextHints, StructuredIntent};
use crate::intent_engine::pattern_compiler::PatternCompiler;
use intentos_protocol::{CapabilityDescriptor, DataClass, RouteLayer};
use serde_json::json;
use std::collections::HashSet;

/// Fast, zero-latency semantic goal & state-intent analyzer.
pub fn parse_structured_intent(
    raw_text: &str,
    capabilities: &[CapabilityDescriptor],
) -> StructuredIntent {
    let t = raw_text.trim();
    if t.is_empty() {
        return StructuredIntent {
            intent_type: CognitiveIntentKind::DeterministicCommand,
            goal: String::new(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: Vec::new(),
            recommended_route: RouteLayer::L0,
            requires_planning: false,
            direct_capability: None,
            confidence: 0.0,
        };
    }

    // 1. Guard exact built-in composite scenes (`护眼模式`, `会议模式`, `专注模式`, etc.) so they remain L0 deterministic
    if let Some(scene_intent) = try_parse_exact_builtin_scene(t) {
        return scene_intent;
    }

    // 2. Guard explicit preference memory & custom scene snapshot commands (`记住...`, `把当前设置存为...`)
    if t.starts_with("记住")
        || t.starts_with("以后默认")
        || (t.contains("设置")
            && (t.contains("保存为")
                || t.contains("保存成")
                || t.contains("存成")
                || t.contains("存为")))
    {
        return StructuredIntent {
            intent_type: CognitiveIntentKind::DeterministicCommand,
            goal: t.to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: Vec::new(),
            recommended_route: RouteLayer::L0,
            requires_planning: false,
            direct_capability: None,
            confidence: 0.95,
        };
    }

    // 3. System Diagnosis (`电脑最近有点卡`, `系统好慢帮我查查`, `我的软件怎么又启动不了了`)
    // Checked before generic `怎么...` procedural rules so `"我的软件怎么又启动不了了"` classifies as `SystemDiagnosis`!
    if let Some(diag) = try_parse_system_diagnosis(t) {
        return diag;
    }

    // 4. Compound Multi-Goal Task (`帮我看下今天的天气，告诉我早上起床穿什么衣服，然后告诉我今天最应该完成哪些任务`)
    if let Some(compound) = try_parse_compound_task(t) {
        return compound;
    }

    // 5. Goal Workspace (`今天想专心写论文`, `我准备开组会了`, `下载目录太乱了`)
    if let Some(goal_ws) = try_parse_goal_workspace(t) {
        return goal_ws;
    }

    // 6. Procedural / How-To / Command Guidance (`怎么批量查找最近7天修改过的日志`, `如何...`)
    if let Some(proc_q) = try_parse_procedural_or_knowledge(t) {
        return proc_q;
    }

    // 7. Implicit State-Complaint & Directional Relative Adjustments (`声音有点吵`, `屏幕有点刺眼`, `太亮了`)
    if let Some(rel) = try_parse_relative_adjustment(t) {
        return rel;
    }

    // 8. High-frequency Deterministic Commands (`查一下内网地址`, `开启省电续航`, + dynamic descriptor match)
    parse_deterministic_or_fallback(t, capabilities)
}

/// Fast LLM structured JSON parser via [`ModelGateway`] (`profile: "fast"` fallback `"main"`)
/// for non-trivial or low-confidence utterances, strictly validated against `capabilities`
/// with guaranteed local fallback.
pub async fn parse_structured_intent_with_llm(
    gateway: &ModelGateway,
    raw_text: &str,
    desktop_state_hint: Option<&str>,
    capabilities: &[CapabilityDescriptor],
) -> StructuredIntent {
    let local = parse_structured_intent(raw_text, capabilities);
    let trimmed = raw_text.trim();
    if trimmed.is_empty() {
        return local;
    }

    // Never allow suspected prompt-injection payloads to steer structured intent classification via LLM
    if score_prompt_injection_risk(trimmed) >= 0.65 {
        return local;
    }

    let is_non_trivial = matches!(
        local.intent_type,
        CognitiveIntentKind::GoalWorkspace
            | CognitiveIntentKind::SystemDiagnosis
            | CognitiveIntentKind::CompoundTask
    ) || local.confidence < 0.80;

    if !is_non_trivial || !gateway.has_usable_credentials() {
        return local;
    }

    let profile_name = if gateway.resolve_profile("fast").is_ok() {
        "fast"
    } else {
        "main"
    };
    let Ok((profile, _)) = gateway.resolve_profile(profile_name) else {
        return local;
    };

    let data_class = if desktop_state_hint.is_some() {
        DataClass::Personal
    } else {
        DataClass::Public
    };
    let lease = gateway.issue_run_lease("l1_cognitive_parser", profile_name, data_class);

    let cap_catalog: Vec<String> = capabilities
        .iter()
        .take(96)
        .map(|c| format!("{}: {}", c.id, c.summary))
        .collect();
    let system_prompt = concat!(
        "You are the IntentOS Cognitive Goal Parser (L1 Structured Intent Analyzer).\n",
        "Analyze the user's desktop utterance and return ONLY a single valid JSON object matching this exact schema:\n",
        "{\n",
        "  \"intent_type\": \"deterministic_command\" | \"relative_adjustment\" | \"goal_workspace\" | \"system_diagnosis\" | \"procedural_or_knowledge\" | \"compound_task\",\n",
        "  \"goal\": \"concise canonical goal in Chinese\",\n",
        "  \"sub_goals\": [\"ordered sub-goal 1\", \"...\"],\n",
        "  \"context\": {\n",
        "    \"project_hint\": null | \"string\",\n",
        "    \"preferred_apps\": [\"app.desktop\"],\n",
        "    \"restore_previous_workspace\": boolean,\n",
        "    \"avoid_distraction\": boolean,\n",
        "    \"preserve_running_critical_apps\": boolean\n",
        "  },\n",
        "  \"constraints\": [\"safety or UX constraint\"],\n",
        "  \"required_capabilities\": [\"registered.capability.id\"],\n",
        "  \"recommended_route\": \"L0\" | \"L1\" | \"L2\",\n",
        "  \"requires_planning\": boolean,\n",
        "  \"direct_capability\": null | [\"capability.id\", { ...args }],\n",
        "  \"confidence\": 0.0..1.0\n",
        "}\n",
        "Rules:\n",
        "1. Only reference capability IDs from the provided registered capabilities list.\n",
        "2. For goal_workspace, system_diagnosis, procedural_or_knowledge, or compound_task, set recommended_route=\"L2\", requires_planning=true, direct_capability=null.\n",
        "3. Output raw JSON only without markdown prose."
    );

    let user_payload = json!({
        "utterance": trimmed,
        "desktop_state_hint": desktop_state_hint,
        "local_prior": &local,
        "registered_capabilities": cap_catalog,
    });

    let body = json!({
        "model": profile.model,
        "temperature": 0.0,
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user_payload.to_string() }
        ]
    });

    let resp = gateway.proxy_chat_completion(&lease, body).await;
    gateway.revoke_lease(&lease);

    let Ok(resp_json) = resp else {
        return local;
    };
    let Some(raw_content) = resp_json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|v| v.as_str())
    else {
        return local;
    };

    let cleaned_json = strip_markdown_json_fence(raw_content);
    let Ok(llm_intent) = serde_json::from_str::<StructuredIntent>(cleaned_json) else {
        return local;
    };

    validate_and_sanitize_llm_intent(llm_intent, &local, capabilities)
}

fn strip_markdown_json_fence(raw: &str) -> &str {
    let t = raw.trim();
    if let Some(rest) = t.strip_prefix("```json") {
        rest.trim().strip_suffix("```").unwrap_or(rest).trim()
    } else if let Some(rest) = t.strip_prefix("```") {
        rest.trim().strip_suffix("```").unwrap_or(rest).trim()
    } else {
        t
    }
}

fn validate_and_sanitize_llm_intent(
    mut candidate: StructuredIntent,
    local_fallback: &StructuredIntent,
    capabilities: &[CapabilityDescriptor],
) -> StructuredIntent {
    if candidate.goal.trim().is_empty() {
        return local_fallback.clone();
    }
    candidate.goal = candidate.goal.trim().to_string();
    candidate.confidence = candidate.confidence.clamp(0.0, 1.0);

    let allowed_ids: Option<HashSet<&str>> = if capabilities.is_empty() {
        None
    } else {
        Some(capabilities.iter().map(|c| c.id.as_str()).collect())
    };

    if let Some(ref allow) = allowed_ids {
        candidate
            .required_capabilities
            .retain(|cap_id| allow.contains(cap_id.as_str()));
        if candidate.required_capabilities.is_empty()
            && !local_fallback.required_capabilities.is_empty()
        {
            candidate.required_capabilities = local_fallback
                .required_capabilities
                .iter()
                .filter(|c| allow.contains(c.as_str()))
                .cloned()
                .collect();
        }
    }

    // Enforce One-Way Escalation Invariant on higher-order cognitive intents:
    // If local analyzer already identified a planning-required goal, LLM may refine sub-goals/context
    // but must NEVER downgrade a complex goal into an unapproved single-step direct execution.
    if local_fallback.intent_type.requires_agent_planning()
        && !candidate.intent_type.requires_agent_planning()
    {
        candidate.intent_type = local_fallback.intent_type;
    }

    if candidate.intent_type.requires_agent_planning() {
        candidate.requires_planning = true;
        candidate.recommended_route = RouteLayer::L2;
        candidate.direct_capability = None;
    } else if let Some((ref cap_id, ref args)) = candidate.direct_capability {
        let valid_cap = allowed_ids
            .as_ref()
            .is_none_or(|allow| allow.contains(cap_id.as_str()));
        if !valid_cap || !args.is_object() {
            candidate.direct_capability = local_fallback.direct_capability.clone();
        }
    }

    candidate
}

fn try_parse_exact_builtin_scene(t: &str) -> Option<StructuredIntent> {
    for scene_name in ["护眼模式", "演示模式", "安静模式", "会议模式", "专注模式"]
    {
        if t == scene_name
            || t == format!("开启{}", scene_name)
            || t == format!("打开{}", scene_name)
            || t == format!("进入{}", scene_name)
            || t == format!("切到{}", scene_name)
        {
            return Some(StructuredIntent {
                intent_type: CognitiveIntentKind::DeterministicCommand,
                goal: format!("应用「{}」组合设置", scene_name),
                sub_goals: Vec::new(),
                context: GoalContextHints::default(),
                constraints: Vec::new(),
                required_capabilities: vec!["scene.apply".to_string()],
                recommended_route: RouteLayer::L0,
                requires_planning: false,
                direct_capability: Some((
                    "scene.apply".to_string(),
                    json!({ "scene": scene_name }),
                )),
                confidence: 0.98,
            });
        }
    }
    None
}

fn try_parse_system_diagnosis(t: &str) -> Option<StructuredIntent> {
    let lc = t.to_ascii_lowercase();

    // 1. Software / application failure to launch, crash, or hang
    let has_app_subject =
        t.contains("软件") || t.contains("应用") || t.contains("程序") || t.contains("客户端");
    let has_app_failure = t.contains("启动不了")
        || t.contains("打不开")
        || t.contains("开不了")
        || t.contains("闪退")
        || t.contains("崩溃")
        || t.contains("卡死")
        || t.contains("无响应")
        || t.contains("起不来");
    if has_app_subject && has_app_failure && !t.starts_with("用 ") {
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::SystemDiagnosis,
            goal: "诊断软件无法启动或运行异常根因".to_string(),
            sub_goals: vec![
                "检查系统当前资源负载与运行环境状态".to_string(),
                "排查目标进程残留、冲突或异常退出状态".to_string(),
                "检查磁盘剩余空间与临时目录可用性".to_string(),
                "汇总故障原因并提供安全恢复建议".to_string(),
            ],
            context: GoalContextHints {
                project_hint: Some("故障诊断".to_string()),
                preferred_apps: Vec::new(),
                restore_previous_workspace: false,
                avoid_distraction: false,
                preserve_running_critical_apps: true,
            },
            constraints: vec!["只读诊断优先，未经确认绝不终止正常运行的业务进程".to_string()],
            required_capabilities: vec![
                "system.inspect".to_string(),
                "process.list".to_string(),
                "disk.free".to_string(),
            ],
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.94,
        });
    }

    // 2. System lag, slowness, overheating, fan spin, resource exhaustion symptoms
    let has_sys_subject =
        t.contains("电脑") || t.contains("系统") || t.contains("机器") || t.contains("桌面");
    let has_lag_symptom = t.contains("有点卡")
        || t.contains("好卡")
        || t.contains("很卡")
        || t.contains("太卡")
        || t.contains("卡顿")
        || t.contains("好慢")
        || t.contains("很慢")
        || t.contains("变慢")
        || t.contains("有点慢")
        || t.contains("反应慢")
        || t.contains("死机")
        || t.contains("发烫")
        || t.contains("风扇狂转")
        || lc.contains("system slow");

    if (has_sys_subject && has_lag_symptom)
        || matches!(t, "有点卡" | "好卡" | "电脑卡了" | "系统卡了")
    {
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::SystemDiagnosis,
            goal: "诊断系统卡顿与性能瓶颈根因".to_string(),
            sub_goals: vec![
                "采样系统 CPU 负载、内存与交换分区使用率".to_string(),
                "列出 CPU/内存占用最高的前排进程".to_string(),
                "检查本机磁盘剩余容量与存储水位".to_string(),
                "定位卡顿根因并给出可审阅的释放或优化建议".to_string(),
            ],
            context: GoalContextHints {
                project_hint: Some("系统性能诊断".to_string()),
                preferred_apps: Vec::new(),
                restore_previous_workspace: false,
                avoid_distraction: false,
                preserve_running_critical_apps: true,
            },
            constraints: vec![
                "先执行只读采样诊断，结束任何进程前必须征得用户明确批准".to_string(),
                "不关闭正在运行的重要程序".to_string(),
            ],
            required_capabilities: vec![
                "system.inspect".to_string(),
                "process.list".to_string(),
                "disk.free".to_string(),
            ],
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.95,
        });
    }

    None
}

fn try_parse_compound_task(t: &str) -> Option<StructuredIntent> {
    // Explicit AIOS multi-domain daily briefing & planning archetype:
    // `"帮我看下今天的天气，告诉我早上起床穿什么衣服，然后告诉我今天最应该完成哪些任务"`
    if t.contains("天气")
        && (t.contains("穿什么") || t.contains("衣服") || t.contains("穿搭"))
        && (t.contains("任务") || t.contains("待办") || t.contains("日程") || t.contains("工作"))
    {
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::CompoundTask,
            goal: "查询今日天气与早起穿搭建议，并结合近期上下文梳理今日最应优先完成的任务"
                .to_string(),
            sub_goals: vec![
                "查询今天当地天气状况并给出早上起床穿衣搭配建议".to_string(),
                "检索活跃项目与近期任务记忆，按优先级列出今天最应该完成的任务".to_string(),
            ],
            context: GoalContextHints {
                project_hint: Some("每日晨间规划".to_string()),
                preferred_apps: Vec::new(),
                restore_previous_workspace: false,
                avoid_distraction: false,
                preserve_running_critical_apps: true,
            },
            constraints: vec!["只读汇总外部天气与本机待办上下文，不擅自修改用户文件".to_string()],
            required_capabilities: vec!["web.search".to_string(), "file.recent".to_string()],
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.96,
        });
    }

    // General multi-step complex task detection (excluding simple 2-step system setting toggles
    // like `"静音并开启勿扰模式"` or `"把音量调到20然后开启护眼模式"`, unless cognitive verbs exist)
    let cognitive_markers = [
        "生成一份",
        "总结成",
        "按年份分类",
        "按模块汇总",
        "分析报告",
        "分析昨天",
        "报错原因",
        "汇报提纲",
        "再提醒我",
        "告诉我",
        "整理成清单",
    ];
    let step_connectors = ["然后", "接着", "并且", "同时把", "完成后", "再把", "再发给"];
    let comma_count = t.chars().filter(|&c| c == '，' || c == ',').count();

    let has_cognitive_marker = cognitive_markers.iter().any(|m| t.contains(m));
    let has_connector = step_connectors.iter().any(|c| t.contains(c));

    if has_connector && (has_cognitive_marker || comma_count >= 2) {
        let clauses = split_rough_clauses(t);
        let sub_goals = if clauses.len() >= 2 {
            clauses
        } else {
            vec![t.to_string()]
        };

        let mut req_caps = Vec::new();
        if t.contains("天气") || t.contains("上网") || t.contains("搜索") {
            req_caps.push("web.search".to_string());
        }
        if t.contains("磁盘") || t.contains("空间") {
            req_caps.push("disk.free".to_string());
        }
        if t.contains("进程") || t.contains("内存") {
            req_caps.push("process.list".to_string());
        }
        if t.contains("TODO") || t.contains("注释") {
            req_caps.push("file.grep".to_string());
        }
        if t.contains("整理") || t.contains("归档") || t.contains("移动") {
            req_caps.push("file.search".to_string());
            req_caps.push("file.move".to_string());
        }
        if req_caps.is_empty() {
            req_caps.push("file.recent".to_string());
        }

        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::CompoundTask,
            goal: format!("分步规划并执行复合任务：{}", t),
            sub_goals,
            context: GoalContextHints {
                preserve_running_critical_apps: true,
                ..Default::default()
            },
            constraints: vec![
                "跨步操作须按依赖顺序执行，涉及写入或移动时保留可撤销记录".to_string(),
            ],
            required_capabilities: req_caps,
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.92,
        });
    }

    None
}

fn split_rough_clauses(text: &str) -> Vec<String> {
    let mut work = text.to_string();
    for sep in [
        "，然后",
        ",然后",
        "，接着",
        "，并且",
        "，同时",
        "然后",
        "接着",
        "并且",
        "，",
        ",",
    ] {
        work = work.replace(sep, "\n");
    }
    work.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn try_parse_goal_workspace(t: &str) -> Option<StructuredIntent> {
    // 1. Thesis / Deep-Focus Writing Workspace:
    // `"今天想专心写论文"` / `"开始写论文"` / `"进入论文写作状态"`
    // Careful: do NOT match deterministic file open/search/reveal (`打开航天器意图识别论文`, `找下载里的论文`, `定位...`)!
    let is_deterministic_file_op = t.starts_with("打开")
        || t.starts_with("找")
        || t.starts_with("查找")
        || t.starts_with("搜")
        || t.starts_with("定位")
        || t.starts_with("查看")
        || t.starts_with("把 ")
        || t.starts_with("用 ");

    let is_thesis_writing_goal = !is_deterministic_file_op
        && ((t.contains("写论文")
            || t.contains("论文写作")
            || (t.contains("论文")
                && (t.contains("专心") || t.contains("专注") || t.contains("状态"))))
            || matches!(
                t,
                "进入写作状态" | "开始写作" | "今天想专心写作" | "进入专注写作状态"
            ));

    if is_thesis_writing_goal {
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::GoalWorkspace,
            goal: "进入论文写作专注状态".to_string(),
            sub_goals: vec![
                "定位并打开近期编辑的论文文档与参考资料".to_string(),
                "开启系统勿扰模式以屏蔽通知弹窗干扰".to_string(),
                "启动常用写作或文献阅读软件并聚焦主工作窗口".to_string(),
            ],
            context: GoalContextHints {
                project_hint: Some("论文写作".to_string()),
                preferred_apps: vec![
                    "wps-office-prometheus.desktop".to_string(),
                    "libreoffice-writer.desktop".to_string(),
                    "code.desktop".to_string(),
                ],
                restore_previous_workspace: true,
                avoid_distraction: true,
                preserve_running_critical_apps: true,
            },
            constraints: vec![
                "避免打扰".to_string(),
                "不关闭正在运行的重要程序".to_string(),
            ],
            required_capabilities: vec![
                "file.open".to_string(),
                "notify.dnd.set".to_string(),
                "app.launch".to_string(),
                "window.focus".to_string(),
            ],
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.95,
        });
    }

    // 2. Meeting Preparation Workspace:
    // `"我准备开组会了"` / `"准备开组会"` / `"马上要开组会了"` / `"准备开会了"`
    let is_meeting_prep = !is_deterministic_file_op
        && (t.contains("开组会")
            || t.contains("组会汇报")
            || ((t.contains("开会") || t.contains("组会") || t.contains("线上会议"))
                && (t.contains("准备")
                    || t.contains("马上")
                    || t.contains("进入")
                    || t.contains("要"))));

    if is_meeting_prep {
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::GoalWorkspace,
            goal: "准备组会演示文档、勿扰模式与音视频设备状态".to_string(),
            sub_goals: vec![
                "检索并打开近期组会汇报演示文稿或会议纪要".to_string(),
                "开启系统勿扰模式避免投屏期间弹出私人通知".to_string(),
                "检查音频输出设备与麦克风开关状态".to_string(),
            ],
            context: GoalContextHints {
                project_hint: Some("组会汇报".to_string()),
                preferred_apps: vec![
                    "wps-office-prometheus.desktop".to_string(),
                    "libreoffice-impress.desktop".to_string(),
                ],
                restore_previous_workspace: true,
                avoid_distraction: true,
                preserve_running_critical_apps: true,
            },
            constraints: vec![
                "避免打扰".to_string(),
                "保护投屏隐私".to_string(),
                "不关闭正在运行的重要程序".to_string(),
            ],
            required_capabilities: vec![
                "file.open".to_string(),
                "notify.dnd.set".to_string(),
                "sound.output.list".to_string(),
                "sound.mic.mute.set".to_string(),
            ],
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.94,
        });
    }

    // 3. Cluttered Directory Inspection & Controlled Organization Plan:
    // `"下载目录太乱了"` / `"帮我整理下载文件夹"` / `"桌面太乱了"`
    let has_dir_target = t.contains("下载目录")
        || t.contains("下载文件夹")
        || t.contains("桌面")
        || t.contains("文档目录");
    let has_clutter_or_organize =
        t.contains("太乱") || t.contains("好乱") || t.contains("很乱") || t.contains("整理");

    if has_dir_target && has_clutter_or_organize && !t.contains("撤销") {
        let dir_label = if t.contains("桌面") {
            "桌面"
        } else if t.contains("文档") {
            "文档目录"
        } else {
            "下载目录"
        };
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::GoalWorkspace,
            goal: format!("扫描{}结构并生成可审批的分类整理方案", dir_label),
            sub_goals: vec![
                format!("盘点{}内的文件类型、大小与修改时间分布", dir_label),
                "生成按文件类别或项目归档的整理预览方案".to_string(),
                "待用户审批确认后执行可逆移动并记录撤销变更集".to_string(),
            ],
            context: GoalContextHints {
                project_hint: Some(format!("{}整理", dir_label)),
                preferred_apps: Vec::new(),
                restore_previous_workspace: false,
                avoid_distraction: false,
                preserve_running_critical_apps: true,
            },
            constraints: vec![
                "移动或归档文件前必须先展示整理方案并征得用户批准".to_string(),
                "严禁直接永久删除文件，所有变更须支持一键撤销".to_string(),
            ],
            required_capabilities: vec![
                "file.search".to_string(),
                "disk.usage".to_string(),
                "file.move".to_string(),
            ],
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.94,
        });
    }

    None
}

fn try_parse_procedural_or_knowledge(t: &str) -> Option<StructuredIntent> {
    let starts_how_to = t.starts_with("怎么")
        || t.starts_with("如何")
        || t.starts_with("怎样")
        || t.starts_with("请问怎么")
        || t.starts_with("请问如何")
        || t.starts_with("我想知道怎么")
        || t.starts_with("我想知道如何")
        || t.starts_with("能不能告诉我怎么")
        || t.starts_with("帮我看看怎么");

    let has_procedural_phrase = t.contains("怎么批量")
        || t.contains("如何批量")
        || t.contains("命令是什么")
        || t.contains("怎么用命令")
        || t.contains("如何用命令");

    if starts_how_to || has_procedural_phrase {
        let mut req_caps = Vec::new();
        if t.contains("文件") || t.contains("日志") || t.contains("查找") {
            req_caps.push("file.search".to_string());
        }
        if t.contains("进程") || t.contains("内存") {
            req_caps.push("process.list".to_string());
        }
        if t.contains("目录大小") || t.contains("空间") {
            req_caps.push("disk.usage".to_string());
        }
        if t.contains("git") {
            req_caps.push("git.status".to_string());
        }

        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::ProceduralOrKnowledge,
            goal: format!("解答方法步骤或提供安全命令移交指引：{}", t),
            sub_goals: vec![
                "解析用户询问的技术目标与操作边界".to_string(),
                "给出分步说明或可审阅终端命令（handoff_command），绝不未经授权自动执行".to_string(),
            ],
            context: GoalContextHints::default(),
            constraints: vec!["仅提供指引或命令建议，禁止将问答误触发为直接破坏性执行".to_string()],
            required_capabilities: req_caps,
            recommended_route: RouteLayer::L2,
            requires_planning: true,
            direct_capability: None,
            confidence: 0.93,
        });
    }

    None
}

fn try_parse_relative_adjustment(t: &str) -> Option<StructuredIntent> {
    let lc = t.to_ascii_lowercase();

    // 1. Implicit audio state complaints & explicit relative volume adjustments
    // `"声音有点吵"` / `"太吵了"` / `"小声点"` / `"音量调大一点"`
    if matches!(
        t,
        "声音有点吵"
            | "有点吵"
            | "太吵了"
            | "声音太吵"
            | "声音太吵了"
            | "好吵"
            | "声音太大"
            | "声音太大了"
            | "声音有点大"
            | "音量太大"
            | "音量太大了"
            | "小声点"
            | "调小一点"
            | "声音轻一点"
            | "声音小一点"
            | "声音调小一点"
            | "音量小一点"
            | "音量调小一点"
    ) {
        let is_l0_phrase = t.contains("小") || t.contains("轻");
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::RelativeAdjustment,
            goal: "调低系统音量 (-10%)".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["sound.volume.set".to_string()],
            recommended_route: if is_l0_phrase {
                RouteLayer::L0
            } else {
                RouteLayer::L1
            },
            requires_planning: false,
            direct_capability: Some((
                "sound.volume.set".to_string(),
                json!({ "relative": "down" }),
            )),
            confidence: 0.94,
        });
    }

    if matches!(
        t,
        "声音太小"
            | "声音太小了"
            | "声音有点小"
            | "听不见声音"
            | "声音听不清"
            | "大声点"
            | "声音大一点"
            | "声音调大一点"
            | "音量大一点"
            | "音量调大一点"
    ) {
        let is_l0_phrase = t == "大声点" || (t.contains("大") && !t.contains("太"));
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::RelativeAdjustment,
            goal: "调高系统音量 (+10%)".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["sound.volume.set".to_string()],
            recommended_route: if is_l0_phrase {
                RouteLayer::L0
            } else {
                RouteLayer::L1
            },
            requires_planning: false,
            direct_capability: Some(("sound.volume.set".to_string(), json!({ "relative": "up" }))),
            confidence: 0.94,
        });
    }

    // 2. Implicit display brightness complaints & explicit relative brightness adjustments
    // `"屏幕有点刺眼"` / `"太亮了"` / `"暗一点"` / `"屏幕亮一点"`
    if matches!(
        t,
        "屏幕有点刺眼"
            | "有点刺眼"
            | "屏幕刺眼"
            | "屏幕好刺眼"
            | "太刺眼了"
            | "太亮了"
            | "屏幕太亮"
            | "屏幕太亮了"
            | "屏幕有点亮"
            | "好晃眼"
            | "暗一点"
            | "调暗一点"
            | "再暗一点"
            | "屏幕暗一点"
            | "亮度低一点"
            | "亮度调低一点"
    ) {
        let is_l0_phrase = matches!(
            t,
            "暗一点" | "调暗一点" | "再暗一点" | "屏幕暗一点" | "屏幕太亮" | "屏幕太亮了"
        ) || t.contains("亮度");
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::RelativeAdjustment,
            goal: "调暗屏幕亮度 (-10%)".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: vec!["保留最低安全可见亮度 (>=1%) 防止黑屏".to_string()],
            required_capabilities: vec!["display.brightness.set".to_string()],
            recommended_route: if is_l0_phrase {
                RouteLayer::L0
            } else {
                RouteLayer::L1
            },
            requires_planning: false,
            direct_capability: Some((
                "display.brightness.set".to_string(),
                json!({ "relative": "down" }),
            )),
            confidence: 0.94,
        });
    }

    if matches!(
        t,
        "太暗了"
            | "屏幕太暗"
            | "屏幕太暗了"
            | "屏幕有点暗"
            | "看不清屏幕"
            | "亮一点"
            | "调亮一点"
            | "再亮一点"
            | "屏幕亮一点"
            | "亮度高一点"
            | "亮度调高一点"
    ) {
        let is_l0_phrase = matches!(
            t,
            "亮一点" | "调亮一点" | "再亮一点" | "屏幕亮一点" | "屏幕太暗" | "屏幕太暗了"
        ) || t.contains("亮度");
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::RelativeAdjustment,
            goal: "调亮屏幕亮度 (+10%)".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["display.brightness.set".to_string()],
            recommended_route: if is_l0_phrase {
                RouteLayer::L0
            } else {
                RouteLayer::L1
            },
            requires_planning: false,
            direct_capability: Some((
                "display.brightness.set".to_string(),
                json!({ "relative": "up" }),
            )),
            confidence: 0.94,
        });
    }

    // 3. Night-light color temperature & font text-scale relative tweaks
    if matches!(t, "暖一点" | "屏幕暖一点" | "色温暖一点" | "黄一点") {
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::RelativeAdjustment,
            goal: "调暖屏幕夜灯色温".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["display.night_light.temperature".to_string()],
            recommended_route: RouteLayer::L0,
            requires_planning: false,
            direct_capability: Some((
                "display.night_light.temperature".to_string(),
                json!({ "relative": "warmer" }),
            )),
            confidence: 0.94,
        });
    }
    if matches!(t, "冷一点" | "屏幕冷一点" | "色温冷一点") {
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::RelativeAdjustment,
            goal: "调冷屏幕夜灯色温".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["display.night_light.temperature".to_string()],
            recommended_route: RouteLayer::L0,
            requires_planning: false,
            direct_capability: Some((
                "display.night_light.temperature".to_string(),
                json!({ "relative": "cooler" }),
            )),
            confidence: 0.94,
        });
    }
    if matches!(
        lc.as_str(),
        "字体太小" | "字体太小了" | "字太小了" | "把字体调大一点" | "字体大一点" | "字大一点"
    ) {
        return Some(StructuredIntent {
            intent_type: CognitiveIntentKind::RelativeAdjustment,
            goal: "放大界面文字缩放比例".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["appearance.text_scale.set".to_string()],
            recommended_route: if t.contains("太") {
                RouteLayer::L1
            } else {
                RouteLayer::L0
            },
            requires_planning: false,
            direct_capability: Some((
                "appearance.text_scale.set".to_string(),
                json!({ "relative": "up" }),
            )),
            confidence: 0.93,
        });
    }

    None
}

fn parse_deterministic_or_fallback(
    t: &str,
    capabilities: &[CapabilityDescriptor],
) -> StructuredIntent {
    let lc = t.to_ascii_lowercase();

    // 1. Local IP / LAN address inspection (`查一下内网地址`, `内网地址`, `局域网地址`, `查看内网IP`)
    if matches!(
        lc.as_str(),
        "我的 ip"
            | "我的ip"
            | "本机 ip"
            | "本机ip"
            | "查看 ip"
            | "查看ip地址"
            | "查看 ip 地址"
            | "局域网 ip"
            | "局域网ip"
            | "局域网地址"
            | "内网地址"
            | "本机地址"
            | "内网 ip"
            | "内网ip"
            | "查看内网ip"
            | "查看内网 ip"
            | "查一下内网地址"
            | "查一下局域网地址"
            | "查一下内网ip"
            | "查一下内网 ip"
            | "查一下本机ip"
            | "查一下本机 ip"
            | "查一下ip"
            | "查一下 ip"
            | "查一下ip地址"
            | "my ip"
            | "看看局域网地址"
            | "查看内网地址"
    ) {
        let route = if matches!(t, "看看局域网地址" | "查看内网地址") {
            RouteLayer::L1
        } else {
            RouteLayer::L0
        };
        return StructuredIntent {
            intent_type: CognitiveIntentKind::DeterministicCommand,
            goal: "查询本机局域网/内网 IP 地址与网卡信息".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["network.ip".to_string()],
            recommended_route: route,
            requires_planning: false,
            direct_capability: Some(("network.ip".to_string(), json!({}))),
            confidence: 0.96,
        };
    }

    // 2. Power profile deterministic & colloquial commands (`开启省电续航`, `省电续航`, `切到续航优先`, `开启满血性能`)
    if matches!(
        t,
        "省电模式"
            | "开启省电模式"
            | "切到省电模式"
            | "开启省电续航"
            | "省电续航"
            | "切到续航优先"
            | "续航优先"
    ) {
        let route = if matches!(t, "切到续航优先" | "续航优先") {
            RouteLayer::L1
        } else {
            RouteLayer::L0
        };
        return StructuredIntent {
            intent_type: CognitiveIntentKind::DeterministicCommand,
            goal: "切换系统电源模式为省电续航 (power-saver)".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["power.profile.set".to_string()],
            recommended_route: route,
            requires_planning: false,
            direct_capability: Some((
                "power.profile.set".to_string(),
                json!({ "profile": "power-saver" }),
            )),
            confidence: 0.96,
        };
    }
    if matches!(
        t,
        "性能模式" | "高性能模式" | "开启性能模式" | "开启满血性能" | "满血性能"
    ) {
        let route = if t.contains("满血") {
            RouteLayer::L1
        } else {
            RouteLayer::L0
        };
        return StructuredIntent {
            intent_type: CognitiveIntentKind::DeterministicCommand,
            goal: "切换系统电源模式为高性能 (performance)".to_string(),
            sub_goals: Vec::new(),
            context: GoalContextHints::default(),
            constraints: Vec::new(),
            required_capabilities: vec!["power.profile.set".to_string()],
            recommended_route: route,
            requires_planning: false,
            direct_capability: Some((
                "power.profile.set".to_string(),
                json!({ "profile": "performance" }),
            )),
            confidence: 0.96,
        };
    }

    // 3. Consult registered `CapabilityDescriptor` lexicon when provided
    if !capabilities.is_empty() {
        let refs: Vec<&CapabilityDescriptor> = capabilities.iter().collect();
        let compiler = PatternCompiler::compile_from_descriptors(&refs);
        let ranked = fuzzy_scorer::rank_capabilities(t, &compiler, None, 3);
        if let Some(top) = ranked.first() {
            let route = if top.confidence >= 0.85 {
                RouteLayer::L0
            } else if top.confidence >= 0.60 {
                RouteLayer::L1
            } else {
                RouteLayer::L2
            };
            let requires_planning = route == RouteLayer::L2;
            return StructuredIntent {
                intent_type: CognitiveIntentKind::DeterministicCommand,
                goal: top.summary.clone(),
                sub_goals: Vec::new(),
                context: GoalContextHints::default(),
                constraints: Vec::new(),
                required_capabilities: vec![top.capability_id.clone()],
                recommended_route: route,
                requires_planning,
                direct_capability: if !requires_planning {
                    Some((top.capability_id.clone(), json!({})))
                } else {
                    None
                },
                confidence: top.confidence,
            };
        }
    }

    StructuredIntent {
        intent_type: CognitiveIntentKind::DeterministicCommand,
        goal: t.to_string(),
        sub_goals: Vec::new(),
        context: GoalContextHints::default(),
        constraints: Vec::new(),
        required_capabilities: Vec::new(),
        recommended_route: RouteLayer::L1,
        requires_planning: false,
        direct_capability: None,
        confidence: 0.55,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrainConfig;
    use crate::db::StateDb;
    use intentos_protocol::{Effect, ExecutionBackend, UndoStrategy};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn sample_capabilities() -> Vec<CapabilityDescriptor> {
        [
            ("file.open", "使用系统默认关联程序打开授权路径文件"),
            ("notify.dnd.set", "开启或关闭系统勿扰模式"),
            ("app.launch", "按应用 ID 或别名启动桌面应用"),
            ("window.focus", "按名称聚焦已打开的桌面窗口"),
            ("system.inspect", "采样当前系统负载与内存状态"),
            ("process.list", "列出高占用进程"),
            ("disk.free", "查看磁盘剩余空间"),
            ("sound.volume.set", "设置或相对调整系统音量"),
            ("display.brightness.set", "设置或相对调整屏幕亮度"),
            ("network.ip", "查询本机网络接口与局域网 IP 地址"),
            ("power.profile.set", "切换系统电源性能模式"),
            ("web.search", "使用默认搜索引擎打开搜索结果"),
            ("file.recent", "列出最近修改的文件"),
            ("file.search", "按条件检索授权目录文件"),
            ("disk.usage", "统计目录磁盘占用"),
            ("file.move", "可逆移动文件"),
            ("sound.output.list", "列出音频输出设备"),
            ("sound.mic.mute.set", "切换麦克风静音状态"),
        ]
        .into_iter()
        .map(|(id, summary)| CapabilityDescriptor {
            id: id.to_string(),
            version: 1,
            summary: summary.to_string(),
            category: "test".to_string(),
            aliases: Vec::new(),
            l0_patterns: Vec::new(),
            input_schema: json!({ "type": "object", "properties": {} }),
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
        })
        .collect()
    }

    #[test]
    fn parses_thesis_focus_goal_workspace_archetypes() {
        let caps = sample_capabilities();
        for utterance in ["今天想专心写论文", "开始写论文", "进入论文写作状态"]
        {
            let parsed = parse_structured_intent(utterance, &caps);
            assert_eq!(
                parsed.intent_type,
                CognitiveIntentKind::GoalWorkspace,
                "utterance={utterance}"
            );
            assert_eq!(parsed.goal, "进入论文写作专注状态");
            assert!(parsed.context.restore_previous_workspace);
            assert!(parsed.context.avoid_distraction);
            assert!(parsed.context.preserve_running_critical_apps);
            assert_eq!(
                parsed.constraints,
                vec![
                    "避免打扰".to_string(),
                    "不关闭正在运行的重要程序".to_string()
                ]
            );
            assert_eq!(
                parsed.required_capabilities,
                vec![
                    "file.open".to_string(),
                    "notify.dnd.set".to_string(),
                    "app.launch".to_string(),
                    "window.focus".to_string(),
                ]
            );
            assert!(parsed.requires_planning);
            assert_eq!(parsed.recommended_route, RouteLayer::L2);
            assert!(parsed.direct_capability.is_none());
        }
    }

    #[test]
    fn parses_meeting_prep_and_directory_cleanup_goals() {
        let caps = sample_capabilities();

        let meeting = parse_structured_intent("我准备开组会了", &caps);
        assert_eq!(meeting.intent_type, CognitiveIntentKind::GoalWorkspace);
        assert!(meeting.requires_planning);
        assert_eq!(meeting.recommended_route, RouteLayer::L2);
        assert!(meeting.context.avoid_distraction);
        assert!(
            meeting
                .required_capabilities
                .contains(&"notify.dnd.set".to_string())
        );

        for clutter in ["下载目录太乱了", "帮我整理下载文件夹"] {
            let clean_goal = parse_structured_intent(clutter, &caps);
            assert_eq!(clean_goal.intent_type, CognitiveIntentKind::GoalWorkspace);
            assert!(clean_goal.requires_planning);
            assert_eq!(clean_goal.recommended_route, RouteLayer::L2);
            assert!(
                clean_goal
                    .required_capabilities
                    .contains(&"file.search".to_string())
            );
            assert!(
                clean_goal
                    .required_capabilities
                    .contains(&"file.move".to_string())
            );
        }
    }

    #[test]
    fn parses_system_diagnosis_archetypes() {
        let caps = sample_capabilities();
        for utterance in [
            "电脑最近有点卡",
            "系统好慢帮我查查",
            "我的软件怎么又启动不了了",
        ] {
            let diag = parse_structured_intent(utterance, &caps);
            assert_eq!(
                diag.intent_type,
                CognitiveIntentKind::SystemDiagnosis,
                "utterance={utterance}"
            );
            assert_eq!(
                diag.required_capabilities,
                vec![
                    "system.inspect".to_string(),
                    "process.list".to_string(),
                    "disk.free".to_string(),
                ]
            );
            assert!(diag.requires_planning);
            assert_eq!(diag.recommended_route, RouteLayer::L2);
        }
    }

    #[test]
    fn parses_compound_task_and_procedural_queries() {
        let caps = sample_capabilities();

        let compound = parse_structured_intent(
            "帮我看下今天的天气，告诉我早上起床穿什么衣服，然后告诉我今天最应该完成哪些任务",
            &caps,
        );
        assert_eq!(compound.intent_type, CognitiveIntentKind::CompoundTask);
        assert!(compound.sub_goals.len() >= 2);
        assert!(compound.requires_planning);
        assert_eq!(compound.recommended_route, RouteLayer::L2);

        let how_to = parse_structured_intent("怎么批量查找最近7天修改过的日志", &caps);
        assert_eq!(
            how_to.intent_type,
            CognitiveIntentKind::ProceduralOrKnowledge
        );
        assert!(how_to.requires_planning);
        assert_eq!(how_to.recommended_route, RouteLayer::L2);
    }

    #[test]
    fn parses_implicit_relative_adjustments_and_direct_commands() {
        let caps = sample_capabilities();

        let noisy = parse_structured_intent("声音有点吵", &caps);
        assert_eq!(noisy.intent_type, CognitiveIntentKind::RelativeAdjustment);
        assert_eq!(
            noisy.direct_capability,
            Some((
                "sound.volume.set".to_string(),
                json!({ "relative": "down" })
            ))
        );

        for bright in ["屏幕有点刺眼", "太亮了"] {
            let parsed = parse_structured_intent(bright, &caps);
            assert_eq!(parsed.intent_type, CognitiveIntentKind::RelativeAdjustment);
            assert_eq!(
                parsed.direct_capability,
                Some((
                    "display.brightness.set".to_string(),
                    json!({ "relative": "down" })
                ))
            );
        }

        let ip = parse_structured_intent("查一下内网地址", &caps);
        assert_eq!(ip.intent_type, CognitiveIntentKind::DeterministicCommand);
        assert_eq!(ip.recommended_route, RouteLayer::L0);
        assert_eq!(
            ip.direct_capability,
            Some(("network.ip".to_string(), json!({})))
        );

        let pwr = parse_structured_intent("开启省电续航", &caps);
        assert_eq!(pwr.intent_type, CognitiveIntentKind::DeterministicCommand);
        assert_eq!(
            pwr.direct_capability,
            Some((
                "power.profile.set".to_string(),
                json!({ "profile": "power-saver" })
            ))
        );
    }

    #[tokio::test]
    async fn fast_llm_parser_validates_capabilities_and_falls_back_safely() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(StateDb::open(&tmp.path().join("state.db")).unwrap());
        let gw = ModelGateway::new(BrainConfig::default(), db).unwrap();
        let caps = sample_capabilities();

        // 1. Spawn mock HTTP server returning structured JSON with one valid + one hallucinated capability
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let llm_content = json!({
                    "intent_type": "GoalWorkspace",
                    "goal": "进入深度论文写作专注工作区",
                    "sub_goals": ["打开最近论文初稿", "启用系统免打扰"],
                    "context": {
                        "project_hint": "毕业论文",
                        "preferred_apps": ["wps-office-prometheus.desktop"],
                        "restore_previous_workspace": true,
                        "avoid_distraction": true,
                        "preserve_running_critical_apps": true
                    },
                    "constraints": ["避免打扰", "不关闭正在运行的重要程序"],
                    "required_capabilities": ["file.open", "notify.dnd.set", "hallucinated.magic.tool"],
                    "recommended_route": "L2",
                    "requires_planning": true,
                    "direct_capability": ["file.open", {"path": "/etc/passwd"}],
                    "confidence": 0.97
                })
                .to_string();
                let resp_body = json!({
                    "choices": [{ "message": { "content": format!("```json\n{}\n```", llm_content) } }],
                    "usage": { "prompt_tokens": 120, "completion_tokens": 80 }
                })
                .to_string();
                let http_resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = sock.write_all(http_resp.as_bytes()).await;
            }
        });

        gw.set_mock_upstream_url(Some(format!("http://{}", addr)));
        let refined = parse_structured_intent_with_llm(
            &gw,
            "今天想专心写论文",
            Some("active_window=Firefox"),
            &caps,
        )
        .await;
        assert_eq!(refined.intent_type, CognitiveIntentKind::GoalWorkspace);
        assert_eq!(refined.goal, "进入深度论文写作专注工作区");
        // Hallucinated capability MUST be stripped, valid ones preserved, and direct_capability cleared on L2 GoalWorkspace!
        assert_eq!(
            refined.required_capabilities,
            vec!["file.open".to_string(), "notify.dnd.set".to_string()]
        );
        assert!(refined.direct_capability.is_none());
        assert_eq!(refined.recommended_route, RouteLayer::L2);

        // 2. Point mock upstream to closed port -> must gracefully fall back to deterministic local parser!
        gw.set_mock_upstream_url(Some("http://127.0.0.1:9".to_string()));
        let fallback = parse_structured_intent_with_llm(&gw, "今天想专心写论文", None, &caps).await;
        assert_eq!(fallback.intent_type, CognitiveIntentKind::GoalWorkspace);
        assert_eq!(fallback.goal, "进入论文写作专注状态");
        assert_eq!(fallback.recommended_route, RouteLayer::L2);
    }
}
