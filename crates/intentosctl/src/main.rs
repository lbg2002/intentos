#![forbid(unsafe_code)]

//! `intentosctl` — IntentOS Command Line & Interactive TUI Client (`WP11`, §15.1, `v0.1 Intent Shell`).
//! Connects to `intentosd` over the private Unix socket `${XDG_RUNTIME_DIR}/intentos/ui.sock`
//! and seamlessly falls back to an embedded `IntentOsCore` instance if the daemon is not running.

mod eval;
mod tui;

use clap::{Parser, Subcommand};
use intentos_capability_sdk::{generate_markdown_docs, load_descriptors_from_dir};
use intentos_protocol::{
    CandidateResponse, ChangeSet, DaemonStatus, IntentRequest, MemoryEntry, Task, TaskStatus,
    UiRpcEnvelope, UiRpcRequest, UiRpcResponse,
};
use intentosd::config::XdgPaths;
use intentosd::core::IntentOsCore;
use serde_json::Value;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Parser)]
#[command(
    name = "intentosctl",
    version,
    about = "IntentOS 命令行入口与实时意图交互工具 (v0.1 Intent Shell)"
)]
struct Cli {
    /// 自定义 XDG 根目录（用于测试隔离环境）
    #[arg(long, global = true)]
    base_dir: Option<PathBuf>,

    /// 仓库根目录（用于定位内置能力描述与评测集）
    #[arg(long, global = true)]
    repo_root: Option<PathBuf>,

    /// 以 JSON 输出原始结果
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 提交自然语言意图或以 `$ ` 执行终端命令直通
    Ask {
        /// 自然语言意图文本（如："把音量调到 30%"、"进入护眼模式"、"$ git status"）
        intent: Vec<String>,
        /// 强制进入 L2 智能体规划执行
        #[arg(long)]
        agent: bool,
        /// 启用隐私会话（不保存任务历史、命令直通历史或持久化记忆，M-01）
        #[arg(long)]
        incognito: bool,
        /// 指定会话 ID（用于多轮指代消解，如“把它移到文档目录”）
        #[arg(long)]
        session: Option<String>,
        /// 遇到需要审批的操作时自动确认（仅用于测试）
        #[arg(long)]
        yes: bool,
    },
    /// 启动实时 `<30ms` 候选刷新的交互式终端意图启动器 (TUI)
    Ui,
    /// 测试输入过程中的实时候选列表与微秒级响应延迟
    Candidates {
        /// 查询词（可为空字符串以查看默认快捷建议）
        #[arg(default_value = "")]
        query: String,
    },
    /// 一键撤销最近一次（或指定 ID）的可逆文件/系统设置/组合场景变更
    Undo {
        /// 可选：指定 ChangeSet ID 或 Task ID
        target_id: Option<String>,
    },
    /// 批准处于 `awaiting_approval` 状态的待审批单（需携带一次性 Nonce 与 Digest）
    Approve {
        approval_id: String,
        nonce: String,
        digest: String,
    },
    /// 拒绝待审批单
    Deny {
        approval_id: String,
    },
    /// 查看最近的任务列表与状态
    Tasks {
        #[arg(short, long, default_value_t = 15)]
        limit: usize,
    },
    /// 查看最近的变更集（ChangeSet）与可撤销状态
    Changesets {
        #[arg(short, long, default_value_t = 15)]
        limit: usize,
    },
    /// 管理显式偏好记忆中心（列表 / 写入 / 删除并写入拒绝指纹，§11.2, M-03）
    Memories {
        #[command(subcommand)]
        action: Option<MemoryCommands>,
    },
    /// 查看或保存组合场景模式（护眼模式、演示模式、安静模式及自定义场景，§7.8.2 K）
    Scenes {
        /// 可选：将当前系统设置快照保存为指定场景名称
        #[arg(long)]
        save: Option<String>,
    },
    /// 查看或清空 `$ ` 命令直通历史（§8.8）
    History {
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
        /// 清空全部命令直通历史
        #[arg(long)]
        clear: bool,
    },
    /// 查看四页设置中心汇总（大脑 / 资源 / 网站 / 权限与撤销，§14.2）
    Settings,
    /// 查看守护进程、索引规模、撤销配额与大脑中枢状态
    Status,
    /// 探测当前主机可用能力后端（音频/亮度/GNOME/网络/沙箱驱动）
    Probe,
    /// 立即刷新桌面应用、授权目录文件、已安装字体与浏览器书签索引
    Reindex,
    /// 紧急停止全部活动会话并吊销模型租约令牌（Stop All）
    StopAll,
    /// 从 YAML 能力描述单源自动生成 `docs/capabilities.md` 参考手册
    Docs {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// 运行 `v0.1` 300+ 日常意图基准评测与 16 项红队安全门禁套件
    Eval {
        #[arg(long)]
        corpus: Option<PathBuf>,
        #[arg(long)]
        report_out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum MemoryCommands {
    /// 列出全部有效偏好记忆
    List,
    /// 写入或更新一条显式偏好记忆（自动拒绝私钥/令牌）
    Set { subject: String, value: String },
    /// 删除一条记忆并写入拒绝指纹（M-03）
    Delete { id_or_subject: String },
}

pub enum ClientHandle {
    Socket {
        sock_path: PathBuf,
    },
    Embedded {
        core: Arc<IntentOsCore>,
    },
}

impl ClientHandle {
    pub async fn connect_or_embed(
        base_dir: Option<&std::path::Path>,
        repo_root: PathBuf,
    ) -> anyhow::Result<Self> {
        let paths = XdgPaths::resolve(base_dir, repo_root.clone());
        let sock = paths.ui_socket_path();
        if sock.exists() && UnixStream::connect(&sock).await.is_ok() {
            return Ok(Self::Socket { sock_path: sock });
        }
        let core = IntentOsCore::initialize(base_dir, repo_root)?;
        Ok(Self::Embedded { core })
    }

    pub async fn call(&mut self, request: UiRpcRequest) -> anyhow::Result<Value> {
        let req_id = format!("rpc_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let resp: UiRpcResponse = match self {
            Self::Socket { sock_path } => {
                let stream = UnixStream::connect(&*sock_path).await?;
                let (r, mut w) = stream.into_split();
                let env = UiRpcEnvelope {
                    id: req_id,
                    request,
                };
                let line = serde_json::to_string(&env)?;
                w.write_all(line.as_bytes()).await?;
                w.write_all(b"\n").await?;
                w.flush().await?;

                let mut reader = BufReader::new(r).lines();
                let reply_line = reader
                    .next_line()
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("ui.sock 连接提前关闭"))?;
                serde_json::from_str(&reply_line)?
            }
            Self::Embedded { core } => core.handle_trusted_ui_rpc(req_id, request).await,
        };

        if resp.ok {
            Ok(resp.result.unwrap_or(Value::Null))
        } else {
            anyhow::bail!("{}", resp.error.unwrap_or_else(|| "未知 RPC 错误".into()))
        }
    }
}

fn detect_repo_root(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("modules/builtin").exists() {
            return cwd;
        }
        if let Some(parent) = cwd.parent()
            && parent.join("modules/builtin").exists()
        {
            return parent.to_path_buf();
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        for anc in exe.ancestors() {
            if anc.join("modules/builtin").exists() {
                return anc.to_path_buf();
            }
        }
    }
    PathBuf::from(".")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let repo_root = detect_repo_root(cli.repo_root.clone());

    match cli.command {
        Commands::Docs { output } => {
            let dir = repo_root.join("modules/builtin");
            let mut descriptors = load_descriptors_from_dir(&dir)?;
            descriptors.sort_by(|a, b| a.id.cmp(&b.id));
            let md = generate_markdown_docs(&descriptors);
            let out_path = output.unwrap_or_else(|| repo_root.join("docs/capabilities.md"));
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out_path, &md)?;
            println!(
                "✓ 已从 {} 个能力描述单源生成文档: {}",
                descriptors.len(),
                out_path.display()
            );
            return Ok(());
        }
        Commands::Eval { corpus, report_out } => {
            let corpus_path = corpus.unwrap_or_else(|| {
                let v01 = repo_root.join("eval/intents/v0_1_shell_300.json");
                if v01.exists() {
                    v01
                } else {
                    repo_root.join("eval/intents/v0_0_daily_120.json")
                }
            });
            let out_path = report_out.or_else(|| Some(repo_root.join("eval/latest_report.md")));
            let summary =
                eval::run_evaluation_suite(&repo_root, &corpus_path, out_path.as_deref()).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("{}", eval::render_markdown_report(&summary));
            }
            if !summary.all_gates_passed {
                std::process::exit(1);
            }
            return Ok(());
        }
        _ => {}
    }

    let mut client =
        ClientHandle::connect_or_embed(cli.base_dir.as_deref(), repo_root.clone()).await?;

    match cli.command {
        Commands::Ui => {
            tui::run_interactive_tui(&mut client).await?;
        }
        Commands::Candidates { query } => {
            let val = client.call(UiRpcRequest::QueryCandidates { query }).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                let resp: CandidateResponse = serde_json::from_value(val)?;
                println!(
                    "查询: {:?} | 延迟: {:.2} ms ({} µs) | L0直达: {}",
                    resp.query,
                    resp.elapsed_us as f64 / 1000.0,
                    resp.elapsed_us,
                    resp.l0_direct_match
                );
                for (i, item) in resp.items.iter().enumerate() {
                    println!(
                        "  {}. [{}] {} — {} (score={:.2}, cap={:?})",
                        i + 1,
                        item.badge,
                        item.title,
                        item.subtitle,
                        item.score,
                        item.capability_id
                    );
                }
            }
        }
        Commands::Ask {
            intent,
            agent,
            incognito,
            session,
            yes,
        } => {
            let text = intent.join(" ").trim().to_string();
            if text.is_empty() {
                anyhow::bail!("请输入意图内容，例如: intentosctl ask \"把音量调到 30%\"");
            }
            let req = IntentRequest {
                protocol_version: 1,
                text,
                session_id: session,
                force_agent: agent,
                selected_candidate_id: None,
                cwd: std::env::current_dir()
                    .ok()
                    .map(|p| p.to_string_lossy().to_string()),
                incognito,
            };
            let val = client.call(UiRpcRequest::SubmitIntent(req)).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val)?);
                return Ok(());
            }

            if val.get("kind").and_then(|v| v.as_str()) == Some("passthrough") {
                let p = &val["passthrough"];
                println!(
                    "$ {}",
                    p.get("command").and_then(|v| v.as_str()).unwrap_or("")
                );
                if let Some(s) = p
                    .get("stdout")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    print!("{}", s);
                    if !s.ends_with('\n') {
                        println!();
                    }
                }
                if let Some(s) = p
                    .get("stderr")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    eprint!("{}", s);
                }
                println!(
                    "→ {}",
                    p.get("message").and_then(|v| v.as_str()).unwrap_or("")
                );
                return Ok(());
            }

            let task: Task = serde_json::from_value(val)?;
            print_task_summary(&task);

            if task.status == TaskStatus::AwaitingApproval
                && let Some(pa) = task.pending_approval
            {
                println!("\n⚠ 需要用户确认审批 [{}]:", pa.approval_id);
                println!("  能力: {} (效应: {:?})", pa.capability_id, pa.effects);
                println!("  说明: {}", pa.summary);
                println!("  预览: {}", pa.diff_preview);
                println!("  校验: {}", pa.digest);

                let confirmed = if yes {
                    true
                } else {
                    print!("是否批准执行？[y/N]: ");
                    io::stdout().flush()?;
                    let mut line = String::new();
                    io::stdin().read_line(&mut line)?;
                    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
                };

                if confirmed {
                    let approved_val = client
                        .call(UiRpcRequest::Approve {
                            approval_id: pa.approval_id,
                            nonce: pa.nonce,
                            digest: pa.digest,
                        })
                        .await?;
                    let updated: Task = serde_json::from_value(approved_val)?;
                    println!("\n✓ 审批通过，执行结果:");
                    print_task_summary(&updated);
                } else {
                    let _ = client
                        .call(UiRpcRequest::Deny {
                            approval_id: pa.approval_id,
                        })
                        .await;
                    println!("已取消该操作。");
                }
            }
        }
        Commands::Undo { target_id } => {
            let val = client.call(UiRpcRequest::Undo { target_id }).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                println!(
                    "↶ {}",
                    val.get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("撤销成功")
                );
            }
        }
        Commands::Approve {
            approval_id,
            nonce,
            digest,
        } => {
            let val = client
                .call(UiRpcRequest::Approve {
                    approval_id,
                    nonce,
                    digest,
                })
                .await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                let task: Task = serde_json::from_value(val)?;
                print_task_summary(&task);
            }
        }
        Commands::Deny { approval_id } => {
            let val = client.call(UiRpcRequest::Deny { approval_id }).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                println!("已拒绝审批单。");
            }
        }
        Commands::Tasks { limit } => {
            let val = client.call(UiRpcRequest::ListTasks { limit }).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                let tasks: Vec<Task> = serde_json::from_value(val)?;
                if tasks.is_empty() {
                    println!("暂无任务记录。");
                } else {
                    for t in tasks {
                        println!(
                            "[{}] {:?} | {:?} | {} — {}",
                            t.id,
                            t.route,
                            t.status,
                            t.goal,
                            t.assistant_message.unwrap_or_default()
                        );
                    }
                }
            }
        }
        Commands::Changesets { limit } => {
            let val = client.call(UiRpcRequest::ListChangesets { limit }).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                let list: Vec<ChangeSet> = serde_json::from_value(val)?;
                if list.is_empty() {
                    println!("暂无变更集记录。");
                } else {
                    for cs in list {
                        println!(
                            "[{}] {:?} | {} | {} ({} ops)",
                            cs.id,
                            cs.status,
                            cs.capability_id,
                            cs.summary,
                            cs.operations.len()
                        );
                    }
                }
            }
        }
        Commands::Memories { action } => match action.unwrap_or(MemoryCommands::List) {
            MemoryCommands::List => {
                let val = client.call(UiRpcRequest::ListMemories).await?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else {
                    let entries: Vec<MemoryEntry> = serde_json::from_value(val)?;
                    if entries.is_empty() {
                        println!("暂无已保存的显式偏好记忆。");
                    } else {
                        for m in entries {
                            println!("[{}] {} = {} ({})", m.id, m.subject, m.value, m.updated_at);
                        }
                    }
                }
            }
            MemoryCommands::Set { subject, value } => {
                let val = client
                    .call(UiRpcRequest::UpsertMemory { subject, value })
                    .await?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else {
                    println!(
                        "✓ 已保存记忆 [{}]: {} = {}",
                        val["id"].as_str().unwrap_or(""),
                        val["subject"].as_str().unwrap_or(""),
                        val["value"].as_str().unwrap_or("")
                    );
                }
            }
            MemoryCommands::Delete { id_or_subject } => {
                let val = client
                    .call(UiRpcRequest::DeleteMemory { id: id_or_subject })
                    .await?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else if val["deleted"].as_bool() == Some(true) {
                    println!("✓ 已删除记忆并记录拒绝指纹（不会再次自动写入）");
                } else {
                    println!("未找到匹配的记忆条目。");
                }
            }
        },
        Commands::Scenes { save } => {
            if let Some(name) = save {
                let val = client.call(UiRpcRequest::SaveScene { name }).await?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else {
                    println!("{}", val["message"].as_str().unwrap_or("已保存场景"));
                }
            } else {
                let val = client.call(UiRpcRequest::ListScenes).await?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else if let Some(arr) = val.as_array() {
                    for s in arr {
                        let tag = if s["builtin"].as_bool() == Some(true) {
                            "内置"
                        } else {
                            "自定义"
                        };
                        println!(
                            "• [{}] {} — {}",
                            tag,
                            s["name"].as_str().unwrap_or(""),
                            s["description"].as_str().unwrap_or("")
                        );
                    }
                }
            }
        }
        Commands::History { limit, clear } => {
            if clear {
                let val = client.call(UiRpcRequest::ClearPassthroughHistory).await?;
                println!(
                    "✓ 已清空 {} 条命令直通历史记录。",
                    val["cleared"].as_u64().unwrap_or(0)
                );
            } else {
                let val = client
                    .call(UiRpcRequest::ListPassthroughHistory { limit })
                    .await?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else if let Some(arr) = val.as_array() {
                    if arr.is_empty() {
                        println!("暂无 `$ ` 命令直通历史。");
                    } else {
                        for item in arr {
                            println!(
                                "  $ {}   (cwd: {})",
                                item["command"].as_str().unwrap_or(""),
                                item["cwd"].as_str().unwrap_or("")
                            );
                        }
                    }
                }
            }
        }
        Commands::Settings => {
            let val = client.call(UiRpcRequest::GetSettingsOverview).await?;
            println!("{}", serde_json::to_string_pretty(&val)?);
        }
        Commands::Status => {
            let val = client.call(UiRpcRequest::GetStatus).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                let st: DaemonStatus = serde_json::from_value(val)?;
                println!("IntentOS 状态 (v{}, 协议 v{})", st.version, st.protocol_version);
                println!("  PID / 运行时长 : {} / {}s", st.pid, st.uptime_seconds);
                println!(
                    "  资源索引规模   : {} 应用 | {} 文件 | {} 常用站点",
                    st.indexed_apps, st.indexed_files, st.indexed_sites
                );
                println!("  内置结构化能力 : {} 个", st.registered_capabilities);
                println!(
                    "  大脑中枢运行时 : {} (凭据已就绪: {})",
                    st.runtime_mode, st.main_model_configured
                );
                println!("  默认搜索引擎   : {}", st.default_search_engine);
                println!(
                    "  可撤销变更集   : {} 个 (备份占用 {} B)",
                    st.undo_changesets_available, st.undo_backup_bytes
                );
                println!(
                    "  活动会话 / 审批: {} / {}",
                    st.active_sessions, st.pending_approvals
                );
            }
        }
        Commands::Probe => {
            let val = client.call(UiRpcRequest::ProbeCapabilities).await?;
            println!("{}", serde_json::to_string_pretty(&val)?);
        }
        Commands::Reindex => {
            let val = client.call(UiRpcRequest::ReindexResources).await?;
            println!(
                "✓ 索引刷新完成: {} 个桌面应用, {} 个授权目录文件",
                val.get("apps").and_then(|v| v.as_u64()).unwrap_or(0),
                val.get("files").and_then(|v| v.as_u64()).unwrap_or(0)
            );
        }
        Commands::StopAll => {
            let _ = client.call(UiRpcRequest::StopAll).await?;
            println!("✓ 已终止所有活动智能体会话并吊销全部运行令牌。");
        }
        Commands::Docs { .. } | Commands::Eval { .. } => unreachable!(),
    }

    Ok(())
}

fn print_task_summary(task: &Task) {
    println!(
        "[{}] 路由: {:?} | 状态: {:?}",
        task.id, task.route, task.status
    );
    if let Some(ref msg) = task.assistant_message {
        println!("  {}", msg);
    }
    if let Some(ref hc) = task.handoff_command {
        println!("  ⇢ 命令交接（复制到输入框确认执行）: {}", hc);
    }
    for step in &task.steps {
        println!(
            "  • 能力 `{}` -> {:?} (验证: {:?}, 耗时: {} ms){}",
            step.capability_id,
            step.status,
            step.verification.state,
            step.duration_ms,
            step.changeset_id
                .as_ref()
                .map(|id| format!(" [可撤销: {}]", id))
                .unwrap_or_default()
        );
    }
    if !task.candidates_for_disambiguation.is_empty() {
        println!("  候选消歧项:");
        for (i, c) in task.candidates_for_disambiguation.iter().enumerate() {
            println!("    {}. [{}] {} — {}", i + 1, c.badge, c.title, c.subtitle);
        }
    }
}
