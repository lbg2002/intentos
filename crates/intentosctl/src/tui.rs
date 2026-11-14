#![forbid(unsafe_code)]

//! Interactive as-you-type Terminal Intent Launcher (`intentosctl ui`, §3.1, §15.1).
//! Refreshes real-time `<30ms` candidates on every keystroke, supports arrow selection,
//! `Enter` execution, `Tab` force-L2 Agent, `Ctrl+Z` undo, inline approval (`y`/`n`), and `$` passthrough.

use crate::ClientHandle;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{
        self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use intentos_protocol::{
    CandidateItem, CandidateResponse, IntentRequest, PendingApproval, Task, TaskStatus,
    UiRpcRequest,
};
use std::io::{Write, stdout};
use std::time::Duration;

struct RawScreenGuard;

impl RawScreenGuard {
    fn enter() -> anyhow::Result<Self> {
        terminal::enable_raw_mode()?;
        execute!(stdout(), EnterAlternateScreen, cursor::Hide)?;
        Ok(Self)
    }
}

impl Drop for RawScreenGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), cursor::Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

pub async fn run_interactive_tui(client: &mut ClientHandle) -> anyhow::Result<()> {
    let _guard = RawScreenGuard::enter()?;
    let mut input = String::new();
    let mut selected_idx: usize = 0;
    let mut last_candidates = fetch_candidates(client, "").await.unwrap_or(CandidateResponse {
        query: String::new(),
        elapsed_us: 0,
        l0_direct_match: false,
        items: Vec::new(),
    });
    let mut status_banner: Option<(Color, String)> = Some((
        Color::Cyan,
        "就绪：输入自然语言意图、应用/文件名/网址，或以 `$ ` 输入终端命令。↑↓ 选择，Enter 执行，Ctrl+Z 撤销，Esc 退出".into(),
    ));
    let mut pending_approval: Option<PendingApproval> = None;

    loop {
        render_frame(
            &input,
            &last_candidates,
            selected_idx,
            status_banner.as_ref(),
            pending_approval.as_ref(),
        )?;

        if !event::poll(Duration::from_millis(120))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        // Handle active approval modal first
        if let Some(pa) = pending_approval.clone() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    match client
                        .call(UiRpcRequest::Approve {
                            approval_id: pa.approval_id.clone(),
                            nonce: pa.nonce.clone(),
                            digest: pa.digest.clone(),
                        })
                        .await
                    {
                        Ok(val) => {
                            let msg = val
                                .get("assistant_message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("已批准并完成执行");
                            status_banner = Some((Color::Green, format!("✓ {}", msg)));
                        }
                        Err(e) => {
                            status_banner = Some((Color::Red, format!("✗ 审批执行失败: {}", e)));
                        }
                    }
                    pending_approval = None;
                    continue;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    let _ = client
                        .call(UiRpcRequest::Deny {
                            approval_id: pa.approval_id,
                        })
                        .await;
                    pending_approval = None;
                    status_banner = Some((Color::Yellow, "已拒绝待审批操作".into()));
                    continue;
                }
                _ => continue,
            }
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c') | KeyCode::Char('q') => break,
                KeyCode::Char('z') => {
                    match client.call(UiRpcRequest::Undo { target_id: None }).await {
                        Ok(val) => {
                            let msg = val
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("已撤销最近一次变更");
                            status_banner = Some((Color::Green, format!("↶ {}", msg)));
                        }
                        Err(e) => {
                            status_banner = Some((Color::Yellow, format!("无法撤销: {}", e)));
                        }
                    }
                    continue;
                }
                KeyCode::Char('u') => {
                    input.clear();
                    selected_idx = 0;
                    if let Ok(c) = fetch_candidates(client, &input).await {
                        last_candidates = c;
                    }
                    continue;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Esc => {
                if input.is_empty() {
                    break;
                }
                input.clear();
                selected_idx = 0;
                if let Ok(c) = fetch_candidates(client, &input).await {
                    last_candidates = c;
                }
            }
            KeyCode::Up => {
                if !last_candidates.items.is_empty() {
                    selected_idx = selected_idx.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if !last_candidates.items.is_empty() {
                    selected_idx = (selected_idx + 1).min(last_candidates.items.len() - 1);
                }
            }
            KeyCode::Backspace => {
                input.pop();
                selected_idx = 0;
                if let Ok(c) = fetch_candidates(client, &input).await {
                    last_candidates = c;
                }
            }
            KeyCode::Tab => {
                // Force L2 Agent execution on current query
                if !input.trim().is_empty() {
                    execute_submission(
                        client,
                        &mut input,
                        None,
                        true,
                        &mut status_banner,
                        &mut pending_approval,
                    )
                    .await;
                    if let Ok(c) = fetch_candidates(client, &input).await {
                        last_candidates = c;
                    }
                }
            }
            KeyCode::Enter => {
                if input.trim().is_empty() {
                    continue;
                }
                let chosen = last_candidates.items.get(selected_idx).cloned();
                execute_submission(
                    client,
                    &mut input,
                    chosen,
                    false,
                    &mut status_banner,
                    &mut pending_approval,
                )
                .await;
                selected_idx = 0;
                if let Ok(c) = fetch_candidates(client, &input).await {
                    last_candidates = c;
                }
            }
            KeyCode::Char(ch) => {
                input.push(ch);
                selected_idx = 0;
                if let Ok(c) = fetch_candidates(client, &input).await {
                    last_candidates = c;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

async fn fetch_candidates(client: &mut ClientHandle, query: &str) -> anyhow::Result<CandidateResponse> {
    let val = client
        .call(UiRpcRequest::QueryCandidates {
            query: query.to_string(),
        })
        .await?;
    Ok(serde_json::from_value(val)?)
}

async fn execute_submission(
    client: &mut ClientHandle,
    input: &mut String,
    chosen: Option<CandidateItem>,
    force_agent: bool,
    status_banner: &mut Option<(Color, String)>,
    pending_approval: &mut Option<PendingApproval>,
) {
    let text = input.trim().to_string();
    let selected_candidate_id = if force_agent || text.starts_with('$') {
        None
    } else {
        chosen
            .as_ref()
            .filter(|c| c.capability_id.is_some())
            .map(|c| c.id.clone())
    };

    let req = IntentRequest {
        protocol_version: 1,
        text: text.clone(),
        session_id: Some("tui_default".into()),
        force_agent,
        selected_candidate_id,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().to_string()),
        incognito: false,
    };

    match client.call(UiRpcRequest::SubmitIntent(req)).await {
        Ok(val) => {
            if val.get("kind").and_then(|v| v.as_str()) == Some("passthrough") {
                let p = &val["passthrough"];
                let msg = p
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("命令已执行");
                let out = p
                    .get("stdout")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("");
                *status_banner = Some((
                    Color::Cyan,
                    if out.is_empty() {
                        format!("$ {}", msg)
                    } else {
                        format!("$ {} | {}", msg, out)
                    },
                ));
                input.clear();
                return;
            }
            if let Ok(task) = serde_json::from_value::<Task>(val) {
                if task.status == TaskStatus::AwaitingApproval {
                    *pending_approval = task.pending_approval;
                    *status_banner = Some((
                        Color::Yellow,
                        "⚠ 操作触发策略审批，请审阅预览并按 [Y] 批准 / [N] 拒绝".into(),
                    ));
                } else {
                    let color = match task.status {
                        TaskStatus::Completed => Color::Green,
                        TaskStatus::Failed | TaskStatus::Cancelled => Color::Red,
                        _ => Color::Yellow,
                    };
                    let msg = task
                        .assistant_message
                        .unwrap_or_else(|| format!("状态: {:?}", task.status));
                    *status_banner = Some((color, format!("[{:?}] {}", task.route, msg)));
                    input.clear();
                }
            }
        }
        Err(e) => {
            *status_banner = Some((Color::Red, format!("执行错误: {}", e)));
        }
    }
}

fn render_frame(
    input: &str,
    cands: &CandidateResponse,
    selected_idx: usize,
    banner: Option<&(Color, String)>,
    approval: Option<&PendingApproval>,
) -> anyhow::Result<()> {
    let mut out = stdout();
    let (cols, rows) = terminal::size().unwrap_or((100, 30));
    queue!(out, cursor::MoveTo(0, 0), Clear(ClearType::All))?;

    // Header
    queue!(
        out,
        SetForegroundColor(Color::Cyan),
        Print("╭─ IntentOS Shell Launcher (v0.1.0-poc) "),
        SetForegroundColor(Color::DarkGrey),
        Print(format!(
            "─ 延迟 {:.2} ms ─ [Enter]执行 [Tab]L2推理 [Ctrl+Z]撤销 [Esc]退出\r\n",
            cands.elapsed_us as f64 / 1000.0
        )),
        ResetColor
    )?;

    // Input bar
    queue!(
        out,
        SetForegroundColor(Color::Green),
        Print("│ ❯ "),
        ResetColor,
        Print(input),
        SetForegroundColor(Color::DarkGrey),
        Print("█\r\n"),
        SetForegroundColor(Color::Cyan),
        Print(format!("├{}\r\n", "─".repeat(cols.saturating_sub(2) as usize))),
        ResetColor
    )?;

    if let Some(pa) = approval {
        queue!(
            out,
            SetForegroundColor(Color::Yellow),
            Print(format!("│ ⚠ 需要审批确认 [{}]\r\n", pa.capability_id)),
            ResetColor,
            Print(format!("│   摘要: {}\r\n", pa.summary)),
            Print(format!("│   预览: {}\r\n", pa.diff_preview.replace('\n', " | "))),
            Print(format!("│   摘要校验: {}\r\n", &pa.digest[..pa.digest.len().min(32)])),
            SetForegroundColor(Color::Green),
            Print("│   按 [Y] 确认执行   "),
            SetForegroundColor(Color::Red),
            Print("[N / Esc] 取消拒绝\r\n"),
            ResetColor
        )?;
    } else if cands.items.is_empty() {
        queue!(
            out,
            SetForegroundColor(Color::DarkGrey),
            Print("│   输入以检索应用（支持拼音/首字母）、文件、网站（默认 Google 搜索）、系统设置或自然语言意图…\r\n"),
            ResetColor
        )?;
    } else {
        let max_items = (rows.saturating_sub(8) as usize).clamp(3, 9);
        for (i, item) in cands.items.iter().take(max_items).enumerate() {
            let is_sel = i == selected_idx;
            if is_sel {
                queue!(
                    out,
                    SetForegroundColor(Color::Cyan),
                    Print("│ ▸ "),
                    SetForegroundColor(Color::White),
                    Print(format!("[{}] {} ", item.badge, item.title)),
                    SetForegroundColor(Color::Grey),
                    Print(format!("— {}\r\n", item.subtitle)),
                    ResetColor
                )?;
            } else {
                queue!(
                    out,
                    Print("│   "),
                    SetForegroundColor(Color::DarkCyan),
                    Print(format!("[{}] ", item.badge)),
                    ResetColor,
                    Print(format!("{} ", item.title)),
                    SetForegroundColor(Color::DarkGrey),
                    Print(format!("— {}\r\n", item.subtitle)),
                    ResetColor
                )?;
            }
        }
    }

    if let Some((color, msg)) = banner {
        queue!(
            out,
            SetForegroundColor(Color::Cyan),
            Print(format!("├{}\r\n", "─".repeat(cols.saturating_sub(2) as usize))),
            SetForegroundColor(*color),
            Print(format!("╰─ {}\r\n", msg)),
            ResetColor
        )?;
    }

    out.flush()?;
    Ok(())
}
