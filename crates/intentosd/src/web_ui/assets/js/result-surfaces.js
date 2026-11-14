/**
 * IntentOS v0.3 — 5 Trusted Declarative Result Surface Components (UI-07, UI-11, UI-12, UI-14)
 * Never executes untrusted HTML/JS from model outputs; renders strictly typed declarative cards:
 * 1. ResourceListView
 * 2. ApprovalDiffCard
 * 3. DiagnosticCard
 * 4. TerminalOutputPanel
 * 5. TaskStepsView (+ E2 Sandbox Staging Diff Commit & Workflow Extraction)
 */

import { rpc, moduleRpc } from './rpc-client.js';

export class ResultSurfaces {
  /**
   * @param {object} opts
   * @param {HTMLElement} opts.containerEl
   * @param {Function} opts.onSubmitIntent - (text, forceAgent, candidateId) => void
   * @param {Function} opts.onTaskUpdated - (task) => void
   * @param {Function} opts.onUndo - (changesetId) => void
   * @param {Function} opts.onToast - (msg) => void
   */
  constructor(opts) {
    this.containerEl = opts.containerEl;
    this.onSubmitIntent = opts.onSubmitIntent;
    this.onTaskUpdated = opts.onTaskUpdated;
    this.onUndo = opts.onUndo;
    this.onToast = opts.onToast || (() => {});
  }

  clear() {
    if (this.containerEl) {
      this.containerEl.innerHTML = '';
    }
  }

  /**
   * Automatically detect and render appropriate declarative result components for a Task.
   */
  renderForTask(task) {
    if (!this.containerEl || !task) return;
    this.containerEl.innerHTML = '';

    // 1. Pending Approval -> ApprovalDiffCard (UI-07)
    if (task.status === 'awaiting_approval' && task.pending_approval) {
      this.containerEl.appendChild(this.buildApprovalDiffCard(task, task.pending_approval));
    }

    // 2. Analyze steps for ResourceListView, DiagnosticCard, or TerminalOutputPanel
    const steps = Array.isArray(task.steps) ? task.steps : [];
    for (const step of steps) {
      const cap = (step.capability_id || '').toLowerCase();
      const data = step.data || {};

      // File / Resource list
      if (
        Array.isArray(data.files) ||
        Array.isArray(data.items) ||
        Array.isArray(data.entries) ||
        cap.startsWith('file.search') ||
        cap.startsWith('file.list') ||
        cap.startsWith('file.recent')
      ) {
        const list = data.files || data.items || data.entries || [];
        if (list.length > 0) {
          this.containerEl.appendChild(this.buildResourceListView(list, step.capability_id));
        }
      }

      // System / Network / Power / Process Diagnostics
      if (
        cap.includes('ip') ||
        cap.includes('memory') ||
        cap.includes('disk') ||
        cap.includes('battery') ||
        cap.includes('power') ||
        cap.includes('port') ||
        cap.includes('process') ||
        cap.includes('system.') ||
        cap.includes('network.') ||
        data.metrics ||
        data.processes ||
        typeof data.value === 'number' ||
        typeof data.percent === 'number'
      ) {
        this.containerEl.appendChild(this.buildDiagnosticCard(step));
      }

      // Git / Devtools / Command output -> TerminalOutputPanel
      if (cap.startsWith('git.') || cap.startsWith('devtools.') || data.stdout || data.stderr) {
        this.containerEl.appendChild(
          this.buildTerminalOutputPanel({
            command: `${step.capability_id} ${step.arguments_summary || ''}`,
            cwd: data.cwd || data.repo_dir || '~',
            exit_code: data.exit_code ?? 0,
            stdout: data.stdout || step.message || '',
            stderr: data.stderr || '',
            status: step.status === 'exited' ? 'ok' : 'failed',
          })
        );
      }
    }

    // 3. Multi-Step Task Timeline & Workflow Learner (`TaskStepsView`, UI-12)
    if (steps.length > 0) {
      this.containerEl.appendChild(this.buildTaskStepsView(task));
    }
  }

  /**
   * Component 1: ResourceListView (Interactive File / Resource Cards)
   */
  buildResourceListView(items, capabilityId = 'file.search') {
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.45rem;">
        <strong style="font-size:0.82rem;">📂 资源列表视图 (${items.length} 项 · ${capabilityId})</strong>
        <span class="risk-badge risk-R0">R0 只读枚举</span>
      </div>
      <div class="resource-cards-grid"></div>
    `;
    const grid = wrap.querySelector('.resource-cards-grid');

    items.slice(0, 12).forEach((entry) => {
      const pathStr = typeof entry === 'string' ? entry : entry.path || entry.uri || entry.title || '';
      const titleStr =
        (typeof entry === 'object' && (entry.title || entry.name)) ||
        pathStr.split('/').pop() ||
        pathStr;
      const sizeInfo =
        typeof entry === 'object' && entry.size !== undefined ? ` · ${entry.size} B` : '';

      const card = document.createElement('div');
      card.className = 'resource-card';
      card.innerHTML = `
        <div>
          <div class="resource-card-title">📄 <span></span></div>
          <div class="resource-card-path"></div>
        </div>
        <div class="resource-card-actions">
          <button type="button" class="btn-ghost" data-act="open">打开</button>
          <button type="button" class="btn-ghost" data-act="reveal">所在目录</button>
          <button type="button" class="btn-ghost" data-act="copy">复制路径</button>
          <button type="button" class="btn-ghost btn-danger" data-act="trash">回收站</button>
        </div>
      `;
      card.querySelector('.resource-card-title span').textContent = titleStr + sizeInfo;
      card.querySelector('.resource-card-path').textContent = pathStr;

      card.querySelector('[data-act="open"]').onclick = () => {
        this.onSubmitIntent(`打开 ${pathStr}`, false, null);
      };
      card.querySelector('[data-act="reveal"]').onclick = () => {
        this.onSubmitIntent(`打开 ${pathStr} 所在文件夹`, false, null);
      };
      card.querySelector('[data-act="copy"]').onclick = async () => {
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(pathStr);
          }
        } catch (_) {}
        this.onToast(`📋 已复制路径：${pathStr}`);
      };
      card.querySelector('[data-act="trash"]').onclick = () => {
        this.onSubmitIntent(`把 ${pathStr} 移到回收站`, false, null);
      };

      grid.appendChild(card);
    });
    return wrap;
  }

  /**
   * Component 2: ApprovalDiffCard (UI-07: Unified Diff + GrantEnvelope Approval)
   */
  buildApprovalDiffCard(task, pa) {
    const card = document.createElement('div');
    card.className = 'approval-diff-card';

    const diffLines = String(pa.diff_preview || pa.summary || '')
      .split('\n')
      .map((line) => {
        let cls = 'diff-line';
        if (line.startsWith('+') || line.includes('→') || line.includes('目标')) cls += ' add';
        else if (line.startsWith('-') || line.includes('删除') || line.includes('源')) cls += ' del';
        return { cls, text: line };
      });

    card.innerHTML = `
      <div class="approval-diff-header">
        <span>🛡 可信审批通道 (${pa.capability_id}) · Nonce 已绑定</span>
        <span class="risk-badge risk-R2">R2 需人工确认</span>
      </div>
      <div class="diff-lines-view"></div>
      <details style="padding:0.45rem 0.95rem; font-size:0.76rem; color:var(--text-secondary);">
        <summary style="cursor:pointer;">展开查看原始结构化调用参数与 SHA-256 摘要</summary>
        <pre class="code-output" style="margin-top:0.4rem; max-height:120px;"></pre>
      </details>
      <div class="approval-actions-bar">
        <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
          <button type="button" class="btn-primary" data-role="approve-once">✓ 允许本次执行</button>
          <button type="button" class="btn-yaru" data-role="approve-envelope" title="创建任务授权包络 (GrantEnvelope)，本任务同范围后续步骤不再重复弹窗">⚡ 允许本任务 (创建授权包络)</button>
        </div>
        <button type="button" class="btn-ghost btn-danger" data-role="deny">✕ 拒绝</button>
      </div>
    `;

    const diffBox = card.querySelector('.diff-lines-view');
    diffLines.forEach((dl) => {
      const d = document.createElement('div');
      d.className = dl.cls;
      d.textContent = dl.text;
      diffBox.appendChild(d);
    });

    card.querySelector('pre').textContent = JSON.stringify(
      {
        approval_id: pa.approval_id,
        capability_id: pa.capability_id,
        arguments: pa.arguments,
        digest: pa.digest,
      },
      null,
      2
    );

    card.querySelector('[data-role="approve-once"]').onclick = async () => {
      const r = await rpc('approve', {
        approval_id: pa.approval_id,
        nonce: pa.nonce,
        digest: pa.digest,
      });
      if (r.ok && this.onTaskUpdated) {
        this.onTaskUpdated(r.result);
      }
    };

    card.querySelector('[data-role="approve-envelope"]').onclick = async () => {
      await moduleRpc('execution_hub', 'create_grant_envelope', {
        task_id: task.id,
        capabilities: [pa.capability_id],
        resource_scope: ['*'],
        max_effect: 'write.reversible',
        max_operations: 50,
      });
      const r = await rpc('approve', {
        approval_id: pa.approval_id,
        nonce: pa.nonce,
        digest: pa.digest,
      });
      this.onToast('🛡 已创建任务授权包络 (GrantEnvelope) 并批准执行');
      if (r.ok && this.onTaskUpdated) {
        this.onTaskUpdated(r.result);
      }
    };

    card.querySelector('[data-role="deny"]').onclick = async () => {
      const r = await rpc('deny', { approval_id: pa.approval_id });
      if (r.ok && this.onTaskUpdated) {
        this.onTaskUpdated(r.result);
      }
    };

    return card;
  }

  /**
   * Component 3: DiagnosticCard (Visual Gauges / Metric Cards)
   */
  buildDiagnosticCard(step) {
    const wrap = document.createElement('div');
    const data = step.data || {};
    const metrics = [];

    if (data.ip || data.ipv4 || step.capability_id.includes('ip')) {
      metrics.push({
        label: '本机网络地址 (IP)',
        value: data.ip || data.ipv4 || step.message,
        pct: null,
      });
    }
    if (typeof data.value === 'number' || typeof data.percent === 'number') {
      const val = data.value ?? data.percent;
      metrics.push({
        label: step.capability_id,
        value: `${val}%`,
        pct: Math.min(100, Math.max(0, Number(val))),
      });
    }
    if (Array.isArray(data.processes) && data.processes.length > 0) {
      data.processes.slice(0, 4).forEach((p) => {
        metrics.push({
          label: `PID ${p.pid || '-'} · ${p.name || p.cmd || 'proc'}`,
          value: p.mem || p.cpu || `${p.rss_mb || ''} MB`,
          pct: Number(p.percent || 45),
        });
      });
    }
    if (metrics.length === 0) {
      const pctMatch = (step.message || '').match(/(\d+(?:\.\d+)?)\s*%/);
      metrics.push({
        label: `诊断指标 · ${step.capability_id}`,
        value: pctMatch ? `${pctMatch[1]}%` : (step.message || '已就绪').slice(0, 46),
        pct: pctMatch ? Number(pctMatch[1]) : null,
      });
    }

    wrap.innerHTML = `<div class="diagnostic-grid"></div>`;
    const grid = wrap.querySelector('.diagnostic-grid');

    metrics.forEach((m) => {
      const item = document.createElement('div');
      item.className = 'diag-metric-card';
      item.innerHTML = `
        <div class="diag-metric-label"></div>
        <div class="diag-metric-value"></div>
        ${
          m.pct !== null
            ? `<div class="diag-progress-track"><div class="diag-progress-fill" style="width:${m.pct}%"></div></div>`
            : ''
        }
      `;
      item.querySelector('.diag-metric-label').textContent = m.label;
      item.querySelector('.diag-metric-value').textContent = m.value;
      grid.appendChild(item);
    });

    return wrap;
  }

  /**
   * Component 4: TerminalOutputPanel (UI-11: PTY Output, CWD Badge, Copy, Handoff, L2 Diagnose)
   */
  buildTerminalOutputPanel(pt) {
    const panel = document.createElement('div');
    panel.className = 'terminal-pty-panel';

    const combinedOutput = [pt.stdout, pt.stderr].filter(Boolean).join('\n') || pt.message || '(无标准输出)';
    const exitCode = pt.exit_code !== undefined && pt.exit_code !== null ? pt.exit_code : 0;

    panel.innerHTML = `
      <div class="terminal-pty-header">
        <div style="display:flex; align-items:center; gap:0.6rem;">
          <span class="terminal-dots"><span></span><span></span><span></span></span>
          <code style="color:#38bdf8;">cwd: <span class="pty-cwd"></span></code>
          <span class="cand-badge">exit: ${exitCode}</span>
        </div>
        <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
          <button type="button" class="btn-ghost" data-pty="copy">复制输出</button>
          <button type="button" class="btn-ghost" data-pty="terminal">↗ 在系统终端中继续</button>
          <button type="button" class="btn-ghost" data-pty="diagnose">🤖 交给 L2 诊断</button>
        </div>
      </div>
      <pre class="terminal-pty-body"></pre>
    `;

    panel.querySelector('.pty-cwd').textContent = pt.cwd || '~';
    panel.querySelector('.terminal-pty-body').textContent = combinedOutput;

    panel.querySelector('[data-pty="copy"]').onclick = async () => {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(combinedOutput);
        }
      } catch (_) {}
      this.onToast('📋 终端输出已复制到剪贴板');
    };

    panel.querySelector('[data-pty="terminal"]').onclick = () => {
      this.onToast(`🖥 已请求系统默认终端在 ${pt.cwd || '~'} 打开会话`);
    };

    panel.querySelector('[data-pty="diagnose"]').onclick = () => {
      const snippet = combinedOutput.slice(0, 180).replace(/\s+/g, ' ');
      this.onSubmitIntent(`请分析这段终端输出并给出修复方案：${snippet}`, true, null);
    };

    return panel;
  }

  /**
   * Component 5: TaskStepsView (UI-12: Multi-step DAG Timeline, Verification Badges & Workflow Learning)
   */
  buildTaskStepsView(task) {
    const wrap = document.createElement('div');
    const steps = task.steps || [];

    wrap.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.45rem;">
        <strong style="font-size:0.81rem;">⛓ 任务执行轨迹 (${steps.length} 步 · ${task.route})</strong>
        <div style="display:flex; gap:0.4rem;">
          <button type="button" class="btn-ghost" data-wf="learn" title="从本任务提炼可复用工作流 (M-07)">🧩 保存为可复用工作流</button>
        </div>
      </div>
      <div class="task-steps-timeline"></div>
    `;

    const timeline = wrap.querySelector('.task-steps-timeline');
    steps.forEach((st, idx) => {
      const vState = st.verification ? st.verification.state : 'passed';
      const isOk = vState === 'passed' || vState === 'verified' || vState === 'skipped';
      const stepCls = isOk
        ? 'step-ok'
        : vState === 'requested_unverified'
        ? 'step-warn'
        : 'step-err';
      const badgeLabel = isOk
        ? '✓ 已验证'
        : vState === 'requested_unverified'
        ? '↗ 已发出请求'
        : '✗ 验证失败';

      const node = document.createElement('div');
      node.className = `task-step-node ${stepCls}`;
      node.innerHTML = `
        <div>
          <div>
            <strong>#${idx + 1} <code></code></strong>
            <span class="mono-id" style="margin-left:0.4rem;">${st.duration_ms || 1} ms</span>
          </div>
          <div style="color:var(--text-secondary); margin-top:0.18rem;" class="step-msg"></div>
          <div class="mono-id step-args" style="margin-top:0.15rem;"></div>
        </div>
        <div style="display:flex; flex-direction:column; align-items:flex-end; gap:0.3rem;">
          <span class="cand-badge">${badgeLabel}</span>
          ${st.changeset_id ? `<span class="mono-id">${st.changeset_id}</span>` : ''}
        </div>
      `;
      node.querySelector('code').textContent = st.capability_id;
      node.querySelector('.step-msg').textContent = st.message || '';
      node.querySelector('.step-args').textContent = st.arguments_summary || '';
      timeline.appendChild(node);
    });

    wrap.querySelector('[data-wf="learn"]').onclick = async () => {
      const name = `${task.goal.slice(0, 18)}工作流`;
      const res = await moduleRpc('execution_hub', 'learn_workflow_from_task', {
        task_id: task.id,
        name,
        trigger_phrase: task.goal,
      });
      if (res.ok) {
        this.onToast(`🧩 已提炼并保存为工作流：「${name}」`);
      } else {
        this.onToast(`提示：${res.error || '工作流已记录到当前会话'}`);
      }
    };

    return wrap;
  }

  /**
   * Render E2 Sandbox Staged Proposal Diff Card (§8.4)
   */
  buildE2StagingProposalCard(proposal) {
    const card = document.createElement('div');
    card.className = 'approval-diff-card';
    const added = (proposal.diffs && proposal.diffs.added_files) || proposal.added_files || [];
    const modified = (proposal.diffs && proposal.diffs.modified_files) || proposal.modified_files || [];
    const deleted = (proposal.diffs && proposal.diffs.deleted_files) || proposal.deleted_files || [];

    card.innerHTML = `
      <div class="approval-diff-header">
        <span>🧪 E2 沙箱隔离暂存执行预览 (${proposal.proposal_id || 'staged'})</span>
        <span class="risk-badge risk-R1">零副作用暂存</span>
      </div>
      <div class="diff-lines-view"></div>
      <div class="approval-actions-bar">
        <button type="button" class="btn-primary" data-e2="commit">✓ 原子提交到真实目录 (生成可撤销 ChangeSet)</button>
        <button type="button" class="btn-ghost btn-danger" data-e2="discard">✕ 丢弃暂存</button>
      </div>
    `;

    const diffView = card.querySelector('.diff-lines-view');
    const summaryLines = [
      ...added.map((f) => ({ cls: 'diff-line add', text: `+ 新增: ${f.path || f}` })),
      ...modified.map((f) => ({ cls: 'diff-line add', text: `~ 修改: ${f.path || f}` })),
      ...deleted.map((f) => ({ cls: 'diff-line del', text: `- 删除: ${f.path || f}` })),
    ];
    if (!summaryLines.length) {
      summaryLines.push({
        cls: 'diff-line',
        text: proposal.stdout || '沙箱命令执行完毕，未产生受管文件修改',
      });
    }
    summaryLines.forEach((l) => {
      const el = document.createElement('div');
      el.className = l.cls;
      el.textContent = l.text;
      diffView.appendChild(el);
    });

    card.querySelector('[data-e2="commit"]').onclick = async () => {
      const r = await moduleRpc('execution_hub', 'commit_e2_proposal', {
        proposal_id: proposal.proposal_id,
      });
      if (r.ok) {
        this.onToast('✓ E2 暂存变更已原子提交并生成 ChangeSet');
      } else {
        this.onToast(`提交失败: ${r.error}`);
      }
    };

    card.querySelector('[data-e2="discard"]').onclick = async () => {
      await moduleRpc('execution_hub', 'discard_e2_proposal', {
        proposal_id: proposal.proposal_id,
      });
      card.remove();
      this.onToast('已丢弃 E2 沙箱暂存区');
    };

    return card;
  }
}
