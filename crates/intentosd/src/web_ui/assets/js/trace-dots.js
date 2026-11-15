/**
 * IntentOS Wave 4 — 20px Horizontal Colored `Trace Dots` Bar (`●`), Compact `+N` Folding,
 * Honest Verification Badges (`Passed` Emerald `#10b981` vs `RequestedUnverified` Sky-Blue `#38bdf8`)
 * & Auto-Expanded Sensitive Path / Action Inline Approval Card
 *
 * Dot Palette & Semantics:
 * - Gray     `●` (`thinking`)        : Reasoning chain / <think> block (expand/collapse)
 * - Purple   `●` (`memory`)          : Recalled semantic file index / chapter outline / software profile
 * - Cyan     `●` (`adapter`)         : Software Translation Layer (`SNI dbusmenu / MPRIS2 / D-Bus / URI / Headless / Process`)
 * - Amber    `●` (`approval`)        : Auto-expanded inline approval card (`✓ 批准本次` / `⏱ 本会话放行此范围` (本会话放行该范围) / `✕ 拒绝`)
 * - Sky-Blue `●` (`tool_unverified`) : Unverified / simulated desktop request (`已发送请求（待桌面响应）`, `#38bdf8`)
 * - Emerald  `●` (`tool_ok`)         : Strictly verified (`Passed`) tool execution params, duration, and inline `[↶ 撤销]` (`#10b981`)
 * - Red      `●` (`tool_err`)        : Denied / failed tool or policy error details (`#ef4444`)
 */

import { escapeHtml } from './markdown-renderer.js';

export const TRACE_DOT_META = {
  thinking: {
    colorClass: 'dot-gray',
    badgeLabel: '思考链路',
    defaultTitle: '深度思考链路',
  },
  memory: {
    colorClass: 'dot-purple',
    badgeLabel: '记忆召回',
    defaultTitle: '个人记忆、章节大纲与软件画像召回',
  },
  adapter: {
    colorClass: 'dot-cyan',
    badgeLabel: '软件转译',
    defaultTitle: '桌面软件指令接口转译层',
  },
  approval: {
    colorClass: 'dot-amber',
    badgeLabel: '安全审批',
    defaultTitle: '敏感路径与受控动作审批',
  },
  task_partial: {
    colorClass: 'dot-amber',
    badgeLabel: '部分完成',
    defaultTitle: '部分完成 · 已达预算保护上限',
  },
  tool_unverified: {
    colorClass: 'dot-blue',
    badgeLabel: '已发送请求（待桌面响应）',
    defaultTitle: '已发送请求（待桌面响应）',
  },
  tool_ok: {
    colorClass: 'dot-emerald',
    badgeLabel: '已验证能力',
    defaultTitle: '系统能力已验证执行',
  },
  tool_err: {
    colorClass: 'dot-red',
    badgeLabel: '执行异常',
    defaultTitle: '能力拒绝或执行错误',
  },
};

export function isUnverifiedExecution(item = {}) {
  if (!item || typeof item !== 'object') return false;
  if (item.simulated === true || (item.data && item.data.simulated === true)) {
    return true;
  }
  const rawKind = String(item.kind || '').toLowerCase();
  const rawColor = String(item.color || '').toLowerCase();
  if (
    rawKind === 'tool_unverified' ||
    rawKind === 'requested_unverified' ||
    rawKind === 'requestedunverified' ||
    rawKind === 'unverified' ||
    rawColor === 'blue' ||
    rawColor === 'sky'
  ) {
    return true;
  }

  const ver = item.verification;
  if (ver && typeof ver === 'object') {
    const vState = String(ver.state || ver.status || '').toLowerCase();
    const vSummary = String(ver.summary || ver.detail || '');
    if (
      vState === 'requestedunverified' ||
      vState === 'requested_unverified' ||
      vState === 'unverified' ||
      vState === 'skipped' ||
      vSummary.includes('未验证') ||
      vSummary.includes('RequestedUnverified') ||
      vSummary.includes('待桌面响应')
    ) {
      return true;
    }
  } else if (typeof ver === 'string' && ver.trim()) {
    const vLow = ver.trim().toLowerCase();
    if (
      vLow.includes('requestedunverified') ||
      vLow.includes('requested_unverified') ||
      vLow === 'unverified' ||
      vLow === 'skipped' ||
      ver.includes('未验证') ||
      ver.includes('待桌面响应')
    ) {
      return true;
    }
  }

  const detailBlob = [
    typeof item.detail === 'string' ? item.detail : '',
    typeof item.summary === 'string' ? item.summary : '',
    typeof item.message === 'string' ? item.message : '',
    typeof item.title === 'string' ? item.title : '',
  ].join(' ');

  if (
    detailBlob.includes('RequestedUnverified') ||
    detailBlob.includes('requested_unverified') ||
    detailBlob.includes('未验证') ||
    detailBlob.includes('待桌面响应') ||
    detailBlob.includes('无头/仿真环境预演') ||
    detailBlob.includes('"simulated":true') ||
    detailBlob.includes('"simulated": true')
  ) {
    return true;
  }
  return false;
}

function mapRawKind(rawKind, rawColor, rawDot = null) {
  const k = String(rawKind || '').toLowerCase();
  const c = String(rawColor || '').toLowerCase();
  if (k.includes('think') || c === 'gray') return 'thinking';
  if (k.includes('mem') || c === 'purple') return 'memory';
  if (k === 'task_partial' || k === 'partially_completed') return 'task_partial';
  if (
    k.includes('approv') ||
    k.includes('confirm') ||
    c === 'amber' ||
    c === 'yellow' ||
    c === 'orange'
  ) {
    return 'approval';
  }
  if (k.includes('err') || k.includes('fail') || k.includes('deny') || c === 'red') {
    return 'tool_err';
  }
  if (rawDot && isUnverifiedExecution(rawDot)) {
    return 'tool_unverified';
  }
  if (
    k === 'tool_unverified' ||
    k.includes('unverified') ||
    c === 'blue' ||
    c === 'sky'
  ) {
    return 'tool_unverified';
  }
  if (
    k.includes('adapt') ||
    k.includes('mpris') ||
    k.includes('dbus') ||
    k.includes('tray') ||
    c === 'cyan'
  ) {
    return 'adapter';
  }
  if (TRACE_DOT_META[k]) return k;
  return 'tool_ok';
}

function formatChannelLabel(ch) {
  const raw = String(ch || '').toLowerCase();
  if (raw.includes('tray') || raw.includes('sni') || raw.includes('dbusmenu')) {
    return '托盘菜单 (SNI / dbusmenu)';
  }
  if (raw.includes('mpris')) return 'MPRIS2 媒体总线';
  if (raw.includes('dbus') || raw.includes('freedesktop')) return 'Session D-Bus';
  if (raw.includes('uri')) return 'URI Deep-Link';
  if (raw.includes('desktop')) return 'Desktop Action';
  if (raw.includes('headless')) return 'Headless 静默转换';
  if (raw.includes('gui') || raw.includes('atspi')) return 'AT-SPI2 / GUI 窗口转译';
  if (raw.includes('proc') || raw.includes('kill') || raw.includes('quit')) return '进程生命周期校验';
  if (raw.includes('cli')) return 'CLI 封装通道';
  return ch || '自动转译通道';
}

function formatVerificationText(v, unverified = false) {
  if (unverified) return '已发送请求（待桌面响应）';
  if (!v) return '';
  if (typeof v === 'string') {
    if (
      v.toLowerCase().includes('requestedunverified') ||
      v.toLowerCase().includes('unverified') ||
      v.includes('未验证')
    ) {
      return '已发送请求（待桌面响应）';
    }
    return v;
  }
  if (typeof v === 'object') {
    const raw = String(v.state || v.status || v.summary || 'Passed');
    if (
      raw.toLowerCase().includes('requestedunverified') ||
      raw.toLowerCase().includes('unverified') ||
      raw.includes('未验证')
    ) {
      return '已发送请求（待桌面响应）';
    }
    return raw;
  }
  return String(v);
}

/**
 * Extract the best session grant scope (`directory` parent if path arg exists, else `app` or `capability`)
 * and structured target metadata from a `PendingApproval` payload.
 * @param {object} pa
 * @returns {{ scopeKind: string, scopeValue: string, targetPath: string, targetApp: string, pidsText: string, riskCode: string, riskLabel: string, reversible: boolean }}
 */
export function extractApprovalMetadata(pa = {}) {
  const args = (pa && (pa.arguments || pa.params)) || {};
  const pathKeys = ['path', 'source', 'target', 'directory', 'destination', 'output', 'archive'];
  let foundKey = '';
  let foundPath = '';

  for (const k of pathKeys) {
    const val = args[k];
    if (typeof val === 'string' && val.trim()) {
      foundKey = k;
      foundPath = val.trim();
      break;
    }
    if (Array.isArray(val) && typeof val[0] === 'string' && val[0].trim()) {
      foundKey = k;
      foundPath = val[0].trim();
      break;
    }
  }

  if (!foundPath && typeof pa.scope === 'string' && (pa.scope.startsWith('/') || pa.scope.startsWith('~/'))) {
    foundPath = pa.scope.trim();
  }

  const targetApp = String(
    args.app || args.app_hint || args.app_name || pa.app_name || pa.app_hint || ''
  ).trim();

  const rawPids = pa.alive_pids || args.pids || args.alive_pids || [];
  const pidsText = Array.isArray(rawPids) && rawPids.length > 0 ? rawPids.join(', ') : '';

  let scopeKind = 'capability';
  let scopeValue = String(pa.capability_id || pa.scope || '*');

  if (foundPath) {
    scopeKind = 'directory';
    const cleaned = foundPath.replace(/\/+$/, '');
    if (foundKey === 'directory' || foundPath.endsWith('/')) {
      scopeValue = cleaned || '/';
    } else {
      const idx = cleaned.lastIndexOf('/');
      scopeValue = idx > 0 ? cleaned.slice(0, idx) : idx === 0 ? '/' : cleaned;
    }
  } else if (targetApp) {
    scopeKind = 'app';
    scopeValue = targetApp;
  }

  const diffStr = String(pa.diff_preview || pa.summary || '');
  const capId = String(pa.capability_id || '');
  let riskCode = 'R2';
  let riskLabel = '⚠️ R2 · 敏感路径或受控操作';

  if (
    String(pa.risk || '').toUpperCase() === 'R3' ||
    diffStr.includes('R3') ||
    diffStr.includes('高危') ||
    diffStr.includes('不可逆') ||
    diffStr.includes('强制结束')
  ) {
    riskCode = 'R3';
    riskLabel = '🚨 R3 · 高危/强制进程控制';
  } else if (
    String(pa.risk || '').toUpperCase() === 'R1' ||
    (diffStr.includes('R1') && !diffStr.includes('敏感'))
  ) {
    riskCode = 'R1';
    riskLabel = '🛡️ R1 · 可逆受控变更';
  }

  const isWriteCap =
    capId.startsWith('file.move') ||
    capId.startsWith('file.copy') ||
    capId.startsWith('file.rename') ||
    capId.startsWith('file.trash') ||
    capId.startsWith('file.write') ||
    capId.startsWith('archive.extract') ||
    diffStr.includes('可逆') ||
    diffStr.includes('ChangeSet') ||
    diffStr.includes('撤销');
  const reversible = pa.reversible !== undefined ? Boolean(pa.reversible) : isWriteCap;

  return {
    scopeKind,
    scopeValue,
    targetPath: foundPath,
    targetApp,
    pidsText,
    riskCode,
    riskLabel,
    reversible,
  };
}

/**
 * Normalize raw turn data (from `backend_bridge::send_quick_chat_turn` or `submit_intent` fallback)
 * into a clean ordered array of Trace Dot descriptors.
 * @param {object} turn
 * @returns {Array<object>}
 */
export function normalizeTraceDots(turn = {}) {
  const dots = [];
  const rawDots = Array.isArray(turn.trace_dots) ? turn.trace_dots : [];
  const effectivePending =
    turn.pending_approval || (turn.task && turn.task.pending_approval) || null;
  const effectiveTaskId = turn.task_id || (turn.task && turn.task.id) || null;

  // 1. Ensure `thinking` dot appears first if `turn.thinking` is non-empty and not already in `rawDots`
  const hasThinkingDot = rawDots.some((d) => mapRawKind(d.kind, d.color) === 'thinking');
  if (turn.thinking && String(turn.thinking).trim() && !hasThinkingDot) {
    dots.push({
      kind: 'thinking',
      title: '深度思考推理链',
      detail: String(turn.thinking).trim(),
    });
  }

  // 2. Ensure `memory` dot ONLY if non-empty `memory_hits` provided separately
  const hasMemoryDot = rawDots.some((d) => mapRawKind(d.kind, d.color) === 'memory');
  if (Array.isArray(turn.memory_hits) && turn.memory_hits.length > 0 && !hasMemoryDot) {
    dots.push({
      kind: 'memory',
      title: `记忆召回 (${turn.memory_hits.length} 项)`,
      items: turn.memory_hits,
      detail: turn.memory_context || '',
    });
  }

  // 3. Ensure `adapter` / `approval` / `tool_unverified` dots if `adapter_actions` provided separately
  const hasAdapterDot = rawDots.some((d) => {
    const mk = mapRawKind(d.kind, d.color, d);
    return mk === 'adapter' || mk === 'tool_unverified';
  });
  if (Array.isArray(turn.adapter_actions) && turn.adapter_actions.length > 0 && !hasAdapterDot) {
    turn.adapter_actions.forEach((act) => {
      if (act && act.requires_approval) {
        dots.push({
          kind: 'approval',
          title: `待确认权限: ${act.app_name || act.app_id || '受控应用操作'}`,
          detail: act.summary || '该桌面软件操作需要人工确认授权。',
          pending_approval: act,
          task_id: effectiveTaskId,
        });
      } else if (act && isUnverifiedExecution(act)) {
        dots.push({
          kind: 'tool_unverified',
          title: `已发送请求（待桌面响应） · ${act.app_name || act.app_id || '桌面软件'}`,
          channel: act.channel_used || act.channel || 'gui_atspi',
          app_id: act.app_id || act.app_name || '',
          detail: act.summary || act.detail || JSON.stringify(act),
          verification: 'RequestedUnverified',
          simulated: Boolean(act.simulated),
          changeset_id: act.changeset_id || null,
        });
      } else {
        dots.push({
          kind: 'adapter',
          title: `转译层 · ${act.app_name || act.app_id || '桌面软件'}`,
          channel: act.channel_used || act.channel || 'dbus_mpris',
          app_id: act.app_id || act.app_name || '',
          detail: act.summary || act.detail || JSON.stringify(act),
          verification: act.verification || 'Passed',
          changeset_id: act.changeset_id || null,
        });
      }
    });
  }

  // 4. Add normalized `rawDots` (enriching any `approval` dot with `effectivePending` so nonce/digest are never lost!)
  rawDots.forEach((d) => {
    const kind = mapRawKind(d.kind, d.color, d);
    const enriched = {
      ...d,
      kind,
      title:
        kind === 'tool_unverified' && (!d.title || String(d.title).includes('已验证'))
          ? TRACE_DOT_META.tool_unverified.defaultTitle
          : d.title || TRACE_DOT_META[kind].defaultTitle,
      detail: d.detail || d.summary || d.message || '',
    };
    if (kind === 'approval') {
      enriched.pending_approval = d.pending_approval || effectivePending || d;
      enriched.task_id =
        d.task_id || (effectivePending && effectivePending.task_id) || effectiveTaskId;
    }
    dots.push(enriched);
  });

  // 5. Ensure `approval` dot if `effectivePending` exists and no approval dot is present yet
  const hasApprovalDot = dots.some((d) => d.kind === 'approval');
  if (effectivePending && !hasApprovalDot) {
    dots.push({
      kind: 'approval',
      title: `待确认权限: ${effectivePending.capability_id || effectivePending.scope || '受控操作'}`,
      detail:
        effectivePending.summary ||
        effectivePending.diff_preview ||
        '该操作涉及敏感路径或受保护范围，请确认授权级别。',
      pending_approval: effectivePending,
      task_id: effectivePending.task_id || effectiveTaskId,
    });
  }

  // 6. Honest `task_status` badges (`partially_completed` / `recovery_required`) (`H07` / `H10`)
  const taskStatus = String(
    turn.task_status || (turn.task && turn.task.status) || ''
  ).toLowerCase();
  const completedSteps = Array.isArray(turn.completed_steps) ? turn.completed_steps : [];
  const unresolvedGoals = Array.isArray(turn.unresolved_goals) ? turn.unresolved_goals : [];
  const statusDetailParts = [];
  if (completedSteps.length > 0) {
    statusDetailParts.push(`已完成步骤:\n- ${completedSteps.join('\n- ')}`);
  }
  if (unresolvedGoals.length > 0) {
    statusDetailParts.push(`未完成目标:\n- ${unresolvedGoals.join('\n- ')}`);
  }

  if (
    (taskStatus === 'recovery_required' || turn.recovery_required === true) &&
    !dots.some((d) => String(d.title || '').includes('recovery_required'))
  ) {
    dots.push({
      kind: 'tool_err',
      title: '需人工恢复核验 (recovery_required)',
      detail:
        statusDetailParts.join('\n\n') ||
        '智能体执行期间检测到未确认副作用，已阻止自动回退重放以确保安全。',
    });
  } else if (
    taskStatus === 'partially_completed' &&
    !dots.some((d) => d.kind === 'task_partial')
  ) {
    dots.push({
      kind: 'task_partial',
      title: '部分完成 · 已达预算保护上限',
      detail:
        statusDetailParts.join('\n\n') ||
        '当前回合触发预算上限保护，已完成部分步骤并安全收束。',
    });
  }

  return dots;
}

/**
 * Convert an IntentOS `submit_intent` Task (plus optional memory & adapter hits) into Trace Dots.
 * @param {object} task
 * @param {object} [extras]
 * @returns {Array<object>}
 */
export function buildTraceDotsFromTask(task, extras = {}) {
  const dots = [];

  if (extras.thinking) {
    dots.push({
      kind: 'thinking',
      title: '意图解析与规划链路',
      detail: extras.thinking,
    });
  } else if (task && task.route) {
    dots.push({
      kind: 'thinking',
      title: `路由决策: ${task.route}`,
      detail: `目标意图: ${task.goal || ''}\n路由层级: ${task.route}\n任务状态: ${task.status || 'completed'}`,
    });
  }

  if (Array.isArray(extras.memoryHits) && extras.memoryHits.length > 0) {
    dots.push({
      kind: 'memory',
      title: `记忆召回 (${extras.memoryHits.length} 项)`,
      items: extras.memoryHits,
      detail: extras.memoryContext || '',
    });
  }

  if (Array.isArray(extras.adapterActions) && extras.adapterActions.length > 0) {
    extras.adapterActions.forEach((ad) => {
      if (ad && ad.requires_approval) {
        dots.push({
          kind: 'approval',
          title: `待授权: ${ad.app_name || ad.app_id || '受控进程操作'}`,
          detail: ad.summary || '',
          pending_approval: ad,
          task_id: (task && task.id) || null,
        });
      } else if (ad && isUnverifiedExecution(ad)) {
        dots.push({
          kind: 'tool_unverified',
          title: `已发送请求（待桌面响应）: ${ad.app_name || ad.app_id || '应用请求'}`,
          channel: ad.channel_used || ad.channel || 'gui_atspi',
          detail: ad.summary || ad.detail || '',
          verification: 'RequestedUnverified',
          simulated: Boolean(ad.simulated),
          changeset_id: ad.changeset_id || null,
        });
      } else {
        dots.push({
          kind: 'adapter',
          title: `转译层: ${ad.app_name || ad.app_id || '应用控制'}`,
          channel: ad.channel_used || ad.channel || 'dbus_mpris',
          detail: ad.summary || ad.detail || '',
          verification: ad.verification || 'Passed',
          changeset_id: ad.changeset_id || null,
        });
      }
    });
  }

  const steps = task && Array.isArray(task.steps) ? task.steps : [];
  const csIds = task && Array.isArray(task.changeset_ids) ? task.changeset_ids : [];

  steps.forEach((st, idx) => {
    const capId = String(st.capability_id || 'capability');
    const isAdapterStep =
      capId.startsWith('app_adapter') ||
      capId.startsWith('adapter.') ||
      capId.startsWith('media.') ||
      capId.includes('mpris');
    const isMemoryStep = capId.startsWith('memory_') || capId.startsWith('memory.');
    const failed = st.status === 'failed' || st.status === 'denied' || st.error;
    const stepUnverified = isUnverifiedExecution(st);

    if (failed) {
      dots.push({
        kind: 'tool_err',
        title: `${capId} 失败`,
        capability_id: capId,
        params: st.arguments || st.arguments_summary || null,
        detail: st.error || st.message || '执行未通过策略或运行时检查',
      });
      return;
    }

    if (isMemoryStep) {
      dots.push({
        kind: 'memory',
        title: `记忆/大纲检索: ${capId}`,
        detail: st.message || JSON.stringify(st.data || {}, null, 2),
      });
      return;
    }

    if (stepUnverified) {
      dots.push({
        kind: 'tool_unverified',
        title: `${capId} · 已发送请求（待桌面响应）`,
        capability_id: capId,
        channel: (st.data && st.data.channel_used) || null,
        params: st.arguments || st.arguments_summary || st.data || null,
        duration_ms: st.duration_ms ?? st.elapsed_ms ?? null,
        verification: 'RequestedUnverified',
        simulated: Boolean(st.simulated || (st.data && st.data.simulated)),
        detail: st.message || '已发送请求（待桌面响应）',
        changeset_id:
          st.changeset_id ||
          (idx === steps.length - 1 && csIds.length ? csIds[csIds.length - 1] : null),
      });
      return;
    }

    if (isAdapterStep) {
      dots.push({
        kind: 'adapter',
        title: `软件转译: ${capId}`,
        channel:
          (st.data && st.data.channel_used) ||
          (capId.includes('media') ? 'MPRIS2 / D-Bus' : '软件转译层'),
        capability_id: capId,
        params: st.arguments || st.arguments_summary || null,
        duration_ms: st.duration_ms || null,
        verification: (st.verification && st.verification.state) || 'Passed',
        detail: st.message || '',
        changeset_id: st.changeset_id || csIds[idx] || null,
      });
      return;
    }

    dots.push({
      kind: 'tool_ok',
      title: capId,
      capability_id: capId,
      params: st.arguments || st.arguments_summary || st.data || null,
      duration_ms: st.duration_ms ?? st.elapsed_ms ?? null,
      verification: (st.verification && st.verification.state) || 'Passed',
      detail: st.message || '系统能力已验证执行完成',
      changeset_id:
        st.changeset_id ||
        (idx === steps.length - 1 && csIds.length ? csIds[csIds.length - 1] : null),
    });
  });

  if (task && task.pending_approval) {
    dots.push({
      kind: 'approval',
      title: `待授权: ${task.pending_approval.capability_id || '受保护操作'}`,
      detail: task.pending_approval.summary || task.pending_approval.diff_preview || '',
      pending_approval: task.pending_approval,
      task_id: task.id || null,
    });
  } else if (task && task.status === 'failed' && steps.length === 0) {
    dots.push({
      kind: 'tool_err',
      title: '执行受阻',
      detail: task.assistant_message || task.error || '操作被策略拦截或执行失败',
    });
  }

  return dots;
}

/**
 * Render the 20px Horizontal Colored `Trace Dots` Bar (with `+N` compact folding for `> 6` dots)
 * + auto-expanded inline approval card / detail drawer at the top of an Assistant bubble.
 *
 * @param {object} opts
 * @param {Array<object>} opts.dots
 * @param {string} [opts.modelLabel]
 * @param {boolean} [opts.isStreaming]
 * @param {Function} [opts.onRegenerate]
 * @param {Function} [opts.onUndo] - (changesetId) => Promise<boolean>
 * @param {Function} [opts.onApproveDecision] - (decision: 'once'|'scope'|'deny', dot, idx) => Promise<void>
 * @param {Function} [opts.onInsertMention] - (shortName, fullVal) => void
 * @returns {{ barWrapEl: HTMLElement, drawerEl: HTMLElement }}
 */
export function renderTraceDotsHeader(opts) {
  const dots = Array.isArray(opts.dots) ? opts.dots : [];
  const barWrapEl = document.createElement('div');
  barWrapEl.className = 'qc-assistant-topbar';

  const dotsTrack = document.createElement('div');
  dotsTrack.className = 'qc-trace-dots-bar';
  dotsTrack.setAttribute('role', 'toolbar');
  dotsTrack.setAttribute('aria-label', 'AIOS 执行轨迹圆点栏');

  const rightActions = document.createElement('div');
  rightActions.className = 'qc-bubble-meta-actions';

  if (opts.modelLabel) {
    const modelSpan = document.createElement('span');
    modelSpan.className = 'qc-bubble-model-tag';
    modelSpan.textContent = opts.modelLabel;
    rightActions.appendChild(modelSpan);
  }

  if (typeof opts.onRegenerate === 'function') {
    const regenBtn = document.createElement('button');
    regenBtn.type = 'button';
    regenBtn.className = 'qc-regen-btn';
    regenBtn.title = '重新生成回复';
    regenBtn.setAttribute('aria-label', '重新生成回复');
    regenBtn.textContent = '↻';
    regenBtn.onclick = () => opts.onRegenerate();
    rightActions.appendChild(regenBtn);
  }

  const drawerEl = document.createElement('div');
  drawerEl.className = 'qc-trace-drawer';
  drawerEl.hidden = true;

  let activeIdx = -1;
  let expandedAllDots = false;

  const syncActiveDotButton = () => {
    dotsTrack.querySelectorAll('.qc-trace-dot-btn').forEach((btn) => {
      const bIdx = Number(btn.getAttribute('data-dot-idx'));
      btn.classList.toggle('active', bIdx === activeIdx && !drawerEl.hidden);
    });
  };

  const renderDrawerContent = (dot, idx) => {
    const meta = TRACE_DOT_META[dot.kind] || TRACE_DOT_META.tool_ok;
    drawerEl.innerHTML = '';
    drawerEl.className = `qc-trace-drawer kind-${dot.kind}${dot.resolved_status ? ' is-resolved' : ''}`;

    const head = document.createElement('div');
    head.className = 'qc-trace-drawer-head';
    const resolvedTitle =
      dot.resolved_mode === 'deny'
        ? '🛡️ 已拒绝执行该敏感操作'
        : dot.resolved_mode === 'session' || dot.resolved_mode === 'scope'
        ? '🛡️ 已放行本会话范围 · 已继续会话'
        : '🛡️ 敏感权限已批准 · 已继续会话';
    const headTitle =
      dot.kind === 'approval'
        ? dot.resolved_status
          ? resolvedTitle
          : `🛡️ 敏感权限与安全执行审批 · ${dot.title || meta.defaultTitle}`
        : `${meta.badgeLabel} · ${dot.title || meta.defaultTitle}`;

    head.innerHTML = `
      <span class="qc-trace-drawer-badge">
        <span class="qc-trace-dot-inline ${dot.resolved_status ? (dot.resolved_mode === 'deny' ? 'dot-red' : 'dot-green') : meta.colorClass}">●</span>
        <strong>${escapeHtml(headTitle)}</strong>
      </span>
    `;

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'qc-trace-close';
    closeBtn.textContent = '收起 ✕';
    closeBtn.onclick = () => {
      activeIdx = -1;
      drawerEl.hidden = true;
      syncActiveDotButton();
    };
    head.appendChild(closeBtn);
    drawerEl.appendChild(head);

    const body = document.createElement('div');
    body.className = 'qc-trace-drawer-body';

    // 1. Gray `thinking` chain
    if (dot.kind === 'thinking') {
      const pre = document.createElement('div');
      pre.className = 'qc-thinking-box';
      pre.textContent = dot.detail || '已完成上下文推理与路由规划。';
      body.appendChild(pre);
    }
    // 2. Purple `memory` recall items (including document outlines)
    else if (dot.kind === 'memory') {
      const items = Array.isArray(dot.items)
        ? dot.items
        : Array.isArray(dot.hits)
        ? dot.hits
        : [];
      if (items.length > 0) {
        const list = document.createElement('div');
        list.className = 'qc-trace-chips-list';
        items.forEach((it) => {
          const label =
            it.doc_title ||
            it.display_name ||
            it.title ||
            it.name ||
            it.canonical_value ||
            it.value ||
            it.path ||
            String(it);
          const sub =
            (it.matched_section && it.matched_section.heading) ||
            it.toc_preview ||
            it.entity_kind ||
            it.category ||
            it.kind ||
            (it.open_count ? `${it.open_count}次` : '');
          const chip = document.createElement('button');
          chip.type = 'button';
          chip.className = 'qc-trace-mem-chip';
          chip.title = it.canonical_value || it.value || it.path || label;
          chip.innerHTML = `<span>${escapeHtml(label)}</span>${
            sub ? `<small>${escapeHtml(String(sub).slice(0, 32))}</small>` : ''
          }`;
          chip.onclick = () => {
            if (opts.onInsertMention) {
              const targetPath = it.canonical_value || it.value || it.path || label;
              const shortName = String(targetPath).split('/').pop() || label;
              opts.onInsertMention(shortName, targetPath);
            }
          };
          list.appendChild(chip);
        });
        body.appendChild(list);
      }
      if (dot.detail) {
        const note = document.createElement('div');
        note.className = 'qc-trace-detail-text';
        note.textContent = dot.detail;
        body.appendChild(note);
      }
    }
    // 3. Cyan `adapter` Software Translation Layer details
    else if (dot.kind === 'adapter') {
      const chBadge = formatChannelLabel(dot.channel || dot.channel_used);
      const unv = isUnverifiedExecution(dot);
      const verText = formatVerificationText(dot.verification, unv);
      const infoRow = document.createElement('div');
      infoRow.className = 'qc-adapter-meta-row';
      infoRow.innerHTML = `
        <span class="qc-channel-pill">通道: ${escapeHtml(chBadge)}</span>
        ${dot.app_id ? `<span class="qc-channel-pill">目标: ${escapeHtml(dot.app_id)}</span>` : ''}
        ${
          verText
            ? `<span class="qc-channel-pill ${unv ? 'unverified' : 'ok'}">${
                unv ? '⏳' : '✓'
              } ${escapeHtml(verText)}</span>`
            : ''
        }
      `;
      body.appendChild(infoRow);

      if (dot.detail) {
        const txt = document.createElement('div');
        txt.className = 'qc-trace-detail-text';
        txt.textContent = dot.detail;
        body.appendChild(txt);
      }

      if (dot.params) {
        const pre = document.createElement('pre');
        pre.className = 'qc-trace-json';
        pre.textContent =
          typeof dot.params === 'string' ? dot.params : JSON.stringify(dot.params, null, 2);
        body.appendChild(pre);
      }
    }
    // 4. Amber `approval` Auto-Expanded Sensitive Path & Action Approval Card
    else if (dot.kind === 'approval') {
      const pa = dot.pending_approval || dot;
      const metaInfo = extractApprovalMetadata(pa);

      const badgesRow = document.createElement('div');
      badgesRow.className = 'qc-approval-badges-row';
      badgesRow.innerHTML = `
        <span class="risk-badge risk-${metaInfo.riskCode}">${escapeHtml(metaInfo.riskLabel)}</span>
        ${
          pa.capability_id
            ? `<span class="qc-channel-pill">能力: ${escapeHtml(pa.capability_id)}</span>`
            : ''
        }
        ${
          metaInfo.reversible
            ? `<span class="qc-channel-pill ok">↶ 生成可逆 ChangeSet · 支持一键撤销</span>`
            : `<span class="qc-channel-pill">🔒 openat2 沙箱边界与进程校验保护</span>`
        }
      `;
      body.appendChild(badgesRow);

      if (metaInfo.targetPath || metaInfo.targetApp || metaInfo.pidsText) {
        const targetRow = document.createElement('div');
        targetRow.className = 'qc-approval-target-grid';
        targetRow.innerHTML = `
          ${
            metaInfo.targetPath
              ? `<span class="qc-channel-pill">📂 目标路径: ${escapeHtml(metaInfo.targetPath)}</span>`
              : ''
          }
          ${
            metaInfo.targetApp
              ? `<span class="qc-channel-pill">🧩 目标应用: ${escapeHtml(metaInfo.targetApp)}</span>`
              : ''
          }
          ${
            metaInfo.pidsText
              ? `<span class="qc-channel-pill">⚙️ 进程 PID: ${escapeHtml(metaInfo.pidsText)}</span>`
              : ''
          }
        `;
        body.appendChild(targetRow);
      }

      const summary = document.createElement('div');
      summary.className = 'qc-approval-summary';
      summary.textContent =
        pa.summary ||
        dot.detail ||
        '该操作涉及敏感配置路径、非常规目录或受控进程操作，请确认授权级别：';
      body.appendChild(summary);

      const previewText =
        pa.diff_preview ||
        (pa.arguments || pa.scope
          ? JSON.stringify(
              {
                capability: pa.capability_id || dot.capability_id || 'app_control',
                session_grant_preview: `${metaInfo.scopeKind}: ${metaInfo.scopeValue}`,
                arguments: pa.arguments || {},
              },
              null,
              2
            )
          : '');

      if (!dot.resolved_status && previewText) {
        const scopePre = document.createElement('pre');
        scopePre.className = 'qc-trace-json';
        scopePre.textContent = previewText;
        body.appendChild(scopePre);
      }

      if (dot.resolved_status) {
        const resolvedWrap = document.createElement('div');
        resolvedWrap.className = 'qc-approval-resolved';
        const statusSpan = document.createElement('span');
        statusSpan.textContent = dot.resolved_status;
        resolvedWrap.appendChild(statusSpan);

        const csId =
          dot.changeset_id ||
          (Array.isArray(dot.changeset_ids) && dot.changeset_ids.length > 0
            ? dot.changeset_ids[dot.changeset_ids.length - 1]
            : null);

        if (csId && typeof opts.onUndo === 'function') {
          const undoBtn = document.createElement('button');
          undoBtn.type = 'button';
          undoBtn.className = 'qc-inline-undo-btn';
          undoBtn.textContent = dot.undone ? '✓ 已撤销' : '↶ 撤销';
          undoBtn.disabled = Boolean(dot.undone);
          undoBtn.onclick = async () => {
            undoBtn.disabled = true;
            undoBtn.textContent = '撤销中…';
            const ok = await opts.onUndo(csId);
            if (ok) {
              dot.undone = true;
              undoBtn.textContent = '✓ 已撤销';
            } else {
              undoBtn.disabled = false;
              undoBtn.textContent = '↶ 撤销';
            }
          };
          resolvedWrap.appendChild(undoBtn);
        }
        body.appendChild(resolvedWrap);
      } else {
        const btnBar = document.createElement('div');
        btnBar.className = 'qc-approval-actions';

        const pendingStatusEl = document.createElement('div');
        pendingStatusEl.className = 'qc-approval-pending-live';
        pendingStatusEl.hidden = true;

        const btnOnce = document.createElement('button');
        btnOnce.type = 'button';
        btnOnce.className = 'qc-approve-btn qc-btn-approve primary';
        btnOnce.textContent = '✓ 批准本次';

        const btnScope = document.createElement('button');
        btnScope.type = 'button';
        btnScope.className = 'qc-approve-btn qc-btn-scope scope';
        btnScope.textContent = '⏱ 本会话放行此范围';
        btnScope.title = `本会话放行该范围 (${metaInfo.scopeKind}: ${metaInfo.scopeValue})`;
        btnScope.setAttribute('aria-label', '本会话放行该范围');

        const btnDeny = document.createElement('button');
        btnDeny.type = 'button';
        btnDeny.className = 'qc-approve-btn qc-btn-deny deny';
        btnDeny.textContent = '✕ 拒绝';

        const handleDecision = async (decision) => {
          btnOnce.disabled = true;
          btnScope.disabled = true;
          btnDeny.disabled = true;
          btnBar.hidden = true;
          btnBar.style.display = 'none';

          const liveMsg =
            decision === 'deny'
              ? '⏳ 正在取消受控操作…'
              : '⏳ 已确认授权，正在执行并继续会话推理…';
          pendingStatusEl.hidden = false;
          pendingStatusEl.textContent = liveMsg;
          const headStrong = head.querySelector('strong');
          if (headStrong) {
            headStrong.textContent = liveMsg;
          }

          if (opts.onApproveDecision) {
            await opts.onApproveDecision(decision, dot, idx);
          }
        };

        btnOnce.onclick = () => handleDecision('once');
        btnScope.onclick = () => handleDecision('scope');
        btnDeny.onclick = () => handleDecision('deny');

        btnBar.appendChild(btnOnce);
        btnBar.appendChild(btnScope);
        btnBar.appendChild(btnDeny);
        body.appendChild(btnBar);
        body.appendChild(pendingStatusEl);
      }
    }
    // 5a-0. Amber `task_partial` (`partially_completed`) honest budget-bounded partial completion inspector
    else if (dot.kind === 'task_partial') {
      const metaBar = document.createElement('div');
      metaBar.className = 'qc-tool-meta-bar';
      const leftInfo = document.createElement('div');
      leftInfo.className = 'qc-tool-meta-tags';
      leftInfo.innerHTML = '<span class="qc-channel-pill unverified">⚠️ 部分完成（预算上限保护）</span>';
      metaBar.appendChild(leftInfo);
      body.appendChild(metaBar);

      const detailEl = document.createElement('div');
      detailEl.className = 'qc-trace-detail-text';
      detailEl.textContent = dot.detail || '当前任务在预算边界处安全停止，仅完成部分步骤。';
      body.appendChild(detailEl);
    }
    // 5a. Sky-Blue `tool_unverified` (`RequestedUnverified` / `simulated: true`) honest pending response inspector
    else if (dot.kind === 'tool_unverified') {
      const metaBar = document.createElement('div');
      metaBar.className = 'qc-tool-meta-bar';

      const leftInfo = document.createElement('div');
      leftInfo.className = 'qc-tool-meta-tags';
      leftInfo.innerHTML = `
        <span class="qc-channel-pill unverified">⏳ 已发送请求（待桌面响应）</span>
        ${
          dot.channel
            ? `<span class="qc-channel-pill">通道: ${escapeHtml(formatChannelLabel(dot.channel))}</span>`
            : ''
        }
        ${
          dot.duration_ms !== null && dot.duration_ms !== undefined
            ? `<span class="qc-channel-pill">${escapeHtml(String(dot.duration_ms))} ms</span>`
            : ''
        }
      `;
      metaBar.appendChild(leftInfo);
      body.appendChild(metaBar);

      const detailEl = document.createElement('div');
      detailEl.className = 'qc-trace-detail-text';
      detailEl.textContent =
        dot.detail ||
        '启动或控制信号已发送，但尚未观测到新窗口或进程状态变化（软件可能最小化在系统托盘，可在 🧠 转译台中直接点击托盘菜单控制）。';
      body.appendChild(detailEl);

      if (dot.params) {
        const pre = document.createElement('pre');
        pre.className = 'qc-trace-json';
        pre.textContent =
          typeof dot.params === 'string' ? dot.params : JSON.stringify(dot.params, null, 2);
        body.appendChild(pre);
      }
    }
    // 5b. Emerald `tool_ok` strictly verified (`Passed`) tool inspector + inline `[↶ 撤销]`
    else if (dot.kind === 'tool_ok') {
      const metaBar = document.createElement('div');
      metaBar.className = 'qc-tool-meta-bar';

      const leftInfo = document.createElement('div');
      leftInfo.className = 'qc-tool-meta-tags';
      const verLabel = formatVerificationText(dot.verification) || '已验证';
      leftInfo.innerHTML = `
        <span class="qc-channel-pill ok">✓ ${escapeHtml(verLabel)}</span>
        ${
          dot.duration_ms !== null && dot.duration_ms !== undefined
            ? `<span class="qc-channel-pill">${escapeHtml(String(dot.duration_ms))} ms</span>`
            : ''
        }
        ${
          dot.changeset_id
            ? `<span class="qc-channel-pill">变更集 ${escapeHtml(String(dot.changeset_id).slice(0, 12))}</span>`
            : ''
        }
      `;
      metaBar.appendChild(leftInfo);

      if (dot.changeset_id && typeof opts.onUndo === 'function') {
        const undoBtn = document.createElement('button');
        undoBtn.type = 'button';
        undoBtn.className = 'qc-inline-undo-btn';
        undoBtn.textContent = dot.undone ? '✓ 已撤销' : '↶ 撤销';
        undoBtn.disabled = Boolean(dot.undone);
        undoBtn.onclick = async () => {
          undoBtn.disabled = true;
          undoBtn.textContent = '撤销中…';
          const ok = await opts.onUndo(dot.changeset_id);
          if (ok) {
            dot.undone = true;
            undoBtn.textContent = '✓ 已撤销';
          } else {
            undoBtn.disabled = false;
            undoBtn.textContent = '↶ 撤销';
          }
        };
        metaBar.appendChild(undoBtn);
      }
      body.appendChild(metaBar);

      if (dot.detail) {
        const detailEl = document.createElement('div');
        detailEl.className = 'qc-trace-detail-text';
        detailEl.textContent = dot.detail;
        body.appendChild(detailEl);
      }

      if (dot.params) {
        const pre = document.createElement('pre');
        pre.className = 'qc-trace-json';
        pre.textContent =
          typeof dot.params === 'string' ? dot.params : JSON.stringify(dot.params, null, 2);
        body.appendChild(pre);
      }
    }
    // 6. Red `tool_err` error details
    else {
      const errBox = document.createElement('div');
      errBox.className = 'qc-trace-err-box';
      errBox.textContent = dot.detail || '工具调用被拦截或执行失败';
      body.appendChild(errBox);
      if (dot.params) {
        const pre = document.createElement('pre');
        pre.className = 'qc-trace-json';
        pre.textContent =
          typeof dot.params === 'string' ? dot.params : JSON.stringify(dot.params, null, 2);
        body.appendChild(pre);
      }
    }

    drawerEl.appendChild(body);
    drawerEl.hidden = false;
    syncActiveDotButton();
  };

  const makeDotButton = (dot, idx) => {
    const meta = TRACE_DOT_META[dot.kind] || TRACE_DOT_META.tool_ok;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `qc-trace-dot-btn ${meta.colorClass}`;
    btn.setAttribute('data-dot-idx', String(idx));
    btn.title = `${meta.badgeLabel}: ${dot.title || meta.defaultTitle} (点击展开详情)`;
    btn.setAttribute('aria-label', `${meta.badgeLabel}: ${dot.title || ''}`);
    btn.innerHTML = `<span class="dot-glyph">●</span><span class="dot-mini-label">${escapeHtml(
      dot.shortLabel || meta.badgeLabel
    )}</span>`;

    btn.onclick = () => {
      if (activeIdx === idx && !drawerEl.hidden) {
        activeIdx = -1;
        drawerEl.hidden = true;
        syncActiveDotButton();
        return;
      }
      activeIdx = idx;
      renderDrawerContent(dot, idx);
    };
    return btn;
  };

  const rebuildDotsTrack = () => {
    dotsTrack.innerHTML = '';

    if (opts.isStreaming && dots.length === 0) {
      const pulse = document.createElement('span');
      pulse.className = 'qc-trace-dot-btn dot-gray pulsing';
      pulse.title = '正在推理与检索记忆…';
      pulse.innerHTML = '<span class="dot-glyph">●</span><span class="dot-mini-label">思考中…</span>';
      dotsTrack.appendChild(pulse);
      return;
    }

    // Compact folding when `> 6` dots: collapse repetitive middle dots into clickable `+N` pill,
    // while ALWAYS keeping any unresolved `approval` dot directly visible!
    if (dots.length > 6 && !expandedAllDots) {
      const headIndices = [0, 1, 2];
      const tailIndices = [dots.length - 2, dots.length - 1];
      const approvalIndices = dots
        .map((d, i) => (d.kind === 'approval' && !d.resolved_status ? i : -1))
        .filter((i) => i !== -1);

      const visibleSet = new Set([...headIndices, ...tailIndices, ...approvalIndices]);
      const hiddenCount = dots.length - visibleSet.size;

      headIndices.forEach((idx) => {
        dotsTrack.appendChild(makeDotButton(dots[idx], idx));
      });

      approvalIndices.forEach((idx) => {
        if (!headIndices.includes(idx) && !tailIndices.includes(idx)) {
          dotsTrack.appendChild(makeDotButton(dots[idx], idx));
        }
      });

      if (hiddenCount > 0) {
        const morePill = document.createElement('button');
        morePill.type = 'button';
        morePill.className = 'qc-trace-more-pill';
        morePill.textContent = `+${hiddenCount}`;
        morePill.title = `点击展开中间折叠的 ${hiddenCount} 步工具轨迹`;
        morePill.onclick = () => {
          expandedAllDots = true;
          rebuildDotsTrack();
        };
        dotsTrack.appendChild(morePill);
      }

      tailIndices.forEach((idx) => {
        if (!headIndices.includes(idx)) {
          dotsTrack.appendChild(makeDotButton(dots[idx], idx));
        }
      });
    } else {
      dots.forEach((dot, idx) => {
        dotsTrack.appendChild(makeDotButton(dot, idx));
      });
      if (dots.length > 6 && expandedAllDots) {
        const collapsePill = document.createElement('button');
        collapsePill.type = 'button';
        collapsePill.className = 'qc-trace-more-pill';
        collapsePill.textContent = '收起';
        collapsePill.title = '折叠中间重复轨迹圆点';
        collapsePill.onclick = () => {
          expandedAllDots = false;
          rebuildDotsTrack();
        };
        dotsTrack.appendChild(collapsePill);
      }
    }

    syncActiveDotButton();
  };

  rebuildDotsTrack();

  barWrapEl.appendChild(dotsTrack);
  barWrapEl.appendChild(rightActions);

  // CRITICAL UX GUARANTEE: Auto-expand immediately whenever an unresolved `approval` dot exists!
  const approvalIdx = dots.findIndex((d) => d.kind === 'approval' && !d.resolved_status);
  if (approvalIdx !== -1) {
    activeIdx = approvalIdx;
    renderDrawerContent(dots[approvalIdx], approvalIdx);
  }

  return { barWrapEl, drawerEl };
}
