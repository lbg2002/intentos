/**
 * IntentOS v0.3 — Grouped Candidate View & Alt+Enter Contextual Action Menu (UI-02, UI-06)
 */

import { rpc, moduleRpc } from './rpc-client.js';

const GROUP_META = {
  direct_intent: { header: '─ 最佳匹配 ─', icon: '⚡', cat: 'all' },
  apps: { header: '─ 应用 ─', icon: '🧩', cat: 'apps' },
  files: { header: '─ 文件 ─', icon: '📄', cat: 'files' },
  web: { header: '─ 网站与搜索 ─', icon: '🌐', cat: 'web' },
  settings: { header: '─ 系统设置 ─', icon: '⚙', cat: 'settings' },
  skills: { header: '─ 技能与命令 ─', icon: '🛠', cat: 'skills' },
  passthrough: { header: '─ 终端直通 ─', icon: '$', cat: 'skills' },
};

export class CandidateViewController {
  /**
   * @param {object} opts
   * @param {HTMLElement} opts.containerEl
   * @param {HTMLElement} opts.actionMenuEl
   * @param {HTMLElement} opts.compoundBarEl
   * @param {HTMLElement} opts.latencyEl
   * @param {Function} opts.onExecuteCandidate - (item, forceAgent) => void
   * @param {Function} opts.onExecuteAction - (action, item) => void
   * @param {Function} opts.onExecuteCompound - (analysis) => void
   * @param {Function} opts.onToast - (msg) => void
   */
  constructor(opts) {
    this.containerEl = opts.containerEl;
    this.actionMenuEl = opts.actionMenuEl;
    this.compoundBarEl = opts.compoundBarEl;
    this.latencyEl = opts.latencyEl;
    this.onExecuteCandidate = opts.onExecuteCandidate;
    this.onExecuteAction = opts.onExecuteAction;
    this.onExecuteCompound = opts.onExecuteCompound;
    this.onToast = opts.onToast || (() => {});

    this.flatItems = [];
    this.groups = [];
    this.activeIdx = 0;
    this.categoryFilter = 'all';
    this.actionMenuOpen = false;
    this.actionItems = [];
    this.activeActionIdx = 0;
    this.lastCompoundAnalysis = null;
  }

  setCategoryFilter(cat) {
    this.categoryFilter = cat || 'all';
    this.activeIdx = 0;
    this.closeActionMenu();
    this.render();
  }

  cycleCategoryFilter(reverse = false) {
    const order = ['all', 'apps', 'files', 'web', 'settings', 'skills'];
    const cur = order.indexOf(this.categoryFilter);
    const next = reverse
      ? (cur - 1 + order.length) % order.length
      : (cur + 1) % order.length;
    this.setCategoryFilter(order[next]);
    return order[next];
  }

  clear() {
    this.flatItems = [];
    this.groups = [];
    this.activeIdx = 0;
    this.lastCompoundAnalysis = null;
    this.closeActionMenu();
    if (this.containerEl) this.containerEl.innerHTML = '';
    if (this.compoundBarEl) {
      this.compoundBarEl.classList.remove('visible');
      this.compoundBarEl.innerHTML = '';
    }
  }

  getSelectedCandidate() {
    return this.flatItems[this.activeIdx] || null;
  }

  moveSelection(delta) {
    if (this.actionMenuOpen && this.actionItems.length > 0) {
      this.activeActionIdx =
        (this.activeActionIdx + delta + this.actionItems.length) % this.actionItems.length;
      this.renderActionMenuItems();
      return;
    }
    if (!this.flatItems.length) return;
    this.activeIdx = (this.activeIdx + delta + this.flatItems.length) % this.flatItems.length;
    this.render();
  }

  async query(rawQuery, sessionId = null, desktopContext = {}) {
    const q = (rawQuery || '').trim();
    if (!q) {
      this.clear();
      if (this.latencyEl) this.latencyEl.textContent = 'L0 Ready';
      return;
    }

    // 1. Query grouped candidates via `intent_engine.query_grouped_candidates` with fallback to `query_candidates`
    const filterParam = this.categoryFilter === 'all' ? null : this.categoryFilter;
    const res = await moduleRpc(
      'intent_engine',
      'query_grouped_candidates',
      {
        query: q,
        category_filter: filterParam,
        session_id: sessionId,
      },
      async () => {
        const legacy = await rpc('query_candidates', { query: q });
        if (!legacy.ok || !legacy.result) {
          return { query: q, elapsed_us: 0, groups: [], items: [] };
        }
        return this.normalizeLegacyCandidates(legacy.result);
      }
    );

    if (res.ok && res.result) {
      const data = res.result;
      const ms = ((data.elapsed_us || 450) / 1000).toFixed(2);
      if (this.latencyEl) {
        this.latencyEl.textContent = `${ms} ms`;
      }
      this.groups = this.ensureGroups(data);
      this.activeIdx = 0;
      this.closeActionMenu();
      this.render();
    }

    // 2. Check compound multi-step intent if query contains conjunctions
    if (/(然后|并且|接着|再把|再去|并把|并|;|&&)/.test(q) && !q.startsWith('$')) {
      const compRes = await moduleRpc('intent_engine', 'analyze_intent', {
        text: q,
        session_id: sessionId,
        desktop_context: desktopContext,
      });
      if (compRes.ok && compRes.result && compRes.result.is_compound && Array.isArray(compRes.result.steps) && compRes.result.steps.length > 1) {
        this.lastCompoundAnalysis = compRes.result;
        this.renderCompoundBanner(compRes.result);
      } else if (this.compoundBarEl) {
        this.compoundBarEl.classList.remove('visible');
      }
    } else if (this.compoundBarEl) {
      this.compoundBarEl.classList.remove('visible');
    }
  }

  normalizeLegacyCandidates(legacyData) {
    const items = legacyData.items || [];
    const groupedMap = new Map();
    for (const item of items) {
      const gid = this.inferGroupId(item);
      if (!groupedMap.has(gid)) {
        groupedMap.set(gid, []);
      }
      groupedMap.get(gid).push(item);
    }
    const groups = [];
    for (const [group_id, groupItems] of groupedMap.entries()) {
      groups.push({
        group_id,
        title: GROUP_META[group_id] ? GROUP_META[group_id].header : `─ ${group_id} ─`,
        items: groupItems,
      });
    }
    return {
      query: legacyData.query,
      elapsed_us: legacyData.elapsed_us || 500,
      l0_direct_match: legacyData.l0_direct_match,
      groups,
      items,
    };
  }

  inferGroupId(item) {
    const kind = (item.kind || '').toLowerCase();
    const cap = (item.capability_id || '').toLowerCase();
    if (kind === 'app' || kind === 'apps' || cap.startsWith('app.') || cap.startsWith('window.')) {
      return 'apps';
    }
    if (kind === 'file' || kind === 'files' || cap.startsWith('file.') || cap.startsWith('archive.')) {
      return 'files';
    }
    if (kind === 'web' || kind === 'site' || cap.startsWith('web.')) {
      return 'web';
    }
    if (
      kind === 'setting' ||
      kind === 'settings' ||
      cap.startsWith('sound.') ||
      cap.startsWith('display.') ||
      cap.startsWith('appearance.') ||
      cap.startsWith('network.') ||
      cap.startsWith('bluetooth.') ||
      cap.startsWith('power.') ||
      cap.startsWith('scene.')
    ) {
      return 'settings';
    }
    if (kind === 'passthrough' || kind === 'skill' || kind === 'workflow' || kind === 'agent_fallback') {
      return 'skills';
    }
    return 'direct_intent';
  }

  ensureGroups(data) {
    if (Array.isArray(data.groups) && data.groups.length > 0) {
      return data.groups.map((g) => {
        const gid = g.group_id || g.id || 'direct_intent';
        const meta = GROUP_META[gid] || { header: g.title || `─ ${gid} ─`, icon: '✨', cat: gid };
        return {
          group_id: gid,
          header: meta.header,
          icon: meta.icon,
          cat: meta.cat,
          items: g.items || [],
        };
      });
    }
    const normalized = this.normalizeLegacyCandidates(data);
    return this.ensureGroups(normalized);
  }

  renderCompoundBanner(analysis) {
    if (!this.compoundBarEl) return;
    const stepsDesc = analysis.steps
      .map((s, idx) => `${idx + 1}. ${s.summary || s.capability_id || s.raw_segment || '步骤'}`)
      .join(' → ');
    this.compoundBarEl.innerHTML = `
      <div>
        <strong>🔗 复合意图拆解预览 (${analysis.steps.length} 步)</strong>：
        <span></span>
      </div>
      <button type="button" class="btn-yaru" id="btn-run-compound-now">按序执行多步意图</button>
    `;
    this.compoundBarEl.querySelector('span').textContent = stepsDesc;
    this.compoundBarEl.classList.add('visible');
    const btn = this.compoundBarEl.querySelector('#btn-run-compound-now');
    if (btn && this.onExecuteCompound) {
      btn.onclick = () => this.onExecuteCompound(analysis);
    }
  }

  render() {
    if (!this.containerEl) return;
    this.containerEl.innerHTML = '';
    this.flatItems = [];

    const filteredGroups = this.groups.filter((g) => {
      if (this.categoryFilter === 'all') return true;
      return g.group_id === this.categoryFilter || g.cat === this.categoryFilter;
    });

    for (const grp of filteredGroups) {
      if (!grp.items || !grp.items.length) continue;
      const headerEl = document.createElement('div');
      headerEl.className = 'candidate-group-header';
      headerEl.innerHTML = `<span>${grp.header}</span><span>${grp.items.length} 项</span>`;
      this.containerEl.appendChild(headerEl);

      for (const item of grp.items) {
        const idx = this.flatItems.length;
        this.flatItems.push(item);

        const row = document.createElement('div');
        row.className = 'candidate-item' + (idx === this.activeIdx ? ' active' : '');
        row.setAttribute('role', 'option');
        row.setAttribute('data-idx', String(idx));

        const iconChar = this.pickIcon(item, grp.group_id);
        const riskBadgeHtml = item.risk
          ? `<span class="risk-badge risk-${item.risk}">${item.risk}</span>`
          : '';

        row.innerHTML = `
          <div class="cand-icon">${iconChar}</div>
          <div class="cand-main">
            <div class="cand-title"></div>
            <div class="cand-sub"></div>
          </div>
          <div class="cand-right">
            ${riskBadgeHtml}
            <span class="cand-badge"></span>
            <button type="button" class="cand-action-trigger" title="打开上下文动作菜单 (Alt+Enter)">⋯ 动作</button>
          </div>
        `;
        row.querySelector('.cand-title').textContent = item.title || item.id;
        row.querySelector('.cand-sub').textContent = item.subtitle || item.capability_id || '';
        row.querySelector('.cand-badge').textContent = item.badge || grp.group_id;

        row.addEventListener('mouseenter', () => {
          this.activeIdx = idx;
          this.highlightActiveRow();
        });

        row.addEventListener('click', (e) => {
          if (e.target.closest('.cand-action-trigger')) {
            e.stopPropagation();
            this.activeIdx = idx;
            this.highlightActiveRow();
            this.toggleActionMenu(row);
            return;
          }
          this.recordFeedback(item);
          if (this.onExecuteCandidate) {
            this.onExecuteCandidate(item, false);
          }
        });

        this.containerEl.appendChild(row);
      }
    }
  }

  highlightActiveRow() {
    if (!this.containerEl) return;
    const rows = this.containerEl.querySelectorAll('.candidate-item');
    rows.forEach((el) => {
      const i = Number(el.getAttribute('data-idx'));
      el.classList.toggle('active', i === this.activeIdx);
    });
  }

  pickIcon(item, groupId) {
    const kind = (item.kind || groupId || '').toLowerCase();
    if (kind.includes('app')) return '🧩';
    if (kind.includes('file')) return '📄';
    if (kind.includes('web') || kind.includes('site')) return '🌐';
    if (kind.includes('setting')) return '⚙';
    if (kind.includes('passthrough')) return '$';
    if (kind.includes('agent')) return '🤖';
    return '⚡';
  }

  async toggleActionMenu(anchorEl = null) {
    if (this.actionMenuOpen) {
      this.closeActionMenu();
      return;
    }
    const item = this.getSelectedCandidate();
    if (!item) return;

    const actions = await this.fetchActionsForCandidate(item);
    this.actionItems = actions;
    this.activeActionIdx = 0;
    this.actionMenuOpen = true;

    if (!this.actionMenuEl) return;
    this.renderActionMenuItems(item);

    const targetEl =
      anchorEl ||
      (this.containerEl && this.containerEl.querySelector(`.candidate-item[data-idx="${this.activeIdx}"]`)) ||
      this.containerEl;

    if (targetEl) {
      const rect = targetEl.getBoundingClientRect();
      const top = Math.min(window.innerHeight - 280, Math.max(60, rect.bottom + 4));
      const left = Math.min(window.innerWidth - 320, Math.max(16, rect.right - 280));
      this.actionMenuEl.style.top = `${top}px`;
      this.actionMenuEl.style.left = `${left}px`;
    }
    this.actionMenuEl.classList.add('open');
  }

  closeActionMenu() {
    this.actionMenuOpen = false;
    this.actionItems = [];
    this.activeActionIdx = 0;
    if (this.actionMenuEl) {
      this.actionMenuEl.classList.remove('open');
      this.actionMenuEl.innerHTML = '';
    }
  }

  async fetchActionsForCandidate(item) {
    if (Array.isArray(item.actions) && item.actions.length > 0) {
      return item.actions;
    }
    const target =
      (item.arguments && (item.arguments.path || item.arguments.target || item.arguments.url || item.arguments.app)) ||
      item.subtitle ||
      item.title;

    const res = await moduleRpc(
      'intent_engine',
      'get_candidate_actions',
      {
        candidate_id: item.id,
        kind: item.kind || this.inferGroupId(item),
        target,
        capability_id: item.capability_id,
      },
      async () => ({
        actions: this.buildFallbackActions(item, target),
      })
    );

    if (res.ok && res.result && Array.isArray(res.result.actions) && res.result.actions.length) {
      return res.result.actions;
    }
    return this.buildFallbackActions(item, target);
  }

  buildFallbackActions(item, target) {
    const gid = this.inferGroupId(item);
    if (gid === 'files') {
      return [
        { id: 'open', label: '打开文件', shortcut: 'Enter', capability_id: 'file.open', arguments: { path: target } },
        { id: 'open_with', label: '用指定应用打开 (WPS / VS Code)…', shortcut: 'Alt+O', capability_id: 'file.open_with', arguments: { path: target, app: 'wps' } },
        { id: 'reveal', label: '打开所在文件夹', shortcut: 'Alt+R', capability_id: 'file.reveal', arguments: { path: target } },
        { id: 'copy_path', label: '复制完整路径', shortcut: 'Ctrl+C', capability_id: 'clipboard.copy', arguments: { text: target } },
        { id: 'rename', label: '重命名…', shortcut: 'F2', capability_id: 'file.rename', arguments: { path: target } },
        { id: 'trash', label: '移入回收站 (可撤销)', shortcut: 'Del', capability_id: 'file.trash', arguments: { path: target } },
      ];
    }
    if (gid === 'apps') {
      const appName = (item.arguments && item.arguments.app) || item.title;
      return [
        { id: 'launch', label: '启动或聚焦窗口', shortcut: 'Enter', capability_id: 'app.launch', arguments: { app: appName } },
        { id: 'new_window', label: '新窗口启动', shortcut: 'Alt+N', capability_id: 'app.launch', arguments: { app: appName, new_window: true } },
        { id: 'quit', label: '安全退出应用', shortcut: 'Alt+Q', capability_id: 'app.quit', arguments: { app: appName } },
      ];
    }
    if (gid === 'web') {
      const url = (item.arguments && item.arguments.url) || target;
      return [
        { id: 'open_web', label: '默认浏览器打开', shortcut: 'Enter', capability_id: 'web.open', arguments: { url } },
        { id: 'copy_url', label: '复制链接地址', shortcut: 'Ctrl+C', capability_id: 'clipboard.copy', arguments: { text: url } },
        { id: 'search_site', label: '在此站点内搜索…', shortcut: 'Alt+S', capability_id: 'web.search_site', arguments: { site: item.title, query: '' } },
      ];
    }
    if (gid === 'settings') {
      return [
        { id: 'apply_setting', label: '立即执行此设置', shortcut: 'Enter', capability_id: item.capability_id, arguments: item.arguments || {} },
        { id: 'reset_setting', label: '恢复默认设置', shortcut: 'Alt+D', capability_id: 'settings.reset', arguments: { capability_id: item.capability_id } },
        { id: 'open_panel', label: '在系统控制中心打开', shortcut: 'Alt+P', capability_id: 'settings.open_panel', arguments: { panel: item.capability_id } },
      ];
    }
    return [
      { id: 'execute', label: '立即执行首选动作', shortcut: 'Enter', capability_id: item.capability_id, arguments: item.arguments || {} },
      { id: 'force_l2', label: '交给 L2 智能体深度规划', shortcut: 'Ctrl+Enter', force_agent: true },
      { id: 'copy_text', label: '复制候选标题', shortcut: 'Ctrl+C', capability_id: 'clipboard.copy', arguments: { text: item.title || '' } },
    ];
  }

  renderActionMenuItems(cand = this.getSelectedCandidate()) {
    if (!this.actionMenuEl || !cand) return;
    this.actionMenuEl.innerHTML = `
      <div class="action-menu-header">
        <span>⚡ 动作菜单：${cand.title || cand.id}</span>
        <kbd>Esc</kbd>
      </div>
      <div class="action-menu-list"></div>
    `;
    const listEl = this.actionMenuEl.querySelector('.action-menu-list');
    this.actionItems.forEach((act, i) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'action-menu-item' + (i === this.activeActionIdx ? ' active' : '');
      btn.innerHTML = `
        <span></span>
        <kbd></kbd>
      `;
      btn.querySelector('span').textContent = act.label || act.id;
      btn.querySelector('kbd').textContent = act.shortcut || '';
      btn.addEventListener('mouseenter', () => {
        this.activeActionIdx = i;
        listEl.querySelectorAll('.action-menu-item').forEach((el, idx) => {
          el.classList.toggle('active', idx === i);
        });
      });
      btn.addEventListener('click', () => {
        this.executeActionItem(act, cand);
      });
      listEl.appendChild(btn);
    });
  }

  executeActiveAction() {
    const cand = this.getSelectedCandidate();
    const act = this.actionItems[this.activeActionIdx];
    if (!cand || !act) return false;
    this.executeActionItem(act, cand);
    return true;
  }

  async executeActionItem(act, cand) {
    this.closeActionMenu();
    this.recordFeedback(cand);
    if (act.id === 'copy_path' || act.id === 'copy_url' || act.id === 'copy_text' || act.capability_id === 'clipboard.copy') {
      const textToCopy = (act.arguments && (act.arguments.text || act.arguments.path || act.arguments.url)) || cand.subtitle || cand.title;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(textToCopy);
        }
      } catch (_) {
        // Fallback handled by toast
      }
      this.onToast(`📋 已复制到剪贴板：${textToCopy}`);
      return;
    }
    if (this.onExecuteAction) {
      this.onExecuteAction(act, cand);
    }
  }

  async copySelectedCandidatePathOrUrl() {
    const cand = this.getSelectedCandidate();
    if (!cand) return false;
    const text =
      (cand.arguments && (cand.arguments.path || cand.arguments.url || cand.arguments.target)) ||
      cand.subtitle ||
      cand.title;
    if (!text) return false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      }
    } catch (_) {
      // Ignore clipboard permission failure in headless environments
    }
    this.onToast(`📋 已复制路径/链接：${text}`);
    return true;
  }

  recordFeedback(cand) {
    if (!cand || !cand.id) return;
    moduleRpc('intent_engine', 'record_candidate_feedback', {
      query: cand.title || '',
      selected_id: cand.id,
    }).catch(() => {});
  }
}
