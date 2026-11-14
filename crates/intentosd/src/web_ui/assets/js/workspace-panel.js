/**
 * IntentOS v0.3 — Intent Workspace Panel, Multi-Turn Session Drawer, Context Capsules & E2 Staging Runner
 */

import { rpc, moduleRpc } from './rpc-client.js';

export class WorkspacePanelController {
  /**
   * @param {object} opts
   * @param {HTMLElement} opts.turnsListEl
   * @param {HTMLElement} opts.capsulesListEl
   * @param {HTMLElement} opts.inspectorContentEl
   * @param {import('./result-surfaces.js').ResultSurfaces} opts.resultSurfaces
   * @param {Function} opts.onSubmitIntent - (text, forceAgent, candidateId) => void
   * @param {Function} opts.onUndo - (csId) => void
   * @param {Function} opts.onToast - (msg) => void
   */
  constructor(opts) {
    this.turnsListEl = opts.turnsListEl;
    this.capsulesListEl = opts.capsulesListEl;
    this.inspectorContentEl = opts.inspectorContentEl;
    this.resultSurfaces = opts.resultSurfaces;
    this.onSubmitIntent = opts.onSubmitIntent;
    this.onUndo = opts.onUndo;
    this.onToast = opts.onToast || (() => {});

    this.turns = [];
    this.capsules = [
      { id: 'proj_intentos', kind: 'project', label: '📁 项目: intentos-v0.1.0', value: 'project://intentos' },
    ];
    this.activeTab = 'changesets';
  }

  getDesktopContextPayload() {
    const ctx = { capsules: this.capsules };
    for (const c of this.capsules) {
      if (c.kind === 'file') ctx.attached_file = c.value;
      if (c.kind === 'project') ctx.active_project = c.value;
      if (c.kind === 'selection') ctx.selected_text = c.value;
      if (c.kind === 'window') ctx.active_window = c.value;
    }
    return ctx;
  }

  addCapsule(kind, label, value) {
    const id = `cap_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    this.capsules.push({ id, kind, label, value });
    this.renderCapsules();
    this.onToast(`📎 已附加工作区上下文：${label}`);
  }

  removeCapsule(id) {
    this.capsules = this.capsules.filter((c) => c.id !== id);
    this.renderCapsules();
  }

  renderCapsules() {
    if (!this.capsulesListEl) return;
    this.capsulesListEl.innerHTML = '';
    if (!this.capsules.length) {
      const empty = document.createElement('span');
      empty.className = 'mono-id';
      empty.textContent = '无附加引用（可拖入文件或点击右侧附加）';
      this.capsulesListEl.appendChild(empty);
      return;
    }
    this.capsules.forEach((c) => {
      const pill = document.createElement('span');
      pill.className = 'context-capsule';
      pill.innerHTML = `
        <span class="cap-label"></span>
        <button type="button" class="capsule-remove" title="移除此上下文引用">✕</button>
      `;
      pill.querySelector('.cap-label').textContent = c.label;
      pill.querySelector('.capsule-remove').onclick = () => this.removeCapsule(c.id);
      this.capsulesListEl.appendChild(pill);
    });
  }

  appendConversationTurn(userText, assistantText, route = 'L0', resourceRef = null) {
    this.turns.push({
      time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      userText,
      assistantText,
      route,
      resourceRef,
    });
    this.renderTurns();
  }

  resetSessionTurns() {
    this.turns = [];
    this.renderTurns();
  }

  renderTurns() {
    if (!this.turnsListEl) return;
    this.turnsListEl.innerHTML = '';
    if (!this.turns.length) {
      this.turnsListEl.innerHTML = `
        <div style="color:var(--text-muted); font-size:0.79rem; padding:0.4rem;">
          💡 多轮意图会话已就绪（仅驻留内存 Session Buffer，支持「把它移到…」「打开它所在文件夹」等指代消歧）。
        </div>
      `;
      return;
    }
    this.turns.forEach((t) => {
      const uBubble = document.createElement('div');
      uBubble.className = 'turn-bubble user-turn';
      uBubble.innerHTML = `
        <div class="turn-meta"><span>👤 用户意图</span><span>${t.time}</span></div>
        <div class="turn-text"></div>
      `;
      uBubble.querySelector('.turn-text').textContent = t.userText;

      const aBubble = document.createElement('div');
      aBubble.className = 'turn-bubble';
      aBubble.innerHTML = `
        <div class="turn-meta">
          <span>🤖 IntentOS (${t.route})</span>
          ${t.resourceRef ? `<span class="mono-id" title="当前指代绑定对象">🔗 ${t.resourceRef.split('/').pop()}</span>` : ''}
        </div>
        <div class="turn-text"></div>
      `;
      aBubble.querySelector('.turn-text').textContent = t.assistantText;

      this.turnsListEl.appendChild(uBubble);
      this.turnsListEl.appendChild(aBubble);
    });
    this.turnsListEl.scrollTop = this.turnsListEl.scrollHeight;
  }

  async runE2StagedPreview(commandText) {
    const cmd = (commandText || '').trim();
    if (!cmd) return;
    const res = await moduleRpc(
      'execution_hub',
      'stage_e2_command',
      {
        command: cmd,
        work_dir: '.',
        task_id: `task_e2_${Date.now()}`,
      },
      async () => ({
        proposal_id: `prop_sim_${Date.now()}`,
        command: cmd,
        stdout: `[E2 隔离暂存预演] $ ${cmd}\n已计算工作区快照差异，等待确认提交。`,
        diffs: {
          added_files: ['staged_output_preview.txt'],
          modified_files: [],
          deleted_files: [],
        },
      })
    );
    if (res.ok && res.result && this.resultSurfaces && this.resultSurfaces.containerEl) {
      const card = this.resultSurfaces.buildE2StagingProposalCard(res.result);
      this.resultSurfaces.containerEl.prepend(card);
      this.onToast('🧪 E2 沙箱暂存执行完毕，请审阅文件树差异');
    }
  }

  setActiveTab(tab) {
    this.activeTab = tab;
    this.refreshInspector();
  }

  async refreshInspector() {
    if (!this.inspectorContentEl) return;
    const tab = this.activeTab;

    if (tab === 'changesets') {
      const res = await rpc('list_changesets', { limit: 12 });
      const list = res.ok && Array.isArray(res.result) ? res.result : [];
      if (!list.length) {
        this.inspectorContentEl.innerHTML =
          '<div style="color:var(--text-muted)">暂无变更集记录。尝试点击上方「进入护眼模式」体验多设置单变更集一键撤销！</div>';
        return;
      }
      this.inspectorContentEl.innerHTML = '';
      list.forEach((cs) => {
        const row = document.createElement('div');
        row.className = 'row-record';
        row.innerHTML = `
          <div>
            <div><strong></strong> <span class="mono-id"></span></div>
            <div class="mono-id"></div>
          </div>
          <div class="cs-action"></div>
        `;
        row.querySelector('strong').textContent = cs.summary;
        row.querySelectorAll('.mono-id')[0].textContent = `[${cs.id} · ${(cs.operations || []).length} 项变更]`;
        row.querySelectorAll('.mono-id')[1].textContent = `${cs.capability_id} · 状态: ${cs.status}`;
        if (cs.status === 'applied') {
          const b = document.createElement('button');
          b.className = 'btn-ghost';
          b.type = 'button';
          b.textContent = '↶ 一键撤销';
          b.onclick = () => this.onUndo(cs.id);
          row.querySelector('.cs-action').appendChild(b);
        }
        this.inspectorContentEl.appendChild(row);
      });
    } else if (tab === 'scenes') {
      const res = await rpc('list_scenes');
      const scenes = res.ok && Array.isArray(res.result) ? res.result : [];
      this.inspectorContentEl.innerHTML = `
        <div style="display:flex; gap:0.5rem; margin-bottom:0.75rem; flex-wrap:wrap;">
          <input id="new-scene-name" class="form-input" style="max-width:280px;" placeholder="保存当前设置为新场景（如：深夜码字模式）" />
          <button id="btn-save-scene" class="btn-primary" type="button">保存当前设置快照</button>
        </div>
        <div id="scenes-rows"></div>
      `;
      const saveBtn = this.inspectorContentEl.querySelector('#btn-save-scene');
      saveBtn.onclick = async () => {
        const nm = this.inspectorContentEl.querySelector('#new-scene-name').value.trim();
        if (!nm) return;
        const r = await rpc('save_scene', { name: nm });
        if (r.ok) {
          this.onToast(`✓ 已保存自定义场景：「${nm}」`);
          await this.refreshInspector();
        }
      };
      const rowsBox = this.inspectorContentEl.querySelector('#scenes-rows');
      scenes.forEach((sc) => {
        const row = document.createElement('div');
        row.className = 'row-record';
        row.innerHTML = `
          <div>
            <div><strong></strong> <span class="mono-id"></span></div>
            <div class="mono-id"></div>
          </div>
          <button class="btn-ghost" type="button">应用此场景</button>
        `;
        row.querySelector('strong').textContent = sc.name;
        row.querySelectorAll('.mono-id')[0].textContent = sc.builtin ? '[内置场景]' : '[自定义快照]';
        row.querySelectorAll('.mono-id')[1].textContent = sc.description || '';
        row.querySelector('button').onclick = () => this.onSubmitIntent(`进入${sc.name}`, false, null);
        rowsBox.appendChild(row);
      });
    } else if (tab === 'memories') {
      const [memRes, candRes] = await Promise.all([
        rpc('list_memories'),
        moduleRpc('execution_hub', 'list_memory_candidates', {}, async () => ({ candidates: [] })),
      ]);
      const mems = memRes.ok && Array.isArray(memRes.result) ? memRes.result : [];
      const candidates =
        (candRes.ok && candRes.result && (candRes.result.candidates || candRes.result)) || [];

      this.inspectorContentEl.innerHTML = `
        <div style="display:flex; gap:0.5rem; margin-bottom:0.75rem; flex-wrap:wrap;">
          <input id="mem-subj" class="form-input" style="max-width:200px;" placeholder="键（如 open_with.docx）" />
          <input id="mem-val" class="form-input" style="max-width:240px;" placeholder="值（如 WPS Office）" />
          <button id="btn-add-mem" class="btn-primary" type="button">写入偏好记忆</button>
        </div>
        <div id="mem-candidates-box"></div>
        <div id="mem-rows"></div>
      `;
      this.inspectorContentEl.querySelector('#btn-add-mem').onclick = async () => {
        const subject = this.inspectorContentEl.querySelector('#mem-subj').value.trim();
        const value = this.inspectorContentEl.querySelector('#mem-val').value.trim();
        if (!subject || !value) return;
        const r = await rpc('upsert_memory', { subject, value });
        if (!r.ok) this.onToast(`写入失败: ${r.error}`);
        else this.onToast(`✓ 已写入记忆: ${subject} = ${value}`);
        await this.refreshInspector();
      };

      const candBox = this.inspectorContentEl.querySelector('#mem-candidates-box');
      if (Array.isArray(candidates) && candidates.length > 0) {
        candBox.innerHTML = `<div style="margin-bottom:0.4rem; font-weight:650; color:var(--accent);">💡 待确认记忆候选队列 (${candidates.length} 项 · M-05)</div>`;
        candidates.forEach((c) => {
          const r = document.createElement('div');
          r.className = 'row-record';
          r.innerHTML = `
            <div><strong></strong> = <span></span> <span class="mono-id">[候选]</span></div>
            <button type="button" class="btn-primary">确认写入</button>
          `;
          r.querySelector('strong').textContent = c.subject || c.key || 'preference';
          r.querySelectorAll('span')[0].textContent = c.value || '';
          r.querySelector('button').onclick = async () => {
            await moduleRpc('execution_hub', 'confirm_memory_candidate', { candidate_id: c.id });
            await this.refreshInspector();
          };
          candBox.appendChild(r);
        });
      }

      const memRows = this.inspectorContentEl.querySelector('#mem-rows');
      if (!mems.length) {
        memRows.innerHTML =
          '<div style="color:var(--text-muted)">暂无已保存的显式记忆。可输入「记住 docx 用 WPS 打开」体验自动偏好绑定。</div>';
        return;
      }
      mems.forEach((m) => {
        const row = document.createElement('div');
        row.className = 'row-record';
        row.innerHTML = `
          <div>
            <div><strong></strong> = <span></span></div>
            <div class="mono-id"></div>
          </div>
          <button class="btn-ghost btn-danger" type="button">删除并拒写 (M-03)</button>
        `;
        row.querySelector('strong').textContent = m.subject;
        row.querySelectorAll('span')[0].textContent = m.value;
        row.querySelector('.mono-id').textContent = `${m.id} · ${m.scope} · 更新于 ${m.updated_at}`;
        row.querySelector('button').onclick = async () => {
          await rpc('delete_memory', { id: m.id });
          await this.refreshInspector();
        };
        memRows.appendChild(row);
      });
    } else if (tab === 'tasks') {
      const res = await rpc('list_tasks', { limit: 12 });
      const list = res.ok && Array.isArray(res.result) ? res.result : [];
      if (!list.length) {
        this.inspectorContentEl.innerHTML =
          '<div style="color:var(--text-muted)">暂无持久化任务记录（注：隐私会话任务不会写入此处）。</div>';
        return;
      }
      this.inspectorContentEl.innerHTML = '';
      list.forEach((t) => {
        const row = document.createElement('div');
        row.className = 'row-record';
        row.innerHTML = `
          <div>
            <div><strong></strong> <span class="mono-id"></span></div>
            <div class="mono-id"></div>
          </div>
          <div style="display:flex; gap:0.4rem; align-items:center;">
            <span class="cand-badge"></span>
            <button type="button" class="btn-ghost">提炼工作流</button>
          </div>
        `;
        row.querySelector('strong').textContent = t.goal;
        row.querySelectorAll('.mono-id')[0].textContent = `(${t.route} · ${t.id})`;
        row.querySelectorAll('.mono-id')[1].textContent = t.assistant_message || '';
        row.querySelector('.cand-badge').textContent = t.status;
        row.querySelector('button').onclick = async () => {
          await moduleRpc('execution_hub', 'learn_workflow_from_task', {
            task_id: t.id,
            name: `${t.goal.slice(0, 14)}工作流`,
            trigger_phrase: t.goal,
          });
          this.onToast(`🧩 已从任务 ${t.id} 提取工作流`);
        };
        this.inspectorContentEl.appendChild(row);
      });
    } else {
      const res = await rpc('probe_capabilities');
      this.inspectorContentEl.innerHTML = '<pre class="code-output" style="margin-top:0;"></pre>';
      this.inspectorContentEl.querySelector('pre').textContent = JSON.stringify(res.result, null, 2);
    }
  }
}
