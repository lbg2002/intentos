/**
 * IntentOS Wave 2 — Single Floating Quick-Chat AIOS Dialog (`✦ IntentOS · 随问`)
 * Main Controller (`crates/intentosd/src/web_ui/assets/js/main.js`)
 *
 * Powers:
 * 1. Minimal Top Header + Inline `▾` Backend / Provider / Model / Effort Quick Switcher
 * 2. Slide-over `🧠` Memory & Software Translation Adapter Popover + `@` Mention Menu
 * 3. `📋` Clipboard Context Attach, `🕒` Session Switcher, `+` (`Ctrl+N`) New Chat, `🔒` Incognito, `⚙` 11-Page Settings Modal
 * 4. Incremental Markdown Chat Stream + `20px` Colored `Trace Dots` (`thinking`/`memory`/`adapter`/`approval`/`tool_ok`/`tool_err`) + `↻` Regenerate
 * 5. `backend_bridge::send_quick_chat_turn` with seamless fallback to `submit_intent` + `memory_hub` + `app_adapter`
 */

import { rpc, moduleRpc } from './rpc-client.js';
import { escapeHtml, splitThinkAndReply, renderMarkdown, streamMarkdownInto } from './markdown-renderer.js';
import {
  extractApprovalMetadata,
  normalizeTraceDots,
  buildTraceDotsFromTask,
  renderTraceDotsHeader,
} from './trace-dots.js';
import { MemoryAdapterController } from './memory-adapter-popover.js';
import { SettingsCenterController } from './settings-11pages.js';

const BACKEND_LABELS = {
  auto: '自动',
  zcode: 'ZCode',
  codex: 'Codex',
  pi: 'Pi',
  openai: 'OpenAI',
  fallback: 'IntentOS',
};

const EFFORT_LABELS = {
  default: '',
  fast: '快',
  medium: '标准',
  high: '深入',
};

const SECURITY_MODE_LABELS = {
  strict: '严格审批',
  balanced: '平衡防护',
  developer: '开发者模式',
};

const THEME_STORAGE_KEY = 'intentos-theme';

class QuickChatDialogApp {
  constructor() {
    this.incognitoMode = false;
    this.isBusy = false;
    this.activeAbortController = null;
    this.activeTurnId = null;

    this.currentSessionId = `ses_${Date.now().toString(36)}`;
    this.turns = []; // [{ id, userText, clipboardContext, mentions, replyMarkdown, traceDots, modelLabel, task }]
    this.localSessionsCache = new Map();

    // Backend & Model state
    this.catalog = {
      active: {
        backend: 'auto',
        provider: 'auto',
        model: 'deepseek-chat',
        reasoning_effort: 'default',
      },
      backends: {},
    };
    this.activePresetId = 'deepseek';
    this.modelSearchQuery = '';

    // Security Posture state (`strict` | `balanced` | `developer` + session scope grants)
    this.securityPosture = {
      security_mode: 'balanced',
      authorized_roots: [],
      approved_roots: [],
      session_grants: [],
      pending_approvals_count: 0,
    };

    // Attached composer state
    this.clipboardContext = '';
    this.attachedMentions = []; // [{ tag, entity }]

    // Input history recall (`↑` / `↓`)
    this.inputHistory = [];
    this.historyCursor = -1;
    this.historyDraft = '';
    this.isImeComposing = false;

    // Undo toast state
    this.lastChangesetId = null;
    this.undoCountdownTimer = null;
    this.undoSecondsLeft = 0;

    // Session-scoped granted capabilities
    this.sessionScopedGrants = new Set();

    // Voice recognition (ASR) state
    this.speechOverview = null;
    this.isVoiceRecording = false;
    this.isVoiceTranscribing = false;
    this.voiceTimer = null;
    this.voiceStartedAt = 0;
    this.defaultPlaceholder = '';

    // Drag offset for floating desktop dialog
    this.dragOffset = { x: 0, y: 0 };
  }

  async init() {
    this.cacheDom();
    this.initTheme();
    this.initSubcontrollers();
    this.bindEvents();
    this.bindFloatingDrag();
    this.autoResizeTextarea();

    await Promise.all([
      this.refreshBackendCatalog({ refreshRemote: true }),
      this.refreshSecurityPosture(),
      this.refreshSpeechOverview(),
      this.memoryController.refreshSnapshot(false),
    ]);
  }

  cacheDom() {
    this.dialogEl = document.getElementById('quick-chat-dialog');
    this.dragHeaderEl = document.getElementById('qc-drag-header');
    this.sparkleEl = document.getElementById('qc-status-sparkle');

    // Engine switcher & searchable `/v1/models` picker
    this.btnEnginePill = document.getElementById('btn-engine-pill');
    this.enginePillLabel = document.getElementById('qc-engine-pill-label');
    this.engineStripEl = document.getElementById('qc-engine-strip');
    this.backendGroupEl = document.getElementById('qc-backend-group');
    this.providerSelectEl = document.getElementById('qc-provider-select');
    this.btnRefreshModels = document.getElementById('btn-refresh-models');
    this.modelSearchEl = document.getElementById('qc-model-search');
    this.modelPickerListEl = document.getElementById('qc-model-picker-list');
    this.modelRefreshStatusEl = document.getElementById('qc-model-refresh-status');
    this.modelInputEl = document.getElementById('qc-model-input');
    this.modelDatalistEl = document.getElementById('qc-model-datalist');
    this.effortGroupEl = document.getElementById('qc-effort-group');
    this.openaiConfigEl = document.getElementById('qc-openai-config');

    // Security Posture Pill & Popover (`🛡`)
    this.btnSecurityPill = document.getElementById('btn-security-pill');
    this.securityPillLabel = document.getElementById('qc-security-pill-label');
    this.securityPopoverEl = document.getElementById('qc-security-popover');

    // Header buttons
    this.btnClipboard = document.getElementById('btn-clipboard-attach');
    this.btnMemory = document.getElementById('btn-memory-popover');
    this.btnSessionHistory = document.getElementById('btn-session-history');
    this.btnNewChat = document.getElementById('btn-new-chat');
    this.btnIncognito = document.getElementById('btn-incognito');
    this.btnHeaderThemeToggle = document.getElementById('btn-header-theme-toggle');
    this.btnOpenSettings = document.getElementById('btn-open-settings');
    this.btnThemeToggle = document.getElementById('btn-theme-toggle');

    // Popovers & Stream
    this.memoryPopoverEl = document.getElementById('qc-memory-popover');
    this.sessionsPopoverEl = document.getElementById('qc-sessions-popover');
    this.chatStreamEl = document.getElementById('qc-chat-stream');
    this.emptyStateEl = document.getElementById('qc-empty-state');
    this.messagesListEl = document.getElementById('qc-messages-list');

    // Composer
    this.mentionMenuEl = document.getElementById('qc-mention-menu');
    this.contextStripEl = document.getElementById('qc-context-strip');
    this.pasteBarEl = document.getElementById('qc-paste-bar');
    this.pasteInputEl = document.getElementById('qc-paste-input');
    this.voiceBannerEl = document.getElementById('qc-voice-banner');
    this.inputEl = document.getElementById('intent-input');
    this.defaultPlaceholder =
      (this.inputEl && this.inputEl.getAttribute('placeholder')) ||
      '随问任何事、输入 @ 引用文件大纲与软件… (Enter 发送 · Shift+Enter 换行)';
    this.btnVoiceInput = document.getElementById('btn-voice-input');
    this.btnSubmit = document.getElementById('btn-submit-intent');

    // Toast
    this.undoToastEl = document.getElementById('undo-toast-banner');
    this.undoToastTextEl = document.getElementById('undo-toast-text');
    this.undoCountdownEl = document.getElementById('undo-countdown-ring');
  }

  initTheme() {
    let resolved = 'dark';
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved === 'light' || saved === 'dark') {
        resolved = saved;
      } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        resolved = 'light';
      }
    } catch (_) {}

    this.applyThemeAttribute(resolved, false);

    if (window.matchMedia) {
      const mq = window.matchMedia('(prefers-color-scheme: light)');
      const onSchemeChange = (ev) => {
        try {
          const pinned = localStorage.getItem(THEME_STORAGE_KEY);
          if (pinned !== 'light' && pinned !== 'dark') {
            this.applyThemeAttribute(ev.matches ? 'light' : 'dark', false);
          }
        } catch (_) {}
      };
      if (typeof mq.addEventListener === 'function') {
        mq.addEventListener('change', onSchemeChange);
      }
    }
  }

  applyThemeAttribute(theme, persist = true) {
    const next = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    if (persist) {
      try {
        localStorage.setItem(THEME_STORAGE_KEY, next);
      } catch (_) {}
    }
    if (this.btnThemeToggle) {
      this.btnThemeToggle.textContent = next === 'light' ? '◑ 深色' : '◑ 浅色';
    }
    if (this.btnHeaderThemeToggle) {
      this.btnHeaderThemeToggle.title =
        next === 'light'
          ? '当前为浅色高对比度主题 · 点击切换深色主题'
          : '当前为深色主题 · 点击切换浅色高对比度主题';
    }
  }

  toggleTheme() {
    const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    const next = cur === 'dark' ? 'light' : 'dark';
    this.applyThemeAttribute(next, true);
    this.showToast(
      next === 'light' ? '◑ 已切换为浅色高对比度主题' : '◑ 已切换为深色主题'
    );
  }

  initSubcontrollers() {
    this.memoryController = new MemoryAdapterController({
      popoverEl: this.memoryPopoverEl,
      mentionMenuEl: this.mentionMenuEl,
      inputEl: this.inputEl,
      onInsertMention: (tag, entity, alreadyInInput = false) => {
        if (!alreadyInInput && this.inputEl) {
          const cur = this.inputEl.value;
          const prefix = cur && !cur.endsWith(' ') ? `${cur} ` : cur;
          this.inputEl.value = `${prefix}@${tag} `;
          this.autoResizeTextarea();
          this.inputEl.focus();
        }
        if (entity) {
          const exists = this.attachedMentions.some((m) => m.tag === tag);
          if (!exists) {
            this.attachedMentions.push({ tag, entity });
            this.renderContextStrip();
          }
        }
      },
      onQuickAction: (promptText) => {
        this.sendTurn(promptText);
      },
      onOpenAdapterWorkbench: (appQuery = '') => {
        this.memoryController.closePopover();
        if (this.settingsCenter) {
          this.settingsCenter.open('capabilities', { prefillAppQuery: appQuery });
        }
      },
      getSessionId: () => (this.incognitoMode ? null : this.currentSessionId),
      onToast: (msg) => this.showToast(msg),
    });

    this.settingsCenter = new SettingsCenterController({
      modalEl: document.getElementById('settings-modal'),
      sidebarEl: document.getElementById('settings-sidebar-nav'),
      contentEl: document.getElementById('settings-modal-body'),
      onToast: (msg) => this.showToast(msg),
      onStatusRefresh: async () => {
        await Promise.all([
          this.refreshBackendCatalog({ refreshRemote: true }),
          this.refreshSecurityPosture(),
          this.refreshSpeechOverview(),
        ]);
      },
      onTranscriptToggle: () => {},
    });
  }

  /* ================= Floating Dialog Drag ================= */
  bindFloatingDrag() {
    if (!this.dragHeaderEl || !this.dialogEl) return;
    let dragging = false;
    let startX = 0;
    let startY = 0;
    let origX = 0;
    let origY = 0;

    this.dragHeaderEl.addEventListener('pointerdown', (e) => {
      if (e.target.closest('button, input, select')) return;
      dragging = true;
      startX = e.clientX;
      startY = e.clientY;
      origX = this.dragOffset.x;
      origY = this.dragOffset.y;
      this.dragHeaderEl.setPointerCapture(e.pointerId);
    });

    this.dragHeaderEl.addEventListener('pointermove', (e) => {
      if (!dragging) return;
      const maxDx = Math.max(40, (window.innerWidth - this.dialogEl.offsetWidth) / 2);
      const maxDy = Math.max(24, (window.innerHeight - this.dialogEl.offsetHeight) / 2);
      this.dragOffset.x = Math.min(maxDx, Math.max(-maxDx, origX + (e.clientX - startX)));
      this.dragOffset.y = Math.min(maxDy, Math.max(-maxDy, origY + (e.clientY - startY)));
      this.dialogEl.style.transform = `translate3d(${this.dragOffset.x}px, ${this.dragOffset.y}px, 0)`;
    });

    const endDrag = () => {
      dragging = false;
    };
    this.dragHeaderEl.addEventListener('pointerup', endDrag);
    this.dragHeaderEl.addEventListener('pointercancel', endDrag);

    this.dragHeaderEl.addEventListener('dblclick', (e) => {
      if (e.target.closest('button')) return;
      this.dragOffset = { x: 0, y: 0 };
      this.dialogEl.style.transform = '';
    });
  }

  /* ================= Backend Catalog, Live `/v1/models` & Searchable Switcher (`▾`) ================= */
  async refreshBackendCatalog(opts = {}) {
    const refreshRemote = opts.refreshRemote !== undefined ? Boolean(opts.refreshRemote) : true;
    const forceRefresh = Boolean(opts.forceRefresh);

    let catRes = null;
    if (forceRefresh) {
      const refRes = await moduleRpc(
        'backend_bridge',
        'refresh_models',
        { force_refresh: true },
        async () => null
      );
      if (refRes && refRes.ok && refRes.result && refRes.result.active && refRes.result.backends) {
        catRes = refRes;
      } else {
        catRes = await moduleRpc(
          'backend_bridge',
          'get_backends_catalog',
          { refresh_remote: true, force_refresh: true },
          async () => null
        );
      }
    } else {
      catRes = await moduleRpc(
        'backend_bridge',
        'get_backends_catalog',
        { refresh_remote: refreshRemote },
        async () => null
      );
    }

    const [stRes, domRes] = await Promise.all([
      rpc('get_status'),
      moduleRpc('config_center', 'get_all_domains', {}, async () => null),
    ]);

    const st = (stRes && stRes.ok && stRes.result) || {};
    const dom = (domRes && domRes.ok && domRes.result) || {};

    if (catRes && catRes.ok && catRes.result && catRes.result.active) {
      this.catalog = catRes.result;
    } else {
      // Build clean catalog from config_center / status when backend_bridge is in stub mode
      const brain = dom.brain || {};
      const mainProfile = (brain.profiles && brain.profiles.main) || {};
      const providers = Array.isArray(brain.providers) ? brain.providers : [];
      this.catalog = {
        active: {
          backend: st.main_model_configured ? 'openai' : 'auto',
          provider: mainProfile.provider || (providers[0] && providers[0].id) || 'auto',
          model: mainProfile.model || (st.main_model_configured ? 'deepseek-chat' : 'AIOS 混合引擎'),
          reasoning_effort: mainProfile.thinking || 'default',
        },
        backends: {
          zcode: { available: false, providers: [], models: ['glm-4.7', 'glm-4.5'] },
          codex: { available: false, providers: [], models: ['gpt-5-codex', 'o4-mini'] },
          pi: { available: false, providers: [], models: ['claude-sonnet-4'] },
          openai: {
            available: Boolean(st.main_model_configured),
            providers: providers.map((p) => ({
              id: p.id,
              name: p.name || p.id,
              models: p.available_models || [p.default_model || 'deepseek-chat'],
            })),
            models: ['deepseek-chat', 'deepseek-reasoner', 'gpt-4o-mini', 'qwen-plus', 'qwen2.5:7b'],
          },
        },
      };
    }

    this.syncEngineStripUI();
  }

  async handleManualRefreshModels() {
    if (this.btnRefreshModels) {
      this.btnRefreshModels.disabled = true;
      this.btnRefreshModels.textContent = '⏳ 正在同步…';
    }
    if (this.modelRefreshStatusEl) {
      this.modelRefreshStatusEl.hidden = false;
      this.modelRefreshStatusEl.textContent = '⏳ 正在实时查询各供应商 /v1/models 接口…';
    }

    try {
      await this.refreshBackendCatalog({ refreshRemote: true, forceRefresh: true });
      const active = this.catalog.active || {};
      const opts = this.collectAvailableModelOptions(active.backend || 'auto', active.provider || 'auto');
      if (this.modelRefreshStatusEl) {
        this.modelRefreshStatusEl.hidden = false;
        this.modelRefreshStatusEl.textContent = `✓ 已实时同步 ${opts.length} 个接口模型`;
      }
      this.showToast(`↻ 已从接口刷新 ${opts.length} 个可用模型`);
    } finally {
      if (this.btnRefreshModels) {
        this.btnRefreshModels.disabled = false;
        this.btnRefreshModels.textContent = '↻ 刷新接口模型';
      }
    }
  }

  collectAvailableModelOptions(backendKey = 'auto', providerKey = 'auto') {
    const backendsMap = (this.catalog && this.catalog.backends) || {};
    const orderedKeys = ['zcode', 'codex', 'openai', 'pi'];
    const entries =
      backendKey && backendKey !== 'auto' && backendsMap[backendKey]
        ? [[backendKey, backendsMap[backendKey]]]
        : [
            ...orderedKeys
              .filter((k) => backendsMap[k] && backendsMap[k].available)
              .map((k) => [k, backendsMap[k]]),
            ...Object.entries(backendsMap).filter(
              ([k, v]) => !orderedKeys.includes(k) || !v || !v.available
            ),
          ];

    const options = [];
    const seen = new Set();

    entries.forEach(([bKey, bInfo]) => {
      if (!bInfo) return;
      const provs = Array.isArray(bInfo.providers) ? bInfo.providers : [];
      provs.forEach((p) => {
        const pId = typeof p === 'string' ? p : p.id || p.name;
        const pName = typeof p === 'string' ? p : p.name || p.id || bKey;
        if (providerKey && providerKey !== 'auto' && pId !== providerKey) return;
        const models = Array.isArray(p && p.models) ? p.models : [];
        models.forEach((rawM) => {
          const mId = typeof rawM === 'string' ? rawM : rawM && (rawM.id || rawM.name);
          if (!mId) return;
          const sig = `${bKey}::${pId}::${mId}`;
          if (seen.has(sig)) return;
          seen.add(sig);
          options.push({
            model: mId,
            backend: bKey,
            provider: pId || 'auto',
            providerName: pName,
            liveFetched: Boolean(p && p.live_models_fetched),
          });
        });
      });

      if (!providerKey || providerKey === 'auto') {
        const topModels = Array.isArray(bInfo.models) ? bInfo.models : [];
        topModels.forEach((rawM) => {
          const mId = typeof rawM === 'string' ? rawM : rawM && (rawM.id || rawM.name);
          if (!mId) return;
          if (options.some((o) => o.model === mId && o.backend === bKey)) return;
          options.push({
            model: mId,
            backend: bKey,
            provider: bInfo.default_provider || 'auto',
            providerName: BACKEND_LABELS[bKey] || bKey,
            liveFetched: false,
          });
        });
      }
    });

    if (options.length === 0) {
      ['glm-4.7', 'deepseek-chat', 'deepseek-reasoner', 'gpt-4o', 'gpt-4o-mini', 'qwen-plus', 'qwen2.5:7b'].forEach(
        (m) => {
          options.push({
            model: m,
            backend: backendKey === 'auto' ? 'openai' : backendKey,
            provider: providerKey || 'auto',
            providerName: '预设',
            liveFetched: false,
          });
        }
      );
    }

    return options;
  }

  renderSearchableModelPicker() {
    const active = this.catalog.active || {};
    const backendKey = active.backend || 'auto';
    const providerKey =
      (this.providerSelectEl && this.providerSelectEl.value) || active.provider || 'auto';
    const allOptions = this.collectAvailableModelOptions(backendKey, providerKey);

    if (this.modelSearchEl) {
      this.modelSearchEl.placeholder = `搜索模型 (共 ${allOptions.length} 个)...`;
    }

    if (!this.modelPickerListEl) return;
    this.modelPickerListEl.innerHTML = '';

    const kw = (this.modelSearchQuery || '').trim().toLowerCase();
    const filtered = kw
      ? allOptions.filter(
          (opt) =>
            opt.model.toLowerCase().includes(kw) ||
            String(opt.provider).toLowerCase().includes(kw) ||
            String(opt.providerName).toLowerCase().includes(kw) ||
            String(opt.backend).toLowerCase().includes(kw)
        )
      : allOptions;

    if (filtered.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'qc-model-picker-empty';
      empty.textContent = kw
        ? `未找到包含「${this.modelSearchQuery}」的接口模型，可直接在右侧输入自定义模型名或点击「↻ 刷新接口模型」`
        : '暂无可选模型，请点击「↻ 刷新接口模型」';
      this.modelPickerListEl.appendChild(empty);
      return;
    }

    filtered.forEach((opt) => {
      const isSelected =
        opt.model === active.model &&
        (providerKey === 'auto' || opt.provider === active.provider || !active.provider);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.setAttribute('role', 'option');
      btn.setAttribute('aria-selected', String(isSelected));
      btn.className = 'qc-model-option-btn' + (isSelected ? ' active' : '');

      const metaTag =
        opt.provider && opt.provider !== 'auto'
          ? `${opt.provider}${opt.liveFetched ? ' · 实时' : ''}`
          : `${BACKEND_LABELS[opt.backend] || opt.backend}${opt.liveFetched ? ' · 实时' : ''}`;

      btn.innerHTML = `
        <span class="qc-model-option-name">${escapeHtml(opt.model)}</span>
        <span class="qc-model-option-meta">${escapeHtml(metaTag)}</span>
      `;
      btn.onclick = () => {
        if (this.modelInputEl) {
          this.modelInputEl.value = opt.model;
        }
        const nextBackend = backendKey === 'auto' && opt.backend ? opt.backend : backendKey;
        const nextProvider = providerKey === 'auto' && opt.provider ? opt.provider : providerKey;
        this.applyBackendSelection({
          backend: nextBackend,
          provider: nextProvider,
          model: opt.model,
        });
        this.showToast(`✦ 已切换模型：${opt.model}`);
      };
      this.modelPickerListEl.appendChild(btn);
    });
  }

  syncEngineStripUI() {
    const active = this.catalog.active || {};
    const backendKey = active.backend || 'auto';
    const bLabel = BACKEND_LABELS[backendKey] || backendKey;
    const mLabel = active.model || '默认模型';
    const effLabel = EFFORT_LABELS[active.reasoning_effort || 'default'];

    if (this.enginePillLabel) {
      this.enginePillLabel.textContent = `${bLabel} · ${mLabel}${effLabel ? ` · ${effLabel}` : ''}`;
    }

    // Highlight active backend pill & mark detected availability dots
    if (this.backendGroupEl) {
      this.backendGroupEl.querySelectorAll('[data-backend]').forEach((btn) => {
        const key = btn.getAttribute('data-backend');
        btn.classList.toggle('active', key === backendKey);
        const info = this.catalog.backends && this.catalog.backends[key];
        const existingDot = btn.querySelector('.qc-avail-dot');
        if (info && info.available && !existingDot) {
          const dot = document.createElement('span');
          dot.className = 'qc-avail-dot';
          dot.title = '已检测到本机配置';
          btn.prepend(dot);
        } else if ((!info || !info.available) && existingDot) {
          existingDot.remove();
        }
      });
    }

    // Populate providers across chosen backend (or all backends when `auto`)
    const backendsMap = (this.catalog && this.catalog.backends) || {};
    const rawProviders = [];
    const seenProvIds = new Set();
    const targetBackends =
      backendKey !== 'auto' && backendsMap[backendKey]
        ? [[backendKey, backendsMap[backendKey]]]
        : Object.entries(backendsMap);

    targetBackends.forEach(([bk, bInfo]) => {
      if (!bInfo || !Array.isArray(bInfo.providers)) return;
      bInfo.providers.forEach((p) => {
        const id = typeof p === 'string' ? p : p.id || p.name;
        if (!id || seenProvIds.has(id)) return;
        seenProvIds.add(id);
        rawProviders.push({ raw: p, backendKey: bk });
      });
    });

    if (this.providerSelectEl) {
      this.providerSelectEl.innerHTML = '';
      const defOpt = document.createElement('option');
      defOpt.value = 'auto';
      defOpt.textContent = '自动选择供应商 (Auto)';
      this.providerSelectEl.appendChild(defOpt);

      rawProviders.forEach(({ raw: p, backendKey: bk }) => {
        const id = typeof p === 'string' ? p : p.id || p.name;
        const name = typeof p === 'string' ? p : p.name || p.id;
        const cnt = p && Array.isArray(p.models) ? p.models.length : 0;
        if (!id) return;
        const opt = document.createElement('option');
        opt.value = id;
        opt.textContent =
          backendKey === 'auto'
            ? `${name} (${BACKEND_LABELS[bk] || bk}${cnt ? ` · ${cnt}` : ''})`
            : `${name}${cnt ? ` (${cnt} 个模型)` : ''}`;
        this.providerSelectEl.appendChild(opt);
      });

      if (active.provider && Array.from(this.providerSelectEl.options).some((o) => o.value === active.provider)) {
        this.providerSelectEl.value = active.provider;
      }
    }

    // Populate model datalist & searchable scrollable model picker (`max-height: 190px`)
    const allOptions = this.collectAvailableModelOptions(
      backendKey,
      (this.providerSelectEl && this.providerSelectEl.value) || active.provider || 'auto'
    );
    if (this.modelDatalistEl) {
      this.modelDatalistEl.innerHTML = '';
      const dlSeen = new Set();
      allOptions.forEach((o) => {
        if (!o.model || dlSeen.has(o.model)) return;
        dlSeen.add(o.model);
        const opt = document.createElement('option');
        opt.value = o.model;
        this.modelDatalistEl.appendChild(opt);
      });
    }

    if (this.modelInputEl && active.model && active.model !== 'AIOS 混合引擎') {
      this.modelInputEl.value = active.model;
    }

    this.renderSearchableModelPicker();

    // Highlight active reasoning effort
    if (this.effortGroupEl) {
      const curEff = active.reasoning_effort || 'default';
      this.effortGroupEl.querySelectorAll('[data-effort]').forEach((btn) => {
        btn.classList.toggle('active', btn.getAttribute('data-effort') === curEff);
      });
    }

    // Show inline OpenAI API quick input when `openai` is selected
    if (this.openaiConfigEl) {
      this.openaiConfigEl.hidden = backendKey !== 'openai';
    }
  }

  /* ================= Security Posture Pill & Popover (`🛡`) ================= */
  async refreshSecurityPosture() {
    const res = await moduleRpc(
      'execution_hub',
      'get_security_posture',
      {},
      async () => null
    );
    if (res && res.ok && res.result) {
      this.securityPosture = {
        security_mode: res.result.security_mode || 'balanced',
        authorized_roots: Array.isArray(res.result.authorized_roots) ? res.result.authorized_roots : [],
        approved_roots: Array.isArray(res.result.approved_roots) ? res.result.approved_roots : [],
        session_grants: Array.isArray(res.result.session_grants) ? res.result.session_grants : [],
        pending_approvals_count: Number(res.result.pending_approvals_count || 0),
      };
    }
    this.syncSecurityPillUI();
  }

  syncSecurityPillUI() {
    const mode = this.securityPosture.security_mode || 'balanced';
    const label = SECURITY_MODE_LABELS[mode] || '平衡防护';
    const grantsCount = Array.isArray(this.securityPosture.session_grants)
      ? this.securityPosture.session_grants.length
      : 0;

    if (this.btnSecurityPill) {
      this.btnSecurityPill.classList.remove('mode-strict', 'mode-balanced', 'mode-developer');
      this.btnSecurityPill.classList.add(`mode-${mode}`);
    }
    if (this.securityPillLabel) {
      this.securityPillLabel.textContent = grantsCount > 0 ? `${label} · ${grantsCount}` : label;
    }
  }

  async openSecurityPopover() {
    if (!this.securityPopoverEl) return;
    this.securityPopoverEl.hidden = false;
    await this.refreshSecurityPosture();

    const mode = this.securityPosture.security_mode || 'balanced';
    const grants = Array.isArray(this.securityPosture.session_grants)
      ? this.securityPosture.session_grants
      : [];
    const authRoots = Array.isArray(this.securityPosture.authorized_roots)
      ? this.securityPosture.authorized_roots
      : [];

    this.securityPopoverEl.innerHTML = `
      <div class="qc-popover-head">
        <div class="qc-popover-title">🛡 安全防护态势与会话放行范围</div>
        <div class="qc-popover-head-actions">
          <button type="button" class="qc-mini-btn" id="btn-sec-open-settings">完整策略设置 ↗</button>
          <button type="button" class="qc-mini-btn" id="btn-close-sec-popover">✕</button>
        </div>
      </div>
      <div class="qc-popover-scroll">
        <div class="qc-mem-section">
          <div class="qc-mem-sec-title"><span>全局审批防护等级 (Security Mode)</span></div>
          <div class="qc-sec-modes-grid">
            <button type="button" class="qc-sec-mode-btn ${mode === 'strict' ? 'active' : ''}" data-sec-mode="strict">
              <span class="qc-sec-mode-title">🔒 严格审批 (strict)</span>
              <span class="qc-sec-mode-desc">所有写入、应用操控与跨目录读取均逐次内联审批</span>
            </button>
            <button type="button" class="qc-sec-mode-btn ${mode === 'balanced' ? 'active' : ''}" data-sec-mode="balanced">
              <span class="qc-sec-mode-title">🛡 平衡防护 (balanced · 默认)</span>
              <span class="qc-sec-mode-desc">授权目录内可逆操作顺畅执行；敏感路径与强制杀进程必审</span>
            </button>
            <button type="button" class="qc-sec-mode-btn ${mode === 'developer' ? 'active' : ''}" data-sec-mode="developer">
              <span class="qc-sec-mode-title">⚡ 开发者模式 (developer)</span>
              <span class="qc-sec-mode-desc">用户工作空间免打扰，仅硬性禁区 (~/.ssh、密钥库) 与高危动作拦截</span>
            </button>
          </div>
        </div>

        <div class="qc-mem-section">
          <div class="qc-mem-sec-title">
            <span>⏱ 本会话临时放行范围 (${grants.length} 项)</span>
          </div>
          <div style="display:flex; gap:5px; margin-bottom:6px;">
            <select id="qc-sec-grant-kind" class="qc-compact-select" style="max-width:118px;">
              <option value="directory">目录范围</option>
              <option value="app">软件范围</option>
              <option value="capability">能力 ID</option>
            </select>
            <input id="qc-sec-grant-val" class="qc-compact-input" placeholder="如 /tmp/work 或 sodam" />
            <button type="button" id="qc-btn-add-grant" class="qc-mini-btn">+ 放行</button>
          </div>
          <div id="qc-sec-grants-list"></div>
        </div>

        <div class="qc-mem-section">
          <div class="qc-mem-sec-title"><span>✅ 已授权工作目录 (${authRoots.length})</span></div>
          <div class="qc-mem-empty" style="text-align:left;">
            ${
              authRoots.length > 0
                ? authRoots.map((r) => `<code>${escapeHtml(r)}</code>`).join(' · ')
                : '默认按当前工作区保护；禁区 (~/.ssh, ~/.gnupg, /etc/shadow) 永久硬件级锁定拦截。'
            }
          </div>
        </div>
      </div>
    `;

    this.securityPopoverEl.querySelector('#btn-close-sec-popover').onclick = () => {
      this.closeOverlayPopovers();
    };
    this.securityPopoverEl.querySelector('#btn-sec-open-settings').onclick = () => {
      this.closeOverlayPopovers();
      this.settingsCenter.open('skills');
    };

    this.securityPopoverEl.querySelectorAll('[data-sec-mode]').forEach((btn) => {
      btn.onclick = async () => {
        const nextMode = btn.getAttribute('data-sec-mode') || 'balanced';
        await moduleRpc(
          'execution_hub',
          'set_security_mode',
          { mode: nextMode },
          async () => ({ security_mode: nextMode })
        );
        this.securityPosture.security_mode = nextMode;
        this.syncSecurityPillUI();
        this.showToast(`🛡 已切换安全防护模式：${SECURITY_MODE_LABELS[nextMode] || nextMode}`);
        await this.openSecurityPopover();
      };
    });

    this.securityPopoverEl.querySelector('#qc-btn-add-grant').onclick = async () => {
      const scope_kind = this.securityPopoverEl.querySelector('#qc-sec-grant-kind').value;
      const scope_value = this.securityPopoverEl.querySelector('#qc-sec-grant-val').value.trim();
      if (!scope_value) return;
      const gr = await moduleRpc(
        'execution_hub',
        'grant_session_scope',
        { scope_kind, scope_value, ttl_minutes: 60 },
        async () => null
      );
      if (gr && gr.ok) {
        this.showToast(`⏱ 本会话已放行：${scope_value}`);
        await this.openSecurityPopover();
      } else {
        this.showToast(`⚠️ 拒绝放行受保护禁区: ${(gr && gr.error) || scope_value}`);
      }
    };

    const grantsListEl = this.securityPopoverEl.querySelector('#qc-sec-grants-list');
    if (grants.length === 0) {
      grantsListEl.innerHTML =
        '<div class="qc-mem-empty">暂无临时放行记录（在黄色内联审批卡片点击「⏱ 本会话放行此范围」后将在此处列出并可随时收回）。</div>';
    } else {
      grants.forEach((g) => {
        const row = document.createElement('div');
        row.className = 'qc-sec-grant-item';
        row.innerHTML = `
          <div style="min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
            <strong>[${escapeHtml(g.scope_kind || 'scope')}]</strong>
            <code>${escapeHtml(g.scope_value || '')}</code>
          </div>
          <button type="button" class="qc-mini-btn">✕ 收回</button>
        `;
        row.querySelector('button').onclick = async () => {
          await moduleRpc(
            'execution_hub',
            'revoke_session_grant',
            { id: g.id },
            async () => null
          );
          this.showToast(`已收回放行范围：${g.scope_value}`);
          await this.openSecurityPopover();
        };
        grantsListEl.appendChild(row);
      });
    }
  }

  async applyBackendSelection(patch = {}) {
    this.catalog.active = {
      ...(this.catalog.active || {}),
      ...patch,
    };
    this.syncEngineStripUI();

    await moduleRpc(
      'backend_bridge',
      'set_active_backend',
      {
        backend: this.catalog.active.backend,
        provider: this.catalog.active.provider,
        model: this.catalog.active.model,
        reasoning_effort: this.catalog.active.reasoning_effort,
      },
      async () => ({ saved: true, active: this.catalog.active })
    );
  }

  async saveQuickOpenAiKey() {
    const urlEl = document.getElementById('quick-llm-url');
    const keyEl = document.getElementById('quick-llm-key');
    const statusEl = document.getElementById('quick-llm-status');

    const baseUrl = (urlEl ? urlEl.value : '').trim();
    const model = (this.modelInputEl ? this.modelInputEl.value : '').trim() || 'deepseek-chat';
    const apiKey = (keyEl ? keyEl.value : '').trim();
    const isLocal = baseUrl.includes('127.0.0.1') || baseUrl.includes('localhost');

    if (!baseUrl) {
      if (statusEl) statusEl.textContent = '❌ 请填写 API Base URL';
      return;
    }
    if (!isLocal && !apiKey) {
      if (statusEl) statusEl.textContent = '⚠️ 远程 OpenAI 兼容接口需填写 API Key';
      return;
    }

    const providerId = this.activePresetId || 'openai-custom';
    if (statusEl) statusEl.textContent = '⏳ 正在存入 0600 密钥库并激活模型…';

    await Promise.all([
      moduleRpc('config_center', 'upsert_provider', {
        id: providerId,
        name: providerId.toUpperCase(),
        kind: isLocal ? 'ollama-local' : 'openai-compatible',
        base_url: baseUrl,
        api_key: apiKey,
        trust: isLocal ? 'local_full' : 'standard',
        enabled: true,
        default_model: model,
      }),
      moduleRpc('config_center', 'update_model_profiles', {
        default_profile: 'main',
        profiles: {
          main: { provider: providerId, model },
          fast: { provider: providerId, model },
          decision: { provider: providerId, model },
        },
      }),
      moduleRpc(
        'backend_bridge',
        'set_active_backend',
        {
          backend: 'openai',
          provider: providerId,
          model,
          reasoning_effort: this.catalog.active.reasoning_effort || 'default',
          base_url: baseUrl,
          api_key: apiKey,
        },
        async () => ({ saved: true })
      ),
    ]);

    if (keyEl) keyEl.value = '';
    this.catalog.active.backend = 'openai';
    this.catalog.active.provider = providerId;
    this.catalog.active.model = model;
    this.syncEngineStripUI();

    if (statusEl) {
      statusEl.textContent = `✓ 已保存并激活 ${providerId} · ${model}`;
    }
    this.showToast(`✦ 已切换模型：OpenAI · ${model}`);
  }

  /* ================= DOM & Keyboard Event Bindings ================= */
  bindEvents() {
    // 1. Engine Switcher Pill (`▾`)
    if (this.btnEnginePill) {
      this.btnEnginePill.onclick = () => {
        const willOpen = this.engineStripEl.hidden;
        this.closeOverlayPopovers();
        this.engineStripEl.hidden = !willOpen;
        this.btnEnginePill.classList.toggle('open', willOpen);
        this.btnEnginePill.setAttribute('aria-expanded', String(willOpen));
      };
    }

    if (this.backendGroupEl) {
      this.backendGroupEl.querySelectorAll('[data-backend]').forEach((btn) => {
        btn.onclick = () => {
          const backend = btn.getAttribute('data-backend') || 'auto';
          const bInfo = this.catalog.backends && this.catalog.backends[backend];
          const defaultProvider = (bInfo && bInfo.default_provider) || 'auto';
          const defaultModel =
            (bInfo && bInfo.default_model) ||
            (bInfo && Array.isArray(bInfo.models) && bInfo.models[0]) ||
            (backend === 'zcode'
              ? 'glm-4.7'
              : backend === 'codex'
              ? 'gpt-5-codex'
              : backend === 'pi'
              ? 'claude-sonnet-4'
              : this.catalog.active.model || 'deepseek-chat');
          this.applyBackendSelection({ backend, provider: defaultProvider, model: defaultModel });
        };
      });
    }

    if (this.providerSelectEl) {
      this.providerSelectEl.onchange = () => {
        this.applyBackendSelection({ provider: this.providerSelectEl.value });
      };
    }

    if (this.btnRefreshModels) {
      this.btnRefreshModels.onclick = () => this.handleManualRefreshModels();
    }

    if (this.modelSearchEl) {
      this.modelSearchEl.addEventListener('input', () => {
        this.modelSearchQuery = this.modelSearchEl.value || '';
        this.renderSearchableModelPicker();
      });
      this.modelSearchEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const firstBtn =
            this.modelPickerListEl && this.modelPickerListEl.querySelector('.qc-model-option-btn');
          if (firstBtn) firstBtn.click();
        }
      });
    }

    if (this.modelInputEl) {
      this.modelInputEl.onchange = () => {
        const m = this.modelInputEl.value.trim();
        if (m) this.applyBackendSelection({ model: m });
      };
    }

    if (this.effortGroupEl) {
      this.effortGroupEl.querySelectorAll('[data-effort]').forEach((btn) => {
        btn.onclick = () => {
          const reasoning_effort = btn.getAttribute('data-effort') || 'default';
          this.applyBackendSelection({ reasoning_effort });
        };
      });
    }

    document.querySelectorAll('.llm-preset-btn').forEach((btn) => {
      btn.onclick = () => {
        this.activePresetId = btn.getAttribute('data-id') || 'deepseek';
        const urlEl = document.getElementById('quick-llm-url');
        const m = btn.getAttribute('data-model') || 'deepseek-chat';
        if (urlEl) urlEl.value = btn.getAttribute('data-url') || '';
        if (this.modelInputEl) this.modelInputEl.value = m;
        this.catalog.active.model = m;
        this.syncEngineStripUI();
      };
    });

    const btnSaveQuick = document.getElementById('btn-save-quick-llm');
    if (btnSaveQuick) {
      btnSaveQuick.onclick = () => this.saveQuickOpenAiKey();
    }

    if (this.btnThemeToggle) {
      this.btnThemeToggle.onclick = () => this.toggleTheme();
    }
    if (this.btnHeaderThemeToggle) {
      this.btnHeaderThemeToggle.onclick = () => this.toggleTheme();
    }

    // 1b. Header Security Posture Pill (`🛡`)
    if (this.btnSecurityPill) {
      this.btnSecurityPill.onclick = async () => {
        const willOpen = !this.securityPopoverEl || this.securityPopoverEl.hidden;
        this.closeOverlayPopovers();
        if (willOpen) {
          this.btnSecurityPill.classList.add('active');
          this.btnSecurityPill.setAttribute('aria-expanded', 'true');
          await this.openSecurityPopover();
        }
      };
    }

    // 2. Header Right Buttons (`📋`, `🧠`, `🕒`, `+`, `🔒`, `⚙`)
    if (this.btnClipboard) {
      this.btnClipboard.onclick = () => this.handleClipboardAttach();
    }

    const btnConfirmPaste = document.getElementById('btn-confirm-paste');
    const btnCancelPaste = document.getElementById('btn-cancel-paste');
    if (btnConfirmPaste) {
      btnConfirmPaste.onclick = () => this.confirmManualPaste();
    }
    if (btnCancelPaste) {
      btnCancelPaste.onclick = () => {
        if (this.pasteBarEl) this.pasteBarEl.hidden = true;
      };
    }
    if (this.pasteInputEl) {
      this.pasteInputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          this.confirmManualPaste();
        } else if (e.key === 'Escape') {
          e.preventDefault();
          this.pasteBarEl.hidden = true;
          this.inputEl.focus();
        }
      });
    }

    if (this.btnMemory) {
      this.btnMemory.onclick = async () => {
        const willOpen = !this.memoryController.isOpen();
        this.closeOverlayPopovers();
        if (willOpen) {
          this.btnMemory.classList.add('active');
          await this.memoryController.openPopover();
        }
      };
    }

    if (this.btnSessionHistory) {
      this.btnSessionHistory.onclick = async () => {
        const willOpen = this.sessionsPopoverEl.hidden;
        this.closeOverlayPopovers();
        if (willOpen) {
          this.btnSessionHistory.classList.add('active');
          await this.openSessionsPopover();
        }
      };
    }

    if (this.btnNewChat) {
      this.btnNewChat.onclick = () => this.startNewChat();
    }

    if (this.btnIncognito) {
      this.btnIncognito.onclick = () => this.toggleIncognito();
    }

    if (this.btnOpenSettings) {
      this.btnOpenSettings.onclick = () => {
        this.closeOverlayPopovers();
        this.settingsCenter.open();
      };
    }

    const btnCloseSettings = document.getElementById('btn-close-settings');
    if (btnCloseSettings) {
      btnCloseSettings.onclick = () => this.settingsCenter.close();
    }
    const settingsModal = document.getElementById('settings-modal');
    if (settingsModal) {
      settingsModal.addEventListener('click', (e) => {
        if (e.target === settingsModal) this.settingsCenter.close();
      });
    }

    // 3. Welcome Starter Pills
    document.querySelectorAll('.qc-starter-pill').forEach((pill) => {
      pill.onclick = () => {
        const prompt = pill.getAttribute('data-prompt') || pill.textContent.trim();
        this.sendTurn(prompt);
      };
    });

    // 4. Undo Toast Buttons
    const btnToastUndo = document.getElementById('btn-toast-undo');
    const btnToastDismiss = document.getElementById('btn-toast-dismiss');
    if (btnToastUndo) {
      btnToastUndo.onclick = () => this.triggerUndo(this.lastChangesetId);
    }
    if (btnToastDismiss) {
      btnToastDismiss.onclick = () => this.hideUndoToast();
    }

    // 5. Composer `<textarea>` & Send/Stop button
    if (this.inputEl) {
      this.inputEl.addEventListener('compositionstart', () => {
        this.isImeComposing = true;
      });
      this.inputEl.addEventListener('compositionend', () => {
        this.isImeComposing = false;
        this.memoryController.handleInputForMention();
      });
      this.inputEl.addEventListener('input', () => {
        this.autoResizeTextarea();
        if (!this.isImeComposing) {
          this.memoryController.handleInputForMention();
        }
      });
      this.inputEl.addEventListener('keydown', (e) => this.handleComposerKeydown(e));
    }

    if (this.btnVoiceInput) {
      this.btnVoiceInput.onclick = () => this.handleVoiceMicClick();
    }

    if (this.btnSubmit) {
      this.btnSubmit.onclick = () => {
        if (this.isBusy) {
          this.cancelActiveTurn();
        } else {
          this.sendTurn(this.inputEl.value);
        }
      };
    }

    // 6. Global Keyboard Shortcuts (`Esc`, `Ctrl+N`, `Ctrl+,`, `Ctrl+Z`)
    document.addEventListener('keydown', (e) => {
      const ctrl = e.ctrlKey || e.metaKey;

      if (ctrl && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        this.startNewChat();
        return;
      }

      if (ctrl && e.key === ',') {
        e.preventDefault();
        if (this.settingsCenter.isOpen()) {
          this.settingsCenter.close();
        } else {
          this.closeOverlayPopovers();
          this.settingsCenter.open();
        }
        return;
      }

      if (ctrl && !e.shiftKey && e.key.toLowerCase() === 'z') {
        const inInputWithText =
          document.activeElement === this.inputEl && this.inputEl.value.trim().length > 0;
        if (!inInputWithText && !this.settingsCenter.isOpen()) {
          e.preventDefault();
          this.triggerUndo(this.lastChangesetId);
        }
        return;
      }

      if (e.key === 'Escape') {
        if (this.isVoiceRecording) {
          e.preventDefault();
          this.cancelVoiceRecording();
          return;
        }
        if (this.memoryController.mentionOpen) {
          e.preventDefault();
          this.memoryController.closeMentionMenu();
          return;
        }
        if (this.settingsCenter.isOpen()) {
          e.preventDefault();
          this.settingsCenter.close();
          return;
        }
        if (this.hasOpenOverlayPopover()) {
          e.preventDefault();
          this.closeOverlayPopovers();
          return;
        }
        if (this.isBusy) {
          e.preventDefault();
          this.cancelActiveTurn();
        }
      }
    });
  }

  /* ================= Voice Recognition (ASR) Input (`🎙`) ================= */
  async refreshSpeechOverview() {
    const res = await moduleRpc('speech_hub', 'get_speech_overview', {}, async () => null);
    if (res && res.ok && res.result && res.result.status !== 'stub') {
      this.speechOverview = res.result;
    }
    this.syncVoiceMicBadge();
    return this.speechOverview;
  }

  syncVoiceMicBadge() {
    if (!this.btnVoiceInput || this.isVoiceRecording || this.isVoiceTranscribing) return;
    const cfg = (this.speechOverview && this.speechOverview.config) || {};
    const models = (this.speechOverview && Array.isArray(this.speechOverview.models))
      ? this.speechOverview.models
      : [];
    const hasInstalled = models.some((m) => m.installed);
    const activeModel = models.find((m) => m.id === cfg.active_model_id && m.installed);
    if (cfg.enabled && hasInstalled) {
      this.btnVoiceInput.classList.add('is-ready');
      this.btnVoiceInput.title = `本地离线语音识别输入 (${
        (activeModel && activeModel.name) || cfg.active_model_id || '已就绪'
      } · 点击开始录音)`;
    } else {
      this.btnVoiceInput.classList.remove('is-ready');
      this.btnVoiceInput.title =
        '语音识别输入 (点击查看本地离线 ASR 模型下载与启用设置)';
    }
  }

  hideVoiceBanner() {
    if (this.voiceBannerEl) {
      this.voiceBannerEl.hidden = true;
      this.voiceBannerEl.innerHTML = '';
    }
  }

  renderVoiceSetupBanner(reasonText, hasInstalledModel, isDisabled) {
    if (!this.voiceBannerEl) {
      this.showToast(reasonText);
      return;
    }
    this.voiceBannerEl.hidden = false;
    this.voiceBannerEl.innerHTML = `
      <div class="qc-voice-banner-text">${escapeHtml(reasonText)}</div>
      <div class="qc-voice-banner-actions">
        ${
          hasInstalledModel && isDisabled
            ? '<button type="button" class="qc-mini-btn primary" id="btn-voice-quick-enable">⚡ 立即开启并录音</button>'
            : ''
        }
        <button type="button" class="qc-mini-btn" id="btn-voice-open-settings">⚙ 打开语音识别模型下载与开关设置</button>
        <button type="button" class="qc-mini-btn" id="btn-voice-close-banner" title="关闭提示">✕</button>
      </div>
    `;

    const btnOpen = this.voiceBannerEl.querySelector('#btn-voice-open-settings');
    if (btnOpen) {
      btnOpen.onclick = () => {
        this.hideVoiceBanner();
        this.closeOverlayPopovers();
        if (this.settingsCenter) {
          this.settingsCenter.open('speech');
        }
      };
    }

    const btnQuickEnable = this.voiceBannerEl.querySelector('#btn-voice-quick-enable');
    if (btnQuickEnable) {
      btnQuickEnable.onclick = async () => {
        btnQuickEnable.disabled = true;
        btnQuickEnable.textContent = '开启中…';
        await moduleRpc(
          'speech_hub',
          'update_speech_config',
          { enabled: true },
          async () => null
        );
        await this.refreshSpeechOverview();
        this.hideVoiceBanner();
        await this.startVoiceRecordingFlow();
      };
    }

    const btnClose = this.voiceBannerEl.querySelector('#btn-voice-close-banner');
    if (btnClose) {
      btnClose.onclick = () => this.hideVoiceBanner();
    }
  }

  async handleVoiceMicClick() {
    if (this.isVoiceTranscribing) return;
    if (this.isVoiceRecording) {
      await this.stopVoiceAndTranscribe();
      return;
    }

    const ov = await this.refreshSpeechOverview();
    const cfg = (ov && ov.config) || {};
    const models = (ov && Array.isArray(ov.models)) ? ov.models : [];
    const hasInstalled = models.some((m) => m.installed);

    if (!ov) {
      this.renderVoiceSetupBanner(
        '🎙 尚未配置本地离线语音识别模型。可在设置中心第 1 页一键下载 SenseVoice / Whisper 离线模型并开启语音输入。',
        false,
        true
      );
      return;
    }

    if (!hasInstalled && !cfg.allow_cloud_fallback) {
      this.renderVoiceSetupBanner(
        '🎙 尚未下载本地离线语音识别模型（推荐下载 SenseVoice-Small 中英混合模型，~160 MB），下载后即可零云端离线语音输入。',
        false,
        cfg.enabled === false
      );
      return;
    }

    if (cfg.enabled === false) {
      this.renderVoiceSetupBanner(
        hasInstalled
          ? '🎙 本机已安装离线语音识别模型，但悬浮窗语音输入开关当前处于关闭状态。'
          : '🎙 悬浮窗语音识别输入尚未开启，请先下载离线模型并开启语音开关。',
        hasInstalled,
        true
      );
      return;
    }

    this.hideVoiceBanner();
    await this.startVoiceRecordingFlow();
  }

  async startVoiceRecordingFlow() {
    if (!this.btnVoiceInput) return;
    const cfg = (this.speechOverview && this.speechOverview.config) || {};
    const res = await moduleRpc(
      'speech_hub',
      'start_recording',
      {
        test_mode: false,
        audio_source: cfg.audio_source || 'default',
        language: cfg.language || 'zh',
      },
      async () => null
    );

    if (!res || !res.ok || (res.result && res.result.error)) {
      const errMsg =
        (res && (res.error || (res.result && res.result.error))) ||
        '无法启动麦克风录音，请检查输入设备或离线语音模型状态';
      const models = (this.speechOverview && Array.isArray(this.speechOverview.models))
        ? this.speechOverview.models
        : [];
      this.renderVoiceSetupBanner(`⚠️ ${errMsg}`, models.some((m) => m.installed), cfg.enabled === false);
      return;
    }

    this.isVoiceRecording = true;
    this.voiceStartedAt = Date.now();
    this.btnVoiceInput.classList.add('qc-mic-recording');
    this.btnVoiceInput.textContent = '🔴 00:00';
    this.btnVoiceInput.title = '正在录音… 再次点击完成语音识别 (Esc 取消)';
    if (this.inputEl) {
      this.inputEl.setAttribute('placeholder', '正在聆听您的语音指令… 再次点击 🔴 完成识别');
    }

    clearInterval(this.voiceTimer);
    this.voiceTimer = setInterval(() => {
      if (!this.isVoiceRecording || !this.btnVoiceInput) return;
      const sec = Math.max(0, Math.floor((Date.now() - this.voiceStartedAt) / 1000));
      const mm = String(Math.floor(sec / 60)).padStart(2, '0');
      const ss = String(sec % 60).padStart(2, '0');
      this.btnVoiceInput.textContent = `🔴 ${mm}:${ss}`;
    }, 400);
  }

  async stopVoiceAndTranscribe() {
    clearInterval(this.voiceTimer);
    this.voiceTimer = null;
    this.isVoiceRecording = false;
    this.isVoiceTranscribing = true;

    if (this.btnVoiceInput) {
      this.btnVoiceInput.classList.remove('qc-mic-recording');
      this.btnVoiceInput.classList.add('is-transcribing');
      this.btnVoiceInput.textContent = '⏳';
      this.btnVoiceInput.title = '正在使用本地离线模型转写语音…';
    }
    if (this.inputEl) {
      this.inputEl.setAttribute('placeholder', '⏳ 正在本地离线转写您的语音指令…');
    }

    const cfg = (this.speechOverview && this.speechOverview.config) || {};
    try {
      const res = await moduleRpc(
        'speech_hub',
        'stop_and_transcribe',
        { language: cfg.language || 'zh' },
        async () => null
      );

      if (res && res.ok && res.result) {
        const transcript = String(
          res.result.text ?? res.result.transcript ?? res.result.recognized_text ?? ''
        ).trim();
        if (transcript && this.inputEl) {
          const prev = this.inputEl.value.trim();
          this.inputEl.value = prev ? `${prev} ${transcript}` : transcript;
          this.autoResizeTextarea();
          this.inputEl.focus();
          if (cfg.auto_send_after_transcribe && !this.isBusy) {
            await this.sendTurn(this.inputEl.value);
          } else {
            this.showToast(`🎙 识别完成 (${res.result.model_used || cfg.active_model_id || '本地模型'})`);
          }
        } else {
          this.showToast('🎙 未检测到清晰语音内容，请靠近麦克风重试');
        }
      } else {
        this.showToast(`⚠️ 语音转写失败: ${(res && res.error) || '模型执行异常'}`);
      }
    } finally {
      this.isVoiceTranscribing = false;
      if (this.btnVoiceInput) {
        this.btnVoiceInput.classList.remove('is-transcribing');
        this.btnVoiceInput.textContent = '🎙';
      }
      if (this.inputEl) {
        this.inputEl.setAttribute('placeholder', this.defaultPlaceholder);
      }
      this.syncVoiceMicBadge();
    }
  }

  async cancelVoiceRecording() {
    clearInterval(this.voiceTimer);
    this.voiceTimer = null;
    this.isVoiceRecording = false;
    this.isVoiceTranscribing = false;
    if (this.btnVoiceInput) {
      this.btnVoiceInput.classList.remove('qc-mic-recording', 'is-transcribing');
      this.btnVoiceInput.textContent = '🎙';
    }
    if (this.inputEl) {
      this.inputEl.setAttribute('placeholder', this.defaultPlaceholder);
    }
    this.syncVoiceMicBadge();
    await moduleRpc('speech_hub', 'cancel_recording', {}, async () => null);
    this.showToast('⏹ 已取消本次语音录入');
  }

  handleComposerKeydown(e) {
    if (this.isImeComposing || e.isComposing) return;

    // 1. `@` Mention Menu keyboard navigation
    if (this.memoryController.mentionOpen) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        this.memoryController.moveMentionSelection(1);
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        this.memoryController.moveMentionSelection(-1);
        return;
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault();
        this.memoryController.confirmMentionSelection();
        this.autoResizeTextarea();
        return;
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        this.memoryController.closeMentionMenu();
        return;
      }
    }

    // 2. `Enter` to send, `Shift+Enter` for newline
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (!this.isBusy && this.inputEl.value.trim()) {
        this.sendTurn(this.inputEl.value);
      }
      return;
    }

    // 3. `↑ / ↓` Input History Recall (when input is single-line / empty or browsing history)
    if (e.key === 'ArrowUp' && !e.shiftKey && !e.altKey) {
      const atStart = (this.inputEl.selectionStart ?? 0) === 0;
      const singleLine = !this.inputEl.value.includes('\n');
      if ((this.inputEl.value === '' || this.historyCursor !== -1 || singleLine) && atStart) {
        if (this.inputHistory.length > 0) {
          e.preventDefault();
          if (this.historyCursor === -1) {
            this.historyDraft = this.inputEl.value;
            this.historyCursor = this.inputHistory.length - 1;
          } else if (this.historyCursor > 0) {
            this.historyCursor -= 1;
          }
          this.inputEl.value = this.inputHistory[this.historyCursor];
          this.autoResizeTextarea();
        }
      }
      return;
    }

    if (e.key === 'ArrowDown' && !e.shiftKey && !e.altKey && this.historyCursor !== -1) {
      e.preventDefault();
      if (this.historyCursor < this.inputHistory.length - 1) {
        this.historyCursor += 1;
        this.inputEl.value = this.inputHistory[this.historyCursor];
      } else {
        this.historyCursor = -1;
        this.inputEl.value = this.historyDraft;
      }
      this.autoResizeTextarea();
    }
  }

  autoResizeTextarea() {
    if (!this.inputEl) return;
    this.inputEl.style.height = 'auto';
    const nextHeight = Math.min(132, Math.max(24, this.inputEl.scrollHeight));
    this.inputEl.style.height = `${nextHeight}px`;
  }

  hasOpenOverlayPopover() {
    return Boolean(
      this.memoryController.isOpen() ||
        (this.securityPopoverEl && !this.securityPopoverEl.hidden) ||
        (this.sessionsPopoverEl && !this.sessionsPopoverEl.hidden) ||
        (this.engineStripEl && !this.engineStripEl.hidden) ||
        (this.pasteBarEl && !this.pasteBarEl.hidden)
    );
  }

  closeOverlayPopovers() {
    this.memoryController.closePopover();
    if (this.btnMemory) this.btnMemory.classList.remove('active');
    if (this.securityPopoverEl) this.securityPopoverEl.hidden = true;
    if (this.btnSecurityPill) {
      this.btnSecurityPill.classList.remove('active');
      this.btnSecurityPill.setAttribute('aria-expanded', 'false');
    }
    if (this.sessionsPopoverEl) this.sessionsPopoverEl.hidden = true;
    if (this.btnSessionHistory) this.btnSessionHistory.classList.remove('active');
    if (this.engineStripEl) this.engineStripEl.hidden = true;
    if (this.btnEnginePill) {
      this.btnEnginePill.classList.remove('open');
      this.btnEnginePill.setAttribute('aria-expanded', 'false');
    }
  }

  /* ================= Clipboard Context & Chips ================= */
  async handleClipboardAttach() {
    if (this.clipboardContext) {
      this.clipboardContext = '';
      this.renderContextStrip();
      this.showToast('📋 已移除剪贴板上下文');
      return;
    }

    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = (await navigator.clipboard.readText()).trim();
        if (text) {
          this.clipboardContext = text.slice(0, 4000);
          this.renderContextStrip();
          this.inputEl.focus();
          return;
        }
      }
    } catch (_) {}

    // Fallback manual paste bar if browser restricts clipboard read without gesture permission
    if (this.pasteBarEl && this.pasteInputEl) {
      this.pasteBarEl.hidden = false;
      this.pasteInputEl.value = '';
      this.pasteInputEl.focus();
    }
  }

  confirmManualPaste() {
    if (!this.pasteInputEl) return;
    const text = this.pasteInputEl.value.trim();
    if (text) {
      this.clipboardContext = text.slice(0, 4000);
      this.renderContextStrip();
    }
    if (this.pasteBarEl) this.pasteBarEl.hidden = true;
    this.inputEl.focus();
  }

  renderContextStrip() {
    if (!this.contextStripEl) return;
    this.contextStripEl.innerHTML = '';

    const hasClip = Boolean(this.clipboardContext);
    const hasMentions = this.attachedMentions.length > 0;
    this.contextStripEl.hidden = !hasClip && !hasMentions;
    if (this.btnClipboard) {
      this.btnClipboard.classList.toggle('active', hasClip);
    }

    if (hasClip) {
      const preview = this.clipboardContext.replace(/\s+/g, ' ').slice(0, 38);
      const chip = document.createElement('div');
      chip.className = 'qc-ctx-chip';
      chip.innerHTML = `<span>📋 剪贴板: "${escapeHtml(preview)}${
        this.clipboardContext.length > 38 ? '…' : ''
      }"</span><button type="button" title="移除">✕</button>`;
      chip.querySelector('button').onclick = () => {
        this.clipboardContext = '';
        this.renderContextStrip();
      };
      this.contextStripEl.appendChild(chip);
    }

    this.attachedMentions.forEach((m, idx) => {
      const sub = (m.entity && (m.entity.path || m.entity.channel || m.entity.app_id)) || '';
      const chip = document.createElement('div');
      chip.className = 'qc-ctx-chip';
      chip.innerHTML = `<span>@${escapeHtml(m.tag)}${
        sub ? ` · ${escapeHtml(String(sub).split('/').pop())}` : ''
      }</span><button type="button" title="移除引用">✕</button>`;
      chip.querySelector('button').onclick = () => {
        this.attachedMentions.splice(idx, 1);
        this.renderContextStrip();
      };
      this.contextStripEl.appendChild(chip);
    });
  }

  /* ================= Sessions & Incognito ================= */
  toggleIncognito() {
    this.incognitoMode = !this.incognitoMode;
    if (this.dialogEl) {
      this.dialogEl.setAttribute('data-incognito', String(this.incognitoMode));
    }
    if (this.btnIncognito) {
      this.btnIncognito.classList.toggle('incog-on', this.incognitoMode);
    }
    this.updateSparkleState();
    this.showToast(
      this.incognitoMode
        ? '🔒 已开启隐私会话：对话不写入持久记忆库'
        : '🔓 已恢复常规会话：自动启用个人记忆召回与沉淀'
    );
  }

  async startNewChat() {
    this.closeOverlayPopovers();
    if (this.turns.length > 0 && !this.incognitoMode) {
      this.localSessionsCache.set(this.currentSessionId, {
        session_id: this.currentSessionId,
        title: this.turns[0].userText.slice(0, 32),
        updated_at: new Date().toLocaleTimeString(),
        turns: [...this.turns],
      });
    }

    this.turns = [];
    this.currentSessionId = `ses_${Date.now().toString(36)}`;

    if (!this.incognitoMode) {
      const created = await moduleRpc(
        'memory_hub',
        'create_session',
        { title: '随问新对话' },
        async () => null
      );
      if (created && created.ok && created.result && created.result.session_id) {
        this.currentSessionId = created.result.session_id;
      }
    }

    this.renderAllTurns();
    if (this.inputEl) {
      this.inputEl.value = '';
      this.autoResizeTextarea();
      this.inputEl.focus();
    }
  }

  async openSessionsPopover() {
    if (!this.sessionsPopoverEl) return;
    this.sessionsPopoverEl.hidden = false;
    this.sessionsPopoverEl.innerHTML = `
      <div class="qc-popover-head">
        <div class="qc-popover-title">🕒 历史会话列表</div>
        <div class="qc-popover-head-actions">
          <button type="button" class="qc-mini-btn" id="btn-pop-new-chat">+ 新建对话 (Ctrl+N)</button>
          <button type="button" class="qc-mini-btn" id="btn-close-ses-popover">✕</button>
        </div>
      </div>
      <div class="qc-popover-scroll" id="qc-sessions-list-body">
        <div class="qc-mem-empty">正在读取会话记录…</div>
      </div>
    `;

    this.sessionsPopoverEl.querySelector('#btn-close-ses-popover').onclick = () => {
      this.closeOverlayPopovers();
    };
    this.sessionsPopoverEl.querySelector('#btn-pop-new-chat').onclick = () => {
      this.startNewChat();
    };

    const res = await moduleRpc('memory_hub', 'list_sessions', { limit: 20 }, async () => null);
    const remoteList =
      (res && res.ok && res.result && (res.result.sessions || res.result)) || [];

    const merged = [];
    const seen = new Set();

    if (Array.isArray(remoteList)) {
      remoteList.forEach((s) => {
        const id = s.session_id || s.id;
        if (!id || seen.has(id)) return;
        seen.add(id);
        merged.push({
          id,
          title: s.title || s.preview || '历史对话',
          meta: s.updated_at || (s.message_count ? `${s.message_count} 条消息` : ''),
        });
      });
    }

    for (const [id, s] of this.localSessionsCache.entries()) {
      if (!seen.has(id)) {
        seen.add(id);
        merged.push({
          id,
          title: s.title || '本地会话',
          meta: `${s.turns.length} 轮 · ${s.updated_at || ''}`,
        });
      }
    }

    const listBody = this.sessionsPopoverEl.querySelector('#qc-sessions-list-body');
    if (!listBody) return;
    listBody.innerHTML = '';

    if (merged.length === 0) {
      listBody.innerHTML = '<div class="qc-mem-empty">暂无历史对话记录，发送首条提问后将自动保存。</div>';
      return;
    }

    merged.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'qc-session-item';

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'qc-session-btn' + (item.id === this.currentSessionId ? ' active' : '');
      btn.innerHTML = `
        <div class="qc-session-title">${escapeHtml(item.title)}</div>
        <div class="qc-session-meta">${escapeHtml(String(item.meta || item.id))}</div>
      `;
      btn.onclick = async () => {
        await this.loadSessionById(item.id);
        this.closeOverlayPopovers();
      };

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'qc-mem-row-open';
      delBtn.title = '删除该会话';
      delBtn.textContent = '🗑';
      delBtn.onclick = async (e) => {
        e.stopPropagation();
        this.localSessionsCache.delete(item.id);
        await moduleRpc('memory_hub', 'delete_session', { session_id: item.id }, async () => null);
        row.remove();
      };

      row.appendChild(btn);
      row.appendChild(delBtn);
      listBody.appendChild(row);
    });
  }

  async loadSessionById(sessionId) {
    if (this.localSessionsCache.has(sessionId)) {
      const cached = this.localSessionsCache.get(sessionId);
      this.currentSessionId = sessionId;
      this.turns = [...cached.turns];
      this.renderAllTurns();
      return;
    }

    const res = await moduleRpc(
      'memory_hub',
      'get_session',
      { session_id: sessionId },
      async () => null
    );
    if (res && res.ok && res.result) {
      this.currentSessionId = sessionId;
      const msgs = Array.isArray(res.result.messages) ? res.result.messages : [];
      const rebuilt = [];
      for (let i = 0; i < msgs.length; i += 1) {
        const m = msgs[i];
        if (m.role === 'user') {
          const next = msgs[i + 1] && msgs[i + 1].role === 'assistant' ? msgs[i + 1] : null;
          if (next) i += 1;
          rebuilt.push({
            id: `turn_${i}`,
            userText: m.content || m.text || '',
            clipboardContext: '',
            mentions: [],
            replyMarkdown: next ? next.content || next.text || '' : '',
            traceDots: (next && next.trace_dots) || [],
            modelLabel: (next && next.model) || '',
          });
        }
      }
      this.turns = rebuilt;
      this.renderAllTurns();
    }
  }

  /* ================= Chat Stream & Turn Execution ================= */
  setBusyState(busy, awaitingApproval = false) {
    this.isBusy = busy;
    if (this.btnSubmit) {
      this.btnSubmit.classList.toggle('stop-mode', busy);
      this.btnSubmit.textContent = busy ? '■' : '↑';
      this.btnSubmit.title = busy ? '中止当前回合 (Esc)' : '发送 (Enter)';
    }
    this.updateSparkleState(awaitingApproval);
  }

  updateSparkleState(awaitingApproval = false) {
    if (!this.sparkleEl) return;
    this.sparkleEl.className = 'qc-sparkle';
    if (this.isBusy) {
      this.sparkleEl.classList.add('busy');
    } else if (awaitingApproval) {
      this.sparkleEl.classList.add('approval');
    } else if (this.incognitoMode) {
      this.sparkleEl.classList.add('incognito');
    }
  }

  cancelActiveTurn() {
    if (this.activeAbortController) {
      this.activeAbortController.abort();
      this.activeAbortController = null;
    }
    if (this.activeTurnId) {
      moduleRpc('backend_bridge', 'cancel_turn', { turn_id: this.activeTurnId }, async () => null);
      this.activeTurnId = null;
    }
    this.setBusyState(false);
    this.showToast('⏹ 已中止当前生成');
  }

  scrollToBottom() {
    if (this.chatStreamEl) {
      this.chatStreamEl.scrollTop = this.chatStreamEl.scrollHeight;
    }
  }

  renderAllTurns() {
    if (!this.messagesListEl || !this.emptyStateEl) return;
    this.messagesListEl.innerHTML = '';
    this.emptyStateEl.hidden = this.turns.length > 0;

    this.turns.forEach((turn, idx) => {
      this.mountTurnElements(turn, idx, false);
    });
    this.scrollToBottom();
  }

  mountTurnElements(turn, turnIdx, isPendingStream = false) {
    if (!this.messagesListEl) return null;

    // 1. User Bubble
    const userRow = document.createElement('div');
    userRow.className = 'qc-msg-row user';
    const userBubble = document.createElement('div');
    userBubble.className = 'qc-bubble-user';
    if (turn.clipboardContext) {
      const clipBadge = document.createElement('div');
      clipBadge.className = 'qc-user-clip-tag';
      clipBadge.textContent = `📋 附带剪贴板 (${turn.clipboardContext.length} 字)`;
      userBubble.appendChild(clipBadge);
    }
    const txtNode = document.createElement('div');
    txtNode.textContent = turn.userText;
    userBubble.appendChild(txtNode);
    userRow.appendChild(userBubble);

    // 2. Assistant Bubble
    const asstRow = document.createElement('div');
    asstRow.className = 'qc-msg-row assistant';
    const asstBubble = document.createElement('div');
    asstBubble.className = 'qc-bubble-assistant';

    const mdBody = document.createElement('div');
    mdBody.className = 'qc-md-body';

    if (isPendingStream) {
      const { barWrapEl, drawerEl } = renderTraceDotsHeader({
        dots: [],
        isStreaming: true,
      });
      mdBody.innerHTML = '<span class="qc-streaming-placeholder">✦ 正在检索个人记忆与推理执行…</span>';
      asstBubble.appendChild(barWrapEl);
      asstBubble.appendChild(drawerEl);
      asstBubble.appendChild(mdBody);
    } else {
      this.populateAssistantBubble(asstBubble, mdBody, turn, turnIdx, false);
    }

    asstRow.appendChild(asstBubble);
    this.messagesListEl.appendChild(userRow);
    this.messagesListEl.appendChild(asstRow);

    return { userRow, asstRow, asstBubble, mdBody };
  }

  async populateAssistantBubble(asstBubble, mdBody, turn, turnIdx, animateStream = true, signal = null) {
    asstBubble.innerHTML = '';

    const { barWrapEl, drawerEl } = renderTraceDotsHeader({
      dots: turn.traceDots || [],
      modelLabel: turn.modelLabel || '',
      isStreaming: false,
      onRegenerate: () => this.regenerateTurn(turnIdx),
      onUndo: (csId) => this.triggerUndo(csId),
      onApproveDecision: (decision, dot) => this.handleInlineApproval(decision, dot, turn, asstBubble, mdBody, turnIdx),
      onInsertMention: (shortName, fullVal) => {
        if (this.inputEl) {
          const cur = this.inputEl.value;
          this.inputEl.value = `${cur && !cur.endsWith(' ') ? cur + ' ' : cur}@${shortName} `;
          this.autoResizeTextarea();
          this.inputEl.focus();
        }
        if (fullVal) {
          this.attachedMentions.push({ tag: shortName, entity: { path: fullVal, name: shortName } });
          this.renderContextStrip();
        }
      },
    });

    asstBubble.appendChild(barWrapEl);
    asstBubble.appendChild(drawerEl);

    // Compact Resolved Approval Banner (shown sleekly after user approves/denies without raw JSON preview)
    if (turn.approvalResolvedBanner) {
      const rb = turn.approvalResolvedBanner;
      const bannerEl = document.createElement('div');
      bannerEl.className = `qc-approval-resolved-card ${
        rb.mode === 'deny' ? 'is-denied' : 'is-approved'
      }`;

      const leftSpan = document.createElement('div');
      leftSpan.className = 'qc-approval-resolved-main';
      leftSpan.innerHTML = `<strong>${escapeHtml(rb.title)}</strong>${
        rb.detail ? `<span class="qc-approval-resolved-sub">${escapeHtml(rb.detail)}</span>` : ''
      }`;
      bannerEl.appendChild(leftSpan);

      if (rb.changesetId) {
        const undoBtn = document.createElement('button');
        undoBtn.type = 'button';
        undoBtn.className = 'qc-inline-undo-btn';
        undoBtn.textContent = rb.undone ? '✓ 已撤销' : '↶ 撤销';
        undoBtn.disabled = Boolean(rb.undone);
        undoBtn.onclick = async () => {
          undoBtn.disabled = true;
          undoBtn.textContent = '撤销中…';
          const ok = await this.triggerUndo(rb.changesetId);
          if (ok) {
            rb.undone = true;
            undoBtn.textContent = '✓ 已撤销';
          } else {
            undoBtn.disabled = false;
            undoBtn.textContent = '↶ 撤销';
          }
        };
        bannerEl.appendChild(undoBtn);
      }

      asstBubble.appendChild(bannerEl);
    }

    asstBubble.appendChild(mdBody);

    if (animateStream) {
      await streamMarkdownInto(mdBody, turn.replyMarkdown || '', {
        signal,
        onStepScroll: () => this.scrollToBottom(),
      });
    } else {
      renderMarkdown(mdBody, turn.replyMarkdown || '');
    }

    // Subtle Non-Linear Time-Decay Context Compression Footer Indicator
    const cc = turn.contextCompression;
    if (
      cc &&
      cc.enabled !== false &&
      (Number(cc.saved_pct || 0) > 0 || Number(cc.included_qa_turns || 0) > 0)
    ) {
      const footerEl = document.createElement('div');
      footerEl.className = 'qc-bubble-footer';
      const estTok = Number(cc.compressed_estimated_tokens ?? cc.estimated_tokens ?? 0);
      const savedPct = Math.round(Number(cc.saved_pct || 0));
      const droppedTools = Number(cc.dropped_tool_records || 0);
      footerEl.innerHTML = `
        <span class="qc-cc-badge" title="非线性时间衰减会话压缩：保留近期完整问答，自动折叠远期轮次并剥离历史工具调用轨迹">
          📉 上下文 ${estTok} tok${savedPct > 0 ? ` (省 ${savedPct}%)` : ''}${
        droppedTools > 0 ? ` · 已剥离 ${droppedTools} 条工具记录` : ''
      }
        </span>
      `;
      asstBubble.appendChild(footerEl);
    }
  }

  async regenerateTurn(turnIdx) {
    if (this.isBusy || !this.turns[turnIdx]) return;
    const target = this.turns[turnIdx];
    this.turns.splice(turnIdx, 1);
    this.renderAllTurns();
    await this.sendTurn(target.userText, {
      clipboardOverride: target.clipboardContext,
      mentionsOverride: target.mentions,
    });
  }

  async sendTurn(rawText, opts = {}) {
    const userText = String(rawText ?? '').trim();
    if (!userText || this.isBusy) return;

    this.closeOverlayPopovers();
    this.memoryController.closeMentionMenu();

    // Record input history
    if (this.inputHistory[this.inputHistory.length - 1] !== userText) {
      this.inputHistory.push(userText);
    }
    this.historyCursor = -1;
    this.historyDraft = '';

    const clipboardContext =
      opts.clipboardOverride !== undefined ? opts.clipboardOverride : this.clipboardContext;
    const mentions =
      opts.mentionsOverride !== undefined ? opts.mentionsOverride : [...this.attachedMentions];

    // Clear composer right away
    if (this.inputEl) {
      this.inputEl.value = '';
      this.autoResizeTextarea();
    }
    this.clipboardContext = '';
    this.attachedMentions = [];
    this.renderContextStrip();

    if (this.emptyStateEl) this.emptyStateEl.hidden = true;

    const turnObj = {
      id: `turn_${Date.now()}`,
      userText,
      clipboardContext,
      mentions,
      replyMarkdown: '',
      traceDots: [],
      modelLabel: '',
      task: null,
    };
    const turnIdx = this.turns.length;
    this.turns.push(turnObj);

    const mounted = this.mountTurnElements(turnObj, turnIdx, true);
    this.scrollToBottom();

    const abortCtrl = new AbortController();
    this.activeAbortController = abortCtrl;
    this.setBusyState(true);

    try {
      // Build contextual prompt if mentions or clipboard are attached
      let effectiveText = userText;
      if (mentions.length > 0) {
        const refNotes = mentions
          .map((m) => {
            const detail =
              (m.entity && (m.entity.path || m.entity.app_id || m.entity.name)) || m.tag;
            return `@${m.tag} (${detail})`;
          })
          .join(', ');
        effectiveText = `${userText}\n[引用对象: ${refNotes}]`;
      }

      // 1. Primary Wave 2 Path: `backend_bridge::send_quick_chat_turn`
      const bridgeRes = await moduleRpc(
        'backend_bridge',
        'send_quick_chat_turn',
        {
          session_id: this.incognitoMode ? null : this.currentSessionId,
          text: effectiveText,
          clipboard_context: clipboardContext || null,
          incognito: this.incognitoMode,
          reasoning_effort: (this.catalog.active && this.catalog.active.reasoning_effort) || 'default',
        },
        null,
        { signal: abortCtrl.signal }
      );

      if (bridgeRes && bridgeRes.aborted) {
        turnObj.replyMarkdown = '_（已取消本次提问）_';
        turnObj.traceDots = [{ kind: 'thinking', title: '已中止', detail: '用户主动取消了当前回合。' }];
        await this.populateAssistantBubble(mounted.asstBubble, mounted.mdBody, turnObj, turnIdx, false);
        return;
      }

      if (
        bridgeRes &&
        bridgeRes.ok &&
        bridgeRes.result &&
        bridgeRes.result.status !== 'stub' &&
        (typeof bridgeRes.result.reply_markdown === 'string' || typeof bridgeRes.result.reply === 'string')
      ) {
        const r = bridgeRes.result;
        this.activeTurnId = r.turn_id || null;
        if (!this.incognitoMode && r.session_id) {
          this.currentSessionId = r.session_id;
        }

        const rawReply = r.reply_markdown ?? r.reply ?? '';
        const split = splitThinkAndReply(rawReply);
        const mergedThinking = [r.thinking, split.thinking].filter(Boolean).join('\n\n');

        turnObj.replyMarkdown = split.reply || rawReply || '已完成处理。';
        turnObj.traceDots = normalizeTraceDots({
          ...r,
          thinking: mergedThinking,
        });
        turnObj.modelLabel = [r.backend_used, r.model_used].filter(Boolean).join(' · ');
        turnObj.contextCompression = r.context_compression || null;
        turnObj.task = r.task || null;

        if (r.task) this.syncVisualEffects(r.task);
        this.captureLatestChangeset(turnObj.traceDots, r.task);

        const hasPendingApproval = turnObj.traceDots.some((d) => d.kind === 'approval' && !d.resolved_status);
        await this.populateAssistantBubble(
          mounted.asstBubble,
          mounted.mdBody,
          turnObj,
          turnIdx,
          true,
          abortCtrl.signal
        );
        this.setBusyState(false, hasPendingApproval);

        if (!this.incognitoMode) {
          this.recordTurnToMemoryHub(userText, turnObj.replyMarkdown, turnObj.traceDots);
          this.memoryController.loadedOnce = false;
        }
        return;
      }

      // 2. Seamless Automatic Fallback: `memory_hub` + `app_adapter` + `rpc('submit_intent')`
      await this.runFallbackIntentTurn(
        userText,
        effectiveText,
        clipboardContext,
        turnObj,
        mounted,
        turnIdx,
        abortCtrl.signal
      );
    } finally {
      this.activeAbortController = null;
      this.activeTurnId = null;
      if (this.isBusy) {
        this.setBusyState(false);
      }
      this.scrollToBottom();
    }
  }

  async runFallbackIntentTurn(
    userText,
    effectiveText,
    clipboardContext,
    turnObj,
    mounted,
    turnIdx,
    signal
  ) {
    // Query personal memory & adapter context in parallel for rich AIOS answers
    const asksFiles = /文件|文档|周报|最近|常用/.test(userText);
    const asksApps = /装了哪些|常用软件|有哪些软件|应用/.test(userText);
    const asksMediaOrAdapter = /音乐|播放|暂停|下一首|上一首|转译/.test(userText);

    const [memQueryRes, memDashRes, adapterProbeRes] = await Promise.all([
      moduleRpc(
        'memory_hub',
        'query_personal_memory',
        { query: userText, kind: 'all', limit: 6 },
        async () => null,
        { signal }
      ),
      asksFiles || asksApps
        ? moduleRpc('memory_hub', 'get_memory_dashboard', {}, async () => null, { signal })
        : Promise.resolve(null),
      asksMediaOrAdapter
        ? moduleRpc('app_adapter', 'probe_live_controllable_apps', {}, async () => null, { signal })
        : Promise.resolve(null),
    ]);

    const memoryHits =
      (memQueryRes && memQueryRes.ok && memQueryRes.result && memQueryRes.result.hits) || [];
    const memoryContext =
      (memQueryRes && memQueryRes.ok && memQueryRes.result && memQueryRes.result.context_markdown) || '';

    const adapterActions = [];
    let adapterMarkdown = '';

    // If user explicitly asks to view/control music via Software Translation Layer
    if (asksMediaOrAdapter) {
      const actionVerb = /暂停/.test(userText)
        ? 'pause'
        : /下一/.test(userText)
        ? 'next'
        : /上一/.test(userText)
        ? 'previous'
        : /继续|播放音乐/.test(userText) && !/查看/.test(userText)
        ? 'play_pause'
        : 'get_now_playing';

      const adExec = await moduleRpc(
        'app_adapter',
        'translate_and_execute',
        { app_hint: 'media_player', intent_action: actionVerb, params: {} },
        async () => null,
        { signal }
      );
      if (adExec && adExec.ok && adExec.result && adExec.result.status !== 'stub') {
        const ar = adExec.result;
        adapterActions.push({
          app_id: ar.app_id || 'mpris2',
          app_name: ar.app_id || '媒体播放器',
          channel_used: ar.channel_used || 'dbus_mpris',
          summary: ar.summary || '已通过 MPRIS2 / D-Bus 通道完成转译调用',
          verification: ar.verification || 'verified',
          changeset_id: ar.changeset_id || null,
        });
        if (ar.summary) {
          adapterMarkdown = `### 🔌 软件转译层执行结果\n- **转译通道**：\`${ar.channel_used || 'MPRIS2 / D-Bus'}\`\n- **状态摘要**：${ar.summary}`;
        }
      } else if (adapterProbeRes && adapterProbeRes.ok && adapterProbeRes.result) {
        const players = adapterProbeRes.result.mpris_players || [];
        adapterActions.push({
          app_id: 'mpris2-probe',
          app_name: 'MPRIS2 媒体会话探测',
          channel_used: 'dbus_mpris',
          summary:
            players.length > 0
              ? `发现活跃播放器: ${players.join(', ')}`
              : 'MPRIS2 / D-Bus 转译层就绪（当前无正在播放的桌面媒体会话）',
        });
      }
    }

    const fullIntentInput = clipboardContext
      ? `${effectiveText}\n\n[剪贴板上下文]:\n${clipboardContext.slice(0, 1200)}`
      : effectiveText;

    const intentRes = await rpc(
      'submit_intent',
      {
        protocol_version: 1,
        text: fullIntentInput,
        session_id: this.incognitoMode ? null : this.currentSessionId,
        force_agent: true,
        selected_candidate_id: null,
        incognito: this.incognitoMode,
      },
      { signal }
    );

    if (intentRes && intentRes.aborted) {
      turnObj.replyMarkdown = '_（已取消本次提问）_';
      turnObj.traceDots = [{ kind: 'thinking', title: '已中止', detail: '用户取消了当前回合。' }];
      await this.populateAssistantBubble(mounted.asstBubble, mounted.mdBody, turnObj, turnIdx, false);
      return;
    }

    let replyMd = '';
    let dots = [];

    if (intentRes && intentRes.ok && intentRes.result) {
      if (intentRes.result.kind === 'passthrough' && intentRes.result.passthrough) {
        const pt = intentRes.result.passthrough;
        replyMd = `${pt.message || '直通命令执行结果：'}\n\n\`\`\`bash\n$ ${pt.command}\n${(
          pt.stdout ||
          pt.stderr ||
          '(无输出)'
        ).trim()}\n\`\`\``;
        dots = [
          {
            kind: pt.status === 'ok' ? 'tool_ok' : 'tool_err',
            title: `$ ${pt.command}`,
            detail: `cwd: ${pt.cwd} · exit: ${pt.exit_code ?? 0}`,
          },
        ];
      } else {
        const task = intentRes.result;
        turnObj.task = task;
        if (!this.incognitoMode && task.session_id) {
          this.currentSessionId = task.session_id;
        }
        this.syncVisualEffects(task);

        const rawMsg = task.assistant_message || task.result_summary || '';
        const split = splitThinkAndReply(rawMsg);
        replyMd = split.reply || rawMsg;

        // Enrich file / software starter answers if memory_hub dashboard returned structured items
        if (memDashRes && memDashRes.ok && memDashRes.result) {
          const d = memDashRes.result;
          if (asksFiles && (!replyMd || replyMd.includes('未找到') || replyMd.length < 30)) {
            const mf = Array.isArray(d.mentioned_files) ? d.mentioned_files.slice(0, 5) : [];
            const ff = Array.isArray(d.frequent_files) ? d.frequent_files.slice(0, 6) : [];
            if (mf.length > 0 || ff.length > 0) {
              const lines = ['### 📂 您的个人文件记忆画像'];
              if (mf.length > 0) {
                lines.push('\n**之前对话提到的文件：**');
                mf.forEach((f) =>
                  lines.push(`- \`${f.display_name || f.canonical_value}\` — ${f.canonical_value || ''}`)
                );
              }
              if (ff.length > 0) {
                lines.push('\n**长期高频使用的文件：**');
                ff.forEach((f) =>
                  lines.push(
                    `- \`${f.title || f.path}\` (${f.open_count || 1} 次) — \`${f.path || ''}\``
                  )
                );
              }
              replyMd = lines.join('\n');
              memoryHits.push(...mf.slice(0, 3), ...ff.slice(0, 3));
            }
          } else if (asksApps && (!replyMd || replyMd.includes('未找到') || replyMd.length < 30)) {
            const apps = Array.isArray(d.frequent_apps) ? d.frequent_apps.slice(0, 8) : [];
            const total =
              (d.installed_apps_summary &&
                (d.installed_apps_summary.total_installed || d.installed_apps_summary.total_count)) ||
              apps.length;
            if (apps.length > 0) {
              const lines = [`### 🧩 本机已装与常用软件画像（共识别 ${total} 款桌面应用）`];
              apps.forEach((a) =>
                lines.push(
                  `- **${a.name_zh || a.name}**${
                    a.launch_count ? `（使用 ${a.launch_count} 次）` : ''
                  }${a.category ? ` · _${a.category}_` : ''}`
                )
              );
              replyMd = lines.join('\n');
              memoryHits.push(...apps.slice(0, 4));
            }
          }
        }

        if (adapterMarkdown) {
          replyMd = replyMd ? `${adapterMarkdown}\n\n${replyMd}` : adapterMarkdown;
        }

        dots = buildTraceDotsFromTask(task, {
          thinking: split.thinking,
          memoryHits,
          memoryContext,
          adapterActions,
        });
        this.captureLatestChangeset(dots, task);
      }
    } else {
      const errMsg = (intentRes && intentRes.error) || '核心服务暂未响应';
      replyMd = adapterMarkdown || `⚠️ 请求未能完成：${errMsg}`;
      dots = [
        ...adapterActions.map((a) => ({
          kind: 'adapter',
          title: `转译层: ${a.app_name}`,
          channel: a.channel_used,
          detail: a.summary,
        })),
        { kind: 'tool_err', title: '请求异常', detail: errMsg },
      ];
    }

    turnObj.replyMarkdown = replyMd || '已完成执行。';
    turnObj.traceDots = dots;
    turnObj.modelLabel =
      (turnObj.task && turnObj.task.route) ||
      `${BACKEND_LABELS[this.catalog.active.backend] || 'AIOS'} · ${this.catalog.active.model}`;

    const awaitingApproval = dots.some((d) => d.kind === 'approval' && !d.resolved_status);
    await this.populateAssistantBubble(
      mounted.asstBubble,
      mounted.mdBody,
      turnObj,
      turnIdx,
      true,
      signal
    );
    this.setBusyState(false, awaitingApproval);

    if (!this.incognitoMode) {
      this.recordTurnToMemoryHub(userText, turnObj.replyMarkdown, dots);
      this.memoryController.loadedOnce = false;
    }
  }

  recordTurnToMemoryHub(userText, assistantText, traceDots) {
    moduleRpc(
      'memory_hub',
      'record_conversation_turn',
      {
        session_id: this.currentSessionId,
        user_text: userText,
        assistant_text: assistantText,
        tool_steps: (traceDots || []).filter((d) => d.kind === 'tool_ok' || d.kind === 'adapter'),
        incognito: false,
      },
      async () => null
    ).catch(() => {});
  }

  /* ================= Inline Scoped Approval (`✓ 批准本次` / `⏱ 本会话放行此范围` / `✕ 拒绝`) & Undo ================= */
  async handleInlineApproval(decision, dot, turn, asstBubble, mdBody, turnIdx) {
    const pa = dot.pending_approval || dot;
    const meta = extractApprovalMetadata(pa);
    const mode =
      decision === 'deny'
        ? 'deny'
        : decision === 'scope' || decision === 'session'
        ? 'session'
        : 'once';

    this.setBusyState(true);

    try {
      // 1. Primary Wave 5 Seamless In-Session Continuation: `backend_bridge::resume_approved_turn`
      if (pa.approval_id) {
        const resumeRes = await moduleRpc(
          'backend_bridge',
          'resume_approved_turn',
          {
            approval_id: pa.approval_id || '',
            nonce: pa.nonce || '',
            digest: pa.digest || '',
            decision: mode,
            scope_kind: meta.scopeKind,
            scope_value: meta.scopeValue,
            ttl_minutes: 60,
          },
          async () => null
        );

        const isUnknownAction =
          resumeRes &&
          !resumeRes.ok &&
          String(resumeRes.error || '').toLowerCase().includes('unknown action');

        if (
          resumeRes &&
          resumeRes.ok &&
          resumeRes.result &&
          resumeRes.result.status !== 'stub'
        ) {
          const r = resumeRes.result;
          if (!this.incognitoMode && r.session_id) {
            this.currentSessionId = r.session_id;
          }
          if (r.task) {
            turn.task = r.task;
            this.syncVisualEffects(r.task);
          }

          if (mode === 'session') {
            this.sessionScopedGrants.add(`${meta.scopeKind}:${meta.scopeValue}`);
            await this.refreshSecurityPosture();
          }

          const rawReply = r.reply_markdown ?? r.reply ?? '';
          const split = splitThinkAndReply(rawReply);
          const mergedThinking = [r.thinking, split.thinking].filter(Boolean).join('\n\n');

          turn.traceDots = normalizeTraceDots({
            ...r,
            thinking: mergedThinking,
          });
          turn.modelLabel =
            [r.backend_used, r.model_used].filter(Boolean).join(' · ') || turn.modelLabel;
          turn.contextCompression = r.context_compression || turn.contextCompression || null;

          const csList = Array.isArray(r.changeset_ids)
            ? r.changeset_ids
            : r.task && Array.isArray(r.task.changeset_ids)
            ? r.task.changeset_ids
            : [];
          const latestCsId =
            csList.length > 0 ? csList[csList.length - 1] : r.changeset_id || null;

          this.captureLatestChangeset(turn.traceDots, r.task || { changeset_ids: csList });

          dot.resolved_mode = mode;
          dot.changeset_id = latestCsId;
          dot.resolved_status =
            mode === 'deny'
              ? '✕ 已拒绝执行该敏感操作'
              : mode === 'session'
              ? `✓ 已放行本会话范围 (${meta.scopeKind}: ${meta.scopeValue}) · 已继续会话`
              : '✓ 敏感权限已批准 · 已继续会话';

          turn.approvalResolvedBanner = {
            mode,
            title:
              mode === 'deny'
                ? '🛡️ 已拒绝执行该敏感操作'
                : mode === 'session'
                ? '🛡️ 已放行本会话范围 · 已继续会话'
                : '🛡️ 敏感权限已批准 · 已继续会话',
            detail:
              mode === 'deny'
                ? '未执行受控操作，会话保持安全状态'
                : meta.targetPath || meta.scopeValue || pa.capability_id || '',
            changesetId: latestCsId,
            undone: false,
          };

          turn.replyMarkdown =
            split.reply ||
            rawReply ||
            (mode === 'deny' ? '已拒绝执行该敏感操作。' : '已完成授权执行并继续会话。');

          if (latestCsId) {
            this.showToast(`✓ 已执行可逆变更 (${latestCsId})`);
          }

          const hasNextPending = turn.traceDots.some(
            (d) => d.kind === 'approval' && !d.resolved_status
          );
          await this.populateAssistantBubble(asstBubble, mdBody, turn, turnIdx, false);
          this.setBusyState(false, hasNextPending);
          this.scrollToBottom();

          if (!this.incognitoMode) {
            this.memoryController.loadedOnce = false;
          }
          return;
        }

        if (resumeRes && !resumeRes.ok && !isUnknownAction) {
          dot.resolved_mode = mode;
          dot.resolved_status = `⚠ 授权续跑异常: ${resumeRes.error || '未知错误'}`;
          turn.approvalResolvedBanner = {
            mode,
            title: `⚠️ 授权执行未能完成`,
            detail: String(resumeRes.error || '请重试或检查策略状态'),
            changesetId: null,
          };
          await this.populateAssistantBubble(asstBubble, mdBody, turn, turnIdx, false);
          this.setBusyState(false, false);
          return;
        }
      }

      // 2. Fallback Path (when `!pa.approval_id` e.g. custom adapter / PID close, or legacy daemon without `resume_approved_turn`)
      if (mode === 'deny') {
        if (pa.approval_id) {
          const r = await rpc('deny', { approval_id: pa.approval_id });
          if (r.ok && r.result) {
            turn.task = r.result;
            turn.replyMarkdown =
              r.result.assistant_message || '已拒绝执行该敏感操作，未产生任何修改。';
          } else {
            turn.replyMarkdown = '已拒绝执行该敏感操作。';
          }
        } else {
          turn.replyMarkdown = '已拒绝执行该受控操作。';
        }
        dot.resolved_mode = 'deny';
        dot.resolved_status = '✕ 已拒绝执行';
        turn.approvalResolvedBanner = {
          mode: 'deny',
          title: '🛡️ 已拒绝执行该敏感操作',
          detail: '未执行受控操作',
          changesetId: null,
        };
        await this.populateAssistantBubble(asstBubble, mdBody, turn, turnIdx, false);
        this.setBusyState(false, false);
        return;
      }

      if (mode === 'session') {
        const capId = pa.capability_id || dot.capability_id || '*';
        this.sessionScopedGrants.add(`${meta.scopeKind}:${meta.scopeValue}`);
        await moduleRpc(
          'execution_hub',
          'grant_session_scope',
          {
            scope_kind: meta.scopeKind,
            scope_value: meta.scopeValue,
            ttl_minutes: 60,
          },
          async () => null
        );
        if (turn.task && turn.task.id) {
          await moduleRpc(
            'execution_hub',
            'create_grant_envelope',
            {
              task_id: turn.task.id,
              capabilities: [capId],
              resource_scope: [meta.scopeValue || pa.scope || '*'],
              max_effect: 'write.reversible',
              max_operations: 50,
            },
            async () => null
          );
        }
        await this.refreshSecurityPosture();
      }

      if (pa.approval_id) {
        const r = await rpc('approve', {
          approval_id: pa.approval_id,
          nonce: pa.nonce,
          digest: pa.digest,
        });
        if (r.ok && r.result) {
          const updatedTask = r.result;
          turn.task = updatedTask;
          this.syncVisualEffects(updatedTask);

          dot.resolved_mode = mode;
          dot.resolved_status =
            mode === 'session'
              ? `✓ 已在本会话放行 [${meta.scopeKind}] ${meta.scopeValue} 并批准执行`
              : '✓ 已批准本次并完成核验执行';

          const preservedPriorDots = (turn.traceDots || []).filter(
            (d) => d === dot || d.kind === 'thinking' || d.kind === 'memory'
          );
          const taskStepDots = buildTraceDotsFromTask(updatedTask).filter(
            (d) => d.kind !== 'thinking'
          );
          turn.traceDots = [...preservedPriorDots, ...taskStepDots];
          this.captureLatestChangeset(turn.traceDots, updatedTask);

          const verifiedSummary =
            updatedTask.assistant_message ||
            updatedTask.result_summary ||
            '已完成授权执行并通过状态校验。';
          const latestCsId =
            Array.isArray(updatedTask.changeset_ids) && updatedTask.changeset_ids.length > 0
              ? updatedTask.changeset_ids[updatedTask.changeset_ids.length - 1]
              : null;

          turn.approvalResolvedBanner = {
            mode,
            title:
              mode === 'session'
                ? '🛡️ 已放行本会话范围 · 已继续会话'
                : '🛡️ 敏感权限已批准 · 已继续会话',
            detail: meta.targetPath || meta.scopeValue || '',
            changesetId: latestCsId,
            undone: false,
          };

          turn.replyMarkdown = latestCsId
            ? `✅ **已批准执行并通过验证**：${verifiedSummary}\n\n> ↶ 已生成可逆备份变更集 \`${latestCsId}\`，可点击上方 **[↶ 撤销]** 或按 \`Ctrl+Z\` 一键还原。`
            : `✅ **已批准执行并通过验证**：${verifiedSummary}`;

          if (latestCsId) {
            this.showToast(`✓ 已执行可逆变更 (${latestCsId})`);
          }
        } else {
          dot.resolved_status = `⚠ 授权执行失败: ${(r && r.error) || '未知错误'}`;
        }
      } else if (Array.isArray(pa.alive_pids) && pa.alive_pids.length > 0) {
        const targetApp = pa.app_name || pa.app_id || pa.app_hint || meta.targetApp;
        const closeRes = await moduleRpc('app_adapter', 'close_app_verified', {
          app_query: targetApp,
          force_kill_approved: true,
        });
        if (closeRes && closeRes.ok && closeRes.result) {
          dot.resolved_mode = mode;
          dot.resolved_status =
            mode === 'session' ? '✓ 已放行并完成进程退出核验' : '✓ 已批准并完成进程退出核验';
          turn.approvalResolvedBanner = {
            mode,
            title:
              mode === 'session'
                ? '🛡️ 已放行本会话范围 · 已继续会话'
                : '🛡️ 敏感权限已批准 · 已继续会话',
            detail: targetApp,
            changesetId: null,
          };
          turn.traceDots.push({
            kind: 'adapter',
            title: `进程核验关闭: ${targetApp}`,
            channel: 'process_lifecycle',
            detail: closeRes.result.summary || '目标进程已全部退出',
            verification: 'passed',
          });
          turn.replyMarkdown = `✅ **进程关闭已验证**：${closeRes.result.summary || '目标应用进程已退出'}`;
        } else {
          dot.resolved_status = `⚠ 强制关闭异常: ${(closeRes && closeRes.error) || '未知错误'}`;
        }
      } else if (pa.app_hint || pa.intent_action || meta.targetApp) {
        const adRes = await moduleRpc('app_adapter', 'translate_and_execute', {
          app_hint: pa.app_hint || meta.targetApp || '',
          intent_action: pa.intent_action || pa.action || '',
          params: pa.arguments || pa.params || {},
          approved: true,
        });
        if (adRes.ok && adRes.result) {
          dot.resolved_mode = mode;
          dot.resolved_status =
            mode === 'session' ? '✓ 已本会话放行并执行' : '✓ 已批准本次执行';
          turn.approvalResolvedBanner = {
            mode,
            title:
              mode === 'session'
                ? '🛡️ 已放行本会话范围 · 已继续会话'
                : '🛡️ 敏感权限已批准 · 已继续会话',
            detail: adRes.result.app_id || pa.app_hint || meta.targetApp || '',
            changesetId: adRes.result.changeset_id || null,
          };
          turn.traceDots.push({
            kind: 'adapter',
            title: `转译执行: ${adRes.result.app_id || pa.app_hint || meta.targetApp}`,
            channel: adRes.result.channel_used || 'gui_atspi',
            detail: adRes.result.summary || '已完成授权转译动作',
            changeset_id: adRes.result.changeset_id || null,
          });
          this.captureLatestChangeset(turn.traceDots, turn.task);
          turn.replyMarkdown = adRes.result.summary || '已完成授权软件转译操作。';
        }
      } else {
        dot.resolved_mode = mode;
        dot.resolved_status =
          mode === 'session' ? '✓ 已在本会话放行该范围' : '✓ 已批准本次执行';
      }

      await this.populateAssistantBubble(asstBubble, mdBody, turn, turnIdx, false);
      this.setBusyState(false, false);
    } finally {
      if (this.isBusy) {
        this.setBusyState(false, false);
      }
    }
  }

  captureLatestChangeset(dots, task) {
    if (task && Array.isArray(task.changeset_ids) && task.changeset_ids.length > 0) {
      this.lastChangesetId = task.changeset_ids[task.changeset_ids.length - 1];
      return;
    }
    const revDot = [...(dots || [])].reverse().find((d) => d.changeset_id);
    if (revDot && revDot.changeset_id) {
      this.lastChangesetId = revDot.changeset_id;
    }
  }

  syncVisualEffects(task) {
    if (!task || !Array.isArray(task.steps)) return;
    for (const st of task.steps) {
      if (st.capability_id === 'appearance.color_scheme.set' || st.capability_id === 'scene.apply') {
        const msg = st.message || '';
        if (msg.includes('深色模式')) {
          this.applyThemeAttribute('dark', true);
        } else if (msg.includes('浅色模式')) {
          this.applyThemeAttribute('light', true);
        }
      }
    }
  }

  async triggerUndo(targetId = null) {
    this.hideUndoToast();
    const res = await rpc('undo', { target_id: targetId });
    if (!res.ok) {
      this.showToast(`⚠️ ${res.error || '当前没有可撤销的变更集'}`);
      return false;
    }
    const msg = (res.result && res.result.message) || '已撤销最近一次操作';
    if (msg.includes('深色模式')) {
      this.applyThemeAttribute('dark', true);
    } else if (msg.includes('浅色模式')) {
      this.applyThemeAttribute('light', true);
    }
    this.showToast(`↶ ${msg}`);
    return true;
  }

  showToast(message) {
    if (!this.undoToastEl) return;
    clearInterval(this.undoCountdownTimer);
    this.undoSecondsLeft = 5;
    if (this.undoToastTextEl) {
      this.undoToastTextEl.textContent = message;
    }
    if (this.undoCountdownEl) {
      this.undoCountdownEl.textContent = '✦';
    }
    const btnUndo = document.getElementById('btn-toast-undo');
    if (btnUndo) {
      btnUndo.style.display = this.lastChangesetId ? 'inline-flex' : 'none';
    }
    this.undoToastEl.classList.add('visible');

    this.undoCountdownTimer = setInterval(() => {
      this.undoSecondsLeft -= 1;
      if (this.undoSecondsLeft <= 0) {
        this.hideUndoToast();
      }
    }, 1000);
  }

  hideUndoToast() {
    clearInterval(this.undoCountdownTimer);
    if (this.undoToastEl) {
      this.undoToastEl.classList.remove('visible');
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const app = new QuickChatDialogApp();
  app.init();
  window.__INTENTOS_APP__ = app;
});
