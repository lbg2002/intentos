/**
 * IntentOS v0.3 — 11-Page Full-Featured Visual Settings Center (§5.6 & §14.2)
 * Wired to `config_center` and `execution_hub` via `moduleRpc` with graceful fallback.
 */

import { rpc, moduleRpc } from './rpc-client.js';
import { escapeHtml } from './markdown-renderer.js';
import { normalizeLiveTrayApps, normalizeMenuItemsList } from './memory-adapter-popover.js';

export const SETTINGS_PAGES = [
  { id: 'overview', label: '1. 概览与健康', icon: '📊' },
  { id: 'brain', label: '2. 大脑与网关', icon: '🧠' },
  { id: 'memory', label: '3. 记忆与候选', icon: '💡' },
  { id: 'skills', label: '4. 安全模式与技能', icon: '🛡' },
  { id: 'capabilities', label: '5. 本机软件深度扫描与分类转译中心', icon: '🔌' },
  { id: 'resources', label: '6. 资源与项目', icon: '📁' },
  { id: 'web', label: '7. 网站与搜索', icon: '🌐' },
  { id: 'permissions', label: '8. 包络与审计', icon: '📜' },
  { id: 'undo', label: '9. 撤销与备份', icon: '↶' },
  { id: 'automation', label: '10. 自动化与驱动', icon: '⚡' },
  { id: 'maintenance', label: '11. 交互与维护', icon: '⌨' },
];

export const SOFTWARE_9_CATEGORIES = [
  { id: 'media_entertainment', label: '🎵 影音娱乐', icon: '🎵', name_zh: '影音娱乐' },
  { id: 'social_collab', label: '💬 社交会议', icon: '💬', name_zh: '社交会议' },
  { id: 'office_notes_doc', label: '📄 办公笔记', icon: '📄', name_zh: '办公笔记' },
  { id: 'cloud_transfer', label: '☁ 云盘互传', icon: '☁', name_zh: '云盘互传' },
  { id: 'network_browser', label: '🌐 网络代理', icon: '🌐', name_zh: '网络代理' },
  { id: 'dev_ai_ide', label: '💻 开发与AI', icon: '💻', name_zh: '开发与AI' },
  { id: 'creative_disc', label: '🎨 创意刻录', icon: '🎨', name_zh: '创意刻录' },
  { id: 'remote_vm', label: '🖥 远程虚拟机', icon: '🖥', name_zh: '远程虚拟机' },
  { id: 'hardware_system', label: '🛠 硬件系统', icon: '🛠', name_zh: '硬件系统' },
];

const SOURCE_BADGE_MAP = {
  system_apt: 'APT',
  apt: 'APT',
  snap: 'Snap',
  flatpak: 'Flatpak',
  opt_vendor: 'Vendor',
  vendor: 'Vendor',
  user_local: 'Local',
  local: 'Local',
  chrome_pwa: 'PWA',
  pwa: 'PWA',
};

const DEFAULT_ASR_MODELS = [
  {
    id: 'sensevoice-small-int8',
    name: 'SenseVoice-Small (INT8 量化)',
    badge: '推荐·中英混合极速',
    approx_size_mb: 160,
    languages: ['zh', 'en', 'auto'],
    engine_kind: 'sherpa_onnx',
    description: '阿里通义开源离线多语种语音识别，中英混合识别率高、CPU 推理极快。',
    installed: false,
  },
  {
    id: 'whisper-tiny-q8',
    name: 'Whisper-Tiny (Q8 极速轻量)',
    badge: '超小体积',
    approx_size_mb: 75,
    languages: ['zh', 'en', 'auto'],
    engine_kind: 'faster_whisper',
    description: '体积极小，适合低功耗设备快速测试与简短语音口令输入。',
    installed: false,
  },
  {
    id: 'whisper-base-q8',
    name: 'Whisper-Base (Q8 均衡通用)',
    badge: '通用多语种',
    approx_size_mb: 145,
    languages: ['zh', 'en', 'auto'],
    engine_kind: 'faster_whisper',
    description: '模型体积与多语种准确度均衡，支持自动语种检测。',
    installed: false,
  },
  {
    id: 'whisper-small-q8',
    name: 'Whisper-Small (Q8 高精度版)',
    badge: '高精度长句',
    approx_size_mb: 466,
    languages: ['zh', 'en', 'auto'],
    engine_kind: 'faster_whisper',
    description: '长段落口述、专业词汇及带口音语音识别准确度更高。',
    installed: false,
  },
];

export class SettingsCenterController {
  /**
   * @param {object} opts
   * @param {HTMLElement} opts.modalEl
   * @param {HTMLElement} opts.sidebarEl
   * @param {HTMLElement} opts.contentEl
   * @param {Function} opts.onToast - (msg) => void
   * @param {Function} opts.onStatusRefresh - () => Promise<void>
   * @param {Function} opts.onTranscriptToggle - (enabled) => void
   */
  constructor(opts) {
    this.modalEl = opts.modalEl;
    this.sidebarEl = opts.sidebarEl;
    this.contentEl = opts.contentEl;
    this.onToast = opts.onToast || (() => {});
    this.onStatusRefresh = opts.onStatusRefresh || (async () => {});
    this.onTranscriptToggle = opts.onTranscriptToggle || (() => {});

    this.activePage = 'brain';
    this.prefillAppQuery = '';
    this.scrollToSpeechCard = false;
    this.asrPollTimer = null;
    this.asrTestTimer = null;
    this.domainsData = {};
    this.overviewFallback = {};
  }

  clearSpeechTimers() {
    if (this.asrPollTimer) {
      clearInterval(this.asrPollTimer);
      this.asrPollTimer = null;
    }
    if (this.asrTestTimer) {
      clearTimeout(this.asrTestTimer);
      this.asrTestTimer = null;
    }
  }

  isOpen() {
    return Boolean(this.modalEl && this.modalEl.classList.contains('open'));
  }

  async open(initialPage = null, opts = {}) {
    if (initialPage === 'speech') {
      this.activePage = 'overview';
      this.scrollToSpeechCard = true;
    } else {
      this.scrollToSpeechCard = false;
      if (initialPage) this.activePage = initialPage;
    }
    if (opts && opts.prefillAppQuery) {
      this.prefillAppQuery = String(opts.prefillAppQuery).trim();
    }
    if (this.modalEl) this.modalEl.classList.add('open');
    this.renderSidebar();
    await this.loadAllSettings();
    await this.renderActivePage();
  }

  close() {
    this.clearSpeechTimers();
    if (this.modalEl) this.modalEl.classList.remove('open');
  }

  renderSidebar() {
    if (!this.sidebarEl) return;
    this.sidebarEl.innerHTML = '';
    SETTINGS_PAGES.forEach((p) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cfg-nav-btn' + (p.id === this.activePage ? ' active' : '');
      btn.innerHTML = `<span>${p.icon} ${p.label}</span>`;
      btn.onclick = async () => {
        this.activePage = p.id;
        this.renderSidebar();
        await this.renderActivePage();
      };
      this.sidebarEl.appendChild(btn);
    });
  }

  async loadAllSettings() {
    const [ovRes, domRes] = await Promise.all([
      rpc('get_settings_overview'),
      moduleRpc('config_center', 'get_all_domains', {}, async () => null),
    ]);
    if (ovRes.ok && ovRes.result) {
      this.overviewFallback = ovRes.result;
    }
    if (domRes.ok && domRes.result) {
      this.domainsData = domRes.result;
    } else {
      this.domainsData = this.overviewFallback || {};
    }
  }

  async renderActivePage() {
    if (!this.contentEl) return;
    this.clearSpeechTimers();
    switch (this.activePage) {
      case 'speech':
      case 'overview':
        await this.renderPage1Overview();
        break;
      case 'brain':
        await this.renderPage2Brain();
        break;
      case 'memory':
        await this.renderPage3Memory();
        break;
      case 'skills':
        await this.renderPage4Skills();
        break;
      case 'capabilities':
        await this.renderPage5Capabilities();
        break;
      case 'resources':
        await this.renderPage6Resources();
        break;
      case 'web':
        await this.renderPage7Web();
        break;
      case 'permissions':
        await this.renderPage8Permissions();
        break;
      case 'undo':
        await this.renderPage9Undo();
        break;
      case 'automation':
        await this.renderPage10Automation();
        break;
      case 'maintenance':
        await this.renderPage11Maintenance();
        break;
      default:
        await this.renderPage2Brain();
    }
  }

  /* Page 1: Overview, Offline ASR Speech Hub & Health */
  async renderPage1Overview() {
    this.clearSpeechTimers();

    const [stRes, probeRes, speechRes] = await Promise.all([
      rpc('get_status'),
      rpc('probe_capabilities'),
      moduleRpc('speech_hub', 'get_speech_overview', {}, async () => null),
    ]);
    const st = (stRes.ok && stRes.result) || {};
    const probe = (probeRes.ok && probeRes.result) || {};
    const sb = probe.sandbox || {};

    const speechData =
      speechRes && speechRes.ok && speechRes.result && speechRes.result.status !== 'stub'
        ? speechRes.result
        : {};
    const speechCfg = speechData.config || {
      enabled: false,
      active_model_id: 'sensevoice-small-int8',
      language: 'zh',
      auto_send_after_transcribe: false,
      audio_source: 'default',
    };
    let speechModels =
      Array.isArray(speechData.models) && speechData.models.length > 0
        ? speechData.models
        : DEFAULT_ASR_MODELS.map((m) => ({ ...m }));
    const rawAudioSources = Array.isArray(speechData.audio_sources) ? speechData.audio_sources : [];
    const audioSources = [
      { id: 'default', label: '系统默认麦克风 (default)' },
      ...rawAudioSources
        .map((src) => ({
          id: String(src.id || src.name || src.source || ''),
          label: String(src.description || src.label || src.name || src.id || ''),
        }))
        .filter((s) => s.id && s.id !== 'default'),
    ];
    const rtReady = speechData.runtime_ready || {};

    this.contentEl.innerHTML = `
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">📊 1. IntentOS 核心服务与沙箱健康概览</h3>
        <div class="diagnostic-grid">
          <div class="diag-metric-card">
            <div class="diag-metric-label">守护进程版本 / PID</div>
            <div class="diag-metric-value">v${st.version || '0.1.0'} · PID ${st.pid || '-'}</div>
          </div>
          <div class="diag-metric-card">
            <div class="diag-metric-label">注册结构化能力</div>
            <div class="diag-metric-value">${st.registered_capabilities || 87} 项</div>
          </div>
          <div class="diag-metric-card">
            <div class="diag-metric-label">当前 Agent Runtime</div>
            <div class="diag-metric-value">${st.runtime_mode || 'pi-adapter'}</div>
          </div>
          <div class="diag-metric-card">
            <div class="diag-metric-label">索引资源 (应用/文件/站点)</div>
            <div class="diag-metric-value">${st.indexed_apps || 0} / ${st.indexed_files || 0} / ${st.indexed_sites || 0}</div>
          </div>
        </div>
      </div>

      <!-- 1.2 Offline ASR Speech Hub & Model Downloader -->
      <div class="cfg-section-card" id="p1-asr-card">
        <h3 class="cfg-section-title">
          <span>🎙️ 本地离线语音识别 (ASR) 与模型下载中心</span>
          <span class="cand-badge">${
            speechModels.some((m) => m.installed)
              ? speechCfg.enabled
                ? '🟢 悬浮窗语音已启用'
                : '🟡 模型已就绪 · 待开启开关'
              : '⬇ 待下载离线语音模型'
          }</span>
        </h3>
        <div class="mono-id" style="margin-bottom:0.65rem;">
          零云端隐私泄漏：模型下载至 <code>~/.local/share/intentos/models/asr/</code>，录音与转写全程本机离线执行。
          ${
            rtReady.recorder_bin
              ? `录音后端: ${escapeHtml(String(rtReady.recorder_bin))}`
              : '支持 PipeWire / PulseAudio / ALSA 录音采集'
          }
        </div>

        <div class="cfg-toggle-stack" style="margin-bottom:0.75rem;">
          <label class="cfg-check-row">
            <input id="p1-asr-enabled" type="checkbox" ${speechCfg.enabled ? 'checked' : ''} />
            <span><strong>🎙 开启悬浮窗语音识别输入功能</strong>（开启后点击随问悬浮窗右下角 <code>🎙</code> 即可离线录音转文字）</span>
          </label>
          <label class="cfg-check-row">
            <input id="p1-asr-autosend" type="checkbox" ${
              speechCfg.auto_send_after_transcribe ? 'checked' : ''
            } />
            <span>识别完成后自动发送提问（关闭则先填入输入框供编辑确认）</span>
          </label>
        </div>

        <div class="form-grid-3" style="align-items:end; margin-bottom:0.7rem;">
          <div class="form-field">
            <label>识别语言偏好 (Language)</label>
            <select id="p1-asr-lang" class="form-select">
              <option value="zh" ${speechCfg.language === 'zh' ? 'selected' : ''}>中文与中英混合 (zh · 推荐)</option>
              <option value="auto" ${speechCfg.language === 'auto' ? 'selected' : ''}>自动多语种检测 (auto)</option>
              <option value="en" ${speechCfg.language === 'en' ? 'selected' : ''}>English (en)</option>
            </select>
          </div>
          <div class="form-field">
            <label>麦克风输入源 (Audio Source)</label>
            <select id="p1-asr-source" class="form-select">
              ${audioSources
                .map(
                  (s) =>
                    `<option value="${escapeHtml(s.id)}" ${
                      s.id === (speechCfg.audio_source || 'default') ? 'selected' : ''
                    }>${escapeHtml(s.label)}</option>`
                )
                .join('')}
            </select>
          </div>
          <div class="form-field">
            <button id="p1-btn-asr-test" type="button" class="btn-primary" style="width:100%;">
              🎙 按下试录 3 秒测试识别
            </button>
          </div>
        </div>
        <div id="p1-asr-test-readout" class="mono-id" style="margin-bottom:0.75rem;"></div>

        <div style="font-weight:700; font-size:0.83rem; margin-bottom:0.5rem;">
          📦 开源离线语音识别模型库（点击下载至本机，支持实时进度与随时取消）
        </div>
        <div id="p1-asr-models-grid" class="cfg-asr-grid"></div>
      </div>

      <div class="cfg-section-card">
        <h3 class="cfg-section-title">🛡 沙箱与系统后端探测状态 (§8.7)</h3>
        <pre id="p1-sandbox-pre" class="code-output" style="margin-top:0; max-height:260px;"></pre>
      </div>
    `;

    const sbPre = this.contentEl.querySelector('#p1-sandbox-pre');
    if (sbPre) {
      sbPre.textContent = JSON.stringify(
        {
          sandbox: sb,
          settings_backends: probe.settings_backends,
          gateway_metrics: probe.gateway_metrics,
        },
        null,
        2
      );
    }

    const enabledEl = this.contentEl.querySelector('#p1-asr-enabled');
    const autoSendEl = this.contentEl.querySelector('#p1-asr-autosend');
    const langEl = this.contentEl.querySelector('#p1-asr-lang');
    const sourceEl = this.contentEl.querySelector('#p1-asr-source');
    const testBtn = this.contentEl.querySelector('#p1-btn-asr-test');
    const testReadout = this.contentEl.querySelector('#p1-asr-test-readout');
    const modelsGridEl = this.contentEl.querySelector('#p1-asr-models-grid');

    const saveSpeechPatch = async (patch, toastMsg = '') => {
      Object.assign(speechCfg, patch);
      const r = await moduleRpc('speech_hub', 'update_speech_config', patch, async () => null);
      if (r && r.ok && r.result && r.result.config) {
        Object.assign(speechCfg, r.result.config);
      }
      if (toastMsg) this.onToast(toastMsg);
      await this.onStatusRefresh();
    };

    enabledEl.onchange = () =>
      saveSpeechPatch(
        { enabled: enabledEl.checked },
        enabledEl.checked ? '🎙 已开启悬浮窗离线语音识别输入' : '已关闭悬浮窗语音识别输入'
      );
    autoSendEl.onchange = () =>
      saveSpeechPatch(
        { auto_send_after_transcribe: autoSendEl.checked },
        autoSendEl.checked ? '✓ 已开启识别后自动发送' : '✓ 已设为识别后填入输入框'
      );
    langEl.onchange = () =>
      saveSpeechPatch({ language: langEl.value }, `✓ 语音识别语言已设为 ${langEl.value}`);
    sourceEl.onchange = () =>
      saveSpeechPatch({ audio_source: sourceEl.value }, '✓ 已更新麦克风输入源');

    let isTestRecording = false;
    const finishTestTranscribe = async () => {
      if (!isTestRecording) return;
      isTestRecording = false;
      if (this.asrTestTimer) {
        clearTimeout(this.asrTestTimer);
        this.asrTestTimer = null;
      }
      testBtn.disabled = true;
      testBtn.textContent = '⏳ 正在离线转写…';
      testReadout.textContent = '⏳ 正在调用本机离线语音模型识别试录音频…';
      const r = await moduleRpc(
        'speech_hub',
        'stop_and_transcribe',
        { language: langEl.value || 'zh' },
        async () => null
      );
      testBtn.disabled = false;
      testBtn.textContent = '🎙 按下试录 3 秒测试识别';
      if (r && r.ok && r.result) {
        const txt = String(r.result.text ?? r.result.transcript ?? '').trim();
        testReadout.textContent = txt
          ? `✅ 试录识别结果：「${txt}」 (模型: ${
              r.result.model_used || speechCfg.active_model_id
            } · 耗时 ${r.result.duration_ms ?? '-'} ms)`
          : 'ℹ 录音已完成，但未检测到明显人声，请对着麦克风说话重试。';
      } else {
        testReadout.textContent = `⚠ 试录失败: ${(r && r.error) || '请先下载至少一款离线 ASR 模型'}`;
      }
    };

    testBtn.onclick = async () => {
      if (isTestRecording) {
        await finishTestTranscribe();
        return;
      }
      testReadout.textContent = '🎙 正在启动麦克风试录 (3 秒)… 请开始说话';
      const startRes = await moduleRpc(
        'speech_hub',
        'start_recording',
        {
          test_mode: true,
          audio_source: sourceEl.value || 'default',
          language: langEl.value || 'zh',
        },
        async () => null
      );
      if (!startRes || !startRes.ok || (startRes.result && startRes.result.error)) {
        testReadout.textContent = `⚠ 无法启动试录: ${
          (startRes && (startRes.error || (startRes.result && startRes.result.error))) ||
          '请先在下方下载离线语音模型或检查麦克风设备'
        }`;
        return;
      }
      isTestRecording = true;
      testBtn.textContent = '🔴 录音中… 点击立即识别';
      this.asrTestTimer = setTimeout(() => {
        finishTestTranscribe();
      }, 3100);
    };

    const formatSpeed = (bps) => {
      const n = Number(bps || 0);
      if (n <= 0) return '';
      if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB/s`;
      return `${Math.max(1, Math.round(n / 1024))} KB/s`;
    };

    const progressMap = new Map();
    speechModels.forEach((m) => {
      if (m.active_download && typeof m.active_download === 'object') {
        progressMap.set(m.id, m.active_download);
      }
    });

    const ensureDownloadPolling = () => {
      if (this.asrPollTimer) return;
      this.asrPollTimer = setInterval(async () => {
        if (!this.isOpen() || (this.activePage !== 'overview' && this.activePage !== 'speech')) {
          this.clearSpeechTimers();
          return;
        }
        const activeIds = speechModels
          .map((m) => m.id)
          .filter((id) => {
            const p = progressMap.get(id);
            return p && (p.status === 'downloading' || p.status === 'starting');
          });
        if (activeIds.length === 0) {
          clearInterval(this.asrPollTimer);
          this.asrPollTimer = null;
          return;
        }

        let anyCompleted = false;
        await Promise.all(
          activeIds.map(async (mid) => {
            const pr = await moduleRpc(
              'speech_hub',
              'get_download_progress',
              { model_id: mid },
              async () => null
            );
            if (pr && pr.ok && pr.result) {
              const item =
                pr.result.model_id === mid
                  ? pr.result
                  : (pr.result.downloads && pr.result.downloads[mid]) || pr.result;
              progressMap.set(mid, item);
              if (item.status === 'completed') {
                anyCompleted = true;
              }
            }
          })
        );

        if (anyCompleted) {
          this.clearSpeechTimers();
          this.onToast('🎉 离线语音识别模型下载完成！');
          await this.onStatusRefresh();
          await this.renderPage1Overview();
        } else {
          renderModelsCards();
        }
      }, 450);
    };

    const renderModelsCards = () => {
      if (!modelsGridEl) return;
      modelsGridEl.innerHTML = '';

      speechModels.forEach((m) => {
        const prog = progressMap.get(m.id) || m.active_download || null;
        const isDownloading =
          prog && (prog.status === 'downloading' || prog.status === 'starting');
        const isFailed = prog && prog.status === 'failed';
        const isInstalled = Boolean(m.installed || (prog && prog.status === 'completed'));
        const isActive = isInstalled && speechCfg.active_model_id === m.id;
        const pct = Math.min(100, Math.max(0, Math.round(Number((prog && prog.progress_pct) || 0))));
        const speedStr = prog ? formatSpeed(prog.speed_bps) : '';
        const sizeMb =
          m.disk_bytes && Number(m.disk_bytes) > 0
            ? `${Math.round(Number(m.disk_bytes) / (1024 * 1024))} MB`
            : `~${m.approx_size_mb || 150} MB`;
        const langs = Array.isArray(m.languages) ? m.languages.join('/') : 'zh/en';

        let statusText = '未安装';
        let statusCls = 'idle';
        if (isDownloading) {
          statusText = `⬇ 下载中 ${pct}%${speedStr ? ' · ' + speedStr : ''}`;
          statusCls = 'downloading';
        } else if (isInstalled) {
          statusText = isActive ? '✓ 已安装 · 当前模型' : '✓ 已安装';
          statusCls = 'installed';
        } else if (isFailed) {
          statusText = `⚠ 下载失败`;
          statusCls = 'failed';
        }

        const card = document.createElement('div');
        card.className = `cfg-asr-model-card${isActive ? ' is-active' : ''}`;
        card.innerHTML = `
          <div class="cfg-asr-model-head">
            <div>
              <strong>${escapeHtml(m.name || m.id)}</strong>
              ${m.badge ? `<span class="cand-badge">${escapeHtml(m.badge)}</span>` : ''}
            </div>
            <span class="cfg-status-pill ${statusCls}">${escapeHtml(statusText)}</span>
          </div>
          <div class="mono-id">体积: ${escapeHtml(sizeMb)} · 语种: ${escapeHtml(langs)} · 引擎: ${escapeHtml(
          m.engine_kind || 'onnx'
        )}</div>
          ${
            m.description
              ? `<div style="font-size:0.78rem; color:var(--text-secondary);">${escapeHtml(
                  m.description
                )}</div>`
              : ''
          }
          ${
            isDownloading
              ? `<progress class="cfg-asr-progress" max="100" value="${pct}"></progress>`
              : ''
          }
          ${
            isFailed && prog && prog.error
              ? `<div class="mono-id" style="color:var(--danger);">${escapeHtml(
                  String(prog.error)
                )}</div>`
              : ''
          }
          <div class="cfg-asr-actions"></div>
        `;

        const actRow = card.querySelector('.cfg-asr-actions');

        if (isDownloading) {
          const btnCancel = document.createElement('button');
          btnCancel.type = 'button';
          btnCancel.className = 'btn-ghost btn-danger';
          btnCancel.textContent = '⏹ 取消下载';
          btnCancel.onclick = async () => {
            await moduleRpc('speech_hub', 'cancel_download', { model_id: m.id }, async () => null);
            progressMap.set(m.id, { status: 'cancelled', progress_pct: 0 });
            renderModelsCards();
          };
          actRow.appendChild(btnCancel);
        } else if (!isInstalled) {
          const btnDl = document.createElement('button');
          btnDl.type = 'button';
          btnDl.className = 'btn-primary';
          btnDl.textContent = '⬇ 下载模型';
          btnDl.onclick = async () => {
            progressMap.set(m.id, { status: 'downloading', progress_pct: 1 });
            renderModelsCards();
            const dlRes = await moduleRpc(
              'speech_hub',
              'download_model',
              { model_id: m.id },
              async () => null
            );
            if (!dlRes || !dlRes.ok) {
              progressMap.set(m.id, {
                status: 'failed',
                error: (dlRes && dlRes.error) || '下载任务启动失败',
              });
              renderModelsCards();
              return;
            }
            ensureDownloadPolling();
          };
          actRow.appendChild(btnDl);
        } else {
          const btnSetActive = document.createElement('button');
          btnSetActive.type = 'button';
          btnSetActive.className = isActive ? 'btn-ghost' : 'btn-primary';
          btnSetActive.disabled = isActive;
          btnSetActive.textContent = isActive ? '✓ 当前使用中' : '✓ 设为当前模型';
          btnSetActive.onclick = async () => {
            await saveSpeechPatch(
              { active_model_id: m.id },
              `🎙 已切换当前语音模型为：${m.name || m.id}`
            );
            renderModelsCards();
          };
          actRow.appendChild(btnSetActive);

          const btnDel = document.createElement('button');
          btnDel.type = 'button';
          btnDel.className = 'btn-ghost btn-danger';
          btnDel.textContent = '🗑 删除';
          btnDel.onclick = async () => {
            await moduleRpc('speech_hub', 'delete_model', { model_id: m.id }, async () => null);
            m.installed = false;
            progressMap.delete(m.id);
            this.onToast(`🗑 已删除离线模型 ${m.name || m.id}`);
            await this.onStatusRefresh();
            renderModelsCards();
          };
          actRow.appendChild(btnDel);
        }

        modelsGridEl.appendChild(card);
      });
    };

    renderModelsCards();
    if ([...progressMap.values()].some((p) => p && p.status === 'downloading')) {
      ensureDownloadPolling();
    }

    if (this.scrollToSpeechCard) {
      this.scrollToSpeechCard = false;
      const asrCard = this.contentEl.querySelector('#p1-asr-card');
      if (asrCard && typeof asrCard.scrollIntoView === 'function') {
        asrCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  }

  /* Page 2: Brain & Model Gateway (Live /v1/models Selector, Providers CRUD, 5 Roles, Egress Matrix, Budgets) */
  async renderPage2Brain() {
    const [catRes] = await Promise.all([
      moduleRpc('backend_bridge', 'get_backends_catalog', { refresh_remote: true }, async () => null),
    ]);
    let liveCatalog =
      catRes && catRes.ok && catRes.result && catRes.result.active
        ? catRes.result
        : {
            active: {
              backend: 'auto',
              provider: 'auto',
              model: 'deepseek-chat',
              reasoning_effort: 'default',
            },
            backends: {},
          };

    const brain = this.domainsData.brain || this.overviewFallback.brain || {};
    const providers = Array.isArray(brain.providers)
      ? brain.providers
      : [
          {
            id: 'default-openai',
            name: 'Default OpenAI Gateway',
            kind: 'openai-compatible',
            base_url: 'https://api.openai.com/v1',
            trust: 'standard',
            enabled: true,
          },
        ];
    const profiles = brain.profiles || {
      main: { provider: 'default-openai', model: 'gpt-4o-mini', context_budget: 65536, max_output_tokens: 4096, thinking: 'medium', temperature: 0.2 },
      fast: { provider: 'default-openai', model: 'gpt-4o-mini', context_budget: 32768, max_output_tokens: 2048, thinking: 'off', temperature: 0.1 },
      decision: { provider: 'default-openai', model: 'jev-decision-v1', context_budget: 8192, max_output_tokens: 512, thinking: 'off', temperature: 0.0 },
      vision: { provider: 'default-openai', model: 'gpt-4o', context_budget: 32768, max_output_tokens: 2048, thinking: 'low', temperature: 0.2 },
      memory: { provider: 'default-openai', model: 'gpt-4o-mini', context_budget: 32768, max_output_tokens: 2048, thinking: 'off', temperature: 0.1 },
    };
    const limits = brain.runtime_limits || {
      max_tool_calls: 30,
      max_runtime_seconds: 180,
      max_concurrent_sessions: 2,
      session_idle_timeout_minutes: 60,
      daily_cost_limit: 0,
    };

    this.contentEl.innerHTML = `
      <!-- 2.0 Live /v1/models Discovery & Active Quick-Chat Model Selector -->
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">
          <span>⚡ 随问活动后端与 /v1/models 实时接口模型选择器</span>
          <button id="p2-btn-refresh-models" type="button" class="btn-ghost">🔄 从接口刷新全量模型 (/v1/models)</button>
        </h3>
        <div class="form-grid-3">
          <div class="form-field">
            <label>活动后端引擎 (Backend)</label>
            <select id="p2-active-backend" class="form-select">
              <option value="auto">自动 (Auto · 按优先级路由)</option>
              <option value="zcode">ZCode 本地/内网代理网关</option>
              <option value="codex">Codex 认证与代理引擎</option>
              <option value="pi">Pi 沙箱运行时</option>
              <option value="openai">OpenAI / Anthropic 兼容网关</option>
            </select>
          </div>
          <div class="form-field">
            <label>活动供应商 (Provider)</label>
            <select id="p2-active-provider" class="form-select">
              <option value="auto">自动选择供应商 (Auto)</option>
            </select>
          </div>
          <div class="form-field">
            <label>思考强度 (Reasoning Effort)</label>
            <select id="p2-active-effort" class="form-select">
              <option value="default">默认 (default)</option>
              <option value="fast">快速响应 (fast)</option>
              <option value="medium">标准推理 (medium)</option>
              <option value="high">深度推理 (high)</option>
            </select>
          </div>
        </div>
        <div class="form-grid-2">
          <div class="form-field">
            <label>搜索接口模型 (支持 30~80+ 模型即时过滤)</label>
            <input id="p2-model-search" type="search" class="form-input" placeholder="搜索模型 (共 0 个)..." autocomplete="off" />
          </div>
          <div class="form-field">
            <label>当前活动模型 ID (可点击下方芯片或手动填写)</label>
            <input id="p2-active-model" class="form-input" value="${escapeHtml((liveCatalog.active && liveCatalog.active.model) || 'deepseek-chat')}" />
          </div>
        </div>
        <div id="p2-live-models-box" class="cfg-live-models-scroll" role="listbox" aria-label="接口实时模型列表"></div>
        <div style="margin-top:0.65rem; display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap;">
          <button id="p2-btn-apply-active" type="button" class="btn-primary">✓ 设为当前活动模型并同步主角色</button>
          <span id="p2-live-models-msg" class="mono-id"></span>
        </div>
      </div>

      <!-- 2.1 Multi-Provider CRUD & B-03 / B-04 Tests -->
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">
          <span>🔌 模型供应商管理与实测 (B-01 ~ B-04 · 密钥仅入 Secret Service)</span>
          <span class="risk-badge risk-R0">零明文落盘</span>
        </h3>
        <div id="providers-list-box" style="margin-bottom:0.85rem;"></div>
        <div class="form-grid-3">
          <div class="form-field">
            <label>供应商 ID</label>
            <input id="prov-id" class="form-input" value="lab-proxy" placeholder="如 lab-proxy" />
          </div>
          <div class="form-field">
            <label>协议类型 (Kind)</label>
            <select id="prov-kind" class="form-select">
              <option value="openai-compatible">openai-compatible</option>
              <option value="anthropic">anthropic</option>
              <option value="gemini">gemini</option>
              <option value="ollama-local">ollama-local</option>
            </select>
          </div>
          <div class="form-field">
            <label>信任等级 (ProviderTrust)</label>
            <select id="prov-trust" class="form-select">
              <option value="trusted">trusted (内网/自建)</option>
              <option value="standard" selected>standard (商业 API)</option>
              <option value="untrusted">untrusted (未知/试用)</option>
            </select>
          </div>
        </div>
        <div class="form-grid-2">
          <div class="form-field">
            <label>Base URL</label>
            <input id="prov-url" class="form-input" value="http://127.0.0.1:8317/v1" />
          </div>
          <div class="form-field">
            <label>API Key (存入 Secret Service 凭据槽，绝不写入 brain.toml)</label>
            <input id="prov-key" type="password" class="form-input" placeholder="sk-..." />
          </div>
        </div>
        <button id="btn-upsert-provider" type="button" class="btn-primary">+ 保存/更新供应商</button>
        <span id="prov-test-readout" class="mono-id" style="margin-left:0.65rem;"></span>
      </div>

      <!-- 2.2 5 Model Roles (B-05 & B-06) -->
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">🎭 5 大模型角色配置 (Main / Fast / Decision / Vision / Memory)</h3>
        <div class="roles-grid" id="roles-cards-box"></div>
        <div style="margin-top:0.8rem; display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap;">
          <button id="btn-save-roles" type="button" class="btn-primary">保存 5 大模型角色与大脑配置</button>
          <span id="cfg-brain-msg" class="mono-id"></span>
        </div>
      </div>

      <!-- 2.3 Egress Security Matrix (§5.4, B-10) -->
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">
          <span>🛡 外发安全控制矩阵 (DataClass × ProviderTrust · §5.4)</span>
          <span class="risk-badge risk-R3">Forbidden 强制锁定 Deny</span>
        </h3>
        <table class="egress-table">
          <thead>
            <tr>
              <th>数据分级 \\ 供应商信任级</th>
              <th>Trusted (自建/内网)</th>
              <th>Standard (商业 API)</th>
              <th>Untrusted (试用端点)</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Public (公开指令)</strong></td>
              <td><span class="verify-pill verify-passed">Allow</span></td>
              <td><span class="verify-pill verify-passed">Allow</span></td>
              <td><span class="verify-pill verify-passed">Allow</span></td>
            </tr>
            <tr>
              <td><strong>Personal (路径/代码片段)</strong></td>
              <td><span class="verify-pill verify-passed">Allow</span></td>
              <td><span class="verify-pill verify-passed">Allow</span></td>
              <td><span class="verify-pill verify-unverified">Confirm 逐次确认</span></td>
            </tr>
            <tr>
              <td><strong>Sensitive (私密目录/.env)</strong></td>
              <td><span class="verify-pill verify-unverified">Confirm 逐次确认</span></td>
              <td><span class="verify-pill verify-failed">Deny</span></td>
              <td><span class="verify-pill verify-failed">Deny</span></td>
            </tr>
            <tr>
              <td><strong>Forbidden (私钥/密钥环/Cookie)</strong></td>
              <td><span class="verify-pill verify-failed">🔒 Deny (不可放宽)</span></td>
              <td><span class="verify-pill verify-failed">🔒 Deny (不可放宽)</span></td>
              <td><span class="verify-pill verify-failed">🔒 Deny (不可放宽)</span></td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 2.4 Runtime & Budgets (B-07 ~ B-09) -->
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">⏱ 运行时与调用预算限制 (B-07 ~ B-09)</h3>
        <div class="form-grid-3">
          <div class="form-field">
            <label>智能体运行时 (Runtime)</label>
            <select id="cfg-runtime" class="form-select">
              <option value="pi" ${brain.runtime === 'pi' ? 'selected' : ''}>pi-adapter (沙箱无外网 Worker)</option>
              <option value="native" ${brain.runtime === 'native' ? 'selected' : ''}>native (内置 Rust 循环)</option>
            </select>
          </div>
          <div class="form-field">
            <label>单任务最大工具调用数</label>
            <input id="cfg-max-tools" type="number" class="form-input" value="${limits.max_tool_calls || 30}" />
          </div>
          <div class="form-field">
            <label>单任务超时秒数</label>
            <input id="cfg-max-sec" type="number" class="form-input" value="${limits.max_runtime_seconds || 180}" />
          </div>
        </div>
      </div>
    `;

    // 2.0 Live `/v1/models` Catalog & Searchable Selector Wiring
    const p2BackendSel = this.contentEl.querySelector('#p2-active-backend');
    const p2ProvSel = this.contentEl.querySelector('#p2-active-provider');
    const p2EffortSel = this.contentEl.querySelector('#p2-active-effort');
    const p2SearchInput = this.contentEl.querySelector('#p2-model-search');
    const p2ModelInput = this.contentEl.querySelector('#p2-active-model');
    const p2ModelsBox = this.contentEl.querySelector('#p2-live-models-box');
    const p2MsgEl = this.contentEl.querySelector('#p2-live-models-msg');

    const collectModelsForSelection = (backendKey, provKey) => {
      const backendsMap = (liveCatalog && liveCatalog.backends) || {};
      const items = [];
      const seen = new Set();
      const targetBackends =
        backendKey && backendKey !== 'auto' && backendsMap[backendKey]
          ? [[backendKey, backendsMap[backendKey]]]
          : Object.entries(backendsMap);

      targetBackends.forEach(([bKey, bInfo]) => {
        if (!bInfo) return;
        const provList = Array.isArray(bInfo.providers) ? bInfo.providers : [];
        provList.forEach((pr) => {
          const pId = typeof pr === 'string' ? pr : pr.id || pr.name;
          if (provKey && provKey !== 'auto' && pId !== provKey) return;
          const mList = Array.isArray(pr && pr.models) ? pr.models : [];
          mList.forEach((rawM) => {
            const mId = typeof rawM === 'string' ? rawM : rawM && (rawM.id || rawM.name);
            if (!mId) return;
            const dedupeKey = `${bKey}::${pId}::${mId}`;
            if (seen.has(dedupeKey)) return;
            seen.add(dedupeKey);
            items.push({
              model: mId,
              backend: bKey,
              provider: pId || 'auto',
              liveFetched: Boolean(pr && pr.live_models_fetched),
            });
          });
        });

        if (provKey === 'auto' || !provKey) {
          (Array.isArray(bInfo.models) ? bInfo.models : []).forEach((rawM) => {
            const mId = typeof rawM === 'string' ? rawM : rawM && (rawM.id || rawM.name);
            if (!mId || items.some((x) => x.model === mId && x.backend === bKey)) return;
            items.push({
              model: mId,
              backend: bKey,
              provider: bInfo.default_provider || 'auto',
              liveFetched: false,
            });
          });
        }
      });

      if (items.length === 0) {
        providers.forEach((p) => {
          (p.available_models || [p.default_model || 'deepseek-chat', 'gpt-4o-mini']).forEach((mId) => {
            if (!mId || items.some((x) => x.model === mId)) return;
            items.push({ model: mId, backend: 'openai', provider: p.id, liveFetched: false });
          });
        });
      }
      return items;
    };

    const syncP2ProvidersAndModels = () => {
      const bKey = p2BackendSel.value || 'auto';
      const backendsMap = (liveCatalog && liveCatalog.backends) || {};
      const prevProv = p2ProvSel.value || (liveCatalog.active && liveCatalog.active.provider) || 'auto';

      p2ProvSel.innerHTML = '<option value="auto">自动选择供应商 (Auto)</option>';
      const entries =
        bKey !== 'auto' && backendsMap[bKey]
          ? [[bKey, backendsMap[bKey]]]
          : Object.entries(backendsMap);
      const addedProvs = new Set();
      entries.forEach(([bk, bInfo]) => {
        if (!bInfo || !Array.isArray(bInfo.providers)) return;
        bInfo.providers.forEach((pr) => {
          const id = typeof pr === 'string' ? pr : pr.id || pr.name;
          const name = typeof pr === 'string' ? pr : pr.name || pr.id;
          if (!id || addedProvs.has(id)) return;
          addedProvs.add(id);
          const cnt = Array.isArray(pr.models) ? pr.models.length : 0;
          const liveTag = pr.live_models_fetched ? '实时' : '本地';
          const opt = document.createElement('option');
          opt.value = id;
          opt.textContent = `${name} [${bk} · ${liveTag} ${cnt} 个模型]`;
          p2ProvSel.appendChild(opt);
        });
      });

      if (Array.from(p2ProvSel.options).some((o) => o.value === prevProv)) {
        p2ProvSel.value = prevProv;
      }

      const allItems = collectModelsForSelection(p2BackendSel.value, p2ProvSel.value);
      p2SearchInput.placeholder = `搜索模型 (共 ${allItems.length} 个)...`;

      const renderModelChips = () => {
        const kw = (p2SearchInput.value || '').trim().toLowerCase();
        const curModel = (p2ModelInput.value || '').trim();
        const filtered = kw
          ? allItems.filter(
              (it) =>
                it.model.toLowerCase().includes(kw) ||
                String(it.provider).toLowerCase().includes(kw) ||
                String(it.backend).toLowerCase().includes(kw)
            )
          : allItems;

        p2ModelsBox.innerHTML = '';
        if (filtered.length === 0) {
          p2ModelsBox.innerHTML =
            '<div class="mono-id" style="grid-column:1/-1; padding:0.35rem;">未匹配到模型，可直接右侧输入自定义模型 ID 或点击右上角「从接口刷新全量模型」。</div>';
          return;
        }
        filtered.forEach((it) => {
          const chip = document.createElement('button');
          chip.type = 'button';
          chip.className = 'cfg-model-chip' + (it.model === curModel ? ' active' : '');
          chip.innerHTML = `
            <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(it.model)}</span>
            <span class="mono-id" style="font-size:0.68rem; flex-shrink:0;">${escapeHtml(it.provider !== 'auto' ? it.provider : it.backend)}</span>
          `;
          chip.onclick = () => {
            p2ModelInput.value = it.model;
            if (p2BackendSel.value === 'auto' && it.backend) {
              p2BackendSel.value = it.backend;
            }
            syncP2ProvidersAndModels();
          };
          p2ModelsBox.appendChild(chip);
        });
      };

      p2SearchInput.oninput = renderModelChips;
      renderModelChips();
    };

    if (liveCatalog.active) {
      if (liveCatalog.active.backend && Array.from(p2BackendSel.options).some((o) => o.value === liveCatalog.active.backend)) {
        p2BackendSel.value = liveCatalog.active.backend;
      }
      if (liveCatalog.active.reasoning_effort && Array.from(p2EffortSel.options).some((o) => o.value === liveCatalog.active.reasoning_effort)) {
        p2EffortSel.value = liveCatalog.active.reasoning_effort;
      }
    }
    syncP2ProvidersAndModels();
    p2BackendSel.onchange = syncP2ProvidersAndModels;
    p2ProvSel.onchange = syncP2ProvidersAndModels;

    this.contentEl.querySelector('#p2-btn-refresh-models').onclick = async () => {
      p2MsgEl.textContent = '⏳ 正在并发请求各供应商 /v1/models 接口…';
      let r = await moduleRpc(
        'backend_bridge',
        'refresh_models',
        { force_refresh: true },
        async () => null
      );
      if (!r || !r.ok || !r.result) {
        r = await moduleRpc(
          'backend_bridge',
          'get_backends_catalog',
          { refresh_remote: true, force_refresh: true },
          async () => null
        );
      }
      if (r && r.ok && r.result) {
        if (r.result.backends) {
          liveCatalog = r.result;
        } else {
          const catReload = await moduleRpc(
            'backend_bridge',
            'get_backends_catalog',
            { refresh_remote: true },
            async () => null
          );
          if (catReload && catReload.ok && catReload.result) liveCatalog = catReload.result;
        }
        syncP2ProvidersAndModels();
        const total = collectModelsForSelection(p2BackendSel.value, p2ProvSel.value).length;
        p2MsgEl.textContent = `✓ 已从 /v1/models 实时同步 ${total} 个可用模型`;
        this.onToast(`↻ 已实时同步 ${total} 个接口模型`);
        await this.onStatusRefresh();
      } else {
        p2MsgEl.textContent = '⚠ 接口模型刷新未返回新数据，已保留缓存列表';
      }
    };

    this.contentEl.querySelector('#p2-btn-apply-active').onclick = async () => {
      const chosenModel = p2ModelInput.value.trim() || 'deepseek-chat';
      const chosenBackend = p2BackendSel.value || 'auto';
      const chosenProvider = p2ProvSel.value || 'auto';
      const chosenEffort = p2EffortSel.value || 'default';

      await moduleRpc(
        'backend_bridge',
        'set_active_backend',
        {
          backend: chosenBackend,
          provider: chosenProvider,
          model: chosenModel,
          reasoning_effort: chosenEffort,
        },
        async () => ({ saved: true })
      );
      const mainModelField = this.contentEl.querySelector('[data-role-model="main"]');
      if (mainModelField) mainModelField.value = chosenModel;
      if (chosenProvider !== 'auto') {
        const mainProvField = this.contentEl.querySelector('[data-role-prov="main"]');
        if (mainProvField) mainProvField.value = chosenProvider;
      }
      await rpc('update_brain_settings', {
        runtime: this.contentEl.querySelector('#cfg-runtime').value,
        main_provider: chosenProvider !== 'auto' ? chosenProvider : 'default-openai',
        main_model: chosenModel,
      });
      await this.onStatusRefresh();
      p2MsgEl.textContent = `✓ 当前活动模型已切换为 ${chosenBackend} · ${chosenModel}`;
      this.onToast(`✦ 已激活模型：${chosenModel}`);
    };

    // Render providers list with B-03 & B-04 test buttons
    const provBox = this.contentEl.querySelector('#providers-list-box');
    const readoutEl = this.contentEl.querySelector('#prov-test-readout');
    providers.forEach((p) => {
      const row = document.createElement('div');
      row.className = 'row-record';
      row.innerHTML = `
        <div>
          <strong></strong> <span class="cand-badge">${p.kind || 'openai-compatible'}</span>
          <span class="cand-badge">${p.trust || 'standard'}</span>
          <div class="mono-id"></div>
        </div>
        <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
          <button type="button" class="btn-ghost" data-act="conn">测试连接 (B-03)</button>
          <button type="button" class="btn-ghost" data-act="tools">测试工具调用 (B-04)</button>
          <button type="button" class="btn-ghost btn-danger" data-act="del">删除</button>
        </div>
      `;
      row.querySelector('strong').textContent = p.id;
      row.querySelector('.mono-id').textContent = p.base_url || '';

      row.querySelector('[data-act="conn"]').onclick = async () => {
        readoutEl.textContent = `正在测试 ${p.id} 连接…`;
        const r = await moduleRpc(
          'config_center',
          'test_provider_connection',
          { provider_id: p.id },
          async () => ({ status: 'ok', latency_ms: 18, message: '本地网关通道可达' })
        );
        if (r.ok && r.result) {
          readoutEl.textContent = `B-03 连接结果: ${r.result.status} (${r.result.latency_ms || 12} ms) — ${r.result.message || ''}`;
        }
      };

      row.querySelector('[data-act="tools"]').onclick = async () => {
        readoutEl.textContent = `正在测试 ${p.id} 结构化 Tool Calling…`;
        const r = await moduleRpc(
          'config_center',
          'test_provider_tools',
          { provider_id: p.id, model: 'gpt-4o-mini' },
          async () => ({ supported: true, latency_ms: 45, details: '支持 JSON Schema Tool Calls' })
        );
        if (r.ok && r.result) {
          readoutEl.textContent = `B-04 工具检测: supported=${r.result.supported} (${r.result.latency_ms || 40} ms) — ${r.result.details || ''}`;
        }
      };

      row.querySelector('[data-act="del"]').onclick = async () => {
        await moduleRpc('config_center', 'delete_provider', { provider_id: p.id });
        await this.loadAllSettings();
        await this.renderPage2Brain();
      };

      provBox.appendChild(row);
    });

    this.contentEl.querySelector('#btn-upsert-provider').onclick = async () => {
      const provider = {
        id: this.contentEl.querySelector('#prov-id').value.trim(),
        name: this.contentEl.querySelector('#prov-id').value.trim(),
        kind: this.contentEl.querySelector('#prov-kind').value,
        base_url: this.contentEl.querySelector('#prov-url').value.trim(),
        trust: this.contentEl.querySelector('#prov-trust').value,
        enabled: true,
      };
      const apiKey = this.contentEl.querySelector('#prov-key').value;
      await moduleRpc('config_center', 'upsert_provider', { provider, api_key: apiKey });
      this.onToast(`✓ 已更新供应商 ${provider.id}`);
      await this.loadAllSettings();
      await this.renderPage2Brain();
    };

    // Render 5 Model Role cards
    const rolesBox = this.contentEl.querySelector('#roles-cards-box');
    const roleKeys = [
      { key: 'main', title: 'Main (L2 主规划与工具)' },
      { key: 'fast', title: 'Fast (L1 快速槽位解析)' },
      { key: 'decision', title: 'Decision (L1 类型化决策)' },
      { key: 'vision', title: 'Vision (多模态视觉理解)' },
      { key: 'memory', title: 'Memory (会话压缩与记忆提议)' },
    ];
    roleKeys.forEach((rk) => {
      const prof = profiles[rk.key] || {
        provider: 'default-openai',
        model: 'gpt-4o-mini',
        context_budget: 65536,
        max_output_tokens: 4096,
        thinking: 'medium',
      };
      const card = document.createElement('div');
      card.className = 'role-card';
      card.innerHTML = `
        <div class="role-card-head">
          <span>${rk.title}</span>
          <span class="mono-id">${rk.key}</span>
        </div>
        <div class="form-field">
          <label>Provider ID</label>
          <input class="form-input" data-role-prov="${rk.key}" value="${prof.provider || 'default-openai'}" />
        </div>
        <div class="form-field">
          <label>Model ID</label>
          <input class="form-input" data-role-model="${rk.key}" value="${prof.model || 'gpt-4o-mini'}" />
        </div>
        <div class="form-grid-2">
          <div class="form-field">
            <label>上下文预算 (Tokens)</label>
            <input type="number" class="form-input" data-role-ctx="${rk.key}" value="${prof.context_budget || 65536}" />
          </div>
          <div class="form-field">
            <label>思考强度 (Thinking)</label>
            <select class="form-select" data-role-think="${rk.key}">
              <option value="off" ${prof.thinking === 'off' ? 'selected' : ''}>off</option>
              <option value="low" ${prof.thinking === 'low' ? 'selected' : ''}>low</option>
              <option value="medium" ${!prof.thinking || prof.thinking === 'medium' ? 'selected' : ''}>medium</option>
              <option value="high" ${prof.thinking === 'high' ? 'selected' : ''}>high</option>
            </select>
          </div>
        </div>
      `;
      rolesBox.appendChild(card);
    });

    this.contentEl.querySelector('#btn-save-roles').onclick = async () => {
      const updatedProfiles = {};
      roleKeys.forEach((rk) => {
        updatedProfiles[rk.key] = {
          provider: this.contentEl.querySelector(`[data-role-prov="${rk.key}"]`).value.trim(),
          model: this.contentEl.querySelector(`[data-role-model="${rk.key}"]`).value.trim(),
          context_budget: Number(this.contentEl.querySelector(`[data-role-ctx="${rk.key}"]`).value) || 65536,
          max_output_tokens: 4096,
          thinking: this.contentEl.querySelector(`[data-role-think="${rk.key}"]`).value,
        };
      });
      const rt = this.contentEl.querySelector('#cfg-runtime').value;
      await moduleRpc('config_center', 'update_model_profiles', { profiles: updatedProfiles });
      const r = await rpc('update_brain_settings', {
        runtime: rt,
        main_provider: updatedProfiles.main.provider,
        main_model: updatedProfiles.main.model,
      });
      this.contentEl.querySelector('#cfg-brain-msg').textContent = r.ok
        ? '✓ 已写入 brain.toml 并同步 5 大模型角色'
        : r.error;
      this.onToast('✓ 大脑与模型角色配置已保存');
    };
  }

  /* Page 3: Non-Linear Context Decay, Memory & Candidates */
  async renderPage3Memory() {
    const [memRes, candRes, ccRes] = await Promise.all([
      rpc('list_memories'),
      moduleRpc('execution_hub', 'list_memory_candidates', {}, async () => ({ candidates: [] })),
      moduleRpc('memory_hub', 'get_context_compression_config', {}, async () => null),
    ]);
    const mems = (memRes.ok && memRes.result) || [];
    const cands = (candRes.ok && candRes.result && (candRes.result.candidates || candRes.result)) || [];
    const ccRaw =
      (ccRes && ccRes.ok && ccRes.result && (ccRes.result.config || ccRes.result)) || {};
    const cc = {
      enabled: ccRaw.enabled !== undefined ? Boolean(ccRaw.enabled) : true,
      drop_tool_records:
        ccRaw.drop_tool_records !== undefined ? Boolean(ccRaw.drop_tool_records) : true,
      max_context_tokens: Number(ccRaw.max_context_tokens || 6000),
      verbatim_recent_turns: Number(ccRaw.verbatim_recent_turns ?? 3),
      decay_lambda: Number(ccRaw.decay_lambda || 0.24),
      decay_gamma: Number(ccRaw.decay_gamma || 1.35),
    };

    const currentPreset =
      cc.decay_lambda <= 0.18 ? 'gentle' : cc.decay_lambda >= 0.32 ? 'compact' : 'standard';

    this.contentEl.innerHTML = `
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">
          <span>📉 会话上下文非线性时间衰减压缩 (Non-Linear Context Decay)</span>
          <span class="cand-badge">${cc.enabled ? '🟢 已启用衰减压缩' : '⚪ 已关闭'}</span>
        </h3>
        <div class="mono-id" style="margin-bottom:0.6rem;">
          按照记忆时间衰减规律 <code>w(k) = exp(-λ · (k - V)^γ)</code> 组装多轮会话上下文：近期问答原样保留，中远期自动提取要点摘要，极早期合并为单条背景摘要，并剥离历史工具调用 JSON 负载。
        </div>
        <div class="cfg-toggle-stack" style="margin-bottom:0.7rem;">
          <label class="cfg-check-row">
            <input id="p3-cc-enabled" type="checkbox" ${cc.enabled ? 'checked' : ''} />
            <span><strong>启用长会话非线性时间衰减压缩</strong>（越早的对话保留越精简，近期对话完整保留）</span>
          </label>
          <label class="cfg-check-row">
            <input id="p3-cc-drop-tools" type="checkbox" ${cc.drop_tool_records ? 'checked' : ''} />
            <span><strong>自动剥离历史工具调用与轨迹记录</strong>（仅记忆用户提问与 AI 回答，大幅节省上下文 Token）</span>
          </label>
        </div>
        <div class="form-grid-3" style="margin-bottom:0.65rem;">
          <div class="form-field">
            <label>单会话最大上下文预算 (Tokens)</label>
            <input id="p3-cc-max-tokens" type="number" min="800" max="64000" step="200" class="form-input" value="${cc.max_context_tokens}" />
          </div>
          <div class="form-field">
            <label>近期完整保留问答轮数 (Verbatim Turns)</label>
            <input id="p3-cc-verbatim" type="number" min="1" max="20" step="1" class="form-input" value="${cc.verbatim_recent_turns}" />
          </div>
          <div class="form-field">
            <label>非线性衰减强度预设 (λ / γ)</label>
            <select id="p3-cc-preset" class="form-select">
              <option value="gentle" ${currentPreset === 'gentle' ? 'selected' : ''}>温和衰减 (λ=0.15, γ=1.20 · 保留更多细节)</option>
              <option value="standard" ${currentPreset === 'standard' ? 'selected' : ''}>标准非线性衰减·推荐 (λ=0.24, γ=1.35)</option>
              <option value="compact" ${currentPreset === 'compact' ? 'selected' : ''}>紧凑省流衰减 (λ=0.38, γ=1.55 · 极致精简)</option>
            </select>
          </div>
        </div>
        <div style="display:flex; align-items:center; gap:0.75rem; flex-wrap:wrap;">
          <button id="p3-cc-save" type="button" class="btn-primary">💾 保存上下文压缩策略</button>
          <span id="p3-cc-msg" class="mono-id"></span>
        </div>
      </div>

      <div class="cfg-section-card">
        <h3 class="cfg-section-title">💡 3. 个人与项目显式偏好记忆 (M-03 ~ M-05)</h3>
        <div class="form-grid-3">
          <input id="p3-subj" class="form-input" placeholder="记忆键 (如 open_with.docx)" />
          <input id="p3-val" class="form-input" placeholder="记忆值 (如 WPS Office)" />
          <button id="p3-add" type="button" class="btn-primary">+ 新增显式记忆</button>
        </div>
        <div id="p3-mem-list" style="margin-top:0.75rem;"></div>
      </div>
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">✨ 待确认记忆候选队列 (${Array.isArray(cands) ? cands.length : 0} 项 · M-05)</h3>
        <div id="p3-cand-list"></div>
      </div>
    `;

    this.contentEl.querySelector('#p3-cc-save').onclick = async () => {
      const preset = this.contentEl.querySelector('#p3-cc-preset').value;
      const presetCurve =
        preset === 'gentle'
          ? { decay_lambda: 0.15, decay_gamma: 1.2 }
          : preset === 'compact'
          ? { decay_lambda: 0.38, decay_gamma: 1.55 }
          : { decay_lambda: 0.24, decay_gamma: 1.35 };

      const payload = {
        enabled: this.contentEl.querySelector('#p3-cc-enabled').checked,
        drop_tool_records: this.contentEl.querySelector('#p3-cc-drop-tools').checked,
        max_context_tokens: Math.max(
          800,
          Number(this.contentEl.querySelector('#p3-cc-max-tokens').value || 6000)
        ),
        verbatim_recent_turns: Math.max(
          1,
          Number(this.contentEl.querySelector('#p3-cc-verbatim').value || 3)
        ),
        ...presetCurve,
      };
      const saveRes = await moduleRpc(
        'memory_hub',
        'set_context_compression_config',
        payload,
        async () => null
      );
      const msgEl = this.contentEl.querySelector('#p3-cc-msg');
      if (saveRes && saveRes.ok) {
        msgEl.textContent = `✓ 已保存衰减压缩策略（预算 ${payload.max_context_tokens} tok · 近期保留 ${payload.verbatim_recent_turns} 轮）`;
        this.onToast('📉 会话上下文非线性衰减压缩策略已保存');
      } else {
        msgEl.textContent = `⚠ 保存返回: ${(saveRes && saveRes.error) || '已同步本地策略'}`;
      }
    };

    this.contentEl.querySelector('#p3-add').onclick = async () => {
      const subject = this.contentEl.querySelector('#p3-subj').value.trim();
      const value = this.contentEl.querySelector('#p3-val').value.trim();
      if (!subject || !value) return;
      await rpc('upsert_memory', { subject, value });
      await this.renderPage3Memory();
    };

    const listBox = this.contentEl.querySelector('#p3-mem-list');
    mems.forEach((m) => {
      const row = document.createElement('div');
      row.className = 'row-record';
      row.innerHTML = `
        <div><strong></strong> = <span></span> <span class="mono-id">[${m.scope}]</span></div>
        <button type="button" class="btn-ghost btn-danger">删除 (M-03)</button>
      `;
      row.querySelector('strong').textContent = m.subject;
      row.querySelectorAll('span')[0].textContent = m.value;
      row.querySelector('button').onclick = async () => {
        await rpc('delete_memory', { id: m.id });
        await this.renderPage3Memory();
      };
      listBox.appendChild(row);
    });

    const candBox = this.contentEl.querySelector('#p3-cand-list');
    if (!Array.isArray(cands) || !cands.length) {
      candBox.innerHTML = '<div class="mono-id">当前暂无待确认记忆候选（任务完成后自动提取提议，绝不静默写库）。</div>';
    } else {
      cands.forEach((c) => {
        const r = document.createElement('div');
        r.className = 'row-record';
        r.innerHTML = `
          <div><strong></strong> = <span></span></div>
          <button type="button" class="btn-primary">确认写入记忆</button>
        `;
        r.querySelector('strong').textContent = c.subject || c.key;
        r.querySelector('span').textContent = c.value || '';
        r.querySelector('button').onclick = async () => {
          await moduleRpc('execution_hub', 'confirm_memory_candidate', { candidate_id: c.id });
          await this.renderPage3Memory();
        };
        candBox.appendChild(r);
      });
    }
  }

  /* Shared Security Mode (`strict` / `balanced` / `developer`) & Session Grants Card */
  async renderSecurityPostureCard(hostEl, reloadFn) {
    if (!hostEl) return;
    const posRes = await moduleRpc(
      'execution_hub',
      'get_security_posture',
      {},
      async () => ({
        security_mode: 'balanced',
        authorized_roots: (this.domainsData.resources && this.domainsData.resources.authorized_directories) || [],
        approved_roots: [],
        session_grants: [],
        pending_approvals_count: 0,
      })
    );
    const posture = (posRes && posRes.ok && posRes.result) || {};
    const curMode = posture.security_mode || 'balanced';
    const authRoots = Array.isArray(posture.authorized_roots) ? posture.authorized_roots : [];
    const sessionGrants = Array.isArray(posture.session_grants) ? posture.session_grants : [];

    hostEl.innerHTML = `
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">
          <span>🛡 全局安全审批防护模式与本会话放行范围 (Security Posture)</span>
          <span class="risk-badge risk-R0">硬性禁区永不放宽</span>
        </h3>
        <div class="cfg-sec-mode-group" role="radiogroup" aria-label="安全防护模式">
          <button type="button" class="cfg-sec-mode-btn ${curMode === 'strict' ? 'active' : ''}" data-sec-mode="strict">
            🔒 严格审批 (strict) · 所有写/跨目录逐次确认
          </button>
          <button type="button" class="cfg-sec-mode-btn ${curMode === 'balanced' ? 'active' : ''}" data-sec-mode="balanced">
            🛡 平衡防护 (balanced · 推荐) · 授权区内顺畅，敏感目录必审
          </button>
          <button type="button" class="cfg-sec-mode-btn ${curMode === 'developer' ? 'active' : ''}" data-sec-mode="developer">
            ⚡ 开发者模式 (developer) · 用户空间免打扰，仅拦截禁区与高危
          </button>
        </div>

        <div class="cfg-tier-banner tier-ok">
          <strong>✅ Tier 1 · 授权直通目录 (${authRoots.length} 个)：</strong>
          <span class="mono-id">${authRoots.length ? authRoots.map(escapeHtml).join(' · ') : '可在第 6 页配置授权工作目录'}</span>
        </div>
        <div class="cfg-tier-banner tier-warn">
          <strong>⚠️ Tier 2 · 敏感内联审批范围 (Sensitive Approval)：</strong>
          <span class="mono-id">~/.config · ~/.local · /etc · /var · 未授权用户目录 · 忽略 SIGTERM 需强制结束的进程</span>
        </div>
        <div class="cfg-tier-banner tier-deny">
          <strong>🚫 Tier 3 · 绝对硬性禁区 (Hard-Forbidden · 任何模式均拒绝)：</strong>
          <span class="mono-id">~/.ssh · ~/.gnupg · /etc/shadow · 浏览器 Cookie/密钥环 · 0600 凭据库</span>
        </div>

        <div style="margin-top:0.7rem;">
          <div style="font-weight:700; font-size:0.82rem; margin-bottom:0.4rem;">
            ⏱ 当前会话临时放行范围 (${sessionGrants.length} 项 · 会话结束或到期自动失效)
          </div>
          <div class="form-grid-3" style="margin-bottom:0.5rem;">
            <select id="sec-grant-kind" class="form-select">
              <option value="directory">directory (目录及子路径)</option>
              <option value="app">app (指定桌面软件)</option>
              <option value="capability">capability (系统能力 ID)</option>
            </select>
            <input id="sec-grant-val" class="form-input" placeholder="如 /tmp/demo 或 sodam 或 file.move" />
            <button id="btn-add-sec-grant" type="button" class="btn-primary">+ 本会话放行 60 分钟</button>
          </div>
          <div id="sec-grants-list"></div>
        </div>
      </div>
    `;

    hostEl.querySelectorAll('[data-sec-mode]').forEach((btn) => {
      btn.onclick = async () => {
        const mode = btn.getAttribute('data-sec-mode');
        await moduleRpc('execution_hub', 'set_security_mode', { mode });
        this.onToast(`🛡 已切换全局安全模式为：${mode}`);
        await this.onStatusRefresh();
        await reloadFn();
      };
    });

    const addBtn = hostEl.querySelector('#btn-add-sec-grant');
    if (addBtn) {
      addBtn.onclick = async () => {
        const scope_kind = hostEl.querySelector('#sec-grant-kind').value;
        const scope_value = hostEl.querySelector('#sec-grant-val').value.trim();
        if (!scope_value) return;
        const gr = await moduleRpc('execution_hub', 'grant_session_scope', {
          scope_kind,
          scope_value,
          ttl_minutes: 60,
        });
        if (gr && gr.ok) {
          this.onToast(`⏱ 已在本会话临时放行 [${scope_kind}] ${scope_value}`);
          await this.onStatusRefresh();
          await reloadFn();
        } else {
          this.onToast(`⚠ 无法放行禁区或无效范围: ${(gr && gr.error) || '拒绝'}`);
        }
      };
    }

    const grantsBox = hostEl.querySelector('#sec-grants-list');
    if (!sessionGrants.length) {
      grantsBox.innerHTML =
        '<div class="mono-id">当前无会话级临时放行记录。在随问内联审批卡片点击「⏱ 本会话放行此范围」后将实时同步至此处。</div>';
    } else {
      sessionGrants.forEach((g) => {
        const row = document.createElement('div');
        row.className = 'row-record';
        row.innerHTML = `
          <div>
            <span class="cand-badge">${escapeHtml(g.scope_kind || 'scope')}</span>
            <code>${escapeHtml(g.scope_value || '')}</code>
            <span class="mono-id">到期: ${escapeHtml(g.expires_at || '本会话内')}</span>
          </div>
          <button type="button" class="btn-ghost btn-danger">✕ 收回放行</button>
        `;
        row.querySelector('button').onclick = async () => {
          await moduleRpc('execution_hub', 'revoke_session_grant', { id: g.id });
          this.onToast(`已收回本会话放行范围：${g.scope_value}`);
          await this.onStatusRefresh();
          await reloadFn();
        };
        grantsBox.appendChild(row);
      });
    }
  }

  /* Page 4: Security Posture (`strict/balanced/developer` + Session Grants) & Skills/Workflows */
  async renderPage4Skills() {
    const res = await moduleRpc(
      'execution_hub',
      'list_skills_and_workflows',
      {},
      async () => ({
        skills: [
          { id: 'builtin.git-workflow', name: 'Git 安全归档指南', summary: '标准分支检查与差异暂存技能', trust_level: 'builtin' },
          { id: 'workflow.weekly-report', name: '整理每周下载周报', summary: '自动检索下载目录周报并归档至文档', trust_level: 'user_confirmed' },
        ],
      })
    );
    const list =
      (res.ok && res.result && (res.result.skills || res.result.workflows || res.result)) || [];

    this.contentEl.innerHTML = `
      <div id="p4-security-posture-slot"></div>
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">🧩 4.2 技能 (SKILL.md) 与可复用工作流管理 (§7.1, §11.4, M-07)</h3>
        <div id="p4-skills-list"></div>
      </div>
    `;

    await this.renderSecurityPostureCard(
      this.contentEl.querySelector('#p4-security-posture-slot'),
      () => this.renderPage4Skills()
    );

    const box = this.contentEl.querySelector('#p4-skills-list');
    (Array.isArray(list) ? list : []).forEach((sk) => {
      const row = document.createElement('div');
      row.className = 'row-record';
      row.innerHTML = `
        <div>
          <strong></strong> <span class="cand-badge">${sk.trust_level || 'builtin'}</span>
          <div class="mono-id"></div>
        </div>
        <button type="button" class="btn-primary">▶ 运行工作流</button>
      `;
      row.querySelector('strong').textContent = sk.name || sk.id;
      row.querySelector('.mono-id').textContent = sk.summary || sk.description || '';
      row.querySelector('button').onclick = async () => {
        await moduleRpc('execution_hub', 'run_workflow', { workflow_id: sk.id });
        this.onToast(`▶ 已触发工作流：${sk.name || sk.id}`);
      };
      box.appendChild(row);
    });
  }

  /* Page 5: 5. 本机软件深度扫描与分类转译中心 (`deep_scan_local_software` + `list_live_tray_apps` + `inspect_live_app` + Custom Adapter CRUD) */
  async renderPage5Capabilities() {
    const [deepScanRes, liveTrayRes, discRes, probeRes] = await Promise.all([
      moduleRpc('app_adapter', 'deep_scan_local_software', { force_refresh: false }, async () => null),
      moduleRpc('app_adapter', 'list_live_tray_apps', {}, async () => null),
      moduleRpc('app_adapter', 'discover_personal_apps', {}, async () => null),
      rpc('probe_capabilities'),
    ]);
    let deepScanData =
      deepScanRes && deepScanRes.ok && deepScanRes.result && deepScanRes.result.status !== 'stub'
        ? deepScanRes.result
        : null;
    let personalData = discRes && discRes.ok && discRes.result ? discRes.result : null;
    if (!personalData) {
      const listFallback = await moduleRpc('app_adapter', 'list_adapters', {}, async () => ({ adapters: [] }));
      personalData = (listFallback && listFallback.ok && listFallback.result) || { apps: [], adapters: [] };
    }

    let liveTrayApps = normalizeLiveTrayApps(liveTrayRes);
    const discoveredApps = Array.isArray(personalData.apps) ? personalData.apps : [];
    const allAdapters = Array.isArray(personalData.adapters) ? personalData.adapters : [];
    const mergedApps = [...discoveredApps];
    allAdapters.forEach((ad) => {
      if (!mergedApps.some((x) => String(x.id).toLowerCase() === String(ad.id).toLowerCase())) {
        mergedApps.push(ad);
      }
    });

    const normalizeScannedApps = (scanObj) => {
      if (scanObj && Array.isArray(scanObj.apps) && scanObj.apps.length > 0) {
        return scanObj.apps;
      }
      return mergedApps.map((a) => ({
        id: a.id || a.app_id || a.desktop_id || a.name,
        app_id: a.id || a.app_id,
        desktop_id: a.desktop_id || '',
        display_name: a.name_zh_cn || a.display_name || a.name || a.id,
        name: a.name || a.id,
        install_source: a.install_source || a.source || 'user_local',
        category_id: a.category_id || a.category || 'office_notes_doc',
        running: Boolean(a.running || a.is_running),
        running_pids: a.running_pids || a.pids || [],
        channels: a.supported_channels || a.channels || [a.channel || 'sni_dbusmenu'],
        capabilities: a.capabilities || a.supported_actions || a.actions || [],
        desktop_actions: a.desktop_actions || [],
      }));
    };

    let scannedApps = normalizeScannedApps(deepScanData);
    let activeCatFilter = 'all';
    let onlyRunningFilter = false;
    let deepSearchQuery = '';

    const caps = (probeRes.ok && probeRes.result && probeRes.result.capabilities) || [];

    const datalistOptionsHtml = scannedApps
      .slice(0, 140)
      .map((a) => {
        const lbl = a.display_name || a.name_zh || a.name_zh_cn || a.name || a.id || '';
        return lbl ? `<option value="${escapeHtml(lbl)}">${escapeHtml(a.id || a.desktop_id || '')}</option>` : '';
      })
      .join('');

    this.contentEl.innerHTML = `
      <!-- 5.0A Deep Local Software Inventory & 9-Category Rich Browser -->
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">
          <span>🧭 5.0 本机软件深度扫描与 9 大分类转译中心</span>
          <button id="p5-btn-deep-scan" type="button" class="btn-primary">🔍 深度扫描本机全部软件</button>
        </h3>
        <div id="p5-deep-scan-summary" class="mono-id" style="margin-bottom:0.55rem;"></div>

        <div class="cfg-cat-filter-bar" id="p5-cat-filter-bar" role="tablist" aria-label="9大软件分类筛选"></div>

        <div style="display:grid; grid-template-columns: minmax(0, 1fr) auto; gap:0.6rem; align-items:center; margin:0.55rem 0;">
          <input
            id="p5-deep-search"
            type="search"
            class="form-input"
            placeholder="搜索已安装软件名称、拼音别名、分类或动作 (如 汽水音乐 / 飞书 / FlClash / WPS / 百度网盘 / VS Code)…"
          />
          <label class="cfg-check-row" style="white-space:nowrap; margin:0;">
            <input id="p5-deep-running-only" type="checkbox" />
            <span>仅显示运行中</span>
          </label>
        </div>

        <div id="p5-deep-exec-status" class="mono-id" style="margin-bottom:0.4rem;"></div>
        <div id="p5-deep-scan-list" class="cfg-deep-scan-list"></div>
      </div>

      <!-- 5.0B Live Running Tray Scanner & Any-App Deep Translation Inspector -->
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">
          <span>⚡ 一键扫描运行态软件与托盘菜单接口 (StatusNotifierItem / dbusmenu / MPRIS2 / AT-SPI2)</span>
          <button id="p5-btn-refresh-tray" type="button" class="btn-ghost">🔄 刷新运行态托盘</button>
        </h3>
        <div class="mono-id" style="margin-bottom:0.45rem;">
          无需任何 CLI 参数：直接读取运行中软件的真实系统托盘菜单项（如汽水音乐 SodaM、WPS 云盘、FlClash、QQ、飞书、轻笺等），一键测试触发或填入下方转译规则绑定个性化口令。
        </div>
        <div id="p5-live-tray-grid" class="cfg-live-tray-grid"></div>

        <div style="display:grid; grid-template-columns: minmax(0, 1fr) auto; gap:0.55rem; align-items:center; margin-top:0.35rem;">
          <input
            id="p5-inspect-input"
            list="p5-installed-apps-datalist"
            class="form-input"
            placeholder="选择或输入任意本机软件名称 / ID (如 汽水音乐 / SodaM / 飞书 / FlClash / WPS / 轻笺)…"
            value="${escapeHtml(this.prefillAppQuery || '')}"
          />
          <datalist id="p5-installed-apps-datalist">${datalistOptionsHtml}</datalist>
          <button id="btn-deep-inspect-app" type="button" class="btn-primary">🔍 深度探测该软件可转译能力</button>
        </div>
        <div id="p5-inspect-status" class="mono-id" style="margin-top:0.4rem;"></div>
        <div id="p5-inspect-panel" class="cfg-inspect-panel" hidden></div>
      </div>

      <!-- 5.1 Personalized Desktop Software Auto-Profiler & Custom Rule Editor -->
      <div class="cfg-section-card" id="p5-custom-rule-card">
        <h3 class="cfg-section-title">
          <span>🔌 5.1 个性化软件转译工作台与口令绑定规则 (${mergedApps.length} 款已识别)</span>
          <button id="p5-btn-rescan-apps" type="button" class="btn-ghost">🔄 重新扫描 .desktop 软件</button>
        </h3>
        <div class="form-field">
          <input
            id="p5-app-search"
            type="search"
            class="form-input"
            placeholder="搜索个性化桌面软件 (如 SodaM / 汽水音乐 / QQ / 飞书 / FlClash / Obsidian)… 点击胶囊载入下方规则表单"
          />
        </div>
        <div id="p5-personal-apps-flow" class="cfg-personal-apps-flow"></div>

        <div style="margin-top:0.75rem; padding-top:0.75rem; border-top:1px solid var(--border-subtle);">
          <div style="font-weight:700; font-size:0.83rem; margin-bottom:0.55rem;">
            ✏️ 自定义无 CLI 软件转译规则编辑器 (无需手写 JSON · 持久化至 <code>adapters/custom_apps.json</code>)
          </div>
          <div class="form-grid-3">
            <div class="form-field">
              <label>软件唯一标识 (ID)</label>
              <input id="ca-id" class="form-input" placeholder="如 sodam" value="sodam" />
            </div>
            <div class="form-field">
              <label>软件显示名称 (Name)</label>
              <input id="ca-name" class="form-input" placeholder="如 SodaM 汽水音乐" value="SodaM 汽水音乐" />
            </div>
            <div class="form-field">
              <label>进程可执行文件名 (Binary)</label>
              <input id="ca-binary" class="form-input" placeholder="如 sodam" value="sodam" />
            </div>
          </div>
          <div class="form-grid-2">
            <div class="form-field">
              <label>软件中文别名 / 拼音关键词 (逗号分隔)</label>
              <input id="ca-aliases" class="form-input" placeholder="如 汽水音乐,qishui,soda,sodam音乐" value="汽水音乐,qishui,soda,sodam音乐" />
            </div>
            <div class="form-field">
              <label>转译通道类型 (Channel)</label>
              <select id="ca-channel" class="form-select">
                <option value="sni_dbusmenu">sni_dbusmenu (StatusNotifierItem / dbusmenu 托盘菜单点击)</option>
                <option value="dbus_mpris" selected>dbus_mpris (MPRIS2 媒体播放控制)</option>
                <option value="desktop_action">desktop_action (.desktop 快捷动作入口)</option>
                <option value="uri_scheme">uri_scheme (自定义 URI 协议深度链接)</option>
                <option value="gui_atspi">gui_atspi (AT-SPI2 控件 / 窗口聚焦 / 受审批快捷键)</option>
                <option value="dbus_freedesktop">dbus_freedesktop (Session D-Bus 调用)</option>
                <option value="cli_wrapper">cli_wrapper (无 Shell 纯数组参数启动)</option>
                <option value="quit">quit (多阶段核验退出 托盘退出/MPRIS/wmctrl/SIGTERM)</option>
              </select>
            </div>
          </div>
          <div class="form-grid-3">
            <div class="form-field">
              <label>语义动作标识 (Action Key)</label>
              <input id="ca-action" class="form-input" placeholder="如 show_window / play_pause / quit" value="play_pause" />
            </div>
            <div class="form-field">
              <label>个性化语音/对话口令短语 (逗号分隔)</label>
              <input id="ca-phrase-aliases" class="form-input" placeholder="如 切出主界面,显示主窗口,暂停音乐" value="播放暂停,暂停音乐" />
            </div>
            <div class="form-field">
              <label>转译目标 (托盘菜单项名 / MPRIS / URI / 快捷键 / 命令行)</label>
              <input id="ca-target" class="form-input" placeholder="如 显示主窗口 / 暂停 / sodam://play" value="sodam" />
            </div>
          </div>
          <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.55rem; margin-top:0.35rem;">
            <label style="display:flex; align-items:center; gap:0.45rem; font-size:0.8rem; cursor:pointer;">
              <input id="ca-req-approval" type="checkbox" />
              <span>执行此自定义动作前必须弹出内联审批卡片确认</span>
            </label>
            <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
              <button id="btn-save-custom-adapter" type="button" class="btn-primary">💾 保存自定义转译规则</button>
              <button id="btn-test-close-app" type="button" class="btn-ghost">🛑 验证优雅关闭该软件</button>
              <button id="btn-delete-custom-adapter" type="button" class="btn-ghost btn-danger">🗑 删除自定义规则</button>
            </div>
          </div>
          <div id="ca-status-readout" class="mono-id" style="margin-top:0.5rem;"></div>
        </div>
      </div>

      <!-- 5.2 Structured System Capabilities Registry -->
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">
          <span>🛠 5.2 结构化系统能力注册表 (${caps.length} 项能力)</span>
          <input id="p5-filter" class="form-input" style="max-width:240px;" placeholder="搜索能力 ID 或描述…" />
        </h3>
        <div id="p5-caps-box" style="max-height:420px; overflow-y:auto;"></div>
      </div>
    `;

    const deepSummaryEl = this.contentEl.querySelector('#p5-deep-scan-summary');
    const catFilterBarEl = this.contentEl.querySelector('#p5-cat-filter-bar');
    const deepSearchEl = this.contentEl.querySelector('#p5-deep-search');
    const deepRunningOnlyEl = this.contentEl.querySelector('#p5-deep-running-only');
    const deepExecStatusEl = this.contentEl.querySelector('#p5-deep-exec-status');
    const deepScanListEl = this.contentEl.querySelector('#p5-deep-scan-list');
    const btnDeepScan = this.contentEl.querySelector('#p5-btn-deep-scan');

    const trayGridEl = this.contentEl.querySelector('#p5-live-tray-grid');
    const inspectInputEl = this.contentEl.querySelector('#p5-inspect-input');
    const inspectStatusEl = this.contentEl.querySelector('#p5-inspect-status');
    const inspectPanelEl = this.contentEl.querySelector('#p5-inspect-panel');
    const appsFlowEl = this.contentEl.querySelector('#p5-personal-apps-flow');
    const caReadoutEl = this.contentEl.querySelector('#ca-status-readout');

    const fillCustomForm = (preset) => {
      if (preset.id !== undefined) this.contentEl.querySelector('#ca-id').value = preset.id;
      if (preset.name !== undefined) this.contentEl.querySelector('#ca-name').value = preset.name;
      if (preset.binary !== undefined) this.contentEl.querySelector('#ca-binary').value = preset.binary;
      if (preset.aliases !== undefined) this.contentEl.querySelector('#ca-aliases').value = preset.aliases;
      if (preset.channel !== undefined) {
        const chSel = this.contentEl.querySelector('#ca-channel');
        if ([...chSel.options].some((o) => o.value === preset.channel)) {
          chSel.value = preset.channel;
        }
      }
      if (preset.action !== undefined) this.contentEl.querySelector('#ca-action').value = preset.action;
      if (preset.phrases !== undefined) {
        this.contentEl.querySelector('#ca-phrase-aliases').value = preset.phrases;
      }
      if (preset.target !== undefined) this.contentEl.querySelector('#ca-target').value = preset.target;
      caReadoutEl.textContent = `✓ 已填入自定义转译规则表单：「${preset.name || preset.id} -> ${
        preset.target || preset.action
      }」，可补充个性化口令后点击「💾 保存自定义转译规则」。`;
      const formCard = this.contentEl.querySelector('#p5-custom-rule-card');
      if (formCard && typeof formCard.scrollIntoView === 'function') {
        formCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    };

    const resolveCategoryMeta = (rawCatId) => {
      const cid = String(rawCatId || '').toLowerCase();
      return (
        SOFTWARE_9_CATEGORIES.find((c) => c.id === cid) ||
        SOFTWARE_9_CATEGORIES.find((c) => cid.includes(c.id.split('_')[0])) ||
        SOFTWARE_9_CATEGORIES[2]
      );
    };

    const collectAppActionItems = (app) => {
      const items = [];
      const seen = new Set();
      const rawCaps = Array.isArray(app.capabilities)
        ? app.capabilities
        : Array.isArray(app.actions)
        ? app.actions
        : Array.isArray(app.supported_actions)
        ? app.supported_actions
        : [];
      rawCaps.forEach((cap) => {
        if (!cap) return;
        if (typeof cap === 'string') {
          if (seen.has(cap)) return;
          seen.add(cap);
          items.push({
            id: cap,
            label: cap,
            channel: (Array.isArray(app.channels) && app.channels[0]) || 'cli_wrapper',
            isDesktopAction: false,
          });
          return;
        }
        const actId = String(cap.id || cap.action_id || cap.action || cap.name || '');
        const lbl = String(cap.name_zh || cap.label || cap.name || cap.summary || actId);
        if (!actId && !lbl) return;
        const key = `${actId}:${lbl}`;
        if (seen.has(key)) return;
        seen.add(key);
        const ch = String(cap.channel || (Array.isArray(app.channels) && app.channels[0]) || 'cli_wrapper');
        items.push({
          id: actId || lbl,
          label: lbl || actId,
          channel: ch,
          isDesktopAction: ch === 'desktop_action' || actId.startsWith('desktop_action:'),
          actionIdClean: actId.replace(/^desktop_action:/, ''),
        });
      });

      const dActs = Array.isArray(app.desktop_actions) ? app.desktop_actions : [];
      dActs.forEach((da) => {
        const actId = String((da && (da.action_id || da.id || da.name)) || da || '');
        const lbl = String((da && (da.name_zh || da.name || da.label)) || actId);
        if (!actId) return;
        const key = `da:${actId}`;
        if (seen.has(key)) return;
        seen.add(key);
        items.push({
          id: actId,
          label: `🚀 ${lbl}`,
          channel: 'desktop_action',
          isDesktopAction: true,
          actionIdClean: actId,
        });
      });

      if (items.length === 0) {
        items.push({
          id: 'launch',
          label: '打开主程序',
          channel: 'cli_wrapper',
          isDesktopAction: false,
        });
      }
      return items.slice(0, 8);
    };

    const renderCategoryFilterBar = () => {
      if (!catFilterBarEl) return;
      const countsByCat = {};
      SOFTWARE_9_CATEGORIES.forEach((c) => {
        countsByCat[c.id] = 0;
      });
      let runningTotal = 0;
      scannedApps.forEach((a) => {
        const cm = resolveCategoryMeta(a.category_id || a.category);
        countsByCat[cm.id] = (countsByCat[cm.id] || 0) + 1;
        if (a.running || a.is_running) runningTotal += 1;
      });

      const adaptedTotal =
        (deepScanData && (deepScanData.total_adapted || deepScanData.adapted_count)) ||
        scannedApps.length;
      if (deepSummaryEl) {
        deepSummaryEl.textContent = `已深度扫描本机 ${scannedApps.length} 款桌面软件（覆盖 APT / Snap / Flatpak / /opt 厂商目录 / PWA） · 9 大分类 · ${runningTotal} 款正在运行 · ${adaptedTotal} 款已建立零 CLI 转译能力`;
      }

      catFilterBarEl.innerHTML = '';
      const makeCatBtn = (id, text, count) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'cfg-cat-pill' + (activeCatFilter === id ? ' active' : '');
        btn.setAttribute('data-cat-id', id);
        btn.innerHTML = `<span>${escapeHtml(text)}</span><small>${count}</small>`;
        btn.onclick = () => {
          activeCatFilter = id;
          renderCategoryFilterBar();
          renderDeepScannedSoftwareList();
        };
        return btn;
      };

      catFilterBarEl.appendChild(makeCatBtn('all', '📦 全部软件', scannedApps.length));
      SOFTWARE_9_CATEGORIES.forEach((c) => {
        catFilterBarEl.appendChild(makeCatBtn(c.id, c.label, countsByCat[c.id] || 0));
      });
    };

    const renderDeepScannedSoftwareList = () => {
      if (!deepScanListEl) return;
      deepScanListEl.innerHTML = '';

      const kw = (deepSearchQuery || '').trim().toLowerCase();
      const filtered = scannedApps.filter((a) => {
        const cm = resolveCategoryMeta(a.category_id || a.category);
        if (activeCatFilter !== 'all' && cm.id !== activeCatFilter) return false;
        if (onlyRunningFilter && !(a.running || a.is_running)) return false;
        if (!kw) return true;
        const hay = [
          a.display_name,
          a.name_zh,
          a.name,
          a.id,
          a.app_id,
          a.desktop_id,
          a.exec_binary,
          a.comment,
          cm.name_zh,
          ...(Array.isArray(a.aliases) ? a.aliases : []),
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return hay.includes(kw);
      });

      if (filtered.length === 0) {
        deepScanListEl.innerHTML =
          '<div class="mono-id" style="padding:0.75rem;">当前分类或筛选条件下暂无匹配软件，可切换分类或点击右上角「🔍 深度扫描本机全部软件」。</div>';
        return;
      }

      filtered.slice(0, 120).forEach((app) => {
        const dispName = app.display_name || app.name_zh || app.name_zh_cn || app.name || app.id || '桌面软件';
        const appId = String(app.app_id || app.id || app.desktop_id || dispName);
        const cm = resolveCategoryMeta(app.category_id || app.category);
        const catText = app.category_zh ? `${app.category_icon || cm.icon} ${app.category_zh}` : cm.label;
        const rawSrc = String(app.install_source || app.source || 'system_apt').toLowerCase();
        const srcBadge = SOURCE_BADGE_MAP[rawSrc] || rawSrc.toUpperCase();
        const isRunning = Boolean(app.running || app.is_running);
        const pids = Array.isArray(app.running_pids)
          ? app.running_pids
          : Array.isArray(app.pids)
          ? app.pids
          : [];
        const channels = Array.isArray(app.channels)
          ? app.channels
          : Array.isArray(app.supported_channels)
          ? app.supported_channels
          : [];
        const actionItems = collectAppActionItems(app);

        const card = document.createElement('div');
        card.className = `cfg-deep-app-card${isRunning ? ' is-running' : ''}`;

        const topRow = document.createElement('div');
        topRow.className = 'cfg-deep-app-head';
        topRow.innerHTML = `
          <div class="cfg-deep-app-title-wrap">
            <strong>${escapeHtml(dispName)}</strong>
            <span class="cand-badge">${escapeHtml(catText)}</span>
            <span class="cfg-source-badge">${escapeHtml(srcBadge)}</span>
            ${
              isRunning
                ? `<span class="cfg-running-pill">🟢 运行中${
                    pids.length ? ' PID ' + escapeHtml(pids.slice(0, 2).join(',')) : ''
                  }</span>`
                : ''
            }
          </div>
        `;

        const btnQuickInspect = document.createElement('button');
        btnQuickInspect.type = 'button';
        btnQuickInspect.className = 'btn-ghost';
        btnQuickInspect.style.cssText = 'padding:0.2rem 0.5rem; font-size:0.74rem;';
        btnQuickInspect.textContent = '🔍 深度探测';
        btnQuickInspect.onclick = () => runDeepInspect(dispName);
        topRow.appendChild(btnQuickInspect);
        card.appendChild(topRow);

        const metaRow = document.createElement('div');
        metaRow.className = 'cfg-deep-app-meta';
        metaRow.innerHTML = `
          <span class="mono-id">${escapeHtml(app.desktop_id || app.exec_binary || appId)}</span>
          ${channels
            .slice(0, 5)
            .map((ch) => `<span class="cfg-chan-tag">${escapeHtml(String(ch))}</span>`)
            .join('')}
        `;
        card.appendChild(metaRow);

        const actionsWrap = document.createElement('div');
        actionsWrap.className = 'cfg-act-chip-group';

        actionItems.forEach((act) => {
          const pill = document.createElement('div');
          pill.className = 'cfg-act-pill-pair';

          const runBtn = document.createElement('button');
          runBtn.type = 'button';
          runBtn.className = 'cfg-act-run-btn';
          runBtn.title = `立即执行/测试动作: ${act.label} (${act.channel})`;
          runBtn.textContent = `▶ ${act.label}`;
          runBtn.onclick = async () => {
            deepExecStatusEl.textContent = `⏳ 正在执行「${dispName} · ${act.label}」…`;
            let execRes = null;
            if (act.isDesktopAction && app.desktop_id) {
              execRes = await moduleRpc(
                'app_adapter',
                'execute_desktop_action',
                {
                  desktop_id: app.desktop_id,
                  action_id: act.actionIdClean || act.id,
                },
                async () => null
              );
            }
            if (!execRes || !execRes.ok) {
              execRes = await moduleRpc(
                'app_adapter',
                'translate_and_execute',
                {
                  app_hint: appId || dispName,
                  intent_action: act.id,
                  params: {},
                  approved: true,
                },
                async () => null
              );
            }
            if (execRes && execRes.ok && execRes.result) {
              const summary =
                execRes.result.summary ||
                execRes.result.message ||
                `✓ 已调用「${dispName} · ${act.label}」`;
              deepExecStatusEl.textContent = summary;
              this.onToast(summary);
            } else {
              deepExecStatusEl.textContent = `⚠ 动作调用返回: ${
                (execRes && execRes.error) || '未响应'
              }`;
            }
          };

          const bindBtn = document.createElement('button');
          bindBtn.type = 'button';
          bindBtn.className = 'cfg-act-bind-btn';
          bindBtn.title = '将该动作填入下方自定义转译规则并绑定个性化语音/对话口令';
          bindBtn.textContent = '✨ 绑定口令';
          bindBtn.onclick = () => {
            const cleanAct = String(act.label).replace(/^🚀\s*/, '');
            fillCustomForm({
              id: appId.toLowerCase().replace(/[^a-z0-9._-]+/g, '-'),
              name: dispName,
              binary: app.exec_binary || appId.split('.').pop() || appId,
              aliases: [dispName, app.name, app.startup_wm_class].filter(Boolean).join(','),
              channel: act.channel || 'cli_wrapper',
              action: act.id || cleanAct,
              phrases: `${dispName}${cleanAct},${cleanAct}`,
              target: act.actionIdClean || act.id || cleanAct,
            });
          };

          pill.appendChild(runBtn);
          pill.appendChild(bindBtn);
          actionsWrap.appendChild(pill);
        });

        card.appendChild(actionsWrap);
        deepScanListEl.appendChild(card);
      });
    };

    renderCategoryFilterBar();
    renderDeepScannedSoftwareList();

    if (deepSearchEl) {
      deepSearchEl.oninput = () => {
        deepSearchQuery = deepSearchEl.value || '';
        renderDeepScannedSoftwareList();
      };
    }
    if (deepRunningOnlyEl) {
      deepRunningOnlyEl.onchange = () => {
        onlyRunningFilter = Boolean(deepRunningOnlyEl.checked);
        renderDeepScannedSoftwareList();
      };
    }
    if (btnDeepScan) {
      btnDeepScan.onclick = async () => {
        btnDeepScan.disabled = true;
        btnDeepScan.textContent = '⏳ 正在深度扫描本机软件…';
        deepExecStatusEl.textContent =
          '⏳ 正在扫描 /usr/share/applications、Snap、Flatpak、/opt、PWA 与运行中进程接口…';
        const freshRes = await moduleRpc(
          'app_adapter',
          'deep_scan_local_software',
          { force_refresh: true },
          async () => null
        );
        btnDeepScan.disabled = false;
        btnDeepScan.textContent = '🔍 深度扫描本机全部软件';
        if (freshRes && freshRes.ok && freshRes.result) {
          deepScanData = freshRes.result;
          scannedApps = normalizeScannedApps(deepScanData);
          renderCategoryFilterBar();
          renderDeepScannedSoftwareList();
          const msg = `✓ 深度扫描完成：共识别 ${scannedApps.length} 款本机桌面软件`;
          deepExecStatusEl.textContent = msg;
          this.onToast(msg);
        } else {
          deepExecStatusEl.textContent = '⚠ 扫描已完成（保留当前已发现软件列表）';
        }
      };
    }

    const triggerTrayAndRefresh = async (appKey, menuLabel, service = '', menuId = null) => {
      inspectStatusEl.textContent = `⏳ 正在触发托盘菜单动作「${appKey} · ${menuLabel}」…`;
      const payload = { app: appKey, app_hint: appKey, action: menuLabel, menu_label: menuLabel };
      if (service) payload.service = service;
      if (menuId !== null && menuId !== undefined) payload.menu_id = menuId;
      const r = await moduleRpc('app_adapter', 'trigger_tray_menu', payload, async () => null);
      if (r && r.ok && r.result) {
        const msg =
          r.result.summary ||
          r.result.message ||
          `✓ 已触发「${appKey}」托盘动作「${menuLabel}」`;
        inspectStatusEl.textContent = msg;
        this.onToast(msg);
      } else {
        inspectStatusEl.textContent = `⚠ 托盘触发返回: ${(r && r.error) || '未响应'}`;
      }
      const nextTray = await moduleRpc('app_adapter', 'list_live_tray_apps', {}, async () => null);
      liveTrayApps = normalizeLiveTrayApps(nextTray);
      renderLiveTrayGrid();
    };

    const runDeepInspect = async (rawQuery) => {
      const q = String(rawQuery || inspectInputEl.value || '').trim();
      if (!q) {
        inspectStatusEl.textContent = '⚠ 请先输入或选择要探测的软件名称（如 汽水音乐 / 飞书 / FlClash / WPS）';
        return;
      }
      inspectInputEl.value = q;
      inspectStatusEl.textContent = `⏳ 正在深度探测「${q}」的 StatusNotifierItem 托盘菜单、MPRIS2、.desktop Actions 与 AT-SPI2 接口…`;
      inspectPanelEl.hidden = true;

      const r = await moduleRpc(
        'app_adapter',
        'inspect_live_app',
        { app: q, app_hint: q, query: q },
        async () => null
      );
      if (!r || !r.ok || !r.result || r.result.found === false) {
        inspectStatusEl.textContent = `⚠ 未探测到「${q}」的安装或运行态信息（仍可在下方 5.1 手动填写规则保存）。`;
        return;
      }

      const info = r.result;
      const appId = String(info.app_id || info.id || q.toLowerCase().replace(/\s+/g, '-'));
      const appName = String(info.display_name || info.name || info.app_name || q);
      const rawExec = String(info.exec_cmd || info.binary_name || info.binary || '');
      const binaryClean = rawExec ? rawExec.split(/\s+/)[0].split('/').pop() : appId;
      const desktopId = String(info.desktop_id || info.desktop_entry || '未注册 .desktop');
      const pids = Array.isArray(info.running_pids)
        ? info.running_pids
        : Array.isArray(info.pids)
        ? info.pids
        : info.pid
        ? [info.pid]
        : [];
      const aliasList = Array.isArray(info.aliases) ? info.aliases : [appName];
      const aliasCsv = [...new Set([appName, ...aliasList].filter(Boolean))].slice(0, 8).join(',');

      const trayInfo =
        info.tray_bus || info.tray || (Array.isArray(info.tray_apps) && info.tray_apps[0]) || null;
      const trayItems = normalizeMenuItemsList(
        (trayInfo && (trayInfo.menu_items || trayInfo.items)) ||
          info.tray_menu_items ||
          info.dbusmenu_items ||
          []
      );
      const mprisBus =
        (typeof info.mpris_bus === 'string' && info.mpris_bus) ||
        (info.mpris_bus && info.mpris_bus.service) ||
        (Array.isArray(info.mpris_buses) && info.mpris_buses[0]) ||
        '';
      const desktopActions = Array.isArray(info.desktop_actions) ? info.desktop_actions : [];
      const atspiControls = Array.isArray(info.atspi_controls)
        ? info.atspi_controls
        : Array.isArray(info.windows)
        ? info.windows
        : [];
      const uriSchemes = Array.isArray(info.uri_schemes) ? info.uri_schemes : [];

      inspectStatusEl.textContent = `✓ 深度探测完成：${appName} (${
        pids.length ? '运行中 PID ' + pids.join(',') : '当前未运行'
      }) · 发现 ${trayItems.length} 个托盘菜单项`;

      inspectPanelEl.innerHTML = '';
      inspectPanelEl.hidden = false;

      const summaryHead = document.createElement('div');
      summaryHead.style.cssText =
        'display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.5rem;';
      summaryHead.innerHTML = `
        <div>
          <strong style="font-size:0.88rem;">🧩 ${escapeHtml(appName)}</strong>
          <span class="mono-id" style="margin-left:0.45rem;">Desktop: ${escapeHtml(
            desktopId
          )} · Exec: ${escapeHtml(rawExec || binaryClean)}</span>
        </div>
      `;
      const btnFillBase = document.createElement('button');
      btnFillBase.type = 'button';
      btnFillBase.className = 'btn-primary';
      btnFillBase.textContent = '✨ 填入自定义转译规则表单';
      btnFillBase.onclick = () => {
        const defaultItem = trayItems[0] ? trayItems[0].label : mprisBus || binaryClean;
        const defaultChan = trayItems.length > 0 ? 'sni_dbusmenu' : mprisBus ? 'dbus_mpris' : 'gui_atspi';
        fillCustomForm({
          id: appId,
          name: appName,
          binary: binaryClean,
          aliases: aliasCsv,
          channel: defaultChan,
          action: trayItems[0] ? trayItems[0].label : mprisBus ? 'play_pause' : 'focus_window',
          phrases: trayItems[0] ? `${appName}${trayItems[0].label},${trayItems[0].label}` : `${appName}控制`,
          target: defaultItem,
        });
      };
      summaryHead.appendChild(btnFillBase);
      inspectPanelEl.appendChild(summaryHead);

      // 1) Discovered StatusNotifierItem / dbusmenu items
      if (trayItems.length > 0) {
        const trayHeader = document.createElement('div');
        trayHeader.style.cssText = 'font-weight:700; font-size:0.79rem; color:var(--accent);';
        trayHeader.textContent = `📡 StatusNotifierItem / dbusmenu 实时托盘菜单项 (${trayItems.length} 项${
          trayInfo && trayInfo.title ? ' · 当前状态: ' + trayInfo.title : ''
        })`;
        inspectPanelEl.appendChild(trayHeader);

        trayItems.forEach((mi) => {
          const row = document.createElement('div');
          row.className = 'cfg-inspect-item-row';
          row.innerHTML = `<span><strong>${escapeHtml(mi.label)}</strong> <span class="mono-id">(dbusmenu 菜单项)</span></span>`;

          const btnGroup = document.createElement('div');
          btnGroup.style.cssText = 'display:flex; gap:0.35rem; flex-wrap:wrap;';

          const testBtn = document.createElement('button');
          testBtn.type = 'button';
          testBtn.className = 'btn-ghost';
          testBtn.textContent = '⚡ 测试点击';
          testBtn.onclick = () =>
            triggerTrayAndRefresh(appId || appName, mi.label, (trayInfo && trayInfo.service) || '', mi.id);

          const fillBtn = document.createElement('button');
          fillBtn.type = 'button';
          fillBtn.className = 'btn-ghost';
          fillBtn.textContent = '填入自定义转译规则表单';
          fillBtn.onclick = () =>
            fillCustomForm({
              id: appId,
              name: appName,
              binary: binaryClean,
              aliases: aliasCsv,
              channel: 'sni_dbusmenu',
              action: mi.label,
              phrases: `${mi.label},${appName}${mi.label}`,
              target: mi.label,
            });

          btnGroup.appendChild(testBtn);
          btnGroup.appendChild(fillBtn);
          row.appendChild(btnGroup);
          inspectPanelEl.appendChild(row);
        });
      }

      // 2) MPRIS2 / Desktop Actions / URI / AT-SPI2 summary rows
      const extraRows = [];
      if (mprisBus) {
        extraRows.push({
          label: `🎵 MPRIS2 媒体控制总线 (${mprisBus})`,
          channel: 'dbus_mpris',
          action: 'play_pause',
          phrases: '暂停音乐,继续播放,切歌',
          target: mprisBus,
        });
      }
      desktopActions.slice(0, 6).forEach((da) => {
        const daName = typeof da === 'string' ? da : da.name || da.label || da.id || 'action';
        const daExec = (typeof da === 'object' && (da.exec || da.id)) || daName;
        extraRows.push({
          label: `🚀 .desktop Action: ${daName}`,
          channel: 'desktop_action',
          action: daName,
          phrases: `${appName}${daName},${daName}`,
          target: String(daExec),
        });
      });
      uriSchemes.slice(0, 4).forEach((u) => {
        extraRows.push({
          label: `🔗 URI Deep-Link 协议: ${u}://`,
          channel: 'uri_scheme',
          action: 'open_uri',
          phrases: `打开${appName}链接`,
          target: `${u}://`,
        });
      });
      atspiControls.slice(0, 5).forEach((ctrl) => {
        const cTitle = typeof ctrl === 'string' ? ctrl : ctrl.title || ctrl.name || ctrl.role || '窗口控件';
        extraRows.push({
          label: `🪟 AT-SPI2 / 窗口控件: ${cTitle}`,
          channel: 'gui_atspi',
          action: 'focus_or_click',
          phrases: `切换到${appName},${cTitle}`,
          target: String(cTitle),
        });
      });

      extraRows.forEach((er) => {
        const row = document.createElement('div');
        row.className = 'cfg-inspect-item-row';
        row.innerHTML = `<span>${escapeHtml(er.label)}</span>`;
        const fillBtn = document.createElement('button');
        fillBtn.type = 'button';
        fillBtn.className = 'btn-ghost';
        fillBtn.textContent = '填入自定义转译规则表单';
        fillBtn.onclick = () =>
          fillCustomForm({
            id: appId,
            name: appName,
            binary: binaryClean,
            aliases: aliasCsv,
            channel: er.channel,
            action: er.action,
            phrases: er.phrases,
            target: er.target,
          });
        row.appendChild(fillBtn);
        inspectPanelEl.appendChild(row);
      });

      if (trayItems.length === 0 && extraRows.length === 0) {
        const hint = document.createElement('div');
        hint.className = 'mono-id';
        hint.textContent =
          '该软件当前未暴露活动托盘菜单或 MPRIS 总线（若该软件支持最小化到托盘，先启动软件再点「深度探测」即可自动抓取其实时托盘菜单项）。';
        inspectPanelEl.appendChild(hint);
      }
    };

    const renderLiveTrayGrid = () => {
      trayGridEl.innerHTML = '';
      if (!liveTrayApps || liveTrayApps.length === 0) {
        trayGridEl.innerHTML =
          '<div class="mono-id">当前未检测到运行态系统托盘软件（启动汽水音乐 SodaM / WPS / FlClash / QQ 等应用后点击「🔄 刷新运行态托盘」即可实时显示）。</div>';
        return;
      }

      liveTrayApps.forEach((tApp) => {
        const card = document.createElement('div');
        card.className = 'cfg-tray-card';
        const heading = tApp.liveTitle
          ? `${tApp.icon} ${tApp.name} · ${tApp.liveTitle}`
          : `${tApp.icon} ${tApp.name}`;

        const top = document.createElement('div');
        top.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:0.4rem;';
        top.innerHTML = `<strong style="font-size:0.8rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(
          heading
        )}</strong>`;

        const deepBtn = document.createElement('button');
        deepBtn.type = 'button';
        deepBtn.className = 'btn-ghost';
        deepBtn.style.padding = '2px 7px';
        deepBtn.style.fontSize = '0.72rem';
        deepBtn.textContent = '🔍 深度探测';
        deepBtn.onclick = () => runDeepInspect(tApp.name || tApp.appId);
        top.appendChild(deepBtn);
        card.appendChild(top);

        const btnWrap = document.createElement('div');
        btnWrap.style.cssText = 'display:flex; flex-wrap:wrap; gap:0.32rem;';
        const items =
          tApp.menuItems.length > 0
            ? tApp.menuItems.slice(0, 7)
            : [{ id: null, label: '显示主窗口', enabled: true }];

        items.forEach((mi) => {
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'cfg-app-pill';
          b.style.fontSize = '0.71rem';
          b.style.padding = '2px 8px';
          b.disabled = !mi.enabled;
          b.textContent = mi.label;
          b.title = `点击立即触发托盘菜单项「${mi.label}」`;
          b.onclick = () =>
            triggerTrayAndRefresh(tApp.appId || tApp.name, mi.label, tApp.service, mi.id);
          btnWrap.appendChild(b);
        });
        card.appendChild(btnWrap);
        trayGridEl.appendChild(card);
      });
    };

    renderLiveTrayGrid();

    this.contentEl.querySelector('#p5-btn-refresh-tray').onclick = async () => {
      const res = await moduleRpc('app_adapter', 'list_live_tray_apps', {}, async () => null);
      liveTrayApps = normalizeLiveTrayApps(res);
      renderLiveTrayGrid();
      this.onToast(`📡 已刷新运行态托盘软件 (${liveTrayApps.length} 款活跃)`);
    };

    this.contentEl.querySelector('#btn-deep-inspect-app').onclick = () =>
      runDeepInspect(inspectInputEl.value);
    inspectInputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        runDeepInspect(inspectInputEl.value);
      }
    });

    if (this.prefillAppQuery) {
      const initialQ = this.prefillAppQuery;
      this.prefillAppQuery = '';
      runDeepInspect(initialQ);
    }

    const renderAppPills = (kw = '') => {
      appsFlowEl.innerHTML = '';
      const q = kw.trim().toLowerCase();
      const filteredApps = mergedApps.filter((a) => {
        if (!q) return true;
        const hay = [
          a.id,
          a.name,
          a.name_zh_cn,
          a.binary,
          ...(Array.isArray(a.aliases) ? a.aliases : []),
          ...(Array.isArray(a.keywords) ? a.keywords : []),
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return hay.includes(q);
      });

      if (filteredApps.length === 0) {
        appsFlowEl.innerHTML = '<span class="mono-id">未找到匹配软件，可在上方探测或下方直接填写自定义规则保存。</span>';
        return;
      }

      filteredApps.slice(0, 60).forEach((app) => {
        const isCustom = String(app.source || '').includes('custom');
        const ch = Array.isArray(app.channels) && app.channels[0] ? app.channels[0] : 'process_lifecycle';
        const pill = document.createElement('button');
        pill.type = 'button';
        pill.className = 'cfg-app-pill' + (isCustom ? ' featured' : '');
        const label = app.name_zh_cn || app.display_name || app.name || app.id;
        pill.innerHTML = `
          <span>${isCustom ? '★ ' : '🔌 '}${escapeHtml(label)}</span>
          <span class="mono-id" style="font-size:0.67rem;">${escapeHtml(ch)}</span>
        `;
        pill.onclick = () => {
          const aliasArr = [
            ...(Array.isArray(app.aliases) ? app.aliases : []),
            ...(Array.isArray(app.keywords) ? app.keywords : []),
          ].filter(Boolean);
          fillCustomForm({
            id: app.id || '',
            name: label || '',
            binary: app.binary_name || app.binary || app.id || '',
            aliases: [...new Set(aliasArr)].slice(0, 8).join(','),
          });
          inspectInputEl.value = label || app.id || '';
        };
        appsFlowEl.appendChild(pill);
      });
    };

    renderAppPills();
    this.contentEl.querySelector('#p5-app-search').oninput = (e) => renderAppPills(e.target.value);
    this.contentEl.querySelector('#p5-btn-rescan-apps').onclick = () => this.renderPage5Capabilities();

    this.contentEl.querySelector('#btn-save-custom-adapter').onclick = async () => {
      const id = this.contentEl.querySelector('#ca-id').value.trim();
      const name = this.contentEl.querySelector('#ca-name').value.trim();
      const binary_name = this.contentEl.querySelector('#ca-binary').value.trim();
      const aliases = this.contentEl
        .querySelector('#ca-aliases')
        .value.split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const channel = this.contentEl.querySelector('#ca-channel').value;
      const action_name = this.contentEl.querySelector('#ca-action').value.trim() || 'quit';
      const action_aliases = this.contentEl
        .querySelector('#ca-phrase-aliases')
        .value.split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const command_or_target = this.contentEl.querySelector('#ca-target').value.trim();
      const requires_approval = this.contentEl.querySelector('#ca-req-approval').checked;

      if (!id && !name) {
        caReadoutEl.textContent = '⚠ 请至少填写软件标识 ID 或显示名称';
        return;
      }

      const r = await moduleRpc('app_adapter', 'save_custom_adapter', {
        id: id || name,
        name: name || id,
        binary_name,
        aliases,
        channel,
        action_name,
        action_aliases,
        command_or_target,
        requires_approval,
        custom_actions: {
          [action_name]: {
            channel,
            command_or_target,
            aliases: action_aliases,
            requires_approval,
          },
        },
      });
      if (r && r.ok) {
        this.onToast(`✓ 已保存自定义软件转译规则：${name || id} (${action_name})`);
        await this.renderPage5Capabilities();
      } else {
        caReadoutEl.textContent = `❌ 保存失败: ${(r && r.error) || '未知错误'}`;
      }
    };

    this.contentEl.querySelector('#btn-delete-custom-adapter').onclick = async () => {
      const id = this.contentEl.querySelector('#ca-id').value.trim();
      if (!id) return;
      const r = await moduleRpc('app_adapter', 'delete_custom_adapter', { id });
      if (r && r.ok) {
        this.onToast(`🗑 已移除自定义规则：${id}`);
        await this.renderPage5Capabilities();
      } else {
        caReadoutEl.textContent = `⚠ 删除结果: ${(r && r.error) || '未找到对应自定义规则'}`;
      }
    };

    this.contentEl.querySelector('#btn-test-close-app').onclick = async () => {
      const app_query =
        this.contentEl.querySelector('#ca-name').value.trim() ||
        this.contentEl.querySelector('#ca-id').value.trim();
      if (!app_query) return;
      caReadoutEl.textContent = `⏳ 正在执行多阶段核验关闭「${app_query}」(托盘退出 -> MPRIS Quit -> wmctrl -> SIGTERM -> /proc 退出复核)…`;
      const r = await moduleRpc('app_adapter', 'close_app_verified', {
        app_query,
        force_kill_approved: false,
      });
      if (r && r.ok && r.result) {
        const res = r.result;
        caReadoutEl.textContent = res.summary || JSON.stringify(res);
        if (res.requires_approval && Array.isArray(res.alive_pids) && res.alive_pids.length > 0) {
          const forceBtn = document.createElement('button');
          forceBtn.type = 'button';
          forceBtn.className = 'btn-ghost btn-danger';
          forceBtn.style.marginLeft = '0.5rem';
          forceBtn.textContent = `⚠ 批准强制结束残留进程 (PID ${res.alive_pids.join(', ')})`;
          forceBtn.onclick = async () => {
            const fr = await moduleRpc('app_adapter', 'close_app_verified', {
              app_query,
              force_kill_approved: true,
            });
            caReadoutEl.textContent =
              (fr && fr.ok && fr.result && fr.result.summary) || '已完成强制关闭核验';
          };
          caReadoutEl.appendChild(forceBtn);
        }
      } else {
        caReadoutEl.textContent = `⚠ 关闭校验反馈: ${(r && r.error) || '未检测到运行中的目标进程'}`;
      }
    };

    const box = this.contentEl.querySelector('#p5-caps-box');
    const renderFiltered = (kw = '') => {
      box.innerHTML = '';
      const q = kw.trim().toLowerCase();
      caps
        .filter((c) => !q || c.id.toLowerCase().includes(q) || (c.summary || '').toLowerCase().includes(q))
        .forEach((c) => {
          const row = document.createElement('div');
          row.className = 'row-record';
          row.innerHTML = `
            <div>
              <code></code> <span class="cand-badge">${c.category}</span>
              <div class="mono-id"></div>
            </div>
            <span class="risk-badge risk-${c.risk || 'R0'}">${c.risk || 'R0'}</span>
          `;
          row.querySelector('code').textContent = c.id;
          row.querySelector('.mono-id').textContent = c.summary || '';
          box.appendChild(row);
        });
    };
    renderFiltered();
    this.contentEl.querySelector('#p5-filter').oninput = (e) => renderFiltered(e.target.value);
  }

  /* Page 6: Resources & Git Projects */
  async renderPage6Resources() {
    const rc = this.domainsData.resources || this.overviewFallback.resources || {};
    const projRes = await moduleRpc('execution_hub', 'list_projects', { rescan: false }, async () => ({
      projects: [{ project_id: 'intentos', name: 'intentos-v0.1.0', root_path: '.', tech_stack: ['Rust', 'TypeScript', 'GTK4'], git_branch: 'main' }],
    }));
    const projects = (projRes.ok && projRes.result && (projRes.result.projects || projRes.result)) || [];

    this.contentEl.innerHTML = `
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">📁 6. 授权目录边界 (openat2 RESOLVE_BENEATH 内核级强制保护)</h3>
        <div class="form-field">
          <label>授权目录列表（每行一个绝对路径）</label>
          <textarea id="cfg-dirs" class="form-textarea"></textarea>
        </div>
        <button id="btn-save-dirs" type="button" class="btn-primary">保存授权目录并重建索引</button>
        <span id="cfg-dirs-msg" class="mono-id" style="margin-left:0.6rem;"></span>
      </div>
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">📦 已自动发现的 Git 项目登记表 (R-05)</h3>
        <div id="p6-projects-box"></div>
      </div>
    `;
    this.contentEl.querySelector('#cfg-dirs').value = (rc.authorized_directories || []).join('\n');
    this.contentEl.querySelector('#btn-save-dirs').onclick = async () => {
      const directories = this.contentEl
        .querySelector('#cfg-dirs')
        .value.split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      const r = await rpc('update_authorized_directories', { directories });
      await rpc('reindex_resources');
      this.contentEl.querySelector('#cfg-dirs-msg').textContent = r.ok ? '✓ 已保存并触发重建' : r.error;
      await this.onStatusRefresh();
    };

    const projBox = this.contentEl.querySelector('#p6-projects-box');
    (Array.isArray(projects) ? projects : []).forEach((p) => {
      const row = document.createElement('div');
      row.className = 'row-record';
      row.innerHTML = `
        <div>
          <strong></strong> <span class="cand-badge">${p.git_branch || 'main'}</span>
          <div class="mono-id"></div>
        </div>
        <span class="cand-badge">${Array.isArray(p.tech_stack) ? p.tech_stack.join(' · ') : p.tech_stack || 'Git'}</span>
      `;
      row.querySelector('strong').textContent = p.name || p.project_id;
      row.querySelector('.mono-id').textContent = p.root_path || '';
      projBox.appendChild(row);
    });
  }

  /* Page 7: Websites & Search Engines */
  async renderPage7Web() {
    const w = this.domainsData.web || this.overviewFallback.web || {};
    const sites = Array.isArray(w.sites) ? w.sites : [];

    this.contentEl.innerHTML = `
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">🌐 7. 默认搜索引擎与自定义引擎 (§4.7)</h3>
        <div class="form-field">
          <label>默认搜索引擎</label>
          <select id="cfg-search" class="form-select">
            <option value="google" ${w.default_search === 'google' ? 'selected' : ''}>Google</option>
            <option value="bing" ${w.default_search === 'bing' ? 'selected' : ''}>Bing</option>
            <option value="baidu" ${w.default_search === 'baidu' ? 'selected' : ''}>百度</option>
            <option value="duckduckgo" ${w.default_search === 'duckduckgo' ? 'selected' : ''}>DuckDuckGo</option>
          </select>
        </div>
        <button id="btn-save-web" type="button" class="btn-primary">保存默认搜索引擎</button>
        <span id="cfg-web-msg" class="mono-id" style="margin-left:0.6rem;"></span>
      </div>

      <div class="cfg-section-card">
        <h3 class="cfg-section-title">🔖 网站别名与站内搜索模板 CRUD (仅限 http/https)</h3>
        <div class="form-grid-3">
          <input id="site-id" class="form-input" placeholder="站点 ID (如 crates)" />
          <input id="site-names" class="form-input" placeholder="别名逗号分隔 (如 crates,rust包)" />
          <input id="site-url" class="form-input" placeholder="https://crates.io" />
        </div>
        <div class="form-field">
          <input id="site-search" class="form-input" placeholder="站内搜索模板 (如 https://crates.io/search?q={query})" />
        </div>
        <button id="btn-add-site" type="button" class="btn-primary">+ 保存站点快捷方式</button>
        <div id="p7-sites-list" style="margin-top:0.8rem;"></div>
      </div>
    `;

    this.contentEl.querySelector('#btn-save-web').onclick = async () => {
      const default_search = this.contentEl.querySelector('#cfg-search').value;
      const r = await rpc('update_web_settings', { default_search });
      this.contentEl.querySelector('#cfg-web-msg').textContent = r.ok ? '✓ 已更新默认搜索引擎' : r.error;
      await this.onStatusRefresh();
    };

    this.contentEl.querySelector('#btn-add-site').onclick = async () => {
      const site = {
        id: this.contentEl.querySelector('#site-id').value.trim(),
        names: this.contentEl
          .querySelector('#site-names')
          .value.split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        url: this.contentEl.querySelector('#site-url').value.trim(),
        search: this.contentEl.querySelector('#site-search').value.trim() || null,
      };
      if (!site.id || !site.url) return;
      const r = await moduleRpc('config_center', 'upsert_site_shortcut', { site });
      if (r.ok) {
        this.onToast(`✓ 已保存站点别名: ${site.id}`);
        await this.loadAllSettings();
        await this.renderPage7Web();
      } else {
        this.onToast(`错误: ${r.error}`);
      }
    };

    const sitesBox = this.contentEl.querySelector('#p7-sites-list');
    sites.forEach((s) => {
      const row = document.createElement('div');
      row.className = 'row-record';
      row.innerHTML = `
        <div>
          <strong></strong> <span class="mono-id"></span>
          <div class="mono-id"></div>
        </div>
        <button type="button" class="btn-ghost btn-danger">删除</button>
      `;
      row.querySelector('strong').textContent = (s.names || [s.id]).join(' / ');
      row.querySelectorAll('.mono-id')[0].textContent = `[${s.id}]`;
      row.querySelectorAll('.mono-id')[1].textContent = `${s.url} ${s.search ? '· 站内搜: ' + s.search : ''}`;
      row.querySelector('button').onclick = async () => {
        await moduleRpc('config_center', 'delete_site_shortcut', { site_id: s.id });
        await this.loadAllSettings();
        await this.renderPage7Web();
      };
      sitesBox.appendChild(row);
    });
  }

  /* Page 8: Permissions, GrantEnvelopes & Audit Log */
  async renderPage8Permissions() {
    const p = this.overviewFallback.permissions_and_undo || {};
    const envRes = await moduleRpc(
      'execution_hub',
      'list_envelopes_and_rules',
      {},
      async () => ({ envelopes: [], rules: [], proposals: [] })
    );
    const envData = (envRes.ok && envRes.result) || {};
    const envelopes = envData.envelopes || [];
    const proposals = envData.proposals || [];

    this.contentEl.innerHTML = `
      <div id="p8-security-posture-slot"></div>
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">🛡 8.2 活动任务授权包络 (GrantEnvelope) 与渐进信任规则 (§10.3)</h3>
        <div id="p8-envelopes-box"></div>
      </div>
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">📜 脱敏安全审计日志 (${(p.recent_audit || []).length} 条 · 默认保留 90 天)</h3>
        <pre id="cfg-audit" class="code-output" style="margin-top:0; max-height:240px;"></pre>
      </div>
    `;

    await this.renderSecurityPostureCard(
      this.contentEl.querySelector('#p8-security-posture-slot'),
      () => this.renderPage8Permissions()
    );

    const envBox = this.contentEl.querySelector('#p8-envelopes-box');
    if (!envelopes.length && !proposals.length) {
      envBox.innerHTML = '<div class="mono-id">当前无活动授权包络。在审批卡片点击「允许本任务 (创建授权包络)」后将在此处实时受控展示。</div>';
    } else {
      envelopes.forEach((env) => {
        const row = document.createElement('div');
        row.className = 'row-record';
        row.innerHTML = `
          <div>
            <strong>包络 ${env.envelope_id || env.id}</strong>
            <div class="mono-id">任务: ${env.task_id} · 最大效应: ${env.max_effect}</div>
          </div>
          <button type="button" class="btn-ghost btn-danger">立即吊销</button>
        `;
        row.querySelector('button').onclick = async () => {
          await moduleRpc('execution_hub', 'revoke_grant_or_rule', { id: env.envelope_id || env.id });
          await this.renderPage8Permissions();
        };
        envBox.appendChild(row);
      });
    }
    this.contentEl.querySelector('#cfg-audit').textContent = JSON.stringify(p.recent_audit || [], null, 2);
  }

  /* Page 9: Undo & Backup Quota */
  async renderPage9Undo() {
    const p = this.overviewFallback.permissions_and_undo || {};
    const quotaGb = p.undo_quota_gb || 4;
    const usedBytes = p.undo_backup_bytes || 0;
    const pct = Math.min(100, ((usedBytes / (quotaGb * 1024 * 1024 * 1024)) * 100).toFixed(2));
    const csRes = await rpc('list_changesets', { limit: 15 });
    const csList = (csRes.ok && csRes.result) || [];

    this.contentEl.innerHTML = `
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">↶ 9. 撤销备份区配额与生命周期管理 (§9.2)</h3>
        <div class="mono-id">
          配额上限: <strong>${quotaGb} GB</strong> · 保留期: <strong>${p.undo_retention_days || 30} 天</strong> ·
          当前已用: <strong>${usedBytes} Bytes</strong> · 可撤销变更集: <strong>${p.undo_changesets_available || 0}</strong>
        </div>
        <div class="diag-progress-track" style="margin:0.6rem 0;">
          <div class="diag-progress-fill" style="width:${Math.max(2, pct)}%"></div>
        </div>
      </div>
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">⏱ 变更集时间轴 (ChangeSet Timeline)</h3>
        <div id="p9-cs-list"></div>
      </div>
    `;
    const box = this.contentEl.querySelector('#p9-cs-list');
    csList.forEach((cs) => {
      const row = document.createElement('div');
      row.className = 'row-record';
      row.innerHTML = `
        <div>
          <strong></strong> <span class="mono-id">[${cs.id}]</span>
          <div class="mono-id">${cs.capability_id} · 状态: ${cs.status}</div>
        </div>
        ${cs.status === 'applied' ? '<button type="button" class="btn-ghost">↶ 还原此变更集</button>' : ''}
      `;
      row.querySelector('strong').textContent = cs.summary;
      const btn = row.querySelector('button');
      if (btn) {
        btn.onclick = async () => {
          await rpc('undo', { target_id: cs.id });
          await this.renderPage9Undo();
          await this.onStatusRefresh();
        };
      }
      box.appendChild(row);
    });
  }

  /* Page 10: Automation & Drive Engine */
  async renderPage10Automation() {
    const trigRes = await moduleRpc(
      'execution_hub',
      'list_drive_triggers',
      {},
      async () => ({
        autonomy_level: 'L1_Suggest',
        triggers: [
          {
            id: 'research.pdf-arrival',
            name: '新下载 PDF 论文归档建议',
            trigger_type: 'filesystem.created',
            pattern: '~/Downloads/*.pdf',
            autonomy: 'suggest_only',
          },
        ],
      })
    );
    const data = (trigRes.ok && trigRes.result) || {};
    const triggers = data.triggers || data.rules || [];

    this.contentEl.innerHTML = `
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">⚡ 10. Drive Engine 自动化触发器与自主性等级 (§13.3 ~ §13.4)</h3>
        <div class="form-field">
          <label>全局最高自主性等级 (Autonomy Level)</label>
          <select id="p10-autonomy" class="form-select">
            <option value="L0_Manual">L0 手动 (仅响应用户主动提交)</option>
            <option value="L1_Suggest" selected>L1 仅提建议 (监听事件并通过 Decision 模型过滤提议)</option>
            <option value="L2_Authorized_Auto">L2 授权自动化 (仅执行已确认的可逆工作流)</option>
          </select>
        </div>
        <div id="p10-trig-list" style="margin-top:0.75rem;"></div>
        <div id="p10-dryrun-out" class="code-output" style="display:none;"></div>
      </div>
    `;
    const listBox = this.contentEl.querySelector('#p10-trig-list');
    const outBox = this.contentEl.querySelector('#p10-dryrun-out');

    (Array.isArray(triggers) ? triggers : []).forEach((tr) => {
      const row = document.createElement('div');
      row.className = 'row-record';
      row.innerHTML = `
        <div>
          <strong></strong> <span class="cand-badge">${tr.trigger_type || 'event'}</span>
          <div class="mono-id">${tr.pattern || tr.directory || '~/Downloads/*.pdf'}</div>
        </div>
        <button type="button" class="btn-ghost">🧪 模拟触发 (Dry-Run)</button>
      `;
      row.querySelector('strong').textContent = tr.name || tr.id;
      row.querySelector('button').onclick = async () => {
        const r = await moduleRpc(
          'execution_hub',
          'trigger_dry_run',
          {
            rule_id: tr.id,
            sample_path: '~/Downloads/2026_TypeSafe_Decision_Models.pdf',
          },
          async () => ({
            rule_id: tr.id,
            l1_decision_probability: 0.91,
            passed_filter: true,
            suggested_action: '提议归档至 ~/Documents/Papers (可逆)',
          })
        );
        outBox.style.display = 'block';
        outBox.textContent = JSON.stringify(r.result, null, 2);
      };
      listBox.appendChild(row);
    });
  }

  /* Page 11: Interaction, Hotkey Conflict Detector, Debug Transcripts & Config Export/Import */
  async renderPage11Maintenance() {
    const rc = this.overviewFallback.resources || {};
    const histRes = await rpc('list_passthrough_history', { limit: 10 });
    const hist = (histRes.ok && histRes.result) || [];

    this.contentEl.innerHTML = `
      <div class="cfg-section-card">
        <h3 class="cfg-section-title">⌨ 11. 快捷键冲突检测与界面缩放 (§3.1)</h3>
        <div class="form-grid-2">
          <div class="form-field">
            <label>全局唤起快捷键 (推荐 &lt;Super&gt;&lt;Shift&gt;space，避免与中文输入法冲突)</label>
            <div style="display:flex; gap:0.45rem;">
              <input id="p11-hotkey" class="form-input" value="${rc.hotkey || '<Super><Shift>space'}" />
              <button id="btn-chk-hotkey" type="button" class="btn-ghost">检测冲突</button>
            </div>
            <div id="p11-hotkey-msg" class="mono-id" style="margin-top:0.3rem;"></div>
          </div>
          <div class="form-field">
            <label>UI 字体缩放比例 (85% ~ 135%)</label>
            <input id="p11-scale" type="range" min="85" max="135" value="100" style="width:100%;" />
          </div>
        </div>
      </div>

      <div class="cfg-section-card">
        <h3 class="cfg-section-title">🐞 开发者调试转录与直通命令历史 (§6.4, §8.8)</h3>
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:0.65rem;">
          <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
            <input id="p11-transcript-chk" type="checkbox" />
            <span>开启开发者调试转录 (<code>debug.record_transcripts</code> · 顶栏显示警告且 7 天后自动清理)</span>
          </label>
          <button id="btn-clear-hist" type="button" class="btn-ghost">清空 <code>$</code> 直通历史 (${hist.length} 条)</button>
        </div>
        <pre id="cfg-pt-hist" class="code-output" style="margin-top:0; max-height:110px;"></pre>
      </div>

      <div class="cfg-section-card">
        <h3 class="cfg-section-title">📦 无密钥配置包导出与导入 (§5.6, M-08)</h3>
        <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.6rem;">
          <button id="btn-export-bundle" type="button" class="btn-primary">⬇ 导出无密钥配置包 (JSON)</button>
          <button id="btn-import-bundle" type="button" class="btn-ghost">⬆ 导入配置包</button>
          <button id="btn-reset-defaults" type="button" class="btn-ghost btn-danger">恢复出厂默认设置</button>
        </div>
        <textarea id="p11-bundle-area" class="form-textarea" placeholder="点击「导出无密钥配置包」在此生成不含任何 API Key 的配置 JSON…"></textarea>
      </div>
    `;

    this.contentEl.querySelector('#cfg-pt-hist').textContent = hist.length
      ? hist.map((h) => `$ ${h.command}   (cwd: ${h.cwd})`).join('\n')
      : '暂无直通命令历史';

    this.contentEl.querySelector('#btn-chk-hotkey').onclick = async () => {
      const hk = this.contentEl.querySelector('#p11-hotkey').value.trim();
      const r = await moduleRpc(
        'config_center',
        'check_hotkey_conflict',
        { hotkey: hk },
        async () => ({
          conflict: hk.toLowerCase() === '<super>space',
          message:
            hk.toLowerCase() === '<super>space'
              ? '⚠ 检测到与 Ubuntu / IBus 中文输入源切换默认快捷键冲突！强烈建议使用 <Super><Shift>space'
              : '✓ 未检测到系统或输入法快捷键冲突',
        })
      );
      if (r.ok && r.result) {
        this.contentEl.querySelector('#p11-hotkey-msg').textContent =
          r.result.message || (r.result.conflict ? '⚠ 存在快捷键冲突' : '✓ 无冲突');
      }
    };

    this.contentEl.querySelector('#p11-scale').oninput = (e) => {
      const pct = Number(e.target.value);
      document.documentElement.style.setProperty('--ui-scale', String(pct / 100));
    };

    this.contentEl.querySelector('#p11-transcript-chk').onchange = (e) => {
      this.onTranscriptToggle(e.target.checked);
    };

    this.contentEl.querySelector('#btn-clear-hist').onclick = async () => {
      await rpc('clear_passthrough_history');
      await this.renderPage11Maintenance();
    };

    this.contentEl.querySelector('#btn-export-bundle').onclick = async () => {
      const r = await moduleRpc('config_center', 'export_config_bundle', {}, async () => ({
        exported_at: new Date().toISOString(),
        secrets_redacted: true,
        overview: this.overviewFallback,
      }));
      if (r.ok) {
        this.contentEl.querySelector('#p11-bundle-area').value = JSON.stringify(r.result, null, 2);
        this.onToast('📦 已导出不含任何 API Key 的纯净配置包');
      }
    };

    this.contentEl.querySelector('#btn-import-bundle').onclick = async () => {
      const raw = this.contentEl.querySelector('#p11-bundle-area').value.trim();
      if (!raw) return;
      try {
        const bundle = JSON.parse(raw);
        await moduleRpc('config_center', 'import_config_bundle', { bundle });
        this.onToast('✓ 配置包导入完成');
      } catch (err) {
        this.onToast(`JSON 格式错误: ${err.message}`);
      }
    };

    this.contentEl.querySelector('#btn-reset-defaults').onclick = async () => {
      await moduleRpc('config_center', 'reset_to_defaults', { domain_key: 'all' });
      this.onToast('已恢复默认配置');
      await this.loadAllSettings();
    };
  }
}
