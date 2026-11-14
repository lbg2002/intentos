/**
 * IntentOS Wave 3 — Slide-Over Memory, Document Chapter Outlines & Personalized Software Adapter Popover (`🧠`)
 * + Lightweight `@` Inline Mention Autocomplete Menu above the chat composer.
 */

import { rpc, moduleRpc } from './rpc-client.js';
import { escapeHtml } from './markdown-renderer.js';

const DEFAULT_ADAPTER_PROFILES = [
  {
    id: 'sodam-music',
    name: 'SodaM / 汽水音乐 (个性化桌面播放器)',
    channel: 'MPRIS2 + 托盘进程验证关闭',
    actions: ['播放/暂停', '下一曲', '验证退出进程'],
    personalized: true,
  },
  {
    id: 'mpris-music',
    name: '音乐播放器 (Spotify / QQ音乐 / VLC / 网易云)',
    channel: 'MPRIS2 / D-Bus',
    actions: ['播放/暂停', '下一曲', '当前曲目', '音量调节'],
  },
  {
    id: 'freedesktop-fm',
    name: '文件管理器 (Nautilus / Dolphin)',
    channel: 'D-Bus FileManager1',
    actions: ['高亮定位文件', '打开目录'],
  },
  {
    id: 'vscode-uri',
    name: 'VS Code / ZCode / Cursor',
    channel: 'URI vscode:// + CLI',
    actions: ['定位文件行列', '打开工作区'],
  },
  {
    id: 'libreoffice-headless',
    name: 'LibreOffice / WPS 文档转换',
    channel: 'Headless 静默转换',
    actions: ['转 PDF', '打开文档'],
  },
  {
    id: 'gui-atspi',
    name: '纯 GUI 个性化桌面软件通用桥接',
    channel: 'AT-SPI2 / 进程生命周期',
    actions: ['聚焦窗口', '验证退出进程'],
  },
];

function shortChannelTag(raw) {
  const s = String(raw || '').toLowerCase();
  if (s.includes('tray') || s.includes('sni') || s.includes('dbusmenu')) return '托盘菜单';
  if (s.includes('mpris')) return 'MPRIS2';
  if (s.includes('dbus') || s.includes('freedesktop')) return 'D-Bus';
  if (s.includes('uri')) return 'URI';
  if (s.includes('desktop')) return 'DesktopAction';
  if (s.includes('headless')) return 'Headless';
  if (s.includes('proc') || s.includes('quit')) return '进程校验';
  if (s.includes('gui') || s.includes('atspi') || s.includes('shortcut')) return 'GUI/快捷键';
  if (s.includes('cli') || s.includes('argv')) return 'CLI';
  return raw || 'Adapter';
}

function pickTrayAppIcon(nameStr) {
  const s = String(nameStr || '').toLowerCase();
  if (
    s.includes('soda') ||
    s.includes('汽水') ||
    s.includes('music') ||
    s.includes('音乐') ||
    s.includes('spotify') ||
    s.includes('vlc') ||
    s.includes('netease')
  ) {
    return '🎵';
  }
  if (s.includes('wps') || s.includes('baidu') || s.includes('网盘') || s.includes('cloud')) {
    return '☁';
  }
  if (s.includes('clash') || s.includes('proxy') || s.includes('vpn') || s.includes('v2ray')) {
    return '🛡';
  }
  if (
    s.includes('qq') ||
    s.includes('wechat') ||
    s.includes('微信') ||
    s.includes('feishu') ||
    s.includes('飞书') ||
    s.includes('lark')
  ) {
    return '💬';
  }
  if (s.includes('note') || s.includes('轻笺') || s.includes('obsidian')) {
    return '📝';
  }
  return '📡';
}

export function normalizeMenuItemsList(rawItems) {
  if (!Array.isArray(rawItems)) return [];
  const out = [];
  const seen = new Set();
  rawItems.forEach((it) => {
    if (!it) return;
    if (typeof it === 'string') {
      const lbl = it.trim();
      if (!lbl || lbl === '-' || lbl === '---' || seen.has(lbl)) return;
      seen.add(lbl);
      out.push({ id: null, label: lbl, enabled: true });
      return;
    }
    if (typeof it === 'object') {
      if (it.visible === false || it.is_separator === true || it.type === 'separator') return;
      const lbl = String(
        it.label || it.text || it.title || it.name || it.action || ''
      )
        .replace(/_/g, '')
        .trim();
      if (!lbl || lbl === '-' || lbl === '---' || seen.has(lbl)) return;
      seen.add(lbl);
      out.push({
        id: it.id !== undefined ? it.id : null,
        label: lbl,
        enabled: it.enabled !== false,
      });
    }
  });
  return out;
}

export function normalizeLiveTrayApps(rawRes) {
  const data = (rawRes && rawRes.result) || rawRes || {};
  const arr = Array.isArray(data.apps)
    ? data.apps
    : Array.isArray(data.tray_apps)
    ? data.tray_apps
    : Array.isArray(data.items)
    ? data.items
    : Array.isArray(data)
    ? data
    : [];

  return arr
    .filter((t) => t && typeof t === 'object')
    .map((t) => {
      const appId = String(
        t.app_id || t.id || t.comm || t.binary || t.name || t.app_name || t.service || 'tray-app'
      );
      const name = String(
        t.display_name || t.app_name || t.name || t.comm || t.app_id || t.id || '托盘应用'
      );
      const rawTitle = String(
        t.title || t.status_title || t.track_title || t.now_playing || t.tooltip || ''
      ).trim();
      const liveTitle =
        rawTitle && rawTitle.toLowerCase() !== name.toLowerCase() ? rawTitle : '';
      const menuItems = normalizeMenuItemsList(
        t.menu_items || t.dbusmenu_items || t.items || t.actions || []
      );
      return {
        appId,
        name,
        liveTitle,
        icon: pickTrayAppIcon(`${name} ${appId} ${liveTitle}`),
        pid: t.pid || (Array.isArray(t.pids) && t.pids[0]) || null,
        service: t.service || t.bus_name || '',
        menuPath: t.menu_path || '',
        status: t.status || 'Active',
        menuItems,
      };
    });
}

export class MemoryAdapterController {
  /**
   * @param {object} opts
   * @param {HTMLElement} opts.popoverEl
   * @param {HTMLElement} opts.mentionMenuEl
   * @param {HTMLTextAreaElement} opts.inputEl
   * @param {Function} opts.onInsertMention - (shortTag, fullEntity, alreadyInInput) => void
   * @param {Function} opts.onQuickAction - (promptText) => void
   * @param {Function} [opts.onOpenAdapterWorkbench] - (appQuery) => void
   * @param {Function} opts.onToast - (msg) => void
   */
  constructor(opts) {
    this.popoverEl = opts.popoverEl;
    this.mentionMenuEl = opts.mentionMenuEl;
    this.inputEl = opts.inputEl;
    this.onInsertMention = opts.onInsertMention;
    this.onQuickAction = opts.onQuickAction;
    this.onOpenAdapterWorkbench = opts.onOpenAdapterWorkbench || null;
    this.getSessionId = opts.getSessionId || (() => null);
    this.onToast = opts.onToast || (() => {});

    this.activeSection = 'all'; // 'all' | 'outlines' | 'mentioned' | 'frequent' | 'software' | 'adapters'
    this.filterText = '';
    this.loadedOnce = false;
    this.inspectQuery = '';
    this.lastInspectedApp = null;
    this.liveConsoleStatus = '';

    this.snapshot = {
      documentOutlines: [],
      mentionedFiles: [],
      frequentFiles: [],
      frequentApps: [],
      installedSummary: { total_count: 0 },
      adapters: DEFAULT_ADAPTER_PROFILES,
      liveTrayApps: [],
      liveProbe: { mpris_players: [], running_windows: [], dbus_activatable_count: 0 },
      deepScanSummary: null,
      compressionPreview: null,
    };

    // `@` mention autocomplete state
    this.mentionOpen = false;
    this.mentionItems = [];
    this.mentionActiveIdx = 0;
    this.mentionTriggerRange = null; // { start, end }
  }

  isOpen() {
    return Boolean(this.popoverEl && !this.popoverEl.hidden);
  }

  async togglePopover() {
    if (this.isOpen()) {
      this.closePopover();
      return;
    }
    await this.openPopover();
  }

  async openPopover() {
    if (!this.popoverEl) return;
    this.popoverEl.hidden = false;
    this.renderPopoverSkeleton();
    await this.refreshSnapshot();
    this.renderPopoverBody();
  }

  closePopover() {
    if (this.popoverEl) {
      this.popoverEl.hidden = true;
    }
  }

  async refreshSnapshot(forceSync = false) {
    if (forceSync) {
      await moduleRpc('memory_hub', 'sync_system_usage', {}, async () => ({ synced: true }));
    }

    const activeSessionId = this.getSessionId ? this.getSessionId() : null;

    const [
      memRes,
      personalAdpRes,
      adpRes,
      liveTrayRes,
      liveRes,
      deepScanRes,
      ccPreviewRes,
      stRes,
    ] = await Promise.all([
      moduleRpc('memory_hub', 'get_memory_dashboard', { auto_sync: true }, async () => null),
      moduleRpc('app_adapter', 'discover_personal_apps', {}, async () => null),
      moduleRpc('app_adapter', 'list_adapters', {}, async () => null),
      moduleRpc('app_adapter', 'list_live_tray_apps', {}, async () => null),
      moduleRpc('app_adapter', 'probe_live_controllable_apps', {}, async () => null),
      moduleRpc(
        'app_adapter',
        'deep_scan_local_software',
        { force_refresh: Boolean(forceSync) },
        async () => null
      ),
      activeSessionId
        ? moduleRpc(
            'memory_hub',
            'preview_session_compression',
            { session_id: activeSessionId },
            async () => null
          )
        : moduleRpc('memory_hub', 'get_context_compression_config', {}, async () => null),
      rpc('get_status'),
    ]);

    const mem = (memRes && memRes.ok && memRes.result) || {};
    const personalAdp = (personalAdpRes && personalAdpRes.ok && personalAdpRes.result) || {};
    const adp = (adpRes && adpRes.ok && adpRes.result) || {};
    const live = (liveRes && liveRes.ok && liveRes.result) || {};
    const st = (stRes && stRes.ok && stRes.result) || {};

    if (
      deepScanRes &&
      deepScanRes.ok &&
      deepScanRes.result &&
      deepScanRes.result.status !== 'stub'
    ) {
      const ds = deepScanRes.result;
      this.snapshot.deepScanSummary = {
        total_scanned:
          ds.total_scanned ?? (Array.isArray(ds.apps) ? ds.apps.length : 0),
        running_count: ds.running_count ?? 0,
        total_adapted: ds.total_adapted ?? ds.adapted_count ?? 0,
        categories: Array.isArray(ds.categories) ? ds.categories : [],
      };
    } else {
      this.snapshot.deepScanSummary = null;
    }

    if (
      ccPreviewRes &&
      ccPreviewRes.ok &&
      ccPreviewRes.result &&
      ccPreviewRes.result.status !== 'stub'
    ) {
      const rawCc = ccPreviewRes.result.stats || ccPreviewRes.result;
      this.snapshot.compressionPreview = rawCc;
    } else if (mem.context_compression_config) {
      this.snapshot.compressionPreview = mem.context_compression_config;
    } else {
      this.snapshot.compressionPreview = null;
    }

    this.snapshot.liveTrayApps = normalizeLiveTrayApps(liveTrayRes);

    this.snapshot.documentOutlines = Array.isArray(mem.document_outlines_preview)
      ? mem.document_outlines_preview
      : [];
    this.snapshot.mentionedFiles = Array.isArray(mem.mentioned_files) ? mem.mentioned_files : [];
    this.snapshot.frequentFiles = Array.isArray(mem.frequent_files) ? mem.frequent_files : [];
    this.snapshot.frequentApps = Array.isArray(mem.frequent_apps)
      ? mem.frequent_apps
      : Array.isArray(mem.software)
      ? mem.software
      : [];
    this.snapshot.installedSummary = mem.installed_apps_summary || {
      total_count: st.indexed_apps || this.snapshot.frequentApps.length || 0,
    };

    // Fallback enrichment from candidate indexer if memory_hub hasn't populated files/apps yet
    if (this.snapshot.frequentFiles.length === 0 || this.snapshot.frequentApps.length === 0) {
      const candRes = await moduleRpc(
        'intent_engine',
        'query_grouped_candidates',
        { query: '', limit: 16 },
        async () => null
      );
      if (candRes && candRes.ok && candRes.result && Array.isArray(candRes.result.candidates)) {
        const cands = candRes.result.candidates;
        if (this.snapshot.frequentFiles.length === 0) {
          this.snapshot.frequentFiles = cands
            .filter((c) => c.category === 'files' || c.kind === 'file')
            .slice(0, 6)
            .map((c) => ({
              title: c.title,
              path: (c.arguments && c.arguments.path) || c.subtitle || c.title,
              open_count: 1,
            }));
        }
        if (this.snapshot.frequentApps.length === 0) {
          this.snapshot.frequentApps = cands
            .filter((c) => c.category === 'apps' || c.kind === 'app')
            .slice(0, 8)
            .map((c) => ({
              name: c.title,
              desktop_id: c.id,
              category: c.subtitle || '桌面应用',
              launch_count: 1,
            }));
        }
      }
    }

    // Merge personalized discovered apps (`discover_personal_apps`) + registered adapters (`list_adapters`)
    const mergedAdapters = [];
    const seenAdapterIds = new Set();
    const rawPersonalList = Array.isArray(personalAdp.apps)
      ? personalAdp.apps
      : Array.isArray(personalAdp.adapters)
      ? personalAdp.adapters
      : Array.isArray(personalAdp)
      ? personalAdp
      : [];
    const rawAdapterList = Array.isArray(adp.adapters) ? adp.adapters : [];

    const pushAdapter = (item, fromPersonal = false) => {
      if (!item || typeof item !== 'object') return;
      const key = String(item.id || item.app_id || item.desktop_id || item.name || '').toLowerCase();
      if (!key || seenAdapterIds.has(key)) return;
      seenAdapterIds.add(key);
      const blob = JSON.stringify(item).toLowerCase();
      const isFeatured =
        fromPersonal ||
        item.source === 'custom' ||
        blob.includes('sodam') ||
        blob.includes('汽水') ||
        blob.includes('qq') ||
        blob.includes('netease');
      mergedAdapters.push({ ...item, _featured: isFeatured });
    };

    rawPersonalList.forEach((it) => pushAdapter(it, true));
    rawAdapterList.forEach((it) => pushAdapter(it, false));

    mergedAdapters.sort((a, b) => (a._featured === b._featured ? 0 : a._featured ? -1 : 1));
    this.snapshot.adapters = mergedAdapters.length > 0 ? mergedAdapters : DEFAULT_ADAPTER_PROFILES;

    this.snapshot.liveProbe = {
      mpris_players: Array.isArray(live.mpris_players) ? live.mpris_players : [],
      running_windows: Array.isArray(live.running_windows) ? live.running_windows : [],
      dbus_activatable_count: live.dbus_activatable_count || 0,
    };

    this.loadedOnce = true;
    return this.snapshot;
  }

  renderPopoverSkeleton() {
    if (!this.popoverEl) return;
    this.popoverEl.innerHTML = `
      <div class="qc-popover-head">
        <div class="qc-popover-title">🧠 记忆、文档章节大纲与个性化转译快照</div>
        <div class="qc-popover-head-actions">
          <button type="button" class="qc-mini-btn" id="btn-sync-memory" title="重新扫描系统最近文件、文档章节大纲与桌面软件">🔄 同步</button>
          <button type="button" class="qc-mini-btn" id="btn-close-mem-popover" title="关闭 (Esc)">✕</button>
        </div>
      </div>
      <div class="qc-popover-toolbar">
        <input type="text" id="qc-mem-search" class="qc-mem-search" placeholder="筛选文档章节大纲、提及文件、高频文件或个性化软件适配器…" value="${escapeHtml(
          this.filterText
        )}" />
        <div class="qc-mem-tabs" role="tablist">
          <button type="button" class="qc-mem-tab ${this.activeSection === 'all' ? 'active' : ''}" data-sec="all">全部</button>
          <button type="button" class="qc-mem-tab ${this.activeSection === 'outlines' ? 'active' : ''}" data-sec="outlines">文档大纲</button>
          <button type="button" class="qc-mem-tab ${this.activeSection === 'mentioned' ? 'active' : ''}" data-sec="mentioned">提及文件</button>
          <button type="button" class="qc-mem-tab ${this.activeSection === 'frequent' ? 'active' : ''}" data-sec="frequent">高频文件</button>
          <button type="button" class="qc-mem-tab ${this.activeSection === 'software' ? 'active' : ''}" data-sec="software">本机软件</button>
          <button type="button" class="qc-mem-tab ${this.activeSection === 'adapters' ? 'active' : ''}" data-sec="adapters">软件转译</button>
        </div>
      </div>
      <div class="qc-popover-scroll" id="qc-mem-scroll-body">
        <div class="qc-mem-empty">正在读取文档章节大纲、个人记忆与个性化转译适配器…</div>
      </div>
    `;

    const closeBtn = this.popoverEl.querySelector('#btn-close-mem-popover');
    if (closeBtn) closeBtn.onclick = () => this.closePopover();

    const syncBtn = this.popoverEl.querySelector('#btn-sync-memory');
    if (syncBtn) {
      syncBtn.onclick = async () => {
        syncBtn.textContent = '⏳ 同步中';
        await this.refreshSnapshot(true);
        syncBtn.textContent = '🔄 同步';
        this.renderPopoverBody();
        this.onToast('🧠 已同步本机文档章节大纲、高频文件与个性化软件资产');
      };
    }

    const searchInput = this.popoverEl.querySelector('#qc-mem-search');
    if (searchInput) {
      searchInput.oninput = () => {
        this.filterText = searchInput.value.trim();
        this.renderPopoverBody();
      };
    }

    this.popoverEl.querySelectorAll('.qc-mem-tab').forEach((tab) => {
      tab.onclick = () => {
        this.activeSection = tab.getAttribute('data-sec') || 'all';
        this.popoverEl
          .querySelectorAll('.qc-mem-tab')
          .forEach((t) => t.classList.toggle('active', t === tab));
        this.renderPopoverBody();
      };
    });
  }

  matchesFilter(str) {
    if (!this.filterText) return true;
    return String(str || '')
      .toLowerCase()
      .includes(this.filterText.toLowerCase());
  }

  renderPopoverBody() {
    const bodyEl = this.popoverEl && this.popoverEl.querySelector('#qc-mem-scroll-body');
    if (!bodyEl) return;
    bodyEl.innerHTML = '';

    const showAll = this.activeSection === 'all';
    const consolePinnedTop =
      this.activeSection === 'adapters' ||
      (showAll &&
        ((this.snapshot.liveTrayApps && this.snapshot.liveTrayApps.length > 0) ||
          Boolean(this.lastInspectedApp)));

    if (showAll) {
      const ccBox = this.buildContextCompressionBanner();
      if (ccBox) bodyEl.appendChild(ccBox);
    }

    if (showAll || this.activeSection === 'software' || this.activeSection === 'adapters') {
      const dsBox = this.buildDeepScanCategoryShortcutSection();
      if (dsBox) bodyEl.appendChild(dsBox);
    }

    if (consolePinnedTop) {
      bodyEl.appendChild(this.buildLiveAdapterConsoleSection());
    }

    // Section 0: 文档章节大纲索引 (`document_outlines_preview`)
    if (showAll || this.activeSection === 'outlines') {
      const outlineItems = this.snapshot.documentOutlines.filter((doc) =>
        this.matchesFilter(
          `${doc.doc_title || ''} ${doc.file_name || ''} ${doc.path || ''} ${(
            doc.sample_headings || []
          ).join(' ')}`
        )
      );
      bodyEl.appendChild(this.buildDocumentOutlinesSection(outlineItems));
    }

    // Section 1: 之前提到的文件
    if (showAll || this.activeSection === 'mentioned') {
      const items = this.snapshot.mentionedFiles.filter((f) =>
        this.matchesFilter(`${f.display_name || ''} ${f.canonical_value || ''} ${f.path || ''}`)
      );
      bodyEl.appendChild(
        this.buildSectionCard(
          '💬 之前提到的文件',
          items.length ? `${items.length} 项` : '随对话自动沉淀',
          items,
          (f) => {
            const fullPath = f.canonical_value || f.path || f.display_name || '';
            const name = f.display_name || fullPath.split('/').pop() || fullPath;
            const sub = f.context_snippet || fullPath;
            const badge = f.mention_count ? `${f.mention_count}次提及` : '会话记忆';
            return {
              name,
              sub,
              badge,
              mentionTag: name.replace(/\s+/g, '_'),
              entity: { kind: 'mentioned_file', name, path: fullPath },
              openPrompt: `打开 ${fullPath}`,
            };
          },
          '在对话中提到的文件路径与《文档名》会自动记录于此，点击可插入 @引用。'
        )
      );
    }

    // Section 2: 长期高频使用的文件
    if (showAll || this.activeSection === 'frequent') {
      const items = this.snapshot.frequentFiles.filter((f) =>
        this.matchesFilter(`${f.title || ''} ${f.path || ''} ${f.display_name || ''}`)
      );
      bodyEl.appendChild(
        this.buildSectionCard(
          '🔥 长期高频使用的文件',
          items.length ? `${items.length} 项` : '来自 XBEL 与使用画像',
          items,
          (f) => {
            const fullPath = f.path || f.canonical_value || f.title || '';
            const name = f.title || f.display_name || fullPath.split('/').pop() || fullPath;
            const count = f.open_count || f.use_count || f.frecency_score || '';
            const badge = count ? `热度 ${count}` : '常用';
            return {
              name,
              sub: fullPath,
              badge,
              mentionTag: name.replace(/\s+/g, '_'),
              entity: { kind: 'frequent_file', name, path: fullPath },
              openPrompt: `打开 ${fullPath}`,
            };
          },
          '暂无匹配的高频文件，点击右上角「🔄 同步」可扫描系统最近使用记录。'
        )
      );
    }

    // Section 3: 本机常用与已装软件
    if (showAll || this.activeSection === 'software') {
      const items = this.snapshot.frequentApps.filter((a) =>
        this.matchesFilter(`${a.name || ''} ${a.name_zh || ''} ${a.desktop_id || ''} ${a.category || ''}`)
      );
      const totalApps =
        this.snapshot.installedSummary.total_installed ||
        this.snapshot.installedSummary.total_count ||
        this.snapshot.installedSummary.total ||
        items.length;
      bodyEl.appendChild(
        this.buildSectionCard(
          '🧩 本机常用与已装软件',
          totalApps ? `已扫描 ${totalApps} 款应用` : '桌面应用画像',
          items,
          (a) => {
            const name = a.name_zh || a.display_name || a.name || a.app_id || '桌面软件';
            const sub = a.comment || a.generic_name || a.category || a.exec || a.desktop_id || '';
            const cnt = a.launch_count || a.usage_count || 0;
            const badge = cnt > 0 ? `启动 ${cnt}次` : '已安装';
            return {
              name,
              sub,
              badge,
              mentionTag: name.replace(/\s+/g, ''),
              entity: { kind: 'software', name, app_id: a.desktop_id || a.id || name },
              openPrompt: `打开 ${name}`,
            };
          },
          '点击「🔄 同步」即可建立 Ubuntu 全量桌面应用与常用软件画像。'
        )
      );
    }

    // Section 4: 个性化软件实时转译台 + 已注册适配器
    if (showAll || this.activeSection === 'adapters') {
      if (!consolePinnedTop) {
        bodyEl.appendChild(this.buildLiveAdapterConsoleSection());
      }

      const items = this.snapshot.adapters.filter((ad) =>
        this.matchesFilter(
          `${ad.name || ''} ${ad.display_name || ''} ${ad.id || ''} ${(ad.aliases || []).join(
            ' '
          )} ${ad.channel || ''} ${ad.primary_channel || ''}`
        )
      );
      const liveMpris = this.snapshot.liveProbe.mpris_players || [];
      const liveTrayCount = (this.snapshot.liveTrayApps || []).length;
      const liveSubtitle =
        liveTrayCount > 0 || liveMpris.length > 0
          ? `运行态托盘: ${liveTrayCount} · 媒体总线: ${liveMpris.length} · 已适配 ${items.length} 款`
          : `${items.length} 款个性化与桌面转译适配器就绪`;

      bodyEl.appendChild(
        this.buildSectionCard(
          '🔌 个性化软件转译适配器',
          liveSubtitle,
          items,
          (ad) => {
            const name = ad.display_name || ad.name || ad.app_name || ad.id || '软件适配器';
            const ch = shortChannelTag(
              ad.channel || ad.primary_channel || (Array.isArray(ad.channels) ? ad.channels[0] : '')
            );
            const acts = Array.isArray(ad.supported_actions)
              ? ad.supported_actions
                  .slice(0, 3)
                  .map((x) => (typeof x === 'string' ? x : x.summary || x.action || x.id))
                  .join(' · ')
              : Array.isArray(ad.actions)
              ? ad.actions
                  .slice(0, 3)
                  .map((x) => (typeof x === 'string' ? x : x.name || x.id))
                  .join(' · ')
              : ad.notes || ad.description || '支持非 CLI 桌面控制与托盘进程验证关闭';
            return {
              name: ad.source === 'custom' ? `★ ${name}` : name,
              sub: acts,
              badge: ch,
              badgeCyan: true,
              mentionTag: (ad.id || name).replace(/\s+/g, ''),
              entity: { kind: 'adapter', name, app_id: ad.id || name, channel: ch },
              openPrompt: `使用转译层查看或控制 ${name}`,
            };
          },
          '无匹配的软件转译适配器，可在「⚙ 设置中心 -> 5. 本机软件深度扫描与分类转译中心」中自定义添加'
        )
      );
    }
  }

  buildContextCompressionBanner() {
    const cp = this.snapshot.compressionPreview;
    if (!cp) return null;
    const enabled = cp.enabled !== false;
    const qaTurns = Number(cp.included_qa_turns ?? cp.raw_qa_turns ?? 0);
    const estTok = Number(cp.compressed_estimated_tokens ?? cp.max_context_tokens ?? 0);
    const savedPct = Math.round(Number(cp.saved_pct || 0));
    const droppedTools = Number(cp.dropped_tool_records || 0);

    const sec = document.createElement('div');
    sec.className = 'qc-mem-section';
    sec.innerHTML = `
      <div class="qc-mem-sec-head">
        <span>📉 会话上下文非线性时间衰减压缩</span>
        <span class="qc-mem-sec-sub">${enabled ? '🟢 已启用' : '⚪ 已关闭'}</span>
      </div>
      <div class="qc-mem-row" style="cursor:default;">
        <div class="qc-mem-row-main">
          <div class="qc-mem-row-title" style="font-size:0.78rem;">
            ${
              qaTurns > 0
                ? `当前会话纳入 ${qaTurns} 轮问答 · 估算 ${estTok} tok${
                    savedPct > 0 ? ` (节省 ${savedPct}%)` : ''
                  }${droppedTools > 0 ? ` · 已剥离 ${droppedTools} 条工具记录` : ''}`
                : `衰减曲线就绪（近期完整保留，远期自动摘要并剥离历史工具 JSON）`
            }
          </div>
        </div>
      </div>
    `;
    return sec;
  }

  buildDeepScanCategoryShortcutSection() {
    const ds = this.snapshot.deepScanSummary;
    const totalScanned =
      (ds && ds.total_scanned) ||
      this.snapshot.installedSummary.total_installed ||
      this.snapshot.installedSummary.total_count ||
      0;
    const runningCount = (ds && ds.running_count) || (this.snapshot.liveTrayApps || []).length;
    const cats = (ds && Array.isArray(ds.categories) && ds.categories) || [];

    const sec = document.createElement('div');
    sec.className = 'qc-mem-section';
    sec.innerHTML = `
      <div class="qc-mem-sec-head">
        <span>🔍 本机软件分类统计 (9 大分类)</span>
        <span class="qc-mem-sec-sub">共 ${totalScanned} 款 · 运行中 ${runningCount} 款</span>
      </div>
    `;

    if (cats.length > 0) {
      const strip = document.createElement('div');
      strip.style.cssText = 'display:flex; flex-wrap:wrap; gap:0.3rem; padding:0.35rem 0.5rem;';
      cats.slice(0, 9).forEach((c) => {
        const pill = document.createElement('button');
        pill.type = 'button';
        pill.className = 'qc-mini-btn';
        pill.textContent = `${c.icon || '📦'} ${c.name_zh || c.id} (${c.count ?? 0})`;
        pill.onclick = () => {
          if (this.onOpenAdapterWorkbench) {
            this.onOpenAdapterWorkbench('');
          }
        };
        strip.appendChild(pill);
      });
      sec.appendChild(strip);
    }

    if (this.onOpenAdapterWorkbench) {
      const jumpBar = document.createElement('div');
      jumpBar.style.cssText = 'padding:0.25rem 0.5rem 0.45rem;';
      const jumpBtn = document.createElement('button');
      jumpBtn.type = 'button';
      jumpBtn.className = 'qc-mini-btn';
      jumpBtn.style.width = '100%';
      jumpBtn.textContent = '🧭 打开本机软件深度扫描与 9 大分类转译中心 (第 5 页)';
      jumpBtn.onclick = () => this.onOpenAdapterWorkbench('');
      jumpBar.appendChild(jumpBtn);
      sec.appendChild(jumpBar);
    }

    return sec;
  }

  async refreshLiveTrayOnly() {
    const liveTrayRes = await moduleRpc('app_adapter', 'list_live_tray_apps', {}, async () => null);
    this.snapshot.liveTrayApps = normalizeLiveTrayApps(liveTrayRes);
    this.renderPopoverBody();
  }

  async triggerTrayMenuAction(appKey, actionLabel, service = '', menuId = null) {
    this.liveConsoleStatus = `⏳ 正在触发「${appKey} · ${actionLabel}」(dbusmenu)…`;
    this.renderPopoverBody();

    const payload = {
      app: appKey,
      app_hint: appKey,
      action: actionLabel,
      menu_label: actionLabel,
    };
    if (service) payload.service = service;
    if (menuId !== null && menuId !== undefined) payload.menu_id = menuId;

    const r = await moduleRpc('app_adapter', 'trigger_tray_menu', payload, async () => null);
    if (r && r.ok && r.result) {
      const res = r.result;
      const msg =
        res.summary ||
        res.message ||
        (res.title_after && res.title_after !== res.title_before
          ? `✓ 已触发「${actionLabel}」· 实时状态更新为: ${res.title_after}`
          : `✓ 已向「${appKey}」托盘菜单发送「${actionLabel}」`);
      this.liveConsoleStatus = msg;
      this.onToast(msg);
    } else {
      const errMsg = `⚠ 托盘动作反馈: ${(r && r.error) || '请确认目标软件仍在系统托盘运行'}`;
      this.liveConsoleStatus = errMsg;
      this.onToast(errMsg);
    }

    setTimeout(() => {
      this.refreshLiveTrayOnly().catch(() => {});
    }, 320);
  }

  async inspectLiveApp(appQuery) {
    const q = String(appQuery || '').trim();
    if (!q) return;
    this.inspectQuery = q;
    this.liveConsoleStatus = `⏳ 正在深度探测「${q}」的托盘菜单、MPRIS2、.desktop 与 AT-SPI2 接口…`;
    this.renderPopoverBody();

    const r = await moduleRpc(
      'app_adapter',
      'inspect_live_app',
      { app: q, app_hint: q, query: q },
      async () => null
    );
    if (r && r.ok && r.result) {
      this.lastInspectedApp = { query: q, ...r.result };
      this.liveConsoleStatus = '';
    } else {
      this.lastInspectedApp = {
        query: q,
        found: false,
        error: (r && r.error) || '未探测到匹配软件，请检查名称或点击右上角同步',
      };
      this.liveConsoleStatus = '';
    }
    this.renderPopoverBody();
  }

  buildLiveAdapterConsoleSection() {
    const sec = document.createElement('section');
    sec.className = 'qc-mem-section';

    const trayApps = (this.snapshot.liveTrayApps || []).filter((t) =>
      this.matchesFilter(
        `${t.name} ${t.appId} ${t.liveTitle} ${t.menuItems.map((m) => m.label).join(' ')}`
      )
    );

    const head = document.createElement('div');
    head.className = 'qc-mem-sec-head';
    head.innerHTML = `
      <strong>⚡ 个性化软件实时转译台 (托盘菜单直连 &amp; 任意软件探测)</strong>
      <span>${trayApps.length ? `${trayApps.length} 款托盘活跃` : 'SNI / dbusmenu / MPRIS2'}</span>
    `;
    sec.appendChild(head);

    const consoleBox = document.createElement('div');
    consoleBox.className = 'qc-adapter-console';

    // --- Section A: 运行态托盘与软件实时控制 (`list_live_tray_apps`) ---
    const secAHead = document.createElement('div');
    secAHead.className = 'qc-live-tray-top';
    secAHead.innerHTML = `
      <span style="font-size:0.73rem; font-weight:700; color:var(--text-primary);">
        📡 A. 运行态托盘与软件实时控制 (${trayApps.length})
      </span>
    `;
    const btnTrayRefresh = document.createElement('button');
    btnTrayRefresh.type = 'button';
    btnTrayRefresh.className = 'qc-mini-btn';
    btnTrayRefresh.textContent = '↻ 刷新托盘';
    btnTrayRefresh.onclick = () => this.refreshLiveTrayOnly();
    secAHead.appendChild(btnTrayRefresh);
    consoleBox.appendChild(secAHead);

    if (trayApps.length === 0) {
      const emptyTray = document.createElement('div');
      emptyTray.className = 'qc-mem-empty-hint';
      emptyTray.textContent =
        '当前未检测到暴露 StatusNotifierItem / dbusmenu 托盘菜单的运行态软件（启动汽水音乐 SodaM、WPS、FlClash、QQ 等软件后点击「↻ 刷新托盘」即可一键点击其真实托盘菜单项）。';
      consoleBox.appendChild(emptyTray);
    } else {
      trayApps.slice(0, 8).forEach((tApp) => {
        const card = document.createElement('div');
        card.className = 'qc-live-tray-card';

        const topRow = document.createElement('div');
        topRow.className = 'qc-live-tray-top';
        const titleText = tApp.liveTitle
          ? `${tApp.icon} ${tApp.name} · ${tApp.liveTitle}`
          : `${tApp.icon} ${tApp.name}`;

        const titleSpan = document.createElement('span');
        titleSpan.className = 'qc-live-tray-title';
        titleSpan.title = `${titleText}${tApp.service ? ' (' + tApp.service + ')' : ''}`;
        titleSpan.textContent = titleText;
        topRow.appendChild(titleSpan);

        const inspectBtn = document.createElement('button');
        inspectBtn.type = 'button';
        inspectBtn.className = 'qc-mini-btn';
        inspectBtn.textContent = '🔍 接口';
        inspectBtn.title = `深度探测 ${tApp.name} 的全部转译通道`;
        inspectBtn.onclick = () => this.inspectLiveApp(tApp.name || tApp.appId);
        topRow.appendChild(inspectBtn);
        card.appendChild(topRow);

        const actsWrap = document.createElement('div');
        actsWrap.className = 'qc-live-tray-actions';
        const itemsToShow =
          tApp.menuItems.length > 0
            ? tApp.menuItems.slice(0, 8)
            : [{ id: null, label: '显示主窗口', enabled: true }];

        itemsToShow.forEach((mItem) => {
          const isQuit =
            mItem.label.includes('退出') ||
            mItem.label.toLowerCase() === 'quit' ||
            mItem.label.toLowerCase() === 'exit';
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'qc-tray-action-btn' + (isQuit ? ' danger' : '');
          b.disabled = !mItem.enabled;
          b.textContent = mItem.label;
          b.title = `直接触发 ${tApp.name} 托盘菜单项: ${mItem.label}`;
          b.onclick = () =>
            this.triggerTrayMenuAction(
              tApp.appId || tApp.name,
              mItem.label,
              tApp.service,
              mItem.id
            );
          actsWrap.appendChild(b);
        });
        card.appendChild(actsWrap);
        consoleBox.appendChild(card);
      });
    }

    // --- Section B: 探测并转译任意软件 (`inspect_live_app`) ---
    const secBTitle = document.createElement('div');
    secBTitle.style.cssText = 'font-size:0.73rem; font-weight:700; color:var(--text-primary); margin-top:2px;';
    secBTitle.textContent = '🔍 B. 探测并转译任意软件 (自动发现 dbusmenu / MPRIS / URI / AT-SPI)';
    consoleBox.appendChild(secBTitle);

    const inspectBar = document.createElement('div');
    inspectBar.className = 'qc-inspect-bar';

    const inspectInput = document.createElement('input');
    inspectInput.type = 'text';
    inspectInput.className = 'qc-mem-search';
    inspectInput.placeholder = '输入任意软件名探测接口 (如 飞书 / FlClash / 轻笺 / 汽水音乐)...';
    inspectInput.value = this.inspectQuery || '';

    const inspectSubmitBtn = document.createElement('button');
    inspectSubmitBtn.type = 'button';
    inspectSubmitBtn.className = 'qc-inspect-btn';
    inspectSubmitBtn.textContent = '⚡ 探测接口';

    const triggerInspect = () => {
      const val = inspectInput.value.trim();
      if (val) this.inspectLiveApp(val);
    };
    inspectSubmitBtn.onclick = triggerInspect;
    inspectInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        triggerInspect();
      }
    });

    inspectBar.appendChild(inspectInput);
    inspectBar.appendChild(inspectSubmitBtn);
    consoleBox.appendChild(inspectBar);

    if (this.liveConsoleStatus) {
      const stBanner = document.createElement('div');
      stBanner.style.cssText = 'font-size:0.71rem; color:#38bdf8; font-weight:600;';
      stBanner.textContent = this.liveConsoleStatus;
      consoleBox.appendChild(stBanner);
    }

    if (this.lastInspectedApp) {
      const info = this.lastInspectedApp;
      const resBox = document.createElement('div');
      resBox.className = 'qc-inspect-result-box';

      if (info.found === false && info.error) {
        resBox.textContent = `⚠ ${info.error}`;
      } else {
        const appName = info.display_name || info.name || info.app_name || info.app_id || info.query;
        const desktopId = info.desktop_id || info.desktop_entry || '无 .desktop';
        const pids = Array.isArray(info.running_pids)
          ? info.running_pids
          : Array.isArray(info.pids)
          ? info.pids
          : info.pid
          ? [info.pid]
          : [];
        const isRunning = Boolean(info.is_running || pids.length > 0);

        const trayInfo = info.tray_bus || info.tray || (Array.isArray(info.tray_apps) && info.tray_apps[0]) || null;
        const trayMenuItems = normalizeMenuItemsList(
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

        const headLine = document.createElement('div');
        headLine.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:6px; flex-wrap:wrap;';
        headLine.innerHTML = `
          <strong style="color:var(--text-primary);">${escapeHtml(appName)}</strong>
          <span class="qc-mem-badge ${isRunning ? 'cyan' : ''}">${
          isRunning ? `运行中 PID ${escapeHtml(pids.join(','))}` : '未运行 / 已安装'
        }</span>
        `;
        resBox.appendChild(headLine);

        const metaDiv = document.createElement('div');
        metaDiv.style.cssText = 'font-size:0.69rem; line-height:1.45;';
        const channelsSummary = [];
        if (trayMenuItems.length > 0) channelsSummary.push(`托盘菜单(${trayMenuItems.length}项)`);
        if (mprisBus) channelsSummary.push(`MPRIS2(${mprisBus})`);
        if (desktopActions.length > 0) channelsSummary.push(`.desktop动作(${desktopActions.length})`);
        if (uriSchemes.length > 0) channelsSummary.push(`URI(${uriSchemes.join(',')})`);
        if (atspiControls.length > 0) channelsSummary.push(`AT-SPI/窗口(${atspiControls.length})`);
        metaDiv.textContent =
          `Desktop: ${desktopId}` +
          (info.exec_cmd || info.binary_name ? ` · Exec: ${info.exec_cmd || info.binary_name}` : '') +
          (channelsSummary.length ? `\n可转译通道: ${channelsSummary.join(' · ')}` : '');
        resBox.appendChild(metaDiv);

        const testBar = document.createElement('div');
        testBar.className = 'qc-live-tray-actions';

        // 1-click live tray menu test buttons
        trayMenuItems.slice(0, 8).forEach((mi) => {
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'qc-tray-action-btn';
          b.textContent = `📡 ${mi.label}`;
          b.onclick = () =>
            this.triggerTrayMenuAction(
              info.app_id || appName,
              mi.label,
              (trayInfo && trayInfo.service) || '',
              mi.id
            );
          testBar.appendChild(b);
        });

        // If MPRIS available, offer quick play/pause & next test
        if (mprisBus) {
          ['play_pause', 'next'].forEach((actKey) => {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'qc-tray-action-btn';
            b.textContent = actKey === 'play_pause' ? '🎵 播放/暂停' : '⏭ 下一首';
            b.onclick = async () => {
              const tr = await moduleRpc(
                'app_adapter',
                'translate_and_execute',
                { app_hint: info.app_id || appName, intent_action: actKey, params: {} },
                async () => null
              );
              const msg =
                (tr && tr.ok && tr.result && tr.result.summary) ||
                `已发送 MPRIS 动作: ${actKey}`;
              this.liveConsoleStatus = msg;
              this.onToast(msg);
              this.renderPopoverBody();
            };
            testBar.appendChild(b);
          });
        }

        if (this.onOpenAdapterWorkbench) {
          const bindBtn = document.createElement('button');
          bindBtn.type = 'button';
          bindBtn.className = 'qc-mini-btn';
          bindBtn.textContent = '⚙ 绑定自定义口令 (设置页 5)';
          bindBtn.onclick = () => this.onOpenAdapterWorkbench(info.app_id || appName);
          testBar.appendChild(bindBtn);
        }

        resBox.appendChild(testBar);
      }

      consoleBox.appendChild(resBox);
    }

    sec.appendChild(consoleBox);
    return sec;
  }

  buildDocumentOutlinesSection(outlineItems) {
    const sec = document.createElement('section');
    sec.className = 'qc-mem-section';

    const head = document.createElement('div');
    head.className = 'qc-mem-sec-head';
    head.innerHTML = `
      <strong>📑 文档章节大纲索引 (渐进式语义目录)</strong>
      <span>${outlineItems.length ? `已建索引 ${outlineItems.length} 篇` : '自动解析 .docx/.md/.pdf 章节'}</span>
    `;
    sec.appendChild(head);

    if (!outlineItems || outlineItems.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'qc-mem-empty-hint';
      empty.textContent =
        '桌面/文档目录中的 .docx、.md、.tex、.pdf 文档会自动提取标题与章节大纲（仅约 60 tokens/篇，支持按“第四章”精准定位而无需塞入全文）。';
      sec.appendChild(empty);
      return sec;
    }

    const ul = document.createElement('div');
    ul.className = 'qc-mem-list';

    outlineItems.slice(0, 10).forEach((doc) => {
      const fullPath = doc.path || '';
      const fileName = doc.file_name || fullPath.split('/').pop() || '文档';
      const title = doc.doc_title || fileName;
      const headings = Array.isArray(doc.sample_headings) ? doc.sample_headings : [];
      const hCount = doc.heading_count ?? headings.length;
      const tocLine =
        headings.length > 0
          ? `章节: ${headings.slice(0, 4).join(' | ')}`
          : doc.doc_summary || fullPath;
      const mentionTag = fileName.replace(/\s+/g, '_');

      const wrap = document.createElement('div');
      wrap.style.display = 'flex';
      wrap.style.flexDirection = 'column';
      wrap.style.gap = '3px';

      const row = document.createElement('div');
      row.className = 'qc-mem-row';

      const mainBtn = document.createElement('button');
      mainBtn.type = 'button';
      mainBtn.className = 'qc-mem-row-main';
      mainBtn.title = `${fullPath}\n点击插入 @${mentionTag}`;
      mainBtn.innerHTML = `
        <div class="qc-mem-row-top">
          <span class="qc-mem-name">${escapeHtml(title)}</span>
          <span class="qc-mem-badge amber">${escapeHtml(`${hCount} 章节`)}</span>
        </div>
        <div class="qc-mem-sub">${escapeHtml(fileName)} · ${escapeHtml(tocLine)}</div>
      `;
      mainBtn.onclick = () => {
        if (this.onInsertMention) {
          this.onInsertMention(mentionTag, {
            kind: 'document_outline',
            name: title,
            path: fullPath,
          });
        }
        this.closePopover();
      };

      const previewBox = document.createElement('div');
      previewBox.className = 'qc-mem-outline-preview';
      previewBox.hidden = true;

      const inspectBtn = document.createElement('button');
      inspectBtn.type = 'button';
      inspectBtn.className = 'qc-mem-row-open';
      inspectBtn.title = '按需读取该文档完整章节大纲 (inspect_document)';
      inspectBtn.textContent = '目录';
      inspectBtn.onclick = async (e) => {
        e.stopPropagation();
        if (!previewBox.hidden) {
          previewBox.hidden = true;
          return;
        }
        previewBox.hidden = false;
        previewBox.textContent = '⏳ 正在读取章节结构…';
        const r = await moduleRpc(
          'memory_hub',
          'inspect_document',
          { query: fullPath || title },
          async () => null
        );
        if (r && r.ok && r.result && r.result.found) {
          const outlineArr = Array.isArray(r.result.outline) ? r.result.outline : headings;
          previewBox.textContent =
            `📄 路径: ${r.result.path || fullPath}\n` +
            (outlineArr.length > 0
              ? `📑 章节列表:\n  • ${outlineArr.slice(0, 12).join('\n  • ')}`
              : r.result.doc_summary || '已建立文档索引');
        } else {
          previewBox.textContent =
            headings.length > 0
              ? `📑 章节预览:\n  • ${headings.join('\n  • ')}`
              : `📄 ${fullPath}`;
        }
      };

      const openBtn = document.createElement('button');
      openBtn.type = 'button';
      openBtn.className = 'qc-mem-row-open';
      openBtn.title = `打开 ${title}`;
      openBtn.textContent = '↗';
      openBtn.onclick = (e) => {
        e.stopPropagation();
        this.closePopover();
        if (this.onQuickAction) {
          const sampleChap = headings[0] ? `并查看${headings[0]}` : '';
          this.onQuickAction(`打开 ${fullPath}${sampleChap}`);
        }
      };

      row.appendChild(mainBtn);
      row.appendChild(inspectBtn);
      row.appendChild(openBtn);
      wrap.appendChild(row);
      wrap.appendChild(previewBox);
      ul.appendChild(wrap);
    });

    sec.appendChild(ul);
    return sec;
  }

  buildSectionCard(title, rightMeta, list, mapper, emptyHint) {
    const sec = document.createElement('section');
    sec.className = 'qc-mem-section';

    const head = document.createElement('div');
    head.className = 'qc-mem-sec-head';
    head.innerHTML = `<strong>${escapeHtml(title)}</strong><span>${escapeHtml(rightMeta)}</span>`;
    sec.appendChild(head);

    if (!list || list.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'qc-mem-empty-hint';
      empty.textContent = emptyHint;
      sec.appendChild(empty);
      return sec;
    }

    const ul = document.createElement('div');
    ul.className = 'qc-mem-list';

    list.slice(0, 10).forEach((rawItem) => {
      const mapped = mapper(rawItem);
      const row = document.createElement('div');
      row.className = 'qc-mem-row';

      const mainBtn = document.createElement('button');
      mainBtn.type = 'button';
      mainBtn.className = 'qc-mem-row-main';
      mainBtn.title = `点击插入 @${mapped.mentionTag}`;
      mainBtn.innerHTML = `
        <div class="qc-mem-row-top">
          <span class="qc-mem-name">${escapeHtml(mapped.name)}</span>
          <span class="qc-mem-badge ${mapped.badgeCyan ? 'cyan' : ''}">${escapeHtml(mapped.badge)}</span>
        </div>
        <div class="qc-mem-sub">${escapeHtml(mapped.sub || '')}</div>
      `;
      mainBtn.onclick = () => {
        if (this.onInsertMention) {
          this.onInsertMention(mapped.mentionTag, mapped.entity);
        }
        this.closePopover();
      };

      const actBtn = document.createElement('button');
      actBtn.type = 'button';
      actBtn.className = 'qc-mem-row-open';
      actBtn.title = mapped.openPrompt;
      actBtn.textContent = '↗';
      actBtn.onclick = (e) => {
        e.stopPropagation();
        this.closePopover();
        if (this.onQuickAction) {
          this.onQuickAction(mapped.openPrompt);
        }
      };

      row.appendChild(mainBtn);
      row.appendChild(actBtn);
      ul.appendChild(row);
    });

    sec.appendChild(ul);
    return sec;
  }

  /* ================= `@` Inline Mention Menu ================= */

  buildCombinedMentionCandidates(query) {
    const q = String(query || '').toLowerCase();
    const pool = [];
    const seen = new Set();

    const pushUnique = (item) => {
      const key = `${item.kind}:${item.tag}:${item.subtitle}`;
      if (seen.has(key)) return;
      if (
        q &&
        !`${item.tag} ${item.label} ${item.subtitle} ${item.keywords || ''}`
          .toLowerCase()
          .includes(q)
      ) {
        return;
      }
      seen.add(key);
      pool.push(item);
    };

    // 1. Document Outlines first (matches semantic title & chapter headings even if filename is English!)
    this.snapshot.documentOutlines.forEach((doc) => {
      const path = doc.path || '';
      const fileName = doc.file_name || path.split('/').pop() || '';
      const title = doc.doc_title || fileName;
      if (!fileName && !title) return;
      const chapHint = Array.isArray(doc.sample_headings) ? doc.sample_headings.slice(0, 3).join(' · ') : '';
      pushUnique({
        icon: '📑',
        kind: 'document_outline',
        tag: (fileName || title).replace(/\s+/g, '_'),
        label: title,
        subtitle: `大纲 (${doc.heading_count || 0}章) · ${title}${chapHint ? ' · ' + chapHint : ''}`,
        keywords: `${title} ${chapHint} ${path}`,
        entity: { kind: 'document_outline', name: title, path },
      });
    });

    // 2. Previously mentioned files
    this.snapshot.mentionedFiles.forEach((f) => {
      const path = f.canonical_value || f.path || f.display_name || '';
      const name = f.display_name || path.split('/').pop() || path;
      if (!name) return;
      pushUnique({
        icon: '💬',
        kind: 'mentioned_file',
        tag: name.replace(/\s+/g, '_'),
        label: name,
        subtitle: `之前提及 · ${path}`,
        entity: { kind: 'mentioned_file', name, path },
      });
    });

    // 3. Frequent files
    this.snapshot.frequentFiles.forEach((f) => {
      const path = f.path || f.canonical_value || f.title || '';
      const name = f.title || f.display_name || path.split('/').pop() || path;
      if (!name) return;
      pushUnique({
        icon: '🔥',
        kind: 'frequent_file',
        tag: name.replace(/\s+/g, '_'),
        label: name,
        subtitle: `长期常用 · ${path}`,
        entity: { kind: 'frequent_file', name, path },
      });
    });

    // 4. Personalized & built-in software adapters
    this.snapshot.adapters.forEach((ad) => {
      const name = ad.display_name || ad.name || ad.id || '';
      if (!name) return;
      const ch = shortChannelTag(
        ad.channel || ad.primary_channel || (Array.isArray(ad.channels) ? ad.channels[0] : '')
      );
      const shortId = (ad.id || name.split(' ')[0]).replace(/\s+/g, '');
      pushUnique({
        icon: '🔌',
        kind: 'adapter',
        tag: shortId,
        label: name,
        subtitle: `转译层 (${ch}) · ${name}`,
        keywords: (ad.aliases || []).join(' '),
        entity: { kind: 'adapter', name, app_id: ad.id || shortId, channel: ch },
      });
    });

    // 5. Installed desktop software
    this.snapshot.frequentApps.forEach((a) => {
      const name = a.name_zh || a.display_name || a.name || '';
      if (!name) return;
      pushUnique({
        icon: '🧩',
        kind: 'software',
        tag: name.replace(/\s+/g, ''),
        label: name,
        subtitle: `本机软件 · ${a.category || a.desktop_id || ''}`,
        entity: { kind: 'software', name, app_id: a.desktop_id || name },
      });
    });

    return pool.slice(0, 8);
  }

  async handleInputForMention() {
    if (!this.inputEl || !this.mentionMenuEl) return;
    const val = this.inputEl.value;
    const caret = this.inputEl.selectionStart ?? val.length;
    const beforeCaret = val.slice(0, caret);

    // Match `@query` at start of input or preceded by whitespace
    const m = beforeCaret.match(/(?:^|\s)@([^\s@]{0,36})$/);
    if (!m) {
      this.closeMentionMenu();
      return;
    }

    const query = m[1] || '';
    const atIndex = beforeCaret.lastIndexOf('@');
    this.mentionTriggerRange = { start: atIndex, end: caret };

    if (!this.loadedOnce) {
      await this.refreshSnapshot(false);
    }

    const items = this.buildCombinedMentionCandidates(query);
    if (items.length === 0) {
      this.closeMentionMenu();
      return;
    }

    this.mentionItems = items;
    this.mentionActiveIdx = 0;
    this.mentionOpen = true;
    this.renderMentionMenu();
  }

  renderMentionMenu() {
    if (!this.mentionMenuEl) return;
    if (!this.mentionOpen || this.mentionItems.length === 0) {
      this.mentionMenuEl.hidden = true;
      return;
    }

    this.mentionMenuEl.hidden = false;
    this.mentionMenuEl.innerHTML = '';

    const header = document.createElement('div');
    header.className = 'qc-mention-head';
    header.textContent = '引用文档章节大纲、记忆文件与个性化软件 (↑/↓ 选择 · Enter 插入)';
    this.mentionMenuEl.appendChild(header);

    this.mentionItems.forEach((it, idx) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'qc-mention-item' + (idx === this.mentionActiveIdx ? ' active' : '');
      btn.innerHTML = `
        <span class="qc-mention-icon">${it.icon}</span>
        <span class="qc-mention-main">
          <strong>@${escapeHtml(it.tag)}</strong>
          <small>${escapeHtml(it.subtitle)}</small>
        </span>
      `;
      btn.onmouseenter = () => {
        this.mentionActiveIdx = idx;
        this.mentionMenuEl
          .querySelectorAll('.qc-mention-item')
          .forEach((el, i) => el.classList.toggle('active', i === idx));
      };
      btn.onclick = (e) => {
        e.preventDefault();
        this.confirmMentionSelection(idx);
      };
      this.mentionMenuEl.appendChild(btn);
    });
  }

  moveMentionSelection(delta) {
    if (!this.mentionOpen || this.mentionItems.length === 0) return false;
    const len = this.mentionItems.length;
    this.mentionActiveIdx = (this.mentionActiveIdx + delta + len) % len;
    this.renderMentionMenu();
    return true;
  }

  confirmMentionSelection(idx = this.mentionActiveIdx) {
    if (!this.mentionOpen || !this.mentionItems[idx] || !this.inputEl) return false;
    const item = this.mentionItems[idx];
    const val = this.inputEl.value;
    const range = this.mentionTriggerRange || { start: val.length, end: val.length };
    const replacement = `@${item.tag} `;
    this.inputEl.value = val.slice(0, range.start) + replacement + val.slice(range.end);
    const nextCaret = range.start + replacement.length;
    this.inputEl.focus();
    this.inputEl.setSelectionRange(nextCaret, nextCaret);
    this.closeMentionMenu();

    if (this.onInsertMention) {
      this.onInsertMention(item.tag, item.entity, true /* alreadyInsertedInInput */);
    }
    return true;
  }

  closeMentionMenu() {
    this.mentionOpen = false;
    this.mentionItems = [];
    if (this.mentionMenuEl) {
      this.mentionMenuEl.hidden = true;
    }
  }
}
