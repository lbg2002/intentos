/**
 * IntentOS · 随问 — GNOME Shell 46–50 Desktop-Floating Quick-Chat AIOS Extension (Wave 3).
 *
 * Mounts a sleek, draggable, single-dialog Floating Quick-Chat AIOS Window directly above
 * desktop windows via `Main.layoutManager.addTopChrome` (never inside DateMenu notification bar):
 * - Global Hotkeys:
 *     - `<Super><Shift>q` / `<Super><Shift>space`: Toggle floating chat dialog & focus input
 *     - `<Super><Shift>y`: Wake floating dialog & pre-attach primary selection / clipboard text
 * - Top-Panel Tiny Indicator: `✦` + colored status dot (`busy` blue / `pending` yellow / `unread` green)
 * - Single-Dialog Quick-Chat UI:
 *     - Draggable top handle + inline `▾` Backend (`自动 / ZCode / Codex / Pi / OpenAI API`),
 *       live `/v1/models` searchable & scrollable selector (`↻ 刷新`) & Reasoning Effort (`默认 / 快 / 标准 / 深入`)
 *     - Header Trust Shield (`🛡`) synced with `execution_hub.get_security_posture` (`严格 / 平衡 / 开发者`)
 *       + active Session Scope Grants management
 *     - `🧠` Personal Memory Hub (`mentioned_files`, `frequent_files`, `frequent_apps`) &
 *       Software Translation Layer (`app_adapter`) quick view (click any item to insert `@mention`)
 *     - Scrollable Markdown chat stream with `20px` horizontal colored `Trace Dots` (`●`, compact `+N`
 *       collapse when `> 6` dots) + `[↶ 撤销]`
 *     - Auto-expanded Inline Sensitive Approval Card (`🛡️ 敏感权限与安全执行审批`:
 *       `[✓ 批准本次]` `[⏱ 本会话放行此范围]` `[✕ 拒绝]`)
 *     - Multi-line input (`Enter` send, `Shift+Enter` newline, `Up/Down` history, `@` mention, `Esc` abort/hide)
 * - Strictly non-blocking async `Gio.UnixSocketAddress` I/O to `${XDG_RUNTIME_DIR}/intentos/ui.sock`.
 */

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Meta from 'gi://Meta';
import Pango from 'gi://Pango';
import Shell from 'gi://Shell';
import St from 'gi://St';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';

const SCHEMA_ID = 'org.gnome.shell.extensions.intentos';
const KEY_TOGGLE_CHAT = 'toggle-quick-chat';
const KEY_CLIPBOARD_ASK = 'clipboard-quick-ask';

const BACKEND_OPTIONS = [
    {id: 'auto', label: '自动'},
    {id: 'zcode', label: 'ZCode'},
    {id: 'codex', label: 'Codex'},
    {id: 'pi', label: 'Pi'},
    {id: 'openai', label: 'OpenAI'},
];

const EFFORT_OPTIONS = [
    {id: 'default', label: '默认'},
    {id: 'fast', label: '快'},
    {id: 'medium', label: '标准'},
    {id: 'high', label: '深入'},
];

const SECURITY_MODES = [
    {id: 'strict', short: '严格', label: '严格逐次审批'},
    {id: 'balanced', short: '平衡', label: '平衡受控防护'},
    {id: 'developer', short: '开发者', label: '信任目录免批'},
];

const STARTER_PROMPTS = [
    {label: '📂 我之前提到的和长期常用的文件有哪些？', prompt: '我之前说的文件和长期高频使用的文件有哪些？'},
    {label: '🧩 我电脑上装了哪些软件？常用的是什么？', prompt: '我电脑上装了哪些软件？最常用的软件是什么？'},
    {label: '🎵 用转译层查看或暂停当前音乐播放', prompt: '用软件转译层查看或暂停当前正在播放的音乐'},
    {label: '🌙 屏幕太亮了，调低一点并开启护眼模式', prompt: '屏幕太亮了，帮我把亮度调低一点并开启护眼模式'},
];

const TRACE_COLOR_MAP = {
    thinking: 'gray',
    gray: 'gray',
    memory: 'purple',
    purple: 'purple',
    adapter: 'cyan',
    cyan: 'cyan',
    tool_unverified: 'blue',
    requested_unverified: 'blue',
    unverified: 'blue',
    simulated: 'blue',
    blue: 'blue',
    sky: 'blue',
    approval: 'amber',
    amber: 'amber',
    yellow: 'amber',
    orange: 'amber',
    tool_ok: 'green',
    green: 'green',
    emerald: 'green',
    tool_err: 'red',
    error: 'red',
    red: 'red',
};

const FALLBACK_GSCHEMA_XML = `<?xml version="1.0" encoding="UTF-8"?>
<schemalist>
  <schema id="org.gnome.shell.extensions.intentos" path="/org/gnome/shell/extensions/intentos/">
    <key name="toggle-quick-chat" type="as">
      <default>['&lt;Super&gt;&lt;Shift&gt;q', '&lt;Super&gt;&lt;Shift&gt;space']</default>
    </key>
    <key name="clipboard-quick-ask" type="as">
      <default>['&lt;Super&gt;&lt;Shift&gt;y']</default>
    </key>
    <key name="dialog-x" type="i"><default>-1</default></key>
    <key name="dialog-y" type="i"><default>-1</default></key>
    <key name="pinned" type="b"><default>false</default></key>
    <key name="light-theme" type="b"><default>false</default></key>
  </schema>
</schemalist>
`;

export default class IntentOsQuickChatExtension extends Extension {
    enable() {
        this._visible = false;
        this._incognito = false;
        this._pinned = false;
        this._lightTheme = false;
        this._userThemeOverride = false;
        this._turnBusy = false;
        this._hasUnread = false;
        this._hasPendingApproval = false;
        this._activePendingApproval = null;
        this._activePendingCardCtx = null;
        this._activeTurnToken = 0;

        this._sessionId = `ses_${Date.now()}`;
        this._dialogPos = null; // {x, y}
        this._dragging = false;
        this._dragGrabSignal = 0;

        this._catalog = this._normalizeCatalog(null);
        this._selectedBackend = 'auto';
        this._selectedProvider = '';
        this._selectedModel = '';
        this._selectedEffort = 'default';
        this._modelSearchQuery = '';
        this._refreshingModels = false;

        this._securityMode = 'balanced';
        this._securityPosture = {};

        this._switcherOpen = false;
        this._securityOpen = false;
        this._memoryOpen = false;

        this._clipboardContext = '';
        this._inputHistory = [];
        this._historyCursor = -1;
        this._lastChangesetId = null;
        this._memoryDashboard = {};
        this._adaptersList = [];
        this._liveTrayApps = [];
        this._inspectAppQuery = '';
        this._lastInspectedApp = null;
        this._liveAdapterStatus = '';
        this._mentionHints = [];
        this._suppressTextChanged = false;
        this._keybindingsBound = false;
        this._settings = null;
        this._interfaceSettings = null;
        this._interfaceThemeSignal = 0;
        this._speechOverview = null;
        this._voiceRecording = false;
        this._voiceTranscribing = false;
        this._voiceTimerId = 0;
        this._voiceStartSec = 0;
        this._deepScanSummary = null;
        this._compressionPreview = null;
        this._defaultHintText = '随问 AIOS… (Enter 发送 · Shift+Enter 换行 · @ 引用文件/软件)';

        this._initSettingsAndHotkeys();
        this._buildPanelIndicator();
        this._buildFloatingDialog();

        // Warm catalog (/v1/models), security posture, ASR speech overview & personal memory hints asynchronously
        this._refreshCatalogAsync(true);
        this._refreshSecurityPostureAsync(false);
        this._refreshSpeechOverviewAsync();
        this._refreshMemoryAsync(false);
    }

    disable() {
        this._stopDrag();
        this._unbindHotkeys();
        this._activeTurnToken += 1;
        this._turnBusy = false;

        if (this._voiceTimerId) {
            try {
                GLib.source_remove(this._voiceTimerId);
            } catch (_e) {}
            this._voiceTimerId = 0;
        }
        this._voiceRecording = false;
        this._voiceTranscribing = false;

        if (this._interfaceSettings && this._interfaceThemeSignal) {
            try {
                this._interfaceSettings.disconnect(this._interfaceThemeSignal);
            } catch (_e) {}
            this._interfaceThemeSignal = 0;
            this._interfaceSettings = null;
        }

        if (this._dialog) {
            Main.layoutManager.removeChrome(this._dialog);
            this._dialog.destroy();
            this._dialog = null;
        }
        if (this._indicator) {
            this._indicator.destroy();
            this._indicator = null;
        }
        this._settings = null;
    }

    _socketPath() {
        const baseDir = GLib.getenv('INTENTOS_BASE_DIR');
        if (baseDir)
            return `${baseDir}/run/ui.sock`;
        const runtimeDir = GLib.getenv('XDG_RUNTIME_DIR') || `/run/user/${GLib.getuid?.() ?? 1000}`;
        return `${runtimeDir}/intentos/ui.sock`;
    }

    _detectSystemLightTheme() {
        try {
            if (!this._interfaceSettings)
                this._interfaceSettings = new Gio.Settings({schema_id: 'org.gnome.desktop.interface'});
            const scheme = String(this._interfaceSettings.get_string('color-scheme') || '').toLowerCase();
            return !scheme.includes('prefer-dark');
        } catch (_e) {
            return false;
        }
    }

    _applyDialogThemeClass() {
        if (!this._dialog)
            return;
        this._dialog.set_style_class_name(
            this._lightTheme
                ? 'intentos-floating-dialog intentos-floating-dialog-light'
                : 'intentos-floating-dialog'
        );
    }

    // ------------------------------------------------------------------
    // GSettings, System Theme Sync & Global Hotkeys (`Super+Shift+Q` & `Super+Shift+Y`)
    // ------------------------------------------------------------------
    _initSettingsAndHotkeys() {
        try {
            this._settings = this.getSettings(SCHEMA_ID);
        } catch (_err) {
            this._settings = this._loadRuntimeFallbackSettings();
        }

        const systemLight = this._detectSystemLightTheme();
        this._lightTheme = systemLight;

        if (this._interfaceSettings) {
            try {
                this._interfaceThemeSignal = this._interfaceSettings.connect('changed::color-scheme', () => {
                    if (!this._userThemeOverride) {
                        this._lightTheme = this._detectSystemLightTheme();
                        this._applyDialogThemeClass();
                    }
                });
            } catch (_e) {}
        }

        if (this._settings) {
            try {
                const sx = this._settings.get_int('dialog-x');
                const sy = this._settings.get_int('dialog-y');
                if (sx >= 0 && sy >= 0)
                    this._dialogPos = {x: sx, y: sy};
                this._pinned = this._settings.get_boolean('pinned');
                const userThemeVal = this._settings.get_user_value?.('light-theme');
                if (userThemeVal !== null && userThemeVal !== undefined) {
                    this._userThemeOverride = true;
                    this._lightTheme = this._settings.get_boolean('light-theme');
                }
            } catch (_e) {
                // Ignore optional preference read errors
            }

            try {
                Main.wm.addKeybinding(
                    KEY_TOGGLE_CHAT,
                    this._settings,
                    Meta.KeyBindingFlags.NONE,
                    Shell.ActionMode.NORMAL | Shell.ActionMode.OVERVIEW,
                    () => this.toggleDialog()
                );
                Main.wm.addKeybinding(
                    KEY_CLIPBOARD_ASK,
                    this._settings,
                    Meta.KeyBindingFlags.NONE,
                    Shell.ActionMode.NORMAL | Shell.ActionMode.OVERVIEW,
                    () => this.summonWithClipboard()
                );
                this._keybindingsBound = true;
            } catch (_bindErr) {
                this._keybindingsBound = false;
            }
        }
    }

    _loadRuntimeFallbackSettings() {
        try {
            const rtDir = `${GLib.get_user_runtime_dir()}/intentos/gschemas`;
            GLib.mkdir_with_parents(rtDir, 0o700);
            const xmlPath = `${rtDir}/${SCHEMA_ID}.gschema.xml`;
            const compiledPath = `${rtDir}/gschemas.compiled`;
            if (!GLib.file_test(compiledPath, GLib.FileTest.EXISTS)) {
                GLib.file_set_contents(xmlPath, FALLBACK_GSCHEMA_XML);
                const proc = Gio.Subprocess.new(
                    ['glib-compile-schemas', rtDir],
                    Gio.SubprocessFlags.STDOUT_SILENCE | Gio.SubprocessFlags.STDERR_SILENCE
                );
                proc.wait(null);
            }
            const source = Gio.SettingsSchemaSource.new_from_directory(
                rtDir,
                Gio.SettingsSchemaSource.get_default(),
                false
            );
            const schema = source.lookup(SCHEMA_ID, false);
            if (schema)
                return new Gio.Settings({settings_schema: schema});
        } catch (_e) {
            // Schema compilation unavailable; panel click still works
        }
        return null;
    }

    _unbindHotkeys() {
        if (!this._keybindingsBound)
            return;
        try {
            Main.wm.removeKeybinding(KEY_TOGGLE_CHAT);
        } catch (_e) {}
        try {
            Main.wm.removeKeybinding(KEY_CLIPBOARD_ASK);
        } catch (_e) {}
        this._keybindingsBound = false;
    }

    // ------------------------------------------------------------------
    // Top-Panel Tiny Indicator (`✦` + busy/pending/unread dot)
    // ------------------------------------------------------------------
    _buildPanelIndicator() {
        this._indicator = new PanelMenu.Button(0.0, 'IntentOS Quick Chat', false);

        const panelBox = new St.BoxLayout({
            style_class: 'intentos-panel-box',
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._panelStar = new St.Label({
            style_class: 'intentos-panel-star',
            text: '✦',
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._panelDot = new St.Label({
            style_class: 'intentos-panel-dot-idle',
            text: '●',
            y_align: Clutter.ActorAlign.CENTER,
        });
        panelBox.add_child(this._panelStar);
        panelBox.add_child(this._panelDot);
        this._indicator.add_child(panelBox);

        // Left-click directly toggles the floating desktop chat window; right-click opens menu
        this._indicator.connect('button-press-event', (_actor, event) => {
            const btn = event.get_button();
            if (btn === 1) {
                this._indicator.menu.close();
                this.toggleDialog();
                return Clutter.EVENT_STOP;
            }
            return Clutter.EVENT_PROPAGATE;
        });

        const toggleItem = new PopupMenu.PopupMenuItem('✦ 呼出/收起随问悬浮窗 (Super+Shift+Q)');
        toggleItem.connect('activate', () => this.toggleDialog());
        this._indicator.menu.addMenuItem(toggleItem);

        const clipItem = new PopupMenu.PopupMenuItem('📋 选区/剪贴板随问 (Super+Shift+Y)');
        clipItem.connect('activate', () => this.summonWithClipboard());
        this._indicator.menu.addMenuItem(clipItem);

        const newItem = new PopupMenu.PopupMenuItem('+ 新建对话会话 (Ctrl+N)');
        newItem.connect('activate', () => {
            this._showDialog();
            this._startNewSession();
        });
        this._indicator.menu.addMenuItem(newItem);

        this._indicator.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._privSwitchItem = new PopupMenu.PopupSwitchMenuItem('🔒 隐私无痕会话', false);
        this._privSwitchItem.connect('toggled', (_item, state) => {
            this._setIncognito(state);
        });
        this._indicator.menu.addMenuItem(this._privSwitchItem);

        const undoItem = new PopupMenu.PopupMenuItem('↶ 撤销最近一次系统变更 (Ctrl+Z)');
        undoItem.connect('activate', () => this._triggerUndo(this._lastChangesetId));
        this._indicator.menu.addMenuItem(undoItem);

        const settingsItem = new PopupMenu.PopupMenuItem('⚙ 打开 11 页设置中心 (intentos-settings)');
        settingsItem.connect('activate', () => this._launchSettingsCenter());
        this._indicator.menu.addMenuItem(settingsItem);

        const stopItem = new PopupMenu.PopupMenuItem('■ 紧急停止全部会话');
        stopItem.connect('activate', () => this._abortActiveTurn());
        this._indicator.menu.addMenuItem(stopItem);

        Main.panel.addToStatusArea(this.uuid, this._indicator);
        this._refreshPanelDot();
    }

    _refreshPanelDot() {
        if (!this._panelDot)
            return;
        if (this._turnBusy) {
            this._panelDot.set_style_class_name('intentos-panel-dot-busy');
        } else if (this._hasPendingApproval) {
            this._panelDot.set_style_class_name('intentos-panel-dot-pending');
        } else if (this._hasUnread) {
            this._panelDot.set_style_class_name('intentos-panel-dot-unread');
        } else {
            this._panelDot.set_style_class_name('intentos-panel-dot-idle');
        }
    }

    _launchSettingsCenter(page = '', appQuery = '') {
        let extra = '';
        if (page)
            extra += ` --page ${GLib.shell_quote(String(page))}`;
        if (appQuery)
            extra += ` --inspect-app ${GLib.shell_quote(String(appQuery))}`;
        try {
            GLib.spawn_command_line_async(`intentos-settings${extra}`);
        } catch (_e) {
            try {
                GLib.spawn_command_line_async(`python3 desktop/settings/intentos-settings.py${extra}`);
            } catch (_err) {}
        }
    }

    // ------------------------------------------------------------------
    // Desktop-Floating Single Chat Dialog (`Main.layoutManager.addTopChrome`)
    // ------------------------------------------------------------------
    _buildFloatingDialog() {
        this._dialog = new St.BoxLayout({
            style_class: this._lightTheme
                ? 'intentos-floating-dialog intentos-floating-dialog-light'
                : 'intentos-floating-dialog',
            vertical: true,
            reactive: true,
            visible: false,
        });

        // 1. Draggable Top Header Bar
        this._headerBar = new St.BoxLayout({
            style_class: 'intentos-top-header',
            vertical: false,
            reactive: true,
        });

        const brandLbl = new St.Label({
            style_class: 'intentos-brand-title',
            text: '✦ IntentOS',
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._headerBar.add_child(brandLbl);

        this._modelPillBtn = new St.Button({
            style_class: 'intentos-model-pill',
            label: '自动 · 默认 ▾',
            reactive: true,
            can_focus: false,
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._modelPillBtn.connect('clicked', () => this._toggleSwitcherStrip());
        this._headerBar.add_child(this._modelPillBtn);

        this._shieldBtn = new St.Button({
            style_class: 'intentos-shield-btn',
            label: '🛡 平衡',
            reactive: true,
            can_focus: false,
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._shieldBtn.connect('clicked', () => this._toggleSecurityStrip());
        this._headerBar.add_child(this._shieldBtn);

        const headerSpacer = new St.Widget({x_expand: true});
        this._headerBar.add_child(headerSpacer);

        const clipBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '📋',
            reactive: true,
            can_focus: false,
        });
        clipBtn.connect('clicked', () => this._captureClipboardContext());
        this._headerBar.add_child(clipBtn);

        this._memBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '🧠',
            reactive: true,
            can_focus: false,
        });
        this._memBtn.connect('clicked', () => this._toggleMemoryStrip());
        this._headerBar.add_child(this._memBtn);

        this._incogBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '🔒',
            reactive: true,
            can_focus: false,
        });
        this._incogBtn.connect('clicked', () => this._setIncognito(!this._incognito));
        this._headerBar.add_child(this._incogBtn);

        const newBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '+',
            reactive: true,
            can_focus: false,
        });
        newBtn.connect('clicked', () => this._startNewSession());
        this._headerBar.add_child(newBtn);

        this._pinBtn = new St.Button({
            style_class: this._pinned ? 'intentos-icon-btn intentos-icon-btn-active' : 'intentos-icon-btn',
            label: '📌',
            reactive: true,
            can_focus: false,
        });
        this._pinBtn.connect('clicked', () => {
            this._pinned = !this._pinned;
            this._pinBtn.set_style_class_name(
                this._pinned ? 'intentos-icon-btn intentos-icon-btn-active' : 'intentos-icon-btn'
            );
            try {
                this._settings?.set_boolean('pinned', this._pinned);
            } catch (_e) {}
        });
        this._headerBar.add_child(this._pinBtn);

        const themeBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '◑',
            reactive: true,
            can_focus: false,
        });
        themeBtn.connect('clicked', () => {
            this._userThemeOverride = true;
            this._lightTheme = !this._lightTheme;
            this._applyDialogThemeClass();
            try {
                this._settings?.set_boolean('light-theme', this._lightTheme);
            } catch (_e) {}
        });
        this._headerBar.add_child(themeBtn);

        const cfgBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '⚙',
            reactive: true,
            can_focus: false,
        });
        cfgBtn.connect('clicked', () => this._launchSettingsCenter());
        this._headerBar.add_child(cfgBtn);

        const closeBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '✕',
            reactive: true,
            can_focus: false,
        });
        closeBtn.connect('clicked', () => this._hideDialog());
        this._headerBar.add_child(closeBtn);

        // Drag window by grabbing header bar background
        this._headerBar.connect('button-press-event', (_actor, event) => {
            if (event.get_button() !== 1)
                return Clutter.EVENT_PROPAGATE;
            const src = event.get_source();
            if (src instanceof St.Button || src instanceof St.Entry)
                return Clutter.EVENT_PROPAGATE;
            const [px, py] = event.get_coords();
            this._startDrag(px, py);
            return Clutter.EVENT_STOP;
        });

        this._dialog.add_child(this._headerBar);

        // 2. Inline Collapsible Backend/Model/Effort Switcher Strip (`▾`)
        this._switcherStrip = new St.BoxLayout({
            style_class: 'intentos-drawer-strip',
            vertical: true,
            visible: false,
        });
        this._dialog.add_child(this._switcherStrip);

        // 3. Inline Collapsible Security Posture & Session Grants Strip (`🛡`)
        this._securityStrip = new St.BoxLayout({
            style_class: 'intentos-drawer-strip',
            vertical: true,
            visible: false,
        });
        this._dialog.add_child(this._securityStrip);

        // 4. Inline Collapsible Personal Memory & Adapter Strip (`🧠`)
        this._memoryStrip = new St.BoxLayout({
            style_class: 'intentos-drawer-strip',
            vertical: true,
            visible: false,
        });
        this._dialog.add_child(this._memoryStrip);

        // 5. Scrollable Chat Message Stream
        this._chatScroll = new St.ScrollView({
            style_class: 'intentos-chat-scroll',
            hscrollbar_policy: St.PolicyType.NEVER,
            vscrollbar_policy: St.PolicyType.AUTOMATIC,
            overlay_scrollbars: true,
        });
        this._chatList = new St.BoxLayout({
            style_class: 'intentos-chat-list',
            vertical: true,
            x_expand: true,
        });
        if (typeof this._chatScroll.set_child === 'function')
            this._chatScroll.set_child(this._chatList);
        else
            this._chatScroll.add_actor(this._chatList);
        this._dialog.add_child(this._chatScroll);

        this._renderWelcomeView();

        // 6. Bottom Context Chips + Multi-Line Chat Input
        const bottomBox = new St.BoxLayout({
            style_class: 'intentos-bottom-box',
            vertical: true,
        });

        this._mentionStrip = new St.BoxLayout({
            style_class: 'intentos-mention-strip',
            vertical: false,
            visible: false,
        });
        bottomBox.add_child(this._mentionStrip);

        this._clipStrip = new St.BoxLayout({
            style_class: 'intentos-context-chip',
            vertical: false,
            visible: false,
        });
        this._clipLabel = new St.Label({
            text: '',
            x_expand: true,
            y_align: Clutter.ActorAlign.CENTER,
        });
        const clipClearBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '✕',
            reactive: true,
        });
        clipClearBtn.connect('clicked', () => this._setClipboardContext(''));
        this._clipStrip.add_child(this._clipLabel);
        this._clipStrip.add_child(clipClearBtn);
        bottomBox.add_child(this._clipStrip);

        this._voiceBanner = new St.BoxLayout({
            style_class: 'intentos-voice-banner',
            vertical: true,
            visible: false,
        });
        bottomBox.add_child(this._voiceBanner);

        const inputShell = new St.BoxLayout({
            style_class: 'intentos-input-shell',
            vertical: false,
        });
        this._inputEntry = new St.Entry({
            style_class: 'intentos-chat-entry',
            hint_text: this._defaultHintText,
            can_focus: true,
            x_expand: true,
        });

        const ct = this._inputEntry.clutter_text;
        ct.set_single_line_mode(false);
        ct.set_line_wrap(true);
        ct.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR);
        ct.set_activatable(false);

        ct.connect('text-changed', () => {
            if (this._suppressTextChanged)
                return;
            this._historyCursor = -1;
            this._updateMentionStrip(this._inputEntry.get_text());
        });
        ct.connect('key-press-event', (_actor, event) => this._onInputKeyPress(event));

        this._micBtn = new St.Button({
            style_class: 'intentos-mic-btn',
            label: '🎙',
            reactive: true,
            can_focus: false,
            y_align: Clutter.ActorAlign.END,
        });
        this._micBtn.connect('clicked', () => this._onMicButtonClicked());

        this._sendBtn = new St.Button({
            style_class: 'intentos-send-btn',
            label: '➤',
            reactive: true,
            can_focus: false,
            y_align: Clutter.ActorAlign.END,
        });
        this._sendBtn.connect('clicked', () => {
            if (this._turnBusy)
                this._abortActiveTurn();
            else
                this._submitFromEntry();
        });

        inputShell.add_child(this._inputEntry);
        inputShell.add_child(this._micBtn);
        inputShell.add_child(this._sendBtn);
        bottomBox.add_child(inputShell);

        this._dialog.add_child(bottomBox);

        Main.layoutManager.addTopChrome(this._dialog, {
            affectInputRegion: true,
            trackFullscreen: true,
        });
        this._updateModelPillLabel();
        this._updateShieldLabel();
    }

    // ------------------------------------------------------------------
    // Dragging & Positioning Above Desktop Windows
    // ------------------------------------------------------------------
    _startDrag(startX, startY) {
        this._stopDrag();
        this._dragging = true;
        const [origX, origY] = this._dialog.get_position();
        this._dragOffset = {dx: startX - origX, dy: startY - origY};

        this._dragGrabSignal = global.stage.connect('captured-event', (_stage, event) => {
            const type = event.type();
            if (type === Clutter.EventType.MOTION) {
                const [mx, my] = event.get_coords();
                const nx = Math.round(mx - this._dragOffset.dx);
                const ny = Math.round(my - this._dragOffset.dy);
                this._dialog.set_position(nx, ny);
                this._dialogPos = {x: nx, y: ny};
                return Clutter.EVENT_STOP;
            }
            if (type === Clutter.EventType.BUTTON_RELEASE) {
                this._stopDrag();
                if (this._dialogPos) {
                    try {
                        this._settings?.set_int('dialog-x', this._dialogPos.x);
                        this._settings?.set_int('dialog-y', this._dialogPos.y);
                    } catch (_e) {}
                }
                return Clutter.EVENT_STOP;
            }
            return Clutter.EVENT_PROPAGATE;
        });
    }

    _stopDrag() {
        if (this._dragGrabSignal) {
            global.stage.disconnect(this._dragGrabSignal);
            this._dragGrabSignal = 0;
        }
        this._dragging = false;
    }

    toggleDialog() {
        if (this._visible)
            this._hideDialog();
        else
            this._showDialog();
    }

    summonWithClipboard() {
        this._showDialog();
        this._captureClipboardContext();
    }

    _showDialog() {
        if (!this._dialog)
            return;
        const monitor = Main.layoutManager.primaryMonitor;
        if (!this._dialogPos && monitor) {
            const x = Math.floor(monitor.x + (monitor.width - 492) / 2);
            const y = Math.floor(monitor.y + Math.max(48, monitor.height * 0.14));
            this._dialogPos = {x, y};
        }
        if (this._dialogPos)
            this._dialog.set_position(this._dialogPos.x, this._dialogPos.y);
        this._dialog.show();
        this._visible = true;
        this._hasUnread = false;
        this._refreshPanelDot();
        this._refreshSecurityPostureAsync(false);
        this._refreshSpeechOverviewAsync();
        global.stage.set_key_focus(this._inputEntry.clutter_text);
    }

    _hideDialog() {
        if (!this._dialog)
            return;
        this._stopDrag();
        this._switcherOpen = false;
        this._securityOpen = false;
        this._memoryOpen = false;
        this._switcherStrip?.hide();
        this._securityStrip?.hide();
        this._memoryStrip?.hide();
        this._mentionStrip?.hide();
        this._updateModelPillLabel();
        this._updateShieldLabel();
        this._memBtn?.set_style_class_name('intentos-icon-btn');
        this._dialog.hide();
        this._visible = false;
    }

    _setIncognito(enabled) {
        this._incognito = Boolean(enabled);
        if (this._incogBtn) {
            this._incogBtn.set_style_class_name(
                this._incognito ? 'intentos-icon-btn intentos-icon-btn-active' : 'intentos-icon-btn'
            );
        }
        if (this._privSwitchItem && this._privSwitchItem.state !== this._incognito)
            this._privSwitchItem.setToggleState(this._incognito);
    }

    // ------------------------------------------------------------------
    // Inline Switcher Strip (`▾`) — Live `/v1/models` Search & Scroll
    // ------------------------------------------------------------------
    _normalizeCatalog(raw) {
        const data = raw && typeof raw === 'object' ? raw : {};
        const act = data.active && typeof data.active === 'object' ? data.active : {};
        const active = {
            backend: String(act.backend || data.active_backend || 'auto').toLowerCase(),
            provider: String(act.provider || data.active_provider || ''),
            model: String(act.model || data.active_model || ''),
            reasoning_effort: String(act.reasoning_effort || data.reasoning_effort || 'default').toLowerCase(),
        };

        const rawBackends = data.backends;
        const map = {};
        if (Array.isArray(rawBackends)) {
            for (const b of rawBackends) {
                if (b && typeof b === 'object') {
                    const bid = String(b.id || b.backend || b.name || '').toLowerCase();
                    if (bid)
                        map[bid] = b;
                }
            }
        } else if (rawBackends && typeof rawBackends === 'object') {
            for (const [k, v] of Object.entries(rawBackends)) {
                if (v && typeof v === 'object')
                    map[k.toLowerCase()] = v;
            }
        }

        const backends = {};
        for (const opt of BACKEND_OPTIONS) {
            const b = map[opt.id] || {};
            const available = Boolean(b.available ?? b.installed ?? b.detected ?? (opt.id === 'auto' || opt.id === 'openai'));
            const models = [];
            const seen = new Set();
            const pushModel = (prov, mod) => {
                const mStr = String(mod || '').trim();
                const pStr = String(prov || '').trim();
                if (!mStr)
                    return;
                const key = `${pStr}::${mStr}`;
                if (seen.has(key))
                    return;
                seen.add(key);
                models.push({provider: pStr, model: mStr});
            };

            if (Array.isArray(b.providers)) {
                for (const p of b.providers) {
                    const pid = String(p?.id || p?.provider || p?.name || '');
                    if (p?.default_model)
                        pushModel(pid, p.default_model);
                    const mlist = p?.models || p?.available_models || [];
                    for (const m of mlist) {
                        const mid = typeof m === 'object' ? String(m?.id || m?.name || '') : String(m || '');
                        pushModel(pid, mid);
                    }
                }
            } else if (b.providers && typeof b.providers === 'object') {
                for (const [pid, p] of Object.entries(b.providers)) {
                    if (p?.default_model)
                        pushModel(pid, p.default_model);
                    const mlist = p?.models || p?.available_models || [];
                    for (const m of mlist) {
                        const mid = typeof m === 'object' ? String(m?.id || m?.name || '') : String(m || '');
                        pushModel(pid, mid);
                    }
                }
            }
            const flatModels = b.models || b.available_models || [];
            if (Array.isArray(flatModels)) {
                const defProv = String(b.default_provider || b.provider || '');
                for (const m of flatModels) {
                    const mid = typeof m === 'object' ? String(m?.id || m?.name || '') : String(m || '');
                    pushModel(defProv, mid);
                }
            }
            backends[opt.id] = {
                id: opt.id,
                label: opt.label,
                available,
                models,
                defaultProvider: String(b.default_provider || models[0]?.provider || ''),
                defaultModel: String(b.default_model || models[0]?.model || ''),
                baseUrl: String(b.base_url || ''),
            };
        }

        // Populate `auto` with aggregated live models across available backends
        if (backends.auto && backends.auto.models.length === 0) {
            const autoSeen = new Set();
            for (const bid of ['zcode', 'codex', 'pi', 'openai']) {
                const bInfo = backends[bid];
                if (!bInfo)
                    continue;
                for (const item of bInfo.models) {
                    const key = `${item.provider}::${item.model}`;
                    if (!autoSeen.has(key)) {
                        autoSeen.add(key);
                        backends.auto.models.push(item);
                    }
                }
            }
        }

        return {active, backends};
    }

    _updateModelPillLabel() {
        if (!this._modelPillBtn)
            return;
        const bLabel = BACKEND_OPTIONS.find(x => x.id === this._selectedBackend)?.label || this._selectedBackend;
        const eLabel = EFFORT_OPTIONS.find(x => x.id === this._selectedEffort)?.label || '默认';
        if (this._selectedModel) {
            const shortM = this._selectedModel.length <= 16
                ? this._selectedModel
                : `${this._selectedModel.slice(0, 14)}…`;
            this._modelPillBtn.set_label(`${bLabel} · ${shortM} ▾`);
        } else {
            this._modelPillBtn.set_label(`${bLabel} · ${eLabel} ▾`);
        }
        this._modelPillBtn.set_style_class_name(
            this._switcherOpen ? 'intentos-model-pill intentos-model-pill-active' : 'intentos-model-pill'
        );
    }

    _toggleSwitcherStrip() {
        this._switcherOpen = !this._switcherOpen;
        if (this._switcherOpen) {
            this._securityOpen = false;
            this._memoryOpen = false;
            this._securityStrip?.hide();
            this._memoryStrip?.hide();
            this._updateShieldLabel();
            this._memBtn?.set_style_class_name('intentos-icon-btn');
            this._renderSwitcherStrip();
            this._switcherStrip.show();
            this._refreshCatalogAsync(true);
        } else {
            this._switcherStrip.hide();
        }
        this._updateModelPillLabel();
    }

    _renderSwitcherStrip() {
        if (!this._switcherStrip)
            return;
        this._switcherStrip.destroy_all_children();

        // 1. Engine row + Live `/v1/models` Refresh button
        const engRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
        engRow.add_child(new St.Label({
            style_class: 'intentos-strip-label',
            text: '引擎:',
            y_align: Clutter.ActorAlign.CENTER,
        }));
        for (const opt of BACKEND_OPTIONS) {
            const bInfo = this._catalog.backends[opt.id] || {};
            const mark = bInfo.available && opt.id !== 'auto' && opt.id !== 'openai' ? ' ·' : '';
            const btn = new St.Button({
                style_class: opt.id === this._selectedBackend
                    ? 'intentos-seg-btn intentos-seg-btn-active'
                    : 'intentos-seg-btn',
                label: `${opt.label}${mark}`,
                reactive: true,
            });
            btn.connect('clicked', () => {
                this._selectedBackend = opt.id;
                if (bInfo.defaultProvider)
                    this._selectedProvider = bInfo.defaultProvider;
                if (bInfo.defaultModel)
                    this._selectedModel = bInfo.defaultModel;
                this._saveActiveBackend();
                this._renderSwitcherStrip();
            });
            engRow.add_child(btn);
        }
        engRow.add_child(new St.Widget({x_expand: true}));

        const refreshBtn = new St.Button({
            style_class: 'intentos-seg-btn',
            label: this._refreshingModels ? '刷新中…' : '↻ 刷新',
            reactive: !this._refreshingModels,
        });
        refreshBtn.connect('clicked', () => {
            this._refreshLiveModelsAsync();
        });
        engRow.add_child(refreshBtn);
        this._switcherStrip.add_child(engRow);

        // 2. Search Entry + Scrollable Live `/v1/models` Chips Container
        const curB = this._catalog.backends[this._selectedBackend] || {};
        const allModels = Array.isArray(curB.models) ? curB.models : [];

        const searchRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
        const searchEntry = new St.Entry({
            style_class: 'intentos-compact-entry',
            hint_text: `搜索模型 (共 ${allModels.length} 个 /v1/models)…`,
            text: this._modelSearchQuery || '',
            can_focus: true,
            x_expand: true,
        });
        searchRow.add_child(searchEntry);
        this._switcherStrip.add_child(searchRow);

        const modelScroll = new St.ScrollView({
            style_class: 'intentos-model-scroll',
            hscrollbar_policy: St.PolicyType.NEVER,
            vscrollbar_policy: St.PolicyType.AUTOMATIC,
            overlay_scrollbars: true,
        });
        const chipsBox = new St.BoxLayout({
            style_class: 'intentos-model-chips-box',
            vertical: true,
            x_expand: true,
        });
        if (typeof modelScroll.set_child === 'function')
            modelScroll.set_child(chipsBox);
        else
            modelScroll.add_actor(chipsBox);
        this._switcherStrip.add_child(modelScroll);

        const renderFilteredChips = queryText => {
            chipsBox.destroy_all_children();
            const q = String(queryText || '').trim().toLowerCase();
            const filtered = q
                ? allModels.filter(x =>
                    x.model.toLowerCase().includes(q) || x.provider.toLowerCase().includes(q)
                )
                : allModels;

            if (filtered.length === 0) {
                chipsBox.add_child(new St.Label({
                    style_class: 'intentos-meta-footer',
                    text: allModels.length === 0
                        ? '暂未探测到模型列表，可点击右上角「↻ 刷新」或在下方直接输入模型 ID'
                        : `未找到匹配 "${queryText}" 的模型`,
                }));
                return;
            }

            let row = null;
            filtered.forEach((item, idx) => {
                if (idx % 3 === 0) {
                    row = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
                    chipsBox.add_child(row);
                }
                const shortM = item.model.length <= 20 ? item.model : `${item.model.slice(0, 18)}…`;
                const labelTxt = item.provider ? `${shortM}` : shortM;
                const mBtn = new St.Button({
                    style_class: item.model === this._selectedModel
                        ? 'intentos-seg-btn intentos-seg-btn-active'
                        : 'intentos-seg-btn',
                    label: labelTxt,
                    reactive: true,
                });
                mBtn.connect('clicked', () => {
                    if (item.provider)
                        this._selectedProvider = item.provider;
                    this._selectedModel = item.model;
                    this._saveActiveBackend();
                    this._renderSwitcherStrip();
                });
                row.add_child(mBtn);
            });
        };

        renderFilteredChips(this._modelSearchQuery);
        searchEntry.clutter_text.connect('text-changed', () => {
            this._modelSearchQuery = searchEntry.get_text();
            renderFilteredChips(this._modelSearchQuery);
        });

        // 3. Custom model override entry row
        const customRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
        const modelEntry = new St.Entry({
            style_class: 'intentos-compact-entry',
            hint_text: '手动指定模型 ID (如 gpt-5.4 / glm-4.7)',
            text: this._selectedModel,
            can_focus: true,
            x_expand: true,
        });
        const applyBtn = new St.Button({
            style_class: 'intentos-seg-btn intentos-seg-btn-active',
            label: '✓ 设为活动模型',
            reactive: true,
        });
        applyBtn.connect('clicked', () => {
            this._selectedModel = modelEntry.get_text().trim();
            this._saveActiveBackend(
                this._openAiUrlEntry?.get_text()?.trim(),
                this._openAiKeyEntry?.get_text()?.trim()
            );
            this._renderSwitcherStrip();
        });
        customRow.add_child(modelEntry);
        customRow.add_child(applyBtn);
        this._switcherStrip.add_child(customRow);

        // Optional OpenAI Base URL + API Key quick inputs
        if (this._selectedBackend === 'openai') {
            const apiRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
            this._openAiUrlEntry = new St.Entry({
                style_class: 'intentos-compact-entry',
                hint_text: 'Base URL (https://.../v1)',
                text: curB.baseUrl || '',
                can_focus: true,
                x_expand: true,
            });
            this._openAiKeyEntry = new St.Entry({
                style_class: 'intentos-compact-entry',
                hint_text: 'API Key (安全存储)',
                can_focus: true,
                x_expand: true,
            });
            this._openAiKeyEntry.clutter_text.set_password_char('•');
            apiRow.add_child(this._openAiUrlEntry);
            apiRow.add_child(this._openAiKeyEntry);
            this._switcherStrip.add_child(apiRow);
        }

        // 4. Reasoning effort row (`默认 / 快 / 标准 / 深入`)
        const effRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
        effRow.add_child(new St.Label({
            style_class: 'intentos-strip-label',
            text: '思考:',
            y_align: Clutter.ActorAlign.CENTER,
        }));
        for (const ef of EFFORT_OPTIONS) {
            const eBtn = new St.Button({
                style_class: ef.id === this._selectedEffort
                    ? 'intentos-seg-btn intentos-seg-btn-active'
                    : 'intentos-seg-btn',
                label: ef.label,
                reactive: true,
            });
            eBtn.connect('clicked', () => {
                this._selectedEffort = ef.id;
                this._saveActiveBackend();
                this._renderSwitcherStrip();
            });
            effRow.add_child(eBtn);
        }
        this._switcherStrip.add_child(effRow);
    }

    async _refreshCatalogAsync(refreshRemote = true) {
        try {
            const raw = await this._moduleRpc('backend_bridge', 'get_backends_catalog', {
                refresh_remote: Boolean(refreshRemote),
            });
            this._applyNormalizedCatalog(raw);
        } catch (_e) {
            // Keep clean local defaults when daemon is warming up
        }
    }

    async _refreshLiveModelsAsync() {
        if (this._refreshingModels)
            return;
        this._refreshingModels = true;
        if (this._switcherOpen)
            this._renderSwitcherStrip();
        try {
            const payload = {force_refresh: true};
            if (this._selectedBackend && this._selectedBackend !== 'auto')
                payload.backend = this._selectedBackend;
            let raw = null;
            try {
                raw = await this._moduleRpc('backend_bridge', 'refresh_models', payload);
            } catch (_innerErr) {
                raw = await this._moduleRpc('backend_bridge', 'get_backends_catalog', {refresh_remote: true});
            }
            if (raw && raw.backends) {
                this._applyNormalizedCatalog(raw);
            } else {
                const cat = await this._moduleRpc('backend_bridge', 'get_backends_catalog', {refresh_remote: true});
                this._applyNormalizedCatalog(cat);
            }
        } catch (_e) {
            // Ignore transient refresh failure
        } finally {
            this._refreshingModels = false;
            if (this._switcherOpen)
                this._renderSwitcherStrip();
        }
    }

    _applyNormalizedCatalog(raw) {
        this._catalog = this._normalizeCatalog(raw);
        const act = this._catalog.active;
        if (act.backend)
            this._selectedBackend = act.backend;
        if (act.provider)
            this._selectedProvider = act.provider;
        if (act.model)
            this._selectedModel = act.model;
        if (EFFORT_OPTIONS.some(x => x.id === act.reasoning_effort))
            this._selectedEffort = act.reasoning_effort;
        this._updateModelPillLabel();
        if (this._switcherOpen)
            this._renderSwitcherStrip();
    }

    async _saveActiveBackend(baseUrl = '', apiKey = '') {
        this._updateModelPillLabel();
        const payload = {
            backend: this._selectedBackend,
            provider: this._selectedProvider,
            model: this._selectedModel,
            reasoning_effort: this._selectedEffort,
        };
        if (baseUrl)
            payload.base_url = baseUrl;
        if (apiKey)
            payload.api_key = apiKey;
        try {
            await this._moduleRpc('backend_bridge', 'set_active_backend', payload);
        } catch (_e) {}
    }

    // ------------------------------------------------------------------
    // Header Trust Shield (`🛡`) & Collapsible Security Strip
    // ------------------------------------------------------------------
    _updateShieldLabel() {
        if (!this._shieldBtn)
            return;
        const mInfo = SECURITY_MODES.find(m => m.id === this._securityMode) || SECURITY_MODES[1];
        this._shieldBtn.set_label(`🛡 ${mInfo.short}`);
        const classes = ['intentos-shield-btn'];
        if (this._securityMode === 'strict')
            classes.push('intentos-shield-btn-strict');
        else if (this._securityMode === 'developer')
            classes.push('intentos-shield-btn-dev');
        if (this._securityOpen)
            classes.push('intentos-shield-btn-active');
        this._shieldBtn.set_style_class_name(classes.join(' '));
    }

    _toggleSecurityStrip() {
        this._securityOpen = !this._securityOpen;
        if (this._securityOpen) {
            this._switcherOpen = false;
            this._memoryOpen = false;
            this._switcherStrip?.hide();
            this._memoryStrip?.hide();
            this._updateModelPillLabel();
            this._memBtn?.set_style_class_name('intentos-icon-btn');
            this._renderSecurityStrip();
            this._securityStrip.show();
            this._refreshSecurityPostureAsync(true);
        } else {
            this._securityStrip.hide();
        }
        this._updateShieldLabel();
    }

    async _refreshSecurityPostureAsync(reRender = false) {
        try {
            const posture = await this._moduleRpc('execution_hub', 'get_security_posture', {});
            if (posture && typeof posture === 'object') {
                this._securityPosture = posture;
                const mode = String(posture.security_mode || posture.mode || 'balanced').toLowerCase();
                if (SECURITY_MODES.some(m => m.id === mode))
                    this._securityMode = mode;
                this._updateShieldLabel();
                if (reRender && this._securityOpen)
                    this._renderSecurityStrip();
            }
        } catch (_e) {}
    }

    _renderSecurityStrip() {
        if (!this._securityStrip)
            return;
        this._securityStrip.destroy_all_children();

        const modeRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
        modeRow.add_child(new St.Label({
            style_class: 'intentos-strip-label',
            text: '🛡 安全防护:',
            y_align: Clutter.ActorAlign.CENTER,
        }));
        for (const m of SECURITY_MODES) {
            const btn = new St.Button({
                style_class: m.id === this._securityMode
                    ? 'intentos-seg-btn intentos-seg-btn-active'
                    : 'intentos-seg-btn',
                label: m.label,
                reactive: true,
            });
            btn.connect('clicked', () => {
                this._securityMode = m.id;
                this._updateShieldLabel();
                this._renderSecurityStrip();
                this._moduleRpc('execution_hub', 'set_security_mode', {mode: m.id})
                    .then(() => this._refreshSecurityPostureAsync(true))
                    .catch(() => {});
            });
            modeRow.add_child(btn);
        }
        this._securityStrip.add_child(modeRow);

        const zoneLbl = new St.Label({
            style_class: 'intentos-trace-summary',
            text: '用户目录($HOME/桌面/文档/下载)受控直达 · 敏感配置(~/.config, /etc)弹窗审批 · 密钥禁区(~/.ssh)硬拦截',
        });
        zoneLbl.clutter_text.set_line_wrap(true);
        this._securityStrip.add_child(zoneLbl);

        const grants = Array.isArray(this._securityPosture?.session_grants)
            ? this._securityPosture.session_grants
            : (Array.isArray(this._securityPosture?.active_grants) ? this._securityPosture.active_grants : []);

        if (grants.length > 0) {
            const grantHdr = new St.Label({
                style_class: 'intentos-strip-label',
                text: `当前会话临时放行 (${grants.length} 项):`,
            });
            this._securityStrip.add_child(grantHdr);

            for (const g of grants.slice(0, 4)) {
                const gRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
                const gid = String(g?.id || g?.grant_id || '');
                const kind = String(g?.scope_kind || g?.kind || 'scope');
                const val = String(g?.scope_value || g?.value || gid);
                gRow.add_child(new St.Label({
                    style_class: 'intentos-meta-footer',
                    text: `• [${kind}] ${val}`,
                    x_expand: true,
                    y_align: Clutter.ActorAlign.CENTER,
                }));
                if (gid) {
                    const revBtn = new St.Button({
                        style_class: 'intentos-seg-btn',
                        label: '撤销',
                        reactive: true,
                    });
                    revBtn.connect('clicked', () => {
                        this._moduleRpc('execution_hub', 'revoke_session_grant', {id: gid})
                            .then(() => this._refreshSecurityPostureAsync(true))
                            .catch(() => {});
                    });
                    gRow.add_child(revBtn);
                }
                this._securityStrip.add_child(gRow);
            }
        }
    }

    // ------------------------------------------------------------------
    // Personal Memory Hub & Software Translation Quick View (`🧠`)
    // ------------------------------------------------------------------
    _toggleMemoryStrip() {
        this._memoryOpen = !this._memoryOpen;
        if (this._memoryOpen) {
            this._switcherOpen = false;
            this._securityOpen = false;
            this._switcherStrip?.hide();
            this._securityStrip?.hide();
            this._updateModelPillLabel();
            this._updateShieldLabel();
            this._memBtn.set_style_class_name('intentos-icon-btn intentos-icon-btn-active');
            this._renderMemoryStrip();
            this._memoryStrip.show();
            this._refreshMemoryAsync(true);
        } else {
            this._memoryStrip.hide();
            this._memBtn.set_style_class_name('intentos-icon-btn');
        }
    }

    _normalizeMenuItems(rawItems) {
        if (!Array.isArray(rawItems))
            return [];
        const out = [];
        const seen = new Set();
        for (const item of rawItems) {
            if (typeof item === 'string') {
                const lbl = item.trim();
                if (lbl && lbl !== '-' && lbl !== 'separator' && !seen.has(lbl)) {
                    seen.add(lbl);
                    out.push({id: null, label: lbl, enabled: true});
                }
            } else if (item && typeof item === 'object') {
                if (item.is_separator || item.type === 'separator' || item.visible === false)
                    continue;
                const lbl = String(item.label || item.title || item.name || item.action || '').replace(/_/g, '').trim();
                if (lbl && !seen.has(lbl)) {
                    seen.add(lbl);
                    out.push({
                        id: item.id ?? item.menu_id ?? null,
                        label: lbl,
                        enabled: item.enabled !== false,
                    });
                }
            }
        }
        return out;
    }

    _normalizeLiveTrayApps(raw) {
        let arr = [];
        if (Array.isArray(raw)) {
            arr = raw;
        } else if (raw && typeof raw === 'object') {
            for (const k of ['apps', 'tray_apps', 'items', 'live_apps']) {
                if (Array.isArray(raw[k])) {
                    arr = raw[k];
                    break;
                }
            }
        }
        return arr.filter(x => x && typeof x === 'object').map(item => {
            const appId = String(item.app_id || item.id || item.desktop_id || item.name || item.title || 'tray_app');
            const name = String(item.display_name || item.zh_name || item.app_name || item.name || item.title || appId);
            const liveTitle = String(
                item.live_title || item.status_title || item.tooltip || item.media_title || item.now_playing || ''
            ).trim();
            const menuRaw = item.menu_items || item.dbusmenu_items || item.clickable_items || item.actions || item.tray?.menu_items || [];
            return {
                app_id: appId,
                name,
                live_title: liveTitle !== name ? liveTitle : '',
                service: String(item.service || item.bus_name || item.sni_service || ''),
                mpris_service: String(item.mpris_service || item.mpris || ''),
                menu_items: this._normalizeMenuItems(menuRaw),
            };
        });
    }

    async _triggerTrayMenuAsync(appKey, actionLabel, service = '', menuId = null) {
        this._liveAdapterStatus = `⏳ 正在触发 ${appKey} → 「${actionLabel}」...`;
        if (this._memoryOpen)
            this._renderMemoryStrip();
        try {
            const payload = {
                app: appKey,
                app_hint: appKey,
                action: actionLabel,
                menu_label: actionLabel,
            };
            if (service)
                payload.service = service;
            if (menuId !== null && menuId !== undefined)
                payload.menu_id = menuId;
            const res = await this._moduleRpc('app_adapter', 'trigger_tray_menu', payload);
            const unv = this._isUnverifiedStepOrDot(res);
            const summary = String(res?.summary || res?.message || `${appKey} · ${actionLabel}`);
            this._liveAdapterStatus = unv
                ? `⏳ 已发送请求（待桌面响应）: ${summary}`
                : `✓ 已触发并验证: ${summary}`;
        } catch (err) {
            this._liveAdapterStatus = `✕ 触发失败: ${err?.message || err}`;
        }
        await this._refreshMemoryAsync(true);
    }

    async _inspectLiveAppAsync(appQuery) {
        const q = String(appQuery || '').trim();
        if (!q)
            return;
        this._inspectAppQuery = q;
        this._liveAdapterStatus = `🔍 正在探测「${q}」可转译接口...`;
        if (this._memoryOpen)
            this._renderMemoryStrip();
        try {
            const res = await this._moduleRpc('app_adapter', 'inspect_live_app', {
                app: q,
                app_hint: q,
                query: q,
            });
            this._lastInspectedApp = (res && typeof res === 'object') ? res : null;
            const nm = String(res?.display_name || res?.name || res?.app || q);
            this._liveAdapterStatus = `✓ 已完成「${nm}」实时能力探测`;
        } catch (err) {
            this._lastInspectedApp = null;
            this._liveAdapterStatus = `✕ 探测失败: ${err?.message || err}`;
        }
        if (this._memoryOpen)
            this._renderMemoryStrip();
    }

    async _refreshMemoryAsync(reRender = false) {
        try {
            const dash = await this._moduleRpc('memory_hub', 'get_memory_dashboard', {});
            if (dash && typeof dash === 'object')
                this._memoryDashboard = dash;
        } catch (_e) {}

        try {
            const adResp = await this._moduleRpc('app_adapter', 'list_adapters', {});
            if (Array.isArray(adResp?.adapters))
                this._adaptersList = adResp.adapters;
            else if (Array.isArray(adResp))
                this._adaptersList = adResp;
        } catch (_e) {}

        try {
            const trayResp = await this._moduleRpc('app_adapter', 'list_live_tray_apps', {});
            this._liveTrayApps = this._normalizeLiveTrayApps(trayResp);
        } catch (_e) {}

        try {
            const dsResp = await this._moduleRpc('app_adapter', 'deep_scan_local_software', {
                force_refresh: false,
            });
            if (dsResp && typeof dsResp === 'object') {
                this._deepScanSummary = {
                    total_scanned: dsResp.total_scanned ?? (Array.isArray(dsResp.apps) ? dsResp.apps.length : 0),
                    running_count: dsResp.running_count ?? 0,
                    categories: Array.isArray(dsResp.categories) ? dsResp.categories : [],
                };
            }
        } catch (_e) {}

        try {
            const ccResp = this._incognito
                ? await this._moduleRpc('memory_hub', 'get_context_compression_config', {})
                : await this._moduleRpc('memory_hub', 'preview_session_compression', {
                      session_id: this._sessionId,
                  });
            if (ccResp && typeof ccResp === 'object')
                this._compressionPreview = ccResp.stats || ccResp;
        } catch (_e) {}

        const hints = [];
        const d = this._memoryDashboard || {};
        for (const item of (d.mentioned_files || d.recent_mentions || []).slice(0, 8)) {
            const val = String(item?.canonical_value || item?.path || item?.display_name || '');
            const lbl = String(item?.display_name || item?.title || val.split('/').pop() || val);
            if (val)
                hints.push({tag: '📂', label: lbl, value: val});
        }
        for (const item of (d.frequent_files || d.long_term_files || []).slice(0, 8)) {
            const val = String(item?.path || item?.canonical_value || '');
            const lbl = String(item?.title || item?.name || val.split('/').pop() || val);
            if (val && !hints.some(h => h.value === val))
                hints.push({tag: '🔥', label: lbl, value: val});
        }
        for (const item of (d.frequent_apps || d.top_apps || []).slice(0, 8)) {
            const lbl = String(item?.zh_name || item?.display_name || item?.name || '');
            if (lbl && !hints.some(h => h.value === lbl))
                hints.push({tag: '🧩', label: lbl, value: lbl});
        }
        for (const tr of (this._liveTrayApps || []).slice(0, 6)) {
            const lbl = String(tr.name || tr.app_id || '');
            if (lbl && !hints.some(h => h.value === lbl))
                hints.push({tag: '🟢', label: lbl, value: lbl});
        }
        for (const ad of (this._adaptersList || []).slice(0, 6)) {
            const lbl = String(ad?.display_name || ad?.name || ad?.id || '');
            if (lbl && !hints.some(h => h.value === lbl))
                hints.push({tag: '🔌', label: lbl, value: lbl});
        }
        this._mentionHints = hints;

        if (reRender && this._memoryOpen)
            this._renderMemoryStrip();
    }

    _renderMemoryStrip() {
        if (!this._memoryStrip)
            return;
        this._memoryStrip.destroy_all_children();

        const topRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
        topRow.add_child(new St.Label({
            style_class: 'intentos-strip-label',
            text: '🧠 个性化软件实时转译台 & 记忆快照',
            x_expand: true,
            y_align: Clutter.ActorAlign.CENTER,
        }));
        const wbBtn = new St.Button({
            style_class: 'intentos-seg-btn',
            label: '⚙ 分类转译中心',
            reactive: true,
        });
        wbBtn.connect('clicked', () => this._launchSettingsCenter('capabilities', this._inspectAppQuery));
        topRow.add_child(wbBtn);

        const syncBtn = new St.Button({
            style_class: 'intentos-seg-btn',
            label: '↻ 刷新',
            reactive: true,
        });
        syncBtn.connect('clicked', () => {
            this._moduleRpc('memory_hub', 'sync_system_usage', {})
                .then(() => this._refreshMemoryAsync(true))
                .catch(() => this._refreshMemoryAsync(true));
        });
        topRow.add_child(syncBtn);
        this._memoryStrip.add_child(topRow);

        if (this._compressionPreview) {
            const cp = this._compressionPreview;
            const ccEnabled = cp.enabled !== false;
            const qaTurns = Number(cp.included_qa_turns ?? cp.raw_qa_turns ?? 0);
            const estTok = Number(cp.compressed_estimated_tokens ?? cp.max_context_tokens ?? 0);
            const savedPct = Math.round(Number(cp.saved_pct || 0));
            const ccTxt = ccEnabled
                ? (qaTurns > 0
                    ? `📉 上下文非线性衰减压缩: ${qaTurns} 轮问答 · ${estTok} tok${savedPct > 0 ? ` (省 ${savedPct}%)` : ''}`
                    : '📉 上下文非线性衰减压缩已启用（近期完整保留，远期摘要并剥离历史工具记录）')
                : '📉 上下文非线性衰减压缩: 已关闭';
            this._memoryStrip.add_child(new St.Label({
                style_class: 'intentos-meta-footer',
                text: ccTxt,
            }));
        }

        if (this._deepScanSummary) {
            const ds = this._deepScanSummary;
            const dsRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
            dsRow.add_child(new St.Label({
                style_class: 'intentos-trace-summary',
                text: `🧭 本机软件深度扫描: 共 ${ds.total_scanned || 0} 款 · 9 大分类 · 运行中 ${ds.running_count || 0} 款`,
                x_expand: true,
                y_align: Clutter.ActorAlign.CENTER,
            }));
            this._memoryStrip.add_child(dsRow);

            if (Array.isArray(ds.categories) && ds.categories.length > 0) {
                const catRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
                for (const c of ds.categories.slice(0, 5)) {
                    const cPill = new St.Button({
                        style_class: 'intentos-mem-chip',
                        label: `${c.icon || '📦'}${c.name_zh || c.id}(${c.count ?? 0})`,
                        reactive: true,
                    });
                    cPill.connect('clicked', () => this._launchSettingsCenter('capabilities', ''));
                    catRow.add_child(cPill);
                }
                this._memoryStrip.add_child(catRow);
            }
        }

        if (this._liveAdapterStatus) {
            const stLbl = new St.Label({
                style_class: 'intentos-trace-summary',
                text: this._liveAdapterStatus,
            });
            stLbl.clutter_text.set_line_wrap(true);
            this._memoryStrip.add_child(stLbl);
        }

        // Section A: 运行态托盘与软件实时控制 (`list_live_tray_apps`)
        this._memoryStrip.add_child(new St.Label({
            style_class: 'intentos-trace-summary',
            text: `🟢 运行态托盘与软件实时控制 (${(this._liveTrayApps || []).length} 款在线 · 一键直控 dbusmenu):`,
        }));
        if (!this._liveTrayApps || this._liveTrayApps.length === 0) {
            this._memoryStrip.add_child(new St.Label({
                style_class: 'intentos-meta-footer',
                text: '  暂未检测到运行态托盘应用（支持下方直接输入任意软件名探测接口）',
            }));
        } else {
            for (const tr of this._liveTrayApps.slice(0, 4)) {
                const tCard = new St.BoxLayout({style_class: 'intentos-tray-card', vertical: true});
                const hdr = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
                const icon = (tr.mpris_service || tr.name.includes('音') || tr.name.toLowerCase().includes('soda')) ? '🎵' : '🟢';
                const headTxt = `${icon} ${tr.name}${tr.live_title ? ` · ${tr.live_title}` : ''}`;
                hdr.add_child(new St.Label({
                    style_class: 'intentos-strip-label',
                    text: headTxt.length <= 36 ? headTxt : `${headTxt.slice(0, 34)}…`,
                    x_expand: true,
                    y_align: Clutter.ActorAlign.CENTER,
                }));
                const probeMini = new St.Button({
                    style_class: 'intentos-tray-action-btn',
                    label: '🔍 探测',
                    reactive: true,
                });
                probeMini.connect('clicked', () => this._inspectLiveAppAsync(tr.name));
                hdr.add_child(probeMini);
                tCard.add_child(hdr);

                if (Array.isArray(tr.menu_items) && tr.menu_items.length > 0) {
                    const actRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
                    for (const mi of tr.menu_items.slice(0, 5)) {
                        const shortLbl = mi.label.length <= 10 ? mi.label : `${mi.label.slice(0, 9)}…`;
                        const aBtn = new St.Button({
                            style_class: 'intentos-tray-action-btn',
                            label: shortLbl,
                            reactive: mi.enabled !== false,
                        });
                        aBtn.connect('clicked', () => {
                            this._triggerTrayMenuAsync(tr.app_id || tr.name, mi.label, tr.service, mi.id);
                        });
                        actRow.add_child(aBtn);
                    }
                    tCard.add_child(actRow);
                }
                this._memoryStrip.add_child(tCard);
            }
        }

        // Section B: 探测并转译任意软件 (`inspect_live_app`)
        const inspectRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
        const inspectEntry = new St.Entry({
            style_class: 'intentos-model-search',
            hint_text: '输入任意软件名探测接口 (如 飞书 / FlClash / 轻笺 / 汽水音乐)...',
            text: this._inspectAppQuery || '',
            x_expand: true,
            can_focus: true,
        });
        inspectEntry.clutter_text.connect('activate', () => {
            this._inspectLiveAppAsync(inspectEntry.get_text());
        });
        const inspectBtn = new St.Button({
            style_class: 'intentos-seg-btn intentos-seg-btn-active',
            label: '⚡ 探测接口',
            reactive: true,
        });
        inspectBtn.connect('clicked', () => {
            this._inspectLiveAppAsync(inspectEntry.get_text());
        });
        inspectRow.add_child(inspectEntry);
        inspectRow.add_child(inspectBtn);
        this._memoryStrip.add_child(inspectRow);

        if (this._lastInspectedApp && typeof this._lastInspectedApp === 'object') {
            const ins = this._lastInspectedApp;
            const insCard = new St.BoxLayout({style_class: 'intentos-tray-card', vertical: true});
            const insName = String(ins.display_name || ins.name || ins.app || this._inspectAppQuery || '软件');
            const deskId = String(ins.desktop_id || ins.desktop_file || '无.desktop');
            const pids = Array.isArray(ins.pids || ins.running_pids)
                ? (ins.pids || ins.running_pids).join(',')
                : (ins.pid ? String(ins.pid) : '未运行');
            const chans = Array.isArray(ins.channels || ins.supported_channels)
                ? (ins.channels || ins.supported_channels).join(',')
                : '';
            const metaLbl = new St.Label({
                style_class: 'intentos-meta-footer',
                text: `📦 ${insName} · ${deskId} · PID:${pids}${chans ? ` · 通道:${chans}` : ''}`,
            });
            metaLbl.clutter_text.set_line_wrap(true);
            insCard.add_child(metaLbl);

            const discMenus = this._normalizeMenuItems(
                ins.tray_menu_items || ins.dbusmenu_items || ins.menu_items || ins.tray?.menu_items || []
            );
            const discRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
            for (const dm of discMenus.slice(0, 4)) {
                const tBtn = new St.Button({
                    style_class: 'intentos-tray-action-btn',
                    label: `▶ ${dm.label.length <= 9 ? dm.label : `${dm.label.slice(0, 8)}…`}`,
                    reactive: true,
                });
                tBtn.connect('clicked', () => this._triggerTrayMenuAsync(insName, dm.label, '', dm.id));
                discRow.add_child(tBtn);
            }
            const bindBtn = new St.Button({
                style_class: 'intentos-adapter-chip',
                label: '⚙ 绑定口令',
                reactive: true,
            });
            bindBtn.connect('clicked', () => this._launchSettingsCenter('capabilities', insName));
            discRow.add_child(bindBtn);
            insCard.add_child(discRow);
            this._memoryStrip.add_child(insCard);
        }

        const d = this._memoryDashboard || {};
        const addChipRow = (title, entries, chipCls) => {
            const row = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
            row.add_child(new St.Label({
                style_class: 'intentos-trace-summary',
                text: title,
                y_align: Clutter.ActorAlign.CENTER,
            }));
            if (entries.length === 0) {
                row.add_child(new St.Label({
                    style_class: 'intentos-meta-footer',
                    text: '暂无记录',
                    y_align: Clutter.ActorAlign.CENTER,
                }));
            } else {
                for (const item of entries.slice(0, 3)) {
                    const shortL = item.label.length <= 14 ? item.label : `${item.label.slice(0, 12)}…`;
                    const cBtn = new St.Button({
                        style_class: chipCls,
                        label: shortL,
                        reactive: true,
                    });
                    cBtn.connect('clicked', () => this._insertAtMention(item.value));
                    row.add_child(cBtn);
                }
            }
            this._memoryStrip.add_child(row);
        };

        const mentioned = (d.mentioned_files || d.recent_mentions || []).map(x => ({
            label: String(x?.display_name || x?.title || String(x?.canonical_value || '').split('/').pop() || '文件'),
            value: String(x?.canonical_value || x?.path || x?.display_name || ''),
        })).filter(x => x.value);

        const frequent = (d.frequent_files || d.long_term_files || []).map(x => ({
            label: String(x?.title || x?.name || String(x?.path || '').split('/').pop() || '文件'),
            value: String(x?.path || x?.title || ''),
        })).filter(x => x.value);

        const apps = (d.frequent_apps || d.top_apps || []).map(x => ({
            label: String(x?.zh_name || x?.display_name || x?.name || '软件'),
            value: String(x?.zh_name || x?.display_name || x?.name || ''),
        })).filter(x => x.value);

        const adapters = (this._adaptersList || []).map(x => ({
            label: String(x?.display_name || x?.name || x?.id || '适配器'),
            value: String(x?.display_name || x?.name || x?.id || ''),
        })).filter(x => x.value);

        addChipRow('📂 之前提及:', mentioned, 'intentos-mem-chip');
        addChipRow('🔥 长期常用:', frequent, 'intentos-mem-chip');
        addChipRow('🧩 常用软件:', apps, 'intentos-mem-chip');
        if (adapters.length > 0)
            addChipRow('🔌 转译适配:', adapters, 'intentos-adapter-chip');
    }

    // ------------------------------------------------------------------
    // Clipboard Quick-Ask & `@` Mention Completion
    // ------------------------------------------------------------------
    _captureClipboardContext() {
        const cb = St.Clipboard.get_default();
        cb.get_text(St.ClipboardType.PRIMARY, (_c1, primaryText) => {
            if (primaryText && primaryText.trim()) {
                this._setClipboardContext(primaryText);
                return;
            }
            cb.get_text(St.ClipboardType.CLIPBOARD, (_c2, clipText) => {
                if (clipText && clipText.trim())
                    this._setClipboardContext(clipText);
            });
        });
    }

    _setClipboardContext(rawText) {
        const cleaned = String(rawText || '').trim();
        this._clipboardContext = cleaned;
        if (!this._clipStrip || !this._clipLabel)
            return;
        if (cleaned) {
            const single = cleaned.replace(/\s+/g, ' ');
            const preview = single.length <= 40 ? single : `${single.slice(0, 38)}…`;
            this._clipLabel.set_text(`📋 已附带选区/剪贴板 (${cleaned.length} 字): ${preview}`);
            this._clipStrip.show();
        } else {
            this._clipStrip.hide();
        }
        if (this._visible)
            global.stage.set_key_focus(this._inputEntry.clutter_text);
    }

    _updateMentionStrip(text) {
        if (!this._mentionStrip)
            return;
        const match = /(?:^|\s)@([^\s@]*)$/.exec(text || '');
        if (!match) {
            this._mentionStrip.hide();
            return;
        }
        const q = match[1].toLowerCase();
        const filtered = this._mentionHints.filter(
            h => !q || h.label.toLowerCase().includes(q) || h.value.toLowerCase().includes(q)
        ).slice(0, 4);

        if (filtered.length === 0) {
            this._mentionStrip.hide();
            return;
        }
        this._mentionStrip.destroy_all_children();
        this._mentionStrip.add_child(new St.Label({
            style_class: 'intentos-strip-label',
            text: '@引用:',
            y_align: Clutter.ActorAlign.CENTER,
        }));
        this._currentMentionTopValue = filtered[0].value;
        for (const h of filtered) {
            const shortL = h.label.length <= 14 ? h.label : `${h.label.slice(0, 12)}…`;
            const btn = new St.Button({
                style_class: 'intentos-mem-chip',
                label: `${h.tag} ${shortL}`,
                reactive: true,
            });
            btn.connect('clicked', () => this._completeMentionInEntry(h.value));
            this._mentionStrip.add_child(btn);
        }
        this._mentionStrip.show();
    }

    _completeMentionInEntry(val) {
        const cur = this._inputEntry.get_text();
        const updated = cur.replace(/@([^\s@]*)$/, `@${val} `);
        this._setEntryTextSilent(updated);
        this._mentionStrip.hide();
        global.stage.set_key_focus(this._inputEntry.clutter_text);
    }

    _insertAtMention(val) {
        const cur = this._inputEntry.get_text();
        const sep = (!cur || cur.endsWith(' ')) ? '' : ' ';
        this._setEntryTextSilent(`${cur}${sep}@${val} `);
        this._memoryOpen = false;
        this._memoryStrip.hide();
        this._memBtn.set_style_class_name('intentos-icon-btn');
        global.stage.set_key_focus(this._inputEntry.clutter_text);
    }

    _setEntryTextSilent(text) {
        this._suppressTextChanged = true;
        this._inputEntry.set_text(text);
        this._suppressTextChanged = false;
    }

    // ------------------------------------------------------------------
    // Keyboard Handling (`Enter`, `Shift+Enter`, `Up/Down`, `Esc`, `Ctrl+Z`)
    // ------------------------------------------------------------------
    _onInputKeyPress(event) {
        const sym = event.get_key_symbol();
        const state = event.get_state();
        const ctrl = (state & Clutter.ModifierType.CONTROL_MASK) !== 0;
        const shift = (state & Clutter.ModifierType.SHIFT_MASK) !== 0;
        const currentText = this._inputEntry.get_text();

        // Quick keyboard approval when awaiting approval and input is empty
        if (this._activePendingApproval && currentText.trim() === '') {
            if (sym === Clutter.KEY_y || sym === Clutter.KEY_Y) {
                this._resolvePendingApproval(this._activePendingApproval, 'once', this._activePendingCardCtx);
                return Clutter.EVENT_STOP;
            }
            if (sym === Clutter.KEY_g || sym === Clutter.KEY_G) {
                this._resolvePendingApproval(this._activePendingApproval, 'session', this._activePendingCardCtx);
                return Clutter.EVENT_STOP;
            }
            if (sym === Clutter.KEY_n || sym === Clutter.KEY_N) {
                this._resolvePendingApproval(this._activePendingApproval, 'deny', this._activePendingCardCtx);
                return Clutter.EVENT_STOP;
            }
        }

        // Escape: cancel voice recording -> close popovers -> abort active turn -> hide dialog
        if (sym === Clutter.KEY_Escape) {
            if (this._voiceRecording) {
                this._cancelVoiceRecordingAsync();
                return Clutter.EVENT_STOP;
            }
            if (this._voiceBanner?.visible) {
                this._voiceBanner.hide();
                return Clutter.EVENT_STOP;
            }
            if (this._mentionStrip?.visible) {
                this._mentionStrip.hide();
                return Clutter.EVENT_STOP;
            }
            if (this._switcherOpen) {
                this._toggleSwitcherStrip();
                return Clutter.EVENT_STOP;
            }
            if (this._securityOpen) {
                this._toggleSecurityStrip();
                return Clutter.EVENT_STOP;
            }
            if (this._memoryOpen) {
                this._toggleMemoryStrip();
                return Clutter.EVENT_STOP;
            }
            if (this._turnBusy) {
                this._abortActiveTurn();
                return Clutter.EVENT_STOP;
            }
            this._hideDialog();
            return Clutter.EVENT_STOP;
        }

        // Enter sends; Shift+Enter inserts newline
        if (sym === Clutter.KEY_Return || sym === Clutter.KEY_KP_Enter) {
            if (shift) {
                const ct = this._inputEntry.clutter_text;
                const pos = ct.get_cursor_position();
                if (pos < 0)
                    this._setEntryTextSilent(`${currentText}\n`);
                else
                    ct.insert_text('\n', pos);
                return Clutter.EVENT_STOP;
            }
            this._submitFromEntry();
            return Clutter.EVENT_STOP;
        }

        // Tab completes top @mention
        if ((sym === Clutter.KEY_Tab || sym === Clutter.KEY_ISO_Left_Tab) && this._mentionStrip?.visible) {
            if (this._currentMentionTopValue) {
                this._completeMentionInEntry(this._currentMentionTopValue);
                return Clutter.EVENT_STOP;
            }
        }

        // Up / Down prompt history recall
        if (sym === Clutter.KEY_Up && (currentText.trim() === '' || this._historyCursor >= 0)) {
            if (this._inputHistory.length > 0) {
                this._historyCursor = Math.min(this._historyCursor + 1, this._inputHistory.length - 1);
                const recalled = this._inputHistory[this._inputHistory.length - 1 - this._historyCursor];
                this._setEntryTextSilent(recalled);
                return Clutter.EVENT_STOP;
            }
        }
        if (sym === Clutter.KEY_Down && this._historyCursor >= 0) {
            this._historyCursor -= 1;
            if (this._historyCursor < 0) {
                this._setEntryTextSilent('');
            } else {
                const recalled = this._inputHistory[this._inputHistory.length - 1 - this._historyCursor];
                this._setEntryTextSilent(recalled);
            }
            return Clutter.EVENT_STOP;
        }

        // Ctrl+Z Undo / Ctrl+N New Session
        if (ctrl && (sym === Clutter.KEY_z || sym === Clutter.KEY_Z)) {
            this._triggerUndo(this._lastChangesetId);
            return Clutter.EVENT_STOP;
        }
        if (ctrl && (sym === Clutter.KEY_n || sym === Clutter.KEY_N)) {
            this._startNewSession();
            return Clutter.EVENT_STOP;
        }

        return Clutter.EVENT_PROPAGATE;
    }

    // ------------------------------------------------------------------
    // Chat Stream, Compact Trace Dots & Auto-Expanded Approval Card
    // ------------------------------------------------------------------
    _startNewSession() {
        this._activeTurnToken += 1;
        this._setBusyState(false);
        this._hasPendingApproval = false;
        this._activePendingApproval = null;
        this._activePendingCardCtx = null;
        this._refreshPanelDot();
        this._sessionId = `ses_${Date.now()}`;
        this._historyCursor = -1;

        if (!this._incognito) {
            this._moduleRpc('memory_hub', 'create_session', {session_id: this._sessionId})
                .then(res => {
                    if (res?.session_id || res?.id)
                        this._sessionId = String(res.session_id || res.id);
                })
                .catch(() => {});
        }

        this._chatList.destroy_all_children();
        this._renderWelcomeView();
    }

    _renderWelcomeView() {
        this._welcomeBox = new St.BoxLayout({
            style_class: 'intentos-welcome-box',
            vertical: true,
            x_expand: true,
        });
        this._welcomeBox.add_child(new St.Label({
            style_class: 'intentos-welcome-title',
            text: '✦ IntentOS · 随问',
        }));
        this._welcomeBox.add_child(new St.Label({
            style_class: 'intentos-welcome-sub',
            text: '桌面悬浮极简 AIOS 对话窗 · 记忆层 + 软件指令转译层 + 可信安全审批',
        }));

        for (const sp of STARTER_PROMPTS) {
            const btn = new St.Button({
                style_class: 'intentos-starter-btn',
                label: sp.label,
                reactive: true,
                x_expand: true,
            });
            btn.connect('clicked', () => this._sendTurn(sp.prompt));
            this._welcomeBox.add_child(btn);
        }
        this._chatList.add_child(this._welcomeBox);
    }

    _scrollToBottom() {
        GLib.idle_add(GLib.PRIORITY_DEFAULT_IDLE, () => {
            try {
                const vscroll = this._chatScroll?.get_vscroll_bar?.();
                const adj = vscroll?.get_adjustment?.() || this._chatScroll?.vadjustment;
                if (adj)
                    adj.set_value(Math.max(0, adj.upper - adj.page_size));
            } catch (_e) {}
            return GLib.SOURCE_REMOVE;
        });
    }

    _appendUserBubble(text, hadClipboard) {
        if (this._welcomeBox && this._welcomeBox.get_parent()) {
            this._chatList.remove_child(this._welcomeBox);
            this._welcomeBox = null;
        }
        const row = new St.BoxLayout({vertical: false, x_expand: true});
        row.add_child(new St.Widget({x_expand: true}));

        const bubble = new St.BoxLayout({
            style_class: 'intentos-user-bubble',
            vertical: true,
        });
        if (hadClipboard) {
            bubble.add_child(new St.Label({
                style_class: 'intentos-trace-summary',
                text: '📋 附带选区/剪贴板文本',
            }));
        }
        const lbl = new St.Label({text});
        lbl.clutter_text.set_line_wrap(true);
        lbl.clutter_text.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR);
        bubble.add_child(lbl);
        row.add_child(bubble);
        this._chatList.add_child(row);
        this._scrollToBottom();
    }

    _appendThinkingBubble() {
        const bubble = new St.BoxLayout({
            style_class: 'intentos-assistant-bubble',
            vertical: false,
        });
        bubble.add_child(new St.Button({
            style_class: 'intentos-trace-dot intentos-trace-dot-gray',
            label: '●',
            reactive: false,
        }));
        bubble.add_child(new St.Label({
            style_class: 'intentos-trace-summary',
            text: '  正在思考与调度系统能力… (Esc 中止)',
            y_align: Clutter.ActorAlign.CENTER,
        }));
        this._chatList.add_child(bubble);
        this._scrollToBottom();
        return bubble;
    }

    _extractPendingFromTurn(turnRes) {
        if (turnRes?.pending_approval && typeof turnRes.pending_approval === 'object')
            return turnRes.pending_approval;
        const rawDots = Array.isArray(turnRes?.trace_dots) ? turnRes.trace_dots : [];
        for (const d of rawDots) {
            if (d?.pending_approval && typeof d.pending_approval === 'object')
                return d.pending_approval;
            const kind = String(d?.kind || '').toLowerCase();
            if (kind === 'approval' && (d?.approval_id || d?.capability_id || d?.intent_action)) {
                return {
                    approval_id: d.approval_id || '',
                    nonce: d.nonce || '',
                    digest: d.digest || '',
                    capability_id: d.capability_id || d.title || '受控操作',
                    summary: d.summary || d.title || '',
                    diff_preview: typeof d.detail === 'string' ? d.detail : JSON.stringify(d.detail || ''),
                    target_path: d.target_path || d.path || '',
                    app_id: d.app_id || d.app_hint || '',
                    pid: d.pid || null,
                    undoable: d.undoable ?? true,
                };
            }
        }
        return null;
    }

    _isUnverifiedStepOrDot(d) {
        if (!d || typeof d !== 'object')
            return false;
        if (d.simulated === true || d.unverified === true)
            return true;
        const kind = String(d.kind || '').toLowerCase();
        if (['tool_unverified', 'requested_unverified', 'unverified', 'simulated'].includes(kind))
            return true;
        const ver = d.verification;
        if (ver && typeof ver === 'object') {
            const vs = String(ver.state || ver.status || '').toLowerCase();
            const vn = String(ver.note || ver.reason || ver.summary || '').toLowerCase();
            if (vs.includes('unverified') || vs.includes('pending') || vs.includes('simulated'))
                return true;
            if (ver.simulated === true || vn.includes('requestedunverified') || vn.includes('未验证') || vn.includes('待桌面响应'))
                return true;
        } else if (typeof ver === 'string') {
            const vl = ver.toLowerCase();
            if (vl.includes('unverified') || vl.includes('未验证') || vl.includes('待桌面响应') || vl.includes('simulated'))
                return true;
        }
        const st = String(d.status || d.verification_state || '').toLowerCase();
        if (st.includes('unverified') || st === 'simulated')
            return true;
        const blob = `${d.title || ''} ${d.label || ''} ${typeof d.detail === 'string' ? d.detail : JSON.stringify(d.detail || '')} ${d.summary || ''}`.toLowerCase();
        return (
            blob.includes('requestedunverified') ||
            blob.includes('requested_unverified') ||
            blob.includes('未验证') ||
            blob.includes('待桌面响应') ||
            blob.includes('"simulated":true') ||
            blob.includes('"simulated": true')
        );
    }

    _normalizeTraceDots(turnRes) {
        const rawDots = Array.isArray(turnRes?.trace_dots) ? turnRes.trace_dots : [];
        const dots = rawDots.map(d => {
            let kind = String(d?.kind || 'tool_ok').toLowerCase();
            const rawColor = String(d?.color || kind).toLowerCase();
            let color = TRACE_COLOR_MAP[rawColor] || TRACE_COLOR_MAP[kind] || 'green';
            const detailVal = d?.detail ?? d?.summary ?? d?.output ?? '';
            let detail = typeof detailVal === 'object' ? JSON.stringify(detailVal, null, 2) : String(detailVal);
            let title = String(d?.title || d?.label || kind);

            // Honest verification badge: NEVER paint emerald green (`Passed`) when RequestedUnverified or simulated!
            if (!['thinking', 'memory', 'approval', 'tool_err', 'error'].includes(kind) && color !== 'red') {
                if (this._isUnverifiedStepOrDot(d)) {
                    kind = 'tool_unverified';
                    color = 'blue';
                    if (!title.includes('待桌面响应') && !title.includes('未验证'))
                        title = `${title} · 已发送请求（待桌面响应）`;
                    if (!detail.includes('已发送请求（待桌面响应）'))
                        detail = `⏳ 验证状态: 已发送请求（待桌面响应 / RequestedUnverified）\n${detail}`.trim();
                }
            }
            return {
                kind,
                color,
                title,
                detail,
                changeset_id: d?.changeset_id || null,
                duration_ms: d?.duration_ms ?? null,
            };
        });

        const rawSteps = Array.isArray(turnRes?.steps) ? turnRes.steps : [];
        if (rawSteps.length > 0 && !dots.some(d => ['tool_ok', 'tool_unverified', 'tool_err'].includes(d.kind))) {
            for (const st of rawSteps) {
                if (!st || typeof st !== 'object')
                    continue;
                const cap = String(st.capability_id || st.tool || st.name || '系统调用');
                const failed = st.ok === false || ['failed', 'error', 'denied'].includes(String(st.status || '').toLowerCase());
                const unver = !failed && this._isUnverifiedStepOrDot(st);
                dots.push({
                    kind: failed ? 'tool_err' : (unver ? 'tool_unverified' : 'tool_ok'),
                    color: failed ? 'red' : (unver ? 'blue' : 'green'),
                    title: `${cap} · ${failed ? '执行失败' : (unver ? '已发送请求（待桌面响应）' : '已验证完成')}`,
                    detail: String(st.summary || st.detail || JSON.stringify(st, null, 2)),
                    changeset_id: st.changeset_id || null,
                    duration_ms: st.duration_ms ?? null,
                });
            }
        }

        const thinking = String(turnRes?.thinking || '').trim();
        if (thinking && !dots.some(d => d.kind === 'thinking')) {
            dots.unshift({
                kind: 'thinking',
                color: 'gray',
                title: '深度思考链路',
                detail: thinking,
                changeset_id: null,
                duration_ms: null,
            });
        }
        if (Array.isArray(turnRes?.memory_hits) && turnRes.memory_hits.length > 0 && !dots.some(d => d.kind === 'memory')) {
            dots.push({
                kind: 'memory',
                color: 'purple',
                title: `记忆召回: ${turnRes.memory_hits.length} 项个人数据`,
                detail: JSON.stringify(turnRes.memory_hits.slice(0, 6), null, 2),
                changeset_id: null,
                duration_ms: null,
            });
        }
        if (Array.isArray(turnRes?.adapter_actions) && turnRes.adapter_actions.length > 0 && !dots.some(d => d.kind === 'adapter')) {
            const anyUnv = turnRes.adapter_actions.some(a => this._isUnverifiedStepOrDot(a));
            dots.push({
                kind: 'adapter',
                color: anyUnv ? 'blue' : 'cyan',
                title: anyUnv
                    ? `软件转译层: ${turnRes.adapter_actions.length} 项适配 · 已发送请求（待桌面响应）`
                    : `软件转译层: ${turnRes.adapter_actions.length} 项适配`,
                detail: JSON.stringify(turnRes.adapter_actions, null, 2),
                changeset_id: null,
                duration_ms: null,
            });
        }
        const pa = this._extractPendingFromTurn(turnRes);
        if (pa && typeof pa === 'object' && !dots.some(d => d.kind === 'approval')) {
            dots.push({
                kind: 'approval',
                color: 'amber',
                title: `待审批权限: ${pa.capability_id || pa.intent_action || '受控操作'}`,
                detail: `${pa.summary || ''}\n${pa.diff_preview || ''}`.trim(),
                changeset_id: null,
                duration_ms: null,
            });
        }
        return dots;
    }

    _inlineMarkdownToPango(line) {
        const codes = [];
        const withTokens = String(line).replace(/`([^`\n]+)`/g, (_m, c) => {
            const idx = codes.length;
            codes.push(`<tt>${GLib.markup_escape_text(c, -1)}</tt>`);
            return `\x00C${idx}\x00`;
        });
        let esc = GLib.markup_escape_text(withTokens, -1);
        esc = esc.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
        esc = esc.replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g, '<i>$1</i>');
        codes.forEach((snippet, idx) => {
            esc = esc.replace(`\x00C${idx}\x00`, snippet);
        });
        return esc;
    }

    _renderMarkdownIntoBubble(container, markdownText) {
        const raw = String(markdownText || '').trim();
        if (!raw)
            return;
        const fenceRe = /```([a-zA-Z0-9_+-]*)\n?([\s\S]*?)```/g;
        let lastIdx = 0;
        let match;

        const addProse = prose => {
            const trimmed = prose.trim();
            if (!trimmed)
                return;
            const pangoLines = trimmed.split('\n').map(l => {
                const s = l.trimEnd();
                if (s.startsWith('### '))
                    return `<b>${this._inlineMarkdownToPango(s.slice(4))}</b>`;
                if (s.startsWith('## ') || s.startsWith('# '))
                    return `<b>${this._inlineMarkdownToPango(s.replace(/^#+\s*/, ''))}</b>`;
                if (s.startsWith('- ') || s.startsWith('* '))
                    return `  • ${this._inlineMarkdownToPango(s.slice(2))}`;
                if (s.startsWith('> '))
                    return `<i>▎ ${this._inlineMarkdownToPango(s.slice(2))}</i>`;
                return this._inlineMarkdownToPango(s);
            });
            const lbl = new St.Label({style_class: 'intentos-md-text'});
            lbl.clutter_text.set_line_wrap(true);
            lbl.clutter_text.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR);
            try {
                lbl.clutter_text.set_markup(pangoLines.join('\n'));
            } catch (_e) {
                lbl.set_text(trimmed);
            }
            container.add_child(lbl);
        };

        while ((match = fenceRe.exec(raw)) !== null) {
            addProse(raw.slice(lastIdx, match.index));
            const lang = match[1] || 'code';
            const codeBody = match[2].replace(/\n$/, '');

            const codeCard = new St.BoxLayout({style_class: 'intentos-code-card', vertical: true});
            const codeHdr = new St.BoxLayout({vertical: false});
            codeHdr.add_child(new St.Label({
                style_class: 'intentos-meta-footer',
                text: lang,
                x_expand: true,
                y_align: Clutter.ActorAlign.CENTER,
            }));
            const cpBtn = new St.Button({
                style_class: 'intentos-seg-btn',
                label: '复制',
                reactive: true,
            });
            cpBtn.connect('clicked', () => {
                St.Clipboard.get_default().set_text(St.ClipboardType.CLIPBOARD, codeBody);
            });
            codeHdr.add_child(cpBtn);
            codeCard.add_child(codeHdr);

            const codeLbl = new St.Label({style_class: 'intentos-code-body', text: codeBody});
            codeLbl.clutter_text.set_line_wrap(true);
            codeLbl.clutter_text.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR);
            codeCard.add_child(codeLbl);
            container.add_child(codeCard);

            lastIdx = fenceRe.lastIndex;
        }
        addProse(raw.slice(lastIdx));
    }

    _formatFooterMetaText(turnData) {
        const parts = [];
        const engineStr = [turnData?.backend_used, turnData?.model_used].filter(Boolean).join(' · ');
        if (engineStr)
            parts.push(engineStr);
        const cc = turnData?.context_compression;
        if (cc && cc.enabled !== false && (Number(cc.saved_pct || 0) > 0 || Number(cc.included_qa_turns || 0) > 0)) {
            const estTok = Number(cc.compressed_estimated_tokens ?? cc.estimated_tokens ?? 0);
            const savedPct = Math.round(Number(cc.saved_pct || 0));
            parts.push(`📉 上下文 ${estTok} tok${savedPct > 0 ? ` (省 ${savedPct}%)` : ''}`);
        }
        return parts.join(' · ');
    }

    _appendAssistantTurn(turnData, origPrompt) {
        const bubble = new St.BoxLayout({
            style_class: 'intentos-assistant-bubble',
            vertical: true,
            x_expand: true,
        });

        // 1. 20px Horizontal Colored Trace Dots (`●`) Bar with `> 6` `+N` Compact Collapse (updatable on approval resume!)
        let dots = this._normalizeTraceDots(turnData);
        const traceBar = new St.BoxLayout({
            style_class: 'intentos-trace-bar',
            vertical: false,
            visible: dots.length > 0,
        });
        const detailBox = new St.BoxLayout({
            style_class: 'intentos-trace-detail',
            vertical: true,
            visible: false,
        });

        let activeDotIdx = -1;
        let dotsExpanded = dots.length <= 6;

        const rebuildTraceBar = () => {
            traceBar.destroy_all_children();
            if (dots.length === 0) {
                traceBar.hide();
                detailBox.hide();
                return;
            }
            traceBar.show();
            const dotBtnsByIdx = new Map();

            const makeDotBtn = idx => {
                const d = dots[idx];
                const baseCls = `intentos-trace-dot intentos-trace-dot-${d.color}`;
                const dBtn = new St.Button({
                    style_class: activeDotIdx === idx ? `${baseCls} intentos-trace-dot-selected` : baseCls,
                    label: '●',
                    reactive: true,
                    y_align: Clutter.ActorAlign.CENTER,
                });
                dBtn.connect('clicked', () => {
                    if (activeDotIdx === idx) {
                        activeDotIdx = -1;
                        detailBox.hide();
                        for (const [k, btn] of dotBtnsByIdx.entries())
                            btn.set_style_class_name(`intentos-trace-dot intentos-trace-dot-${dots[k].color}`);
                        return;
                    }
                    activeDotIdx = idx;
                    for (const [k, btn] of dotBtnsByIdx.entries()) {
                        const bCls = `intentos-trace-dot intentos-trace-dot-${dots[k].color}`;
                        btn.set_style_class_name(k === idx ? `${bCls} intentos-trace-dot-selected` : bCls);
                    }

                    detailBox.destroy_all_children();
                    const dHdr = new St.BoxLayout({vertical: false});
                    dHdr.add_child(new St.Label({
                        text: `● ${d.title}`,
                        x_expand: true,
                        y_align: Clutter.ActorAlign.CENTER,
                    }));
                    if (d.changeset_id) {
                        const uBtn = new St.Button({
                            style_class: 'intentos-btn-undo',
                            label: '↶ 撤销',
                            reactive: true,
                        });
                        uBtn.connect('clicked', () => this._triggerUndo(d.changeset_id));
                        dHdr.add_child(uBtn);
                    }
                    detailBox.add_child(dHdr);
                    if (d.detail) {
                        const bodyLbl = new St.Label({text: d.detail.slice(0, 1200)});
                        bodyLbl.clutter_text.set_line_wrap(true);
                        bodyLbl.clutter_text.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR);
                        detailBox.add_child(bodyLbl);
                    }
                    detailBox.show();
                    this._scrollToBottom();
                });
                dotBtnsByIdx.set(idx, dBtn);
                return dBtn;
            };

            if (dots.length > 6 && !dotsExpanded) {
                const hiddenCount = dots.length - 5;
                for (const i of [0, 1, 2])
                    traceBar.add_child(makeDotBtn(i));
                const moreBtn = new St.Button({
                    style_class: 'intentos-trace-more-pill',
                    label: `+${hiddenCount}`,
                    reactive: true,
                    y_align: Clutter.ActorAlign.CENTER,
                });
                moreBtn.connect('clicked', () => {
                    dotsExpanded = true;
                    rebuildTraceBar();
                });
                traceBar.add_child(moreBtn);
                for (const i of [dots.length - 2, dots.length - 1])
                    traceBar.add_child(makeDotBtn(i));
            } else {
                for (let i = 0; i < dots.length; i++)
                    traceBar.add_child(makeDotBtn(i));
                if (dots.length > 6) {
                    const foldBtn = new St.Button({
                        style_class: 'intentos-trace-more-pill',
                        label: '收起',
                        reactive: true,
                        y_align: Clutter.ActorAlign.CENTER,
                    });
                    foldBtn.connect('clicked', () => {
                        dotsExpanded = false;
                        rebuildTraceBar();
                    });
                    traceBar.add_child(foldBtn);
                }
            }

            const summaryText = dots.slice(0, 2).map(d => d.title).join(' · ');
            traceBar.add_child(new St.Label({
                style_class: 'intentos-trace-summary',
                text: summaryText,
                x_expand: true,
                y_align: Clutter.ActorAlign.CENTER,
            }));

            const firstCs = dots.find(d => d.changeset_id)?.changeset_id;
            if (firstCs) {
                this._lastChangesetId = String(firstCs);
                const quickUndo = new St.Button({
                    style_class: 'intentos-btn-undo',
                    label: '↶ 撤销',
                    reactive: true,
                });
                quickUndo.connect('clicked', () => this._triggerUndo(String(firstCs)));
                traceBar.add_child(quickUndo);
            }
        };

        const updateTurnDots = nextTurnData => {
            dots = this._normalizeTraceDots(nextTurnData);
            activeDotIdx = -1;
            dotsExpanded = dots.length <= 6;
            detailBox.hide();
            rebuildTraceBar();
        };

        rebuildTraceBar();
        bubble.add_child(traceBar);
        bubble.add_child(detailBox);

        // 2. Approval Slot Container (above or alongside reply, compacts cleanly upon resolution)
        const approvalHost = new St.BoxLayout({vertical: true, x_expand: true});
        bubble.add_child(approvalHost);

        // 3. Markdown Reply Body Container (updatable in-place upon approval)
        const mdContainer = new St.BoxLayout({vertical: true, x_expand: true});
        let currentReplyMd = String(turnData?.reply_markdown || '✓ 已完成');
        this._renderMarkdownIntoBubble(mdContainer, currentReplyMd);
        bubble.add_child(mdContainer);

        // 4. Footer Meta + Crisp Copy + Regenerate Buttons
        const footer = new St.BoxLayout({vertical: false});
        const footerMetaLbl = new St.Label({
            style_class: 'intentos-meta-footer',
            text: this._formatFooterMetaText(turnData),
            x_expand: true,
            y_align: Clutter.ActorAlign.CENTER,
        });
        footer.add_child(footerMetaLbl);
        const cpBtn = new St.Button({style_class: 'intentos-footer-btn', label: '复制', reactive: true});
        cpBtn.connect('clicked', () => {
            St.Clipboard.get_default().set_text(St.ClipboardType.CLIPBOARD, currentReplyMd);
        });
        const retryBtn = new St.Button({style_class: 'intentos-footer-btn', label: '↻', reactive: true});
        retryBtn.connect('clicked', () => this._sendTurn(origPrompt));
        footer.add_child(cpBtn);
        footer.add_child(retryBtn);
        bubble.add_child(footer);

        // Mount Auto-Expanded Inline Approval Card (`🛡️ 敏感权限与安全执行审批`)
        const mountPendingApprovalCard = paObj => {
            if (!paObj || typeof paObj !== 'object')
                return;
            this._hasPendingApproval = true;
            this._activePendingApproval = paObj;
            this._refreshPanelDot();

            const appCard = new St.BoxLayout({
                style_class: 'intentos-inline-approval',
                vertical: true,
                visible: true, // Always auto-expanded!
            });

            const hdrRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
            const titleLbl = new St.Label({
                style_class: 'intentos-approval-title',
                text: '🛡️ 敏感权限与安全执行审批',
                x_expand: true,
                y_align: Clutter.ActorAlign.CENTER,
            });
            hdrRow.add_child(titleLbl);
            const reversible = !(paObj.undoable === false || paObj.reversible === false);
            const badgeLbl = new St.Label({
                style_class: 'intentos-approval-badge',
                text: reversible ? '↶ 可撤销变更' : '⚠ 不可逆需确认',
                y_align: Clutter.ActorAlign.CENTER,
            });
            hdrRow.add_child(badgeLbl);
            appCard.add_child(hdrRow);

            const args = paObj.arguments || paObj.params || {};
            const metaParts = [];
            if (paObj.capability_id || paObj.intent_action)
                metaParts.push(`能力: ${paObj.capability_id || paObj.intent_action}`);
            const pTarget = paObj.target_path || paObj.path || args.path || args.directory || args.source || '';
            if (pTarget)
                metaParts.push(`路径: ${pTarget}`);
            if (paObj.app_id || paObj.app_hint || args.app)
                metaParts.push(`应用: ${paObj.app_id || paObj.app_hint || args.app}`);
            if (paObj.pid)
                metaParts.push(`PID: ${paObj.pid}`);
            let metaLbl = null;
            if (metaParts.length > 0) {
                metaLbl = new St.Label({
                    style_class: 'intentos-trace-summary',
                    text: metaParts.join(' · '),
                });
                metaLbl.clutter_text.set_line_wrap(true);
                appCard.add_child(metaLbl);
            }

            let previewBox = null;
            const diffTxt = [paObj.summary, paObj.diff_preview].filter(Boolean).join('\n').trim();
            if (diffTxt) {
                previewBox = new St.BoxLayout({
                    style_class: 'intentos-approval-preview',
                    vertical: true,
                });
                const diffLbl = new St.Label({text: diffTxt.slice(0, 600)});
                diffLbl.clutter_text.set_line_wrap(true);
                diffLbl.clutter_text.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR);
                previewBox.add_child(diffLbl);
                appCard.add_child(previewBox);
            }

            const btnRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
            const statusRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
            const statusLbl = new St.Label({
                style_class: 'intentos-trace-summary',
                text: '',
                x_expand: true,
                y_align: Clutter.ActorAlign.CENTER,
            });
            statusLbl.clutter_text.set_line_wrap(true);
            statusRow.add_child(statusLbl);

            const onceBtn = new St.Button({
                style_class: 'intentos-btn-approve',
                label: '✓ 批准本次',
                reactive: true,
            });
            const scopeBtn = new St.Button({
                style_class: 'intentos-btn-scope',
                label: '⏱ 本会话放行此范围',
                reactive: true,
            });
            const denyBtn = new St.Button({
                style_class: 'intentos-btn-deny',
                label: '✕ 拒绝',
                reactive: true,
            });

            const cardCtx = {
                appCard,
                titleLbl,
                badgeLbl,
                metaLbl,
                previewBox,
                onceBtn,
                scopeBtn,
                denyBtn,
                btnRow,
                statusRow,
                statusLbl,
                mdContainer,
                footerMetaLbl,
                updateTurnDots,
                setCurrentReplyMd: txt => {
                    currentReplyMd = String(txt || '');
                },
                mountNextApproval: nextPa => mountPendingApprovalCard(nextPa),
            };
            this._activePendingCardCtx = cardCtx;

            onceBtn.connect('clicked', () => this._resolvePendingApproval(paObj, 'once', cardCtx));
            scopeBtn.connect('clicked', () => this._resolvePendingApproval(paObj, 'session', cardCtx));
            denyBtn.connect('clicked', () => this._resolvePendingApproval(paObj, 'deny', cardCtx));

            btnRow.add_child(onceBtn);
            btnRow.add_child(scopeBtn);
            btnRow.add_child(denyBtn);
            appCard.add_child(btnRow);
            appCard.add_child(statusRow);
            approvalHost.add_child(appCard);
        };

        const pa = this._extractPendingFromTurn(turnData);
        if (pa && typeof pa === 'object')
            mountPendingApprovalCard(pa);

        this._chatList.add_child(bubble);
        this._scrollToBottom();
    }

    // ------------------------------------------------------------------
    // Turn Submission, Fallback & Scoped Approval Resolution
    // ------------------------------------------------------------------
    _setBusyState(busy) {
        this._turnBusy = Boolean(busy);
        if (this._sendBtn) {
            this._sendBtn.set_label(this._turnBusy ? '■' : '➤');
            this._sendBtn.set_style_class_name(this._turnBusy ? 'intentos-stop-btn' : 'intentos-send-btn');
        }
        this._refreshPanelDot();
    }

    _abortActiveTurn() {
        this._activeTurnToken += 1;
        this._setBusyState(false);
        this._moduleRpc('backend_bridge', 'cancel_turn', {session_id: this._sessionId}).catch(() => {
            this._rpcCall({method: 'stop_all'}).catch(() => {});
        });
    }

    _submitFromEntry() {
        let text = this._inputEntry.get_text().trim();
        if (!text && this._clipboardContext)
            text = '请帮我解释或处理这段选区/剪贴板内容';
        if (!text)
            return;
        this._sendTurn(text);
    }

    async _sendTurn(rawPrompt) {
        const text = String(rawPrompt || '').trim();
        if (!text || this._turnBusy)
            return;

        if (!this._incognito) {
            if (this._inputHistory[this._inputHistory.length - 1] !== text)
                this._inputHistory.push(text);
            if (this._inputHistory.length > 50)
                this._inputHistory.shift();
        }

        const clipCtx = this._clipboardContext;
        this._setEntryTextSilent('');
        this._setClipboardContext('');
        this._mentionStrip?.hide();

        this._appendUserBubble(text, Boolean(clipCtx));
        const thinkingBubble = this._appendThinkingBubble();

        this._activeTurnToken += 1;
        const token = this._activeTurnToken;
        this._setBusyState(true);

        let turnResult = null;
        try {
            turnResult = await this._executeQuickChatTurn(text, clipCtx);
        } catch (err) {
            turnResult = {
                backend_used: 'offline',
                model_used: '',
                reply_markdown: `无法连接到 \`intentosd\` 守护进程：\`${err.message}\``,
                trace_dots: [{
                    kind: 'tool_err',
                    color: 'red',
                    title: '连接错误',
                    detail: err.message,
                }],
                pending_approval: null,
            };
        }

        if (thinkingBubble && thinkingBubble.get_parent())
            this._chatList.remove_child(thinkingBubble);

        if (token !== this._activeTurnToken)
            return;

        this._setBusyState(false);
        if (turnResult?.session_id)
            this._sessionId = String(turnResult.session_id);
        if (!this._visible)
            this._hasUnread = true;
        this._appendAssistantTurn(turnResult, text);
        this._refreshPanelDot();
        this._refreshMemoryAsync(false);
    }

    async _executeQuickChatTurn(text, clipCtx) {
        try {
            const bridgeResp = await this._moduleRpc('backend_bridge', 'send_quick_chat_turn', {
                session_id: this._incognito ? null : this._sessionId,
                text,
                clipboard_context: clipCtx || null,
                incognito: this._incognito,
                reasoning_effort: this._selectedEffort,
            });
            if (bridgeResp && (
                bridgeResp.reply_markdown !== undefined ||
                bridgeResp.reply !== undefined ||
                bridgeResp.assistant_message !== undefined ||
                Array.isArray(bridgeResp.trace_dots) ||
                bridgeResp.pending_approval
            )) {
                return {
                    session_id: bridgeResp.session_id || this._sessionId,
                    backend_used: bridgeResp.backend_used || bridgeResp.backend || this._selectedBackend,
                    model_used: bridgeResp.model_used || bridgeResp.model || this._selectedModel,
                    thinking: bridgeResp.thinking || '',
                    reply_markdown: String(
                        bridgeResp.reply_markdown ?? bridgeResp.reply ?? bridgeResp.assistant_message ?? '✓ 已完成'
                    ),
                    trace_dots: bridgeResp.trace_dots || [],
                    memory_hits: bridgeResp.memory_hits || [],
                    adapter_actions: bridgeResp.adapter_actions || [],
                    pending_approval: bridgeResp.pending_approval || null,
                    context_compression: bridgeResp.context_compression || null,
                };
            }
        } catch (_bridgeErr) {
            // Fall through to `submit_intent`
        }

        const combined = clipCtx ? `${text}\n\n[剪贴板/选区内容]:\n${clipCtx.slice(0, 2000)}` : text;
        const res = await this._rpcCall({
            method: 'submit_intent',
            params: {
                protocol_version: 1,
                text: combined,
                session_id: this._incognito ? null : this._sessionId,
                force_agent: false,
                cwd: GLib.get_home_dir(),
                incognito: this._incognito,
            },
        });

        let replyMd = '';
        if (res?.kind === 'passthrough' && res?.passthrough) {
            const stdout = String(res.passthrough.stdout || '').trim();
            replyMd = String(res.passthrough.message || '命令已执行');
            if (stdout)
                replyMd += `\n\`\`\`text\n${stdout}\n\`\`\``;
        } else {
            replyMd = String(res?.assistant_message || res?.goal || '✓ 已执行完成');
            if (res?.handoff_command)
                replyMd += `\n\n建议命令：\n\`\`\`bash\n${res.handoff_command}\n\`\`\``;
        }

        const csets = Array.isArray(res?.changeset_ids) ? res.changeset_ids : [];
        const latestCs = csets.length > 0 ? csets[csets.length - 1] : null;
        const route = String(res?.route || 'L0');
        const pending = (res?.status === 'awaiting_approval' || res?.pending_approval)
            ? (res.pending_approval || null)
            : null;

        let synthDots = [];
        if (pending) {
            synthDots = [{
                kind: 'approval',
                color: 'amber',
                title: `待审批: ${pending.capability_id || ''}`,
                detail: `${pending.summary || ''}\n${pending.diff_preview || ''}`.trim(),
            }];
        } else if (Array.isArray(res?.steps) && res.steps.length > 0) {
            synthDots = res.steps.filter(s => s && typeof s === 'object').map(st => {
                const cap = String(st.capability_id || st.tool || st.name || route);
                const failed = st.ok === false || ['failed', 'error', 'denied'].includes(String(st.status || '').toLowerCase());
                const unver = !failed && this._isUnverifiedStepOrDot(st);
                return {
                    kind: failed ? 'tool_err' : (unver ? 'tool_unverified' : 'tool_ok'),
                    color: failed ? 'red' : (unver ? 'blue' : 'green'),
                    title: `${cap} · ${failed ? '执行失败' : (unver ? '已发送请求（待桌面响应）' : '已验证完成')}`,
                    detail: String(st.summary || st.detail || JSON.stringify(st, null, 2)),
                    changeset_id: st.changeset_id || latestCs,
                };
            });
        }
        if (synthDots.length === 0) {
            const failedTurn = ['failed', 'error', 'denied'].includes(String(res?.status || '').toLowerCase());
            const unverTurn = !failedTurn && (
                this._isUnverifiedStepOrDot(res) ||
                replyMd.includes('待桌面响应') ||
                replyMd.includes('未验证')
            );
            synthDots = [{
                kind: failedTurn ? 'tool_err' : (unverTurn ? 'tool_unverified' : 'tool_ok'),
                color: failedTurn ? 'red' : (unverTurn ? 'blue' : 'green'),
                title: failedTurn
                    ? `${route} 执行失败`
                    : (unverTurn ? `${route} 已发送请求（待桌面响应）` : `${route} 系统能力已执行`),
                detail: `${unverTurn ? '⏳ 验证状态: 已发送请求（待桌面响应 / RequestedUnverified）\n' : ''}状态: ${res?.status || 'completed'}${latestCs ? `\n变更集: ${latestCs}` : ''}`,
                changeset_id: latestCs,
            }];
        }

        const outSid = res?.session_id || this._sessionId;
        if (!this._incognito) {
            this._moduleRpc('memory_hub', 'record_conversation_turn', {
                session_id: outSid,
                user_text: text,
                assistant_text: replyMd,
                tool_steps: synthDots,
                incognito: false,
            }).catch(() => {});
        }

        return {
            session_id: outSid,
            backend_used: route,
            model_used: '',
            reply_markdown: replyMd,
            trace_dots: synthDots,
            pending_approval: pending,
        };
    }

    _extractApprovalScope(pa) {
        const args = pa?.arguments || pa?.params || {};
        if (typeof args.directory === 'string' && args.directory.trim()) {
            const cleanDir = args.directory.trim().replace(/\/+$/, '') || '/';
            return {scope_kind: 'directory', scope_value: cleanDir};
        }
        const rawPath = String(
            pa?.target_path ||
            pa?.path ||
            args.path ||
            args.source ||
            args.target ||
            (Array.isArray(pa?.paths) && pa.paths[0]) ||
            ''
        ).trim();
        if (rawPath) {
            if (rawPath.endsWith('/'))
                return {scope_kind: 'directory', scope_value: rawPath.replace(/\/+$/, '') || '/'};
            const slashIdx = rawPath.lastIndexOf('/');
            const dirVal = slashIdx > 0 ? rawPath.slice(0, slashIdx) : (slashIdx === 0 ? '/' : rawPath);
            return {scope_kind: 'directory', scope_value: dirVal || rawPath};
        }
        const textBlob = `${pa?.summary || ''} ${pa?.diff_preview || ''}`;
        const pathMatch = /(?:~\/|\/home\/|\/etc\/|\/opt\/|\/var\/)[^\s"'`]+/.exec(textBlob);
        if (pathMatch) {
            const p = pathMatch[0];
            const idx = p.lastIndexOf('/');
            const dir = idx > 0 ? p.slice(0, idx) : p;
            return {scope_kind: 'directory', scope_value: dir};
        }
        if (pa?.app_id || pa?.app_hint || args.app) {
            return {scope_kind: 'app', scope_value: String(pa.app_id || pa.app_hint || args.app)};
        }
        return {
            scope_kind: 'capability',
            scope_value: String(pa?.capability_id || pa?.intent_action || 'controlled_op'),
        };
    }

    async _resolvePendingApproval(pa, mode, cardCtx) {
        this._hasPendingApproval = false;
        this._activePendingApproval = null;
        this._activePendingCardCtx = null;

        if (cardCtx) {
            cardCtx.onceBtn?.set_reactive(false);
            cardCtx.scopeBtn?.set_reactive(false);
            cardCtx.denyBtn?.set_reactive(false);
            cardCtx.btnRow?.hide();
            cardCtx.statusLbl?.set_text(
                mode === 'deny'
                    ? '⏳ 正在取消受控操作…'
                    : '⏳ 已确认授权，正在执行并继续会话推理…'
            );
            cardCtx.titleLbl?.set_text(
                mode === 'deny'
                    ? '⏳ 正在取消受控操作…'
                    : '⏳ 已确认授权，正在执行并继续会话推理…'
            );
        }

        this._setBusyState(true);
        const scope = this._extractApprovalScope(pa);

        try {
            // 1. Primary Wave 5 Seamless In-Session Continuation: `backend_bridge.resume_approved_turn`
            if (pa.approval_id) {
                try {
                    const r = await this._moduleRpc('backend_bridge', 'resume_approved_turn', {
                        approval_id: pa.approval_id || '',
                        nonce: pa.nonce || '',
                        digest: pa.digest || '',
                        decision: mode === 'deny' ? 'deny' : (mode === 'session' ? 'session' : 'once'),
                        scope_kind: scope.scope_kind,
                        scope_value: scope.scope_value,
                        ttl_minutes: 60,
                    });

                    if (r && typeof r === 'object' && r.status !== 'stub') {
                        if (!this._incognito && r.session_id)
                            this._sessionId = String(r.session_id);
                        if (mode === 'session')
                            this._refreshSecurityPostureAsync(false);

                        const csets = Array.isArray(r.changeset_ids) ? r.changeset_ids : [];
                        const resolvedCs = r.changeset_id
                            ? String(r.changeset_id)
                            : (csets.length > 0 ? String(csets[csets.length - 1]) : null);
                        if (resolvedCs)
                            this._lastChangesetId = resolvedCs;

                        const fullReply = String(
                            r.reply_markdown ?? r.reply ?? r.assistant_message ??
                            (mode === 'deny' ? '已拒绝执行该敏感操作。' : '已完成授权执行并继续会话。')
                        );

                        if (cardCtx) {
                            cardCtx.appCard?.set_style_class_name('intentos-inline-approval intentos-inline-approval-resolved');
                            cardCtx.previewBox?.hide();
                            cardCtx.badgeLbl?.hide();
                            cardCtx.titleLbl?.set_text(
                                mode === 'deny'
                                    ? '🛡️ 已拒绝执行该敏感操作'
                                    : (mode === 'session'
                                        ? '🛡️ 已放行本会话范围 · 已继续会话'
                                        : '🛡️ 敏感权限已批准 · 已继续会话')
                            );
                            cardCtx.statusLbl?.set_text(
                                mode === 'deny'
                                    ? '未执行受控操作，会话保持安全状态'
                                    : (mode === 'session'
                                        ? `本会话已放行 [${scope.scope_kind}] ${scope.scope_value}`
                                        : '已完成授权操作并回填对话结果')
                            );
                            if (resolvedCs && cardCtx.statusRow) {
                                const undoBtn = new St.Button({
                                    style_class: 'intentos-btn-undo',
                                    label: '↶ 撤销',
                                    reactive: true,
                                });
                                undoBtn.connect('clicked', () => this._triggerUndo(resolvedCs));
                                cardCtx.statusRow.add_child(undoBtn);
                            }

                            cardCtx.updateTurnDots?.(r);
                            if (cardCtx.mdContainer) {
                                cardCtx.mdContainer.destroy_all_children();
                                this._renderMarkdownIntoBubble(cardCtx.mdContainer, fullReply);
                            }
                            cardCtx.setCurrentReplyMd?.(fullReply);
                            if (cardCtx.footerMetaLbl)
                                cardCtx.footerMetaLbl.set_text(this._formatFooterMetaText(r));
                            if (r.pending_approval)
                                cardCtx.mountNextApproval?.(r.pending_approval);
                        }

                        this._setBusyState(false);
                        this._refreshMemoryAsync(false);
                        this._scrollToBottom();
                        return;
                    }
                } catch (resumeErr) {
                    const errTxt = String(resumeErr?.message || resumeErr || '').toLowerCase();
                    if (!errTxt.includes('unknown action')) {
                        if (cardCtx?.statusLbl)
                            cardCtx.statusLbl.set_text(`✗ 授权续跑错误: ${resumeErr?.message || resumeErr}`);
                        this._setBusyState(false);
                        return;
                    }
                    // Fall through ONLY when daemon does not implement `resume_approved_turn`
                }
            }

            // 2. Fallback Path (`!pa.approval_id` custom adapter action or legacy `approve`/`deny`)
            if (mode === 'deny') {
                if (pa.approval_id)
                    await this._rpcCall({method: 'deny', params: {approval_id: pa.approval_id}});
                if (cardCtx) {
                    cardCtx.appCard?.set_style_class_name('intentos-inline-approval intentos-inline-approval-resolved');
                    cardCtx.previewBox?.hide();
                    cardCtx.titleLbl?.set_text('🛡️ 已拒绝执行该敏感操作');
                    cardCtx.statusLbl?.set_text('已拒绝执行');
                }
                this._setBusyState(false);
                return;
            }

            if (mode === 'session') {
                try {
                    await this._moduleRpc('execution_hub', 'grant_session_scope', {
                        scope_kind: scope.scope_kind,
                        scope_value: scope.scope_value,
                        ttl_minutes: 60,
                    });
                } catch (_grantErr) {
                    if (pa.capability_id) {
                        try {
                            await this._moduleRpc('execution_hub', 'create_grant_envelope', {
                                task_id: pa.task_id || this._sessionId,
                                capabilities: [pa.capability_id],
                                resource_scope: [GLib.get_home_dir()],
                                max_effect: 'write.reversible',
                                max_operations: 30,
                            });
                        } catch (_envErr) {}
                    }
                }
                this._refreshSecurityPostureAsync(false);
            }

            let resolvedCs = null;
            let resultMsg = '';

            if (pa.approval_id) {
                const res = await this._rpcCall({
                    method: 'approve',
                    params: {
                        approval_id: pa.approval_id,
                        nonce: pa.nonce || '',
                        digest: pa.digest || '',
                    },
                });
                const csets = Array.isArray(res?.changeset_ids) ? res.changeset_ids : [];
                if (res?.changeset_id)
                    resolvedCs = String(res.changeset_id);
                else if (csets.length > 0)
                    resolvedCs = String(csets[csets.length - 1]);
                resultMsg = String(res?.reply_markdown || res?.assistant_message || res?.summary || '已批准并验证执行完成');
            } else if (pa.app_hint || pa.intent_action) {
                const res = await this._moduleRpc('app_adapter', 'translate_and_execute', {
                    app_hint: pa.app_hint || '',
                    intent_action: pa.intent_action || '',
                    params: pa.params || {},
                    approved: true,
                });
                if (res?.changeset_id)
                    resolvedCs = String(res.changeset_id);
                resultMsg = String(res?.summary || '已放行并执行完成');
            } else {
                resultMsg = '已批准本次执行';
            }

            if (resolvedCs)
                this._lastChangesetId = resolvedCs;

            if (cardCtx) {
                cardCtx.appCard?.set_style_class_name('intentos-inline-approval intentos-inline-approval-resolved');
                cardCtx.previewBox?.hide();
                cardCtx.titleLbl?.set_text(
                    mode === 'session'
                        ? '🛡️ 已放行本会话范围 · 已继续会话'
                        : '🛡️ 敏感权限已批准 · 已继续会话'
                );
                const scopeNote = mode === 'session' ? ' (已加入本会话放行范围)' : '';
                cardCtx.statusLbl?.set_text(`✓ ${resultMsg}${scopeNote}`);
                if (cardCtx.mdContainer && resultMsg) {
                    cardCtx.mdContainer.destroy_all_children();
                    this._renderMarkdownIntoBubble(cardCtx.mdContainer, resultMsg);
                }
                cardCtx.setCurrentReplyMd?.(resultMsg);
                if (resolvedCs && cardCtx.statusRow) {
                    const undoBtn = new St.Button({
                        style_class: 'intentos-btn-undo',
                        label: '↶ 撤销',
                        reactive: true,
                    });
                    undoBtn.connect('clicked', () => this._triggerUndo(resolvedCs));
                    cardCtx.statusRow.add_child(undoBtn);
                }
            }
            this._scrollToBottom();
        } catch (err) {
            if (cardCtx?.statusLbl)
                cardCtx.statusLbl.set_text(`✗ 审批错误: ${err.message}`);
        } finally {
            this._setBusyState(false);
        }
    }

    // ------------------------------------------------------------------
    // Voice Recognition (ASR) Mic Input (`🎙` -> `speech_hub`)
    // ------------------------------------------------------------------
    async _refreshSpeechOverviewAsync() {
        try {
            const ov = await this._moduleRpc('speech_hub', 'get_speech_overview', {});
            if (ov && typeof ov === 'object')
                this._speechOverview = ov;
        } catch (_e) {}
        return this._speechOverview;
    }

    _showVoiceSetupBanner(message, hasInstalledModel, isDisabled) {
        if (!this._voiceBanner)
            return;
        this._voiceBanner.destroy_all_children();
        const msgLbl = new St.Label({
            style_class: 'intentos-trace-summary',
            text: message,
        });
        msgLbl.clutter_text.set_line_wrap(true);
        this._voiceBanner.add_child(msgLbl);

        const actRow = new St.BoxLayout({style_class: 'intentos-strip-row', vertical: false});
        if (hasInstalledModel && isDisabled) {
            const enableNowBtn = new St.Button({
                style_class: 'intentos-btn-approve',
                label: '⚡ 立即开启并录音',
                reactive: true,
            });
            enableNowBtn.connect('clicked', () => {
                this._voiceBanner.hide();
                this._moduleRpc('speech_hub', 'update_speech_config', {enabled: true})
                    .then(() => this._refreshSpeechOverviewAsync())
                    .then(() => this._startVoiceRecordingAsync())
                    .catch(() => {});
            });
            actRow.add_child(enableNowBtn);
        }

        const openCfgBtn = new St.Button({
            style_class: 'intentos-seg-btn',
            label: '⚙ 打开语音识别模型下载与开关设置',
            reactive: true,
        });
        openCfgBtn.connect('clicked', () => {
            this._voiceBanner.hide();
            this._launchSettingsCenter('speech');
        });
        actRow.add_child(openCfgBtn);

        const closeBtn = new St.Button({
            style_class: 'intentos-icon-btn',
            label: '✕',
            reactive: true,
        });
        closeBtn.connect('clicked', () => this._voiceBanner.hide());
        actRow.add_child(closeBtn);

        this._voiceBanner.add_child(actRow);
        this._voiceBanner.show();
    }

    async _onMicButtonClicked() {
        if (this._voiceTranscribing)
            return;
        if (this._voiceRecording) {
            await this._stopVoiceAndTranscribeAsync();
            return;
        }

        const ov = await this._refreshSpeechOverviewAsync();
        const cfg = ov?.config || {};
        const models = Array.isArray(ov?.models) ? ov.models : [];
        const hasInstalled = models.some(m => m.installed);

        if (!ov || (!hasInstalled && !cfg.allow_cloud_fallback)) {
            this._showVoiceSetupBanner(
                '🎙 尚未下载本地离线语音识别模型（推荐 SenseVoice-Small 中英混合模型），点击下方打开设置中心下载并启用。',
                false,
                cfg.enabled === false
            );
            return;
        }

        if (cfg.enabled === false) {
            this._showVoiceSetupBanner(
                '🎙 本机离线语音模型已安装，但悬浮窗语音输入开关尚未开启。',
                hasInstalled,
                true
            );
            return;
        }

        this._voiceBanner?.hide();
        await this._startVoiceRecordingAsync();
    }

    async _startVoiceRecordingAsync() {
        const cfg = this._speechOverview?.config || {};
        try {
            await this._moduleRpc('speech_hub', 'start_recording', {
                test_mode: false,
                audio_source: cfg.audio_source || 'default',
                language: cfg.language || 'zh',
            });
        } catch (err) {
            const models = Array.isArray(this._speechOverview?.models) ? this._speechOverview.models : [];
            this._showVoiceSetupBanner(
                `⚠️ 无法启动语音录制: ${err?.message || err}`,
                models.some(m => m.installed),
                cfg.enabled === false
            );
            return;
        }

        this._voiceRecording = true;
        this._voiceStartSec = Math.floor(GLib.get_monotonic_time() / 1000000);
        this._micBtn?.set_style_class_name('intentos-mic-recording');
        this._micBtn?.set_label('🔴 00:00');
        if (this._inputEntry)
            this._inputEntry.hint_text = '正在聆听您的语音指令… 再次点击 🔴 完成识别';

        if (this._voiceTimerId) {
            try {
                GLib.source_remove(this._voiceTimerId);
            } catch (_e) {}
            this._voiceTimerId = 0;
        }
        this._voiceTimerId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 1, () => {
            if (!this._voiceRecording || !this._micBtn) {
                this._voiceTimerId = 0;
                return GLib.SOURCE_REMOVE;
            }
            const nowSec = Math.floor(GLib.get_monotonic_time() / 1000000);
            const elapsed = Math.max(0, nowSec - this._voiceStartSec);
            const mm = String(Math.floor(elapsed / 60)).padStart(2, '0');
            const ss = String(elapsed % 60).padStart(2, '0');
            this._micBtn.set_label(`🔴 ${mm}:${ss}`);
            return GLib.SOURCE_CONTINUE;
        });
    }

    async _stopVoiceAndTranscribeAsync() {
        if (this._voiceTimerId) {
            try {
                GLib.source_remove(this._voiceTimerId);
            } catch (_e) {}
            this._voiceTimerId = 0;
        }
        this._voiceRecording = false;
        this._voiceTranscribing = true;
        this._micBtn?.set_style_class_name('intentos-mic-btn');
        this._micBtn?.set_label('⏳');
        if (this._inputEntry)
            this._inputEntry.hint_text = '⏳ 正在使用本机离线语音模型转写…';

        const cfg = this._speechOverview?.config || {};
        try {
            const res = await this._moduleRpc('speech_hub', 'stop_and_transcribe', {
                language: cfg.language || 'zh',
            });
            const transcript = String(res?.text ?? res?.transcript ?? '').trim();
            if (transcript && this._inputEntry) {
                const cur = this._inputEntry.get_text().trim();
                this._setEntryTextSilent(cur ? `${cur} ${transcript}` : transcript);
                global.stage.set_key_focus(this._inputEntry.clutter_text);
                if (cfg.auto_send_after_transcribe && !this._turnBusy)
                    this._submitFromEntry();
            }
        } catch (err) {
            this._showVoiceSetupBanner(`⚠️ 语音转写异常: ${err?.message || err}`, false, false);
        } finally {
            this._voiceTranscribing = false;
            this._micBtn?.set_style_class_name('intentos-mic-btn');
            this._micBtn?.set_label('🎙');
            if (this._inputEntry)
                this._inputEntry.hint_text = this._defaultHintText;
        }
    }

    async _cancelVoiceRecordingAsync() {
        if (this._voiceTimerId) {
            try {
                GLib.source_remove(this._voiceTimerId);
            } catch (_e) {}
            this._voiceTimerId = 0;
        }
        this._voiceRecording = false;
        this._voiceTranscribing = false;
        this._micBtn?.set_style_class_name('intentos-mic-btn');
        this._micBtn?.set_label('🎙');
        if (this._inputEntry)
            this._inputEntry.hint_text = this._defaultHintText;
        try {
            await this._moduleRpc('speech_hub', 'cancel_recording', {});
        } catch (_e) {}
    }

    async _triggerUndo(targetId) {
        try {
            const res = await this._rpcCall({
                method: 'undo',
                params: {target_id: targetId || null},
            });
            const msg = `↶ ${res?.message || '已撤销最近一次系统变更'}`;
            this._appendAssistantTurn({
                backend_used: 'undo',
                model_used: '',
                reply_markdown: msg,
                trace_dots: [{kind: 'tool_ok', color: 'green', title: '变更已回滚', detail: msg}],
            }, '撤销上一步');
        } catch (err) {
            this._appendAssistantTurn({
                backend_used: 'undo',
                model_used: '',
                reply_markdown: `无法撤销：\`${err.message}\``,
                trace_dots: [{kind: 'tool_err', color: 'red', title: '撤销失败', detail: err.message}],
            }, '撤销上一步');
        }
    }

    // ------------------------------------------------------------------
    // Non-Blocking Async Unix Socket RPC (`${XDG_RUNTIME_DIR}/intentos/ui.sock`)
    // ------------------------------------------------------------------
    _moduleRpc(domain, action, payload = {}) {
        return this._rpcCall({
            method: 'module_rpc',
            params: {domain, action, payload},
        });
    }

    _rpcCall(payload) {
        return new Promise((resolve, reject) => {
            const client = new Gio.SocketClient();
            const addr = Gio.UnixSocketAddress.new(this._socketPath());
            client.connect_async(addr, null, (src, asyncRes) => {
                try {
                    const conn = src.connect_finish(asyncRes);
                    const reqLine = `${JSON.stringify({id: `gjs_${Date.now()}`, ...payload})}\n`;
                    const outStream = conn.get_output_stream();
                    outStream.write_all_async(
                        new TextEncoder().encode(reqLine),
                        GLib.PRIORITY_DEFAULT,
                        null,
                        (_os, writeRes) => {
                            try {
                                outStream.write_all_finish(writeRes);
                                const dataIn = new Gio.DataInputStream({
                                    base_stream: conn.get_input_stream(),
                                    buffer_size: 131072,
                                });
                                dataIn.read_line_async(GLib.PRIORITY_DEFAULT, null, (_di, readRes) => {
                                    try {
                                        const [lineBytes] = dataIn.read_line_finish(readRes);
                                        conn.close(null);
                                        if (!lineBytes) {
                                            reject(new Error('Empty response from intentosd'));
                                            return;
                                        }
                                        const decoded = new TextDecoder().decode(lineBytes);
                                        const parsed = JSON.parse(decoded);
                                        if (parsed.ok)
                                            resolve(parsed.result);
                                        else
                                            reject(new Error(parsed.error || 'RPC failed'));
                                    } catch (err) {
                                        reject(err);
                                    }
                                });
                            } catch (err) {
                                reject(err);
                            }
                        }
                    );
                } catch (err) {
                    reject(err);
                }
            });
        });
    }
}
