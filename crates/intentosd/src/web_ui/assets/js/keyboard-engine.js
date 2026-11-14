/**
 * IntentOS v0.3 — Full Keyboard Navigation Engine (§3.1 Keyboard-First Ergonomics)
 * Supports: Enter, Ctrl+Enter, Alt+Enter, Tab/Shift+Tab, ArrowUp/ArrowDown (+ empty-input history recall),
 * Ctrl+C (copy path/URL), Ctrl+Z (undo), Ctrl+, (11-Page Settings), Escape.
 */

export class KeyboardEngine {
  /**
   * @param {object} opts
   * @param {HTMLInputElement} opts.inputEl
   * @param {import('./candidate-view.js').CandidateViewController} opts.candidateView
   * @param {Function} opts.onSubmit - (text, forceAgent, candidate) => void
   * @param {Function} opts.onUndo - () => void
   * @param {Function} opts.onOpenSettings - () => void
   * @param {Function} opts.onCloseModals - () => boolean
   * @param {Function} opts.onCategoryChanged - (newCat) => void
   */
  constructor(opts) {
    this.inputEl = opts.inputEl;
    this.candidateView = opts.candidateView;
    this.onSubmit = opts.onSubmit;
    this.onUndo = opts.onUndo;
    this.onOpenSettings = opts.onOpenSettings;
    this.onCloseModals = opts.onCloseModals;
    this.onCategoryChanged = opts.onCategoryChanged || (() => {});

    this.isImeComposing = false;
    this.inputHistory = [
      '进入护眼模式',
      '本机 IP 是多少',
      '记住 docx 用 WPS 打开',
      '怎么撤销上一次 git commit 但保留改动',
    ];
    this.historyCursor = -1;
  }

  recordInputHistory(text) {
    const clean = (text || '').trim();
    if (!clean) return;
    const existingIdx = this.inputHistory.indexOf(clean);
    if (existingIdx !== -1) {
      this.inputHistory.splice(existingIdx, 1);
    }
    this.inputHistory.unshift(clean);
    if (this.inputHistory.length > 50) {
      this.inputHistory.pop();
    }
    this.historyCursor = -1;
  }

  bind() {
    if (!this.inputEl) return;

    this.inputEl.addEventListener('compositionstart', () => {
      this.isImeComposing = true;
    });
    this.inputEl.addEventListener('compositionend', () => {
      this.isImeComposing = false;
    });

    this.inputEl.addEventListener('keydown', (e) => {
      if (this.isImeComposing) return;

      // Alt+Enter -> Toggle Contextual Action Menu on selected candidate (UI-06)
      if (e.key === 'Enter' && e.altKey) {
        e.preventDefault();
        this.candidateView.toggleActionMenu();
        return;
      }

      // Ctrl+Enter -> Force L1/L2 Agent execution
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        this.candidateView.closeActionMenu();
        const text = this.inputEl.value;
        this.recordInputHistory(text);
        this.onSubmit(text, true, null);
        return;
      }

      // Enter -> Execute active action menu item OR selected candidate
      if (e.key === 'Enter') {
        e.preventDefault();
        if (this.candidateView.actionMenuOpen) {
          this.candidateView.executeActiveAction();
          return;
        }
        const picked = this.candidateView.getSelectedCandidate();
        const text = this.inputEl.value;
        this.recordInputHistory(text);
        if (picked && picked.kind === 'agent_fallback') {
          this.onSubmit(text, true, null);
        } else {
          this.onSubmit(text, false, picked);
        }
        return;
      }

      // Tab / Shift+Tab -> Autocomplete candidate or cycle category groups
      if (e.key === 'Tab') {
        e.preventDefault();
        const picked = this.candidateView.getSelectedCandidate();
        if (!e.shiftKey && picked && picked.completion_text && picked.completion_text !== this.inputEl.value) {
          this.inputEl.value = picked.completion_text;
          this.inputEl.dispatchEvent(new Event('input', { bubbles: true }));
          return;
        }
        const nextCat = this.candidateView.cycleCategoryFilter(e.shiftKey);
        this.onCategoryChanged(nextCat);
        return;
      }

      // ArrowDown -> Next candidate or action item
      if (e.key === 'ArrowDown') {
        if (this.candidateView.flatItems.length > 0 || this.candidateView.actionMenuOpen) {
          e.preventDefault();
          this.candidateView.moveSelection(1);
        }
        return;
      }

      // ArrowUp -> Previous candidate OR recall previous input history when input is empty (§3.1)
      if (e.key === 'ArrowUp') {
        if (this.candidateView.actionMenuOpen || this.candidateView.flatItems.length > 0) {
          e.preventDefault();
          this.candidateView.moveSelection(-1);
          return;
        }
        if (!this.inputEl.value.trim() && this.inputHistory.length > 0) {
          e.preventDefault();
          this.historyCursor = Math.min(this.historyCursor + 1, this.inputHistory.length - 1);
          this.inputEl.value = this.inputHistory[this.historyCursor];
          this.inputEl.dispatchEvent(new Event('input', { bubbles: true }));
        }
        return;
      }

      // Escape -> Close action menu first, or clear candidates
      if (e.key === 'Escape') {
        if (this.candidateView.actionMenuOpen) {
          e.preventDefault();
          this.candidateView.closeActionMenu();
          return;
        }
        if (this.candidateView.flatItems.length > 0) {
          e.preventDefault();
          this.candidateView.clear();
          return;
        }
      }
    });

    // Global keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      // Ctrl+, -> Open 11-Page Settings Center
      if ((e.ctrlKey || e.metaKey) && e.key === ',') {
        e.preventDefault();
        if (this.onOpenSettings) this.onOpenSettings();
        return;
      }

      // Ctrl+Z -> Undo latest reversible ChangeSet (when not typing inside an input with text)
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'z' && !e.shiftKey) {
        const active = document.activeElement;
        const isTyping =
          active &&
          (active.tagName === 'TEXTAREA' ||
            (active.tagName === 'INPUT' && active.value && active.value.length > 0));
        if (!isTyping) {
          e.preventDefault();
          if (this.onUndo) this.onUndo();
          return;
        }
      }

      // Ctrl+C -> Copy selected candidate path/URL when no text is selected (§3.1)
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c') {
        const sel = window.getSelection ? String(window.getSelection()) : '';
        if (!sel && this.candidateView.flatItems.length > 0) {
          const copied = this.candidateView.copySelectedCandidatePathOrUrl();
          if (copied) {
            e.preventDefault();
          }
        }
        return;
      }

      // Escape -> Close open modals or action menu
      if (e.key === 'Escape') {
        if (this.candidateView.actionMenuOpen) {
          this.candidateView.closeActionMenu();
          return;
        }
        if (this.onCloseModals && this.onCloseModals()) {
          e.preventDefault();
        }
      }
    });
  }
}
