/**
 * IntentOS Wave 2 — Pure Offline Zero-XSS Markdown & Incremental Stream Renderer
 * Supports headings, lists, GFM tables, blockquotes, inline code, @mentions,
 * and fenced code blocks with 1-click Copy button. Zero external CDN dependencies.
 */

export function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Extract `<think>...</think>` blocks cleanly from model output (including partial streaming `<think>`).
 * @param {string} raw
 * @returns {{ thinking: string, reply: string }}
 */
export function splitThinkAndReply(raw) {
  const text = String(raw ?? '');
  const extracted = [];
  let cleaned = text.replace(/<think>([\s\S]*?)<\/think>/gi, (_m, inner) => {
    if (inner && inner.trim()) extracted.push(inner.trim());
    return '';
  });

  // Handle unclosed <think> while streaming
  const openIdx = cleaned.search(/<think>/i);
  if (openIdx !== -1) {
    const partial = cleaned.slice(openIdx + 7).trim();
    if (partial) extracted.push(partial);
    cleaned = cleaned.slice(0, openIdx);
  }

  return {
    thinking: extracted.join('\n\n').trim(),
    reply: cleaned.trim(),
  };
}

function isSafeUrl(url) {
  const trimmed = String(url || '').trim().toLowerCase();
  if (
    trimmed.startsWith('javascript:') ||
    trimmed.startsWith('data:') ||
    trimmed.startsWith('vbscript:')
  ) {
    return false;
  }
  return (
    trimmed.startsWith('https://') ||
    trimmed.startsWith('http://') ||
    trimmed.startsWith('mailto:') ||
    trimmed.startsWith('/') ||
    trimmed.startsWith('#')
  );
}

/**
 * Format escaped inline markdown tokens safely.
 * @param {string} rawLine
 * @returns {string}
 */
function formatInline(rawLine) {
  const codeTokens = [];
  // 1. Protect inline code spans first
  let working = String(rawLine ?? '').replace(/`([^`\n]+)`/g, (_m, code) => {
    const idx = codeTokens.length;
    codeTokens.push(`<code class="qc-inline-code">${escapeHtml(code)}</code>`);
    return `\u0000CODE_${idx}_\u0000`;
  });

  // 2. Escape remaining HTML
  working = escapeHtml(working);

  // 3. Safe Markdown links [text](url)
  working = working.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, label, rawHref) => {
    const unescapedHref = rawHref.replace(/&amp;/g, '&');
    if (!isSafeUrl(unescapedHref)) {
      return `${label} (${rawHref})`;
    }
    return `<a class="qc-md-link" href="${escapeHtml(unescapedHref)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
  });

  // 4. Bold, Italic, Strikethrough
  working = working.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  working = working.replace(/~~([^~]+)~~/g, '<del>$1</del>');
  working = working.replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s).,!?:;]|$)/g, '$1<em>$2</em>');

  // 5. Highlight @mentions (e.g. @周报.docx, @VSCode)
  working = working.replace(
    /(^|[\s(])@([\w\u4e00-\u9fa5._/-]{1,48})/g,
    '$1<span class="qc-mention-chip">@$2</span>'
  );

  // 6. Restore protected inline code spans
  working = working.replace(/\u0000CODE_(\d+)_\u0000/g, (_m, i) => codeTokens[Number(i)] || '');

  return working;
}

function parseTableCells(rowLine) {
  let trimmed = rowLine.trim();
  if (trimmed.startsWith('|')) trimmed = trimmed.slice(1);
  if (trimmed.endsWith('|')) trimmed = trimmed.slice(0, -1);
  return trimmed.split('|').map((c) => c.trim());
}

function isTableSeparator(line) {
  const trimmed = line.trim();
  if (!trimmed.includes('|')) return false;
  const cells = parseTableCells(trimmed);
  return cells.length > 0 && cells.every((c) => /^:?-{2,}:?$/.test(c));
}

/**
 * Render Markdown text into safe HTML string, storing raw code blocks in `codeStore` for 1-click Copy.
 * @param {string} markdown
 * @param {string[]} codeStore
 * @returns {string}
 */
function markdownToSafeHtml(markdown, codeStore) {
  const src = String(markdown ?? '').replace(/\r\n/g, '\n');
  if (!src.trim()) return '';

  const lines = src.split('\n');
  const htmlParts = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // 1. Fenced Code Block (```lang ... ```)
    const fenceMatch = line.match(/^\s*```([\w+-]*)\s*$/);
    if (fenceMatch) {
      const lang = (fenceMatch[1] || 'text').toLowerCase();
      const codeLines = [];
      i += 1;
      while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) {
        codeLines.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) i += 1; // skip closing ```
      const rawCode = codeLines.join('\n');
      const codeIdx = codeStore.length;
      codeStore.push(rawCode);

      htmlParts.push(`
        <div class="qc-code-block">
          <div class="qc-code-head">
            <span class="qc-code-lang">${escapeHtml(lang)}</span>
            <button type="button" class="qc-code-copy-btn" data-code-idx="${codeIdx}" title="复制代码">复制</button>
          </div>
          <pre class="qc-code-pre"><code>${escapeHtml(rawCode)}</code></pre>
        </div>
      `);
      continue;
    }

    // 2. Empty line
    if (!line.trim()) {
      i += 1;
      continue;
    }

    // 3. Horizontal rule
    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      htmlParts.push('<hr class="qc-md-hr" />');
      i += 1;
      continue;
    }

    // 4. Headings (# ~ ####)
    const hMatch = line.match(/^\s*(#{1,4})\s+(.+)$/);
    if (hMatch) {
      const level = Math.min(4, hMatch[1].length);
      htmlParts.push(`<h${level} class="qc-md-h${level}">${formatInline(hMatch[2].trim())}</h${level}>`);
      i += 1;
      continue;
    }

    // 5. GFM Table
    if (line.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const headers = parseTableCells(line);
      i += 2; // skip header + separator
      const rows = [];
      while (i < lines.length && lines[i].trim() && lines[i].includes('|')) {
        rows.push(parseTableCells(lines[i]));
        i += 1;
      }
      const theadHtml = `<thead><tr>${headers
        .map((h) => `<th>${formatInline(h)}</th>`)
        .join('')}</tr></thead>`;
      const tbodyHtml = `<tbody>${rows
        .map(
          (r) =>
            `<tr>${headers
              .map((_h, colIdx) => `<td>${formatInline(r[colIdx] ?? '')}</td>`)
              .join('')}</tr>`
        )
        .join('')}</tbody>`;
      htmlParts.push(`<div class="qc-table-wrap"><table class="qc-md-table">${theadHtml}${tbodyHtml}</table></div>`);
      continue;
    }

    // 6. Blockquote
    if (/^\s*>\s?/.test(line)) {
      const quoteLines = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
        quoteLines.push(lines[i].replace(/^\s*>\s?/, ''));
        i += 1;
      }
      htmlParts.push(
        `<blockquote class="qc-md-quote">${quoteLines.map((ql) => formatInline(ql)).join('<br/>')}</blockquote>`
      );
      continue;
    }

    // 7. Unordered list
    if (/^\s*[-*+]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*+]\s+/, ''));
        i += 1;
      }
      htmlParts.push(
        `<ul class="qc-md-ul">${items.map((it) => `<li>${formatInline(it)}</li>`).join('')}</ul>`
      );
      continue;
    }

    // 8. Ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ''));
        i += 1;
      }
      htmlParts.push(
        `<ol class="qc-md-ol">${items.map((it) => `<li>${formatInline(it)}</li>`).join('')}</ol>`
      );
      continue;
    }

    // 9. Paragraph (merge consecutive plain lines)
    const paraLines = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !/^\s*```/.test(lines[i]) &&
      !/^\s*#{1,4}\s+/.test(lines[i]) &&
      !/^\s*>\s?/.test(lines[i]) &&
      !/^\s*[-*+]\s+/.test(lines[i]) &&
      !/^\s*\d+\.\s+/.test(lines[i]) &&
      !/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(lines[i]) &&
      !(lines[i].includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1]))
    ) {
      paraLines.push(lines[i]);
      i += 1;
    }
    htmlParts.push(`<p class="qc-md-p">${paraLines.map((pl) => formatInline(pl)).join('<br/>')}</p>`);
  }

  return htmlParts.join('\n');
}

export async function copyTextSafe(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_) {}
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Render Markdown into a target DOM container and bind 1-click Copy buttons on fenced code blocks.
 * @param {HTMLElement} containerEl
 * @param {string} markdown
 */
export function renderMarkdown(containerEl, markdown) {
  if (!containerEl) return;
  const codeStore = [];
  containerEl.innerHTML = markdownToSafeHtml(markdown, codeStore);

  containerEl.querySelectorAll('.qc-code-copy-btn').forEach((btn) => {
    btn.onclick = async () => {
      const idx = Number(btn.getAttribute('data-code-idx'));
      const raw = codeStore[idx] ?? '';
      const ok = await copyTextSafe(raw);
      btn.textContent = ok ? '✓ 已复制' : '复制失败';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = '复制';
        btn.classList.remove('copied');
      }, 1500);
    };
  });
}

/**
 * Smoothly stream/reveal Markdown into `containerEl` like `gnome-quick-chat`, with instant completion on abort.
 * @param {HTMLElement} containerEl
 * @param {string} fullMarkdown
 * @param {{ signal?: AbortSignal, onStepScroll?: () => void }} [opts]
 * @returns {Promise<void>}
 */
export async function streamMarkdownInto(containerEl, fullMarkdown, opts = {}) {
  if (!containerEl) return;
  const text = String(fullMarkdown ?? '');
  if (text.length <= 36) {
    renderMarkdown(containerEl, text);
    if (opts.onStepScroll) opts.onStepScroll();
    return;
  }

  // Adaptive step size so even long answers finish crisply in ~280-550ms
  const totalFrames = Math.min(22, Math.max(8, Math.ceil(text.length / 45)));
  const charsPerFrame = Math.max(12, Math.ceil(text.length / totalFrames));
  let cursor = 0;

  await new Promise((resolve) => {
    const tick = () => {
      if (opts.signal && opts.signal.aborted) {
        renderMarkdown(containerEl, text);
        resolve();
        return;
      }
      cursor = Math.min(text.length, cursor + charsPerFrame);
      renderMarkdown(containerEl, text.slice(0, cursor));
      if (opts.onStepScroll) opts.onStepScroll();
      if (cursor >= text.length) {
        resolve();
        return;
      }
      setTimeout(tick, 18);
    };
    tick();
  });
}
