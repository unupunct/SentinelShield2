/**
 * SentinelShield2 - ajutoare de interfață partajate.
 *
 * Reguli de securitate aplicate aici (și testate):
 * - NICIODATĂ `innerHTML` cu date provenite din URL-uri sau din pagini web;
 *   tot textul extern trece prin `textContent` / noduri de text;
 * - linkurile externe sunt validate înainte de a fi puse în `href`;
 * - toate elementele interactive au etichetă accesibilă (text sau aria-label).
 */

import { RISK_LABELS, RISK_LEVELS } from './constants.js';
import { splitByRanges, truncate } from './validators.js';

/** Clasa CSS pentru un nivel de risc. */
export const RISK_CLASS = Object.freeze({
  [RISK_LEVELS.NONE]: 'risk-none',
  [RISK_LEVELS.LOW]: 'risk-low',
  [RISK_LEVELS.MODERATE]: 'risk-moderate',
  [RISK_LEVELS.HIGH]: 'risk-high',
  [RISK_LEVELS.CONFIRMED_DANGEROUS]: 'risk-confirmed',
});

/** Simboluri textuale pentru niveluri (nu ne bazăm doar pe culoare). */
export const RISK_SYMBOL = Object.freeze({
  [RISK_LEVELS.NONE]: '○',
  [RISK_LEVELS.LOW]: '▫',
  [RISK_LEVELS.MODERATE]: '▲',
  [RISK_LEVELS.HIGH]: '◆',
  [RISK_LEVELS.CONFIRMED_DANGEROUS]: '⛔',
});

/**
 * Permite doar adrese sigure ca `href`. Orice altceva devine `#`.
 * @param {unknown} value
 * @returns {string}
 */
export function safeHref(value) {
  if (typeof value !== 'string') return '#';
  const trimmed = value.trim();
  if (trimmed.startsWith('#')) return trimmed;
  if (/^(https?|mailto):/i.test(trimmed)) return trimmed;
  if (/^(about:blank|chrome:\/\/extensions)/i.test(trimmed)) return trimmed;
  return '#';
}

/**
 * Adaugă copii într-un nod, transformând textul în noduri de text (niciodată HTML).
 * @param {Node} node
 * @param {unknown} children
 * @returns {Node}
 */
function appendChildren(node, children) {
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined || child === false) continue;
    if (child instanceof Node) {
      node.appendChild(child);
    } else {
      node.appendChild(document.createTextNode(String(child)));
    }
  }
  return node;
}

/**
 * Construiește un element DOM în siguranță.
 * @param {string} tag
 * @param {object} [props]
 * @param {unknown} [children]
 * @returns {HTMLElement}
 */
export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') {
      node.className = String(value);
    } else if (key === 'text') {
      node.textContent = String(value);
    } else if (key === 'dataset') {
      for (const [dataKey, dataValue] of Object.entries(value)) {
        node.dataset[dataKey] = String(dataValue);
      }
    } else if (key === 'style') {
      for (const [styleKey, styleValue] of Object.entries(value)) {
        node.style.setProperty(styleKey, String(styleValue));
      }
    } else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === 'href') {
      node.setAttribute('href', safeHref(value));
    } else if (value === true) {
      node.setAttribute(key, '');
    } else {
      node.setAttribute(key, String(value));
    }
  }
  return appendChildren(node, children);
}

/**
 * @param {string} tag
 * @param {object} [props]
 * @param {unknown} [children]
 * @returns {HTMLElement}
 */
export function h(tag, props = {}, children = []) {
  return el(tag, props, children);
}

/** Golește un container. */
export function clear(node) {
  if (node) node.replaceChildren();
  return node;
}

/**
 * Afișează un text cu intervalele suspecte evidențiate, fără HTML.
 * @param {HTMLElement} container
 * @param {string} text
 * @param {Array<{start: number, end: number}>} [ranges]
 * @param {{ limit?: number }} [options]
 * @returns {HTMLElement}
 */
export function renderHighlightedText(container, text, ranges = [], options = {}) {
  clear(container);
  const limit = options.limit ?? 0;
  const source = limit > 0 ? truncate(text, limit) : String(text ?? '');
  const parts = splitByRanges(source, ranges);
  if (parts.length === 0) {
    container.appendChild(document.createTextNode(''));
    return container;
  }
  for (const part of parts) {
    if (part.highlighted) {
      container.appendChild(el('mark', { title: 'Caracter neobișnuit' }, part.text));
    } else {
      container.appendChild(document.createTextNode(part.text));
    }
  }
  return container;
}

/**
 * Insignă cu nivelul de risc: culoare + simbol + etichetă text.
 * @param {string} level
 * @param {{ score?: number }} [options]
 * @returns {HTMLElement}
 */
export function riskBadge(level, options = {}) {
  const label = RISK_LABELS[level] ?? String(level);
  const scorePart = Number.isFinite(options.score) ? ` · scor ${options.score}` : '';
  return el('span', {
    class: `risk-badge ${RISK_CLASS[level] ?? 'risk-none'}`,
    title: label,
  }, [
    el('span', { 'aria-hidden': 'true', class: 'risk-symbol' }, RISK_SYMBOL[level] ?? '○'),
    el('span', {}, `${label}${scorePart}`),
  ]);
}

/** Etichetă de severitate pentru un indicator. */
export function severityChip(severity) {
  const labels = {
    info: 'informativ',
    low: 'scăzut',
    medium: 'moderat',
    high: 'ridicat',
    critical: 'critic',
  };
  return el('span', { class: `severity severity-${severity}` }, labels[severity] ?? String(severity));
}

/**
 * Card pentru un indicator de risc, cu explicații și limite.
 * @param {object} indicator
 * @param {{ showEvidence?: boolean }} [options]
 * @returns {HTMLElement}
 */
export function indicatorCard(indicator, options = {}) {
  const children = [
    el('div', { class: 'row between' }, [
      el('span', { class: 'indicator-title' }, indicator.title ?? ''),
      el('div', { class: 'row' }, [
        severityChip(indicator.severity),
        el('span', { class: 'chip' }, indicator.ruleId ?? ''),
      ]),
    ]),
    el('p', { class: 'small' }, indicator.detail ?? ''),
  ];

  if (indicator.suppressed === true) {
    children.push(el('p', { class: 'small faint' }, [
      'Atenuat: aceeași caracteristică este deja raportată de un indicator mai puternic, deci nu se adună la scor.',
    ]));
  }

  const details = [];
  if (indicator.why) {
    details.push(el('div', {}, [el('h3', {}, 'De ce contează'), el('p', { class: 'small muted' }, indicator.why)]));
  }
  if (indicator.limits) {
    details.push(el('div', {}, [el('h3', {}, 'Limite și fals pozitiv posibil'), el('p', { class: 'small muted' }, indicator.limits)]));
  }
  if (indicator.recommendation) {
    details.push(el('div', {}, [el('h3', {}, 'Ce poți face'), el('p', { class: 'small muted' }, indicator.recommendation)]));
  }
  if (options.showEvidence && indicator.evidence && Object.keys(indicator.evidence).length > 0) {
    details.push(el('div', {}, [
      el('h3', {}, 'Dovezi (fără date sensibile)'),
      el('pre', { class: 'mono small' }, JSON.stringify(indicator.evidence, null, 2)),
    ]));
  }
  if (details.length > 0) {
    children.push(el('details', {}, [
      el('summary', {}, 'Explicații, limite și recomandări'),
      ...details,
    ]));
  }

  return el('article', { class: `indicator sev-${indicator.severity ?? 'info'}${indicator.suppressed ? ' suppressed' : ''}` }, children);
}

/**
 * Traduce o potrivire din liste într-un text pentru utilizator.
 * @param {{type: string, entry: object, matchKind: string}|null} match
 * @returns {string}
 */
export function describeListMatch(match) {
  if (!match) return '';
  const scope = match.matchKind === 'subdomain' ? 'și subdomeniile ei' : 'exact';
  const listName = match.type === 'blocklist' ? 'lista de blocare' : 'lista de încredere';
  return `${match.entry.host} (${scope}) se află în ${listName}.`;
}

/**
 * Formatează o dată ISO în format local, lizibil.
 * @param {string} iso
 * @returns {string}
 */
export function formatDateTime(iso) {
  if (typeof iso !== 'string' || iso === '') return 'necunoscut';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return 'necunoscut';
  try {
    return date.toLocaleString('ro-RO', { dateStyle: 'short', timeStyle: 'medium' });
  } catch {
    return date.toISOString();
  }
}

/**
 * Trimite un mesaj către service worker, cu tratarea erorilor.
 * @param {object} message
 * @returns {Promise<object>}
 */
export async function send(message) {
  try {
    const response = await chrome.runtime.sendMessage(message);
    if (!response) return { ok: false, error: 'Service worker-ul nu a răspuns.' };
    return response;
  } catch (error) {
    return { ok: false, error: `Comunicarea cu extensia a eșuat: ${String(error?.message ?? error)}` };
  }
}

/**
 * Afișează un mesaj de stare într-un container.
 * @param {HTMLElement} container
 * @param {string} text
 * @param {'info'|'ok'|'danger'} [tone]
 * @returns {HTMLElement}
 */
export function showMessage(container, text, tone = 'info') {
  clear(container);
  container.appendChild(el('p', { class: `notice ${tone}` }, text));
  return container;
}
