/**
 * SentinelShield2 - redarea unui verdict.
 *
 * Modul partajat de popup, pagina de detalii și pagina de avertizare, pentru ca
 * explicațiile să fie identice și consecvente. Folosește exclusiv `ui.js`, care
 * nu construiește niciodată HTML din text extern.
 */

import { RISK_LEVELS } from './constants.js';
import {
  clear,
  el,
  formatDateTime,
  indicatorCard,
  riskBadge,
  severityChip,
} from './ui.js';
import { splitByRanges, truncate } from './validators.js';

/**
 * Adresa analizată, cu caracterele neobișnuite evidențiate.
 * @param {object} verdict
 * @param {HTMLElement} container
 * @param {{ limit?: number }} [options]
 * @returns {HTMLElement}
 */
export function renderUrlDisplay(verdict, container, options = {}) {
  clear(container);
  const text = options.limit ? truncate(verdict.url, options.limit) : String(verdict.url ?? '');
  const ranges = (verdict.facts?.unusualChars ?? []).map((c) => ({ start: c.index, end: c.index + c.char.length }));
  const parts = splitByRanges(text, ranges);
  for (const part of parts) {
    if (part.highlighted) {
      container.appendChild(el('mark', { title: 'Caracter neobișnuit în adresă' }, part.text));
    } else {
      container.appendChild(document.createTextNode(part.text));
    }
  }
  return container;
}

/**
 * Antetul verdictului: insigna de risc, adresa, rezumatul și recomandarea.
 * @param {object} verdict
 * @param {{ showScore?: boolean, urlLimit?: number }} [options]
 * @returns {HTMLElement}
 */
export function renderVerdictHeader(verdict, options = {}) {
  const score = options.showScore === false ? undefined : verdict.score;
  return el('div', { class: 'stack' }, [
    el('div', { class: 'row between' }, [
      riskBadge(verdict.riskLevel, { score }),
      el('span', { class: 'small faint' }, `Verificat: ${formatDateTime(verdict.analyzedAt)}`),
    ]),
    el('div', { class: 'url-display', id: 'verdict-url' }, []),
    el('p', { class: 'small muted' }, verdict.riskDescription ?? ''),
    el('p', {}, verdict.summary ?? ''),
    verdict.recommendation ? el('p', { class: 'notice accent' }, verdict.recommendation) : null,
    verdict.caveat ? el('p', { class: 'small faint' }, verdict.caveat) : null,
  ]);
}

/**
 * Completează adresa evidențiată în elementul deja construit de `renderVerdictHeader`.
 * @param {HTMLElement} root
 * @param {object} verdict
 * @param {{ urlLimit?: number }} [options]
 */
export function fillUrlDisplay(root, verdict, options = {}) {
  const target = root.querySelector('#verdict-url');
  if (target) renderUrlDisplay(verdict, target, options);
}

/**
 * Detalii despre domeniu (formă Unicode, domeniu registrabil, listă).
 * @param {object} verdict
 * @returns {HTMLElement}
 */
export function renderDomainDetails(verdict) {
  const rows = [];
  const add = (term, value) => {
    if (!value) return;
    rows.push(el('dt', {}, term));
    rows.push(el('dd', { class: 'mono' }, value));
  };
  add('Adresă introdusă', verdict.url);
  add('Formă ASCII (Punycode)', verdict.asciiHost);
  if (verdict.unicodeHost && verdict.unicodeHost !== verdict.asciiHost) {
    add('Formă afișată (Unicode)', verdict.unicodeHost);
  }
  add('Domeniu principal', verdict.registrableDomain);
  if (verdict.port !== null && verdict.port !== undefined) add('Port', String(verdict.port));
  if (verdict.lists?.allowlisted) add('Listă', `lista de încredere: ${verdict.lists.matchedHost}`);
  if (verdict.lists?.blocklisted) add('Listă', `lista de blocare: ${verdict.lists.matchedHost}`);
  return el('dl', { class: 'mono small' }, rows);
}

/**
 * Lista indicatorilor, cu explicații.
 * @param {object} verdict
 * @param {{ showEvidence?: boolean, limit?: number }} [options]
 * @returns {HTMLElement}
 */
export function renderIndicators(verdict, options = {}) {
  const indicators = options.limit ? verdict.indicators.slice(0, options.limit) : verdict.indicators;
  if (indicators.length === 0) {
    return el('p', { class: 'small muted' }, 'Nu am identificat indicii cunoscute de risc pentru această adresă.');
  }
  return el('div', {}, indicators.map((indicator) => indicatorCard(indicator, {
    showEvidence: options.showEvidence === true,
  })));
}

/**
 * Secțiunea de incertitudine: ce NU putem ști din această analiză.
 * @param {object} verdict
 * @returns {HTMLElement}
 */
export function renderUncertainty(verdict) {
  const items = (verdict.uncertainty ?? []).map((note) => el('li', {}, note));
  const limits = (verdict.limits ?? []).map((limit) => el('li', {}, limit));
  return el('div', {}, [
    el('h2', {}, 'Incertitudinea rezultatului'),
    el('ul', { class: 'small muted' }, items),
    el('details', {}, [
      el('summary', {}, 'Limitele tehnice ale detecției și ale blocării'),
      el('ul', { class: 'small muted' }, limits),
    ]),
  ]);
}

/**
 * Secțiunea despre sursa de reputație (dacă a fost folosită).
 * @param {object} verdict
 * @returns {HTMLElement|null}
 */
export function renderReputation(verdict) {
  const reputation = verdict.reputation;
  if (!reputation) {
    return el('p', { class: 'small muted' }, 'Nu a fost folosită nicio sursă de reputație externă. Analiza este strict locală.');
  }
  const rows = [
    el('dt', {}, 'Sursă'),
    el('dd', {}, reputation.provider || 'nespecificată'),
    el('dt', {}, 'Verdict'),
    el('dd', {}, reputation.verdict),
    el('dt', {}, 'Confirmat'),
    el('dd', {}, reputation.confirmed ? 'da (sursă autoritară declarată de tine)' : 'nu'),
    el('dt', {}, 'Date trimise'),
    el('dd', { class: 'mono' }, reputation.dataSent || 'niciuna'),
  ];
  if (reputation.confidence !== null && reputation.confidence !== undefined) {
    rows.push(el('dt', {}, 'Încredere raportată'));
    rows.push(el('dd', {}, String(reputation.confidence)));
  }
  if (reputation.error) {
    rows.push(el('dt', {}, 'Eroare'));
    rows.push(el('dd', {}, reputation.error));
  }
  return el('div', {}, [
    el('h2', {}, 'Sursa de reputație'),
    el('dl', { class: 'small' }, rows),
  ]);
}

/**
 * Lista motivelor de risc, compactă (pentru popup).
 * @param {object} verdict
 * @param {number} [limit]
 * @returns {HTMLElement}
 */
export function renderRiskReasons(verdict, limit = 3) {
  const relevant = verdict.indicators.filter((indicator) => indicator.weight > 0);
  const selected = relevant.slice(0, limit);
  const children = selected.map((indicator) => el('li', {}, [
    severityChip(indicator.severity),
    ' ',
    el('span', {}, indicator.title),
    el('div', { class: 'small muted' }, indicator.detail),
  ]));
  if (children.length === 0) {
    return el('p', { class: 'small muted' }, 'Fără indicatori cu impact asupra scorului.');
  }
  const container = el('ul', { class: 'list' }, children);
  if (relevant.length > limit) {
    container.appendChild(el('li', { class: 'small faint' }, `... și încă ${relevant.length - limit} indicatori, în pagina de detalii.`));
  }
  return container;
}

/**
 * Explică nivelul "Fără indicatori evidenți de risc" fără a promite siguranță.
 * @param {object} verdict
 * @returns {HTMLElement|null}
 */
export function renderNoSignalNotice(verdict) {
  if (verdict.riskLevel !== RISK_LEVELS.NONE) return null;
  return el('p', { class: 'notice' }, 'Nu am identificat indicii cunoscute de risc. Aceasta NU este o garanție că site-ul este sigur.');
}
