// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';

import { RISK_LEVELS } from '../src/shared/constants.js';
import {
  clear,
  el,
  formatDateTime,
  indicatorCard,
  renderHighlightedText,
  riskBadge,
  safeHref,
  severityChip,
  showMessage,
} from '../src/shared/ui.js';
import { renderVerdictHeader, renderRiskReasons, renderUrlDisplay } from '../src/shared/verdictView.js';

/** Text ostil, folosit pentru a verifica lipsa injectării de HTML. */
const HOSTILE = '<img src=x onerror="alert(1)"><script>alert(2)</script>';

describe('el (construcție sigură de DOM)', () => {
  it('inserează textul ca nod de text, nu ca HTML', () => {
    const node = el('div', { class: 'x' }, HOSTILE);
    document.body.appendChild(node);
    expect(node.querySelector('img')).toBeNull();
    expect(node.querySelector('script')).toBeNull();
    expect(node.textContent).toBe(HOSTILE);
    // Nu se creează elemente, doar entități în HTML-ul serializat.
    expect(node.innerHTML).toContain('&lt;img');
    node.remove();
  });

  it('permite doar adrese sigure în href', () => {
    expect(safeHref('javascript:alert(1)')).toBe('#');
    expect(safeHref('data:text/html,x')).toBe('#');
    expect(safeHref('https://exemplu.ro/')).toBe('https://exemplu.ro/');
    expect(safeHref('#sectiune')).toBe('#sectiune');

    const link = el('a', { href: 'javascript:alert(1)' }, 'x');
    expect(link.getAttribute('href')).toBe('#');
  });

  it('atașează evenimente doar pentru funcții', () => {
    let clicked = 0;
    const button = el('button', { onclick: () => { clicked += 1; } }, 'apasă');
    button.click();
    expect(clicked).toBe(1);
  });

  it('ignoră copiii null/undefined/false', () => {
    const node = el('div', {}, [null, undefined, false, 'ok']);
    expect(node.textContent).toBe('ok');
  });
});

describe('renderHighlightedText', () => {
  it('evidențiază doar intervalele date, fără HTML injectat', () => {
    const container = el('div');
    renderHighlightedText(container, 'ab<script>cd', [{ start: 2, end: 10 }]);
    expect(container.querySelector('script')).toBeNull();
    const mark = container.querySelector('mark');
    expect(mark).not.toBeNull();
    expect(mark.textContent).toBe('<script>');
    expect(container.textContent).toBe('ab<script>cd');
  });

  it('nu evidențiază nimic pentru intervale invalide', () => {
    const container = el('div');
    renderHighlightedText(container, 'text', [{ start: -5, end: 2 }]);
    expect(container.querySelector('mark')).toBeNull();
    expect(container.textContent).toBe('text');
  });
});

describe('showMessage', () => {
  it('golește containerul și adaugă un notice cu text (nu HTML)', () => {
    const container = el('div');
    container.appendChild(el('span', {}, 'vechi'));
    showMessage(container, HOSTILE, 'danger');
    expect(container.querySelector('span')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('.notice.danger')).not.toBeNull();
    expect(container.textContent).toBe(HOSTILE);
  });
});

describe('riskBadge', () => {
  it('comunică riscul prin etichetă + simbol + scor, nu doar culoare', () => {
    const badge = riskBadge(RISK_LEVELS.HIGH, { score: 65 });
    expect(badge.textContent).toContain('Risc ridicat');
    expect(badge.textContent).toContain('scor 65');
    expect(badge.className).toContain('risk-high');
    expect(badge.querySelector('.risk-symbol')).not.toBeNull();
  });
});

describe('severityChip', () => {
  it('traduce severitatea în română', () => {
    expect(severityChip('critical').textContent).toBe('critic');
    expect(severityChip('info').textContent).toBe('informativ');
  });
});

describe('indicatorCard', () => {
  it('afișează explicații, limite și recomandări pentru un indicator', () => {
    const card = indicatorCard({
      ruleId: 'HOST-001',
      severity: 'high',
      title: 'Titlu',
      detail: 'Detaliu',
      why: 'Motiv',
      limits: 'Limită',
      recommendation: 'Recomandare',
      weight: 30,
    });
    expect(card.textContent).toContain('HOST-001');
    expect(card.textContent).toContain('De ce contează');
    expect(card.textContent).toContain('Limită');
    expect(card.querySelector('details')).not.toBeNull();
  });

  it('marchează indicatorii atenuați', () => {
    const card = indicatorCard({ ruleId: 'X', severity: 'low', title: 't', detail: 'd', suppressed: true, weight: 0 });
    expect(card.className).toContain('suppressed');
    expect(card.textContent).toContain('Atenuat');
  });
});

describe('formatDateTime', () => {
  it('întoarce o valoare lizibilă sau "necunoscut"', () => {
    expect(formatDateTime('nu-e-o-data')).toBe('necunoscut');
    expect(formatDateTime('')).toBe('necunoscut');
    expect(formatDateTime('2026-01-02T03:04:05.000Z')).not.toBe('necunoscut');
  });
});

describe('renderVerdictHeader + renderUrlDisplay (integrare)', () => {
  /** Verdict minimal, de test. */
  const verdict = {
    url: 'https://x<script>.example/cale',
    asciiHost: 'xn--xscript.example',
    unicodeHost: 'x<script>.example',
    registrableDomain: 'example',
    scheme: 'https',
    port: null,
    isIp: false,
    riskLevel: RISK_LEVELS.HIGH,
    riskLabel: 'Risc ridicat',
    riskDescription: 'desc',
    score: 65,
    summary: 'Rezumat',
    recommendation: 'Nu continua',
    indicators: [
      { ruleId: 'A', family: 'a', severity: 'high', weight: 30, title: 'T1', detail: 'D1' },
      { ruleId: 'B', family: 'b', severity: 'low', weight: 5, title: 'T2', detail: 'D2' },
    ],
    uncertainty: ['nota'],
    limits: ['limita'],
    facts: { unusualChars: [{ index: 8, char: '<' }] },
    analyzedAt: '2026-01-02T03:04:05.000Z',
  };

  it('redă antetul și adresa fără a crea elemente din text ostil', () => {
    const header = renderVerdictHeader(verdict);
    const urlBox = header.querySelector('#verdict-url');
    expect(urlBox).not.toBeNull();
    renderUrlDisplay(verdict, urlBox);
    expect(urlBox.querySelector('script')).toBeNull();
    expect(urlBox.querySelector('mark')).not.toBeNull();
    expect(header.textContent).toContain('Risc ridicat');
  });

  it('limitează motivele afișate în popup', () => {
    const reasons = renderRiskReasons(verdict, 1);
    expect(reasons.querySelectorAll('li').length).toBeGreaterThanOrEqual(1);
    expect(reasons.textContent).toContain('T1');
  });
});

describe('clear', () => {
  it('elimină toți copiii', () => {
    const container = el('div', {}, 'text');
    clear(container);
    expect(container.childNodes.length).toBe(0);
  });
});
