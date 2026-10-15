// Ajutoare UI. REGULĂ: nu se construiește HTML din șiruri cu date externe; totul se afișează prin textContent / noduri DOM.
export const $ = (sel, root = document) => root.querySelector(sel);

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v == null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k in node && k !== 'list' && k !== 'form') { try { node[k] = v; } catch { node.setAttribute(k, String(v)); } }
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) if (c != null && c !== false) node.append(c.nodeType ? c : document.createTextNode(String(c)));
  return node;
}
export const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

export async function send(msg) {
  try { return await chrome.runtime.sendMessage(msg); } catch (e) { return { ok: false, error: 'no-response' }; }
}

export const LEVEL = {
  SAFE: { label: 'Risc redus', icon: '✓', cls: 'safe', note: 'Nu au fost identificați indicatori semnificativi. Siguranța absolută nu poate fi garantată.' },
  SUSPICIOUS: { label: 'Suspect', icon: '!', cls: 'suspicious', note: 'Există indicatori care necesită atenție.' },
  DANGEROUS: { label: 'Periculos', icon: '✕', cls: 'dangerous', note: 'Dovezi puternice sau confirmare dintr-o sursă de reputație.' },
  UNKNOWN: { label: 'Neverificat', icon: '?', cls: 'unknown', note: 'Informațiile disponibile sunt insuficiente sau verificarea a eșuat.' }
};
export const CLASS_LABEL = {
  CONFIRMED: 'Amenințare confirmată', SUSPICIOUS: 'Comportament suspect', POTENTIAL: 'Risc potențial',
  LEGITIMATE: 'Observat, dar legitim', INSUFFICIENT: 'Informații insuficiente'
};
export const SEVERITY_LABEL = { high: 'Sever', medium: 'Mediu', low: 'Redus', info: 'Informativ' };
export const CATEGORY_LABEL = { url: 'Adresă', reputation: 'Reputație', redirect: 'Redirecționare', download: 'Descărcare', permission: 'Permisiune', 'data-access': 'Acces la date', behavior: 'Comportament', form: 'Formular', content: 'Conținut', network: 'Rețea' };

export function levelBadge(level, { confirmed = false, note = true } = {}) {
  const m = LEVEL[level] ?? LEVEL.UNKNOWN;
  return el('div', { class: `level ${m.cls}`, role: 'status' },
    el('div', { class: 'icon', 'aria-hidden': 'true', text: m.icon }),
    el('div', {}, el('div', { class: 'name', text: `${m.label}${confirmed ? ' — amenințare confirmată' : ''}` }),
      note ? el('div', { class: 'sub', text: confirmed ? 'Confirmat de o sursă de reputație.' : level === 'DANGEROUS' ? 'Indicatori tehnici puternici; nu este confirmat de o sursă de reputație.' : m.note }) : null));
}

export function fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString('ro-RO', { dateStyle: 'short', timeStyle: 'medium' }); } catch { return String(ts); }
}

function fmtVal(v) {
  if (v == null) return '—';
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch { return '[obiect]'; } }
  return String(v);
}

/** Nivelul 2: detalii tehnice într-o listă de definiții. */
export function techList(obj) {
  const entries = Object.entries(obj ?? {}).filter(([, v]) => v !== undefined);
  if (!entries.length) return null;
  const dl = el('dl');
  for (const [k, v] of entries) dl.append(el('dt', { text: k }), el('dd', { text: fmtVal(v) }));
  return dl;
}

/** Listă de indicatori: nivel 1 (explicație) + nivel 2 (detalii tehnice, în <details>). */
export function renderIndicators(container, indicators, { technical = true, openFirst = false } = {}) {
  clear(container);
  const list = (indicators ?? []).filter(Boolean);
  if (!list.length) { container.append(el('p', { class: 'empty', text: 'Nu a fost identificat niciun indicator.' })); return; }
  list.forEach((i, idx) => {
    const d = el('details', { class: 'ind', open: openFirst && idx === 0 });
    d.append(el('summary', {}, el('span', { class: `chip ${i.severity}`, text: SEVERITY_LABEL[i.severity] ?? i.severity }), el('span', { class: `chip ${i.classification}`, text: CLASS_LABEL[i.classification] ?? i.classification }), el('strong', { text: i.title })));
    const body = el('div', { class: 'body' }, el('p', { text: i.explain ?? i.explainUser ?? '' }));
    if (i.recommendation) body.append(el('p', { class: 'small muted', text: `Recomandare: ${i.recommendation}` }));
    if (technical) {
      const tl = techList({ cod: i.code, ...(i.technical ?? {}) });
      if (tl) body.append(el('h3', { text: 'Detalii tehnice' }), tl);
    }
    d.append(body); container.append(d);
  });
}

export function renderSources(container, sources) {
  clear(container);
  if (!sources?.length) { container.append(el('p', { class: 'empty', text: 'Nicio sursă consultată.' })); return; }
  const t = el('table');
  t.append(el('thead', {}, el('tr', {}, el('th', { text: 'Sursă' }), el('th', { text: 'Rezultat' }), el('th', { text: 'Verificat la' }))));
  const tb = el('tbody');
  for (const s of sources) {
    tb.append(el('tr', {}, el('td', { text: s.name }), el('td', {}, el('span', { text: s.statusLabel ?? s.status }), s.detail ? el('div', { class: 'small muted', text: s.detail }) : null), el('td', { text: fmtTime(s.checkedAt) })));
  }
  t.append(tb); container.append(t);
}

export function renderThirdParties(container, tp) {
  clear(container);
  const obs = tp?.observed ?? []; const decl = tp?.declaredOnly ?? [];
  if (!obs.length && !decl.length) { container.append(el('p', { class: 'empty', text: 'Nu au fost observate domenii terțe (sau nu există încă date).' })); return; }
  const block = (title, items, evidenceText) => {
    if (!items.length) return;
    container.append(el('h3', { text: `${title} (${items.length})` }), el('p', { class: 'small muted', text: evidenceText }));
    const t = el('table'); t.append(el('thead', {}, el('tr', {}, el('th', { text: 'Domeniu' }), el('th', { text: 'Tip' }), el('th', { text: 'Observații' }))));
    const tb = el('tbody');
    for (const x of items) tb.append(el('tr', {}, el('td', { class: 'mono', text: x.registrable }), el('td', { text: x.types.join(', ') }),
      el('td', {}, x.listed ? el('span', { class: 'chip CONFIRMED', text: 'listat ca malițios' }) : null, x.tracker ? el('span', { class: 'chip POTENTIAL', text: x.tracker }) : null, !x.listed && !x.tracker && x.heuristicScore >= 15 ? el('span', { class: 'chip SUSPICIOUS', text: 'indicatori suspecți' }) : null, x.count ? el('span', { class: 'small muted', text: ` ${x.count} cereri` }) : null)));
    t.append(tb); container.append(t);
  };
  block('Domenii contactate (observat)', obs, 'Conexiuni efectiv observate în această pagină.');
  block('Referințe în pagină (deduse, neobservate)', decl, 'Domenii menționate în codul paginii pentru care nu am observat o conexiune: este doar o inferență.');
}

const PERM_LEVEL = { 'api-available': 'API disponibil', requested: 'Cerere observată', 'permission-granted': 'Permisiune acordată în browser', 'access-obtained': 'Acces obținut (apel reușit)', none: 'Indisponibil / necunoscut' };
const JUST = { likely: 'probabil justificată', unlikely: 'neobișnuită', unknown: 'nu se poate stabili' };
export function renderPermissions(container, rows) {
  clear(container);
  if (!rows?.length) { container.append(el('p', { class: 'empty', text: 'Nu există încă date despre permisiuni pentru această pagină.' })); return; }
  const t = el('table'); t.append(el('thead', {}, el('tr', {}, el('th', { text: 'Permisiune' }), el('th', { text: 'Stare observată' }), el('th', { text: 'Justificare' }))));
  const tb = el('tbody');
  for (const r of rows) {
    tb.append(el('tr', {}, el('td', { text: r.label }),
      el('td', {}, el('div', { text: PERM_LEVEL[r.level] ?? r.level }), r.outcome ? el('div', { class: 'small muted', text: `Răspuns: ${r.outcome === 'granted' ? 'acordat' : r.outcome === 'denied' ? 'refuzat' : 'neobservat'}` }) : null,
        el('div', { class: 'small muted', text: `Browser: ${r.browserState}` })),
      el('td', { text: r.requested || r.browserState === 'granted' ? JUST[r.justified] : '—' })));
  }
  t.append(tb); container.append(t,
    el('p', { class: 'small muted', text: 'Distincție: „API disponibil” nu înseamnă cerere; „cerere” nu înseamnă acces; iar ce face pagina cu datele (utilizare) nu poate fi confirmat de o extensie.' }));
}

export function renderEvents(container, events, { onSelect } = {}) {
  clear(container);
  if (!events?.length) { container.append(el('p', { class: 'empty', text: 'Nu există încă date.' })); return; }
  for (const e of events) {
    const m = LEVEL[e.level] ?? LEVEL.UNKNOWN;
    const d = el('details', { class: 'ind' });
    d.append(el('summary', {}, el('span', { class: `chip ${e.level === 'DANGEROUS' ? 'high' : e.level === 'SUSPICIOUS' ? 'medium' : 'low'}`, text: `${m.icon} ${m.label}` }), el('span', { class: 'small muted', text: fmtTime(e.ts) }), el('strong', { text: e.summary || e.type })));
    const body = el('div', { class: 'body' });
    body.append(el('p', { class: 'mono small', text: e.url ?? e.host ?? '' }), el('p', { text: e.userExplanation }));
    if (e.recommendation) body.append(el('p', { class: 'small muted', text: `Recomandare: ${e.recommendation}` }));
    body.append(el('p', { class: 'small muted', text: `Tip: ${e.type} · Acțiune: ${e.action}` }));
    const ind = el('div'); renderIndicators(ind, e.indicators); body.append(ind);
    const src = el('div'); renderSources(src, e.sources.map((s) => ({ ...s, statusLabel: s.status }))); if (e.sources.length) body.append(el('h3', { text: 'Surse' }), src);
    d.append(body); container.append(d);
    d.addEventListener('toggle', () => { if (d.open && onSelect) onSelect(e); });
  }
}

export function openDashboard(hash = '') {
  return chrome.tabs.create({ url: chrome.runtime.getURL(`src/pages/dashboard/dashboard.html${hash}`) });
}

/** Afișează un nume de gazdă Unicode cu caracterele non-ASCII evidențiate (ca un omograf să nu arate identic cu originalul). */
export function hostWithMarkedChars(host) {
  const box = el('span', { class: 'mono' });
  for (const ch of host) {
    if (ch.codePointAt(0) > 127) box.append(el('mark', { class: 'nonascii', title: `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')} (non-ASCII)`, text: ch }));
    else box.append(ch);
  }
  return box;
}
