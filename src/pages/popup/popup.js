import { $, el, clear, send, levelBadge, renderIndicators, renderSources, renderThirdParties, renderPermissions, renderEvents, fmtTime, openDashboard } from '../../shared/ui.js';

const app = $('#app');
let tab = null;

$('#settings').addEventListener('click', () => { chrome.runtime.openOptionsPage(); window.close(); });

function section(title, node, open = false) {
  return el('details', { class: 'sec', open }, el('summary', { text: title }), node);
}

async function load(analyze = false) {
  // `?tab=<id>` permite deschiderea raportului pentru o filă anume (folosit la testarea automată); implicit, fila activă.
  const forced = Number(new URLSearchParams(location.search).get('tab'));
  try { tab = Number.isInteger(forced) && forced > 0 ? await chrome.tabs.get(forced) : (await chrome.tabs.query({ active: true, currentWindow: true }))[0]; } catch { tab = null; }
  if (!tab) { app.textContent = 'Nu există o filă activă.'; return; }
  const msg = { type: analyze ? 'ss.analyzePage' : 'ss.getTabReport', tabId: tab.id, url: tab.url ?? '' };
  const r = await send(msg);
  const ev = await send({ type: 'ss.getEvents', limit: 5 });
  render(r, ev?.events ?? []);
}

function render(r, events) {
  clear(app);
  if (!r?.ok || r.empty) {
    app.append(el('div', { class: 'panel' }, el('p', { text: 'Nu există încă o analiză pentru această pagină.' }), el('p', { class: 'small muted', text: 'Paginile interne ale browserului nu sunt analizate. Pentru un site web, apasă „Analizează pagina”.' })), actions(null), recent(events));
    return;
  }
  const hasBehavior = r.behavior?.hasData;
  app.append(levelBadge(r.level, { confirmed: r.confirmed }),
    el('div', { class: 'domain' }, el('div', { class: 'host mono', text: r.hostUnicode || r.host || r.url }), r.punycode ? el('div', { class: 'small muted mono', text: `Punycode: ${r.punycode}` }) : null),
    el('p', { text: r.userExplanation || r.summary }),
    el('p', { class: 'small muted', text: `Verificat la ${fmtTime(r.checkedAt)} · scor euristic ${r.score}` }),
    actions(r));
  if (r.exception) app.append(el('div', { class: 'notice info', text: `Pentru acest domeniu există o excepție utilizator (${r.exception.kind === 'confirmed' ? 'peste o amenințare confirmată' : 'alertă euristică'}).` }));

  const findings = (r.behavior?.findings ?? []).map((f) => ({ ...f, severity: f.score >= 30 ? 'high' : f.score >= 15 ? 'medium' : f.score > 0 ? 'low' : 'info', explain: f.explainUser, code: f.id }));
  const ind = el('div'); renderIndicators(ind, [...r.indicators.filter((i) => i.severity !== 'info'), ...findings], { technical: false });
  const src = el('div'); renderSources(src, r.sources);
  const perm = el('div'); renderPermissions(perm, r.behavior?.permissions?.filter((p) => p.requested || p.browserState === 'granted' || p.level !== 'none'));
  const tp = el('div'); renderThirdParties(tp, r.behavior?.thirdParties);
  const red = el('div'); if (r.redirects.length > 1) r.redirects.forEach((h, i) => red.append(el('p', { class: 'small mono', text: `${i + 1}. ${h.url} (${h.kind})` }))); else red.append(el('p', { class: 'empty', text: 'Nicio redirecționare observată.' }));
  app.append(section(`Indicatori și constatări (${r.indicators.filter((i) => i.severity !== 'info').length + (r.behavior?.findings?.length ?? 0)})`, ind, r.level !== 'SAFE'),
    section('Permisiuni solicitate sau acordate', hasBehavior ? perm : el('p', { class: 'empty', text: 'Nu există încă date comportamentale (pagina nu a transmis observații).' })),
    section('Domenii terțe', hasBehavior ? tp : el('p', { class: 'empty', text: 'Nu există încă date.' })),
    section('Surse de verificare', src), section('Redirecționări', red), section('Ultimele evenimente de securitate', recentList(events)));
}

function recentList(events) { const d = el('div'); renderEvents(d, events); return d; }
function recent(events) { return section('Ultimele evenimente de securitate', recentList(events), true); }

function actions(r) {
  const row = el('div', { class: 'actions' },
    el('button', { class: 'primary', id: 'analyze', text: 'Analizează pagina', on: { click: async (e) => { e.target.disabled = true; e.target.textContent = 'Se analizează…'; await load(true); } } }),
    el('button', { text: 'Vezi raportul complet', on: { click: () => { openDashboard(`#report=${tab.id}&u=${encodeURIComponent(tab.url ?? '')}`); window.close(); } } }));
  if (r && (r.level === 'SUSPICIOUS' || r.level === 'DANGEROUS') && !r.exception && r.host && /^https?:/.test(tab.url ?? '')) {
    row.append(el('button', { class: 'ghost small', text: 'Marchează ca de încredere (doar acest domeniu și protocol)', on: { click: () => trust(r) } }));
  }
  return row;
}

async function trust(r) {
  const u = new URL(tab.url); const scheme = u.protocol.replace(':', '');
  let res = await send({ type: 'ss.addException', host: r.host, scheme, kind: 'heuristic', ttlDays: 30 });
  if (res?.error === 'confirmed-requires-ack') {
    if (!confirm(`ATENȚIE: ${r.host} este listat ca PERICULOS într-o sursă de reputație.\n\nA-l marca drept de încredere dezactivează avertizarea pentru acest domeniu (doar pentru ${scheme}://, nu pentru subdomenii). Protecțiile pentru descărcări rămân active.\n\nSigur continui?`)) return;
    res = await send({ type: 'ss.addException', host: r.host, scheme, kind: 'confirmed', acknowledged: true, ttlDays: 7 });
  }
  if (res?.ok) await load();
}

load();
