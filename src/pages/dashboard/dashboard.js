import { $, el, clear, send, LEVEL, levelBadge, renderIndicators, renderSources, renderThirdParties, renderPermissions, renderEvents, fmtTime, techList } from '../../shared/ui.js';

const TABS = [['overview', 'Prezentare'], ['history', 'Istoric alerte'], ['report', 'Raport pagină'], ['trust', 'Liste de încredere'], ['sources', 'Surse externe'], ['privacy', 'Confidențialitate'], ['protection', 'Protecție']];
const panel = $('#panel');
const tabsEl = $('#tabs');
let current = 'overview';

/* ---------------------------------------------------------------- navigare */
function buildTabs() {
  clear(tabsEl);
  TABS.forEach(([id, label]) => tabsEl.append(el('button', { role: 'tab', id: `tab-${id}`, 'aria-selected': String(id === current), 'aria-controls': 'panel', tabIndex: id === current ? 0 : -1, text: label, on: { click: () => go(id), keydown: (e) => {
    const i = TABS.findIndex((t) => t[0] === id); const n = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : null;
    if (n != null) { const t = TABS[(n + TABS.length) % TABS.length][0]; go(t); $(`#tab-${t}`).focus(); }
  } } })));
}
function go(id) { current = id; if (!location.hash.startsWith('#report=') || id !== 'report') history.replaceState(null, '', `#tab=${id}`); buildTabs(); VIEWS[id](); }

const status = (n, text, ok = true) => { n.textContent = text; n.className = ok ? 'small' : 'small notice'; };
async function cfg() { return (await send({ type: 'ss.getConfig' })).config; }
async function save(patch, out) { const r = await send({ type: 'ss.setConfig', patch }); if (out) status(out, r?.ok ? 'Salvat.' : 'Salvarea a eșuat.', !!r?.ok); return r; }
const field = (label, input, id) => el('div', {}, el('label', { for: id, text: label }), input);
const check = (id, label, checked, hint) => el('label', { class: 'inline', for: id }, el('input', { type: 'checkbox', id, checked }), el('span', {}, label, hint ? el('div', { class: 'small muted', text: hint }) : null));

/* ---------------------------------------------------------------- prezentare */
async function overview() {
  clear(panel);
  const [s, ls] = await Promise.all([send({ type: 'ss.getStats' }), send({ type: 'ss.getListStatus' })]);
  const st = s.stats;
  panel.append(el('h2', { text: 'Prezentare' }));
  if (!st.total && !st.analyzed) panel.append(el('p', { class: 'empty', text: 'Nu există încă date. Statisticile apar pe măsură ce navighezi; nimic nu este inventat sau preîncărcat.' }));
  else {
    const grid = el('div', { class: 'grid' });
    grid.append(el('div', { class: 'stat' }, el('div', { class: 'n', text: String(st.analyzed) }), el('div', { text: 'pagini analizate' }), el('div', { class: 'small muted', text: st.since ? `din ${fmtTime(st.since)} (doar contor, fără URL-uri)` : '' })));
    for (const lv of ['DANGEROUS', 'SUSPICIOUS', 'UNKNOWN']) grid.append(el('div', { class: `stat ${lv}` }, el('div', { class: 'n', text: String(st.byLevel[lv] ?? 0) }), el('div', { text: `alerte „${LEVEL[lv].label}”` })));
    panel.append(grid);
    const days = Object.entries(st.byDay).sort().slice(-14);
    const max = Math.max(1, ...days.map((d) => d[1]));
    const box = el('div', { class: 'panel' }, el('h3', { text: 'Alerte pe zile (ultimele 14 cu activitate)' }));
    if (!days.length) box.append(el('p', { class: 'empty', text: 'Nu există încă date.' }));
    for (const [d, n] of days) box.append(el('div', { class: 'barrow' }, el('span', { class: 'small', text: d }), el('div', {}, el('div', { class: 'bar', style: `width:${(n / max) * 100}%` })), el('span', { text: String(n) })));
    panel.append(box);
    const top = el('div', { class: 'panel' }, el('h3', { text: 'Cei mai frecvenți indicatori' }));
    if (!st.topIndicators.length) top.append(el('p', { class: 'empty', text: 'Nu există încă date.' }));
    else { const t = el('table'); for (const x of st.topIndicators) t.append(el('tr', {}, el('td', { class: 'mono', text: x.code }), el('td', { text: String(x.count) }))); top.append(t); }
    panel.append(top);
  }
  const l = ls.stats;
  panel.append(el('div', { class: 'panel' }, el('h3', { text: 'Liste de reputație locale' }),
    el('p', { text: `Intrări: ${l.bundled} incluse (test) · ${l.user} ale utilizatorului · ${l.feed} din feed-uri${l.feedUpdatedAt ? ` (actualizat ${fmtTime(l.feedUpdatedAt)})` : ''}.` }),
    l.user + l.feed === 0 ? el('div', { class: 'notice', text: 'Atenție: lista inclusă conține doar intrări SINTETICE de test. Pentru detecție reală a domeniilor cunoscute ca malițioase, activează feed-uri în „Surse externe” sau importă o listă în „Liste de încredere”. Detecția euristică (omografe, imitații de brand etc.) funcționează fără liste.' }) : null));
}

/* ---------------------------------------------------------------- istoric */
async function history_() {
  clear(panel);
  panel.append(el('h2', { text: 'Istoric local al alertelor' }));
  const lv = {}; const f = el('div', { class: 'filters' });
  for (const k of ['DANGEROUS', 'SUSPICIOUS', 'UNKNOWN']) { lv[k] = el('input', { type: 'checkbox', id: `f-${k}`, checked: true }); f.append(el('label', { class: 'inline', for: `f-${k}` }, lv[k], LEVEL[k].label)); }
  const search = el('input', { type: 'text', id: 'f-search', placeholder: 'Caută domeniu / cod…', 'aria-label': 'Caută' });
  const type = el('select', { id: 'f-type', 'aria-label': 'Tip' }, ...[['', 'Toate tipurile'], ['navigation', 'Navigări'], ['download', 'Descărcări'], ['behavior', 'Comportament'], ['exception', 'Excepții']].map(([v, t]) => el('option', { value: v, text: t })));
  const list = el('div'); const info = el('p', { class: 'small muted' });
  async function refresh() {
    const r = await send({ type: 'ss.getEvents', levels: Object.keys(lv).filter((k) => lv[k].checked), eventType: type.value || undefined, search: search.value, limit: 200 });
    renderEvents(list, r.events); info.textContent = r.events.length ? `${r.events.length} evenimente afișate.` : '';
  }
  [search, type, ...Object.values(lv)].forEach((n) => n.addEventListener('input', refresh));
  f.append(search, type);
  const out = el('p', { class: 'small', role: 'status' });
  const exp = (detail) => async () => {
    if (!confirm(detail === 'full' ? 'Exportul complet include explicații și detalii tehnice ale fiecărui eveniment (URL-urile rămân redactate conform setărilor). Continui?' : 'Exportă rezumatul (fără detalii tehnice)?')) return;
    const r = await send({ type: 'ss.exportEvents', detail });
    const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: `sentinel-shield-${detail}-${new Date().toISOString().slice(0, 10)}.json` }); a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    status(out, 'Export generat local. Nu a fost trimis nicăieri.');
  };
  panel.append(f, info, list, el('div', { class: 'row' }, el('button', { text: 'Exportă rezumat (JSON)', on: { click: exp('summary') } }), el('button', { text: 'Exportă complet (JSON)', on: { click: exp('full') } }),
    el('button', { class: 'danger', text: 'Șterge jurnalul', on: { click: async () => { if (confirm('Ștergi definitiv jurnalul local și contoarele?')) { await send({ type: 'ss.clearEvents' }); refresh(); } } } })), out);
  refresh();
}

/* ---------------------------------------------------------------- raport pagină */
async function report() {
  clear(panel);
  panel.append(el('h2', { text: 'Raport complet al paginii' }));
  const m = /^#report=(\d+)&u=(.*)$/.exec(location.hash);
  if (!m) { panel.append(el('p', { class: 'empty', text: 'Deschide acest raport din fereastra extensiei (butonul „Vezi raportul complet”), pentru pagina vizitată.' })); return; }
  const r = await send({ type: 'ss.getTabReport', tabId: Number(m[1]), url: decodeURIComponent(m[2]) });
  if (!r?.ok || r.empty) { panel.append(el('p', { class: 'empty', text: 'Nu există încă date pentru această pagină.' })); return; }
  panel.append(levelBadge(r.level, { confirmed: r.confirmed }), el('div', { class: 'panel' }, el('p', { text: r.userExplanation || r.summary }), el('p', {}, el('strong', { text: 'Recomandare: ' }), r.recommendation)),
    el('h3', { text: 'Detalii tehnice' }), el('div', { class: 'panel' }, techList({ 'URL (redactat)': r.url, 'gazdă Unicode': r.hostUnicode, Punycode: r.punycode ?? '(identică)', 'domeniu înregistrabil': r.registrable, 'scor euristic': `${r.score} (suspect ≥ ${r.thresholds?.suspicious}, periculos ≥ ${r.thresholds?.dangerous})`, 'tip verdict': r.confirmed ? 'confirmat de sursă' : 'euristic / informativ', verificat: fmtTime(r.checkedAt) })));
  const ind = el('div'); renderIndicators(ind, r.indicators); panel.append(el('h3', { text: 'Indicatori URL' }), ind);
  const fin = (r.behavior?.findings ?? []).map((x) => ({ ...x, severity: x.score >= 30 ? 'high' : x.score >= 15 ? 'medium' : x.score > 0 ? 'low' : 'info', explain: x.explainUser, code: x.id }));
  const bi = el('div'); renderIndicators(bi, fin); panel.append(el('h3', { text: 'Constatări comportamentale' }), bi);
  const pm = el('div'); renderPermissions(pm, r.behavior?.permissions); panel.append(el('h3', { text: 'Permisiuni' }), pm);
  const tp = el('div'); renderThirdParties(tp, r.behavior?.thirdParties); panel.append(el('h3', { text: 'Domenii terțe' }), tp);
  const sr = el('div'); renderSources(sr, r.sources); panel.append(el('h3', { text: 'Surse' }), sr);
  const rd = el('div'); (r.redirects.length > 1 ? r.redirects : []).forEach((h, i) => rd.append(el('p', { class: 'mono small', text: `${i + 1}. ${h.url} — ${h.kind}` }))); if (!rd.childNodes.length) rd.append(el('p', { class: 'empty', text: 'Nicio redirecționare observată.' })); panel.append(el('h3', { text: 'Redirecționări observate' }), rd);
}

/* ---------------------------------------------------------------- liste de încredere */
async function trust() {
  clear(panel);
  panel.append(el('h2', { text: 'Liste de încredere și excepții' }),
    el('div', { class: 'notice info', text: 'Excepțiile se aplică exact domeniului și protocolului ales (de ex. https://exemplu.ro), NU subdomeniilor. Un site nu își poate adăuga singur domeniul: doar tu, din această pagină sau din fereastra extensiei. Protecțiile pentru descărcări rămân active.' }));
  const ex = (await send({ type: 'ss.getExceptions' })).exceptions;
  const t = el('table'); t.append(el('thead', {}, el('tr', {}, ...['Domeniu', 'Protocol', 'Tip', 'Creat', 'Expiră', ''].map((h) => el('th', { text: h })))));
  const tb = el('tbody');
  if (!ex.length) tb.append(el('tr', {}, el('td', { colspan: 6, class: 'empty', text: 'Nu există excepții.' })));
  for (const e of ex) tb.append(el('tr', {}, el('td', { class: 'mono', text: e.host }), el('td', { text: e.scheme }), el('td', {}, el('span', { class: `chip ${e.kind === 'confirmed' ? 'high' : 'low'}`, text: e.kind === 'confirmed' ? 'peste amenințare confirmată' : 'alertă euristică' })), el('td', { text: fmtTime(e.createdAt) }), el('td', { text: e.expiresAt ? fmtTime(e.expiresAt) : 'niciodată' }),
    el('td', {}, el('button', { text: 'Șterge', on: { click: async () => { await send({ type: 'ss.removeException', host: e.host, scheme: e.scheme }); trust(); } } }))));
  t.append(tb);
  const out = el('p', { class: 'small', role: 'status' });
  const host = el('input', { type: 'text', id: 'ex-host', placeholder: 'exemplu.ro', autocomplete: 'off' });
  const scheme = el('select', { id: 'ex-scheme' }, el('option', { value: 'https', text: 'https' }), el('option', { value: 'http', text: 'http' }));
  const ttl = el('input', { type: 'number', id: 'ex-ttl', value: 30, min: 0, max: 365 });
  const form = el('div', { class: 'panel' }, el('h3', { text: 'Adaugă o excepție' }), el('div', { class: 'two' }, field('Domeniu (fără subdomenii)', host, 'ex-host'), field('Protocol', scheme, 'ex-scheme')), field('Expiră după (zile, 0 = niciodată)', ttl, 'ex-ttl'),
    el('button', { class: 'primary', text: 'Adaugă excepție', on: { click: async () => {
      let h = host.value.trim().toLowerCase();
      try { if (/^https?:\/\//.test(h)) h = new URL(h).hostname; } catch { /* ignorat */ }
      let r = await send({ type: 'ss.addException', host: h, scheme: scheme.value, kind: 'heuristic', ttlDays: Number(ttl.value) });
      if (r?.error === 'confirmed-requires-ack') {
        if (!confirm(`ATENȚIE: ${h} este listat ca PERICULOS într-o sursă de reputație.\n\nUna este să dezactivezi o alertă euristică (posibil fals pozitiv) și alta să ignori o amenințare CONFIRMATĂ. Dacă continui, avertizarea nu va mai apărea pentru ${scheme.value}://${h}. Sigur?`)) return;
        r = await send({ type: 'ss.addException', host: h, scheme: scheme.value, kind: 'confirmed', acknowledged: true, ttlDays: Math.min(Number(ttl.value) || 7, 30) });
      }
      if (r?.ok) trust(); else status(out, 'Domeniul introdus nu este valid.', false);
    } } }), out);
  const imp = el('textarea', { id: 'imp', placeholder: 'Un domeniu pe linie, format hosts (0.0.0.0 domeniu) sau URL-uri. Se procesează local.' });
  const impName = el('input', { type: 'text', id: 'imp-name', value: 'Listă importată' });
  const impOut = el('p', { class: 'small', role: 'status' });
  const ls = await send({ type: 'ss.getListStatus' });
  panel.append(el('div', { class: 'panel' }, t), form,
    el('div', { class: 'panel' }, el('h3', { text: 'Listă proprie de domenii blocate' }), el('p', { class: 'small muted', text: `Intrări în lista utilizatorului: ${ls.userCount}. Domeniile oficiale ale brandurilor cunoscute și gazdele de hosting partajat sunt omise automat la import.` }), field('Nume listă', impName, 'imp-name'), field('Conținut', imp, 'imp'),
      el('div', { class: 'row' }, el('button', { class: 'primary', text: 'Importă', on: { click: async () => { const r = await send({ type: 'ss.importList', text: imp.value, name: impName.value }); status(impOut, r?.ok ? `Adăugate ${r.added}, omise ${r.skipped}. Total ${r.total}.` : 'Importul a eșuat (text invalid sau prea mare).', !!r?.ok); } } }),
        el('button', { class: 'danger', text: 'Golește lista proprie', on: { click: async () => { if (confirm('Ștergi toate domeniile din lista proprie?')) { await send({ type: 'ss.clearUserList' }); trust(); } } } })), impOut));
}

/* ---------------------------------------------------------------- surse externe */
async function sources() {
  clear(panel);
  const c = await cfg(); const info = (await send({ type: 'ss.getProvidersInfo' })).providers;
  panel.append(el('h2', { text: 'Surse externe de reputație' }), el('div', { class: 'notice info', text: 'Implicit, Sentinel Shield funcționează 100% local. Verificările online sunt opționale, dezactivate, și necesită consimțământul tău explicit. Nu se trimite niciodată istoricul de navigare: doar adresa paginii verificate, conform descrierii fiecărui furnizor. Chei API: introduse de tine, stocate doar local, niciodată incluse în exporturi.' }));
  for (const p of info) {
    const pc = c.reputation.providers[p.id];
    const keyField = p.id === 'urlhaus' ? 'authKey' : 'apiKey';
    const key = el('input', { type: 'password', id: `key-${p.id}`, autocomplete: 'off', placeholder: pc[`${keyField}Set`] ? '(cheie salvată — lasă gol pentru a o păstra)' : 'Cheia ta' });
    const consent = el('input', { type: 'checkbox', id: `consent-${p.id}`, checked: pc.consent });
    const sq = p.id === 'safebrowsing' ? el('input', { type: 'checkbox', id: 'sq', checked: pc.sendQuery }) : null;
    const out = el('p', { class: 'small', role: 'status' });
    panel.append(el('section', { class: 'panel', 'aria-labelledby': `h-${p.id}` }, el('h3', { id: `h-${p.id}`, text: `${p.name} — ${pc.enabled && pc.consent ? 'activ' : 'inactiv'}` }),
      el('div', { class: 'notice disclosure' }, el('strong', { text: 'Ce date sunt transmise, cui și de ce: ' }), p.disclosure),
      field('Cheie API / Auth-Key', key, `key-${p.id}`),
      sq ? el('label', { class: 'inline', for: 'sq' }, sq, el('span', { text: 'Trimite și parametrii URL-ului (NERECOMANDAT: pot conține date sensibile)' })) : null,
      el('label', { class: 'inline', for: `consent-${p.id}` }, consent, el('span', { text: `Înțeleg și sunt de acord să transmit datele descrise mai sus către ${p.name}.` })),
      el('div', { class: 'row' },
        el('button', { class: 'primary', text: 'Salvează și activează', on: { click: async () => {
          if (!consent.checked) { status(out, 'Bifează consimțământul pentru a activa această sursă.', false); return; }
          if (!key.value && !pc[`${keyField}Set`]) { status(out, 'Introdu cheia API.', false); return; }
          const granted = await chrome.permissions.request({ origins: [p.origin] });
          if (!granted) { status(out, 'Permisiunea de rețea a fost refuzată; sursa rămâne inactivă.', false); return; }
          const patch = { reputation: { providers: { [p.id]: { enabled: true, consent: true, ...(key.value ? { [keyField]: key.value } : {}), ...(sq ? { sendQuery: sq.checked } : {}) } } } };
          const r = await save(patch, out); key.value = ''; if (r?.ok) sources();
        } } }),
        el('button', { text: 'Testează', on: { click: async () => { const r = await send({ type: 'ss.testProvider', id: p.id }); status(out, r?.ok && r.result ? `Test: ${r.result.statusLabel ?? r.result.status} — ${r.result.detail ?? ''}` : 'Activează și consimte mai întâi.', !!(r?.ok && r.result && ['clean', 'malicious'].includes(r.result.status))); } } }),
        el('button', { class: 'danger', text: 'Dezactivează și șterge cheia', on: { click: async () => { await save({ reputation: { providers: { [p.id]: { enabled: false, consent: false, [keyField]: '' } } } }, out); sources(); } } })), out));
  }
  panel.append(el('div', { class: 'panel' }, el('h3', { text: 'PhishTank' }), el('p', { class: 'small', text: 'Nu este integrat live: endpoint-ul de verificare documentat folosește HTTP necriptat (URL-ul ar circula în clar), iar documentația nu precizează dacă se mai emit chei noi. Poți importa totuși o listă exportată din PhishTank în „Liste de încredere” (format domenii/URL-uri).' })));
  // feed-uri
  const fOut = el('p', { class: 'small', role: 'status' });
  const on = check('feeds-on', 'Activează actualizarea automată a listelor (descarcă liste publice; NU trimite nimic despre tine)', c.feeds.enabled, 'Se face doar o cerere GET către adresele de mai jos. Verifică licența și adresa fiecărui feed înainte de a-l activa; adresele presetate nu au fost verificate live de dezvoltator.');
  const rows = c.feeds.sources.map((s, i) => check(`feed-${i}`, `${s.name} — ${s.url}`, s.enabled));
  const interval = el('input', { type: 'number', id: 'feed-int', min: 1, max: 168, value: c.feeds.intervalHours });
  panel.append(el('section', { class: 'panel' }, el('h3', { text: 'Feed-uri de liste (descărcare locală)' }), on, ...rows, field('Interval actualizare (ore)', interval, 'feed-int'),
    el('div', { class: 'row' }, el('button', { class: 'primary', text: 'Salvează și actualizează acum', on: { click: async () => {
      const srcs = c.feeds.sources.map((s, i) => ({ ...s, enabled: $(`#feed-${i}`).checked }));
      const enabled = $('#feeds-on').checked;
      if (enabled) {
        const origins = [...new Set(srcs.filter((s) => s.enabled).map((s) => new URL(s.url).origin + '/*'))];
        if (origins.length && !(await chrome.permissions.request({ origins }))) { status(fOut, 'Permisiunea de rețea a fost refuzată.', false); return; }
      }
      await save({ feeds: { enabled, intervalHours: Number(interval.value), sources: srcs } }, fOut);
      if (enabled) { const r = await send({ type: 'ss.syncFeeds' }); status(fOut, r?.ok ? Object.values(r.per).map((p) => `${p.name}: ${p.ok ? p.count + ' intrări' : 'eșec (' + p.error + ')'}`).join(' · ') || 'Nicio sursă activă.' : 'Actualizarea a eșuat.', !!r?.ok); }
    } } })), fOut));
}

/* ---------------------------------------------------------------- confidențialitate */
async function privacy() {
  clear(panel);
  const c = await cfg(); const out = el('p', { class: 'small', role: 'status' });
  const mode = el('select', { id: 'p-mode' }, ...[['redact-sensitive', 'Elimină doar parametrii sensibili (implicit)'], ['strip-query', 'Elimină toți parametrii și fragmentul'], ['host-only', 'Doar domeniul'], ['full', 'URL complet (fără credențiale)']].map(([v, t]) => el('option', { value: v, text: t, selected: c.privacy.logUrlMode === v })));
  const days = el('input', { type: 'number', id: 'p-days', min: 1, max: 365, value: c.privacy.retentionDays });
  const max = el('input', { type: 'number', id: 'p-max', min: 50, max: 5000, value: c.privacy.maxEvents });
  const log = check('p-log', 'Păstrează jurnalul local al alertelor', c.privacy.logEnabled, 'Se înregistrează doar alertele (suspect/periculos/neverificat), nu întregul istoric. Paginile cu risc redus sunt doar numărate, fără URL.');
  panel.append(el('h2', { text: 'Confidențialitate și retenție' }), el('div', { class: 'panel' }, log, field('Cum sunt stocate URL-urile în jurnal', mode, 'p-mode'), el('div', { class: 'two' }, field('Retenție (zile)', days, 'p-days'), field('Număr maxim de evenimente', max, 'p-max')),
    el('button', { class: 'primary', text: 'Salvează', on: { click: async () => save({ privacy: { logEnabled: $('#p-log').checked, logUrlMode: mode.value, retentionDays: Number(days.value), maxEvents: Number(max.value) } }, out) } }), out),
    el('div', { class: 'panel' }, el('h3', { text: 'Ce NU se stochează niciodată' }), el('ul', {}, ...['Parole, conținutul formularelor sau textul din clipboard', 'Credențiale din adrese (utilizator:parolă@) — eliminate întotdeauna', 'Tokenuri/chei din parametri (redactate implicit), fragmentul URL-ului', 'Cheile API în exporturi sau în jurnal'].map((t) => el('li', { text: t })))));
}

/* ---------------------------------------------------------------- protecție */
async function protection() {
  clear(panel);
  const c = await cfg(); const out = el('p', { class: 'small', role: 'status' });
  const sel = (id, opts, val) => el('select', { id }, ...opts.map(([v, t]) => el('option', { value: v, text: t, selected: val === v })));
  const cb = sel('pr-cb', [['typed', 'Permite, cu confirmare prin scrierea domeniului și timp de gândire'], ['never', 'Nu permite niciodată continuarea (politică strictă)']], c.policy.confirmedBypass);
  const hb = sel('pr-hb', [['hold', 'Permite, cu apăsare prelungită după un timp de gândire'], ['never', 'Nu permite niciodată']], c.policy.heuristicBypass);
  const ttl = el('input', { type: 'number', id: 'pr-ttl', min: 1, max: 120, value: c.passTtlMinutes });
  const sus = el('input', { type: 'number', id: 'pr-sus', min: 1, max: 100, value: c.scoring.thresholds.suspicious });
  const dan = el('input', { type: 'number', id: 'pr-dan', min: 2, max: 200, value: c.scoring.thresholds.dangerous });
  panel.append(el('h2', { text: 'Protecție' }), el('div', { class: 'panel' },
    check('pr-en', 'Protecție activă', c.protection.enabled), check('pr-sw', 'Avertizează și pentru pagini „Suspect” (în plus față de „Periculos”)', c.protection.warnOnSuspicious, 'Implicit doar paginile periculoase sunt oprite; cele suspecte apar în popup și în jurnal.'),
    check('pr-strong', 'Blocare timpurie prin declarativeNetRequest (permisiune extinsă, opțională)', c.protection.strongBlocking, 'Interceptează și redirecționările din lanțul de navigare pentru domeniile din liste. Necesită acces la toate site-urile; fără ea, protecția folosește evenimentele de navigare (vezi LIMITARI.md).'),
    check('pr-beh', 'Analiza comportamentului paginii („Ce vrea să acceseze?”)', c.behavior.enabled), check('pr-dl', 'Monitorizează descărcările', c.downloads.monitor), check('pr-dlp', 'Pune în pauză descărcările cu risc ridicat până la decizia ta', c.downloads.pauseDangerous),
    field('Continuare după avertizare — amenințări confirmate', cb, 'pr-cb'), field('Continuare după avertizare — risc euristic', hb, 'pr-hb'), field('Valabilitatea unei continuări (minute, per filă și origine)', ttl, 'pr-ttl'),
    el('details', {}, el('summary', { text: 'Praguri scor euristic (avansat)' }), el('div', { class: 'two' }, field('Suspect de la', sus, 'pr-sus'), field('Periculos de la (necesită și un indicator sever)', dan, 'pr-dan'))),
    el('button', { class: 'primary', text: 'Salvează', on: { click: async () => {
      const strong = $('#pr-strong').checked;
      if (strong && !c.protection.strongBlocking) {
        const ok = await chrome.permissions.request({ permissions: ['declarativeNetRequestWithHostAccess'], origins: ['<all_urls>'] });
        if (!ok) { status(out, 'Permisiunea a fost refuzată; blocarea timpurie rămâne dezactivată.', false); $('#pr-strong').checked = false; return; }
      }
      await save({ protection: { enabled: $('#pr-en').checked, warnOnSuspicious: $('#pr-sw').checked, strongBlocking: strong }, behavior: { enabled: $('#pr-beh').checked }, downloads: { monitor: $('#pr-dl').checked, pauseDangerous: $('#pr-dlp').checked }, policy: { confirmedBypass: cb.value, heuristicBypass: hb.value }, passTtlMinutes: Number(ttl.value), scoring: { thresholds: { suspicious: Number(sus.value), dangerous: Number(dan.value) } } }, out);
    } } }), out));
}

const VIEWS = { overview, history: history_, report, trust, sources, privacy, protection };
(function boot() {
  if (location.hash.startsWith('#report=')) current = 'report';
  else { const m = /^#tab=(\w+)/.exec(location.hash); if (m && VIEWS[m[1]]) current = m[1]; }
  buildTabs(); VIEWS[current]();
})();
