// Interpretarea observațiilor comportamentale ale paginii („Ce vrea să acceseze?”).
// Distincții păstrate explicit în rezultat:
//   api-available      API-ul există în browser (NU înseamnă că e folosit)
//   requested          pagina a apelat API-ul / a cerut permisiunea (observat)
//   permission-granted starea permisiunii în browser e „granted” (poate fi dintr-o sesiune anterioară)
//   access-obtained    apelul API a reușit în această pagină (ex. flux media creat)
// „Utilizare confirmată” a datelor (ce face pagina cu ele) NU poate fi stabilită de extensie și nu este afirmată niciodată.
import { splitHost } from './psl.js';
import { Classification, analyzeUrl } from './url-analyzer.js';
import { isOfficialFor } from './brands.js';
import { computeScore } from './risk-engine.js';

export const TRACKERS = new Map(Object.entries({
  'google-analytics.com': 'analitică', 'googletagmanager.com': 'gestionar de etichete', 'doubleclick.net': 'reclame',
  'googlesyndication.com': 'reclame', 'googleadservices.com': 'reclame', 'facebook.net': 'urmărire socială', 'connect.facebook.net': 'urmărire socială',
  'hotjar.com': 'analitică / înregistrare sesiuni', 'clarity.ms': 'analitică / înregistrare sesiuni', 'segment.io': 'analitică', 'segment.com': 'analitică',
  'mixpanel.com': 'analitică', 'amplitude.com': 'analitică', 'criteo.com': 'reclame', 'taboola.com': 'reclame', 'outbrain.com': 'reclame',
  'adsrvr.org': 'reclame', 'scorecardresearch.com': 'analitică', 'quantserve.com': 'analitică', 'hubspot.com': 'marketing', 'hsforms.com': 'marketing',
  'linkedin.com': 'urmărire socială', 'ads-twitter.com': 'reclame', 'tiktok.com': 'urmărire socială', 'bat.bing.com': 'reclame', 'optimizely.com': 'experimente',
  'newrelic.com': 'monitorizare', 'nr-data.net': 'monitorizare', 'sentry.io': 'monitorizare erori', 'fullstory.com': 'înregistrare sesiuni', 'mouseflow.com': 'înregistrare sesiuni'
}));

const PERMS = {
  geolocation: { label: 'Locație', can: 'browserul poate furniza informații despre poziția ta, în funcție de permisiunea acordată și de capabilitățile dispozitivului.', legit: 'hărți, vreme sau magazine din apropiere' },
  camera: { label: 'Cameră', can: 'pagina poate primi imagine video de la camera ta.', legit: 'apeluri video sau fotografii' },
  microphone: { label: 'Microfon', can: 'pagina poate primi sunet de la microfonul tău.', legit: 'apeluri sau înregistrări vocale' },
  screen: { label: 'Partajare ecran', can: 'pagina poate captura conținutul ecranului sau al unei ferestre alese de tine.', legit: 'ședințe online și demonstrații' },
  'clipboard-read': { label: 'Citire clipboard', can: 'pagina poate citi ce ai copiat (de exemplu parole sau text personal).', legit: 'editoare care lipesc conținut' },
  'clipboard-write': { label: 'Scriere clipboard', can: 'pagina poate modifica ce ai copiat, inclusiv înlocuind conținutul cu altceva.', legit: 'butoane „Copiază”' },
  notifications: { label: 'Notificări', can: 'pagina poate afișa notificări în afara ferestrei ei, uneori folosite pentru reclame sau mesaje înșelătoare.', legit: 'mesagerie sau alerte pe care le-ai cerut' }
};
export const PERMISSION_KEYS = Object.keys(PERMS);

const TEXT_SIGNALS = {
  'virus-warning': { score: 30, cls: Classification.SUSPICIOUS, title: 'Mesaj despre infectarea dispozitivului', user: 'Pagina afișează un mesaj care susține că dispozitivul tău are viruși sau este compromis. Browserul nu poate ști acest lucru dintr-o pagină web; astfel de mesaje sunt tipice pentru înșelătorii (scareware).', rec: 'Nu apela numere afișate și nu instala nimic. Închide fila.' },
  'tech-support': { score: 15, cls: Classification.SUSPICIOUS, title: 'Îndemn de a suna un „suport tehnic”', user: 'Pagina te îndeamnă să suni un număr de „suport tehnic”. Înșelătoriile de acest tip urmăresc obținerea accesului la dispozitivul sau banii tăi.', rec: 'Nu suna și nu oferi acces la distanță.' },
  'run-command': { score: 30, cls: Classification.SUSPICIOUS, title: 'Îndemn de a rula o comandă pe calculator', user: 'Pagina te îndeamnă să deschizi Run/Terminal și să lipești o comandă. Aceasta este o tehnică folosită pentru a instala malware fără ca browserul să îl poată bloca.', rec: 'Nu rula comenzi primite de pe o pagină web.' },
  'disable-protection': { score: 30, cls: Classification.SUSPICIOUS, title: 'Îndemn de a dezactiva protecțiile', user: 'Pagina te îndeamnă să dezactivezi antivirusul sau protecțiile browserului. Site-urile legitime nu au nevoie de acest lucru.', rec: 'Nu dezactiva nicio protecție.' },
  'extension-install': { score: 10, cls: Classification.POTENTIAL, title: 'Cerere de instalare a unei extensii/program', user: 'Pagina te îndeamnă să instalezi o extensie sau un program. Poate fi legitim, dar este și o metodă frecventă de distribuire a software-ului nedorit.', rec: 'Instalează doar din magazinul oficial și dacă ai inițiat tu acțiunea.' }
};

function cls(score, base) { return score > 0 ? base : Classification.POTENTIAL; }

/**
 * @param {object} snap instantaneu validat (vezi messages.js)
 * @param {{pageHost:string, pageScheme:string, urlLevel?:string, lists?:{lookup:Function}, titleBrands?:object[]}} ctx
 */
export function analyzeBehavior(snap, ctx) {
  const findings = [];
  const add = (f) => findings.push({ score: 0, evidence: 'observed', ...f });
  const page = splitHost(ctx.pageHost);
  const hasPassword = (snap.forms?.passwordFields ?? 0) > 0;
  const riskyUrl = ctx.urlLevel === 'SUSPICIOUS' || ctx.urlLevel === 'DANGEROUS';

  // ---------- Permisiuni
  const table = PERMISSION_KEYS.map((key) => {
    const meta = PERMS[key];
    const req = snap.requests?.[key] ?? { count: 0, granted: 0, denied: 0, errors: 0, noGesture: 0 };
    const browserState = snap.permissions?.[key] ?? 'unknown';
    const apiKey = key === 'camera' || key === 'microphone' || key === 'screen' ? 'mediaDevices' : key.startsWith('clipboard') ? 'clipboard' : key;
    const api = (snap.api ?? []).includes(apiKey) ? 'available' : (snap.api ? 'unavailable' : 'unknown');
    const requested = req.count > 0;
    const outcome = req.granted > 0 ? 'granted' : req.denied > 0 ? 'denied' : requested ? 'pending' : null;
    const level = outcome === 'granted' ? 'access-obtained' : browserState === 'granted' ? 'permission-granted' : requested ? 'requested' : api === 'available' ? 'api-available' : 'none';
    let justified = 'unknown';
    if ((key === 'geolocation' && snap.hints?.hasMap) || ((key === 'camera' || key === 'microphone' || key === 'screen') && snap.hints?.hasVideo)) justified = 'likely';
    else if (hasPassword && key !== 'notifications') justified = 'unlikely';
    else if (key === 'clipboard-read') justified = 'unlikely';
    return { key, label: meta.label, api, requested, requestCount: req.count, outcome, browserState, level, justified, usageConfirmed: false };
  });

  for (const row of table) {
    if (!(row.requested || row.browserState === 'granted')) continue;
    const meta = PERMS[row.key];
    const req = snap.requests?.[row.key] ?? { noGesture: 0 };
    const stateTxt = row.level === 'access-obtained' ? 'și a obținut acces (apelul a reușit)' : row.outcome === 'denied' ? 'iar cererea a fost refuzată' : row.requested ? 'iar răspunsul nu a fost observat' : 'iar permisiunea era deja acordată în browser';
    const why = row.justified === 'likely' ? `Funcția poate fi justificată de conținutul paginii (${meta.legit}).`
      : row.justified === 'unlikely' ? (hasPassword ? 'Este neobișnuită pe o pagină care cere o parolă.' : 'Este neobișnuită pentru majoritatea paginilor obișnuite.')
        : 'Nu putem stabili dacă este justificată de funcția paginii.';
    let score = 0; let c;
    if (row.outcome === 'denied') { score = 0; c = Classification.POTENTIAL; }
    else if (row.justified === 'likely') { score = 0; c = Classification.LEGITIMATE; }
    else if (row.justified === 'unlikely') { score = row.level === 'access-obtained' || row.browserState === 'granted' ? 20 : 15; c = Classification.SUSPICIOUS; }
    else { score = 5; c = Classification.POTENTIAL; }
    if (req.noGesture > 0 && row.justified !== 'likely') { score += 5; if (c === Classification.POTENTIAL) c = Classification.SUSPICIOUS; }
    if (riskyUrl && score > 0) score += 5;
    add({
      id: `perm-${row.key}`, category: 'permission', classification: c, score, title: `${meta.label}: ${row.requested ? 'cerere observată' : 'permisiune acordată'}`,
      explainUser: `Site-ul a solicitat acces la ${meta.label.toLowerCase()} ${stateTxt}. Dacă aprobi cererea, ${meta.can} ${why}${req.noGesture > 0 ? ' Cererea a apărut fără o acțiune evidentă din partea ta.' : ''}`,
      technical: { permission: row.key, requests: row.requestCount, outcome: row.outcome, browserState: row.browserState, level: row.level, noGesture: req.noGesture ?? 0, justified: row.justified, note: 'API disponibil ≠ cerere ≠ permisiune acordată ≠ utilizare confirmată; ultima nu poate fi stabilită de extensie.' },
      recommendation: row.outcome === 'denied' ? 'Nu este necesară nicio acțiune.' : row.justified === 'likely' ? 'Acceptă doar dacă ai inițiat tu acțiunea.' : 'Refuză cererea dacă nu înțelegi de ce este necesară; poți revoca permisiunea din setările site-ului.'
    });
  }

  // ---------- Clipboard: text de tip comandă (ClickFix)
  if ((snap.clipboardCommandLike ?? 0) > 0) {
    add({ id: 'clipboard-command', category: 'data-access', classification: Classification.SUSPICIOUS, score: 30, title: 'Pagina a copiat în clipboard un text care arată ca o comandă',
      explainUser: 'Pagina a scris în clipboard un text cu structură de comandă (de exemplu PowerShell, cmd sau curl). Dacă ești îndemnat să îl lipești în Run sau Terminal, acest lucru poate instala malware. Conținutul copiat nu a fost salvat de extensie.',
      technical: { writes: snap.clipboardCommandLike, contentStored: false, heuristic: 'tipar de comandă, nu confirmare de malware' }, recommendation: 'Nu lipi în Run/Terminal conținut copiat de o pagină web.' });
  }

  // ---------- Ferestre și descărcări inițiate de pagină
  const wo = snap.windowOpens ?? { total: 0, noGesture: 0 };
  if (wo.total > 0) {
    const heavy = wo.total >= 3 || wo.noGesture >= 2;
    add({ id: 'window-opens', category: 'behavior', classification: heavy ? Classification.SUSPICIOUS : Classification.POTENTIAL, score: heavy ? 15 : 0, title: `Deschidere de ferestre noi (${wo.total})`,
      explainUser: heavy ? `Pagina a deschis repetat ferestre noi (${wo.total}, dintre care ${wo.noGesture} fără o acțiune evidentă din partea ta). Este un comportament frecvent la pagini cu reclame agresive sau înșelătorii.` : 'Pagina a deschis o fereastră nouă. Este frecvent legitim (de exemplu autentificare externă).',
      technical: wo, recommendation: heavy ? 'Închide ferestrele necunoscute și nu interacționa cu ele.' : 'Nu este necesară nicio acțiune.' });
  }
  const dl = snap.downloads ?? { total: 0, noGesture: 0 };
  if (dl.total > 0) {
    add({ id: 'page-download', category: 'behavior', classification: dl.noGesture > 0 ? Classification.SUSPICIOUS : Classification.POTENTIAL, score: dl.noGesture > 0 ? 10 : 0, title: `Descărcare inițiată prin script (${dl.total})`,
      explainUser: dl.noGesture > 0 ? 'Pagina a pornit programatic o descărcare fără o acțiune evidentă din partea ta. Descărcările neașteptate trebuie tratate cu prudență.' : 'Pagina a pornit o descărcare după o acțiune a ta (de exemplu un click pe un buton).',
      technical: dl, recommendation: 'Verifică numele și sursa fișierului înainte de a-l deschide.' });
  }

  // ---------- Formulare
  const f = snap.forms ?? {};
  const pageOfficialBrands = (ctx.titleBrands ?? []).filter((b) => !isOfficialFor(b, page.registrable));
  if (hasPassword && pageOfficialBrands.length) {
    add({ id: 'login-impersonation', category: 'form', classification: Classification.SUSPICIOUS, score: 30, title: `Pagină de autentificare care pare să reprezinte „${pageOfficialBrands[0].name}”`,
      explainUser: `Pagina cere o parolă și titlul ei menționează „${pageOfficialBrands[0].name}”, dar domeniul (${page.registrable}) nu este unul dintre domeniile oficiale ale serviciului. Dacă introduci parola, aceasta ar putea ajunge la operatorul site-ului.`,
      technical: { brand: pageOfficialBrands[0].name, pageDomain: page.registrable, officialDomains: pageOfficialBrands[0].domains.slice(0, 4), basis: 'titlul paginii + câmp de parolă; inferență, nu confirmare' }, recommendation: 'Nu introduce parola. Accesează serviciul scriind adresa oficială.' });
  }
  const crossPw = (f.crossSiteActions ?? []).filter((a) => a.hasPassword && splitHost(a.host).registrable !== page.registrable);
  if (crossPw.length) {
    add({ id: 'password-form-cross-site', category: 'form', classification: Classification.SUSPICIOUS, score: 30, title: 'Formular cu parolă care trimite către alt domeniu',
      explainUser: `Formularul cu câmp de parolă este configurat să trimită datele către ${crossPw[0].host}, care diferă de domeniul paginii. Poate fi legitim (autentificare centralizată), dar este și tiparul tipic al paginilor false.`,
      technical: { targets: crossPw.map((a) => a.host), note: 'Se observă destinația configurată; conținutul nu este citit.' }, recommendation: 'Verifică dacă destinația este un serviciu pe care îl recunoști.' });
  }
  const submitsPw = (f.submits ?? []).filter((s) => s.hasPassword && splitHost(s.host).registrable !== page.registrable);
  if (submitsPw.length) {
    add({ id: 'password-submit-cross-site', category: 'form', classification: Classification.SUSPICIOUS, score: 40, title: 'Formular cu parolă trimis către alt domeniu',
      explainUser: `S-a observat trimiterea unui formular cu câmp de parolă către ${submitsPw[0].host}, un alt domeniu decât al paginii. Parola ar putea fi primită de acel domeniu.`,
      technical: { targets: submitsPw.map((s) => s.host), valuesRead: false }, recommendation: 'Dacă nu ai recunoscut destinația, schimbă parola serviciului afectat.' });
  }
  if (hasPassword && ctx.pageScheme === 'http:' && !page.isIp) {
    add({ id: 'password-over-http', category: 'form', classification: Classification.SUSPICIOUS, score: 15, title: 'Câmp de parolă pe o conexiune necriptată',
      explainUser: 'Pagina cere o parolă printr-o conexiune HTTP necriptată; datele pot fi interceptate pe rețea.', technical: { scheme: 'http:' }, recommendation: 'Nu introduce parole pe pagini HTTP.' });
  }
  if ((f.cardFields ?? 0) > 0 && ctx.pageScheme === 'http:') {
    add({ id: 'card-over-http', category: 'form', classification: Classification.SUSPICIOUS, score: 30, title: 'Câmpuri de card bancar pe o conexiune necriptată',
      explainUser: 'Pagina pare să ceară date de card printr-o conexiune HTTP necriptată.', technical: { cardFields: f.cardFields }, recommendation: 'Nu introduce date bancare pe pagini HTTP.' });
  }
  if ((f.hiddenFrames ?? 0) > 0) {
    add({ id: 'hidden-frames', category: 'behavior', classification: f.hiddenFrames >= 3 ? Classification.SUSPICIOUS : Classification.POTENTIAL, score: f.hiddenFrames >= 3 ? 10 : 0, title: `Cadre ascunse către alte domenii (${f.hiddenFrames})`,
      explainUser: 'Pagina conține cadre (iframe) practic invizibile încărcate de la alte domenii. Sunt folosite și legitim (urmărire, plăți), dar și pentru a ascunde conținut.', technical: { hiddenFrames: f.hiddenFrames }, recommendation: 'Nu este necesară nicio acțiune imediată.' });
  }

  // ---------- Semnale text
  for (const code of snap.text ?? []) {
    const s = TEXT_SIGNALS[code]; if (!s) continue;
    add({ id: `text-${code}`, category: 'content', classification: s.cls, score: s.score, title: s.title, explainUser: s.user, technical: { signal: code, basis: 'potrivire de tipar în textul vizibil; conținutul nu este stocat' }, recommendation: s.rec });
  }

  // ---------- Rețea: domenii terțe
  const observed = new Map();
  for (const o of snap.net?.observed ?? []) {
    const reg = splitHost(o.host).registrable;
    if (reg === page.registrable) continue;
    const e = observed.get(reg) ?? { registrable: reg, hosts: new Set(), types: new Set(), count: 0, withBody: 0 };
    e.hosts.add(o.host); e.types.add(o.type); e.count += o.count; e.withBody += o.withBody ?? 0;
    observed.set(reg, e);
  }
  const observedHosts = new Set((snap.net?.observed ?? []).map((o) => o.host));
  const declaredOnly = new Map();
  for (const d of snap.net?.declared ?? []) {
    const reg = splitHost(d.host).registrable;
    if (reg === page.registrable || observedHosts.has(d.host)) continue;
    const e = declaredOnly.get(reg) ?? { registrable: reg, hosts: new Set(), kinds: new Set() };
    e.hosts.add(d.host); e.kinds.add(d.kind); declaredOnly.set(reg, e);
  }
  const describe = (e, ev) => {
    const hostList = [...e.hosts];
    const host = hostList.find((h) => ctx.lists?.lookup(h)) ?? hostList[0];
    const lookup = ctx.lists?.lookup(host) ?? null;
    const a = analyzeUrl(`https://${host}/`);
    const hScore = computeScore(a.indicators ?? []);
    return { registrable: e.registrable, hosts: [...e.hosts].slice(0, 5), types: [...(e.types ?? e.kinds)], count: e.count ?? null, withBody: e.withBody ?? 0, evidence: ev,
      tracker: TRACKERS.get(e.registrable) ?? [...e.hosts].map((h) => TRACKERS.get(h)).find(Boolean) ?? null, listed: lookup ? { list: lookup.list, threatType: lookup.threatType } : null, heuristicScore: hScore, heuristicCodes: (a.indicators ?? []).filter((i) => i.severity !== 'info').map((i) => i.code) };
  };
  const obsList = [...observed.values()].map((e) => describe(e, 'observed'));
  const declList = [...declaredOnly.values()].map((e) => describe(e, 'declared'));

  for (const t of obsList.filter((x) => x.listed)) {
    add({ id: `third-party-confirmed-${t.registrable}`, category: 'network', classification: Classification.CONFIRMED, score: 100, title: `Conexiune observată către un domeniu listat ca malițios: ${t.registrable}`,
      explainUser: `Pagina a contactat ${t.registrable}, care apare în lista „${t.listed.list}” ca fiind asociat cu activitate malițioasă. Aceasta este o potrivire cu o listă, nu o presupunere; nu putem ști ce date au fost trimise.`,
      technical: { domain: t.registrable, list: t.listed.list, threatType: t.listed.threatType, types: t.types, requests: t.count, evidence: 'observed' }, recommendation: 'Închide pagina.' });
  }
  for (const t of declList.filter((x) => x.listed)) {
    add({ id: `third-party-declared-listed-${t.registrable}`, evidence: 'declared', category: 'network', classification: Classification.SUSPICIOUS, score: 40, title: `Pagina face referire la un domeniu listat ca malițios: ${t.registrable}`,
      explainUser: `Codul paginii face referire la ${t.registrable}, listat ca malițios în „${t.listed.list}”. Nu am observat o conexiune efectivă (doar referința din pagină), deci impactul real este neconfirmat.`,
      technical: { domain: t.registrable, list: t.listed.list, kinds: t.types, evidence: 'declared' }, recommendation: 'Evită interacțiunea cu pagina.' });
  }
  for (const t of obsList.filter((x) => !x.listed && !x.tracker && x.heuristicScore >= 15).slice(0, 2)) {
    add({ id: `third-party-suspicious-${t.registrable}`, category: 'network', classification: Classification.SUSPICIOUS, score: 15, title: `Domeniu terț cu indicatori suspecți: ${t.registrable}`,
      explainUser: `Pagina contactează ${t.registrable}, al cărui nume prezintă indicatori suspecți (${t.heuristicCodes.join(', ')}). Nu este o confirmare de amenințare.`, technical: { domain: t.registrable, codes: t.heuristicCodes, evidence: 'observed' }, recommendation: 'Fii prudent cu datele introduse pe această pagină.' });
  }
  const trackers = obsList.filter((t) => t.tracker);
  if (trackers.length) {
    add({ id: 'trackers', category: 'network', classification: Classification.POTENTIAL, score: 0, title: `Indicatori de urmărire / analitică (${trackers.length})`,
      explainUser: `Au fost observate conexiuni către servicii cunoscute de analitică sau reclame (${trackers.slice(0, 4).map((t) => t.registrable).join(', ')}${trackers.length > 4 ? '…' : ''}). Este comun pe site-uri legitime și nu indică, singur, o amenințare; pot totuși colecta date de navigare.`,
      technical: { domains: trackers.map((t) => ({ domain: t.registrable, category: t.tracker })), basis: 'listă internă de servicii cunoscute' }, recommendation: 'Poți folosi blocante de reclame dacă dorești mai multă confidențialitate.' });
  }
  const sends = obsList.filter((t) => t.withBody > 0 && !t.tracker);
  if (sends.length) {
    add({ id: 'third-party-data-sends', category: 'network', classification: Classification.POTENTIAL, score: 0, title: `Cereri cu corp trimise către domenii terțe (${sends.reduce((a, t) => a + t.withBody, 0)})`,
      explainUser: 'Pagina a trimis cereri cu conținut (de tip POST) către alte domenii. Extensia nu poate determina ce date conțin și nu afirmă că ar fi date sensibile.', technical: { domains: sends.map((t) => t.registrable), contentInspected: false }, recommendation: 'Nu este necesară nicio acțiune dacă recunoști serviciile.' });
  }
  if (obsList.length >= 10) {
    add({ id: 'many-third-parties', category: 'network', classification: ctx.urlLevel === 'SAFE' || !riskyUrl ? Classification.LEGITIMATE : Classification.POTENTIAL, score: 0, title: `Multe domenii terțe observate (${obsList.length})`,
      explainUser: `Pagina a contactat ${obsList.length} domenii terțe (CDN-uri, analitică, reclame, widgeturi). Este tipic pentru site-uri mari și nu este, în sine, un semn de amenințare.`, technical: { count: obsList.length }, recommendation: 'Nu este necesară nicio acțiune.' });
  }

  const score = Math.min(100, findings.reduce((a, x) => a + x.score, 0));
  return {
    findings: findings.sort((a, b) => b.score - a.score), score, permissions: table,
    thirdParties: { observed: obsList.slice(0, 60), declaredOnly: declList.slice(0, 60) },
    hasData: true
  };
}

export function emptyBehavior() { return { findings: [], score: 0, permissions: [], thirdParties: { observed: [], declaredOnly: [] }, hasData: false }; }
