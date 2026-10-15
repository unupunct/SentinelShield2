// Nucleul coordonator (service worker). Primește dependențele (chrome, fetch, ceas) prin injecție, ca să poată fi
// testat fără browser. `service-worker.js` doar leagă evenimentele Chrome la această logică.
import { analyzeUrl } from '../lib/url-analyzer.js';
import { evaluate, combinePage, redirectChainIndicators, Level } from '../lib/risk-engine.js';
import { DEFAULT_CONFIG, validateConfig } from '../lib/config.js';
import { createStore, createMemoryArea, createMutex } from '../lib/storage.js';
import { createLocalLists, createReputationService, parseFeed, parseUserList, PROVIDERS, MAX_FEED_BYTES } from '../lib/reputation.js';
import { createEventLog } from '../lib/event-log.js';
import { analyzeBehavior, emptyBehavior } from '../lib/behavior.js';
import { analyzeDownload } from '../lib/download-analyzer.js';
import { brandsMentionedIn } from '../lib/brands.js';
import { redactUrl, safeText } from '../lib/sanitize.js';
import { splitHost } from '../lib/psl.js';
import { MSG, CONTENT_ALLOWED, validateSnapshot, validateContentSender, isExtensionPageSender, REQUEST_VALIDATORS } from '../lib/messages.js';

const WARNING_PATH = 'src/pages/warning/warning.html';
const MAX_FRAMES = 20;
const RATE_WINDOW_MS = 10000;
const RATE_MAX = 40;
const WARN_TTL_MS = 60 * 60 * 1000;

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
function deepMerge(target, patch) {
  const out = Array.isArray(target) ? [...target] : { ...target };
  for (const [k, v] of Object.entries(patch)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    out[k] = isObj(v) && isObj(out[k]) ? deepMerge(out[k], v) : v;
  }
  return out;
}

export function createCore({ chrome, fetchImpl = (...a) => fetch(...a), now = () => Date.now(), uuid = () => crypto.randomUUID(), loadBundled = async () => ({ entries: [] }) }) {
  const extId = chrome.runtime.id;
  const local = createStore(chrome.storage.local);
  const session = createStore(chrome.storage.session ?? createMemoryArea());
  const lists = createLocalLists();
  let configCache = null;
  const getConfig = async () => (configCache ??= validateConfig(await local.get('config', DEFAULT_CONFIG)));
  const rep = createReputationService({
    fetchImpl, now, lists,
    hasPermission: async (origin) => { try { return await chrome.permissions.contains({ origins: [origin] }); } catch { return false; } }
  });
  const log = createEventLog({ store: local, getConfig, now, uuid });
  const rateByTab = new Map();
  // Evenimentele de navigare ale aceluiași tab se procesează strict în ordine (altfel `onCommitted` ar putea citi starea înainte ca
  // `onBeforeNavigate` să o fi scris și lanțul de redirecționări s-ar pierde).
  const tabLocks = new Map();
  const withTab = (id, fn) => (tabLocks.get(id) ?? tabLocks.set(id, createMutex()).get(id))(fn);
  let readyPromise = null;

  /* ------------------------------------------------------------------ inițializare / liste */
  async function init() {
    readyPromise ??= (async () => {
      lists.setBundled(await loadBundled());
      lists.setUser(await local.get('userList', []));
      const feed = await local.get('feedList', null);
      if (feed) lists.setFeed(feed);
    })();
    return readyPromise;
  }

  /* ------------------------------------------------------------------ excepții și permise */
  async function getExceptions() {
    const all = await local.get('exceptions', []);
    const live = all.filter((e) => !e.expiresAt || e.expiresAt > now());
    if (live.length !== all.length) await local.set('exceptions', live);
    return live;
  }
  async function findException(host, scheme) {
    return (await getExceptions()).find((e) => e.host === host && e.scheme === scheme) ?? null;
  }
  const originOf = (url) => { try { const u = new URL(url); return `${u.protocol}//${u.host}`; } catch { return null; } };
  async function hasPass(tabId, url) {
    const o = originOf(url); if (!o) return false;
    const exp = await session.get(`pass:${tabId}:${o}`, 0);
    return exp > now();
  }

  /* ------------------------------------------------------------------ evaluare URL */
  async function assessUrl(url, { withOnline = false } = {}) {
    await init();
    const cfg = await getConfig();
    const analysis = analyzeUrl(url);
    // Ținte de redirecționare din parametri: evaluate local (nu se accesează niciodată)
    if (analysis.ok && analysis.redirectTargets?.length) {
      for (const t of analysis.redirectTargets.filter((x) => x.crossSite).slice(0, 3)) {
        const ta = analyzeUrl(t.url);
        const tr = evaluate({ analysis: ta, reputation: [rep.checkLocal(ta)], config: cfg });
        if (tr.level === Level.DANGEROUS) {
          analysis.indicators.push(...redirectChainIndicators([{ url: analysis.normalized }, { url: t.url, kind: `parametrul „${t.param}”` }], () => ({ level: tr.level, confirmed: tr.confirmed })));
          break;
        }
      }
    }
    const exception = analysis.isWeb ? await findException(analysis.hostAscii, analysis.scheme.replace(':', '')) : null;
    const reputation = [rep.checkLocal(analysis)];
    if (withOnline) reputation.push(...(await rep.checkOnline(analysis, cfg)));
    return { analysis, result: evaluate({ analysis, reputation, config: cfg, exception }), cfg };
  }

  /* ------------------------------------------------------------------ stare per tab */
  const tabKey = (id) => `tab:${id}`;
  async function getTab(tabId) { return (await session.get(tabKey(tabId), null)) ?? { tabId, url: null, hops: [], frames: {}, result: null, page: null, loggedBehavior: [], navId: 0 }; }
  const putTab = (st) => session.set(tabKey(st.tabId), st);

  function badgeFor(level, confirmed) {
    const map = { DANGEROUS: ['!', '#d83a3a'], SUSPICIOUS: ['?', '#f08a24'], SAFE: ['', '#2a9d8f'], UNKNOWN: ['–', '#6b7280'] };
    return map[level] ?? map.UNKNOWN;
  }
  async function setBadge(tabId, level, confirmed) {
    try {
      const [text, color] = badgeFor(level, confirmed);
      await chrome.action.setBadgeText({ tabId, text });
      await chrome.action.setBadgeBackgroundColor({ tabId, color });
    } catch { /* tab închis */ }
  }

  /* ------------------------------------------------------------------ pagina de avertizare */
  async function pruneWarnings() {
    const idx = await session.get('warnIndex', []);
    const keep = [];
    for (const e of idx) { if (now() - e.at > WARN_TTL_MS) await session.remove(`warn:${e.id}`); else keep.push(e); }
    await session.set('warnIndex', keep.slice(-100));
    return keep;
  }
  async function createWarning({ tabId, url, result, kind = 'navigation', extra = {} }) {
    const id = uuid();
    await session.set(`warn:${id}`, { id, tabId, url, result, kind, createdAt: now(), shownAt: null, used: false, ...extra });
    const idx = await pruneWarnings(); idx.push({ id, at: now() });
    await session.set('warnIndex', idx);
    return id;
  }
  async function showWarning(tabId, url, result, kind = 'navigation') {
    if (tabId == null || tabId < 0) return null;
    const last = await session.get(`lastWarn:${tabId}`, null);
    if (last && last.url === url && now() - last.at < 3000) return last.id; // evită bucle
    const id = await createWarning({ tabId, url, result, kind });
    await session.set(`lastWarn:${tabId}`, { url, id, at: now() });
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`${WARNING_PATH}?id=${id}`) });
    await setBadge(tabId, result.level, result.confirmed);
    return id;
  }

  function warningView(w) {
    const r = w.result;
    const u = (() => { try { return new URL(w.url); } catch { return null; } })();
    const analysis = analyzeUrl(w.url);
    return {
      id: w.id, kind: w.kind, level: r.level, confirmed: r.confirmed, warnKind: r.kind, score: r.score, thresholds: r.thresholds,
      url: redactUrl(w.url, 'full'), displayUrl: redactUrl(w.url, 'redact-sensitive'), scheme: u?.protocol.replace(':', '') ?? null,
      host: analysis.hostAscii ?? u?.hostname ?? '', hostUnicode: analysis.hostUnicode ?? '', punycode: analysis.punycode ?? null, registrable: analysis.registrable ?? '',
      summary: r.summary, userExplanation: r.userExplanation, recommendation: r.recommendation,
      indicators: r.indicators.map((i) => ({ code: i.code, severity: i.severity, classification: i.classification, title: i.title, explain: i.explain, technical: i.technical })),
      sources: r.sources.map((s) => ({ source: s.source, name: s.name, status: s.status, statusLabel: s.statusLabel, checkedAt: s.checkedAt, detail: s.detail ?? '' })),
      bypass: r.bypass, shownAt: w.shownAt, used: w.used, extra: w.download ?? null,
      redirects: w.hops ?? null
    };
  }

  async function getWarning(p, sender) {
    let w = null;
    if (p.id) w = await session.get(`warn:${p.id}`, null);
    else if (p.dnrUrl) {
      // Redirecționare DNR (blocare timpurie): URL-ul din parametru este doar o INTRARE pentru analiză; verdictul vine din motor.
      const a = analyzeUrl(p.dnrUrl);
      if (!a.ok || !a.isWeb) return { ok: false, error: 'invalid-url' };
      const { result } = await assessUrl(p.dnrUrl);
      if (!result.warn) return { ok: true, notFlagged: true, url: a.normalized };
      const tabId = sender?.tab?.id;
      const id = await createWarning({ tabId, url: a.normalized, result, kind: 'navigation' });
      w = await session.get(`warn:${id}`);
    }
    if (!w) return { ok: false, error: 'not-found' };
    if (sender?.tab && w.tabId !== sender.tab.id) return { ok: false, error: 'wrong-tab' };
    if (!w.shownAt) { w.shownAt = now(); await session.set(`warn:${w.id}`, w); }
    return { ok: true, warning: warningView(w), serverNow: now() };
  }

  async function grantPass(p, sender) {
    const w = await session.get(`warn:${p.id}`, null);
    if (!w || w.kind !== 'navigation') return { ok: false, error: 'not-found' };
    if (!sender?.tab || sender.tab.id !== w.tabId) return { ok: false, error: 'wrong-tab' };
    if (w.used) return { ok: false, error: 'already-used' };
    const bypass = w.result.bypass;
    if (!bypass?.allowed) return { ok: false, error: 'policy-denies' };
    if (!w.shownAt || now() - w.shownAt < bypass.delayMs) return { ok: false, error: 'too-soon' };
    const a = analyzeUrl(w.url);
    if (bypass.mode === 'typed') {
      const typed = p.confirmation.trim().toLowerCase();
      if (typed !== a.hostAscii && typed !== (a.hostUnicode ?? '').toLowerCase()) return { ok: false, error: 'confirmation-mismatch' };
    } else if (p.confirmation !== 'HOLD') return { ok: false, error: 'confirmation-mismatch' };
    const cfg = await getConfig();
    const origin = originOf(w.url);
    await session.set(`pass:${w.tabId}:${origin}`, now() + cfg.passTtlMinutes * 60000);
    w.used = true; await session.set(`warn:${w.id}`, w);
    await dnrAllow(w.tabId, a.hostAscii, cfg.passTtlMinutes);
    await log.record({ type: 'exception', level: w.result.level, url: w.url, host: a.hostAscii, summary: `Utilizatorul a continuat după avertizare (${w.result.confirmed ? 'amenințare confirmată' : 'risc euristic'}).`, action: 'user-continued', indicators: w.result.indicators, sources: w.result.sources });
    await chrome.tabs.update(w.tabId, { url: w.url });
    return { ok: true };
  }

  async function goSafe(p, sender) {
    const w = await session.get(`warn:${p.id}`, null);
    if (!w) return { ok: false, error: 'not-found' };
    if (!sender?.tab || sender.tab.id !== w.tabId) return { ok: false, error: 'wrong-tab' };
    await log.record({ type: 'navigation', level: w.result.level, url: w.url, host: analyzeUrl(w.url).hostAscii, summary: w.result.summary, userExplanation: w.result.userExplanation, action: 'back-to-safety', recommendation: w.result.recommendation, indicators: w.result.indicators, sources: w.result.sources });
    await chrome.tabs.update(w.tabId, { url: 'chrome://newtab/' });
    return { ok: true };
  }

  /* ------------------------------------------------------------------ navigare */
  const onBeforeNavigate = (d) => withTab(d.tabId, () => onBeforeNavigateImpl(d));
  const onCommitted = (d) => withTab(d.tabId, () => onCommittedImpl(d));
  async function onBeforeNavigateImpl(d) {
    if (d.frameId !== 0) return;
    const cfg = await getConfig();
    if (!cfg.protection.enabled) return;
    const st = await getTab(d.tabId);
    st.navId = (st.navId ?? 0) + 1; st.url = d.url; st.hops = [{ url: d.url, kind: 'initial' }]; st.frames = {}; st.page = null; st.loggedBehavior = []; st.pendingUrl = d.url;
    const { analysis, result } = await assessUrl(d.url);
    st.result = result; st.analyzedUrl = d.url;
    await putTab(st);
    if (analysis.skipped) { await setBadge(d.tabId, result.level); return; }
    await log.countAnalysis(result.level);
    await setBadge(d.tabId, result.level, result.confirmed);
    await handleVerdict(d.tabId, d.url, result, st.navId);
    // Verificări online (opționale) rulează în paralel; dacă aduc o amenințare, tab-ul este redirecționat către avertizare.
    onlineFollowUp(d.tabId, d.url, st.navId).catch(() => {});
  }

  async function handleVerdict(tabId, url, result, navId, hops = null) {
    if (result.level !== Level.SAFE) {
      const a = analyzeUrl(url);
      const passed = await hasPass(tabId, url);
      await log.record({ type: 'navigation', level: result.level, url, host: a.hostAscii ?? null, summary: result.summary, userExplanation: result.userExplanation, recommendation: result.recommendation,
        action: result.warn && !passed ? 'warned' : passed ? 'passed' : result.exception ? 'exception' : 'observed', indicators: result.indicators, sources: result.sources });
      if (result.warn && !passed) {
        const st = await getTab(tabId);
        if (st.navId === navId || navId == null) await showWarning(tabId, url, hops ? { ...result } : result, 'navigation');
      }
    }
  }

  async function onlineFollowUp(tabId, url, navId) {
    const cfg = await getConfig();
    const any = Object.values(cfg.reputation.providers).some((p) => p.enabled && p.consent);
    if (!any) return;
    const { result } = await assessUrl(url, { withOnline: true });
    await withTab(tabId, async () => {
      const st = await getTab(tabId);
      if (st.navId !== navId) return;
      st.result = result; await putTab(st);
      await setBadge(tabId, result.level, result.confirmed);
      if (result.level !== Level.SAFE && (result.sources.some((s) => s.status === 'malicious' && s.source !== 'local-lists') || result.level === Level.UNKNOWN)) {
        await handleVerdict(tabId, url, result, navId);
      }
    });
  }

  async function onCommittedImpl(d) {
    if (d.frameId !== 0) return;
    const cfg = await getConfig();
    if (!cfg.protection.enabled) return;
    const st = await getTab(d.tabId);
    const q = d.transitionQualifiers ?? [];
    const redirected = q.includes('server_redirect') || q.includes('client_redirect');
    if (redirected && st.hops.at(-1)?.url !== d.url) st.hops.push({ url: d.url, kind: q.includes('server_redirect') ? 'redirecționare de server' : 'redirecționare din pagină' });
    st.url = d.url; st.frames = {};
    if (st.analyzedUrl !== d.url) {
      const { analysis, result } = await assessUrl(d.url);
      if (st.hops.length > 1) {
        const extra = redirectChainIndicators(st.hops, (u) => { const a = analyzeUrl(u); const r = evaluate({ analysis: a, reputation: [rep.checkLocal(a)], config: cfg }); return { level: r.level, confirmed: r.confirmed }; });
        if (extra.length) { analysis.indicators.push(...extra); const re = evaluate({ analysis, reputation: result.sources, config: cfg, exception: result.exception }); Object.assign(result, re); }
      }
      st.result = result; st.analyzedUrl = d.url;
      await putTab(st);
      if (!analysis.skipped) { await setBadge(d.tabId, result.level, result.confirmed); await handleVerdict(d.tabId, d.url, result, st.navId, st.hops); }
    } else await putTab(st);
  }

  /* ------------------------------------------------------------------ observații de la content scripts */
  function mergeSnapshots(frames) {
    const ids = Object.keys(frames).map(Number).sort((a, b) => a - b);
    if (!ids.length) return null;
    const top = frames[0] ?? frames[ids[0]];
    const m = structuredClone(top);
    for (const id of ids) {
      if (frames[id] === top) continue;
      const f = frames[id];
      for (const [k, r] of Object.entries(f.requests)) {
        const t = (m.requests[k] ??= { count: 0, granted: 0, denied: 0, errors: 0, noGesture: 0 });
        for (const key of Object.keys(t)) t[key] += r[key];
      }
      m.clipboardCommandLike += f.clipboardCommandLike;
      for (const k of ['total', 'noGesture']) { m.windowOpens[k] += f.windowOpens[k]; m.downloads[k] += f.downloads[k]; }
      m.net.observed.push(...f.net.observed); m.net.declared.push(...f.net.declared);
      m.forms.passwordFields += f.forms.passwordFields; m.forms.cardFields += f.forms.cardFields; m.forms.hiddenFrames += f.forms.hiddenFrames;
      m.forms.crossSiteActions.push(...f.forms.crossSiteActions); m.forms.submits.push(...f.forms.submits);
      m.text = [...new Set([...m.text, ...f.text])];
    }
    return m;
  }

  async function recomputePage(tabId, st) {
    const cfg = await getConfig();
    if (!cfg.behavior.enabled || !st.result || st.result.reason !== 'evaluated') return st;
    const snap = mergeSnapshots(st.frames);
    if (!snap) return st;
    const u = new URL(st.url);
    const behavior = analyzeBehavior(snap, { pageHost: u.hostname.toLowerCase(), pageScheme: u.protocol, urlLevel: st.result.level, lists, titleBrands: brandsMentionedIn(snap.hints.title) });
    st.behavior = behavior;
    st.page = combinePage(st.result, behavior, cfg);
    return st;
  }

  async function onObservation(msg, sender) {
    const v = validateContentSender(sender, extId);
    if (!v.ok) return { ok: false, error: v.error };
    const tabId = sender.tab.id;
    // limitare de rată per tab
    const rl = rateByTab.get(tabId) ?? { start: now(), n: 0 };
    if (now() - rl.start > RATE_WINDOW_MS) { rl.start = now(); rl.n = 0; }
    if (++rl.n > RATE_MAX) { rateByTab.set(tabId, rl); return { ok: false, error: 'rate-limited' }; }
    rateByTab.set(tabId, rl);
    const val = validateSnapshot(msg.snapshot);
    if (!val.ok) return { ok: false, error: val.error };
    const st = await getTab(tabId);
    // pagina trebuie să corespundă navigării curente a tab-ului (ignoră mesaje de la documente vechi)
    if (sender.frameId === 0 && st.url && originOf(st.url) !== originOf(sender.url)) return { ok: false, error: 'stale-document' };
    if (!st.url) { st.url = sender.url; const r = await assessUrl(sender.url); st.result = r.result; st.analyzedUrl = sender.url; }
    if (Object.keys(st.frames).length >= MAX_FRAMES && !(sender.frameId in st.frames)) return { ok: false, error: 'too-many-frames' };
    st.frames[sender.frameId] = val.snapshot;
    await recomputePage(tabId, st);
    // jurnalizare: o singură dată per constatare importantă și per navigare
    let tripWarn = false;
    for (const f of st.behavior?.findings ?? []) {
      if ((f.classification === 'SUSPICIOUS' && f.score >= 15) || f.classification === 'CONFIRMED') {
        if (!st.loggedBehavior.includes(f.id)) {
          st.loggedBehavior.push(f.id);
          await log.record({ type: 'behavior', level: f.classification === 'CONFIRMED' ? 'DANGEROUS' : 'SUSPICIOUS', url: st.url, host: new URL(st.url).hostname, summary: f.title, userExplanation: f.explainUser, recommendation: f.recommendation, action: 'observed', indicators: [{ code: f.id, category: f.category, severity: f.score >= 30 ? 'high' : 'medium', classification: f.classification, title: f.title, explain: f.explainUser, technical: f.technical }] });
          if (f.classification === 'CONFIRMED') tripWarn = true;
        }
      }
    }
    await putTab(st);
    if (st.page) await setBadge(tabId, st.page.level, st.page.confirmed);
    if (tripWarn && st.page?.confirmed && st.page.warn !== false && !(await hasPass(tabId, st.url))) await showWarning(tabId, st.url, { ...st.page, warn: true }, 'navigation');
    return { ok: true };
  }

  /* ------------------------------------------------------------------ raport pentru popup */
  async function buildReport(tabId, urlHint) {
    const st = await getTab(tabId);
    const url = st.url ?? urlHint ?? null;
    if (!url) return { ok: true, empty: true };
    if (!st.result || st.analyzedUrl !== url) { const r = await assessUrl(url); st.result = r.result; st.analyzedUrl = url; st.url = url; await putTab(st); }
    const page = st.page ?? st.result;
    const a = analyzeUrl(url);
    return {
      ok: true, empty: false, url: redactUrl(url, 'redact-sensitive'), host: a.hostAscii ?? '', hostUnicode: a.hostUnicode ?? '', punycode: a.punycode ?? null, registrable: a.registrable ?? '',
      level: page.level, confirmed: page.confirmed, score: page.score, summary: page.summary, userExplanation: page.userExplanation, recommendation: page.recommendation, reason: page.reason,
      indicators: page.indicators.map(slimIndicator), sources: page.sources, checkedAt: page.checkedAt, thresholds: page.thresholds,
      behavior: st.behavior ?? emptyBehavior(), redirects: st.hops.map((h) => ({ url: redactUrl(h.url, 'redact-sensitive'), kind: h.kind })),
      exception: page.exception ? { kind: page.exception.kind, expiresAt: page.exception.expiresAt } : null
    };
  }
  const slimIndicator = (i) => ({ code: i.code, severity: i.severity, classification: i.classification, title: i.title, explain: i.explain, technical: i.technical });

  async function analyzePage({ tabId }, sender, urlHint) {
    const st = await getTab(tabId);
    const url = st.url ?? urlHint;
    if (!url) return { ok: false, error: 'no-url' };
    const { analysis, result } = await assessUrl(url, { withOnline: true });
    st.url = url; st.result = result; st.analyzedUrl = url;
    await putTab(st);
    try { await chrome.tabs.sendMessage(tabId, { type: 'ss.requestSnapshot' }); } catch { /* pagina nu are content script (ex. pagină internă) */ }
    const st2 = await getTab(tabId); await recomputePage(tabId, st2); await putTab(st2);
    void analysis;
    await setBadge(tabId, (st2.page ?? result).level, result.confirmed);
    return buildReport(tabId, url);
  }

  /* ------------------------------------------------------------------ descărcări */
  async function onDownloadCreated(item) {
    const cfg = await getConfig();
    if (!cfg.downloads.monitor || !cfg.protection.enabled) return;
    await init();
    const finalUrl = item.finalUrl || item.url || '';
    const source = await assessUrl(finalUrl);
    const nameFromUrl = (() => { try { return decodeURIComponent(new URL(finalUrl).pathname.split('/').pop() || ''); } catch { return ''; } })();
    const filename = (item.filename && item.filename.split(/[\\/]/).pop()) || nameFromUrl;
    const tabState = await findTabByReferrer(item.referrer);
    const dl = analyzeDownload({ filename, url: item.url, finalUrl, referrer: item.referrer, mime: item.mime, sourceLevel: source.result.level, sourceConfirmed: source.result.confirmed, pageLevel: tabState?.page?.level ?? tabState?.result?.level, byPage: !!tabState && ((tabState.behavior?.findings ?? []).some((f) => f.id === 'page-download')) });
    if (dl.level === 'ok') return;
    const level = dl.level === 'danger' ? 'DANGEROUS' : dl.level === 'warn' ? 'SUSPICIOUS' : 'SAFE';
    const ev = await log.record({ type: 'download', level: level === 'SAFE' ? 'UNKNOWN' : level, url: finalUrl, host: dl.host, summary: `${dl.summary}: ${safeText(dl.filename, 80)}`, userExplanation: dl.indicators.map((i) => i.explain).join(' '), action: dl.level === 'danger' && cfg.downloads.pauseDangerous ? 'paused' : 'observed', recommendation: 'Nu deschide fișierul dacă nu ai încredere în sursă. Sentinel Shield nu poate scana conținutul fișierelor.', indicators: dl.indicators, sources: source.result.sources });
    void ev;
    if (dl.level === 'danger' && cfg.downloads.pauseDangerous && !(await session.get(`dlWarned:${item.id}`, false))) {
      await session.set(`dlWarned:${item.id}`, true);
      try { await chrome.downloads.pause(item.id); } catch { /* deja terminat */ }
      const id = await createWarning({ tabId: null, url: finalUrl, kind: 'download', result: { ...source.result, level: 'DANGEROUS', indicators: dl.indicators, summary: dl.summary, userExplanation: dl.indicators.map((i) => i.explain).join(' '), recommendation: 'Anulează descărcarea dacă nu ai inițiat-o sau nu recunoști sursa. Sentinel Shield nu poate scana conținutul fișierului; Chrome își păstrează propriile verificări.' }, extra: { download: { downloadId: item.id, filename: safeText(dl.filename, 120) } } });
      await chrome.tabs.create({ url: chrome.runtime.getURL(`src/pages/warning/download.html?id=${id}`) });
    }
  }
  async function findTabByReferrer(referrer) {
    if (!referrer) return null;
    const o = originOf(referrer); if (!o) return null;
    const keys = await session.all();
    for (const [k, v] of Object.entries(keys)) if (k.startsWith('tab:') && v?.url && originOf(v.url) === o) return v;
    return null;
  }
  async function getDownloadWarning(p, sender) {
    const w = await session.get(`warn:${p.id}`, null);
    if (!w || w.kind !== 'download') return { ok: false, error: 'not-found' };
    void sender;
    return { ok: true, warning: warningView(w) };
  }
  async function downloadDecision(p) {
    const w = await session.get(`warn:${p.id}`, null);
    if (!w || w.kind !== 'download' || w.used) return { ok: false, error: 'not-found' };
    w.used = true; await session.set(`warn:${w.id}`, w);
    const dlId = w.download.downloadId;
    try {
      if (p.action === 'cancel') await chrome.downloads.cancel(dlId); else await chrome.downloads.resume(dlId);
    } catch { return { ok: false, error: 'download-unavailable' }; }
    await log.record({ type: 'download', level: 'DANGEROUS', url: w.url, host: analyzeUrl(w.url).hostAscii, summary: `Utilizatorul a ${p.action === 'cancel' ? 'anulat' : 'permis continuarea'} descărcării ${w.download.filename}`, action: p.action === 'cancel' ? 'cancelled-by-user' : 'user-continued', indicators: w.result.indicators });
    return { ok: true };
  }

  /* ------------------------------------------------------------------ configurare, liste, DNR */
  async function setConfig({ patch }) {
    const cur = await getConfig();
    const next = validateConfig(deepMerge(cur, patch));
    // consimțământ: nu poate fi „implicit"; dezactivarea unui furnizor șterge consimțământul
    for (const [id, p] of Object.entries(next.reputation.providers)) if (!p.enabled) p.consent = false;
    await local.set('config', next); configCache = next;
    rep.clearCache();
    await syncDnr();
    return { ok: true, config: sanitizeConfigForUi(next) };
  }
  function sanitizeConfigForUi(cfg) {
    const c = structuredClone(cfg);
    for (const p of Object.values(c.reputation.providers)) for (const k of ['authKey', 'apiKey']) if (k in p) { p[`${k}Set`] = !!p[k]; p[k] = ''; }
    return c;
  }
  async function getConfigForUi() { return { ok: true, config: sanitizeConfigForUi(await getConfig()) }; }

  async function importList({ text, name }) {
    await init();
    const parsed = parseUserList(text, name);
    const existing = await local.get('userList', []);
    const map = new Map(existing.map((e) => [e.domain, e]));
    for (const e of parsed.entries) map.set(e.domain, e);
    const merged = [...map.values()].slice(-50000);
    await local.set('userList', merged); lists.setUser(merged);
    await syncDnr();
    return { ok: true, added: parsed.entries.length, skipped: parsed.skipped, total: merged.length };
  }
  async function clearUserList() { await local.set('userList', []); lists.setUser([]); await syncDnr(); return { ok: true }; }

  async function syncFeeds() {
    await init();
    const cfg = await getConfig();
    if (!cfg.feeds.enabled) return { ok: false, error: 'feeds-disabled' };
    const hosts = new Set(); const urls = new Set(); const per = {};
    for (const src of cfg.feeds.sources.filter((s) => s.enabled)) {
      const origin = new URL(src.url).origin + '/*';
      per[src.id] = { name: src.name, at: now(), ok: false, count: 0, error: null };
      try {
        if (!(await chrome.permissions.contains({ origins: [origin] }))) { per[src.id].error = 'permisiune de rețea neacordată'; continue; }
        const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 30000);
        const res = await fetchImpl(src.url, { signal: ctrl.signal, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
        clearTimeout(t);
        if (!res.ok) { per[src.id].error = `HTTP ${res.status}`; continue; }
        const text = await res.text();
        if (text.length > MAX_FEED_BYTES) { per[src.id].error = 'feed prea mare'; continue; }
        const parsed = parseFeed(text, src.format);
        parsed.hosts.forEach((h) => hosts.add(h)); parsed.urls.forEach((u) => urls.add(u));
        per[src.id].ok = true; per[src.id].count = parsed.hosts.length + parsed.urls.length;
      } catch (e) { per[src.id].error = e?.name === 'AbortError' ? 'timeout' : 'eroare de rețea'; }
    }
    // Dacă TOATE sursele au eșuat, păstrăm lista veche (protecția existentă nu dispare).
    if (Object.values(per).some((p) => p.ok)) {
      const feed = { hosts: [...hosts].slice(0, 100000), urls: [...urls].slice(0, 100000), updatedAt: now(), per };
      await local.set('feedList', feed); lists.setFeed(feed);
      await syncDnr();
    } else await local.set('feedStatus', { at: now(), per });
    return { ok: true, per };
  }
  async function getListStatus() {
    await init();
    const feed = await local.get('feedList', null);
    return { ok: true, stats: lists.stats(), feed: feed ? { updatedAt: feed.updatedAt, per: feed.per } : null, userCount: (await local.get('userList', [])).length };
  }

  async function testProvider({ id }) {
    const cfg = await getConfig();
    const p = cfg.reputation.providers[id];
    if (!p?.enabled || !p.consent) return { ok: false, error: 'needs-consent' };
    const a = analyzeUrl('https://example.com/');
    const r = await rep.checkOnline(a, { ...cfg, reputation: { ...cfg.reputation, providers: { ...cfg.reputation.providers, ...(id === 'urlhaus' ? { safebrowsing: { ...cfg.reputation.providers.safebrowsing, enabled: false } } : { urlhaus: { ...cfg.reputation.providers.urlhaus, enabled: false } }) } } });
    rep.clearCache();
    return { ok: true, result: r.find((x) => x.source === id) ?? null };
  }

  async function dnrDomains() {
    await init();
    const out = new Set();
    const user = await local.get('userList', []);
    for (const e of user) out.add(e.domain);
    const bundled = await loadBundled(); for (const e of bundled.entries ?? []) out.add(e.domain);
    const feed = await local.get('feedList', null); for (const h of feed?.hosts ?? []) out.add(h);
    return [...out].slice(0, 20000);
  }
  async function syncDnr() {
    const cfg = await getConfig();
    const api = chrome.declarativeNetRequest;
    if (!api?.updateDynamicRules) return { ok: false, error: 'dnr-unavailable' };
    try {
      const existing = (await api.getDynamicRules()).map((r) => r.id);
      let rules = [];
      if (cfg.protection.strongBlocking && (await chrome.permissions.contains({ origins: ['<all_urls>'] }))) {
        const domains = await dnrDomains();
        const excluded = (await getExceptions()).filter((e) => e.kind === 'confirmed').map((e) => e.host);
        const base = chrome.runtime.getURL(WARNING_PATH);
        for (let i = 0; i * 1000 < domains.length; i++) {
          rules.push({ id: i + 1, priority: 1, action: { type: 'redirect', redirect: { regexSubstitution: `${base}?dnr=1&u=\\1` } },
            condition: { regexFilter: '^(https?://.*)$', requestDomains: domains.slice(i * 1000, (i + 1) * 1000), ...(excluded.length ? { excludedRequestDomains: excluded } : {}), resourceTypes: ['main_frame'] } });
        }
      }
      await api.updateDynamicRules({ removeRuleIds: existing, addRules: rules });
      return { ok: true, rules: rules.length };
    } catch (e) { return { ok: false, error: 'dnr-failed' }; }
  }
  async function dnrAllow(tabId, host, minutes) {
    const api = chrome.declarativeNetRequest;
    if (!api?.updateSessionRules) return;
    try {
      const id = 1000 + (tabId % 100000);
      await api.updateSessionRules({ removeRuleIds: [id], addRules: [{ id, priority: 10, action: { type: 'allow' }, condition: { requestDomains: [host], tabIds: [tabId], resourceTypes: ['main_frame'] } }] });
    } catch { /* regula de excepție e best-effort */ }
    void minutes;
  }

  async function addException(p) {
    await init();
    const cfg = await getConfig();
    const probe = analyzeUrl(`${p.scheme}://${p.host}/`);
    const confirmed = evaluate({ analysis: probe, reputation: [rep.checkLocal(probe)], config: cfg }).confirmed;
    if (confirmed && !(p.kind === 'confirmed' && p.acknowledged)) return { ok: false, error: 'confirmed-requires-ack', confirmed: true };
    if (p.kind === 'confirmed' && !confirmed) p.kind = 'heuristic';
    const list = (await getExceptions()).filter((e) => !(e.host === p.host && e.scheme === p.scheme));
    list.push({ host: p.host, scheme: p.scheme, kind: p.kind, createdAt: now(), expiresAt: p.ttlDays ? now() + p.ttlDays * 86400000 : null });
    await local.set('exceptions', list);
    await log.record({ type: 'exception', level: confirmed ? 'DANGEROUS' : 'SUSPICIOUS', url: `${p.scheme}://${p.host}/`, host: p.host, summary: `Excepție adăugată de utilizator (${p.kind === 'confirmed' ? 'peste o amenințare confirmată' : 'alertă euristică'})`, action: 'exception-added' });
    await syncDnr();
    return { ok: true, confirmed };
  }
  async function removeException(p) {
    const list = (await getExceptions()).filter((e) => !(e.host === p.host && e.scheme === p.scheme));
    await local.set('exceptions', list); await syncDnr();
    return { ok: true };
  }

  /* ------------------------------------------------------------------ router de mesaje */
  async function handleMessage(msg, sender) {
    try {
      if (!isObj(msg) || typeof msg.type !== 'string') return { ok: false, error: 'bad-message' };
      if (CONTENT_ALLOWED.has(msg.type)) return sender?.tab ? await withTab(sender.tab.id, () => onObservation(msg, sender)) : await onObservation(msg, sender);
      // Toate celelalte mesaje: DOAR de la paginile proprii ale extensiei (nu de la site-uri, nici din content scripts)
      if (!isExtensionPageSender(sender, extId)) return { ok: false, error: 'forbidden-sender' };
      if ([MSG.GET_WARNING, MSG.GRANT_PASS, MSG.GO_SAFE].includes(msg.type) && sender.frameId !== 0) return { ok: false, error: 'frame-not-allowed' }; // anti-clickjacking: pagina de avertizare nu funcționează încorporată
      const validator = REQUEST_VALIDATORS[msg.type];
      if (!validator) return { ok: false, error: 'unknown-type' };
      const p = validator(msg);
      if (!p) return { ok: false, error: 'invalid-payload' };
      switch (msg.type) {
        case MSG.GET_TAB_REPORT: return await buildReport(p.tabId, p.url);
        case MSG.ANALYZE_PAGE: return await analyzePage(p, sender, p.url);
        case MSG.GET_WARNING: return await getWarning(p, sender);
        case MSG.GRANT_PASS: return await grantPass(p, sender);
        case MSG.GO_SAFE: return await goSafe(p, sender);
        case MSG.GET_EVENTS: return { ok: true, events: await log.query(p) };
        case MSG.GET_STATS: return { ok: true, stats: await log.stats() };
        case MSG.CLEAR_EVENTS: await log.clear(); return { ok: true };
        case MSG.EXPORT_EVENTS: return { ok: true, data: await log.exportJson(p.detail) };
        case MSG.GET_CONFIG: return await getConfigForUi();
        case MSG.SET_CONFIG: return await setConfig(p);
        case MSG.ADD_EXCEPTION: return await addException(p);
        case MSG.REMOVE_EXCEPTION: return await removeException(p);
        case MSG.GET_EXCEPTIONS: return { ok: true, exceptions: await getExceptions() };
        case MSG.IMPORT_LIST: return await importList(p);
        case MSG.CLEAR_USER_LIST: return await clearUserList();
        case MSG.SYNC_FEEDS: return await syncFeeds();
        case MSG.GET_LIST_STATUS: return await getListStatus();
        case MSG.TEST_PROVIDER: return await testProvider(p);
        case MSG.GET_PROVIDERS_INFO: return { ok: true, providers: Object.values(PROVIDERS).map((x) => ({ id: x.id, name: x.name, sends: x.sends, disclosure: x.disclosure, origin: x.origin })) };
        case MSG.DOWNLOAD_DECISION: return await downloadDecision(p);
        case MSG.GET_DOWNLOAD_WARNING: return await getDownloadWarning(p, sender);
        case MSG.ENSURE_PERMISSION: return { ok: true, granted: await chrome.permissions.contains({ origins: p.what === 'strongBlocking' ? ['<all_urls>'] : [] }) };
        default: return { ok: false, error: 'unknown-type' };
      }
    } catch (e) {
      return { ok: false, error: 'internal-error' };
    }
  }

  async function onTabRemoved(tabId) {
    await session.remove(tabKey(tabId)); await session.remove(`lastWarn:${tabId}`); rateByTab.delete(tabId);
    const all = await session.all();
    for (const k of Object.keys(all)) if (k.startsWith(`pass:${tabId}:`)) await session.remove(k);
  }

  return { init, handleMessage, onBeforeNavigate, onCommitted, onDownloadCreated, onTabRemoved, syncFeeds, syncDnr, getConfig, assessUrl, log, lists, rep, _session: session, _local: local, mergeSnapshots };
}
