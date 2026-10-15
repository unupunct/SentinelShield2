// Module extensibil de reputație: liste locale (mereu active) + furnizori online opționali (consimțământ explicit).
// Nu există chei sau secrete în cod; cheile sunt introduse de utilizator în Setări.
import { splitHost, isInternalHost } from './psl.js';
import { isAnyOfficial } from './brands.js';
import { containsSensitiveData } from './sanitize.js';

const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/;
export const MAX_FEED_ENTRIES = 100000;
export const MAX_FEED_BYTES = 8 * 1024 * 1024;

/* ------------------------------------------------------------------ liste locale */

export function createLocalLists() {
  const bundled = new Map();   // domain -> entry
  const user = new Map();      // domain -> entry
  const feedHosts = new Set();
  const feedUrls = new Set();  // host+path exacte
  let feedMeta = { updatedAt: null, count: 0 };

  const api = {
    setBundled(list) {
      bundled.clear();
      for (const e of list?.entries ?? []) if (typeof e.domain === 'string') bundled.set(e.domain.toLowerCase(), { ...e, list: list.name ?? 'Listă inclusă' });
    },
    setUser(entries) {
      user.clear();
      for (const e of entries ?? []) if (typeof e.domain === 'string') user.set(e.domain.toLowerCase(), { ...e, list: e.list ?? 'Listă utilizator' });
    },
    setFeed({ hosts = [], urls = [], updatedAt = null } = {}) {
      feedHosts.clear(); feedUrls.clear();
      for (const h of hosts) feedHosts.add(h);
      for (const u of urls) feedUrls.add(u);
      feedMeta = { updatedAt, count: feedHosts.size + feedUrls.size };
    },
    stats() { return { bundled: bundled.size, user: user.size, feed: feedMeta.count, feedUpdatedAt: feedMeta.updatedAt }; },
    /** Caută gazda și părinții ei; potrivește subdomeniile unui domeniu listat. */
    lookup(host, hostPathKey = null) {
      const labels = host.split('.');
      for (let i = 0; i < labels.length - 1; i++) {
        const d = labels.slice(i).join('.');
        const u = user.get(d); if (u) return { ...u, domain: d, matchedKind: 'domain', origin: 'user' };
        const b = bundled.get(d); if (b) return { ...b, domain: d, matchedKind: 'domain', origin: 'bundled' };
        if (feedHosts.has(d)) return { domain: d, threatType: 'phishing', list: 'Feed importat', matchedKind: 'domain', origin: 'feed' };
      }
      if (hostPathKey && feedUrls.has(hostPathKey)) return { domain: host, threatType: 'phishing', list: 'Feed importat (URL exact)', matchedKind: 'url', origin: 'feed' };
      return null;
    }
  };
  return api;
}

/** Parsează text de feed. Aplică limite; ignoră intrări invalide, gazde interne și gazde de brand oficiale/găzduire partajată. */
export function parseFeed(text, format) {
  if (typeof text !== 'string' || text.length > MAX_FEED_BYTES) return { hosts: [], urls: [], rejected: 'feed prea mare sau invalid' };
  const hosts = new Set(); const urls = new Set(); let skipped = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    if (hosts.size + urls.size >= MAX_FEED_ENTRIES) break;
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith('//')) continue;
    try {
      if (format === 'urls') {
        const u = new URL(line);
        if (!/^https?:$/.test(u.protocol)) { skipped++; continue; }
        const host = u.hostname.toLowerCase();
        const sp = splitHost(host);
        urls.add(host + u.pathname);
        if (!sp.sharedHosting && !sp.isIp && !isAnyOfficial(sp.registrable) && !isInternalHost(host)) hosts.add(host);
      } else {
        const tokens = line.split(/\s+/);
        const cand = (format === 'hosts' && tokens.length > 1 ? tokens[1] : tokens[0]).toLowerCase().replace(/\.$/, '');
        if (!HOST_RE.test(cand) || ['localhost', 'localhost.localdomain', 'broadcasthost'].includes(cand) || isInternalHost(cand)) { skipped++; continue; }
        const sp = splitHost(cand);
        if (sp.sharedHosting && cand === sp.suffix) { skipped++; continue; }
        if (isAnyOfficial(sp.registrable)) { skipped++; continue; } // nu se blochează domenii oficiale ale brandurilor din liste externe
        hosts.add(cand);
      }
    } catch { skipped++; }
  }
  return { hosts: [...hosts], urls: [...urls], skipped };
}

/** Importă text lipit de utilizator (formatul se deduce: URL-uri / hosts / domenii). */
export function parseUserList(text, listName = 'Listă importată') {
  const lines = String(text).split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#'));
  const looksUrl = lines.some((l) => /^https?:\/\//i.test(l.trim()));
  const looksHosts = lines.some((l) => /^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+/.test(l));
  const parsed = parseFeed(text, looksUrl ? 'urls' : looksHosts ? 'hosts' : 'domains');
  return { entries: parsed.hosts.map((d) => ({ domain: d, threatType: 'phishing', list: listName, addedAt: Date.now() })), skipped: parsed.skipped ?? 0 };
}

/* ------------------------------------------------------------------ furnizori online */

async function fetchJson(fetchImpl, url, init, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { ...init, signal: ctrl.signal, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : {}; } catch { /* non-JSON */ }
    return { status: res.status, json };
  } finally { clearTimeout(timer); }
}

export const PROVIDERS = {
  urlhaus: {
    id: 'urlhaus', name: 'URLhaus (abuse.ch)', origin: 'https://urlhaus-api.abuse.ch/*',
    sends: 'host', // se trimite DOAR numele gazdei, nu URL-ul complet
    disclosure: 'Se trimite către urlhaus-api.abuse.ch numele domeniului vizitat (fără cale, parametri sau fragment), împreună cu cheia ta Auth-Key. Scop: verificarea dacă domeniul distribuie malware.',
    ready: (c) => !!c.authKey,
    async check({ analysis, cfg, fetchImpl }) {
      const body = new URLSearchParams({ host: analysis.hostAscii });
      const { status, json } = await fetchJson(fetchImpl, 'https://urlhaus-api.abuse.ch/v1/host/', { method: 'POST', headers: { 'Auth-Key': cfg.providers.urlhaus.authKey, 'Content-Type': 'application/x-www-form-urlencoded' }, body }, cfg.timeoutMs);
      if (status === 401 || status === 403) return { status: 'error', detail: 'Cheie Auth-Key respinsă' };
      if (status === 429) return { status: 'rate-limited', detail: 'Limită de cereri la furnizor' };
      if (status >= 500 || status === 0 || !json) return { status: 'error', detail: `Răspuns invalid (HTTP ${status})` };
      const qs = json.query_status ?? json.query_staus;
      if (qs === 'no_results') return { status: 'clean', detail: 'Domeniul nu apare în URLhaus' };
      if (qs === 'ok') {
        const online = (json.urls ?? []).filter((x) => x.url_status === 'online');
        if (online.length || Object.values(json.blacklists ?? {}).some((v) => v && v !== 'not listed')) {
          return { status: 'malicious', threatType: 'malware_download', matchedDomain: analysis.hostAscii, matchedKind: 'domain', detail: `${online.length} URL(uri) active listate` };
        }
        return { status: 'clean', detail: 'Domeniul apare în istoricul URLhaus, dar fără URL-uri active acum' };
      }
      return { status: 'error', detail: `query_status=${String(qs).slice(0, 30)}` };
    }
  },
  safebrowsing: {
    id: 'safebrowsing', name: 'Google Safe Browsing', origin: 'https://safebrowsing.googleapis.com/*',
    sends: 'url',
    disclosure: 'Se trimite către Google (safebrowsing.googleapis.com) adresa vizitată — implicit fără parametri și fragment — împreună cu cheia ta API. Google poate înregistra cererea conform propriilor condiții. Verifică termenii de utilizare ai API-ului pentru cazul tău de utilizare.',
    ready: (c) => !!c.apiKey,
    async check({ analysis, cfg, fetchImpl }) {
      const full = analysis.normalized;
      const url = cfg.providers.safebrowsing.sendQuery ? full : `${analysis.origin}${new URL(full).pathname}`;
      const body = JSON.stringify({
        client: { clientId: 'sentinel-shield', clientVersion: '0.1.0' },
        threatInfo: { threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }] }
      });
      const { status, json } = await fetchJson(fetchImpl, `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(cfg.providers.safebrowsing.apiKey)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }, cfg.timeoutMs);
      if (status === 400 || status === 403) return { status: 'error', detail: 'Cheie API respinsă sau cerere invalidă' };
      if (status === 429) return { status: 'rate-limited', detail: 'Limită de cereri la furnizor' };
      if (status >= 500 || status === 0 || json == null) return { status: 'error', detail: `Răspuns invalid (HTTP ${status})` };
      if (Array.isArray(json.matches) && json.matches.length) return { status: 'malicious', threatType: json.matches[0].threatType, matchedDomain: analysis.hostAscii, matchedKind: 'url', detail: json.matches[0].threatType };
      return { status: 'clean', detail: 'Nicio potrivire în listele Safe Browsing' };
    }
  }
};

/* ------------------------------------------------------------------ orchestrator */

/**
 * @param {{fetchImpl:Function, now?:()=>number, lists:ReturnType<typeof createLocalLists>, hasPermission?:(origin:string)=>Promise<boolean>}} deps
 */
export function createReputationService({ fetchImpl, now = () => Date.now(), lists, hasPermission = async () => true }) {
  const cache = new Map();
  const windows = new Map();   // provider -> timestamps (rate limit)
  const failures = new Map();  // provider -> {count, openUntil}

  function rateOk(id, limit) {
    const t = now();
    const arr = (windows.get(id) ?? []).filter((x) => t - x < 60000);
    if (arr.length >= limit) { windows.set(id, arr); return false; }
    arr.push(t); windows.set(id, arr); return true;
  }

  return {
    /** Verificare locală: sincronă, funcționează offline. */
    checkLocal(analysis) {
      if (!analysis?.isWeb) return { source: 'local-lists', name: 'Liste locale Sentinel Shield', status: 'unchecked', checkedAt: now(), detail: 'URL non-web' };
      const hit = lists.lookup(analysis.hostAscii, analysis.hostAscii + new URL(analysis.normalized).pathname);
      const s = lists.stats();
      const base = { source: 'local-lists', name: `Liste locale (${hit?.list ?? 'Sentinel Shield'})`, checkedAt: now(), listStats: s };
      if (hit) return { ...base, status: 'malicious', threatType: hit.threatType ?? 'phishing', matchedDomain: hit.domain, matchedKind: hit.matchedKind, origin: hit.origin, detail: `Potrivire în lista „${hit.list}”` };
      return { ...base, name: 'Liste locale Sentinel Shield', status: 'clean', detail: `Nu apare în ${s.bundled + s.user + s.feed} intrări locale` };
    },

    /** Verificări online — doar pentru furnizorii activați ȘI cu consimțământ explicit ȘI permisiune de rețea acordată. */
    async checkOnline(analysis, config) {
      const out = [];
      if (!analysis?.isWeb) return out;
      const rep = config.reputation;
      for (const provider of Object.values(PROVIDERS)) {
        const pc = rep.providers[provider.id];
        if (!pc?.enabled) continue;
        const meta = { source: provider.id, name: provider.name, checkedAt: now(), sends: provider.sends };
        if (!pc.consent) { out.push({ ...meta, status: 'needs-consent', detail: 'Consimțământul pentru transmiterea datelor nu a fost acordat' }); continue; }
        if (!provider.ready(pc)) { out.push({ ...meta, status: 'unavailable', detail: 'Cheie API neconfigurată' }); continue; }
        if (analysis.internal || analysis.hadCredentials) { out.push({ ...meta, status: 'skipped', detail: 'URL intern sau cu credențiale: nu se trimite' }); continue; }
        if (provider.sends === 'url' && containsSensitiveData(pc.sendQuery ? analysis.normalized : analysis.origin + new URL(analysis.normalized).pathname)) { out.push({ ...meta, status: 'skipped', detail: 'URL-ul conține date sensibile: nu se trimite' }); continue; }
        const key = `${provider.id}|${provider.sends === 'host' ? analysis.hostAscii : analysis.normalized}`;
        const hit = cache.get(key);
        if (hit && hit.expires > now()) { out.push({ ...meta, ...hit.value, checkedAt: hit.value.checkedAt, cached: true }); continue; }
        const fail = failures.get(provider.id);
        if (fail && fail.openUntil > now()) { out.push({ ...meta, status: 'unavailable', detail: 'Furnizor temporar suspendat după erori repetate' }); continue; }
        if (!(await hasPermission(provider.origin))) { out.push({ ...meta, status: 'unavailable', detail: 'Permisiunea de rețea pentru furnizor nu este acordată' }); continue; }
        if (!rateOk(provider.id, rep.rateLimitPerMinute)) { out.push({ ...meta, status: 'rate-limited', detail: 'Limita locală de cereri atinsă' }); continue; }
        let value;
        try {
          const r = await provider.check({ analysis, cfg: rep, fetchImpl });
          value = { ...meta, checkedAt: now(), ...r };
        } catch (e) {
          value = { ...meta, checkedAt: now(), status: e?.name === 'AbortError' ? 'timeout' : 'error', detail: e?.name === 'AbortError' ? `Timeout după ${rep.timeoutMs} ms` : 'Eroare de rețea' };
        }
        const failed = ['error', 'timeout', 'unavailable', 'rate-limited'].includes(value.status);
        const f = failures.get(provider.id) ?? { count: 0, openUntil: 0 };
        if (failed && value.status !== 'rate-limited') { f.count++; if (f.count >= 3) { f.openUntil = now() + 120000; f.count = 0; } } else if (!failed) f.count = 0;
        failures.set(provider.id, f);
        const ttl = (failed ? rep.cacheMinutes.error : value.status === 'malicious' ? rep.cacheMinutes.malicious : rep.cacheMinutes.clean) * 60000;
        cache.set(key, { value, expires: now() + ttl });
        if (cache.size > 1000) cache.delete(cache.keys().next().value);
        out.push(value);
      }
      return out;
    },
    clearCache() { cache.clear(); },
    _cache: cache
  };
}
