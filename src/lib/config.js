// Configurare implicită + validare. Nimic din această configurație nu conține secrete; cheile API sunt introduse de utilizator
// și stocate doar în chrome.storage.local.
export const DEFAULT_CONFIG = Object.freeze({
  version: 1,
  protection: { enabled: true, warnOnDangerous: true, warnOnSuspicious: false, strongBlocking: false },
  policy: { confirmedBypass: 'typed', heuristicBypass: 'hold' }, // typed | never ; hold | never
  passTtlMinutes: 10,
  scoring: {
    weights: { info: 0, low: 5, medium: 15, high: 30 },
    overrides: { 'homograph-brand': 70, 'brand-char-substitution': 60, 'brand-in-subdomain': 45, 'at-sign-deception': 40, 'mixed-script': 40, 'ip-obfuscated': 35, 'redirect-to-flagged': 60 },
    thresholds: { suspicious: 15, dangerous: 60 }
  },
  privacy: { logEnabled: true, logUrlMode: 'redact-sensitive', retentionDays: 30, maxEvents: 1000 },
  reputation: {
    cacheMinutes: { clean: 30, malicious: 360, error: 2 },
    timeoutMs: 4000,
    rateLimitPerMinute: 20,
    providers: {
      urlhaus: { enabled: false, consent: false, authKey: '' },
      safebrowsing: { enabled: false, consent: false, apiKey: '', sendQuery: false }
    }
  },
  feeds: {
    enabled: false,
    intervalHours: 12,
    sources: [
      { id: 'urlhaus-hostfile', name: 'URLhaus (listă de gazde)', url: 'https://urlhaus.abuse.ch/downloads/hostfile/', format: 'hosts', enabled: false },
      { id: 'openphish', name: 'OpenPhish (feed comunitar)', url: 'https://openphish.com/feed.txt', format: 'urls', enabled: false }
    ]
  },
  behavior: { enabled: true },
  downloads: { monitor: true, pauseDangerous: true }
});

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const clamp = (n, lo, hi, d) => (Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d);

/** Îmbină configurația stocată peste cea implicită, ignorând chei necunoscute și valori de tip greșit. */
export function mergeConfig(stored, defaults = DEFAULT_CONFIG) {
  const out = {};
  for (const [k, def] of Object.entries(defaults)) {
    const v = isObj(stored) ? stored[k] : undefined;
    if (isObj(def)) out[k] = mergeConfig(isObj(v) ? v : {}, def);
    else if (Array.isArray(def)) out[k] = Array.isArray(v) ? v : def.map((x) => (isObj(x) ? { ...x } : x));
    else out[k] = typeof v === typeof def ? v : def;
  }
  return out;
}

const ENUMS = {
  'policy.confirmedBypass': ['typed', 'never'], 'policy.heuristicBypass': ['hold', 'never'],
  'privacy.logUrlMode': ['redact-sensitive', 'strip-query', 'host-only', 'full']
};

export function validateConfig(cfg) {
  const c = mergeConfig(cfg);
  for (const [path, allowed] of Object.entries(ENUMS)) {
    const [a, b] = path.split('.');
    if (!allowed.includes(c[a][b])) c[a][b] = DEFAULT_CONFIG[a][b];
  }
  c.passTtlMinutes = clamp(c.passTtlMinutes, 1, 120, 10);
  c.privacy.retentionDays = clamp(c.privacy.retentionDays, 1, 365, 30);
  c.privacy.maxEvents = clamp(c.privacy.maxEvents, 50, 5000, 1000);
  c.reputation.timeoutMs = clamp(c.reputation.timeoutMs, 500, 15000, 4000);
  c.reputation.rateLimitPerMinute = clamp(c.reputation.rateLimitPerMinute, 1, 120, 20);
  c.feeds.intervalHours = clamp(c.feeds.intervalHours, 1, 168, 12);
  const t = c.scoring.thresholds;
  t.suspicious = clamp(t.suspicious, 1, 100, 15);
  t.dangerous = clamp(t.dangerous, t.suspicious + 1, 200, 60);
  for (const k of Object.keys(c.scoring.weights)) c.scoring.weights[k] = clamp(c.scoring.weights[k], 0, 100, DEFAULT_CONFIG.scoring.weights[k]);
  // Consimțământul și cheile sunt șiruri/booleeni; chei prea lungi sunt respinse.
  for (const p of Object.values(c.reputation.providers)) {
    for (const key of ['authKey', 'apiKey']) if (key in p && (typeof p[key] !== 'string' || p[key].length > 200 || /\s/.test(p[key]))) p[key] = '';
  }
  c.feeds.sources = c.feeds.sources.filter((s) => isObj(s) && typeof s.url === 'string' && /^https:\/\//.test(s.url) && s.url.length < 500)
    .map((s) => ({ id: String(s.id).slice(0, 40), name: String(s.name).slice(0, 80), url: s.url, format: ['hosts', 'domains', 'urls'].includes(s.format) ? s.format : 'domains', enabled: !!s.enabled }));
  return c;
}
