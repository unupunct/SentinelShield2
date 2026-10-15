// Validarea mesajelor. Tot ce vine dintr-un content script / pagină este NEÎNCREDERE: se construiește un obiect nou,
// cu câmpuri whitelisted, tipuri verificate, enumerări și limite stricte. Câmpurile necunoscute se ignoră.
export const MSG = Object.freeze({
  OBSERVATION: 'ss.observation',
  GET_TAB_REPORT: 'ss.getTabReport', ANALYZE_PAGE: 'ss.analyzePage', GET_WARNING: 'ss.getWarning', GRANT_PASS: 'ss.grantPass', GO_SAFE: 'ss.goSafe',
  GET_EVENTS: 'ss.getEvents', GET_STATS: 'ss.getStats', CLEAR_EVENTS: 'ss.clearEvents', EXPORT_EVENTS: 'ss.exportEvents',
  GET_CONFIG: 'ss.getConfig', SET_CONFIG: 'ss.setConfig', ADD_EXCEPTION: 'ss.addException', REMOVE_EXCEPTION: 'ss.removeException', GET_EXCEPTIONS: 'ss.getExceptions',
  IMPORT_LIST: 'ss.importList', CLEAR_USER_LIST: 'ss.clearUserList', SYNC_FEEDS: 'ss.syncFeeds', GET_LIST_STATUS: 'ss.getListStatus', TEST_PROVIDER: 'ss.testProvider',
  DOWNLOAD_DECISION: 'ss.downloadDecision', GET_DOWNLOAD_WARNING: 'ss.getDownloadWarning', GET_PROVIDERS_INFO: 'ss.getProvidersInfo', ENSURE_PERMISSION: 'ss.ensurePermission'
});

export const CONTENT_ALLOWED = new Set([MSG.OBSERVATION]);

const HOST_RE = /^[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?$/;
const int = (v, max = 10000) => (Number.isFinite(v) ? Math.max(0, Math.min(max, Math.floor(v))) : 0);
const pick = (v, allowed, def) => (allowed.includes(v) ? v : def);
const host = (v) => (typeof v === 'string' && v.length <= 253 && HOST_RE.test(v.toLowerCase()) ? v.toLowerCase() : null);
const arr = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

const PERM_STATES = ['granted', 'denied', 'prompt', 'unknown'];
const PERM_KEYS = ['geolocation', 'camera', 'microphone', 'notifications', 'clipboard-read', 'clipboard-write'];
const REQ_KEYS = ['geolocation', 'camera', 'microphone', 'screen', 'clipboard-read', 'clipboard-write', 'notifications', 'device-enumeration'];
const API_KEYS = ['geolocation', 'mediaDevices', 'clipboard', 'notifications'];
const NET_TYPES = ['script', 'fetch', 'xhr', 'beacon', 'websocket', 'img', 'css', 'iframe', 'font', 'media', 'other'];
const DECL_KINDS = ['script', 'iframe', 'form', 'link', 'img'];
const TEXT_CODES = ['virus-warning', 'tech-support', 'run-command', 'disable-protection', 'extension-install'];

/** Validează și normalizează un instantaneu de observații. */
export function validateSnapshot(raw) {
  if (!isObj(raw)) return { ok: false, error: 'not-object' };
  const s = { permissions: {}, api: [], requests: {}, clipboardCommandLike: int(raw.clipboardCommandLike, 1000), windowOpens: { total: 0, noGesture: 0 }, downloads: { total: 0, noGesture: 0 }, net: { observed: [], declared: [] }, forms: { passwordFields: 0, cardFields: 0, crossSiteActions: [], submits: [], hiddenFrames: 0 }, text: [], hints: { hasMap: false, hasVideo: false, title: '' } };
  if (isObj(raw.permissions)) for (const k of PERM_KEYS) s.permissions[k] = pick(raw.permissions[k], PERM_STATES, 'unknown');
  s.api = arr(raw.api, 10).filter((a) => API_KEYS.includes(a));
  if (isObj(raw.requests)) {
    for (const k of REQ_KEYS) {
      const r = raw.requests[k];
      if (isObj(r)) s.requests[k] = { count: int(r.count, 1000), granted: int(r.granted, 1000), denied: int(r.denied, 1000), errors: int(r.errors, 1000), noGesture: int(r.noGesture, 1000) };
    }
  }
  if (isObj(raw.windowOpens)) s.windowOpens = { total: int(raw.windowOpens.total, 1000), noGesture: int(raw.windowOpens.noGesture, 1000) };
  if (isObj(raw.downloads)) s.downloads = { total: int(raw.downloads.total, 1000), noGesture: int(raw.downloads.noGesture, 1000) };
  if (isObj(raw.net)) {
    const seen = new Set();
    for (const o of arr(raw.net.observed, 150)) {
      const h = isObj(o) ? host(o.host) : null; if (!h) continue;
      const type = pick(o.type, NET_TYPES, 'other'); const key = h + '|' + type; if (seen.has(key)) continue; seen.add(key);
      s.net.observed.push({ host: h, type, count: int(o.count, 100000) || 1, withBody: int(o.withBody, 100000) });
    }
    const seenD = new Set();
    for (const o of arr(raw.net.declared, 150)) {
      const h = isObj(o) ? host(o.host) : null; if (!h) continue;
      const kind = pick(o.kind, DECL_KINDS, 'link'); const key = h + '|' + kind; if (seenD.has(key)) continue; seenD.add(key);
      s.net.declared.push({ host: h, kind });
    }
  }
  if (isObj(raw.forms)) {
    const f = raw.forms;
    s.forms.passwordFields = int(f.passwordFields, 500); s.forms.cardFields = int(f.cardFields, 500); s.forms.hiddenFrames = int(f.hiddenFrames, 500);
    s.forms.crossSiteActions = arr(f.crossSiteActions, 10).map((a) => (isObj(a) && host(a.host) ? { host: host(a.host), hasPassword: a.hasPassword === true } : null)).filter(Boolean);
    s.forms.submits = arr(f.submits, 10).map((a) => (isObj(a) && host(a.host) ? { host: host(a.host), hasPassword: a.hasPassword === true, hasCard: a.hasCard === true, crossSite: a.crossSite === true } : null)).filter(Boolean);
  }
  s.text = [...new Set(arr(raw.text, 10).filter((t) => TEXT_CODES.includes(t)))];
  if (isObj(raw.hints)) s.hints = { hasMap: raw.hints.hasMap === true, hasVideo: raw.hints.hasVideo === true, title: typeof raw.hints.title === 'string' ? raw.hints.title.replace(/[\u0000-\u001f‪-‮]/g, '').slice(0, 120) : '' };
  return { ok: true, snapshot: s };
}

/** Un mesaj de la content script e acceptat doar dacă expeditorul e propriul content script, într-un tab, cu URL web. */
export function validateContentSender(sender, extensionId) {
  if (!sender || sender.id !== extensionId) return { ok: false, error: 'wrong-extension' };
  if (!sender.tab || typeof sender.tab.id !== 'number') return { ok: false, error: 'no-tab' };
  if (typeof sender.url !== 'string' || !/^https?:\/\//i.test(sender.url)) return { ok: false, error: 'non-web-sender' };
  if (typeof sender.frameId !== 'number') return { ok: false, error: 'no-frame' };
  return { ok: true };
}

/** Pagini ale extensiei (popup, avertizare, dashboard): sender.url începe cu originea extensiei și nu are tab web. */
export function isExtensionPageSender(sender, extensionId) {
  if (!sender || sender.id !== extensionId || typeof sender.url !== 'string') return false;
  return sender.url.startsWith(`chrome-extension://${extensionId}/`);
}

const str = (v, max = 200) => (typeof v === 'string' ? v.slice(0, max) : '');
const tabIdOf = (v) => (Number.isInteger(v) && v >= 0 ? v : null);

/** Validatori de payload pentru mesajele de la paginile extensiei. Întorc obiectul curățat sau null. */
export const REQUEST_VALIDATORS = {
  [MSG.GET_TAB_REPORT]: (m) => (tabIdOf(m.tabId) !== null ? { tabId: m.tabId, url: str(m.url, 4096) } : null),
  [MSG.ANALYZE_PAGE]: (m) => (tabIdOf(m.tabId) !== null ? { tabId: m.tabId, url: str(m.url, 4096) } : null),
  [MSG.GET_WARNING]: (m) => (/^[a-f0-9-]{8,64}$/i.test(str(m.id, 64)) ? { id: m.id } : (typeof m.dnrUrl === 'string' && m.dnrUrl.length <= 4096 ? { dnrUrl: m.dnrUrl } : null)),
  [MSG.GRANT_PASS]: (m) => (/^[a-f0-9-]{8,64}$/i.test(str(m.id, 64)) ? { id: m.id, confirmation: str(m.confirmation, 260) } : null),
  [MSG.GO_SAFE]: (m) => (/^[a-f0-9-]{8,64}$/i.test(str(m.id, 64)) ? { id: m.id } : null),
  [MSG.GET_EVENTS]: (m) => ({ levels: arr(m.levels, 5).filter((l) => ['SAFE', 'SUSPICIOUS', 'DANGEROUS', 'UNKNOWN'].includes(l)), type: ['navigation', 'download', 'behavior', 'exception', 'system'].includes(m.eventType) ? m.eventType : null, search: str(m.search, 80), limit: Math.min(500, Math.max(1, Number.isFinite(m.limit) ? Math.floor(m.limit) : 100)) }),
  [MSG.GET_STATS]: () => ({}),
  [MSG.CLEAR_EVENTS]: () => ({}),
  [MSG.EXPORT_EVENTS]: (m) => ({ detail: m.detail === 'full' ? 'full' : 'summary' }),
  [MSG.GET_CONFIG]: () => ({}),
  [MSG.SET_CONFIG]: (m) => (isObj(m.patch) ? { patch: m.patch } : null),
  [MSG.ADD_EXCEPTION]: (m) => (host(str(m.host, 253)) && ['http', 'https'].includes(m.scheme) ? { host: host(m.host), scheme: m.scheme, kind: m.kind === 'confirmed' ? 'confirmed' : 'heuristic', acknowledged: m.acknowledged === true, ttlDays: Number.isFinite(m.ttlDays) ? Math.min(365, Math.max(0, Math.floor(m.ttlDays))) : 30 } : null),
  [MSG.REMOVE_EXCEPTION]: (m) => (host(str(m.host, 253)) && ['http', 'https'].includes(m.scheme) ? { host: host(m.host), scheme: m.scheme } : null),
  [MSG.GET_EXCEPTIONS]: () => ({}),
  [MSG.IMPORT_LIST]: (m) => (typeof m.text === 'string' && m.text.length <= 2 * 1024 * 1024 ? { text: m.text, name: str(m.name, 60) || 'Listă importată' } : null),
  [MSG.CLEAR_USER_LIST]: () => ({}),
  [MSG.SYNC_FEEDS]: () => ({}),
  [MSG.GET_LIST_STATUS]: () => ({}),
  [MSG.TEST_PROVIDER]: (m) => (['urlhaus', 'safebrowsing'].includes(m.id) ? { id: m.id } : null),
  [MSG.DOWNLOAD_DECISION]: (m) => (/^[a-f0-9-]{8,64}$/i.test(str(m.id, 64)) && ['cancel', 'resume'].includes(m.action) ? { id: m.id, action: m.action } : null),
  [MSG.GET_DOWNLOAD_WARNING]: (m) => (/^[a-f0-9-]{8,64}$/i.test(str(m.id, 64)) ? { id: m.id } : null),
  [MSG.GET_PROVIDERS_INFO]: () => ({}),
  [MSG.ENSURE_PERMISSION]: (m) => (['strongBlocking', 'urlhaus', 'safebrowsing', 'feeds'].includes(m.what) ? { what: m.what } : null)
};
