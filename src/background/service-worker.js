// Service worker MV3: leagă evenimentele Chrome la nucleul testabil (core.js). Înregistrarea listenerilor se face
// sincron, la nivel de modul, cum cere MV3 (altfel evenimentele care trezesc worker-ul s-ar pierde).
import { createCore } from './core.js';

const core = createCore({
  chrome,
  loadBundled: async () => {
    try { return await (await fetch(chrome.runtime.getURL('data/blocklist.json'))).json(); } catch { return { entries: [] }; }
  }
});

const guard = (p) => p.catch((e) => console.warn('[Sentinel Shield]', e?.message ?? e));

chrome.webNavigation.onBeforeNavigate.addListener((d) => guard(core.onBeforeNavigate(d)), { url: [{ schemes: ['http', 'https'] }] });
chrome.webNavigation.onCommitted.addListener((d) => guard(core.onCommitted(d)), { url: [{ schemes: ['http', 'https'] }] });
chrome.tabs.onRemoved.addListener((tabId) => guard(core.onTabRemoved(tabId)));

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  core.handleMessage(msg, sender).then(sendResponse);
  return true; // răspuns asincron
});

chrome.downloads.onCreated.addListener((item) => guard(core.onDownloadCreated(item)));
chrome.downloads.onChanged.addListener((delta) => {
  if (!delta.filename?.current) return; // numele final devine cunoscut abia după „created"
  guard(chrome.downloads.search({ id: delta.id }).then(([item]) => item && core.onDownloadCreated(item)));
});

// Actualizarea periodică a feed-urilor (doar dacă utilizatorul le-a activat).
async function ensureAlarm() {
  const cfg = await core.getConfig();
  const existing = await chrome.alarms.get('ss-feeds');
  if (cfg.feeds.enabled) {
    const period = cfg.feeds.intervalHours * 60;
    if (!existing || existing.periodInMinutes !== period) await chrome.alarms.create('ss-feeds', { delayInMinutes: 1, periodInMinutes: period });
  } else if (existing) await chrome.alarms.clear('ss-feeds');
}
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'ss-feeds') guard(core.syncFeeds()); });
chrome.runtime.onInstalled.addListener(() => guard(core.init().then(ensureAlarm).then(() => core.syncDnr())));
chrome.runtime.onStartup.addListener(() => guard(core.init().then(ensureAlarm).then(() => core.syncDnr())));
chrome.storage.onChanged.addListener((changes, area) => { if (area === 'local' && changes.config) guard(ensureAlarm()); });
