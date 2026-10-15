// Mediu Chrome simulat pentru testele de integrare ale nucleului (fără browser real).
import { readFileSync } from 'node:fs';
import { createMemoryArea } from '../src/lib/storage.js';
import { createCore } from '../src/background/core.js';

export const EXT_ID = 'abcdefghijklmnopabcdefghijklmnop';
export const bundled = JSON.parse(readFileSync(new URL('../data/blocklist.json', import.meta.url), 'utf8'));

export function createFakeChrome() {
  const calls = { tabsUpdate: [], tabsCreate: [], badge: [], pause: [], cancel: [], resume: [], dnr: [] };
  const granted = new Set();
  return {
    calls, grant: (o) => granted.add(o),
    runtime: { id: EXT_ID, getURL: (p) => `chrome-extension://${EXT_ID}/${p}` },
    storage: { local: createMemoryArea(), session: createMemoryArea() },
    tabs: { update: async (id, p) => { calls.tabsUpdate.push({ id, ...p }); }, create: async (p) => { calls.tabsCreate.push(p); }, sendMessage: async () => {} },
    action: { setBadgeText: async (b) => { calls.badge.push(b); }, setBadgeBackgroundColor: async () => {} },
    permissions: { contains: async ({ origins = [] }) => origins.every((o) => granted.has(o)), request: async () => true },
    downloads: { pause: async (id) => { calls.pause.push(id); }, cancel: async (id) => { calls.cancel.push(id); }, resume: async (id) => { calls.resume.push(id); } },
    declarativeNetRequest: { getDynamicRules: async () => [], updateDynamicRules: async (x) => { calls.dnr.push(x); }, updateSessionRules: async () => {} }
  };
}

let t = 1_700_000_000_000;
export function createHarness({ fetchImpl, loadBundled = async () => bundled } = {}) {
  const chrome = createFakeChrome();
  let n = 0;
  const clock = { now: () => t, advance: (ms) => { t += ms; } };
  const core = createCore({ chrome, fetchImpl: fetchImpl ?? (async () => { throw new TypeError('Failed to fetch'); }), now: clock.now, uuid: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`, loadBundled });
  const extSender = (tabId = 1, frameId = 0) => ({ id: EXT_ID, url: `chrome-extension://${EXT_ID}/src/pages/warning/warning.html?id=x`, tab: { id: tabId }, frameId });
  const popupSender = () => ({ id: EXT_ID, url: `chrome-extension://${EXT_ID}/src/pages/popup/popup.html`, frameId: 0 });
  const contentSender = (tabId = 1, url = 'https://example-shop.ro/', frameId = 0) => ({ id: EXT_ID, url, tab: { id: tabId }, frameId });
  const webSender = (tabId = 1) => ({ url: 'https://evil.example.com/', tab: { id: tabId }, frameId: 0 }); // fără id de extensie
  return { chrome, core, clock, extSender, popupSender, contentSender, webSender, warnUrl: () => chrome.calls.tabsUpdate.map((u) => u.url).filter((u) => u?.includes('warning.html')).at(-1) };
}
export const warnId = (url) => new URL(url).searchParams.get('id');
