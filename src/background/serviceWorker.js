/**
 * SentinelShield2 - service worker (Manifest V3).
 *
 * Responsabilități:
 * - analiza locală a linkurilor și a tab-ului activ, la cererea utilizatorului;
 * - meniuri contextuale;
 * - monitorizarea navigării (DOAR dacă utilizatorul a activat-o și a acordat
 *   permisiunile opționale) și afișarea paginii de avertizare;
 * - excepții temporare explicite, pe host, pentru "Continuă oricum";
 * - badge cu nivelul de risc.
 *
 * LIMITE TEHNICE (documentate și în README/SECURITY):
 * - `chrome.webNavigation.onBeforeNavigate` NU poate anula o navigare. Pentru
 *   cererile HTTP(S) deja pornite, intervenția noastră este o redirecționare
 *   către pagina de avertizare, deci o mică parte din pagină se poate încărca
 *   înainte. Nu toate tipurile de navigare pot fi interceptate.
 * - Verificarea navigării cere permisiuni opționale suplimentare
 *   (`webNavigation` + acces la site-uri), acordate explicit de utilizator.
 * - Fără aceste permisiuni, extensia funcționează complet pentru analiza
 *   inițiată manual (popup, meniu contextual, verificare de link).
 */

import { analyzeTarget } from '../analyzer/index.js';
import { RULES } from '../analyzer/phishingRules.js';
import { shouldWarn } from '../analyzer/riskScorer.js';
import { permissionProbe, summarizePermissionReport } from '../content/permissionMonitor.js';
import { MSG, SESSION_KEYS, TEMP_EXCEPTION_MINUTES } from '../shared/messages.js';
import { DEFAULT_SETTINGS, RISK_LEVELS } from '../shared/constants.js';
import { ChromeStorageBackend, StorageManager } from '../storage/storageManager.js';

const storage = new StorageManager({ backend: new ChromeStorageBackend() });

const WARNING_PAGE = 'src/warning/warning.html';
const DETAILS_PAGE = 'src/details/details.html';
const OPTIONS_PAGE = 'src/options/options.html';

/** Culorile badge-ului pentru fiecare nivel de risc. */
const BADGE = {
  [RISK_LEVELS.NONE]: { text: '', color: '#4ec98a' },
  [RISK_LEVELS.LOW]: { text: 'i', color: '#6fb3f0' },
  [RISK_LEVELS.MODERATE]: { text: '!', color: '#ffb020' },
  [RISK_LEVELS.HIGH]: { text: '!!', color: '#ff5c5c' },
  [RISK_LEVELS.CONFIRMED_DANGEROUS]: { text: 'X', color: '#d21f1f' },
};

/** Adresa paginilor interne ale extensiei. */
const EXTENSION_ROOT = chrome.runtime.getURL('');

/**
 * @param {string} value
 * @returns {boolean} true dacă adresa aparține extensiei
 */
function isOwnPage(value) {
  return typeof value === 'string' && value.startsWith(EXTENSION_ROOT);
}

/**
 * @param {string} value
 * @returns {boolean} true pentru navigări web normale
 */
function isWebUrl(value) {
  return typeof value === 'string' && /^https?:\/\//i.test(value);
}

/* ------------------------------------------------------------------ sesiune */

/**
 * Citește o valoare din chrome.storage.session.
 * @param {string} key
 * @param {unknown} fallback
 * @returns {Promise<unknown>}
 */
async function sessionGet(key, fallback = null) {
  try {
    const result = await chrome.storage.session.get(key);
    return result?.[key] ?? fallback;
  } catch {
    return fallback;
  }
}

/**
 * Scrie o valoare în chrome.storage.session.
 * @param {string} key
 * @param {unknown} value
 * @returns {Promise<void>}
 */
async function sessionSet(key, value) {
  try {
    await chrome.storage.session.set({ [key]: value });
  } catch (error) {
    console.warn('[SentinelShield2] nu am putut scrie în storage.session:', error?.message ?? error);
  }
}

/* -------------------------------------------------------------------- badge */

/**
 * Actualizează badge-ul pentru un tab.
 * @param {number|undefined} tabId
 * @param {string} level
 * @returns {Promise<void>}
 */
async function setBadge(tabId, level) {
  const config = BADGE[level] ?? BADGE[RISK_LEVELS.NONE];
  try {
    const target = typeof tabId === 'number' ? { tabId } : {};
    await chrome.action.setBadgeText({ ...target, text: config.text });
    await chrome.action.setBadgeBackgroundColor({ ...target, color: config.color });
  } catch {
    // Tab-ul poate să fi fost închis; nu este o eroare de raportat.
  }
}

/* -------------------------------------------- excepții temporare (pe host) */

/**
 * Verifică dacă există o excepție temporară activă pentru un host.
 * @param {string} host
 * @returns {Promise<boolean>}
 */
async function hasTempException(host) {
  if (!host) return false;
  const map = (await sessionGet(SESSION_KEYS.TEMP_ALLOW, {})) ?? {};
  const expiry = map[host];
  if (typeof expiry !== 'number') return false;
  if (expiry <= Date.now()) {
    delete map[host];
    await sessionSet(SESSION_KEYS.TEMP_ALLOW, map);
    return false;
  }
  return true;
}

/**
 * Acordă o excepție temporară pentru un host.
 * @param {string} host
 * @returns {Promise<{ host: string, expiresAt: number, minutes: number }>}
 */
async function grantTempException(host) {
  const map = (await sessionGet(SESSION_KEYS.TEMP_ALLOW, {})) ?? {};
  const expiresAt = Date.now() + TEMP_EXCEPTION_MINUTES * 60 * 1000;
  map[host] = expiresAt;
  await sessionSet(SESSION_KEYS.TEMP_ALLOW, map);
  return { host, expiresAt, minutes: TEMP_EXCEPTION_MINUTES };
}

/* ------------------------------------------------------------------ analiză */

/**
 * Analizează o adresă folosind setările și listele curente.
 * @param {string} url
 * @param {{ withReputation?: boolean }} [options]
 * @returns {Promise<{ ok: boolean, verdict?: object, error?: string }>}
 */
async function analyze(url, options = {}) {
  const [settings, lists] = await Promise.all([storage.getSettings(), storage.getLists()]);
  return analyzeTarget(url, {
    settings,
    lists,
    useReputation: options.withReputation === true,
  });
}

/**
 * Analizează tab-ul activ și actualizează badge-ul.
 * @param {number} tabId
 * @param {string} url
 * @param {{ withReputation?: boolean }} [options]
 * @returns {Promise<object>}
 */
async function analyzeAndRemember(tabId, url, options = {}) {
  const result = await analyze(url, options);
  if (result.ok) {
    await sessionSet(`${SESSION_KEYS.LAST_ANALYSIS}.${tabId}`, result.verdict);
    await setBadge(tabId, result.verdict.riskLevel);
  }
  return result;
}

/**
 * Citește ultima analiză pentru un tab.
 * @param {number} tabId
 * @returns {Promise<object|null>}
 */
async function getLastAnalysis(tabId) {
  return sessionGet(`${SESSION_KEYS.LAST_ANALYSIS}.${tabId}`, null);
}

/* --------------------------------------------------- permisiuni ale paginii */

/**
 * Injectează sonda de permisiuni în tab-ul activ și întoarce un rezumat.
 * Necesită `activeTab` (acordat la interacțiunea utilizatorului) și `scripting`.
 * @param {number} tabId
 * @returns {Promise<object>}
 */
async function readPagePermissions(tabId) {
  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId },
      func: permissionProbe,
    });
    const summary = summarizePermissionReport(injection?.result);
    if (!summary.available) {
      return {
        ...summary,
        notes: [
          'Pagina nu a returnat informații despre permisiuni.',
          'Pagini precum chrome:// sau Chrome Web Store nu permit injectarea de scripturi.',
        ],
      };
    }
    return summary;
  } catch (error) {
    return {
      ...summarizePermissionReport(null),
      notes: [
        `Permisiunile paginii nu au putut fi citite (${String(error?.message ?? error)}).`,
        'Pagini interne Chrome (chrome://, Chrome Web Store) nu permit injectarea de scripturi.',
      ],
    };
  }
}

/* -------------------------------------------------------- meniuri contextuale */

/** Creează meniurile contextuale (idempotent). */
async function ensureContextMenus() {
  try {
    await chrome.contextMenus.removeAll();
    chrome.contextMenus.create({
      id: 'sentinel-check-link',
      title: 'Verifică linkul cu SentinelShield2',
      contexts: ['link'],
    });
    chrome.contextMenus.create({
      id: 'sentinel-check-page',
      title: 'Analizează această pagină cu SentinelShield2',
      contexts: ['page'],
    });
    chrome.contextMenus.create({
      id: 'sentinel-allow-host',
      title: 'Adaugă domeniul în lista de încredere',
      contexts: ['page'],
    });
    chrome.contextMenus.create({
      id: 'sentinel-block-host',
      title: 'Blochează acest domeniu',
      contexts: ['page'],
    });
  } catch (error) {
    console.warn('[SentinelShield2] meniuri contextuale:', error?.message ?? error);
  }
}

/**
 * Deschide pagina de detalii pentru un verdict.
 * @param {object} verdict
 * @param {string} source
 * @param {number|null} [tabId] tab-ul analizat (pentru inspecția permisiunilor)
 * @returns {Promise<void>}
 */
async function openDetails(verdict, source = 'popup', tabId = null) {
  await sessionSet(SESSION_KEYS.PENDING_DETAILS, {
    verdict,
    source,
    tabId: typeof tabId === 'number' ? tabId : null,
    createdAt: Date.now(),
  });
  await chrome.tabs.create({ url: chrome.runtime.getURL(DETAILS_PAGE) });
}

/**
 * Determină host-ul unui tab (poate lipsi fără permisiuni pe site).
 * @param {number} tabId
 * @returns {Promise<{ host: string, url: string, error: string }>}
 */
async function getTabHost(tabId) {
  if (typeof tabId !== 'number') return { host: '', url: '', error: 'Nu am identificat tab-ul.' };
  try {
    const tab = await chrome.tabs.get(tabId);
    if (isOwnPage(tab.url)) return { host: '', url: tab.url ?? '', error: 'Acesta este un tab al extensiei.' };
    if (!isWebUrl(tab.url)) {
      return { host: '', url: tab.url ?? '', error: 'Pagina nu este un site web obișnuit, deci nu are un domeniu de listat.' };
    }
    return { host: new URL(tab.url).hostname.toLowerCase(), url: tab.url, error: '' };
  } catch (error) {
    return { host: '', url: '', error: `Nu am putut citi adresa tab-ului: ${String(error?.message ?? error)}` };
  }
}

/**
 * Tratează click-ul pe un meniu contextual.
 * @param {chrome.contextMenus.OnClickData} info
 * @param {chrome.tabs.Tab|undefined} tab
 * @returns {Promise<void>}
 */
async function handleContextMenu(info, tab) {
  const tabId = tab?.id;

  if (info.menuItemId === 'sentinel-check-link' && typeof info.linkUrl === 'string') {
    const result = await analyze(info.linkUrl, { withReputation: true });
    if (!result.ok) {
      await sessionSet(SESSION_KEYS.LAST_ERROR, result.error);
      return;
    }
    await openDetails(result.verdict, 'context-menu-link');
    return;
  }
  if (info.menuItemId === 'sentinel-check-page') {
    const host = await getTabHost(tabId);
    if (host.error) {
      await sessionSet(SESSION_KEYS.LAST_ERROR, host.error);
      return;
    }
    const result = await analyzeAndRemember(tabId, host.url, { withReputation: true });
    if (result.ok) await openDetails(result.verdict, 'context-menu-page', tabId);
    return;
  }

  if (info.menuItemId === 'sentinel-allow-host' || info.menuItemId === 'sentinel-block-host') {
    const host = await getTabHost(tabId);
    if (host.error) {
      await sessionSet(SESSION_KEYS.LAST_ERROR, host.error);
      return;
    }
    const listType = info.menuItemId === 'sentinel-allow-host' ? 'allowlist' : 'blocklist';
    const added = await storage.addEntry(listType, host.host, { note: 'Adăugat din meniul contextual' });
    if (!added.ok && !added.duplicate) {
      await sessionSet(SESSION_KEYS.LAST_ERROR, added.error);
      return;
    }
    if (tabId !== undefined) await analyzeAndRemember(tabId, host.url, { withReputation: false });
  }
}

/* ----------------------------------------------------- monitorizarea navigării */

/** Indică dacă ascultătorul de navigare a fost deja înregistrat. */
let navigationListenerRegistered = false;

/**
 * Înregistrează ascultătorul de navigare, dacă permisiunea opțională există.
 * Este idempotent și poate fi apelat la pornire sau la cerere (după ce
 * utilizatorul acordă permisiunile din pagina de setări).
 * @returns {Promise<boolean>} true dacă ascultătorul este activ
 */
async function registerNavigationListener() {
  if (navigationListenerRegistered) return true;
  let granted = false;
  try {
    granted = await chrome.permissions.contains({ permissions: ['webNavigation'] });
  } catch {
    granted = false;
  }
  if (!granted) return false;
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    handleBeforeNavigate(details).catch((error) => {
      console.warn('[SentinelShield2] monitorizare navigare:', error?.message ?? error);
    });
  });
  navigationListenerRegistered = true;
  return true;
}

/**
 * Reacționează la începutul unei navigări (doar dacă este activată de utilizator).
 * @param {chrome.webNavigation.WebNavigationParentedCallbackDetails} details
 * @returns {Promise<void>}
 */
async function handleBeforeNavigate(details) {
  if (details.frameId !== 0) return;
  if (!isWebUrl(details.url) || isOwnPage(details.url)) return;

  const settings = await storage.getSettings();
  if (!settings.navigationCheckEnabled) return;

  let host = '';
  try {
    host = new URL(details.url).hostname.toLowerCase();
  } catch {
    return;
  }
  if (await hasTempException(host)) return;

  const result = await analyze(details.url, { withReputation: false });
  if (!result.ok) return;
  const { verdict } = result;
  await sessionSet(`${SESSION_KEYS.LAST_ANALYSIS}.${details.tabId}`, verdict);
  await setBadge(details.tabId, verdict.riskLevel);

  if (!shouldWarn(verdict.riskLevel, settings.warningLevel)) return;

  // Anti-buclă: nu redirecționăm de două ori pentru aceeași adresă.
  const pending = await sessionGet(`${SESSION_KEYS.PENDING_WARNING}.${details.tabId}`, null);
  if (pending && pending.url === details.url && Date.now() - pending.createdAt < 10000) return;

  await sessionSet(`${SESSION_KEYS.PENDING_WARNING}.${details.tabId}`, {
    url: details.url,
    verdict,
    createdAt: Date.now(),
  });

  try {
    await chrome.tabs.update(details.tabId, {
      url: `${chrome.runtime.getURL(WARNING_PAGE)}?tabId=${details.tabId}`,
    });
  } catch (error) {
    // Redirecționarea poate eșua (tab închis, restricții). Analiza rămâne
    // disponibilă în popup; nu pretindem că am blocat navigarea.
    console.warn('[SentinelShield2] nu am putut afișa pagina de avertizare:', error?.message ?? error);
    await sessionSet(SESSION_KEYS.LAST_ERROR, 'Nu am putut afișa pagina de avertizare pentru această navigare.');
  }
}

/* ------------------------------------------------------------ rutare mesaje */

/**
 * Tratează un mesaj venit din paginile extensiei.
 * @param {object} message
 * @param {chrome.runtime.MessageSender} sender
 * @returns {Promise<object>}
 */
async function handleMessage(message, sender) {
  const tabIdFromSender = sender?.tab?.id;

  switch (message?.type) {
    case MSG.ANALYZE_URL: {
      const result = await analyze(String(message.url ?? ''), {
        withReputation: message.withReputation === true,
      });
      if (!result.ok) return { ok: false, error: result.error };
      return { ok: true, verdict: result.verdict };
    }

    case MSG.ANALYZE_ACTIVE_TAB: {
      const host = await getTabHost(message.tabId ?? tabIdFromSender);
      if (host.error) return { ok: false, error: host.error };
      const result = await analyzeAndRemember(message.tabId ?? tabIdFromSender, host.url, {
        withReputation: message.withReputation === true,
      });
      if (!result.ok) return { ok: false, error: result.error };
      const permissions = message.includePermissions === true
        ? await readPagePermissions(message.tabId ?? tabIdFromSender)
        : null;
      return { ok: true, verdict: result.verdict, permissions };
    }

    case MSG.GET_CONTEXT: {
      const tabId = message.tabId ?? tabIdFromSender;
      const host = await getTabHost(tabId);
      const [settings, lists, lastAnalysis] = await Promise.all([
        storage.getSettings(),
        storage.getLists(),
        typeof tabId === 'number' ? getLastAnalysis(tabId) : Promise.resolve(null),
      ]);
      const hostStatus = host.host ? await storage.matchHost(host.host) : null;
      const lastError = await sessionGet(SESSION_KEYS.LAST_ERROR, '');
      if (lastError) await sessionSet(SESSION_KEYS.LAST_ERROR, '');
      return {
        ok: true,
        tabId: typeof tabId === 'number' ? tabId : null,
        url: host.url,
        host: host.host,
        hostError: host.error,
        settings,
        lists,
        listStatus: hostStatus,
        lastAnalysis,
        lastError: typeof lastError === 'string' ? lastError : '',
      };
    }

    case MSG.GET_LAST_ANALYSIS: {
      const tabId = message.tabId ?? tabIdFromSender;
      return { ok: true, verdict: await getLastAnalysis(tabId) };
    }

    case MSG.OPEN_DETAILS: {
      if (!message.verdict) return { ok: false, error: 'Nu există un rezultat de afișat.' };
      await openDetails(message.verdict, message.source ?? 'popup', message.tabId ?? null);
      return { ok: true };
    }

    case MSG.OPEN_OPTIONS: {
      const url = chrome.runtime.getURL(message.anchor ? `${OPTIONS_PAGE}#${message.anchor}` : OPTIONS_PAGE);
      try {
        const existing = await chrome.tabs.query({ url: chrome.runtime.getURL(OPTIONS_PAGE) });
        const reusable = existing.find((tab) => typeof tab.id === 'number');
        if (reusable) {
          await chrome.tabs.update(reusable.id, { active: true, url });
          if (typeof reusable.windowId === 'number') {
            await chrome.windows.update(reusable.windowId, { focused: true });
          }
          return { ok: true };
        }
      } catch {
        // Dacă tab-ul existent nu poate fi reutilizat, deschidem unul nou.
      }
      await chrome.tabs.create({ url });
      return { ok: true };
    }

    case MSG.GET_RULES: {
      return {
        ok: true,
        rules: RULES.map((rule) => ({
          id: rule.id,
          family: rule.family,
          category: rule.category,
          title: rule.title,
          severity: rule.severity,
          weight: rule.weight,
          why: rule.why,
          limits: rule.limits,
          suppressedBy: rule.suppressedBy ?? [],
        })),
      };
    }

    case MSG.GET_SETTINGS:
      return { ok: true, settings: await storage.getSettings() };

    case MSG.SAVE_SETTINGS: {
      const settings = await storage.saveSettings(message.settings ?? {});
      return { ok: true, settings };
    }

    case MSG.GET_LISTS:
      return { ok: true, lists: await storage.getLists() };

    case MSG.LIST_ADD: {
      const result = await storage.addEntry(message.listType, message.value, {
        note: typeof message.note === 'string' ? message.note : '',
      });
      return result.ok
        ? { ok: true, entry: result.entry, lists: await storage.getLists() }
        : { ok: false, error: result.error, duplicate: result.duplicate === true };
    }

    case MSG.LIST_REMOVE: {
      const result = await storage.removeEntry(message.listType, message.host, {
        includeSubdomains: message.includeSubdomains === true,
      });
      return result.ok
        ? { ok: true, lists: await storage.getLists() }
        : { ok: false, error: result.error };
    }

    case MSG.EXPORT_CONFIG:
      return { ok: true, config: await storage.exportConfig() };

    case MSG.IMPORT_CONFIG:
      return { ok: true, report: await storage.importConfig(message.config, { mode: message.mode }) };

    case MSG.RESET_ALL:
      await storage.resetAll();
      return { ok: true };

    case MSG.GET_PENDING_WARNING: {
      const tabId = message.tabId;
      const pending = await sessionGet(`${SESSION_KEYS.PENDING_WARNING}.${tabId}`, null);
      return { ok: true, pending };
    }

    case MSG.CONTINUE_ANYWAY: {
      const pending = await sessionGet(`${SESSION_KEYS.PENDING_WARNING}.${message.tabId}`, null);
      if (!pending?.url) return { ok: false, error: 'Avertismentul a expirat. Reia navigarea manual.' };
      let host = '';
      try {
        host = new URL(pending.url).hostname.toLowerCase();
      } catch {
        host = '';
      }
      const exception = host ? await grantTempException(host) : null;
      await sessionSet(`${SESSION_KEYS.PENDING_WARNING}.${message.tabId}`, null);
      try {
        await chrome.tabs.update(message.tabId, { url: pending.url });
      } catch (error) {
        return { ok: false, error: `Nu am putut relua navigarea: ${String(error?.message ?? error)}` };
      }
      return { ok: true, exception };
    }

    case MSG.GO_BACK_SAFELY: {
      const tabId = message.tabId;
      await sessionSet(`${SESSION_KEYS.PENDING_WARNING}.${tabId}`, null);
      try {
        await chrome.tabs.goBack(tabId);
        return { ok: true, mode: 'back' };
      } catch {
        try {
          await chrome.tabs.update(tabId, { url: 'about:blank' });
          return { ok: true, mode: 'blank' };
        } catch (error) {
          return { ok: false, error: `Nu am putut reveni: ${String(error?.message ?? error)}` };
        }
      }
    }

    case MSG.GET_PAGE_PERMISSIONS: {
      const tabId = message.tabId ?? tabIdFromSender;
      return { ok: true, permissions: await readPagePermissions(tabId) };
    }

    case MSG.REGISTER_NAVIGATION: {
      const registered = await registerNavigationListener();
      return { ok: true, registered };
    }

    default:
      return { ok: false, error: `Tip de mesaj necunoscut: ${String(message?.type)}` };
  }
}

/* ---------------------------------------------------------------- ascultători */

chrome.runtime.onInstalled.addListener(async () => {
  try {
    const current = await storage.getSettings();
    if (!current) await storage.saveSettings(DEFAULT_SETTINGS);
    else await storage.saveSettings({});
  } catch (error) {
    console.warn('[SentinelShield2] inițializare setări:', error?.message ?? error);
  }
  await ensureContextMenus();
});

chrome.runtime.onStartup.addListener(() => {
  ensureContextMenus().catch(() => {});
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  handleContextMenu(info, tab).catch((error) => {
    console.warn('[SentinelShield2] meniu contextual:', error?.message ?? error);
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((response) => sendResponse(response))
    .catch((error) => {
      console.warn('[SentinelShield2] eroare la tratarea mesajului:', error?.message ?? error);
      sendResponse({ ok: false, error: `Eroare internă: ${String(error?.message ?? error)}` });
    });
  return true; // răspuns asincron
});

chrome.runtime.onConnect.addListener((port) => {
  // Nu folosim porturi persistente: comunicarea este prin mesaje cu răspuns,
  // ca service worker-ul să poată fi oprit de browser când nu este necesar.
  if (port.name === 'sentinelshield-refresh') port.onMessage.addListener(() => {});
});

/**
 * Monitorizarea navigării este înregistrată doar dacă permisiunea opțională
 * există deja (utilizatorul a activat funcția). Altfel, funcția rămâne
 * indisponibilă - acest lucru este raportat explicit în pagina de setări.
 * Dacă permisiunea este acordată ulterior, pagina de setări cere înregistrarea
 * prin mesajul `MSG.REGISTER_NAVIGATION`.
 */
registerNavigationListener().catch(() => {});

// La reîncărcarea extensiei, badge-urile vechi sunt curățate.
chrome.tabs.query({}).then((tabs) => {
  for (const tab of tabs) {
    if (typeof tab.id === 'number') setBadge(tab.id, RISK_LEVELS.NONE);
  }
}).catch(() => {});
