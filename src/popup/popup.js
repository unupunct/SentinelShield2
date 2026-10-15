/**
 * SentinelShield2 - logica ferestrei popup.
 *
 * Popup-ul NU analizează nimic pe cont propriu: trimite mesaje către service
 * worker (`MSG.*`), care deține setările, listele și logica de analiză. Astfel
 * există un singur loc unde se produce un verdict.
 *
 * Reguli de siguranță respectate aici:
 * - textul provenit din adrese/pagini este inserat doar prin `textContent`
 *   (`el`/`showMessage`), niciodată prin `innerHTML`;
 * - erorile sunt afișate explicit, fără a pretinde că analiza a reușit.
 */

import { MSG } from '../shared/messages.js';
import {
  clear,
  el,
  send,
  showMessage,
} from '../shared/ui.js';
import { fillUrlDisplay, renderRiskReasons, renderVerdictHeader } from '../shared/verdictView.js';

/* ------------------------------------------------------------------ helpers */

/** Referințe către elementele din pagină. */
const dom = {
  host: document.getElementById('current-host'),
  hostChips: document.getElementById('host-chips'),
  currentStatus: document.getElementById('current-status'),
  pageVerdict: document.getElementById('page-verdict'),
  linkForm: document.getElementById('link-form'),
  linkInput: document.getElementById('link-input'),
  linkVerdict: document.getElementById('link-verdict'),
  actionsHost: document.getElementById('actions-host'),
  actionsMessage: document.getElementById('actions-message'),
  globalError: document.getElementById('global-error'),
  analyzePage: document.getElementById('analyze-page'),
  analyzePageReputation: document.getElementById('analyze-page-reputation'),
  linkScanReputation: document.getElementById('link-scan-reputation'),
  allowHost: document.getElementById('allow-host'),
  blockHost: document.getElementById('block-host'),
  openOptions: document.getElementById('open-options'),
  openDetailsLink: document.getElementById('open-details-link'),
};

/** Starea din popup, reîmprospătată la fiecare deschidere. */
const state = {
  tabId: null,
  host: '',
  url: '',
  hostError: '',
  lastVerdict: null,
};

/**
 * Citește tab-ul activ din fereastra curentă.
 * @returns {Promise<chrome.tabs.Tab|null>}
 */
async function getActiveTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs?.[0] ?? null;
  } catch {
    return null;
  }
}

/**
 * Afișează o eroare globală în popup.
 * @param {string} text
 */
function showGlobalError(text) {
  if (!text) {
    clear(dom.globalError);
    return;
  }
  showMessage(dom.globalError, text, 'danger');
}

/**
 * Redă un verdict în formă compactă, cu acces la pagina de detalii.
 * @param {object} verdict
 * @param {HTMLElement} container
 * @param {{ source: string }} options
 */
function renderCompactVerdict(verdict, container, options) {
  clear(container);
  const block = el('div', { class: 'stack verdict-compact' }, [renderVerdictHeader(verdict, { urlLimit: 240 })]);
  fillUrlDisplay(block, verdict);
  block.appendChild(el('h3', {}, 'Motive principale'));
  block.appendChild(renderRiskReasons(verdict, 3));
  block.appendChild(el('div', { class: 'row' }, [
    el('button', {
      type: 'button',
      class: 'ghost',
      onclick: () => openDetails(verdict, options?.source ?? 'popup', options?.tabId ?? null),
    }, 'Vezi toate detaliile'),
    el('button', {
      type: 'button',
      class: 'ghost',
      onclick: () => openOptions(''),
    }, 'Setări'),
  ]));
  container.appendChild(block);
}

/**
 * Deschide pagina de detalii pentru un verdict.
 * @param {object} verdict
 * @param {string} source
 * @param {number|null} [tabId]
 */
async function openDetails(verdict, source, tabId = null) {
  const result = await send({ type: MSG.OPEN_DETAILS, verdict, source, tabId });
  if (!result.ok) showGlobalError(result.error ?? 'Nu am putut deschide detaliile.');
}

/**
 * Deschide pagina de setări.
 * @param {string} [anchor]
 */
async function openOptions(anchor = '') {
  const result = await send({ type: MSG.OPEN_OPTIONS, anchor });
  if (!result.ok) showGlobalError(result.error ?? 'Nu am putut deschide setările.');
}

/* --------------------------------------------------------------- context */

/**
 * Reîncarcă contextul tab-ului activ (host, stare liste, ultima analiză).
 */
async function refreshContext() {
  showGlobalError('');
  const result = await send({ type: MSG.GET_CONTEXT, tabId: state.tabId });
  if (!result.ok) {
    showGlobalError(result.error ?? 'Nu am putut citi contextul paginii.');
    return;
  }

  state.host = result.host ?? '';
  state.url = result.url ?? '';
  state.hostError = result.hostError ?? '';

  dom.host.textContent = state.host || 'Domeniu indisponibil pentru acest tab';
  dom.actionsHost.textContent = state.host ? `Domeniu: ${state.host}` : 'Nu există un domeniu de modificat.';

  renderHostChips(result.listStatus);

  const canAct = Boolean(state.host) && !state.hostError;
  dom.allowHost.disabled = !canAct;
  dom.blockHost.disabled = !canAct;
  dom.analyzePage.disabled = !state.url;

  clear(dom.currentStatus);
  if (state.hostError) {
    showMessage(dom.currentStatus, state.hostError, 'info');
  }
  if (result.lastError) {
    showMessage(dom.currentStatus, result.lastError, 'danger');
  }

  if (result.lastAnalysis) {
    renderCompactVerdict(result.lastAnalysis, dom.pageVerdict, { source: 'popup', tabId: state.tabId });
  }
}

/**
 * Afișează etichetele de stare (allowlist/blocklist) pentru host.
 * @param {{ status: string, match: object|null }|null} listStatus
 */
function renderHostChips(listStatus) {
  clear(dom.hostChips);
  if (!state.host) return;
  if (listStatus?.status === 'allowlisted') {
    dom.hostChips.appendChild(el('span', { class: 'chip allow' }, '✓ listă de încredere'));
  } else if (listStatus?.status === 'blocklisted') {
    dom.hostChips.appendChild(el('span', { class: 'chip block' }, '⛔ blocat'));
  } else {
    dom.hostChips.appendChild(el('span', { class: 'chip' }, 'fără listă'));
  }
}

/* --------------------------------------------------------------- analize */

/**
 * Analizează tab-ul activ.
 * @param {boolean} withReputation
 */
async function analyzeActiveTab(withReputation) {
  if (!state.url) {
    showMessage(dom.pageVerdict, 'Tab-ul activ nu are o adresă web de analizat.', 'info');
    return;
  }
  clear(dom.pageVerdict);
  showMessage(dom.pageVerdict, 'Se analizează…', 'info');
  dom.analyzePage.disabled = true;
  const result = await send({
    type: MSG.ANALYZE_ACTIVE_TAB,
    tabId: state.tabId,
    withReputation,
  });
  dom.analyzePage.disabled = false;
  if (!result.ok) {
    showMessage(dom.pageVerdict, result.error ?? 'Analiza a eșuat.', 'danger');
    return;
  }
  state.lastVerdict = result.verdict;
  renderCompactVerdict(result.verdict, dom.pageVerdict, { source: 'popup-page', tabId: state.tabId });
}

/**
 * Analizează un link introdus manual.
 * @param {boolean} withReputation
 */
async function analyzeLink(withReputation) {
  const value = dom.linkInput.value.trim();
  if (value === '') {
    showMessage(dom.linkVerdict, 'Introdu o adresă de verificat.', 'info');
    return;
  }
  clear(dom.linkVerdict);
  showMessage(dom.linkVerdict, 'Se verifică…', 'info');
  const result = await send({ type: MSG.ANALYZE_URL, url: value, withReputation });
  if (!result.ok) {
    showMessage(dom.linkVerdict, result.error ?? 'Analiza a eșuat.', 'danger');
    return;
  }
  renderCompactVerdict(result.verdict, dom.linkVerdict, { source: 'popup-link' });
}

/* ----------------------------------------------------------------- liste */

/**
 * Adaugă host-ul curent într-o listă.
 * @param {'allowlist'|'blocklist'} listType
 */
async function addCurrentHost(listType) {
  if (!state.host) return;
  clear(dom.actionsMessage);
  const result = await send({ type: MSG.LIST_ADD, listType, value: state.host });
  if (!result.ok) {
    showMessage(dom.actionsMessage, result.error ?? 'Operațiunea a eșuat.', result.duplicate ? 'info' : 'danger');
    return;
  }
  const label = listType === 'blocklist' ? 'lista de blocare' : 'lista de încredere';
  showMessage(dom.actionsMessage, `${state.host} a fost adăugat în ${label}.`, 'ok');
  await refreshContext();
}

/* ------------------------------------------------------------------ init */

/** Leagă evenimentele și încarcă starea inițială. */
async function init() {
  dom.openOptions.addEventListener('click', () => openOptions());
  dom.openDetailsLink.addEventListener('click', (event) => {
    event.preventDefault();
    if (state.lastVerdict) openDetails(state.lastVerdict, 'popup-link-footer');
    else openOptions('despre');
  });
  dom.analyzePage.addEventListener('click', () => analyzeActiveTab(false));
  dom.analyzePageReputation.addEventListener('click', () => analyzeActiveTab(true));
  dom.linkScanReputation.addEventListener('click', () => analyzeLink(true));
  dom.linkForm.addEventListener('submit', (event) => {
    event.preventDefault();
    analyzeLink(false);
  });
  dom.allowHost.addEventListener('click', () => addCurrentHost('allowlist'));
  dom.blockHost.addEventListener('click', () => addCurrentHost('blocklist'));

  const tab = await getActiveTab();
  if (!tab || typeof tab.id !== 'number') {
    dom.host.textContent = 'Nu am identificat un tab activ.';
    dom.analyzePage.disabled = true;
    dom.analyzePageReputation.disabled = true;
    return;
  }
  state.tabId = tab.id;
  await refreshContext();
}

init().catch((error) => {
  showGlobalError(`Eroare la inițializarea popup-ului: ${String(error?.message ?? error)}`);
});
