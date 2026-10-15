/**
 * SentinelShield2 - logica paginii de setări.
 *
 * Toate operațiunile trec prin service worker (`MSG.*`), care este singurul care
 * atinge stocarea. Pagina doar citește/scrie valori validate și afișează
 * rezultatul. Textele externe (domenii, note) sunt inserate prin noduri de
 * text, niciodată prin `innerHTML`.
 *
 * Permisiunile opționale (`webNavigation` + acces la site-uri) sunt cerute
 * explicit din această pagină, în urma unei acțiuni a utilizatorului.
 */

import { MSG } from '../shared/messages.js';
import { DETECTION_LIMITS, RISK_LABELS } from '../shared/constants.js';
import { clear, el, severityChip, send, showMessage } from '../shared/ui.js';

const dom = {
  globalMessage: document.getElementById('global-message'),
  versionChip: document.getElementById('version-chip'),
  navigationEnabled: document.getElementById('navigation-enabled'),
  navigationState: document.getElementById('navigation-state'),
  warningLevel: document.getElementById('warning-level'),
  reputationEnabled: document.getElementById('reputation-enabled'),
  reputationProvider: document.getElementById('reputation-provider'),
  reputationEndpoint: document.getElementById('reputation-endpoint'),
  reputationTimeout: document.getElementById('reputation-timeout'),
  reputationApiKey: document.getElementById('reputation-apikey'),
  reputationHostnameOnly: document.getElementById('reputation-hostname-only'),
  reputationConfirm: document.getElementById('reputation-confirm'),
  reputationDataSent: document.getElementById('reputation-data-sent'),
  privacyStore: document.getElementById('privacy-store'),
  privacyRedact: document.getElementById('privacy-redact'),
  exportConfig: document.getElementById('export-config'),
  importFile: document.getElementById('import-file'),
  importConfig: document.getElementById('import-config'),
  importReport: document.getElementById('import-report'),
  resetAll: document.getElementById('reset-all'),
  rulesTable: document.getElementById('rules-table'),
  limitsList: document.getElementById('limits-list'),
};

/** Starea paginii. */
const state = {
  settings: null,
  lists: { allowlist: [], blocklist: [] },
  filters: { allowlist: '', blocklist: '' },
  resetArmed: false,
};

/* ------------------------------------------------------------------ mesaje */

/**
 * Afișează un mesaj global (succes/eroare).
 * @param {string} text
 * @param {'info'|'ok'|'danger'} tone
 */
function flash(text, tone = 'ok') {
  showMessage(dom.globalMessage, text, tone);
  window.clearTimeout(flash._timer);
  flash._timer = window.setTimeout(() => clear(dom.globalMessage), 4000);
}

/* ---------------------------------------------------------------- setări */

/** Completează câmpurile din setări. */
function applySettings(settings) {
  state.settings = settings;
  dom.warningLevel.value = settings.warningLevel;
  dom.reputationEnabled.checked = settings.reputation.enabled === true;
  dom.reputationProvider.value = settings.reputation.provider ?? 'none';
  dom.reputationEndpoint.value = settings.reputation.endpoint ?? '';
  dom.reputationTimeout.value = String(settings.reputation.timeoutMs ?? 4000);
  dom.reputationHostnameOnly.checked = settings.reputation.hostnameOnly !== false;
  dom.reputationConfirm.checked = settings.reputation.confirmMalicious === true;
  dom.reputationApiKey.value = settings.reputation.apiKey ?? '';
  dom.privacyStore.checked = settings.privacy.storeLastAnalysis !== false;
  dom.privacyRedact.checked = settings.privacy.redactQueryInEvidence !== false;
  updateDataSentText();
}

/**
 * Construiește obiectul de setări din câmpuri (fără `navigationCheckEnabled`,
 * care se tratează separat).
 * @returns {object}
 */
function collectSettings() {
  return {
    warningLevel: dom.warningLevel.value,
    reputation: {
      enabled: dom.reputationEnabled.checked,
      provider: dom.reputationProvider.value,
      endpoint: dom.reputationEndpoint.value.trim(),
      timeoutMs: Number(dom.reputationTimeout.value) || 4000,
      hostnameOnly: dom.reputationHostnameOnly.checked,
      confirmMalicious: dom.reputationConfirm.checked,
      apiKey: dom.reputationApiKey.value,
    },
    privacy: {
      storeLastAnalysis: dom.privacyStore.checked,
      redactQueryInEvidence: dom.privacyRedact.checked,
    },
  };
}

/** Salvează setările curente. */
async function saveSettings() {
  const result = await send({ type: MSG.SAVE_SETTINGS, settings: collectSettings() });
  if (!result.ok) {
    flash(result.error ?? 'Salvarea setărilor a eșuat.', 'danger');
    return;
  }
  applySettings(result.settings);
  flash('Setările au fost salvate.');
}

/** Actualizează textul despre datele trimise către sursa de reputație. */
function updateDataSentText() {
  const hostnameOnly = dom.reputationHostnameOnly.checked;
  const scope = hostnameOnly
    ? 'doar numele de domeniu (fără cale, parametri sau fragment)'
    : 'numele de domeniu și calea (fără parametri și fără fragment)';
  dom.reputationDataSent.textContent = `Dacă este activată, se trimite: ${scope}.`;
}

/* -------------------------------------------------------------- navigare */

/** Actualizează starea permisiunilor opționale și bifa. */
async function refreshPermissionState() {
  let granted = false;
  try {
    granted = await chrome.permissions.contains({ permissions: ['webNavigation'], origins: ['*://*/*'] });
  } catch {
    granted = false;
  }
  const enabled = state.settings?.navigationCheckEnabled === true;
  dom.navigationEnabled.checked = enabled;
  if (enabled && granted) {
    dom.navigationState.textContent = 'Permisiuni acordate; verificarea înainte de navigare este activă.';
  } else if (enabled && !granted) {
    dom.navigationState.textContent = 'Setarea este activă, dar permisiunile lipsesc (au fost revocate). Re-activează pentru a le re-solicita.';
  } else if (granted) {
    dom.navigationState.textContent = 'Permisiuni acordate, dar funcția este dezactivată.';
  } else {
    dom.navigationState.textContent = 'Permisiunile opționale nu sunt acordate; funcția este dezactivată.';
  }
}

/** Activează/dezactivează monitorizarea navigării. */
async function toggleNavigation() {
  const wantEnabled = dom.navigationEnabled.checked;
  if (wantEnabled) {
    let granted = false;
    try {
      granted = await chrome.permissions.request({ permissions: ['webNavigation'], origins: ['*://*/*'] });
    } catch (error) {
      showMessage(dom.navigationState, `Cererea de permisiuni a eșuat: ${String(error?.message ?? error)}`, 'danger');
      dom.navigationEnabled.checked = false;
      return;
    }
    if (!granted) {
      showMessage(dom.navigationState, 'Permisiunile au fost refuzate; monitorizarea rămâne dezactivată.', 'info');
      dom.navigationEnabled.checked = false;
      return;
    }
    const saved = await send({ type: MSG.SAVE_SETTINGS, settings: { navigationCheckEnabled: true } });
    if (saved.ok) state.settings = saved.settings;
    const registered = await send({ type: MSG.REGISTER_NAVIGATION });
    if (registered.ok && registered.registered) {
      flash('Monitorizarea navigării este activă.');
    } else {
      flash('Permisiunile sunt acordate. Reîncarcă extensia dacă funcția nu pare activă.', 'info');
    }
  } else {
    const saved = await send({ type: MSG.SAVE_SETTINGS, settings: { navigationCheckEnabled: false } });
    if (saved.ok) state.settings = saved.settings;
    try {
      await chrome.permissions.remove({ permissions: ['webNavigation'], origins: ['*://*/*'] });
    } catch {
      // Permisiunile pot fi deja absente.
    }
    flash('Monitorizarea navigării a fost dezactivată.', 'info');
  }
  await refreshPermissionState();
}

/* ----------------------------------------------------------------- liste */

/** Reîncarcă listele din service worker. */
async function reloadLists() {
  const result = await send({ type: MSG.GET_LISTS });
  if (!result.ok) {
    flash(result.error ?? 'Citirea listelor a eșuat.', 'danger');
    return;
  }
  state.lists = result.lists ?? { allowlist: [], blocklist: [] };
  renderList('allowlist');
  renderList('blocklist');
}

/**
 * Redă tabelul unei liste, cu filtrare.
 * @param {'allowlist'|'blocklist'} listType
 */
function renderList(listType) {
  const container = document.querySelector(`[data-list-table="${listType}"]`);
  if (!container) return;
  clear(container);
  const query = state.filters[listType].trim().toLowerCase();
  const entries = (state.lists[listType] ?? []).filter((entry) => (
    query === '' || entry.host.includes(query) || String(entry.note ?? '').toLowerCase().includes(query)
  ));

  if (entries.length === 0) {
    container.appendChild(el('p', { class: 'empty' }, query === '' ? 'Lista este goală.' : 'Nicio potrivire.'));
    return;
  }

  const table = el('table', {}, [
    el('thead', {}, [
      el('tr', {}, [
        el('th', {}, 'Domeniu'),
        el('th', {}, 'Acoperire'),
        el('th', {}, 'Acțiuni'),
      ]),
    ]),
    el('tbody', {}, entries.map((entry) => el('tr', {}, [
      el('td', {}, [
        el('div', { class: 'entry-host' }, entry.host),
        entry.note ? el('div', { class: 'small faint' }, entry.note) : null,
      ]),
      el('td', {}, [
        el('span', { class: 'tag' }, entry.includeSubdomains ? 'subdomenii' : 'exact'),
      ]),
      el('td', {}, [
        el('button', {
          type: 'button',
          class: 'link',
          onclick: () => removeEntry(listType, entry),
        }, 'Șterge'),
      ]),
    ]))),
  ]);
  container.appendChild(el('div', { class: 'entry-table' }, table));
}

/**
 * Adaugă o intrare într-o listă.
 * @param {'allowlist'|'blocklist'} listType
 * @param {HTMLInputElement} input
 */
async function addEntry(listType, input) {
  const value = input.value.trim();
  const messageBox = document.querySelector(`[data-list-message="${listType}"]`);
  if (value === '') {
    showMessage(messageBox, 'Introdu un domeniu.', 'info');
    return;
  }
  const result = await send({ type: MSG.LIST_ADD, listType, value });
  if (!result.ok) {
    showMessage(messageBox, result.error ?? 'Adăugarea a eșuat.', result.duplicate ? 'info' : 'danger');
    return;
  }
  input.value = '';
  showMessage(messageBox, `${result.entry.host} a fost adăugat.`, 'ok');
  await reloadLists();
}

/**
 * Șterge o intrare dintr-o listă.
 * @param {'allowlist'|'blocklist'} listType
 * @param {object} entry
 */
async function removeEntry(listType, entry) {
  const result = await send({
    type: MSG.LIST_REMOVE,
    listType,
    host: entry.host,
    includeSubdomains: entry.includeSubdomains,
  });
  if (!result.ok) {
    flash(result.error ?? 'Ștergerea a eșuat.', 'danger');
    return;
  }
  await reloadLists();
}

/* ------------------------------------------------------- import / export */

/** Exportă configurația ca fișier JSON. */
async function exportConfig() {
  const result = await send({ type: MSG.EXPORT_CONFIG });
  if (!result.ok) {
    flash(result.error ?? 'Exportul a eșuat.', 'danger');
    return;
  }
  const json = JSON.stringify(result.config, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const stamp = new Date().toISOString().slice(0, 10);
  anchor.href = url;
  anchor.download = `sentinelshield2-config-${stamp}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  flash('Configurația a fost exportată.');
}

/** Importă configurația din fișierul selectat. */
async function importConfig() {
  clear(dom.importReport);
  const file = dom.importFile.files?.[0];
  if (!file) {
    showMessage(dom.importReport, 'Selectează un fișier JSON mai întâi.', 'info');
    return;
  }
  let payload;
  try {
    const text = await file.text();
    payload = JSON.parse(text);
  } catch {
    showMessage(dom.importReport, 'Fișierul nu conține JSON valid.', 'danger');
    return;
  }
  const modeInput = document.querySelector('input[name="import-mode"]:checked');
  const mode = modeInput?.value === 'replace' ? 'replace' : 'merge';
  const result = await send({ type: MSG.IMPORT_CONFIG, config: payload, mode });
  if (!result.ok) {
    showMessage(dom.importReport, result.error ?? 'Importul a eșuat.', 'danger');
    return;
  }
  const report = result.report;
  const box = el('div', {}, [
    el('p', { class: 'notice ok' }, `Import reușit (mod: ${report.mode}). Adăugate: ${report.added.allowlist} în lista de încredere, ${report.added.blocklist} în lista de blocare.${report.settingsImported ? ' Setările au fost actualizate.' : ''}`),
  ]);
  if (report.skipped.length > 0) {
    box.appendChild(el('details', {}, [
      el('summary', {}, `${report.skipped.length} intrări ignorate (detalii)`),
      el('ul', { class: 'small muted' }, report.skipped.slice(0, 50).map((skip) => (
        el('li', {}, `${skip.listType}: ${skip.entry} — ${skip.error}`)
      ))),
    ]));
  }
  dom.importReport.appendChild(box);
  await reloadLists();
  const settingsResult = await send({ type: MSG.GET_SETTINGS });
  if (settingsResult.ok) {
    applySettings(settingsResult.settings);
    await refreshPermissionState();
  }
}

/** Resetează toate listele și setările (cu confirmare în doi pași). */
async function resetAll() {
  if (!state.resetArmed) {
    state.resetArmed = true;
    dom.resetAll.textContent = 'Confirmă resetarea (apasă din nou)';
    window.setTimeout(() => {
      state.resetArmed = false;
      dom.resetAll.textContent = 'Resetează tot';
    }, 5000);
    return;
  }
  state.resetArmed = false;
  dom.resetAll.textContent = 'Resetează tot';
  const result = await send({ type: MSG.RESET_ALL });
  if (!result.ok) {
    flash(result.error ?? 'Resetarea a eșuat.', 'danger');
    return;
  }
  const settingsResult = await send({ type: MSG.GET_SETTINGS });
  if (settingsResult.ok) applySettings(settingsResult.settings);
  await reloadLists();
  await refreshPermissionState();
  flash('Toate listele și setările au fost resetate.', 'info');
}

/* ----------------------------------------------------------------- reguli */

/** Încarcă și afișează tabelul regulilor. */
async function loadRules() {
  const result = await send({ type: MSG.GET_RULES });
  if (!result.ok) {
    showMessage(dom.rulesTable, result.error ?? 'Regulile nu au putut fi încărcate.', 'danger');
    return;
  }
  clear(dom.rulesTable);
  const table = el('table', {}, [
    el('thead', {}, [
      el('tr', {}, [
        el('th', {}, 'ID'),
        el('th', {}, 'Categorie'),
        el('th', {}, 'Titlu'),
        el('th', {}, 'Severitate'),
        el('th', {}, 'Pondere'),
      ]),
    ]),
    el('tbody', {}, result.rules.map((rule) => el('tr', {}, [
      el('td', { class: 'mono' }, rule.id),
      el('td', {}, rule.category),
      el('td', {}, [
        el('div', {}, rule.title),
        el('details', {}, [
          el('summary', {}, 'De ce contează / limite'),
          el('p', { class: 'small muted' }, rule.why ?? ''),
          rule.limits ? el('p', { class: 'small faint' }, rule.limits) : null,
        ]),
      ]),
      el('td', {}, [severityChip(rule.severity)]),
      el('td', {}, String(rule.weight)),
    ]))),
  ]);
  dom.rulesTable.appendChild(table);
}

/* --------------------------------------------------------- limite/despre */

/** Afișează lista limitelor de detecție. */
function renderLimits() {
  clear(dom.limitsList);
  dom.limitsList.appendChild(el('ul', { class: 'small muted' }, DETECTION_LIMITS.map((limit) => el('li', {}, limit))));
}

/* ------------------------------------------------------------------ nav */

/** Evidențiază secțiunea activă în navigarea laterală. */
function setupNav() {
  const links = [...document.querySelectorAll('.sidenav a')];
  const sections = links.map((link) => document.querySelector(link.getAttribute('href'))).filter(Boolean);
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        for (const link of links) {
          link.classList.toggle('active', link.getAttribute('href') === `#${entry.target.id}`);
        }
      }
    }
  }, { rootMargin: '-80px 0px -70% 0px', threshold: 0 });
  for (const section of sections) observer.observe(section);
}

/* ------------------------------------------------------------------ init */

/** Leagă toate evenimentele. */
function bindEvents() {
  dom.navigationEnabled.addEventListener('change', () => toggleNavigation());

  for (const id of ['warning-level', 'reputation-enabled', 'reputation-provider', 'reputation-endpoint',
    'reputation-timeout', 'reputation-apikey', 'reputation-hostname-only', 'reputation-confirm',
    'privacy-store', 'privacy-redact']) {
    document.getElementById(id).addEventListener('change', () => saveSettings());
  }
  dom.reputationHostnameOnly.addEventListener('change', () => updateDataSentText());

  for (const listType of ['allowlist', 'blocklist']) {
    document.querySelector(`[data-list-form="${listType}"]`).addEventListener('submit', (event) => {
      event.preventDefault();
      const input = event.currentTarget.elements.host;
      addEntry(listType, input);
    });
    document.querySelector(`[data-list-search="${listType}"]`).addEventListener('input', (event) => {
      state.filters[listType] = event.target.value;
      renderList(listType);
    });
  }

  dom.exportConfig.addEventListener('click', () => exportConfig());
  dom.importConfig.addEventListener('click', () => importConfig());
  dom.resetAll.addEventListener('click', () => resetAll());
}

/** Punctul de intrare al paginii. */
async function init() {
  dom.versionChip.textContent = `versiune ${chrome.runtime.getManifest().version}`;
  renderLimits();
  setupNav();
  bindEvents();

  const settingsResult = await send({ type: MSG.GET_SETTINGS });
  if (!settingsResult.ok) {
    flash(settingsResult.error ?? 'Setările nu au putut fi încărcate.', 'danger');
    return;
  }
  applySettings(settingsResult.settings);
  dom.warningLevel.title = Object.entries(RISK_LABELS).map(([, label]) => label).join(' · ');

  await refreshPermissionState();
  await reloadLists();
  await loadRules();
}

init().catch((error) => {
  flash(`Eroare la încărcarea setărilor: ${String(error?.message ?? error)}`, 'danger');
});
