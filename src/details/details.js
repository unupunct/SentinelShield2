/**
 * SentinelShield2 - pagina de detalii.
 *
 * Primește verdictul prin `chrome.storage.session` (cheia PENDING_DETAILS),
 * scrisă de service worker la deschidere. Nu primește date prin parametri de
 * URL, ca verdictul (care conține adresa analizată) să nu ajungă în istoricul
 * browserului.
 *
 * Siguranță: toate textele (adrese, explicații, dovezi) sunt inserate prin
 * noduri de text; nu se folosește niciodată `innerHTML`.
 */

import { MSG, SESSION_KEYS } from '../shared/messages.js';
import { buildPermissionFindings } from '../content/permissionMonitor.js';
import { clear, el, formatDateTime, send, showMessage } from '../shared/ui.js';
import {
  fillUrlDisplay,
  renderDomainDetails,
  renderIndicators,
  renderReputation,
  renderUncertainty,
  renderVerdictHeader,
} from '../shared/verdictView.js';

const dom = {
  errorArea: document.getElementById('error-area'),
  verdictSection: document.getElementById('verdict-section'),
  verdictHeader: document.getElementById('verdict-header'),
  indicatorsSection: document.getElementById('indicators-section'),
  indicators: document.getElementById('indicators'),
  showEvidence: document.getElementById('show-evidence'),
  domainSection: document.getElementById('domain-section'),
  domainDetails: document.getElementById('domain-details'),
  permissionsSection: document.getElementById('permissions-section'),
  permissions: document.getElementById('permissions'),
  readPermissions: document.getElementById('read-permissions'),
  reputationSection: document.getElementById('reputation-section'),
  reputation: document.getElementById('reputation'),
  uncertaintySection: document.getElementById('uncertainty-section'),
  uncertainty: document.getElementById('uncertainty'),
  openOptions: document.getElementById('open-options'),
  reanalyze: document.getElementById('reanalyze'),
};

/** Datele primite din service worker. */
const state = {
  verdict: null,
  tabId: null,
  showEvidence: false,
};

/* ------------------------------------------------------------------ randare */

/**
 * Afișează verdictul complet.
 * @param {object} verdict
 */
function renderAll(verdict) {
  clear(dom.errorArea);
  dom.verdictSection.hidden = false;
  dom.indicatorsSection.hidden = false;
  dom.domainSection.hidden = false;
  dom.reputationSection.hidden = false;
  dom.uncertaintySection.hidden = false;

  clear(dom.verdictHeader);
  dom.verdictHeader.appendChild(renderVerdictHeader(verdict));
  fillUrlDisplay(dom.verdictHeader, verdict);

  clear(dom.indicators);
  dom.indicators.appendChild(renderIndicators(verdict, { showEvidence: state.showEvidence }));

  clear(dom.domainDetails);
  dom.domainDetails.appendChild(renderDomainDetails(verdict));
  if (verdict.isIp) {
    dom.domainDetails.appendChild(el('p', { class: 'small muted' }, 'Adresa folosește un IP în locul unui nume de domeniu.'));
  }

  clear(dom.reputation);
  dom.reputation.appendChild(renderReputation(verdict));

  clear(dom.uncertainty);
  dom.uncertainty.appendChild(renderUncertainty(verdict));

  // Secțiunea de permisiuni este disponibilă doar dacă știm tab-ul analizat.
  dom.permissionsSection.hidden = typeof state.tabId !== 'number';
  clear(dom.permissions);
  if (typeof state.tabId === 'number') {
    showMessage(dom.permissions, 'Apasă "Citește permisiunile" pentru a interoga browserul pentru acest tab.', 'info');
  }

  dom.reanalyze.disabled = !verdict.url;
}

/**
 * Afișează un rezumat de permisiuni web.
 * @param {object} summary rezultatul `summarizePermissionReport`
 */
function renderPermissions(summary) {
  clear(dom.permissions);
  if (!summary?.available) {
    for (const note of summary?.notes ?? ['Permisiunile nu au putut fi citite.']) {
      dom.permissions.appendChild(el('p', { class: 'notice' }, note));
    }
    return;
  }

  const findings = buildPermissionFindings(summary);
  if (findings.length === 0) {
    dom.permissions.appendChild(el('p', { class: 'small muted' }, 'Pagina nu a solicitat și nu are acordate permisiuni web sensibile.'));
  } else {
    const list = el('ul', { class: 'permission-list' }, findings.map((finding) => el('li', {}, [
      el('div', {}, [
        el('div', { class: 'indicator-title' }, finding.title),
        el('div', { class: 'small muted' }, finding.detail),
      ]),
      el('span', { class: 'chip' }, finding.level),
    ])));
    dom.permissions.appendChild(list);
  }

  const devices = summary.devices ?? {};
  const parts = [];
  if (devices.camera !== null) parts.push(`camere: ${devices.camera}`);
  if (devices.microphone !== null) parts.push(`microfoane: ${devices.microphone}`);
  if (devices.speaker !== null) parts.push(`difuzoare: ${devices.speaker}`);
  if (parts.length > 0) {
    dom.permissions.appendChild(el('p', { class: 'small faint' }, `Dispozitive multimedia detectate (doar număr): ${parts.join(', ')}.`));
  }

  for (const note of summary.notes ?? []) {
    dom.permissions.appendChild(el('p', { class: 'small muted' }, note));
  }
}

/* ------------------------------------------------------------------ acțiuni */

/** Citește permisiunile pentru tab-ul analizat. */
async function readPermissions() {
  if (typeof state.tabId !== 'number') {
    showMessage(dom.permissions, 'Nu cunosc tab-ul analizat, deci nu pot citi permisiunile paginii.', 'info');
    return;
  }
  dom.readPermissions.disabled = true;
  showMessage(dom.permissions, 'Se citesc permisiunile paginii…', 'info');
  const result = await send({ type: MSG.GET_PAGE_PERMISSIONS, tabId: state.tabId });
  dom.readPermissions.disabled = false;
  if (!result.ok) {
    showMessage(dom.permissions, result.error ?? 'Citirea permisiunilor a eșuat.', 'danger');
    return;
  }
  renderPermissions(result.permissions);
}

/** Reanalizează adresa curentă (dacă există). */
async function reanalyze() {
  const url = state.verdict?.url;
  if (!url) {
    showMessage(dom.errorArea, 'Nu există o adresă de reanalizat.', 'info');
    return;
  }
  dom.reanalyze.disabled = true;
  const settingsResult = await send({ type: MSG.GET_SETTINGS });
  const withReputation = settingsResult.ok && settingsResult.settings?.reputation?.enabled === true;
  const result = await send({ type: MSG.ANALYZE_URL, url, withReputation });
  dom.reanalyze.disabled = false;
  if (!result.ok) {
    showMessage(dom.errorArea, result.error ?? 'Reanaliza a eșuat.', 'danger');
    return;
  }
  state.verdict = result.verdict;
  renderAll(result.verdict);
}

/* ------------------------------------------------------------------ init */

/** Afișează un mesaj când nu există un verdict de afișat. */
function renderEmptyState() {
  clear(dom.errorArea);
  showMessage(dom.errorArea, 'Nu există o analiză de afișat. Deschide popup-ul extensiei și apasă "Analizează pagina" sau "Verifică linkul".', 'info');
  dom.verdictSection.hidden = true;
  dom.indicatorsSection.hidden = true;
  dom.domainSection.hidden = true;
  dom.permissionsSection.hidden = true;
  dom.reputationSection.hidden = true;
  dom.uncertaintySection.hidden = true;
  dom.reanalyze.disabled = true;
}

/** Încarcă verdictul din storage.session. */
async function load() {
  let pending = null;
  try {
    const stored = await chrome.storage.session.get(SESSION_KEYS.PENDING_DETAILS);
    pending = stored?.[SESSION_KEYS.PENDING_DETAILS] ?? null;
  } catch {
    pending = null;
  }
  if (!pending?.verdict) {
    renderEmptyState();
    return;
  }
  state.verdict = pending.verdict;
  state.tabId = typeof pending.tabId === 'number' ? pending.tabId : null;
  renderAll(pending.verdict);

  const meta = el('p', { class: 'small faint' }, `Sursă: ${pending.source ?? 'necunoscută'} · Deschis: ${formatDateTime(new Date(pending.createdAt ?? Date.now()).toISOString())}`);
  dom.verdictSection.appendChild(meta);
}

dom.showEvidence.addEventListener('change', () => {
  state.showEvidence = dom.showEvidence.checked;
  if (state.verdict) {
    clear(dom.indicators);
    dom.indicators.appendChild(renderIndicators(state.verdict, { showEvidence: state.showEvidence }));
  }
});
dom.readPermissions.addEventListener('click', () => readPermissions());
dom.reanalyze.addEventListener('click', () => reanalyze());
dom.openOptions.addEventListener('click', async () => {
  const result = await send({ type: MSG.OPEN_OPTIONS });
  if (!result.ok) showMessage(dom.errorArea, result.error ?? 'Nu am putut deschide setările.', 'danger');
});

load().catch((error) => {
  showMessage(dom.errorArea, `Eroare la încărcarea detaliilor: ${String(error?.message ?? error)}`, 'danger');
});
