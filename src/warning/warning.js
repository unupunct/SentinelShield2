/**
 * SentinelShield2 - pagina de avertizare.
 *
 * Este afișată atunci când monitorizarea navigării (activată explicit de
 * utilizator) întâlnește o adresă peste pragul configurat. Primește doar
 * identificatorul tab-ului prin parametru de URL; verdictul este citit din
 * `chrome.storage.session`, ca adresa analizată să nu ajungă în istoric.
 *
 * "Continuă oricum" acordă o excepție temporară, pe host, pentru un număr
 * fix de minute - afișat explicit utilizatorului.
 */

import { MSG, TEMP_EXCEPTION_MINUTES } from '../shared/messages.js';
import { clear, el, send, showMessage } from '../shared/ui.js';
import { fillUrlDisplay, renderRiskReasons, renderVerdictHeader } from '../shared/verdictView.js';

const dom = {
  errorArea: document.getElementById('error-area'),
  card: document.getElementById('warning-card'),
  header: document.getElementById('warning-header'),
  reasons: document.getElementById('warning-reasons'),
  minutes: document.getElementById('exception-minutes'),
  goBack: document.getElementById('go-back'),
  continueAnyway: document.getElementById('continue-anyway'),
  confirmContinue: document.getElementById('confirm-continue'),
  actionMessage: document.getElementById('action-message'),
};

/** Identificatorul tab-ului, din parametrul de URL. */
const tabId = (() => {
  const value = new URLSearchParams(location.search).get('tabId');
  const parsed = Number(value);
  return Number.isInteger(parsed) ? parsed : null;
})();

dom.minutes.textContent = String(TEMP_EXCEPTION_MINUTES);

/**
 * Afișează pagina de avertizare pentru un verdict.
 * @param {object} verdict
 */
function renderWarning(verdict) {
  dom.card.hidden = false;
  clear(dom.header);
  dom.header.appendChild(renderVerdictHeader(verdict, { urlLimit: 300 }));
  fillUrlDisplay(dom.header, verdict);

  clear(dom.reasons);
  dom.reasons.appendChild(el('h2', {}, 'De ce am oprit navigarea'));
  dom.reasons.appendChild(renderRiskReasons(verdict, 5));
}

/** Afișează eroarea "nu am un avertisment activ". */
function renderNoWarning() {
  clear(dom.errorArea);
  showMessage(
    dom.errorArea,
    'Nu există un avertisment activ pentru acest tab. Este posibil să fi expirat sau să fi fost deja tratat. Poți închide acest tab.',
    'info',
  );
  dom.card.hidden = true;
}

/** Revine la pagina anterioară (comportamentul recomandat). */
async function goBackSafely() {
  if (tabId === null) {
    showMessage(dom.actionMessage, 'Nu am identificat tab-ul. Închide acest tab.', 'info');
    return;
  }
  dom.goBack.disabled = true;
  const result = await send({ type: MSG.GO_BACK_SAFELY, tabId });
  if (!result.ok) {
    dom.goBack.disabled = false;
    showMessage(dom.actionMessage, result.error ?? 'Nu am putut reveni.', 'danger');
  }
}

/** Continuă oricum, cu excepție temporară pentru host. */
async function continueAnyway() {
  if (tabId === null) {
    showMessage(dom.actionMessage, 'Nu am identificat tab-ul. Relua navigarea manual.', 'info');
    return;
  }
  dom.continueAnyway.disabled = true;
  const result = await send({ type: MSG.CONTINUE_ANYWAY, tabId });
  if (!result.ok) {
    dom.continueAnyway.disabled = false;
    showMessage(dom.actionMessage, result.error ?? 'Nu am putut continua navigarea.', 'danger');
    return;
  }
  const host = result.exception?.host ?? 'acest domeniu';
  showMessage(
    dom.actionMessage,
    `Continui. Ai o excepție de ${TEMP_EXCEPTION_MINUTES} minute pentru ${host}. Avertismentul va reapărea după expirare.`,
    'ok',
  );
}

/* ------------------------------------------------------------------ init */

dom.goBack.addEventListener('click', () => goBackSafely());
dom.confirmContinue.addEventListener('change', () => {
  dom.continueAnyway.disabled = !dom.confirmContinue.checked;
});
dom.continueAnyway.addEventListener('click', () => continueAnyway());

async function load() {
  if (tabId === null) {
    renderNoWarning();
    return;
  }
  const result = await send({ type: MSG.GET_PENDING_WARNING, tabId });
  if (!result.ok || !result.pending?.verdict) {
    renderNoWarning();
    return;
  }
  renderWarning(result.pending.verdict);
}

load().catch((error) => {
  showMessage(dom.errorArea, `Eroare la afișarea avertismentului: ${String(error?.message ?? error)}`, 'danger');
});
