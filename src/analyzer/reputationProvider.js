/**
 * SentinelShield2 - reputationProvider.
 *
 * ADAPTOR OPȚIONAL. Implicit este DEZACTIVAT: analiza locală rămâne mecanismul
 * principal, iar extensia nu trimite nimic în rețea fără configurare explicită.
 *
 * Ce se transmite (documentat în PRIVACY.md):
 * - implicit DOAR numele de domeniu (fără cale, fără parametri, fără
 *   fragment), pentru a evita scurgerea tokenurilor sau a datelor din URL;
 * - nimic dacă `enabled` este false sau endpoint-ul este gol.
 *
 * Limite:
 * - un serviciu de reputație poate avea fals pozitive și fals negative;
 * - verdictul "Periculos confirmat" este acordat DOAR dacă utilizatorul
 *   activează explicit `confirmMalicious` (a înțeles că sursa este de
 *   încredere) ȘI sursa răspunde cu verdict malițios;
 * - cheile API introduse într-o extensie distribuită NU sunt protejate față
 *   de utilizatorul care inspectează extensia. Nu se includ chei în cod.
 */

import { REPUTATION_PROVIDERS } from '../shared/constants.js';

/** Stările posibile ale unei verificări de reputație. */
export const REPUTATION_STATUS = Object.freeze({
  DISABLED: 'disabled',
  OK: 'ok',
  ERROR: 'error',
  TIMEOUT: 'timeout',
  INVALID: 'invalid',
});

/** Verdictul intern normalizat. */
export const REPUTATION_VERDICT = Object.freeze({
  UNKNOWN: 'unknown',
  CLEAN: 'clean',
  SUSPICIOUS: 'suspicious',
  MALICIOUS: 'malicious',
});

/** Mapa valorilor acceptate de la surse externe către verdictul intern. */
const VERDICT_MAP = Object.freeze({
  clean: REPUTATION_VERDICT.CLEAN,
  safe: REPUTATION_VERDICT.CLEAN,
  benign: REPUTATION_VERDICT.CLEAN,
  ok: REPUTATION_VERDICT.CLEAN,
  suspicious: REPUTATION_VERDICT.SUSPICIOUS,
  warn: REPUTATION_VERDICT.SUSPICIOUS,
  warning: REPUTATION_VERDICT.SUSPICIOUS,
  unknown: REPUTATION_VERDICT.UNKNOWN,
  malicious: REPUTATION_VERDICT.MALICIOUS,
  phishing: REPUTATION_VERDICT.MALICIOUS,
  malware: REPUTATION_VERDICT.MALICIOUS,
  unsafe: REPUTATION_VERDICT.MALICIOUS,
  blocklisted: REPUTATION_VERDICT.MALICIOUS,
});

/**
 * Construiește textul descriptiv al datelor trimise (afișat în UI înainte de a trimite).
 * @param {{ hostnameOnly: boolean }} reputationSettings
 * @param {string} host
 * @returns {string}
 */
export function describeDataSent(reputationSettings, host) {
  const scope = reputationSettings?.hostnameOnly === false ? 'domeniul și calea (fără parametri)' : 'doar numele de domeniu';
  return `${scope}: ${host}`;
}

/**
 * Validează și normalizează endpoint-ul configurat.
 * @param {string} endpoint
 * @returns {{ ok: true, url: URL } | { ok: false, error: string }}
 */
export function validateEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || endpoint.trim() === '') {
    return { ok: false, error: 'Endpoint-ul nu este configurat.' };
  }
  try {
    const url = new URL(endpoint.trim());
    if (url.protocol !== 'https:') {
      return { ok: false, error: 'Endpoint-ul trebuie să folosească HTTPS.' };
    }
    return { ok: true, url };
  } catch {
    return { ok: false, error: 'Endpoint-ul nu este o adresă validă.' };
  }
}

/**
 * Construiește corpul cererii. Niciodată nu include parametri de query sau
 * fragmente din adresa analizată.
 * @param {object} facts
 * @param {{ hostnameOnly?: boolean }} reputationSettings
 * @returns {object}
 */
export function buildRequestPayload(facts, reputationSettings = {}) {
  const payload = {
    host: facts.asciiHost,
    unicodeHost: facts.unicodeHost,
    registrableDomain: facts.registrableDomain,
  };
  if (reputationSettings.hostnameOnly === false) {
    // Doar calea, fără parametri și fără fragment (documentat în PRIVACY.md).
    payload.path = facts.pathname;
    payload.scheme = facts.scheme;
  }
  return payload;
}

/**
 * Interpretează răspunsul unei surse de reputație.
 * @param {unknown} body
 * @returns {{ verdict: string, confidence: number|null, valid: boolean }}
 */
export function parseReputationResponse(body) {
  if (typeof body !== 'object' || body === null) {
    return { verdict: REPUTATION_VERDICT.UNKNOWN, confidence: null, valid: false };
  }
  const raw = String(body.verdict ?? body.status ?? body.result ?? '').toLowerCase().trim();
  const verdict = VERDICT_MAP[raw] ?? REPUTATION_VERDICT.UNKNOWN;
  const confidenceRaw = Number(body.confidence ?? body.score);
  const confidence = Number.isFinite(confidenceRaw)
    ? Math.min(1, Math.max(0, confidenceRaw > 1 ? confidenceRaw / 100 : confidenceRaw))
    : null;
  return { verdict, confidence, valid: verdict !== REPUTATION_VERDICT.UNKNOWN || raw === 'unknown' };
}

/**
 * Verifică reputația unui domeniu folosind adaptorul HTTP configurat.
 * Nu aruncă niciodată: orice eroare este întoarsă ca rezultat cu `error`.
 *
 * @param {object} facts rezultatul analizei URL
 * @param {object} settings setările complete
 * @param {{ fetchImpl?: Function }} [deps] injecție pentru teste
 * @returns {Promise<object>} rezultatul verificării
 */
export async function checkReputation(facts, settings, deps = {}) {
  const reputationSettings = settings?.reputation ?? {};
  const base = {
    checked: false,
    provider: reputationSettings.provider ?? REPUTATION_PROVIDERS.NONE,
    verdict: REPUTATION_VERDICT.UNKNOWN,
    confirmed: false,
    confidence: null,
    status: REPUTATION_STATUS.DISABLED,
    error: '',
    dataSent: '',
    checkedAt: '',
    source: '',
  };

  if (reputationSettings.enabled !== true) {
    return { ...base, error: '' };
  }
  if (reputationSettings.provider !== REPUTATION_PROVIDERS.CUSTOM_HTTP) {
    return { ...base, status: REPUTATION_STATUS.INVALID, error: 'Providerul de reputație configurat nu este suportat.' };
  }

  const endpoint = validateEndpoint(reputationSettings.endpoint);
  if (!endpoint.ok) {
    return { ...base, status: REPUTATION_STATUS.INVALID, error: endpoint.error };
  }

  const fetchImpl = deps.fetchImpl ?? (typeof fetch === 'function' ? fetch : null);
  if (!fetchImpl) {
    return { ...base, status: REPUTATION_STATUS.ERROR, error: 'Nu există API de rețea disponibil în acest context.' };
  }

  const timeoutMs = Number(reputationSettings.timeoutMs) || 4000;
  const controller = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

  const payload = buildRequestPayload(facts, reputationSettings);
  const dataSent = describeDataSent(reputationSettings, facts.asciiHost);

  try {
    const headers = { 'Content-Type': 'application/json' };
    const apiKey = typeof reputationSettings.apiKey === 'string' ? reputationSettings.apiKey : '';
    if (apiKey !== '') headers['X-API-Key'] = apiKey;

    const response = await fetchImpl(`${endpoint.url.href.replace(/\/$/, '')}/check`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: controller ? controller.signal : undefined,
    });

    if (!response || typeof response.json !== 'function') {
      return { ...base, status: REPUTATION_STATUS.INVALID, error: 'Răspunsul sursei nu este JSON.', dataSent };
    }
    if (response.status >= 400) {
      return {
        ...base,
        status: REPUTATION_STATUS.ERROR,
        error: `Sursa de reputație a răspuns cu codul ${response.status}.`,
        dataSent,
      };
    }

    const body = await response.json();
    const parsed = parseReputationResponse(body);
    const confirmed = parsed.verdict === REPUTATION_VERDICT.MALICIOUS && reputationSettings.confirmMalicious === true;

    return {
      checked: true,
      provider: reputationSettings.provider,
      verdict: parsed.verdict,
      confirmed,
      confidence: parsed.confidence,
      status: parsed.valid ? REPUTATION_STATUS.OK : REPUTATION_STATUS.INVALID,
      error: parsed.valid ? '' : 'Sursa a răspuns într-un format nerecunoscut.',
      dataSent,
      checkedAt: new Date().toISOString(),
      source: typeof body?.source === 'string' ? body.source : endpoint.url.host,
    };
  } catch (error) {
    const isAbort = error?.name === 'AbortError';
    return {
      ...base,
      status: isAbort ? REPUTATION_STATUS.TIMEOUT : REPUTATION_STATUS.ERROR,
      error: isAbort
        ? `Sursa de reputație nu a răspuns în ${timeoutMs} ms.`
        : `Verificarea reputației a eșuat: ${String(error?.message ?? error)}`,
      dataSent,
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}
