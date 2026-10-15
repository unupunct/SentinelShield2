/**
 * SentinelShield2 - validatoare și utilitare pure.
 *
 * Reguli respectate în acest modul:
 * - nicio dependență de API Chrome;
 * - nicio funcție nu modifică argumentele primite;
 * - intrările neîncrezătoare (URL-uri, JSON importat) sunt validate strict;
 * - funcțiile de tip "redact" nu păstrează niciodată valori sensibile.
 */

import { MULTI_PART_SUFFIXES, SENSITIVE_PARAMS } from './constants.js';

/** Lungimea maximă acceptată pentru un URL analizat. */
export const MAX_URL_LENGTH = 8192;

/** Lungimea maximă acceptată pentru o intrare din liste. */
export const MAX_DOMAIN_LENGTH = 253;

/** Valoarea folosită la redactare. */
export const REDACTED = '[redactat]';

/**
 * Verifică dacă valoarea este un obiect simplu (nu array, nu null).
 * @param {unknown} value
 * @returns {boolean}
 */
export function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Detectează caracterele de control (C0 și C1) și separatoarele de linie
 * care nu au ce căuta într-un URL afișat.
 * @param {string} value
 * @returns {boolean}
 */
export function hasControlChars(value) {
  if (typeof value !== 'string') return false;
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(value);
}

/**
 * Elimină caracterele de control dintr-un text (folosit înainte de afișare).
 * @param {string} value
 * @returns {string}
 */
export function stripControlChars(value) {
  if (typeof value !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, '');
}

/**
 * Indică dacă un host este o adresă IP (IPv4 sau IPv6).
 * @param {string} host
 * @returns {boolean}
 */
export function isIpHost(host) {
  if (typeof host !== 'string' || host === '') return false;
  const candidate = host.replace(/^\[|\]$/g, '');
  if (candidate.includes(':')) return /^[0-9a-fA-F:]+$/.test(candidate);
  const octets = candidate.split('.');
  if (octets.length !== 4) return false;
  return octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);
}

/**
 * Indică dacă un IP este din spațiul privat / rezervat (localhost, 10/8,
 * 172.16/12, 192.168/16, 169.254/16, 127/8, IPv6 ::1, fc00::/7, fe80::/10).
 * Este folosit doar pentru explicații, NU ca indicator de risc.
 * @param {string} host
 * @returns {boolean}
 */
export function isPrivateIp(host) {
  const candidate = String(host ?? '').replace(/^\[|\]$/g, '').toLowerCase();
  if (!isIpHost(candidate)) return false;
  if (candidate.includes(':')) {
    if (candidate === '::1') return true;
    if (candidate.startsWith('fe80') || candidate.startsWith('fc') || candidate.startsWith('fd')) return true;
    return false;
  }
  const [a, b] = candidate.split('.').map(Number);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

/**
 * Validează un nume de domeniu sau un IP (fără schemă, fără cale).
 * @param {string} host
 * @returns {{ ok: boolean, error?: string }}
 */
export function validateHostname(host) {
  if (typeof host !== 'string' || host.trim() === '') {
    return { ok: false, error: 'Domeniul nu poate fi gol.' };
  }
  const candidate = host.trim().toLowerCase().replace(/\.$/, '');
  if (candidate.length > MAX_DOMAIN_LENGTH) {
    return { ok: false, error: `Domeniul depășește ${MAX_DOMAIN_LENGTH} de caractere.` };
  }
  if (/\s/.test(candidate)) {
    return { ok: false, error: 'Domeniul nu poate conține spații.' };
  }
  if (/[/\\@?#]/.test(candidate)) {
    return { ok: false, error: 'Introdu doar domeniul, fără cale, parametri sau credențiale.' };
  }
  if (isIpHost(candidate)) return { ok: true };

  const labels = candidate.split('.');
  if (labels.length < 2) {
    return { ok: false, error: 'Domeniul trebuie să conțină cel puțin un punct (ex. exemplu.ro).' };
  }
  for (const label of labels) {
    if (label.length === 0) {
      return { ok: false, error: 'Domeniul conține un punct dublu sau un punct la început.' };
    }
    if (label.length > 63) {
      return { ok: false, error: `Eticheta "${label}" depășește 63 de caractere.` };
    }
    if (!/^[a-z0-9-]+$/.test(label)) {
      return {
        ok: false,
        error: `Eticheta "${label}" conține caractere nepermise. Folosește doar litere latine, cifre și cratime (forma ASCII/Punycode).`,
      };
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return { ok: false, error: `Eticheta "${label}" nu poate începe sau termina cu cratimă.` };
    }
  }
  const tld = labels[labels.length - 1];
  if (!/^xn--[a-z0-9-]+$/.test(tld) && !/^[a-z]{2,}$/.test(tld)) {
    return { ok: false, error: `Terminația "${tld}" nu este validă (ex. .ro, .com, .co.uk).` };
  }
  return { ok: true };
}

/**
 * Normalizează o intrare de listă (allowlist/blocklist) introdusă de utilizator.
 * Acceptă: `exemplu.ro`, `https://exemplu.ro/ceva`, `*.exemplu.ro`.
 * @param {string} input
 * @returns {{ ok: true, host: string, includeSubdomains: boolean, raw: string }
 *   | { ok: false, error: string }}
 */
export function normalizeDomainEntry(input) {
  if (typeof input !== 'string') return { ok: false, error: 'Valoarea introdusă nu este text.' };
  let raw = input.trim();
  if (raw === '') return { ok: false, error: 'Introdu un domeniu.' };

  let includeSubdomains = false;
  if (raw.startsWith('*.')) {
    includeSubdomains = true;
    raw = raw.slice(2);
  }

  // Elimină schema, dacă există.
  raw = raw.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');

  // Taie credențialele, calea, parametrii și fragmentul.
  const cutIndex = raw.search(/[/?#]/);
  const hostPart = cutIndex === -1 ? raw : raw.slice(0, cutIndex);

  // Elimină credențialele de tip user:pass@host și portul.
  const withoutCredentials = hostPart.includes('@') ? hostPart.slice(hostPart.lastIndexOf('@') + 1) : hostPart;
  const withoutPort = /^\[[^\]]+\]$/.test(withoutCredentials)
    ? withoutCredentials
    : withoutCredentials.replace(/:\d+$/, '');

  let host = withoutPort.toLowerCase().replace(/\.$/, '');

  // Formele Unicode sunt convertite în ASCII/Punycode, ca listele să fie consistente.
  if (/[^\x00-\x7F]/.test(host)) {
    try {
      host = new URL(`http://${host}`).hostname;
    } catch {
      return { ok: false, error: 'Domeniul conține caractere Unicode care nu pot fi convertite în Punycode.' };
    }
  }

  const validation = validateHostname(host);
  if (!validation.ok) return { ok: false, error: validation.error };

  if (isIpHost(host) && includeSubdomains) {
    return { ok: false, error: 'O adresă IP nu are subdomenii; elimină prefixul "*.". ' };
  }

  return { ok: true, host, includeSubdomains, raw: input.trim() };
}

/**
 * Parsează un URL fără să arunce excepții.
 * @param {string} value
 * @returns {{ ok: true, url: URL } | { ok: false, error: string }}
 */
export function parseUrl(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    return { ok: false, error: 'Adresa este goală.' };
  }
  try {
    return { ok: true, url: new URL(value) };
  } catch {
    return { ok: false, error: 'Adresa nu are o formă validă.' };
  }
}

/**
 * Normalizează intrarea brută a utilizatorului într-un URL parsabil.
 * `exemplu.ro` devine `https://exemplu.ro/`, `javascript:...` rămâne intact
 * (pentru a putea fi semnalat ca schemă periculoasă).
 * @param {string} input
 * @param {{ defaultScheme?: string }} [options]
 * @returns {{ ok: true, url: URL, normalized: string }
 *   | { ok: false, error: string }}
 */
export function normalizeUrlInput(input, options = {}) {
  const defaultScheme = options.defaultScheme ?? 'https';
  if (typeof input !== 'string') return { ok: false, error: 'Introdu o adresă de analizat.' };

  const trimmed = input.trim();
  if (trimmed === '') return { ok: false, error: 'Introdu o adresă de analizat.' };
  if (trimmed.length > MAX_URL_LENGTH) {
    return { ok: false, error: `Adresa depășește ${MAX_URL_LENGTH} de caractere și nu a fost analizată.` };
  }
  // Separatoarele de linie lipite accidental în interior sunt eliminate.
  const withoutBreaks = trimmed.replace(/[\r\n\t]+/g, '');

  let candidate = withoutBreaks;
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+-]*):/.exec(withoutBreaks);
  if (!schemeMatch && withoutBreaks.startsWith('//')) {
    candidate = `${defaultScheme}:${withoutBreaks}`;
  } else if (!schemeMatch) {
    candidate = `${defaultScheme}://${withoutBreaks}`;
  }

  try {
    const url = new URL(candidate);
    return { ok: true, url, normalized: url.href };
  } catch {
    return { ok: false, error: 'Adresa nu are o formă validă.' };
  }
}

/**
 * Determină domeniul registrabil (eTLD+1) folosind o listă documentată de
 * sufixe cu două niveluri. NU este Public Suffix List completa.
 * @param {string} host
 * @param {readonly string[]} [suffixes]
 * @returns {string}
 */
export function getRegistrableDomain(host, suffixes = MULTI_PART_SUFFIXES) {
  const normalized = String(host ?? '').toLowerCase().replace(/\.$/, '');
  if (normalized === '' || isIpHost(normalized)) return normalized;
  const parts = normalized.split('.');
  if (parts.length <= 2) return normalized;
  const lastTwo = parts.slice(-2).join('.');
  if (suffixes.includes(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

/**
 * Distanța Levenshtein între două șiruri, cu ieșire rapidă la diferență mare.
 * @param {string} a
 * @param {string} b
 * @param {number} [maxDistance] dacă este depășită, funcția returnează maxDistance + 1
 * @returns {number}
 */
export function levenshtein(a, b, maxDistance = Number.POSITIVE_INFINITY) {
  const s = String(a ?? '');
  const t = String(b ?? '');
  if (s === t) return 0;
  if (Math.abs(s.length - t.length) > maxDistance) return maxDistance + 1;
  if (s.length === 0) return t.length;
  if (t.length === 0) return s.length;

  let previous = new Array(t.length + 1);
  let current = new Array(t.length + 1);
  for (let j = 0; j <= t.length; j += 1) previous[j] = j;

  for (let i = 1; i <= s.length; i += 1) {
    current[0] = i;
    let rowMin = current[0];
    for (let j = 1; j <= t.length; j += 1) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      current[j] = Math.min(
        previous[j] + 1,
        current[j - 1] + 1,
        previous[j - 1] + cost,
      );
      if (current[j] < rowMin) rowMin = current[j];
    }
    if (rowMin > maxDistance) return maxDistance + 1;
    const swap = previous;
    previous = current;
    current = swap;
  }
  return previous[t.length];
}

/**
 * Redactează dintr-un URL valorile parametrilor sensibili și parola din
 * credențiale. Folosit înainte de orice afișare în jurnal sau în dovezi.
 *
 * Se lucrează pe șirul original (nu pe URLSearchParams), ca adresa redactată
 * să rămână lizibilă: `token=abc` devine `token=[redactat]`.
 *
 * @param {string} value
 * @param {{ stripQuery?: boolean }} [options]
 * @returns {string}
 */
export function redactUrl(value, options = {}) {
  if (typeof value !== 'string') return '';
  const cleaned = stripControlChars(value);
  const parsed = parseUrl(cleaned);

  // Scheme fără host (javascript:, data:, about:) nu au structură de parametri;
  // se aplică o redactare conservatoare.
  if (!parsed.ok || parsed.url.host === '') {
    return cleaned.replace(/=([^&#\s]+)/g, `=${REDACTED}`);
  }

  const url = parsed.url;
  const sensitive = new Set(SENSITIVE_PARAMS);
  const isSensitiveKey = (key) => {
    let decoded = key;
    try {
      decoded = decodeURIComponent(key);
    } catch {
      decoded = key;
    }
    const lower = decoded.toLowerCase();
    return sensitive.has(lower) || /token|secret|pass|key|session|code|auth/i.test(lower);
  };

  let search = url.search;
  if (options.stripQuery) {
    search = '';
  } else if (search !== '') {
    const redactedParts = search.slice(1).split('&').map((part) => {
      const separatorIndex = part.indexOf('=');
      if (separatorIndex === -1) return part;
      const key = part.slice(0, separatorIndex);
      return isSensitiveKey(key) ? `${key}=${REDACTED}` : part;
    });
    search = `?${redactedParts.join('&')}`;
  }

  const credentials = url.username === ''
    ? ''
    : `${url.username}${url.password !== '' ? `:${REDACTED}` : ''}@`;
  const port = url.port === '' ? '' : `:${url.port}`;

  return `${url.protocol}//${credentials}${url.hostname}${port}${url.pathname}${search}${url.hash}`;
}

/**
 * Împarte un text în segmente normal-evidențiate, pe baza unor intervale.
 * Este folosit pentru a evidenția caracterele suspecte FĂRĂ a construi HTML:
 * UI-ul creează apoi noduri de text, nu `innerHTML`.
 * @param {string} text
 * @param {Array<{ start: number, end: number }>} ranges intervale [start, end)
 * @returns {Array<{ text: string, highlighted: boolean }>}
 */
export function splitByRanges(text, ranges) {
  const source = String(text ?? '');
  if (source === '') return [];
  const valid = (Array.isArray(ranges) ? ranges : [])
    .filter((r) => isPlainObject(r) && Number.isInteger(r.start) && Number.isInteger(r.end))
    .filter((r) => r.start >= 0 && r.end > r.start && r.start < source.length)
    .map((r) => ({ start: r.start, end: Math.min(r.end, source.length) }))
    .sort((a, b) => a.start - b.start || a.end - b.end);

  // Unim intervalele care se suprapun, ca să nu producem segmente duplicat.
  const merged = [];
  for (const range of valid) {
    const last = merged[merged.length - 1];
    if (last && range.start <= last.end) {
      last.end = Math.max(last.end, range.end);
    } else {
      merged.push({ ...range });
    }
  }

  const parts = [];
  let cursor = 0;
  for (const range of merged) {
    if (range.start > cursor) {
      parts.push({ text: source.slice(cursor, range.start), highlighted: false });
    }
    parts.push({ text: source.slice(range.start, range.end), highlighted: true });
    cursor = range.end;
  }
  if (cursor < source.length) {
    parts.push({ text: source.slice(cursor), highlighted: false });
  }
  return parts;
}

/**
 * Normalizează un număr de port. Returnează `null` dacă portul lipsește sau
 * este portul implicit al schemei.
 * @param {URL} url
 * @returns {number|null}
 */
export function getExplicitPort(url) {
  const port = url.port;
  if (!port) return null;
  const numeric = Number(port);
  if (Number.isNaN(numeric)) return null;
  return numeric;
}

/**
 * Trunchiază un text lung pentru afișare, marcând clar trunchierea.
 * @param {string} value
 * @param {number} [max]
 * @returns {string}
 */
export function truncate(value, max = 120) {
  const source = String(value ?? '');
  if (source.length <= max) return source;
  return `${source.slice(0, max - 1)}…`;
}
