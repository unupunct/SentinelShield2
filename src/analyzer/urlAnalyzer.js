/**
 * SentinelShield2 - urlAnalyzer.
 *
 * Rol: transformă un URL (sau o intrare brută) în FAPTE obiective, deterministe
 * și serializabile. Acest modul NU decide nivelul de risc: nu atribuie ponderi
 * și nu emite verdicte. Decizia aparține modulelor `phishingRules` + `riskScorer`.
 *
 * Separarea este intenționată: astfel regulile pot fi revizuite, testate și
 * explicate independent de parsare.
 */

import {
  RISKY_TLDS,
  SENSITIVE_KEYWORDS,
  SENSITIVE_PARAMS,
  TRACKING_PARAMS,
  REDIRECT_PARAMS,
  DANGEROUS_SCHEMES,
  SOFT_SUSPICIOUS_SCHEMES,
  URL_SHORTENERS,
} from '../shared/constants.js';
import { collectScripts, detectScript, isPunycodeLabel, toUnicodeHost } from '../shared/idn.js';
import {
  hasControlChars,
  isIpHost,
  isPrivateIp,
  normalizeUrlInput,
  getRegistrableDomain,
  getExplicitPort,
  truncate,
} from '../shared/validators.js';

/** Zonele unui URL, folosite la explicarea poziției caracterelor suspecte. */
export const ZONES = Object.freeze({
  SCHEME: 'scheme',
  USERINFO: 'userinfo',
  HOST: 'host',
  PORT: 'port',
  PATH: 'path',
  QUERY: 'query',
  FRAGMENT: 'fragment',
});

/**
 * Calculează offsetul la care începe host-ul în șirul `href` normalizat.
 * Astfel pozițiile caracterelor suspecte corespund exact textului afișat.
 * @param {string} href
 * @returns {{ authorityStart: number, hostStart: number, hostEnd: number }}
 */
function locateHost(href) {
  const schemeIndex = href.indexOf('://');
  const authorityStart = schemeIndex === -1 ? 0 : schemeIndex + 3;
  const rest = href.slice(authorityStart);
  const boundary = rest.search(/[/?#]/);
  const authority = boundary === -1 ? rest : rest.slice(0, boundary);
  const atIndex = authority.lastIndexOf('@');
  const hostStart = authorityStart + (atIndex === -1 ? 0 : atIndex + 1);
  const hostEnd = authorityStart + authority.length;
  return { authorityStart, hostStart, hostEnd };
}

/**
 * Determină zona unui index din `href`.
 * @param {number} index
 * @param {{ authorityStart: number, hostStart: number, hostEnd: number }} host
 * @param {string} href
 * @returns {string}
 */
function zoneOf(index, host, href) {
  if (index < host.authorityStart) return ZONES.SCHEME;
  if (index < host.hostStart) return ZONES.USERINFO;
  if (index < host.hostEnd) return ZONES.HOST;
  const queryIndex = href.indexOf('?');
  const fragmentIndex = href.indexOf('#');
  if (fragmentIndex !== -1 && index >= fragmentIndex) return ZONES.FRAGMENT;
  if (queryIndex !== -1 && index >= queryIndex) return ZONES.QUERY;
  return ZONES.PATH;
}

/**
 * Decodează un grup de secvențe `%xx` consecutive pornind de la un index.
 * @param {string} href
 * @param {number} start
 * @returns {{ decoded: string, end: number, count: number }}
 */
function decodePercentRun(href, start) {
  const bytes = [];
  let index = start;
  while (index + 2 < href.length + 1 && href[index] === '%') {
    const hex = href.slice(index + 1, index + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) break;
    bytes.push(Number.parseInt(hex, 16));
    index += 3;
    if (bytes.length > 32) break; // plafon de siguranță
  }
  let decoded = '';
  if (bytes.length > 0) {
    try {
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
    } catch {
      decoded = bytes.map((b) => String.fromCharCode(b)).join('');
    }
  }
  return { decoded, end: index, count: bytes.length };
}

/**
 * Extrage caracterele neobișnuite din URL, cu poziția lor exactă, pentru a
 * putea fi evidențiate în interfață fără a genera HTML.
 *
 * Motivele (`reason`):
 * - `control`   : caracter de control / invizibil prezent literal în adresă;
 * - `unicode`   : caracter non-ASCII prezent literal (diacritice, alt alfabet);
 * - `encoded`   : secvență `%xx` care ascunde un caracter de control / invizibil
 *                 (ex. `%00`, `%E2%80%AE` - override de direcție);
 * - `encoded_unicode`: secvență `%xx` care ascunde un caracter non-ASCII obișnuit
 *                 (ex. diacritice codificate); informativ, nu indicator de risc.
 *
 * @param {string} href
 * @param {{ authorityStart: number, hostStart: number, hostEnd: number }} hostRange
 * @returns {Array<{ index: number, char: string, codePoint: number, script: string, zone: string, reason: string }>}
 */
function findUnusualChars(href, hostRange) {
  const findings = [];
  let offset = 0;
  for (const ch of href) {
    const codePoint = ch.codePointAt(0);
    const zone = zoneOf(offset, hostRange, href);
    const script = detectScript(ch);
    if (codePoint < 0x80) {
      if (hasControlChars(ch)) {
        findings.push({ index: offset, char: ch, codePoint, script: 'ascii', zone, reason: 'control' });
      }
    } else {
      findings.push({
        index: offset,
        char: ch,
        codePoint,
        script,
        zone,
        reason: hasControlChars(ch) ? 'control' : 'unicode',
      });
    }
    offset += ch.length;
  }

  // Secvențele codificate procentual pot ascunde caractere invizibile sau
  // caractere care schimbă ordinea de afișare a adresei.
  let scan = 0;
  while (scan < href.length) {
    const percentIndex = href.indexOf('%', scan);
    if (percentIndex === -1) break;
    const run = decodePercentRun(href, percentIndex);
    if (run.count > 0) {
      if (hasControlChars(run.decoded)) {
        findings.push({
          index: percentIndex,
          char: href.slice(percentIndex, run.end),
          codePoint: run.decoded.codePointAt(0) ?? 0,
          script: detectScript(run.decoded[0] ?? 'a'),
          zone: zoneOf(percentIndex, hostRange, href),
          reason: 'encoded',
        });
      } else if (/[^\x00-\x7F]/.test(run.decoded)) {
        findings.push({
          index: percentIndex,
          char: href.slice(percentIndex, run.end),
          codePoint: run.decoded.codePointAt(0) ?? 0,
          script: detectScript(run.decoded[0] ?? 'a'),
          zone: zoneOf(percentIndex, hostRange, href),
          reason: 'encoded_unicode',
        });
      }
    }
    scan = run.end > percentIndex ? run.end : percentIndex + 1;
  }

  // Elimină duplicatele (același index, același motiv) și sortează stabil.
  const seen = new Set();
  return findings
    .filter((f) => {
      const key = `${f.index}:${f.reason}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) => a.index - b.index || a.reason.localeCompare(b.reason));
}

/**
 * Detectează codificarea procentuală din partea de domeniu a adresei BRUTE
 * introduse de utilizator. Este necesar pentru că parserul URL normalizează
 * host-ul (`exa%6dple.ro` -> `example.ro`), deci forma originală se pierde.
 * @param {string} rawInput
 * @returns {boolean}
 */
export function detectRawEncodedHost(rawInput) {
  if (typeof rawInput !== 'string') return false;
  const match = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]*)/.exec(rawInput.trim());
  if (!match) return false;
  const authority = match[1];
  const host = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
  return /%[0-9a-fA-F]{2}/.test(host);
}

/**
 * Caută cuvintele-cheie sensibile în adresă.
 *
 * Două strategii, intenționat diferite:
 * - în HOST se potrivește DOAR token exact (etichete separate prin `.` și `-`),
 *   pentru ca `accounts.google.com` să nu fie raportat pentru `account`;
 * - în cale, parametri și fragment se potrivește substring (cum apar în
 *   adresele reale de phishing: `/account/verify`), doar pentru cuvinte de
 *   minim 4 caractere, pentru a limita zgomotul.
 *
 * Zona `userinfo` este exclusă: credențialele din adresă au regulă proprie.
 *
 * @param {string} href
 * @param {{ hostStart: number, hostEnd: number, authorityStart: number }} hostRange
 * @returns {Array<{ keyword: string, zone: string, index: number }>}
 */
function findKeywordMatches(href, hostRange) {
  const results = [];
  const lowerHref = href.toLowerCase();

  const hostSegment = lowerHref.slice(hostRange.hostStart, hostRange.hostEnd);
  const tokens = hostSegment.split(/[.-]/).filter(Boolean);
  let searchFrom = 0;
  for (const token of tokens) {
    if (!SENSITIVE_KEYWORDS.includes(token)) continue;
    const index = lowerHref.indexOf(token, hostRange.hostStart + searchFrom);
    searchFrom = Math.max(0, index - hostRange.hostStart + token.length);
    results.push({ keyword: token, zone: ZONES.HOST, index: index === -1 ? hostRange.hostStart : index });
  }

  const restStart = hostRange.hostEnd;
  const rest = lowerHref.slice(restStart);
  for (const keyword of SENSITIVE_KEYWORDS) {
    if (keyword.length < 4) continue;
    let from = 0;
    while (from < rest.length) {
      const index = rest.indexOf(keyword, from);
      if (index === -1) break;
      const absolute = restStart + index;
      const zone = zoneOf(absolute, hostRange, href);
      if (zone !== ZONES.USERINFO) {
        results.push({ keyword, zone, index: absolute });
      }
      from = index + keyword.length;
    }
  }

  return results.sort((a, b) => a.index - b.index || a.keyword.localeCompare(b.keyword));
}

/**
 * Analizează structura unui URL deja parsabil.
 * @param {URL} url
 * @param {string} rawInput
 * @returns {object} fapte despre URL
 */
export function analyzeParsedUrl(url, rawInput = '') {
  const href = url.href;
  const asciiHost = url.hostname.toLowerCase();
  const hostRange = locateHost(href);
  const { unicodeHost, decodedLabels, failedLabels } = toUnicodeHost(asciiHost);
  const labels = asciiHost.split('.').filter(Boolean);
  const unicodeLabels = unicodeHost.split('.').filter(Boolean);
  const labelPairs = labels.map((ascii, index) => ({
    ascii,
    unicode: unicodeLabels[index] ?? ascii,
    isPunycode: isPunycodeLabel(ascii),
  }));
  const port = getExplicitPort(url);
  const credentials = url.username !== '' || url.password !== '';

  const params = [];
  for (const [key, value] of url.searchParams.entries()) {
    params.push({
      key,
      value,
      keyLower: key.toLowerCase(),
      isSensitive: SENSITIVE_PARAMS.includes(key.toLowerCase()),
      isTracking: TRACKING_PARAMS.includes(key.toLowerCase()),
      isRedirect: REDIRECT_PARAMS.includes(key.toLowerCase()),
    });
  }

  const percentMatches = href.match(/%[0-9a-fA-F]{2}/g) ?? [];
  const doubleEncoded = /%25[0-9a-fA-F]{2}/i.test(href);
  const pathSegments = url.pathname.split('/').filter(Boolean);
  const tld = labels.length > 1 ? labels[labels.length - 1] : '';
  const longestLabel = labels.reduce((max, l) => Math.max(max, l.length), 0);
  const hyphenCount = (asciiHost.match(/-/g) ?? []).length;
  const digitCount = (asciiHost.match(/\d/g) ?? []).length;

  const sensitiveParams = params.filter((p) => p.isSensitive).map((p) => p.key);
  const trackingParams = params.filter((p) => p.isTracking).map((p) => p.key);
  const redirectParams = params.filter((p) => p.isRedirect).map((p) => p.key);

  const unusualChars = findUnusualChars(href, hostRange);
  const keywordMatches = findKeywordMatches(href, hostRange);
  const controlChars = unusualChars.filter((c) => c.reason === 'control');
  const invisibleEncoded = unusualChars.filter((c) => c.reason === 'encoded');
  const encodedUnicode = unusualChars.filter((c) => c.reason === 'encoded_unicode');
  const encodedInHost = unusualChars.filter(
    (c) => (c.reason === 'encoded' || c.reason === 'encoded_unicode') && c.zone === ZONES.HOST,
  );
  const rawEncodedHost = detectRawEncodedHost(rawInput);

  const registrableDomain = getRegistrableDomain(asciiHost);
  const scriptSet = new Set([...collectScripts(unicodeHost), ...collectScripts(url.pathname), ...collectScripts(url.search)]);

  return {
    rawInput,
    href,
    protocol: url.protocol,
    scheme: url.protocol.replace(/:$/, '').toLowerCase(),
    asciiHost,
    unicodeHost,
    hostDiffersFromAscii: unicodeHost !== asciiHost,
    decodedLabels,
    failedLabels,
    labels,
    unicodeLabels,
    labelPairs,
    labelCount: labels.length,
    subdomainLabels: labels.length > 1 ? labels.slice(0, -1) : [],
    registrableDomain,
    registrableLabel: registrableDomain.split('.')[0] ?? '',
    tld,
    isIp: isIpHost(asciiHost),
    isPrivateIp: isIpHost(asciiHost) ? isPrivateIp(asciiHost) : false,
    port,
    isDefaultPort: port === null,
    hasCredentials: credentials,
    hasUsername: url.username !== '',
    pathname: url.pathname,
    pathSegments,
    pathDepth: pathSegments.length,
    search: url.search,
    fragment: url.hash,
    params,
    paramCount: params.length,
    sensitiveParams,
    trackingParams,
    redirectParams,
    hasTracking: trackingParams.length > 0,
    hasRedirectParam: redirectParams.length > 0,
    unusualChars,
    unusualHostChars: unusualChars.filter((c) => c.zone === ZONES.HOST),
    controlChars,
    invisibleEncoded,
    encodedUnicode,
    encodedInHost,
    rawEncodedHost,
    keywordMatches,
    keywordZones: [...new Set(keywordMatches.map((k) => k.zone))].sort(),
    hasSensitiveKeyword: keywordMatches.length > 0,
    hasKeywordInHost: keywordMatches.some((k) => k.zone === ZONES.HOST),
    hasKeywordInPath: keywordMatches.some((k) => k.zone === ZONES.PATH),
    percentEncodedCount: percentMatches.length,
    hasDoubleEncoding: doubleEncoded,
    hasPunycode: labels.some((l) => isPunycodeLabel(l)),
    punycodeLabels: labels.filter((l) => isPunycodeLabel(l)),
    hasUnicodeHost: /[^\x00-\x7F]/.test(unicodeHost),
    scripts: [...scriptSet].sort(),
    hrefLength: href.length,
    longestLabel,
    hyphenCount,
    digitCount,
    trailingDot: url.hostname.endsWith('.'),
    isRiskyTld: RISKY_TLDS.includes(tld),
    isUrlShortener: URL_SHORTENERS.includes(registrableDomain) || URL_SHORTENERS.includes(asciiHost),
    isDangerousScheme: DANGEROUS_SCHEMES.includes(url.protocol.replace(/:$/, '').toLowerCase()),
    isSoftSuspiciousScheme: SOFT_SUSPICIOUS_SCHEMES.includes(url.protocol.replace(/:$/, '').toLowerCase()),
    isHttp: url.protocol === 'http:',
    isHttps: url.protocol === 'https:',
    hasSearch: url.search !== '',
    hasFragment: url.hash !== '',
  };
}

/**
 * Punct de intrare: normalizează și analizează o intrare brută.
 * @param {string} input
 * @param {{ defaultScheme?: string }} [options]
 * @returns {{ ok: true, facts: object } | { ok: false, error: string }}
 */
export function analyzeUrlInput(input, options = {}) {
  const normalized = normalizeUrlInput(input, options);
  if (!normalized.ok) return { ok: false, error: normalized.error };
  return { ok: true, facts: analyzeParsedUrl(normalized.url, typeof input === 'string' ? input : '') };
}

/**
 * Rezumat scurt, sigur pentru afișare sau jurnal (fără parametri sensibili).
 * @param {object} facts
 * @param {{ stripQuery?: boolean }} [options]
 * @returns {string}
 */
export function describeUrlForLog(facts, options = {}) {
  if (!facts) return '';
  const base = `${facts.scheme}://${facts.asciiHost}${facts.port ? `:${facts.port}` : ''}${facts.pathname}`;
  if (options.stripQuery || facts.search === '') return base;
  const safeKeys = facts.params.filter((p) => !p.isSensitive).map((p) => p.key).slice(0, 5);
  return `${base}?${safeKeys.map((k) => `${k}=${'<valoare>'}`).join('&')}`;
}

export { truncate };
