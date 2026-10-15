/**
 * SentinelShield2 - IDN / Punycode helpers (fără API Chrome, fără dependențe).
 *
 * De ce este nevoie de acest modul:
 * `new URL('https://münchen.de/').hostname` returnează forma ASCII/Punycode
 * (`xn--mnchen-3ya.de`). Pentru a explica utilizatorului CE arată de fapt
 * domeniul (și pentru a detecta caractere amestecate), avem nevoie de forma
 * Unicode. Browserul nu expune un API stabil pentru decodare, deci implementăm
 * aici decodorul Punycode (RFC 3492), care este determinist și testabil.
 */

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_INT = 2147483647;
const DELIMITER = '-';
const PUNYCODE_PREFIX = 'xn--';

/** Eroare aruncată pentru intrări Punycode invalide. */
export class PunycodeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PunycodeError';
  }
}

/**
 * Adaptează bias-ul conform RFC 3492 (secțiunea 6.1).
 * @param {number} delta
 * @param {number} numPoints
 * @param {boolean} firstTime
 * @returns {number}
 */
function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

/**
 * Convertește un punct de cod în cifra Punycode corespunzătoare.
 * @param {number} codePoint
 * @returns {number}
 */
function basicToDigit(codePoint) {
  if (codePoint - 48 < 10) return codePoint - 22; // '0'-'9' -> 26..35
  if (codePoint - 65 < 26) return codePoint - 65; // 'A'-'Z' -> 0..25
  if (codePoint - 97 < 26) return codePoint - 97; // 'a'-'z' -> 0..25
  return BASE;
}

/**
 * Decodează o etichetă Punycode (cu sau fără prefixul `xn--`).
 * @param {string} input
 * @returns {string} eticheta în Unicode
 */
export function decodePunycode(input) {
  if (typeof input !== 'string') throw new PunycodeError('Intrare ne-string');
  const source = input.toLowerCase().startsWith(PUNYCODE_PREFIX)
    ? input.slice(PUNYCODE_PREFIX.length)
    : input;

  const output = [];
  const inputLength = source.length;
  let i = 0;
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;

  let basic = source.lastIndexOf(DELIMITER);
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j += 1) {
    if (source.charCodeAt(j) >= 0x80) throw new PunycodeError('Caracter non-ASCII în partea basică');
    output.push(source.charCodeAt(j));
  }

  for (let index = basic > 0 ? basic + 1 : 0; index < inputLength; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= inputLength) throw new PunycodeError('Intrare Punycode incompletă');
      const digit = basicToDigit(source.charCodeAt(index));
      index += 1;
      if (digit >= BASE) throw new PunycodeError('Cifră Punycode invalidă');
      if (digit > Math.floor((MAX_INT - i) / w)) throw new PunycodeError('Depășire numerică');
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) throw new PunycodeError('Depășire numerică');
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    if (Math.floor(i / out) > MAX_INT - n) throw new PunycodeError('Depășire numerică');
    n += Math.floor(i / out);
    i %= out;
    output.splice(i, 0, n);
    i += 1;
  }

  return String.fromCodePoint(...output);
}

/**
 * Indică dacă o etichetă de domeniu folosește forma Punycode.
 * @param {string} label
 * @returns {boolean}
 */
export function isPunycodeLabel(label) {
  return typeof label === 'string' && label.toLowerCase().startsWith(PUNYCODE_PREFIX);
}

/**
 * Convertește un host ASCII (posibil cu etichete `xn--`) în forma Unicode.
 * Etichetele care nu pot fi decodate sunt păstrate ca atare.
 * @param {string} asciiHost
 * @returns {{ unicodeHost: string, decodedLabels: string[], failedLabels: string[] }}
 */
export function toUnicodeHost(asciiHost) {
  const labels = String(asciiHost ?? '').split('.');
  const decodedLabels = [];
  const failedLabels = [];
  const out = labels.map((label) => {
    if (!isPunycodeLabel(label)) return label;
    try {
      const decoded = decodePunycode(label);
      decodedLabels.push(decoded);
      return decoded;
    } catch {
      failedLabels.push(label);
      return label;
    }
  });
  return { unicodeHost: out.join('.'), decodedLabels, failedLabels };
}

/**
 * Determină scriptul dominant al unui caracter (aproximare suficientă pentru
 * detecția de caractere amestecate).
 * @param {string} ch
 * @returns {'latin'|'cyrillic'|'greek'|'arabic'|'hebrew'|'cjk'|'other'|'ascii'}
 */
export function detectScript(ch) {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return 'other';
  if (cp < 0x80) return 'ascii';
  if (cp >= 0x0400 && cp <= 0x04ff) return 'cyrillic';
  if (cp >= 0x0500 && cp <= 0x052f) return 'cyrillic';
  if (cp >= 0x0370 && cp <= 0x03ff) return 'greek';
  if (cp >= 0x0600 && cp <= 0x06ff) return 'arabic';
  if (cp >= 0x0590 && cp <= 0x05ff) return 'hebrew';
  if (cp >= 0x3040 && cp <= 0x30ff) return 'cjk';
  if (cp >= 0x4e00 && cp <= 0x9fff) return 'cjk';
  if (
    (cp >= 0x00c0 && cp <= 0x024f) ||
    (cp >= 0x1e00 && cp <= 0x1eff)
  ) return 'latin';
  return 'other';
}

/**
 * Returnează mulțimea de scripturi non-ASCII prezente într-un text.
 * @param {string} text
 * @returns {string[]} lista sortată a scripturilor detectate
 */
export function collectScripts(text) {
  const scripts = new Set();
  for (const ch of String(text ?? '')) {
    const script = detectScript(ch);
    if (script !== 'ascii') scripts.add(script);
  }
  return [...scripts].sort();
}
