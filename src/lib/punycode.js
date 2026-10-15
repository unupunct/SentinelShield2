// Decodor Punycode (RFC 3492) — fără dependențe. Folosit pentru afișarea formei Unicode a unui domeniu IDN.
const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta, numPoints, first) {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > (((BASE - T_MIN) * T_MAX) >> 1)) {
    delta = Math.floor(delta / (BASE - T_MIN));
    k += BASE;
  }
  return Math.floor(k + ((BASE - T_MIN + 1) * delta) / (delta + SKEW));
}

function digitValue(cp) {
  if (cp >= 48 && cp <= 57) return cp - 22; // 0-9 -> 26..35
  if (cp >= 65 && cp <= 90) return cp - 65;
  if (cp >= 97 && cp <= 122) return cp - 97;
  return BASE;
}

/** Decodează o etichetă Punycode (fără prefixul "xn--"). Aruncă RangeError dacă e invalidă. */
export function decodePunycode(input) {
  const output = [];
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) throw new RangeError('punycode: caracter non-ASCII în partea de bază');
    output.push(c);
  }
  let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new RangeError('punycode: intrare incompletă');
      const digit = digitValue(input.charCodeAt(index++));
      if (digit >= BASE) throw new RangeError('punycode: cifră invalidă');
      i += digit * w;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    if (n > 0x10ffff) throw new RangeError('punycode: punct de cod invalid');
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Convertește un hostname ASCII (cu etichete xn--) în forma Unicode. `ok=false` dacă o etichetă xn-- e invalidă. */
export function hostToUnicode(host) {
  let ok = true;
  const labels = host.split('.').map((label) => {
    if (label.toLowerCase().startsWith('xn--')) {
      try { return decodePunycode(label.slice(4)); } catch { ok = false; return label; }
    }
    return label;
  });
  return { unicode: labels.join('.'), ok };
}
