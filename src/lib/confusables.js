// Detectarea caracterelor confuzabile (atacuri homograf). Subset documentat al tabelei Unicode confusables,
// concentrat pe literele latine imitate de chirilice/grecești/armenești uzuale în phishing.

/** caracter non-latin -> echivalentul ASCII cu aspect similar */
export const CONFUSABLE_MAP = new Map(Object.entries({
  // Chirilic
  'а': 'a', 'в': 'b', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'һ': 'h', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k', 'ӏ': 'l',
  'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'ԛ': 'q', 'г': 'r', 'ѕ': 's', 'т': 't', 'ү': 'y', 'у': 'y', 'х': 'x',
  'ѡ': 'w', 'ԝ': 'w', 'ɡ': 'g', 'ɩ': 'i', 'ӓ': 'a', 'ё': 'e', 'ӧ': 'o',
  // Grecesc
  'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
  'χ': 'x', 'ω': 'w', 'ϲ': 'c', 'ϳ': 'j',
  // Armean / alte
  'օ': 'o', 'ս': 'u', 'ց': 'g', 'ո': 'n', 'զ': 'q', 'հ': 'h',
  // Latin extins cu aspect de alte litere
  'ı': 'i', 'ɑ': 'a', 'ƅ': 'b', 'ɗ': 'd', 'ƒ': 'f', 'ɦ': 'h', 'ƙ': 'k', 'ɱ': 'm', 'ɴ': 'n', 'ʀ': 'r', 'ʏ': 'y',
  'ℓ': 'l', 'ǀ': 'l', '０': '0', 'ο': 'o'
}));

const SCRIPT_TESTS = [
  ['Latin', /\p{Script=Latin}/u], ['Cyrillic', /\p{Script=Cyrillic}/u], ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u], ['Hebrew', /\p{Script=Hebrew}/u], ['Arabic', /\p{Script=Arabic}/u],
  ['Han', /\p{Script=Han}/u], ['Hiragana', /\p{Script=Hiragana}/u], ['Katakana', /\p{Script=Katakana}/u],
  ['Hangul', /\p{Script=Hangul}/u], ['Thai', /\p{Script=Thai}/u], ['Devanagari', /\p{Script=Devanagari}/u]
];

/** Scripturile prezente într-o etichetă (cifrele și cratima sunt „Common" și se ignoră). */
export function scriptsOf(label) {
  const found = new Set();
  for (const ch of label) {
    for (const [name, re] of SCRIPT_TESTS) {
      if (re.test(ch)) { found.add(name); break; }
    }
  }
  return [...found];
}

/** Caracterele dintr-o etichetă care sunt confuzabile cu litere ASCII (doar non-latine). */
export function confusableChars(label) {
  const out = [];
  for (const ch of label.normalize('NFC')) {
    if (CONFUSABLE_MAP.has(ch)) out.push({ ch, looksLike: CONFUSABLE_MAP.get(ch), codePoint: 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0') });
  }
  return out;
}

/**
 * „Scheletul" unei etichete: minuscule, diacritice eliminate, confuzabile înlocuite cu ASCII.
 * Folosit DOAR pentru comparația cu branduri cunoscute, nu pentru a declara un domeniu confuzabil.
 */
export function skeleton(label) {
  let s = label.normalize('NFKC').toLowerCase().normalize('NFD').replace(/\p{M}/gu, '');
  let out = '';
  for (const ch of s) out += CONFUSABLE_MAP.get(ch) ?? ch;
  return out;
}

/** Variante „leet" (0->o, 1->l/i, rn->m, vv->w ...) pentru detectarea substituirii de caractere. */
export function leetVariants(label) {
  const base = label.toLowerCase();
  const seeds = new Set([base]);
  const swaps = [
    [/0/g, 'o'], [/3/g, 'e'], [/5/g, 's'], [/4/g, 'a'], [/\$/g, 's'], [/rn/g, 'm'], [/vv/g, 'w'], [/cl/g, 'd'], [/1/g, 'l'], [/1/g, 'i'], [/\|/g, 'l']
  ];
  const variants = new Set([base]);
  for (const [re, rep] of swaps) {
    for (const v of [...variants]) variants.add(v.replace(re, rep));
  }
  variants.delete(base);
  return [...variants];
}

/** Distanța Damerau-Levenshtein (OSA), cu oprire timpurie peste `max`. */
export function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}
