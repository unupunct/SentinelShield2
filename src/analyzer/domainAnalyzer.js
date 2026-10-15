/**
 * SentinelShield2 - domainAnalyzer.
 *
 * Rol: analizează numele de domeniu (nu URL-ul întreg) și produce fapte despre:
 * - imitații de brand (homoglife, substituții de cifre, typosquatting);
 * - brand folosit ca subdomeniu al unui domeniu neînrudit;
 * - etichete cu scripturi amestecate (atacuri IDN homograph);
 * - terminații frecvent abuzate (semnal slab, marcat ca euristic).
 *
 * Ca și `urlAnalyzer`, acest modul NU atribuie scoruri. Clasificarea
 * (`kind`) este consumată de `phishingRules`, care stabilește ponderea.
 */

import { BRANDS, KNOWN_LEGIT_BRAND_DOMAINS } from '../shared/constants.js';
import { collectScripts } from '../shared/idn.js';
import { levenshtein } from '../shared/validators.js';

/**
 * Caractere care arată ca litere latine. Sursa: caracterele folosite cel mai
 * des în atacurile de tip homograph (chirilice, grecești, latine unusuale).
 * Cheile sunt caractere Unicode, valorile sunt echivalentul latin.
 */
export const CONFUSABLE_MAP = Object.freeze({
  // Chirilice
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0445': 'x', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
  '\u04bb': 'h', '\u0501': 'd', '\u051b': 'q', '\u051d': 'w', '\u0475': 'v',
  '\u04cf': 'l', '\u044c': 'b', '\u044a': 'b', '\u0432': 'b', '\u043d': 'h',
  '\u043c': 'm', '\u0442': 't', '\u043a': 'k', '\u0433': 'r', '\u043f': 'n',
  '\u043b': 'n', '\u0459': 'n', '\u0438': 'u', '\u0451': 'e',
  // Grecești
  '\u03b1': 'a', '\u03b2': 'b', '\u03b5': 'e', '\u03b9': 'i', '\u03ba': 'k',
  '\u03bd': 'v', '\u03bf': 'o', '\u03c1': 'p', '\u03c4': 't', '\u03c5': 'u',
  '\u03c7': 'x', '\u03b6': 'z', '\u03b7': 'h', '\u03bc': 'm',
  // Latine neobișnuite / alte scripturi folosite ca omoglife
  '\u0261': 'g', '\u0251': 'a', '\u026a': 'i', '\u0268': 'i', '\u0280': 'r',
  '\u0274': 'n', '\u0299': 'b', '\u028f': 'y', '\u0269': 'i',
  '\u0131': 'i', '\u0142': 'l', '\u1d20': 'v', '\u1d04': 'c',
  '\u2160': 'i', '\u216c': 'l', '\u2170': 'i',
  '\u2113': 'l', '\u2110': 'i', '\u2111': 'i', '\u212e': 'e',
  // Latină extinsă folosită în IDN-uri de tip typo (nu diacritice normale)
  '\u00e5': 'a', '\u00f8': 'o', '\u00e6': 'ae', '\u00f0': 'd', '\u00f1': 'n',
  '\u00fe': 'p', '\u0167': 'l', '\u0127': 'h', '\u014b': 'n',
});

/** Substituții de cifre uzuale în typosquatting (leetspeak). */
export const DIGIT_MAP = Object.freeze({
  0: 'o',
  1: 'l',
  3: 'e',
  4: 'a',
  5: 's',
  6: 'g',
  7: 't',
  8: 'b',
  9: 'g',
});

/**
 * Înlocuiește caracterele omoglif cu echivalentul latin.
 * @param {string} input
 * @returns {{ mapped: string, replacements: number }}
 */
export function mapConfusables(input) {
  let mapped = '';
  let replacements = 0;
  for (const ch of String(input ?? '')) {
    const replacement = CONFUSABLE_MAP[ch];
    if (replacement !== undefined) {
      mapped += replacement;
      replacements += 1;
    } else {
      mapped += ch;
    }
  }
  return { mapped, replacements };
}

/**
 * Reduce o etichetă la forma ASCII "skeleton", folosită la compararea cu
 * brandurile: fără diacritice, fără omoglife, fără cifre-substituție,
 * fără cratime.
 * @param {string} label
 * @returns {string}
 */
export function toSkeleton(label) {
  const raw = String(label ?? '').toLowerCase();
  const { mapped } = mapConfusables(raw);
  const deaccented = mapped.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');
  const digitsMapped = deaccented.replace(/[013456789]/g, (d) => DIGIT_MAP[d]);
  const collapsed = digitsMapped.replace(/rn/g, 'm').replace(/vv/g, 'w');
  return collapsed.replace(/[^a-z0-9]/g, '');
}

/**
 * Distanța maximă de editare acceptată pentru un brand, în funcție de lungime.
 * Brandurile foarte scurte generează ușor fals pozitive, de aceea sunt
 * comparate doar exact (homoglif / substituție de cifre).
 * @param {string} brand
 * @returns {number} 0 = doar potrivire exactă a scheletului
 */
export function maxDistanceFor(brand) {
  if (brand.length <= 4) return 0;
  if (brand.length <= 6) return 1;
  return 2;
}

/**
 * Analizează o singură etichetă de domeniu în raport cu lista de branduri.
 * @param {string} label
 * @param {readonly string[]} brands
 * @returns {object}
 */
export function analyzeLabel(label, brands = BRANDS) {
  const raw = String(label ?? '').toLowerCase();
  const { mapped, replacements } = mapConfusables(raw);
  const skeleton = toSkeleton(raw);
  const hasUnicode = /[^\x00-\x7F]/.test(raw);
  const scripts = collectScripts(raw);
  const hasAsciiLetters = /[a-z]/.test(raw);
  const mixedScript = replacements > 0 && hasAsciiLetters;
  const hasDigits = /\d/.test(raw);

  let match = null;
  if (brands.includes(skeleton)) {
    if (replacements > 0) {
      match = { brand: skeleton, kind: 'homoglyph', distance: 0, evidence: mapped };
    } else if (hasDigits) {
      match = { brand: skeleton, kind: 'digit_substitution', distance: 0, evidence: raw };
    } else if (raw === skeleton) {
      match = { brand: skeleton, kind: 'literal', distance: 0, evidence: raw };
    } else {
      // Aceeași literă, dar cu diacritice (ex. `münchen`): nu este o imitație.
      match = { brand: skeleton, kind: 'diacritic_variant', distance: 0, evidence: raw };
    }
  } else {
    // Brand inclus în etichetă (ex. `paypal-secure`, `apple-support`).
    let embedded = null;
    for (const brand of brands) {
      if (brand.length < 4) continue;
      if (skeleton.length < brand.length + 2) continue;
      if (!skeleton.includes(brand)) continue;
      if (embedded === null || brand.length > embedded.brand.length) {
        embedded = { brand, kind: 'embedded_in_label', distance: 0, evidence: raw };
      }
    }
    if (embedded) {
      match = embedded;
    } else {
      // Typosquatting: distanță de editare mică față de un brand.
      let best = null;
      for (const brand of brands) {
        const maxDistance = maxDistanceFor(brand);
        if (maxDistance === 0) continue;
        if (Math.abs(skeleton.length - brand.length) > maxDistance) continue;
        const distance = levenshtein(skeleton, brand, maxDistance);
        if (distance === 0 || distance > maxDistance) continue;
        if (best === null || distance < best.distance) {
          best = { brand, kind: 'typosquat', distance, evidence: raw };
        }
      }
      match = best;
    }
  }

  return {
    label: raw,
    skeleton,
    hasUnicode,
    hasDigits,
    hasAsciiLetters,
    replacedChars: replacements,
    scripts,
    mixedScript,
    match,
  };
}

/**
 * Analizează domeniul complet.
 * @param {object} facts rezultatul `analyzeParsedUrl`
 * @param {{ brands?: readonly string[], legitDomains?: readonly string[] }} [options]
 * @returns {object}
 */
export function analyzeDomain(facts, options = {}) {
  const brands = options.brands ?? BRANDS;
  const legitDomains = options.legitDomains ?? KNOWN_LEGIT_BRAND_DOMAINS;
  const labels = Array.isArray(facts?.labels) ? facts.labels : [];
  const pairs = Array.isArray(facts?.labelPairs) && facts.labelPairs.length > 0
    ? facts.labelPairs
    : labels.map((label) => ({ ascii: label, unicode: label, isPunycode: false }));
  const registrableDomain = facts?.registrableDomain ?? '';
  const registrableLabel = facts?.registrableLabel ?? '';
  const isLegitBrandDomain = legitDomains.includes(registrableDomain);

  // Analiza de brand se face pe forma Unicode (decodată din Punycode): altfel
  // homoglifele ar fi invizibile pentru comparație.
  const labelAnalyses = pairs.map((pair) => ({
    ...analyzeLabel(pair.unicode, brands),
    ascii: pair.ascii,
    isPunycode: pair.isPunycode,
  }));
  const tldPair = pairs.length > 1 ? pairs[pairs.length - 1] : null;

  const matches = [];
  for (const analysis of labelAnalyses) {
    if (!analysis.match) continue;
    if (tldPair && analysis.ascii === tldPair.ascii) continue; // terminația nu este analizată ca brand
    const { brand, kind, distance, evidence } = analysis.match;
    const isRegistrableLabel = analysis.ascii === registrableLabel;
    let effectiveKind = kind;
    if (!isRegistrableLabel && (kind === 'literal' || kind === 'homoglyph' || kind === 'digit_substitution')) {
      effectiveKind = 'brand_in_subdomain';
    }
    // Domeniile oficiale cunoscute care conțin legitim un brand nu primesc indicatori.
    if (isLegitBrandDomain && effectiveKind !== 'brand_in_subdomain') continue;
    matches.push({
      brand,
      kind: effectiveKind,
      distance,
      evidence,
      label: analysis.label,
      asciiLabel: analysis.ascii,
      isPunycode: analysis.isPunycode,
      isRegistrableLabel,
      isSubdomain: !isRegistrableLabel,
      mixedScript: analysis.mixedScript,
      skeleton: analysis.skeleton,
    });
  }

  // Sortare deterministă: severitatea kind-ului, apoi lungimea brandului, apoi alfabetic.
  const kindOrder = {
    homoglyph: 0,
    brand_in_subdomain: 1,
    digit_substitution: 2,
    typosquat: 3,
    embedded_in_label: 4,
    literal: 5,
    diacritic_variant: 6,
  };
  matches.sort((a, b) => (
    kindOrder[a.kind] - kindOrder[b.kind]
    || b.brand.length - a.brand.length
    || a.brand.localeCompare(b.brand)
  ));

  const mixedScriptLabels = labelAnalyses
    .filter((analysis) => analysis.mixedScript)
    .map((analysis) => ({ label: analysis.label, scripts: analysis.scripts }));

  const informationalMatches = matches.filter(
    (m) => m.kind === 'literal' || m.kind === 'diacritic_variant',
  );
  const riskMatches = matches.filter(
    (m) => m.kind !== 'literal' && m.kind !== 'diacritic_variant',
  );

  return {
    host: facts?.asciiHost ?? '',
    unicodeHost: facts?.unicodeHost ?? '',
    registrableDomain,
    registrableLabel,
    tld: tldPair?.ascii ?? '',
    labels,
    labelAnalyses: labelAnalyses.map((a) => ({
      label: a.label,
      ascii: a.ascii,
      isPunycode: a.isPunycode,
      skeleton: a.skeleton,
      hasUnicode: a.hasUnicode,
      mixedScript: a.mixedScript,
      scripts: a.scripts,
      matchKind: a.match?.kind ?? null,
      matchBrand: a.match?.brand ?? null,
    })),
    brandMatches: matches,
    riskMatches,
    informationalMatches,
    primaryBrandMatch: riskMatches[0] ?? null,
    mixedScriptLabels,
    isLegitBrandDomain,
    subdomain: {
      count: Array.isArray(facts?.subdomainLabels) ? facts.subdomainLabels.length : 0,
      labels: facts?.subdomainLabels ?? [],
      hasBrand: matches.some((m) => m.isSubdomain),
      depth: Array.isArray(facts?.subdomainLabels) ? facts.subdomainLabels.length : 0,
    },
  };
}
