// Motor de evaluare a riscului: transparent, configurabil, testabil.
// Principii: (1) scorul euristic e separat de verdictul surselor de reputație; (2) o identificare confirmată
// NU poate fi anulată de un scor euristic mic; (3) „verificarea a eșuat” e diferit de „nu s-a găsit amenințare”.
import { DEFAULT_CONFIG } from './config.js';
import { Severity, Classification } from './url-analyzer.js';

export const Level = Object.freeze({ SAFE: 'SAFE', SUSPICIOUS: 'SUSPICIOUS', DANGEROUS: 'DANGEROUS', UNKNOWN: 'UNKNOWN' });

export const LEVEL_LABELS_RO = Object.freeze({
  SAFE: 'Risc redus', SUSPICIOUS: 'Suspect', DANGEROUS: 'Periculos', UNKNOWN: 'Neverificat'
});

export const SOURCE_STATUS_RO = Object.freeze({
  malicious: 'Amenințare găsită',
  clean: 'Nu a fost găsită o amenințare',
  unchecked: 'Neverificat',
  error: 'Nu a putut fi verificat (eroare)',
  timeout: 'Nu a putut fi verificat (timeout)',
  unavailable: 'Nu a putut fi verificat (indisponibil)',
  'rate-limited': 'Nu a putut fi verificat (limită de cereri)',
  disabled: 'Dezactivat',
  skipped: 'Omis (URL intern sau cu date sensibile)',
  'needs-consent': 'Necesită consimțământ'
});

const FAILED = new Set(['error', 'timeout', 'unavailable', 'rate-limited']);
const SEV_ORDER = { high: 3, medium: 2, low: 1, info: 0 };

export function indicatorWeight(indicator, cfg = DEFAULT_CONFIG) {
  const o = cfg.scoring.overrides?.[indicator.code];
  return Number.isFinite(o) ? o : cfg.scoring.weights[indicator.severity] ?? 0;
}

export function computeScore(indicators, cfg = DEFAULT_CONFIG) {
  const seen = new Set();
  let score = 0;
  for (const i of indicators) {
    if (seen.has(i.code)) continue;
    seen.add(i.code);
    score += indicatorWeight(i, cfg);
  }
  return Math.min(100, score);
}

function sortIndicators(list) {
  return [...list].sort((a, b) => (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]) || a.code.localeCompare(b.code));
}

function reputationIndicators(sources) {
  return sources.filter((s) => s.status === 'malicious').map((s) => ({
    code: 'reputation-malicious', category: 'reputation', severity: Severity.HIGH, classification: Classification.CONFIRMED,
    title: `Raportat ca periculos de: ${s.name}`,
    explain: `Sursa „${s.name}” a identificat acest ${s.matchedKind === 'url' ? 'URL' : 'domeniu'} ca fiind asociat cu ${threatLabel(s.threatType)}. Aceasta este o identificare din sursă externă/listă, nu o presupunere euristică.`,
    technical: { source: s.source, threatType: s.threatType ?? null, matched: s.matchedDomain ?? null, checkedAt: s.checkedAt ?? null }
  }));
}

function threatLabel(t) {
  const m = { MALWARE: 'distribuirea de malware', SOCIAL_ENGINEERING: 'phishing / inginerie socială', UNWANTED_SOFTWARE: 'software nedorit', phishing: 'phishing', malware: 'distribuirea de malware', malware_download: 'distribuirea de malware', test: 'o intrare de test' };
  return m[t] ?? 'activitate malițioasă';
}

const IMPERSONATION = /^(brand-|homograph|mixed-script|at-sign)/;

function consequenceFor(level, indicators, confirmed) {
  const codes = indicators.map((i) => i.code);
  if (confirmed) return 'Dacă introduci date sau descarci fișiere de pe acest site, acestea ar putea ajunge la operatori răuvoitori sau ți-ar putea infecta dispozitivul.';
  if (codes.some((c) => IMPERSONATION.test(c))) return 'Dacă introduci parola sau alte date aici, acestea ar putea ajunge la operatorul site-ului, nu la serviciul pe care crezi că îl accesezi.';
  if (level === Level.DANGEROUS) return 'Este recomandat să nu introduci date personale și să nu descarci fișiere de pe această pagină.';
  if (level === Level.SUSPICIOUS) return 'Nu înseamnă că site-ul este malițios, dar merită prudență înainte de a introduce date.';
  return '';
}

export function recommendationFor(level, confirmed, bypass = null) {
  if (level === Level.DANGEROUS) return confirmed
    ? 'Închide pagina. Nu introduce date și nu descarca fișiere. Dacă ai deja date introduse aici, schimbă parola serviciului afectat.'
    : 'Se recomandă să nu continui. Verifică adresa oficială a serviciului și accesează-l direct, din favorite sau scriind adresa tu.';
  if (level === Level.SUSPICIOUS) return 'Verifică adresa din bara browserului și nu introduce parole sau date bancare dacă nu ești sigur de site.';
  if (level === Level.UNKNOWN) return 'Verificarea nu a putut fi finalizată. Protecțiile locale au rulat, dar procedează cu prudență.';
  void bypass;
  return 'Nu au fost identificați indicatori semnificativi. Aceasta nu garantează că site-ul este sigur.';
}

/**
 * @param {{analysis:object, reputation?:object[], config?:object, exception?:object|null, now?:number}} input
 */
export function evaluate({ analysis, reputation = [], config = DEFAULT_CONFIG, exception = null, now = Date.now() }) {
  const cfg = config;
  const sources = reputation.map((s) => ({ ...s, statusLabel: SOURCE_STATUS_RO[s.status] ?? s.status }));
  const base = { checkedAt: now, sources, thresholds: cfg.scoring.thresholds, exception: null };

  if (!analysis || !analysis.ok) {
    return { ...base, level: Level.UNKNOWN, confirmed: false, score: 0, indicators: [], warn: false, reason: 'invalid-url',
      summary: 'Adresa nu a putut fi interpretată.', userExplanation: 'Adresa nu are un format valid, deci nu poate fi evaluată.', recommendation: recommendationFor(Level.UNKNOWN, false), bypass: null };
  }
  if (analysis.skipped === 'internal') {
    return { ...base, level: Level.UNKNOWN, confirmed: false, score: 0, indicators: [], warn: false, reason: 'internal-page',
      summary: 'Pagină internă a browserului, neanalizată.', userExplanation: 'Aceasta este o pagină internă a browserului sau a unei extensii. Sentinel Shield nu o analizează.', recommendation: '', bypass: null };
  }

  const confirmedSources = sources.filter((s) => s.status === 'malicious');
  const indicators = sortIndicators([...(analysis.indicators ?? []), ...reputationIndicators(sources)]);
  const score = computeScore(indicators, cfg);
  const confirmed = confirmedSources.length > 0;
  const incomplete = sources.some((s) => FAILED.has(s.status));
  const t = cfg.scoring.thresholds;
  const hasStrong = indicators.some((i) => i.severity === Severity.HIGH);

  let level;
  if (confirmed) level = Level.DANGEROUS;
  else if (score >= t.dangerous && hasStrong) level = Level.DANGEROUS;
  else if (score >= t.suspicious) level = Level.SUSPICIOUS;
  else if (incomplete) level = Level.UNKNOWN;
  else level = Level.SAFE;

  // Excepții utilizator: o excepție „euristică” nu poate anula o amenințare confirmată.
  let suppressed = false;
  let appliedException = null;
  if (exception) {
    if (confirmed && exception.kind === 'confirmed') { suppressed = true; appliedException = exception; }
    else if (!confirmed) { suppressed = true; appliedException = exception; }
  }

  const bypass = level === Level.DANGEROUS
    ? (confirmed
      ? { allowed: cfg.policy.confirmedBypass !== 'never', mode: 'typed', delayMs: 8000 }
      : { allowed: cfg.policy.heuristicBypass !== 'never', mode: 'hold', delayMs: 3000 })
    : level === Level.SUSPICIOUS ? { allowed: true, mode: 'hold', delayMs: 1500 } : null;
  const warn = cfg.protection.enabled && !suppressed &&
    ((level === Level.DANGEROUS && cfg.protection.warnOnDangerous) || (level === Level.SUSPICIOUS && cfg.protection.warnOnSuspicious));

  const top = indicators.filter((i) => i.severity !== Severity.INFO).slice(0, 3);
  const summary = confirmed
    ? `Amenințare confirmată de ${confirmedSources.map((s) => s.name).join(', ')}.`
    : level === Level.DANGEROUS ? `Risc ridicat: ${top.length} indicator(i) puternic(i), fără confirmare dintr-o sursă de reputație.`
      : level === Level.SUSPICIOUS ? `${indicators.filter((i) => i.severity !== Severity.INFO).length} indicator(i) necesită atenție.`
        : level === Level.UNKNOWN ? 'Verificarea online nu a putut fi finalizată; nu există concluzie.'
          : 'Nu au fost identificați indicatori semnificativi.';
  const userExplanation = [top.map((i) => i.explain).join(' '), consequenceFor(level, indicators, confirmed)].filter(Boolean).join(' ')
    || (level === Level.SAFE ? 'Nu au fost identificați indicatori semnificativi în adresă. Verificările automate nu pot garanta siguranța absolută a unui site.' : '');

  return {
    ...base, level, confirmed, score, indicators, incomplete, warn, exception: appliedException, bypass,
    reason: 'evaluated', summary, userExplanation, recommendation: recommendationFor(level, confirmed, bypass),
    kind: confirmed ? 'confirmed' : level === Level.DANGEROUS ? 'heuristic-high' : null
  };
}

/** Combină verdictul URL cu constatările comportamentale (pagina curentă). Comportamentul singur NU produce „confirmat”. */
export function combinePage(urlResult, behavior, config = DEFAULT_CONFIG) {
  if (!urlResult || urlResult.reason !== 'evaluated') return { ...urlResult, behavior: behavior ?? null };
  if (!behavior) return { ...urlResult, behavior: null };
  const t = config.scoring.thresholds;
  const confirmedThird = behavior.findings.some((f) => f.classification === Classification.CONFIRMED);
  const bScore = Math.min(behavior.score, 45);
  const score = Math.min(100, urlResult.score + bScore);
  let level = urlResult.level;
  let confirmed = urlResult.confirmed;
  if (confirmedThird) { level = Level.DANGEROUS; confirmed = true; }
  else if (level === Level.SAFE || level === Level.UNKNOWN) { if (score >= t.suspicious) level = Level.SUSPICIOUS; }
  else if (level === Level.SUSPICIOUS && score >= t.dangerous && urlResult.indicators.some((i) => i.severity === Severity.HIGH)) level = Level.DANGEROUS;
  // Textele paginii reflectă și constatările comportamentale (altfel „Suspect" ar fi însoțit de „nu s-au găsit indicatori")
  const top = behavior.findings.filter((f) => f.score >= 15 || f.classification === Classification.CONFIRMED).slice(0, 2);
  let { summary, userExplanation, recommendation } = urlResult;
  if (top.length) {
    const urlPart = urlResult.indicators.some((i) => i.severity !== Severity.INFO) ? urlResult.userExplanation : '';
    userExplanation = [urlPart, ...top.map((f) => f.explainUser)].filter(Boolean).join(' ');
    summary = `${behavior.findings.filter((f) => f.score >= 15).length} constatare/constatări comportamentale necesită atenție${urlResult.level !== Level.SAFE ? ', în plus față de indicatorii adresei' : ''}.`;
    recommendation = recommendationFor(level, confirmed);
  }
  return { ...urlResult, level, confirmed, score, behaviorScore: bScore, behavior, summary, userExplanation, recommendation };
}

/** Indicatori pentru un lanț de redirecționări. `evalHop(url)` -> `{level, confirmed}`. */
export function redirectChainIndicators(hops, evalHop) {
  const out = [];
  if (!Array.isArray(hops) || hops.length < 2) return out;
  for (let i = 1; i < hops.length; i++) {
    const r = evalHop(hops[i].url);
    if (r && r.level === Level.DANGEROUS) {
      out.push({
        code: 'redirect-to-flagged', category: 'redirect', severity: Severity.HIGH,
        classification: r.confirmed ? Classification.CONFIRMED : Classification.SUSPICIOUS,
        title: 'Redirecționare către o destinație periculoasă',
        explain: `Navigarea a fost redirecționată (${hops[i].kind ?? 'redirecționare'}) către o adresă evaluată ca periculoasă${r.confirmed ? ' de o sursă de reputație' : ''}.`,
        technical: { from: hops[i - 1].url, to: hops[i].url, hop: i }
      });
      break;
    }
  }
  const hosts = new Set(hops.map((h) => { try { return new URL(h.url).hostname; } catch { return h.url; } }));
  if (hops.length >= 4) out.push({ code: 'long-redirect-chain', category: 'redirect', severity: Severity.LOW, classification: Classification.POTENTIAL, title: 'Lanț lung de redirecționări', explain: `Pagina a trecut prin ${hops.length} adrese înainte de destinația finală (${hosts.size} gazde distincte). Este uneori normal (autentificare, reclame), dar este și o tehnică de ascundere.`, technical: { hops: hops.length, hosts: hosts.size } });
  return out;
}
