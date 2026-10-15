/**
 * SentinelShield2 - riskScorer.
 *
 * Responsabilități:
 * 1. Deduplicarea indicatorilor: mai mulți indicatori din aceeași familie nu
 *    se însumează (ar dubla aceeași observație), se păstrează ponderea maximă.
 * 2. Calculul scorului determinist și încadrarea în nivel de risc.
 * 3. Aplicarea politicii de liste (blocklist / allowlist) și a verdictului
 *    din surse de reputație.
 * 4. Construirea verdictului final, cu explicații în română.
 *
 * Regulă de aur: eticheta "Periculos confirmat" se acordă EXCLUSIV pe baza unei
 * surse de reputație configurate explicit de utilizator. Euristica nu poate
 * produce, singură, acest nivel.
 */

import {
  DETECTION_LIMITS,
  MAX_HEURISTIC_SCORE,
  NO_SIGNAL_CAVEAT,
  RISK_DESCRIPTIONS,
  RISK_LABELS,
  RISK_LEVELS,
  RISK_ORDER,
  SCORE_THRESHOLDS,
  UNCERTAINTY_NOTES,
} from '../shared/constants.js';

/** Ordinea severităților, pentru sortarea stabilă a indicatorilor. */
const SEVERITY_ORDER = Object.freeze({
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
});

/**
 * Compară două niveluri de risc.
 * @param {string} level
 * @param {string} other
 * @returns {boolean} true dacă `level` este cel puțin la fel de grav ca `other`
 */
export function isAtLeast(level, other) {
  return (RISK_ORDER[level] ?? -1) >= (RISK_ORDER[other] ?? -1);
}

/**
 * Determină nivelul de risc pentru un scor euristic.
 * @param {number} score
 * @returns {string}
 */
export function levelForScore(score) {
  const safeScore = Number.isFinite(score) ? score : 0;
  for (const threshold of SCORE_THRESHOLDS) {
    if (safeScore >= threshold.min) return threshold.level;
  }
  return RISK_LEVELS.NONE;
}

/**
 * Deduplică indicatorii pe familii: pentru fiecare familie se păstrează
 * indicatorul cu ponderea cea mai mare (la egalitate, id-ul mai mic, pentru
 * determinism).
 * @param {Array<object>} indicators
 * @returns {Array<object>}
 */
export function dedupeIndicators(indicators) {
  const byFamily = new Map();
  for (const indicator of indicators ?? []) {
    if (!indicator || typeof indicator.family !== 'string') continue;
    const weight = Number.isFinite(indicator.weight) ? indicator.weight : 0;
    const normalized = { ...indicator, weight };
    const current = byFamily.get(indicator.family);
    if (
      current === undefined
      || normalized.weight > current.weight
      || (normalized.weight === current.weight && normalized.ruleId < current.ruleId)
    ) {
      byFamily.set(indicator.family, normalized);
    }
  }
  return [...byFamily.values()].sort((a, b) => (
    a.weight !== b.weight
      ? b.weight - a.weight
      : (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
        || a.ruleId.localeCompare(b.ruleId)
  ));
}

/**
 * Calculează scorul euristic.
 * @param {Array<object>} indicators
 * @param {{ maxScore?: number }} [options]
 * @returns {{ score: number, level: string, indicators: Array<object>, rawSum: number, capped: boolean }}
 */
export function scoreIndicators(indicators, options = {}) {
  const maxScore = options.maxScore ?? MAX_HEURISTIC_SCORE;
  const deduped = dedupeIndicators(indicators);
  const rawSum = deduped.reduce((sum, indicator) => sum + indicator.weight, 0);
  const score = Math.min(maxScore, rawSum);
  return {
    score,
    level: levelForScore(score),
    indicators: deduped,
    rawSum,
    capped: rawSum > maxScore,
  };
}

/**
 * Aplică politica listelor locale.
 *
 * Reguli de prioritate (explicite, testate):
 * 1. Blocklist-ul are prioritate față de allowlist pentru același host.
 * 2. Blocklist-ul ridică nivelul la "risc ridicat", dar NU produce niciodată
 *    eticheta "periculos confirmat" (aceasta cere dovezi externe).
 * 3. Allowlist-ul reduce severitatea euristicii (nivel maxim "risc scăzut"),
 *    dar NU ascunde indicatorii și NU anulează un verdict confirmat.
 *
 * @param {{ score: number, level: string, indicators: Array<object> }} scored
 * @param {{ type: 'allowlist'|'blocklist', entry: object, matchedHost: string }|null} listMatch
 * @returns {{ score: number, level: string, policy: string, notes: string[] }}
 */
export function applyListPolicy(scored, listMatch) {
  const base = { score: scored.score, level: scored.level, policy: 'none', notes: [] };
  if (!listMatch || !listMatch.type) return base;

  if (listMatch.type === 'blocklist') {
    const score = Math.max(scored.score, 60);
    return {
      score,
      level: isAtLeast(scored.level, RISK_LEVELS.HIGH) ? scored.level : RISK_LEVELS.HIGH,
      policy: 'blocklist',
      notes: [UNCERTAINTY_NOTES.blocklisted],
    };
  }

  // Allowlist
  const score = Math.round(scored.score * 0.3);
  const reduced = levelForScore(score);
  return {
    score,
    level: RISK_ORDER[reduced] > RISK_ORDER[RISK_LEVELS.LOW] ? RISK_LEVELS.LOW : reduced,
    policy: 'allowlist',
    notes: [UNCERTAINTY_NOTES.allowlisted],
  };
}

/**
 * Aplică verdictul din sursa de reputație.
 * @param {{ score: number, level: string }} scored
 * @param {{ status?: string, verdict?: string, source?: string, confirmed?: boolean, error?: string }|null} reputation
 * @returns {{ score: number, level: string, applied: boolean, notes: string[] }}
 */
export function applyReputation(scored, reputation) {
  if (!reputation || reputation.error || !reputation.verdict || reputation.verdict === 'unknown') {
    return { score: scored.score, level: scored.level, applied: false, notes: [] };
  }

  if (reputation.verdict === 'malicious' && reputation.confirmed === true) {
    return {
      score: Math.max(scored.score, 100),
      level: RISK_LEVELS.CONFIRMED_DANGEROUS,
      applied: true,
      notes: [UNCERTAINTY_NOTES.confirmed],
    };
  }

  if (reputation.verdict === 'suspicious') {
    const level = isAtLeast(scored.level, RISK_LEVELS.MODERATE) ? scored.level : RISK_LEVELS.MODERATE;
    return {
      score: Math.max(scored.score, 40),
      level,
      applied: true,
      notes: ['O sursă de reputație configurație de tine a raportat acest domeniu ca suspect.'],
    };
  }

  if (reputation.verdict === 'clean') {
    return { score: scored.score, level: scored.level, applied: true, notes: [] };
  }

  return { score: scored.score, level: scored.level, applied: false, notes: [] };
}

/**
 * Construiește rezumatul în limbaj simplu.
 * @param {string} level
 * @param {Array<object>} indicators
 * @returns {string}
 */
export function buildSummary(level, indicators) {
  if (level === RISK_LEVELS.NONE) {
    return 'Nu am identificat indicii cunoscute de risc pentru această adresă. Vezi precizarea despre limitele analizei.';
  }
  if (level === RISK_LEVELS.CONFIRMED_DANGEROUS) {
    return 'Adresa este raportată ca malițioasă de sursa de reputație pe care ai configurat-o.';
  }
  const titles = indicators.filter((i) => i.weight > 0).map((i) => i.title.toLowerCase());
  if (titles.length === 0) {
    return 'Există observații fără impact asupra scorului. Vezi detaliile.';
  }
  if (titles.length === 1) {
    return `Am identificat un indicator: ${titles[0]}.`;
  }
  const prefix = titles.slice(0, 2);
  const rest = titles.length - prefix.length;
  const tail = rest > 0 ? ` și încă ${rest}` : '';
  return `Am identificat ${titles.length} indicatori, printre care: ${prefix.join(', ')}${tail}.`;
}

/**
 * Construiește recomandarea principală.
 * @param {string} level
 * @param {Array<object>} indicators
 * @returns {string}
 */
export function buildRecommendation(level, indicators) {
  const fromIndicators = indicators
    .filter((i) => i.weight > 0 && i.recommendation)
    .slice(0, 2)
    .map((i) => i.recommendation);
  const generic = {
    [RISK_LEVELS.NONE]: 'Poți continua, dar rămâi atent la ceea ce ți se cere: nicio analiză nu poate garanta siguranța unui site.',
    [RISK_LEVELS.LOW]: 'Continuă cu atenție și verifică domeniul înainte de a introduce date personale.',
    [RISK_LEVELS.MODERATE]: 'Verifică adresa oficială a serviciului înainte de a introduce orice date.',
    [RISK_LEVELS.HIGH]: 'Nu introduce date personale sau bancare. Închide pagina și accesează site-ul scriind adresa oficială.',
    [RISK_LEVELS.CONFIRMED_DANGEROUS]: 'Nu continua. Raportează mesajul care conținea acest link.',
  };
  const parts = [...new Set([...fromIndicators, generic[level] ?? generic[RISK_LEVELS.LOW]])];
  return parts.join(' ');
}

/**
 * Construiește verdictul final.
 * @param {object} input
 * @returns {object}
 */
export function buildVerdict(input) {
  const {
    facts,
    domain,
    indicators = [],
    listMatch = null,
    reputation = null,
    settings = null,
    analyzedAt = new Date().toISOString(),
  } = input ?? {};

  const scored = scoreIndicators(indicators);
  const listPolicy = applyListPolicy(scored, listMatch);
  const reputationApplied = applyReputation(
    { score: listPolicy.score, level: listPolicy.level },
    reputation,
  );

  const level = reputationApplied.level;
  const score = reputationApplied.score;
  // Indicatorii atenuati (aceeasi caracteristica, forma mai slaba) raman
  // vizibili pentru transparenta, dar nu contribuie la scor.
  const visibleIndicators = scored.indicators.filter(
    (i) => i.weight > 0 || i.severity === 'info' || i.suppressed === true,
  );
  const suppressedCount = scored.indicators.filter((i) => i.suppressed === true).length;

  const notes = [UNCERTAINTY_NOTES.heuristic, ...listPolicy.notes, ...reputationApplied.notes];
  if (!reputation) {
    notes.push(UNCERTAINTY_NOTES.noReputation);
  } else if (reputation.error) {
    notes.push(`Verificarea reputației nu a reușit: ${reputation.error}`);
  } else if (reputationApplied.applied === false) {
    if (reputation.verdict === 'malicious') {
      notes.push('Sursa de reputație a raportat un rezultat malițios, dar confirmarea ("confirmMalicious") nu este activată în setări, deci nivelul nu a fost ridicat automat.');
    } else if (reputation.verdict === 'unknown') {
      notes.push('Sursa de reputație nu a oferit un verdict clar pentru acest domeniu.');
    } else {
      notes.push(UNCERTAINTY_NOTES.noReputation);
    }
  }
  if (listPolicy.policy === 'allowlist' && level !== RISK_LEVELS.CONFIRMED_DANGEROUS) {
    notes.push('Pe lista de încredere, severitatea euristicii a fost redusă; indicatorii rămân vizibili mai jos.');
  }

  return {
    url: facts?.href ?? '',
    asciiHost: facts?.asciiHost ?? '',
    unicodeHost: facts?.unicodeHost ?? '',
    registrableDomain: facts?.registrableDomain ?? '',
    scheme: facts?.scheme ?? '',
    port: facts?.port ?? null,
    isIp: Boolean(facts?.isIp),
    riskLevel: level,
    riskLabel: RISK_LABELS[level] ?? String(level),
    riskDescription: RISK_DESCRIPTIONS[level] ?? '',
    caveat: level === RISK_LEVELS.NONE ? NO_SIGNAL_CAVEAT : UNCERTAINTY_NOTES.heuristic,
    score,
    rawScore: scored.rawSum,
    scoreCapped: scored.capped,
    indicators: visibleIndicators,
    dedupedCount: scored.indicators.length,
    detectedCount: indicators.length,
    suppressedCount,
    summary: buildSummary(level, visibleIndicators),
    recommendation: buildRecommendation(level, visibleIndicators),
    uncertainty: [...new Set(notes)],
    lists: {
      blocklisted: listMatch?.type === 'blocklist',
      allowlisted: listMatch?.type === 'allowlist',
      matchedHost: listMatch?.matchedHost ?? '',
      entrySource: listMatch?.entry?.source ?? '',
      includeSubdomains: Boolean(listMatch?.entry?.includeSubdomains),
    },
    reputation: reputation
      ? {
        provider: reputation.provider ?? '',
        verdict: reputation.verdict ?? 'unknown',
        confidence: reputation.confidence ?? null,
        checked: Boolean(reputation.checked),
        error: reputation.error ? String(reputation.error) : '',
        dataSent: reputation.dataSent ?? '',
      }
      : null,
    domain,
    facts,
    settingsUsed: settings ? { warningLevel: settings.warningLevel, navigationCheckEnabled: settings.navigationCheckEnabled } : null,
    analyzedAt,
    limits: [...DETECTION_LIMITS],
  };
}

/**
 * Decide dacă verdictul trebuie să declanșeze o pagină de avertizare.
 * @param {string} level
 * @param {string} warningLevel pragul minim configurat de utilizator
 * @returns {boolean}
 */
export function shouldWarn(level, warningLevel) {
  if (level === RISK_LEVELS.NONE) return false;
  return isAtLeast(level, warningLevel ?? RISK_LEVELS.MODERATE);
}
