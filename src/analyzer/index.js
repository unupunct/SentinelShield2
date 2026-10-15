/**
 * SentinelShield2 - fațada de analiză.
 *
 * Acest modul este singurul punct de intrare folosit de service worker și de
 * interfață. Orchestrează:
 *   urlAnalyzer (fapte) -> domainAnalyzer (domeniu) -> phishingRules (reguli)
 *   -> riskScorer (scor, liste, reputație) -> verdict explicabil.
 *
 * Extindere documentată față de structura din cerință: un modul de compunere
 * evita duplicarea logicii în popup, service worker și paginile interne.
 */

import { DEFAULT_SETTINGS } from '../shared/constants.js';
import { findListMatch } from '../storage/storageManager.js';
import { analyzeDomain } from './domainAnalyzer.js';
import { evaluateRules } from './phishingRules.js';
import { checkReputation } from './reputationProvider.js';
import { buildVerdict } from './riskScorer.js';
import { analyzeUrlInput } from './urlAnalyzer.js';

/**
 * Analizează o intrare (URL brut sau deja normalizat) și produce verdictul.
 *
 * @param {string} input
 * @param {{
 *   settings?: object,
 *   lists?: { allowlist?: object[], blocklist?: object[] },
 *   fetchImpl?: Function,
 *   reputationResult?: object|null,
 *   analyzedAt?: string,
 *   useReputation?: boolean,
 * }} [options]
 * @returns {Promise<{ ok: true, verdict: object } | { ok: false, error: string }>}
 */
export async function analyzeTarget(input, options = {}) {
  const settings = options.settings ?? DEFAULT_SETTINGS;
  const lists = options.lists ?? { allowlist: [], blocklist: [] };

  const parsed = analyzeUrlInput(input);
  if (!parsed.ok) {
    return { ok: false, error: parsed.error };
  }

  const { facts } = parsed;
  const domain = analyzeDomain(facts);
  const indicators = evaluateRules({ facts, domain });
  const listMatch = findListMatch(facts.asciiHost, lists);

  let reputation = options.reputationResult ?? null;
  const useReputation = options.useReputation !== false;
  if (!reputation && useReputation && settings?.reputation?.enabled === true) {
    reputation = await checkReputation(facts, settings, { fetchImpl: options.fetchImpl });
  }

  const verdict = buildVerdict({
    facts,
    domain,
    indicators,
    listMatch,
    reputation,
    settings,
    analyzedAt: options.analyzedAt ?? new Date().toISOString(),
  });

  return { ok: true, verdict };
}

export { analyzeDomain } from './domainAnalyzer.js';
export { evaluateRules, RULES, RULES_BY_ID } from './phishingRules.js';
export { analyzeParsedUrl, analyzeUrlInput, describeUrlForLog } from './urlAnalyzer.js';
export {
  buildVerdict,
  scoreIndicators,
  dedupeIndicators,
  levelForScore,
  shouldWarn,
  isAtLeast,
} from './riskScorer.js';
export { checkReputation, REPUTATION_STATUS, REPUTATION_VERDICT } from './reputationProvider.js';
