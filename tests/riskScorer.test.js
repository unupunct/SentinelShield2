import { describe, expect, it } from 'vitest';

import { analyzeTarget } from '../src/analyzer/index.js';
import {
  applyListPolicy,
  applyReputation,
  buildRecommendation,
  buildSummary,
  buildVerdict,
  dedupeIndicators,
  isAtLeast,
  levelForScore,
  scoreIndicators,
  shouldWarn,
} from '../src/analyzer/riskScorer.js';
import { MAX_HEURISTIC_SCORE, RISK_LEVELS } from '../src/shared/constants.js';

/**
 * Construiește un indicator minimal pentru teste.
 * @param {Partial<object>} overrides
 * @returns {object}
 */
function indicator(overrides = {}) {
  return {
    ruleId: 'X-001',
    family: 'test.family',
    category: 'url',
    title: 'Titlu',
    severity: 'low',
    weight: 10,
    detail: '',
    evidence: {},
    why: '',
    limits: '',
    recommendation: '',
    suppressedBy: [],
    suppressed: false,
    ...overrides,
  };
}

describe('levelForScore', () => {
  it('respectă pragurile documentate', () => {
    expect(levelForScore(0)).toBe(RISK_LEVELS.NONE);
    expect(levelForScore(1)).toBe(RISK_LEVELS.LOW);
    expect(levelForScore(19)).toBe(RISK_LEVELS.LOW);
    expect(levelForScore(20)).toBe(RISK_LEVELS.MODERATE);
    expect(levelForScore(49)).toBe(RISK_LEVELS.MODERATE);
    expect(levelForScore(50)).toBe(RISK_LEVELS.HIGH);
    expect(levelForScore(100)).toBe(RISK_LEVELS.HIGH);
  });

  it('tratează valorile invalide ca zero', () => {
    expect(levelForScore(Number.NaN)).toBe(RISK_LEVELS.NONE);
    expect(levelForScore(undefined)).toBe(RISK_LEVELS.NONE);
  });
});

describe('isAtLeast', () => {
  it('compară nivelurile în ordinea corectă', () => {
    expect(isAtLeast(RISK_LEVELS.HIGH, RISK_LEVELS.MODERATE)).toBe(true);
    expect(isAtLeast(RISK_LEVELS.LOW, RISK_LEVELS.MODERATE)).toBe(false);
    expect(isAtLeast(RISK_LEVELS.CONFIRMED_DANGEROUS, RISK_LEVELS.HIGH)).toBe(true);
  });
});

describe('dedupeIndicators', () => {
  it('păstrează un singur indicator pe familie, pe cel cu ponderea maximă', () => {
    const result = dedupeIndicators([
      indicator({ ruleId: 'A-001', family: 'path.sensitive_keyword', weight: 12 }),
      indicator({ ruleId: 'A-002', family: 'path.sensitive_keyword', weight: 30 }),
      indicator({ ruleId: 'B-001', family: 'host.ip_literal', weight: 20 }),
    ]);
    expect(result).toHaveLength(2);
    expect(result[0]).toMatchObject({ ruleId: 'A-002', weight: 30 });
    expect(result[1]).toMatchObject({ ruleId: 'B-001', weight: 20 });
  });

  it('la pondere egală, alege id-ul mai mic (determinism)', () => {
    const result = dedupeIndicators([
      indicator({ ruleId: 'Z-002', family: 'x.y', weight: 10 }),
      indicator({ ruleId: 'A-001', family: 'x.y', weight: 10 }),
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].ruleId).toBe('A-001');
  });

  it('ignoră intrările invalide', () => {
    expect(dedupeIndicators([null, undefined, { weight: 5 }])).toEqual([]);
  });
});

describe('scoreIndicators', () => {
  it('însumează ponderile famililor distincte', () => {
    const scored = scoreIndicators([
      indicator({ ruleId: 'A-001', family: 'a.b', weight: 30 }),
      indicator({ ruleId: 'B-001', family: 'c.d', weight: 20 }),
      indicator({ ruleId: 'C-001', family: 'c.d', weight: 5 }),
    ]);
    expect(scored.score).toBe(50);
    expect(scored.level).toBe(RISK_LEVELS.HIGH);
    expect(scored.capped).toBe(false);
  });

  it('plafonează scorul la valoarea maximă', () => {
    const scored = scoreIndicators([
      indicator({ ruleId: 'A-001', family: 'a.b', weight: 80 }),
      indicator({ ruleId: 'B-001', family: 'c.d', weight: 40 }),
    ]);
    expect(scored.score).toBe(MAX_HEURISTIC_SCORE);
    expect(scored.rawSum).toBe(120);
    expect(scored.capped).toBe(true);
  });

  it('nu produce niciodată nivelul "periculos confirmat" din euristică', () => {
    const scored = scoreIndicators([indicator({ weight: 100 })]);
    expect(scored.level).toBe(RISK_LEVELS.HIGH);
    expect(scored.level).not.toBe(RISK_LEVELS.CONFIRMED_DANGEROUS);
  });
});

describe('applyListPolicy', () => {
  const blockEntry = { host: 'exemplu.ro', includeSubdomains: false, source: 'user' };
  const allowEntry = { host: 'exemplu.ro', includeSubdomains: true, source: 'user' };

  it('blocklist-ul ridică nivelul la risc ridicat, fără a confirma', () => {
    const result = applyListPolicy({ score: 0, level: RISK_LEVELS.NONE }, { type: 'blocklist', entry: blockEntry, matchedHost: 'exemplu.ro' });
    expect(result.level).toBe(RISK_LEVELS.HIGH);
    expect(result.score).toBe(60);
    expect(result.policy).toBe('blocklist');
    expect(result.notes.join(' ')).toMatch(/lista ta de blocare/);
  });

  it('blocklist-ul nu coboară un nivel mai grav', () => {
    const result = applyListPolicy(
      { score: 90, level: RISK_LEVELS.HIGH },
      { type: 'blocklist', entry: blockEntry, matchedHost: 'exemplu.ro' },
    );
    expect(result.level).toBe(RISK_LEVELS.HIGH);
    expect(result.score).toBe(90);
  });

  it('allowlist-ul reduce scorul și plafonează nivelul la risc scăzut', () => {
    const result = applyListPolicy(
      { score: 90, level: RISK_LEVELS.HIGH },
      { type: 'allowlist', entry: allowEntry, matchedHost: 'exemplu.ro' },
    );
    expect(result.score).toBe(27);
    expect(result.level).toBe(RISK_LEVELS.LOW);
    expect(result.policy).toBe('allowlist');
  });

  it('allowlist-ul nu ridică nivelul unui rezultat curat', () => {
    const result = applyListPolicy({ score: 0, level: RISK_LEVELS.NONE }, { type: 'allowlist', entry: allowEntry, matchedHost: 'exemplu.ro' });
    expect(result.level).toBe(RISK_LEVELS.NONE);
    expect(result.score).toBe(0);
  });

  it('fără potrivire, rezultatul rămâne neschimbat', () => {
    const result = applyListPolicy({ score: 45, level: RISK_LEVELS.MODERATE }, null);
    expect(result).toMatchObject({ score: 45, level: RISK_LEVELS.MODERATE, policy: 'none' });
  });
});

describe('applyReputation', () => {
  it('ridică la "periculos confirmat" doar cu confirmare explicită', () => {
    const confirmed = applyReputation(
      { score: 0, level: RISK_LEVELS.NONE },
      { verdict: 'malicious', confirmed: true },
    );
    expect(confirmed.level).toBe(RISK_LEVELS.CONFIRMED_DANGEROUS);
    expect(confirmed.score).toBe(100);

    const notConfirmed = applyReputation(
      { score: 0, level: RISK_LEVELS.NONE },
      { verdict: 'malicious', confirmed: false },
    );
    expect(notConfirmed.level).toBe(RISK_LEVELS.NONE);
    expect(notConfirmed.applied).toBe(false);
  });

  it('ridică nivelul la moderat pentru un rezultat suspect', () => {
    const result = applyReputation({ score: 0, level: RISK_LEVELS.NONE }, { verdict: 'suspicious' });
    expect(result.level).toBe(RISK_LEVELS.MODERATE);
  });

  it('ignoră erorile și verdictul necunoscut', () => {
    expect(applyReputation({ score: 5, level: RISK_LEVELS.LOW }, { verdict: 'malicious', error: 'timeout' }).level)
      .toBe(RISK_LEVELS.LOW);
    expect(applyReputation({ score: 5, level: RISK_LEVELS.LOW }, { verdict: 'unknown' }).applied).toBe(false);
    expect(applyReputation({ score: 5, level: RISK_LEVELS.LOW }, null).applied).toBe(false);
  });
});

describe('buildSummary / buildRecommendation', () => {
  it('rezumă nivelul fără indicii', () => {
    expect(buildSummary(RISK_LEVELS.NONE, [])).toMatch(/Nu am identificat/);
  });

  it('rezumă un singur indicator și mai mulți indicatori', () => {
    expect(buildSummary(RISK_LEVELS.LOW, [indicator({ weight: 5, title: 'Conexiune necriptată' })]))
      .toBe('Am identificat un indicator: conexiune necriptată.');
    const summary = buildSummary(RISK_LEVELS.HIGH, [
      indicator({ ruleId: 'A-001', family: 'a.b', weight: 30, title: 'Primul' }),
      indicator({ ruleId: 'B-001', family: 'c.d', weight: 20, title: 'Al doilea' }),
      indicator({ ruleId: 'C-001', family: 'e.f', weight: 10, title: 'Al treilea' }),
    ]);
    expect(summary).toBe('Am identificat 3 indicatori, printre care: primul, al doilea și încă 1.');
  });

  it('combină recomandările indicatorilor cu recomandarea generală', () => {
    const recommendation = buildRecommendation(RISK_LEVELS.HIGH, [
      indicator({ weight: 55, recommendation: 'Recomandare specifică 1.' }),
      indicator({ ruleId: 'B-001', family: 'c.d', weight: 40, recommendation: 'Recomandare specifică 2.' }),
      indicator({ ruleId: 'C-001', family: 'e.f', weight: 30, recommendation: 'Recomandare ignorată.' }),
    ]);
    expect(recommendation).toContain('Recomandare specifică 1.');
    expect(recommendation).toContain('Recomandare specifică 2.');
    expect(recommendation).not.toContain('ignorată');
    expect(recommendation).toMatch(/Nu introduce date personale/);
  });
});

describe('shouldWarn', () => {
  it('respectă pragul configurat', () => {
    expect(shouldWarn(RISK_LEVELS.NONE, RISK_LEVELS.MODERATE)).toBe(false);
    expect(shouldWarn(RISK_LEVELS.LOW, RISK_LEVELS.MODERATE)).toBe(false);
    expect(shouldWarn(RISK_LEVELS.MODERATE, RISK_LEVELS.MODERATE)).toBe(true);
    expect(shouldWarn(RISK_LEVELS.HIGH, RISK_LEVELS.MODERATE)).toBe(true);
    expect(shouldWarn(RISK_LEVELS.HIGH, RISK_LEVELS.HIGH)).toBe(true);
    expect(shouldWarn(RISK_LEVELS.MODERATE, RISK_LEVELS.HIGH)).toBe(false);
  });
});

describe('buildVerdict', () => {
  it('include limitele detecției și precizarea de incertitudine', async () => {
    const result = await analyzeTarget('http://exemplu.ro/');
    expect(result.ok).toBe(true);
    const verdict = result.verdict;
    expect(verdict.limits.length).toBeGreaterThan(3);
    expect(verdict.uncertainty.join(' ')).toMatch(/euristice/);
    expect(verdict.uncertainty.join(' ')).toMatch(/nicio sursă de reputație/);
    expect(verdict.caveat).toBeTypeOf('string');
  });

  it('aplică allowlist-ul fără a ascunde indicatorii', async () => {
    const result = await analyzeTarget('https://paypal-secure.example/account/verify', {
      lists: { allowlist: [{ host: 'paypal-secure.example', includeSubdomains: false, source: 'user' }], blocklist: [] },
    });
    const verdict = result.verdict;
    expect(verdict.riskLevel).toBe(RISK_LEVELS.LOW);
    expect(verdict.lists.allowlisted).toBe(true);
    expect(verdict.indicators.length).toBeGreaterThan(0);
    expect(verdict.uncertainty.join(' ')).toMatch(/lista ta de încredere/);
  });

  it('blocklist-ul are prioritate și forțează risc ridicat', async () => {
    const result = await analyzeTarget('https://exemplu.ro/', {
      lists: {
        allowlist: [{ host: 'exemplu.ro', includeSubdomains: true, source: 'user' }],
        blocklist: [{ host: 'exemplu.ro', includeSubdomains: false, source: 'user' }],
      },
    });
    const verdict = result.verdict;
    expect(verdict.riskLevel).toBe(RISK_LEVELS.HIGH);
    expect(verdict.lists.blocklisted).toBe(true);
    expect(verdict.lists.allowlisted).toBe(false);
  });

  it('allowlist-ul NU anulează un verdict confirmat de sursa de reputație', async () => {
    const result = await analyzeTarget('https://exemplu.ro/', {
      lists: { allowlist: [{ host: 'exemplu.ro', includeSubdomains: true, source: 'user' }], blocklist: [] },
      reputationResult: { checked: true, provider: 'custom_http', verdict: 'malicious', confirmed: true, confidence: 1 },
    });
    const verdict = result.verdict;
    expect(verdict.riskLevel).toBe(RISK_LEVELS.CONFIRMED_DANGEROUS);
    expect(verdict.score).toBe(100);
  });

  it('nu inventează verdicte când sursa de reputație lipsește', async () => {
    const result = await analyzeTarget('https://g00gle.example/');
    expect(result.verdict.riskLevel).toBe(RISK_LEVELS.HIGH);
    expect(result.verdict.reputation).toBeNull();
    expect(result.verdict.uncertainty.join(' ')).toMatch(/nu poate fi confirmat/);
  });

  it('indică atenuarea indicatorilor duplicați, fără a-i ascunde', async () => {
    const result = await analyzeTarget('https://xn--pypal-4ve.com/');
    const verdict = result.verdict;
    const suppressed = verdict.indicators.filter((i) => i.suppressed);
    expect(suppressed.length).toBeGreaterThan(0);
    expect(verdict.suppressedCount).toBe(suppressed.length);
    expect(verdict.score).toBe(55);
  });

  it('construiește un verdict din context minimal, fără să arunce', () => {
    const verdict = buildVerdict({ facts: null, domain: null, indicators: [] });
    expect(verdict.riskLevel).toBe(RISK_LEVELS.NONE);
    expect(verdict.url).toBe('');
  });
});
