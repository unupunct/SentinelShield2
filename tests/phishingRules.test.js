import { describe, expect, it } from 'vitest';

import { analyzeDomain } from '../src/analyzer/domainAnalyzer.js';
import { RULES, RULES_BY_ID, evaluateRules } from '../src/analyzer/phishingRules.js';
import { analyzeUrlInput } from '../src/analyzer/urlAnalyzer.js';
import { scoreIndicators } from '../src/analyzer/riskScorer.js';
import { SEVERITY } from '../src/shared/constants.js';

/**
 * Rulează regulile pentru o adresă și întoarce indicatorii detectați.
 * @param {string} input
 * @returns {{ facts: object, domain: object, indicators: Array<object> }}
 */
function run(input) {
  const result = analyzeUrlInput(input);
  expect(result.ok, `adresă validă așteptată: ${input}`).toBe(true);
  const facts = result.facts;
  const domain = analyzeDomain(facts);
  return { facts, domain, indicators: evaluateRules({ facts, domain }) };
}

/**
 * @param {Array<object>} indicators
 * @param {string} ruleId
 * @returns {object|undefined}
 */
function byId(indicators, ruleId) {
  return indicators.find((i) => i.ruleId === ruleId);
}

/**
 * @param {Array<object>} indicators
 * @returns {string[]}
 */
function ids(indicators) {
  return indicators.map((i) => i.ruleId);
}

describe('structura regulilor', () => {
  it('fiecare regulă are metadate complete și ponderi valide', () => {
    const seenIds = new Set();
    const seenFamilies = new Map();
    for (const rule of RULES) {
      expect(rule.id, 'id').toMatch(/^[A-Z]+-\d{3}$/);
      expect(seenIds.has(rule.id), `id duplicat: ${rule.id}`).toBe(false);
      seenIds.add(rule.id);

      expect(rule.family, `familie ${rule.id}`).toMatch(/^[a-z]+\.[a-z_]+$/);
      expect(rule.title.length, `titlu ${rule.id}`).toBeGreaterThan(10);
      expect(rule.why.length, `motiv ${rule.id}`).toBeGreaterThan(30);
      expect(rule.limits.length, `limite ${rule.id}`).toBeGreaterThan(20);
      expect(rule.recommendation.length, `recomandare ${rule.id}`).toBeGreaterThan(10);
      expect(Object.values(SEVERITY)).toContain(rule.severity);
      expect(rule.weight).toBeGreaterThanOrEqual(0);
      expect(rule.weight).toBeLessThanOrEqual(100);
      expect(typeof rule.detect).toBe('function');
      expect(typeof rule.explain).toBe('function');

      // Aceeași familie înseamnă aceeași caracteristică: ponderile trebuie să difere
      // (altfel deduplicarea ar fi nedeterministă în practică).
      if (seenFamilies.has(rule.family)) {
        expect(seenFamilies.get(rule.family).weight, `familie ${rule.family}`).not.toBe(rule.weight);
      }
      seenFamilies.set(rule.family, rule);
    }
    expect(RULES.length).toBe(seenIds.size);
    expect(RULES_BY_ID['DOM-001']).toBe(RULES.find((r) => r.id === 'DOM-001'));
  });

  it('nu există reguli duplicate ca id în index', () => {
    expect(Object.keys(RULES_BY_ID)).toHaveLength(RULES.length);
  });
});

describe('reguli de schemă', () => {
  it('URL-001 semnalează schemele periculoase, dar nu pe cele web', () => {
    expect(byId(run('javascript:alert(1)').indicators, 'URL-001')?.weight).toBe(65);
    expect(byId(run('data:text/html,<b>x</b>').indicators, 'URL-001')?.severity).toBe(SEVERITY.CRITICAL);
    expect(byId(run('https://exemplu.ro').indicators, 'URL-001')).toBeUndefined();
  });

  it('URL-003 semnalează HTTP ca informație, nu ca pericol', () => {
    const http = byId(run('http://exemplu.ro/').indicators, 'URL-003');
    expect(http?.severity).toBe(SEVERITY.INFO);
    expect(http?.weight).toBe(5);
    expect(byId(run('https://exemplu.ro/').indicators, 'URL-003')).toBeUndefined();
  });
});

describe('reguli de gazdă', () => {
  it('HOST-001 / HOST-002 disting IP-ul public de cel privat, în aceeași familie', () => {
    const publicIp = run('http://8.8.8.8/').indicators;
    expect(byId(publicIp, 'HOST-001')?.weight).toBe(30);
    expect(RULES_BY_ID['HOST-001'].family).toBe(RULES_BY_ID['HOST-002'].family);

    const privateIp = run('http://192.168.0.1/admin').indicators;
    expect(byId(privateIp, 'HOST-002')?.weight).toBe(12);
    expect(byId(privateIp, 'HOST-001')).toBeUndefined();
  });

  it('HOST-003 semnalează Punycode, dar este atenuat de regula de imitație de brand', () => {
    const legit = run('https://m\u00fcnchen.de/').indicators;
    expect(byId(legit, 'HOST-003')?.suppressed).toBe(false);

    const homoglyph = run('https://xn--pypal-4ve.com/').indicators;
    expect(byId(homoglyph, 'HOST-003')?.suppressed).toBe(true);
    expect(byId(homoglyph, 'HOST-003')?.weight).toBe(0);
    expect(byId(homoglyph, 'HOST-003')?.suppressedByFamily).toBe('domain.brand_homoglyph');
  });

  it('HOST-004 semnalează scripturile amestecate și este atenuat de DOM-001', () => {
    const brand = run('https://\u0430pple.example/').indicators;
    expect(byId(brand, 'DOM-001')?.weight).toBe(55);
    expect(byId(brand, 'HOST-004')?.suppressed).toBe(true);

    const nonBrand = run('https://g\u0430me.example/').indicators;
    const mixed = byId(nonBrand, 'HOST-004');
    expect(mixed?.weight).toBe(40);
    expect(mixed?.suppressed).toBe(false);
    expect(mixed?.detail).toContain('alfabete diferite');
  });

  it('HOST-005 semnalează caracterele de control literale și pe cele codificate', () => {
    const encoded = byId(run('https://exemplu.ro/a%00b').indicators, 'HOST-005');
    expect(encoded?.weight).toBe(40);
    expect(encoded?.detail).toContain('codificare procentuală');

    const literal = byId(run('https://exemplu.ro/a\u202eb').indicators, 'HOST-005');
    expect(literal).toBeDefined();
  });

  it('HOST-006 semnalează codificarea procentuală din domeniul introdus', () => {
    expect(byId(run('https://exa%6dple.ro/').indicators, 'HOST-006')?.weight).toBe(30);
    expect(byId(run('https://exemplu.ro/').indicators, 'HOST-006')).toBeUndefined();
  });

  it('HOST-007 semnalează credențialele din adresă', () => {
    const indicator = byId(run('https://user:parola@exemplu.ro/').indicators, 'HOST-007');
    expect(indicator?.weight).toBe(35);
    expect(indicator?.detail).toContain('@');
  });

  it('HOST-008 semnalează porturile neobișnuite, dar nu pe cele uzuale', () => {
    expect(byId(run('https://exemplu.ro:9443/').indicators, 'HOST-008')?.weight).toBe(8);
    expect(byId(run('https://exemplu.ro:8443/').indicators, 'HOST-008')).toBeUndefined();
    expect(byId(run('https://exemplu.ro/').indicators, 'HOST-008')).toBeUndefined();
  });

  it('HOST-009 semnalează codificarea excesivă', () => {
    expect(byId(run(`https://exemplu.ro/${'%20'.repeat(12)}`).indicators, 'HOST-009')?.weight).toBe(12);
    expect(byId(run('https://exemplu.ro/a%20b').indicators, 'HOST-009')).toBeUndefined();
  });

  it('HOST-010 semnalează codificarea dublă', () => {
    expect(byId(run('https://exemplu.ro/%2520x').indicators, 'HOST-010')?.weight).toBe(20);
  });

  it('HOST-011 semnalează lanțurile de subdomenii, dar nu pe adresele IP', () => {
    expect(byId(run('https://a.b.c.exemplu.ro/').indicators, 'HOST-011')?.weight).toBe(15);
    expect(byId(run('http://192.168.0.1/admin').indicators, 'HOST-011')).toBeUndefined();
  });

  it('HOST-012 și HOST-013 semnalează domeniile lungi și cele cu multe cratime', () => {
    expect(byId(run(`https://${'a'.repeat(40)}.example/`).indicators, 'HOST-012')?.weight).toBe(10);
    expect(byId(run('https://secure-login-account-verify-more.exemplu.ro/').indicators, 'HOST-013')?.weight).toBe(8);
  });

  it('HOST-014 semnalează terminațiile abuzate, cu pondere mică', () => {
    const indicator = byId(run('https://exemplu.xyz/').indicators, 'HOST-014');
    expect(indicator?.weight).toBe(10);
    expect(indicator?.limits).toMatch(/NU este o dovadă/);
  });

  it('HOST-015 semnalează punctul final din domeniu', () => {
    expect(byId(run('https://exemplu.ro./').indicators, 'HOST-015')?.weight).toBe(10);
  });
});

describe('reguli de cale și context', () => {
  it('PATH-001 semnalează cuvintele de autentificare cu pondere mică', () => {
    const indicator = byId(run('https://exemplu.ro/account/login').indicators, 'PATH-001');
    expect(indicator?.weight).toBe(12);
    expect(indicator?.limits).toContain('legitime');
  });

  it('PATH-002 înlocuiește PATH-001 la scor (aceeași familie, fără dublă numărare)', () => {
    const indicators = run('https://paypal-secure.example/account/verify').indicators;
    expect(byId(indicators, 'PATH-002')?.weight).toBe(30);
    expect(RULES_BY_ID['PATH-001'].family).toBe(RULES_BY_ID['PATH-002'].family);
    expect(byId(indicators, 'PATH-002')?.detail).toContain('paypal');

    // Ambele sunt detectate, dar la scor rămâne doar varianta puternică.
    const scored = scoreIndicators(indicators);
    const pathIndicators = scored.indicators.filter((i) => i.family === 'path.sensitive_keyword');
    expect(pathIndicators).toHaveLength(1);
    expect(pathIndicators[0].ruleId).toBe('PATH-002');
  });

  it('PATH-002 nu se declanșează pe un domeniu fără alți indicatori', () => {
    expect(byId(run('https://exemplu.ro/account/login').indicators, 'PATH-002')).toBeUndefined();
  });

  it('PATH-003 semnalează parametrii de redirecționare', () => {
    expect(byId(run('https://exemplu.ro/x?next=%2Fcont').indicators, 'PATH-003')?.weight).toBe(12);
  });

  it('PATH-004 semnalează redirecționarea către alt domeniu și ignoră redirecționarea internă', () => {
    const external = byId(
      run('https://exemplu.ro/x?next=https%3A%2F%2Fevil.example%2Fp').indicators,
      'PATH-004',
    );
    expect(external?.weight).toBe(25);
    expect(external?.evidence.targetHost).toBe('evil.example');

    const internal = byId(
      run('https://exemplu.ro/x?next=https%3A%2F%2Fexemplu.ro%2Fcont').indicators,
      'PATH-004',
    );
    expect(internal).toBeUndefined();
  });

  it('URL-004 și PRIV-001 semnalează linkurile scurtate și parametrii de urmărire', () => {
    expect(byId(run('https://bit.ly/3abcXYZ').indicators, 'URL-004')?.weight).toBe(10);
    expect(byId(run('https://exemplu.ro/x?utm_source=news').indicators, 'PRIV-001')?.weight).toBe(4);
  });

  it('URL-005 semnalează adresele foarte lungi', () => {
    const long = `https://exemplu.ro/${'segment/'.repeat(30)}`;
    expect(byId(run(long).indicators, 'URL-005')?.weight).toBe(6);
  });
});

describe('reguli de domeniu (imitații de brand)', () => {
  it('DOM-001 detectează omoglifele și explică ce s-a observat', () => {
    const indicator = byId(run('https://xn--pypal-4ve.com/').indicators, 'DOM-001');
    expect(indicator?.weight).toBe(55);
    expect(indicator?.detail).toContain('alt alfabet');
  });

  it('DOM-002 detectează substituția de cifre', () => {
    const indicator = byId(run('https://g00gle.example/').indicators, 'DOM-002');
    expect(indicator?.weight).toBe(50);
    expect(indicator?.detail).toContain('cifre');
  });

  it('DOM-003 detectează typosquatting-ul', () => {
    const indicator = byId(run('https://gogle.example/').indicators, 'DOM-003');
    expect(indicator?.weight).toBe(45);
    expect(indicator?.detail).toMatch(/diferă prin 1 caracter/);
  });

  it('DOM-004 detectează brandul folosit ca subdomeniu', () => {
    const indicator = byId(run('https://google.com.example.org/').indicators, 'DOM-004');
    expect(indicator?.weight).toBe(45);
    expect(indicator?.detail).toContain('example.org');
  });

  it('DOM-005 detectează brandul inclus în alt nume', () => {
    expect(byId(run('https://paypal-secure.example/').indicators, 'DOM-005')?.weight).toBe(35);
  });

  it('DOM-006 este informativ și nu contribuie la scor', () => {
    const indicators = run('https://google.ro/').indicators;
    const indicator = byId(indicators, 'DOM-006');
    expect(indicator?.weight).toBe(0);
    expect(indicator?.severity).toBe(SEVERITY.INFO);
  });

  it('nu semnalează branduri pe domeniile oficiale cunoscute', () => {
    for (const url of ['https://www.google.com/', 'https://microsoftonline.com/', 'https://amazonaws.com/']) {
      const detected = run(url).indicators.filter((i) => i.family.startsWith('domain.'));
      expect(detected, url).toEqual([]);
    }
  });

  it('nu consideră diacriticele drept încercare de imitare', () => {
    const indicators = run('https://m\u00fcnchen.de/').indicators;
    expect(indicators.filter((i) => i.family.startsWith('domain.'))).toEqual([]);
  });

  it('domeniile necunoscute, simple și fără alte semnale nu produc indicatori', () => {
    expect(run('https://un-domeniu-oarecare-1234.example/').indicators.filter((i) => i.weight > 0)).toEqual([]);
  });
});

describe('deduplicare și determinism', () => {
  it('doi indicatori din aceeași familie nu pot avea aceeași pondere (ar fi nedeterminist)', () => {
    const families = new Map();
    for (const rule of RULES) {
      const list = families.get(rule.family) ?? [];
      list.push(rule.weight);
      families.set(rule.family, list);
    }
    for (const [family, weights] of families) {
      expect(new Set(weights).size, `familie ${family}`).toBe(weights.length);
    }
  });

  it('aceeași adresă produce aceiași indicatori la rulări repetate', () => {
    const input = 'https://paypal-secure.example/account/verify?next=https%3A%2F%2Fevil.example';
    const first = run(input).indicators;
    const second = run(input).indicators;
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it('o regulă care aruncă o eroare nu blochează analiza', () => {
    const facts = analyzeUrlInput('https://exemplu.ro/').facts;
    const brokenDomain = new Proxy({}, {
      get() {
        throw new Error('defect simulat');
      },
    });
    const indicators = evaluateRules({ facts, domain: brokenDomain });
    expect(Array.isArray(indicators)).toBe(true);
    const affected = indicators.filter((i) => i.evidence.ruleError);
    expect(affected.length).toBeGreaterThan(0);
    expect(affected[0].severity).toBe(SEVERITY.INFO);
  });

  it('evaluateRules cere contextul complet', () => {
    expect(() => evaluateRules({ facts: null, domain: null })).toThrow(TypeError);
  });
});
