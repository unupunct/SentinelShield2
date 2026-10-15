import { describe, expect, it, vi } from 'vitest';

import { analyzeUrlInput } from '../src/analyzer/urlAnalyzer.js';
import {
  REPUTATION_STATUS,
  REPUTATION_VERDICT,
  buildRequestPayload,
  checkReputation,
  describeDataSent,
  parseReputationResponse,
  validateEndpoint,
} from '../src/analyzer/reputationProvider.js';
import { DEFAULT_SETTINGS } from '../src/shared/constants.js';

/**
 * Construiește setări cu reputația configurată.
 * @param {object} [overrides]
 * @returns {object}
 */
function settingsWith(overrides = {}) {
  return {
    ...DEFAULT_SETTINGS,
    reputation: {
      ...DEFAULT_SETTINGS.reputation,
      enabled: true,
      provider: 'custom_http',
      endpoint: 'https://reputatie.example/api',
      ...overrides,
    },
  };
}

/**
 * Răspuns HTTP simulat.
 * @param {unknown} body
 * @param {number} [status]
 * @returns {object}
 */
function fakeResponse(body, status = 200) {
  return {
    status,
    json: async () => body,
  };
}

const facts = analyzeUrlInput('https://exemplu.ro/cale?token=abc123&x=1').facts;

describe('validateEndpoint', () => {
  it('acceptă doar HTTPS', () => {
    expect(validateEndpoint('https://x.example/api').ok).toBe(true);
    expect(validateEndpoint('http://x.example/api').ok).toBe(false);
    expect(validateEndpoint('http://x.example/api').error).toMatch(/HTTPS/);
    expect(validateEndpoint('').ok).toBe(false);
    expect(validateEndpoint('nu-e-un-url').ok).toBe(false);
  });
});

describe('buildRequestPayload', () => {
  it('trimite implicit doar numele de domeniu, fără parametri', () => {
    const payload = buildRequestPayload(facts, { hostnameOnly: true });
    expect(payload).toEqual({
      host: 'exemplu.ro',
      unicodeHost: 'exemplu.ro',
      registrableDomain: 'exemplu.ro',
    });
    expect(JSON.stringify(payload)).not.toContain('abc123');
    expect(JSON.stringify(payload)).not.toContain('token');
  });

  it('include doar calea când utilizatorul dezactivează modul hostname-only', () => {
    const payload = buildRequestPayload(facts, { hostnameOnly: false });
    expect(payload.path).toBe('/cale');
    expect(JSON.stringify(payload)).not.toContain('abc123');
    expect(JSON.stringify(payload)).not.toContain('token');
  });

  it('descrie clar ce date se trimit', () => {
    expect(describeDataSent({ hostnameOnly: true }, 'exemplu.ro')).toContain('doar numele de domeniu');
    expect(describeDataSent({ hostnameOnly: false }, 'exemplu.ro')).toContain('fără parametri');
  });
});

describe('parseReputationResponse', () => {
  it('normalizează verdictul și încrederea', () => {
    expect(parseReputationResponse({ verdict: 'phishing' }).verdict).toBe(REPUTATION_VERDICT.MALICIOUS);
    expect(parseReputationResponse({ status: 'SAFE' }).verdict).toBe(REPUTATION_VERDICT.CLEAN);
    expect(parseReputationResponse({ verdict: 'suspicious', confidence: 87 }).confidence).toBeCloseTo(0.87);
    expect(parseReputationResponse({ verdict: 'suspicious', confidence: 0.5 }).confidence).toBe(0.5);
  });

  it('tratează răspunsurile necunoscute sau invalide', () => {
    expect(parseReputationResponse(null).valid).toBe(false);
    expect(parseReputationResponse({ ceva: 1 }).verdict).toBe(REPUTATION_VERDICT.UNKNOWN);
    expect(parseReputationResponse('text').valid).toBe(false);
  });
});

describe('checkReputation', () => {
  it('nu face nicio cerere implicit (reputația este dezactivată)', async () => {
    const fetchImpl = vi.fn();
    const result = await checkReputation(facts, DEFAULT_SETTINGS, { fetchImpl });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(result.status).toBe(REPUTATION_STATUS.DISABLED);
    expect(result.checked).toBe(false);
    expect(result.verdict).toBe(REPUTATION_VERDICT.UNKNOWN);
  });

  it('raportează configurația invalidă', async () => {
    const withoutEndpoint = await checkReputation(facts, settingsWith({ endpoint: '' }), { fetchImpl: vi.fn() });
    expect(withoutEndpoint.status).toBe(REPUTATION_STATUS.INVALID);

    const wrongProvider = await checkReputation(facts, settingsWith({ provider: 'altceva' }), { fetchImpl: vi.fn() });
    expect(wrongProvider.status).toBe(REPUTATION_STATUS.INVALID);
  });

  it('interpretează un răspuns malițios, dar nu confirmă fără acord explicit', async () => {
    const fetchImpl = vi.fn(async () => fakeResponse({ verdict: 'malicious', confidence: 0.9, source: 'test' }));
    const result = await checkReputation(facts, settingsWith(), { fetchImpl });
    expect(result.status).toBe(REPUTATION_STATUS.OK);
    expect(result.verdict).toBe(REPUTATION_VERDICT.MALICIOUS);
    expect(result.confirmed).toBe(false);
  });

  it('confirmă doar când `confirmMalicious` este activat', async () => {
    const fetchImpl = vi.fn(async () => fakeResponse({ verdict: 'malicious' }));
    const result = await checkReputation(facts, settingsWith({ confirmMalicious: true }), { fetchImpl });
    expect(result.confirmed).toBe(true);
  });

  it('trimite doar domeniul, fără parametri sensibili', async () => {
    const fetchImpl = vi.fn(async () => fakeResponse({ verdict: 'clean' }));
    await checkReputation(facts, settingsWith(), { fetchImpl });
    const [, init] = fetchImpl.mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body).toEqual({ host: 'exemplu.ro', unicodeHost: 'exemplu.ro', registrableDomain: 'exemplu.ro' });
    expect(init.body).not.toContain('abc123');
    expect(fetchImpl.mock.calls[0][0]).toBe('https://reputatie.example/api/check');
  });

  it('tratează erorile HTTP fără să arunce', async () => {
    const result = await checkReputation(facts, settingsWith(), {
      fetchImpl: async () => fakeResponse({}, 500),
    });
    expect(result.status).toBe(REPUTATION_STATUS.ERROR);
    expect(result.error).toMatch(/500/);
    expect(result.verdict).toBe(REPUTATION_VERDICT.UNKNOWN);
  });

  it('tratează indisponibilitatea serviciului (excepție de rețea)', async () => {
    const result = await checkReputation(facts, settingsWith(), {
      fetchImpl: async () => {
        throw new Error('ECONNREFUSED');
      },
    });
    expect(result.status).toBe(REPUTATION_STATUS.ERROR);
    expect(result.error).toMatch(/ECONNREFUSED/);
  });

  it('tratează depășirea timpului de așteptare', async () => {
    const abortError = new Error('abortat');
    abortError.name = 'AbortError';
    const result = await checkReputation(facts, settingsWith({ timeoutMs: 500 }), {
      fetchImpl: async () => {
        throw abortError;
      },
    });
    expect(result.status).toBe(REPUTATION_STATUS.TIMEOUT);
    expect(result.checked).toBe(false);
    expect(result.error).toMatch(/500 ms/);
  });

  it('tratează un răspuns fără JSON valid', async () => {
    const result = await checkReputation(facts, settingsWith(), {
      fetchImpl: async () => ({ status: 200, json: 'nu-e-functie' }),
    });
    expect(result.status).toBe(REPUTATION_STATUS.INVALID);
    expect(result.error).toMatch(/JSON/);
  });

  it('marchează un format nerecunoscut ca invalid, fără să ridice riscul', async () => {
    const result = await checkReputation(facts, settingsWith(), {
      fetchImpl: async () => fakeResponse({ rezultat: 'cine-știe' }),
    });
    expect(result.status).toBe(REPUTATION_STATUS.INVALID);
    expect(result.verdict).toBe(REPUTATION_VERDICT.UNKNOWN);
  });

  it('nu trimite cheia API atunci când nu este configurată', async () => {
    const fetchImpl = vi.fn(async () => fakeResponse({ verdict: 'clean' }));
    await checkReputation(facts, settingsWith(), { fetchImpl });
    expect(fetchImpl.mock.calls[0][1].headers['X-API-Key']).toBeUndefined();
  });
});
