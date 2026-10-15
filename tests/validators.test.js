import { describe, expect, it } from 'vitest';

import {
  REDACTED,
  getRegistrableDomain,
  hasControlChars,
  isIpHost,
  isPlainObject,
  isPrivateIp,
  levenshtein,
  normalizeDomainEntry,
  normalizeUrlInput,
  parseUrl,
  redactUrl,
  splitByRanges,
  stripControlChars,
  truncate,
  validateHostname,
} from '../src/shared/validators.js';

describe('normalizeUrlInput', () => {
  it('adaugă schema implicită pentru un host simplu', () => {
    const result = normalizeUrlInput('exemplu.ro');
    expect(result.ok).toBe(true);
    expect(result.normalized).toBe('https://exemplu.ro/');
  });

  it('respectă schema implicită configurată', () => {
    const result = normalizeUrlInput('exemplu.ro', { defaultScheme: 'http' });
    expect(result.ok).toBe(true);
    expect(result.normalized).toBe('http://exemplu.ro/');
  });

  it('păstrează schema explicită, inclusiv cele periculoase (pentru a putea fi semnalate)', () => {
    const result = normalizeUrlInput('javascript:alert(1)');
    expect(result.ok).toBe(true);
    expect(result.normalized.startsWith('javascript:')).toBe(true);
  });

  it('acceptă adrese care încep cu //', () => {
    const result = normalizeUrlInput('//exemplu.ro/x');
    expect(result.ok).toBe(true);
    expect(result.normalized).toBe('https://exemplu.ro/x');
  });

  it('acceptă adrese IP', () => {
    const result = normalizeUrlInput('192.168.0.1/admin');
    expect(result.ok).toBe(true);
    expect(result.url.hostname).toBe('192.168.0.1');
  });

  it('respinge adresele invalide', () => {
    for (const invalid of ['', '   ', 'not a url', 'http://[invalid', 'https:// ex.com']) {
      const result = normalizeUrlInput(invalid);
      expect(result.ok, `ar trebui respins: ${JSON.stringify(invalid)}`).toBe(false);
      expect(typeof result.error).toBe('string');
    }
  });

  it('respinge adresele peste limita de lungime', () => {
    const result = normalizeUrlInput(`https://exemplu.ro/${'a'.repeat(9000)}`);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/depășește/);
  });

  it('elimină separatele de linie lipite accidental', () => {
    const result = normalizeUrlInput('https://exemplu.ro/a\nb');
    expect(result.ok).toBe(true);
    expect(result.url.pathname).toBe('/ab');
  });
});

describe('parseUrl', () => {
  it('nu aruncă niciodată, ci întoarce un rezultat tipizat', () => {
    expect(parseUrl('%%%').ok).toBe(false);
    expect(parseUrl('https://exemplu.ro').ok).toBe(true);
    expect(parseUrl(null).ok).toBe(false);
  });
});

describe('validateHostname', () => {
  it('acceptă domenii și subdomenii valide', () => {
    for (const host of ['exemplu.ro', 'sub.exemplu.ro', 'xn--mnchen-3ya.de', '192.168.0.1', 'bcr.ro']) {
      expect(validateHostname(host).ok, host).toBe(true);
    }
  });

  it('respinge intrările invalide', () => {
    const cases = [
      ['', /gol/],
      ['fărăpunct', /punct/],
      ['exemplu..ro', /punct dublu/],
      ['-exemplu.ro', /cratimă/],
      ['exemplu-.ro', /cratimă/],
      ['exemplu.c', /Terminația/],
      ['exemplu.123', /Terminația/],
      ['exemplu .ro', /spații/],
      ['https://exemplu.ro', /cale|credentiale|caractere/i],
      ['exemplu.ro/path', /cale/],
      ['a'.repeat(64) + '.ro', /63/],
    ];
    for (const [input, pattern] of cases) {
      const result = validateHostname(input);
      expect(result.ok, input).toBe(false);
      expect(result.error).toMatch(pattern);
    }
  });
});

describe('normalizeDomainEntry', () => {
  it('extrage domeniul dintr-un URL complet', () => {
    const result = normalizeDomainEntry('https://Exemplu.ro/path?x=1');
    expect(result).toEqual({
      ok: true,
      host: 'exemplu.ro',
      includeSubdomains: false,
      raw: 'https://Exemplu.ro/path?x=1',
    });
  });

  it('acceptă explicit subdomeniile doar prin prefixul *. ', () => {
    const withStar = normalizeDomainEntry('*.exemplu.ro');
    expect(withStar.ok).toBe(true);
    expect(withStar.host).toBe('exemplu.ro');
    expect(withStar.includeSubdomains).toBe(true);

    const withoutStar = normalizeDomainEntry('exemplu.ro');
    expect(withoutStar.includeSubdomains).toBe(false);
  });

  it('convertește formele Unicode în Punycode', () => {
    const result = normalizeDomainEntry('münchen.de');
    expect(result.ok).toBe(true);
    expect(result.host).toBe('xn--mnchen-3ya.de');
  });

  it('elimină credențialele și portul', () => {
    expect(normalizeDomainEntry('exemplu.ro:8080').host).toBe('exemplu.ro');
    expect(normalizeDomainEntry('https://user:pass@exemplu.ro/x').host).toBe('exemplu.ro');
  });

  it('respinge intrările care nu conțin un domeniu', () => {
    for (const input of ['', '   ', 'file:///C:/x', '*.192.168.0.1']) {
      expect(normalizeDomainEntry(input).ok, input).toBe(false);
    }
  });
});

describe('getRegistrableDomain', () => {
  it('tratează sufixele cu două niveluri', () => {
    expect(getRegistrableDomain('a.b.example.co.uk')).toBe('example.co.uk');
    expect(getRegistrableDomain('www.exemplu.ro')).toBe('exemplu.ro');
  });

  it('identifică domeniul real dintr-un lanț de subdomenii', () => {
    expect(getRegistrableDomain('google.com.example.org')).toBe('example.org');
  });

  it('păstrează adresele IP neschimbate', () => {
    expect(getRegistrableDomain('192.168.0.1')).toBe('192.168.0.1');
  });
});

describe('levenshtein', () => {
  it('calculează distanța corect', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(3);
    expect(levenshtein('paypal', 'paypa1')).toBe(1);
    expect(levenshtein('abc', 'abc')).toBe(0);
  });

  it('se oprește când depășește limita cerută', () => {
    expect(levenshtein('abcdefgh', 'zzzzzzzz', 2)).toBeGreaterThan(2);
  });
});

describe('redactUrl', () => {
  it('redactează valorile parametrilor sensibili și păstrează restul lizibil', () => {
    expect(redactUrl('https://exemplu.ro/login?token=abc123&x=1&utm_source=fb'))
      .toBe(`https://exemplu.ro/login?token=${REDACTED}&x=1&utm_source=fb`);
  });

  it('redactează parola din credențiale', () => {
    expect(redactUrl('https://user:parola@exemplu.ro/p?q=1'))
      .toBe(`https://user:${REDACTED}@exemplu.ro/p?q=1`);
  });

  it('poate elimina complet interogarea', () => {
    expect(redactUrl('https://exemplu.ro/p?a=1#f', { stripQuery: true })).toBe('https://exemplu.ro/p#f');
  });

  it('aplică redactare conservatoare pe intrări neparsabile', () => {
    expect(redactUrl('nu=este=url')).toBe(`nu=${REDACTED}`);
  });

  it('redactează și în schemele fără host', () => {
    expect(redactUrl('data:text/plain,token=abc')).toBe(`data:text/plain,token=${REDACTED}`);
  });
});

describe('splitByRanges', () => {
  it('împarte textul în segmente evidențiate', () => {
    expect(splitByRanges('abcdef', [{ start: 1, end: 3 }])).toEqual([
      { text: 'a', highlighted: false },
      { text: 'bc', highlighted: true },
      { text: 'def', highlighted: false },
    ]);
  });

  it('unifică intervalele care se suprapun', () => {
    expect(splitByRanges('abcdef', [{ start: 1, end: 3 }, { start: 2, end: 5 }])).toEqual([
      { text: 'a', highlighted: false },
      { text: 'bcde', highlighted: true },
      { text: 'f', highlighted: false },
    ]);
  });

  it('ignoră intervalele invalide și limitează intervalele în afara textului', () => {
    expect(splitByRanges('abc', [{ start: 99, end: 200 }, { start: -1, end: 2 }, null, 'x', { start: 1.5, end: 2 }]))
      .toEqual([{ text: 'abc', highlighted: false }]);
    expect(splitByRanges('abc', [{ start: 1, end: 99 }])).toEqual([
      { text: 'a', highlighted: false },
      { text: 'bc', highlighted: true },
    ]);
  });

  it('nu produce HTML: segmentele sunt text simplu', () => {
    const parts = splitByRanges('<script>alert(1)</script>', [{ start: 0, end: 8 }]);
    expect(parts[0]).toEqual({ text: '<script>', highlighted: true });
    expect(parts.every((p) => typeof p.text === 'string')).toBe(true);
  });
});

describe('utilitare diverse', () => {
  it('detectează caracterele de control', () => {
    expect(hasControlChars('abc')).toBe(false);
    expect(hasControlChars('a\u202eb')).toBe(true);
    expect(hasControlChars('a\u0000b')).toBe(true);
  });

  it('elimină caracterele de control', () => {
    expect(stripControlChars('a\u202eb')).toBe('ab');
  });

  it('identifică adresele IP și pe cele private', () => {
    expect(isIpHost('8.8.8.8')).toBe(true);
    expect(isIpHost('999.1.1.1')).toBe(false);
    expect(isIpHost('exemplu.ro')).toBe(false);
    expect(isPrivateIp('192.168.0.1')).toBe(true);
    expect(isPrivateIp('10.1.2.3')).toBe(true);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
  });

  it('trunchiază textul lung', () => {
    expect(truncate('abcdef', 4)).toBe('abc…');
    expect(truncate('abc', 10)).toBe('abc');
  });

  it('recunoaște obiectele simple', () => {
    expect(isPlainObject({})).toBe(true);
    expect(isPlainObject([])).toBe(false);
    expect(isPlainObject(null)).toBe(false);
    expect(isPlainObject('x')).toBe(false);
  });
});
