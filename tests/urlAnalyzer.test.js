import { describe, expect, it } from 'vitest';

import {
  analyzeParsedUrl,
  analyzeUrlInput,
  describeUrlForLog,
  detectRawEncodedHost,
} from '../src/analyzer/urlAnalyzer.js';

/**
 * Ajutor: întoarce faptele pentru o adresă, eșuând testul dacă adresa nu este validă.
 * @param {string} input
 * @returns {object}
 */
function factsOf(input) {
  const result = analyzeUrlInput(input);
  expect(result.ok, `adresa ar trebui să fie validă: ${input}`).toBe(true);
  return result.facts;
}

describe('analyzeUrlInput', () => {
  it('respinge intrările invalide fără să arunce', () => {
    const result = analyzeUrlInput('nu este un url');
    expect(result.ok).toBe(false);
    expect(result.error).toBeTypeOf('string');
  });

  it('extrage faptele de bază pentru o adresă HTTPS normală', () => {
    const facts = factsOf('https://www.exemplu.ro/cale/pagina?q=1#top');
    expect(facts.scheme).toBe('https');
    expect(facts.asciiHost).toBe('www.exemplu.ro');
    expect(facts.registrableDomain).toBe('exemplu.ro');
    expect(facts.registrableLabel).toBe('exemplu');
    expect(facts.tld).toBe('ro');
    expect(facts.pathDepth).toBe(2);
    expect(facts.hasSearch).toBe(true);
    expect(facts.hasFragment).toBe(true);
    expect(facts.isHttps).toBe(true);
    expect(facts.isHttp).toBe(false);
    expect(facts.isIp).toBe(false);
  });

  it('recunoaște schemele periculoase și pe cele neobișnuite', () => {
    expect(factsOf('javascript:alert(1)').isDangerousScheme).toBe(true);
    expect(factsOf('data:text/html,<b>x</b>').isDangerousScheme).toBe(true);
    expect(factsOf('about:blank').isSoftSuspiciousScheme).toBe(true);
    expect(factsOf('https://exemplu.ro').isDangerousScheme).toBe(false);
  });

  it('aduce forma Unicode și perechile de etichete pentru domeniile IDN', () => {
    const facts = factsOf('https://xn--pypal-4ve.com/');
    expect(facts.asciiHost).toBe('xn--pypal-4ve.com');
    expect(facts.unicodeHost).toBe('p\u0430ypal.com');
    expect(facts.hostDiffersFromAscii).toBe(true);
    expect(facts.hasPunycode).toBe(true);
    expect(facts.punycodeLabels).toEqual(['xn--pypal-4ve']);
    expect(facts.labelPairs).toEqual([
      { ascii: 'xn--pypal-4ve', unicode: 'p\u0430ypal', isPunycode: true },
      { ascii: 'com', unicode: 'com', isPunycode: false },
    ]);
    expect(facts.scripts).toEqual(['cyrillic']);
  });

  it('tratează adresele IP publice și private', () => {
    expect(factsOf('http://8.8.8.8/').isIp).toBe(true);
    expect(factsOf('http://8.8.8.8/').isPrivateIp).toBe(false);
    expect(factsOf('http://192.168.0.1/').isIp).toBe(true);
    expect(factsOf('http://192.168.0.1/').isPrivateIp).toBe(true);
    expect(factsOf('http://192.168.0.1/').registrableDomain).toBe('192.168.0.1');
  });

  it('detectează credențialele și portul explicit', () => {
    const facts = factsOf('https://user:parola@exemplu.ro:8443/x');
    expect(facts.hasCredentials).toBe(true);
    expect(facts.hasUsername).toBe(true);
    expect(facts.port).toBe(8443);
    expect(facts.asciiHost).toBe('exemplu.ro');
  });

  it('nu raportează portul implicit', () => {
    expect(factsOf('https://exemplu.ro/').port).toBeNull();
    expect(factsOf('https://exemplu.ro/').isDefaultPort).toBe(true);
  });

  it('potrivește cuvintele-cheie exact în host și prin substring în cale', () => {
    const hostOnly = factsOf('https://accounts-google.example/login');
    expect(hostOnly.keywordZones).toEqual(['path']);
    expect(hostOnly.keywordMatches.map((k) => k.keyword)).toEqual(['login']);

    const inHost = factsOf('https://secure-login-account-verify.exemplu.ro/');
    expect(inHost.keywordZones).toEqual(['host']);
    expect(inHost.keywordMatches.map((k) => k.keyword).sort())
      .toEqual(['account', 'login', 'secure', 'verify']);
  });

  it('clasifică parametrii de urmărire, de redirecționare și pe cei sensibili', () => {
    const facts = factsOf('https://exemplu.ro/x?utm_source=a&next=https%3A%2F%2Falt.example&token=zzz');
    expect(facts.hasTracking).toBe(true);
    expect(facts.trackingParams).toEqual(['utm_source']);
    expect(facts.hasRedirectParam).toBe(true);
    expect(facts.redirectParams).toEqual(['next']);
    expect(facts.sensitiveParams).toEqual(['token']);
  });

  it('sesizează caracterele invizibile codificate procentual', () => {
    expect(factsOf('https://exemplu.ro/a%00b').invisibleEncoded).toHaveLength(1);
    expect(factsOf('https://exemplu.ro/%E2%80%AEgpj.exe').invisibleEncoded).toHaveLength(1);
    expect(factsOf('https://exemplu.ro/a%00b').controlChars).toHaveLength(0);
  });

  it('nu semnalează diacriticele codificate, doar le evidențiază informativ', () => {
    const facts = factsOf('https://ro.wikipedia.org/wiki/Bucure%C8%99ti');
    expect(facts.invisibleEncoded).toHaveLength(0);
    expect(facts.encodedUnicode).toHaveLength(1);
    expect(facts.encodedUnicode[0].zone).toBe('path');
  });

  it('detectează codificarea procentuală din domeniul adresei brute', () => {
    expect(detectRawEncodedHost('https://exa%6dple.ro/')).toBe(true);
    expect(detectRawEncodedHost('https://exemplu.ro/a%20b')).toBe(false);
    expect(factsOf('https://exa%6dple.ro/').rawEncodedHost).toBe(true);
    // Parserul normalizează host-ul; faptul rămâne vizibil prin rawEncodedHost.
    expect(factsOf('https://exa%6dple.ro/').asciiHost).toBe('example.ro');
  });

  it('detectează codificarea dublă și numărul de secvențe codificate', () => {
    const facts = factsOf('https://exemplu.ro/%2520x');
    expect(facts.hasDoubleEncoding).toBe(true);
    expect(facts.percentEncodedCount).toBe(1);
    expect(factsOf(`https://exemplu.ro/${'%20'.repeat(12)}`).percentEncodedCount).toBe(12);
  });

  it('marcăm pozițiile caracterelor neobișnuite corect față de adresa normalizată', () => {
    const facts = factsOf('https://exemplu.ro/a%00b');
    for (const finding of facts.unusualChars) {
      expect(facts.href.slice(finding.index, finding.index + finding.char.length)).toBe(finding.char);
    }
  });

  it('acceptă adrese fără host (scheme non-web) fără să arunce', () => {
    const facts = factsOf('javascript:alert(1)');
    expect(facts.asciiHost).toBe('');
    expect(facts.labels).toEqual([]);
    expect(facts.registrableDomain).toBe('');
  });

  it('produce rezultate identice la rulări repetate (determinism)', () => {
    const input = 'https://secure-login.example.co.uk:8443/path?token=1&utm_source=x#f';
    const first = analyzeUrlInput(input);
    const second = analyzeUrlInput(input);
    expect(JSON.stringify(first.facts)).toBe(JSON.stringify(second.facts));
  });
});

describe('analyzeParsedUrl', () => {
  it('poate analiza un URL deja construit', () => {
    const facts = analyzeParsedUrl(new URL('https://exemplu.ro/'), 'https://exemplu.ro/');
    expect(facts.hostDiffersFromAscii).toBe(false);
    expect(facts.rawInput).toBe('https://exemplu.ro/');
  });
});

describe('describeUrlForLog', () => {
  it('nu include valorile parametrilor sensibili', () => {
    const facts = factsOf('https://exemplu.ro/login?token=abc123&user=ion&x=1');
    const log = describeUrlForLog(facts);
    expect(log).not.toContain('abc123');
    expect(log).toContain('<valoare>');
  });

  it('poate elimina complet interogarea', () => {
    const facts = factsOf('https://exemplu.ro/login?token=abc123');
    expect(describeUrlForLog(facts, { stripQuery: true })).toBe('https://exemplu.ro/login');
  });
});
