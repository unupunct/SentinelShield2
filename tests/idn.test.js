import { describe, expect, it } from 'vitest';

import {
  PunycodeError,
  collectScripts,
  decodePunycode,
  detectScript,
  isPunycodeLabel,
  toUnicodeHost,
} from '../src/shared/idn.js';

/**
 * Valorile de referință au fost verificate față de implementarea RFC 3492 din
 * `node:punycode` (modul de referință), nu presupuse.
 */
describe('decodePunycode', () => {
  it('decodează etichete cu diacritice latine', () => {
    expect(decodePunycode('xn--mnchen-3ya')).toBe('münchen');
    expect(decodePunycode('xn--bcher-kva')).toBe('bücher');
    expect(decodePunycode('xn--caf-dma')).toBe('café');
  });

  it('decodează etichete cu caractere chirilice', () => {
    expect(decodePunycode('xn--e1afmkfd')).toBe('пример');
    // „pаypal” - al doilea caracter este chirilicul U+0430, nu „a” latin.
    expect(decodePunycode('xn--pypal-4ve')).toBe('p\u0430ypal');
    // „аррӏе” (exemplul clasic de imitație a „apple”).
    expect(decodePunycode('xn--80ak6aa92e')).toBe('\u0430\u0440\u0440\u04cf\u0435');
  });

  it('acceptă forma fără prefixul xn--', () => {
    expect(decodePunycode('mnchen-3ya')).toBe('münchen');
  });

  it('aruncă o eroare tipizată pentru intrări invalide', () => {
    expect(() => decodePunycode('!')).toThrow(PunycodeError);
    expect(() => decodePunycode(42)).toThrow(PunycodeError);
  });
});

describe('isPunycodeLabel', () => {
  it('recunoaște prefixul xn-- indiferent de majuscule', () => {
    expect(isPunycodeLabel('xn--mnchen-3ya')).toBe(true);
    expect(isPunycodeLabel('XN--MNCHEN-3YA')).toBe(true);
    expect(isPunycodeLabel('münchen')).toBe(false);
  });
});

describe('toUnicodeHost', () => {
  it('decodează etichetele și păstrează structura host-ului', () => {
    const result = toUnicodeHost('xn--googl-9qa.com.evil.example');
    expect(result.unicodeHost).toBe('gãoogl.com.evil.example');
    expect(result.decodedLabels).toEqual(['gãoogl']);
    expect(result.failedLabels).toEqual([]);
  });

  it('păstrează etichetele care nu sunt Punycode', () => {
    expect(toUnicodeHost('www.exemplu.ro').unicodeHost).toBe('www.exemplu.ro');
  });

  it('nu aruncă pentru etichete Punycode corupte', () => {
    const result = toUnicodeHost('xn--!.ro');
    expect(result.unicodeHost).toBe('xn--!.ro');
    expect(result.failedLabels).toEqual(['xn--!']);
  });
});

describe('detectScript / collectScripts', () => {
  it('identifică scripturile', () => {
    expect(detectScript('a')).toBe('ascii');
    expect(detectScript('\u0430')).toBe('cyrillic');
    expect(detectScript('\u03b1')).toBe('greek');
    expect(detectScript('ü')).toBe('latin');
    expect(collectScripts('p\u0430ypal')).toEqual(['cyrillic']);
    expect(collectScripts('plain-ascii')).toEqual([]);
  });
});
