import { describe, it, expect } from 'vitest';
import { assess, codes } from './helpers.js';
import { analyzeUrl } from '../src/lib/url-analyzer.js';
import { decodePunycode, hostToUnicode } from '../src/lib/punycode.js';
import { splitHost } from '../src/lib/psl.js';

describe('Punycode / PSL', () => {
  it('decodează xn-- corect', () => {
    expect(decodePunycode('bcher-kva')).toBe('bücher');
    expect(hostToUnicode('xn--e1afmkfd.xn--p1ai').unicode).toBe('пример.рф');
  });
  it('domeniu înregistrabil', () => {
    expect(splitHost('a.b.example.co.uk').registrable).toBe('example.co.uk');
    expect(splitHost('x.github.io').registrable).toBe('x.github.io');
    expect(splitHost('www.google.com').registrable).toBe('google.com');
  });
});

describe('1. domeniu legitim HTTPS', () => {
  it('SAFE, fără indicatori semnificativi, cu mențiune că nu garantează', () => {
    const { result } = assess('https://www.google.com/search?q=test');
    expect(result.level).toBe('SAFE');
    expect(result.score).toBe(0);
    expect(result.userExplanation).toMatch(/nu pot garanta/i);
    expect(result.warn).toBe(false);
  });
  it('domeniu ccTLD oficial (google.ro) nu e brand-imitație', () => {
    expect(codes(assess('https://www.google.ro/').result)).not.toContain('brand-name-other-tld');
  });
});

describe('2. domeniu confirmat malițios (listă de test)', () => {
  it('DANGEROUS + confirmed + sursă afișată; nu poate fi anulat de scor mic', () => {
    const { result } = assess('https://confirmed-malware.sentinel-test.example/');
    expect(result.level).toBe('DANGEROUS');
    expect(result.confirmed).toBe(true);
    expect(result.sources.some((s) => s.status === 'malicious' && /Liste locale/.test(s.name))).toBe(true);
    expect(result.userExplanation).toMatch(/identificat|asociat/);
    expect(result.warn).toBe(true);
    expect(result.bypass.mode).toBe('typed');
  });
  it('subdomeniile unui domeniu listat sunt confirmate', () => {
    expect(assess('https://a.b.confirmed-phishing.sentinel-test.example/x').result.confirmed).toBe(true);
  });
});

describe('3. imitație de brand', () => {
  it.each([
    ['https://paypal-secure-login.com/signin', 'brand-in-domain'],
    ['https://paypal.com.account-verify.ru/login', 'brand-in-subdomain'],
    ['https://login.microsoft.evil-site.com/', 'brand-in-subdomain'],
    ['https://paypa1.com/', 'brand-char-substitution'],
    ['https://rnicrosoft.com/', 'brand-char-substitution'],
    ['https://paypai.com/', 'brand-typosquat'],
    ['https://paypal.xyz/', 'brand-name-other-tld'],
    ['https://bancatransilvania-ro.com/', 'brand-in-domain']
  ])('%s -> %s', (url, code) => {
    const { result } = assess(url);
    expect(codes(result)).toContain(code);
    expect(['SUSPICIOUS', 'DANGEROUS']).toContain(result.level);
    expect(result.userExplanation.length).toBeGreaterThan(40);
  });
  it('domeniile oficiale NU sunt marcate', () => {
    for (const u of ['https://www.paypal.com/', 'https://accounts.google.com/', 'https://login.microsoftonline.com/', 'https://www.bancatransilvania.ro/', 'https://mail.google.com/']) {
      expect(assess(u).result.level, u).toBe('SAFE');
    }
  });
});

describe('4. Unicode confuzabil / omograf', () => {
  it('chirilic „а” în apple.com -> DANGEROUS (euristic, nu confirmat)', () => {
    const { analysis, result } = assess('https://аpple.com/');
    expect(analysis.punycode).toMatch(/^xn--/);
    expect(analysis.hostUnicode).toBe('аpple.com');
    expect(codes(result)).toEqual(expect.arrayContaining(['mixed-script', 'homograph-brand']));
    expect(result.level).toBe('DANGEROUS');
    expect(result.confirmed).toBe(false);
    expect(result.kind).toBe('heuristic-high');
    expect(result.bypass.mode).toBe('hold');
  });
  it('domeniu IDN legitim cu diacritice românești nu e periculos', () => {
    const { result, analysis } = assess('https://școala.ro/');
    expect(analysis.hostUnicode).toBe('școala.ro');
    expect(result.level).toBe('SAFE');
    expect(codes(result)).toContain('idn-domain');
  });
  it('label complet chirilic imitând brand (аррӏе.com)', () => {
    expect(assess('https://аррӏе.com/').result.level).toBe('DANGEROUS');
  });
});

describe('5. @ și credențiale încorporate', () => {
  it('https://www.google.com@evil-host.top/ -> at-sign-deception', () => {
    const { analysis, result } = assess('https://www.google.com@evil-host.top/login');
    expect(analysis.hostAscii).toBe('evil-host.top');
    expect(codes(result)).toContain('at-sign-deception');
    expect(result.level).not.toBe('SAFE');
  });
  it('user:parolă@ nu apare în URL-ul normalizat', () => {
    const { analysis, result } = assess('https://admin:Secr3t@intern.exemplu.ro/');
    expect(analysis.normalized).not.toContain('Secr3t');
    expect(JSON.stringify(result)).not.toContain('Secr3t');
    expect(codes(result)).toContain('embedded-credentials');
  });
});

describe('IP, scheme, scurtatoare, redirect', () => {
  it('IP obfuscat (hex/decimal)', () => {
    expect(codes(assess('http://0x7f000001/').result)).toContain('ip-obfuscated');
    expect(codes(assess('http://2130706433/').result)).toContain('ip-obfuscated');
  });
  it('IP privat = legitim informativ', () => {
    const { result } = assess('http://192.168.1.1/admin');
    expect(result.level).toBe('SAFE');
    expect(codes(result)).toContain('ip-private');
  });
  it('IP public cu HTTP+login -> suspect', () => {
    expect(assess('http://203.0.113.9/login/verify').result.level).toBe('SUSPICIOUS');
  });
  it('HTTP singur nu blochează și nu avertizează', () => {
    const { result } = assess('http://example-shop.ro/produse?id=3');
    expect(result.level).toBe('SAFE');
    expect(result.warn).toBe(false);
  });
  it('scheme neobișnuite', () => {
    const r = assess('javascript:alert(1)').result;
    expect(codes(r)).toContain('unusual-scheme');
    expect(r.level).toBe('SUSPICIOUS');
  });
  it('scurtator marcat ca destinație ascunsă', () => {
    expect(codes(assess('https://bit.ly/3abcXYZ').result)).toContain('url-shortener');
  });
  it('parametru de redirect către alt domeniu', () => {
    const { analysis, result } = assess('https://site-legit.ro/out?url=https%3A%2F%2Fevil-target.top%2Fx');
    expect(analysis.redirectTargets[0].host).toBe('evil-target.top');
    expect(codes(result)).toContain('redirect-parameter');
  });
  it('port, fragment, cale normalizate', () => {
    const a = analyzeUrl('HTTPS://Example.COM:443/a/../b?x=1#frag');
    expect(a.normalized).toBe('https://example.com/b?x=1');
  });
  it('pagini interne -> UNKNOWN neanalizat', () => {
    const r = assess('chrome://settings').result;
    expect(r.level).toBe('UNKNOWN');
    expect(r.reason).toBe('internal-page');
  });
});

describe('16. site necunoscut fără indicatori', () => {
  it('SAFE cu avertisment de neindicare siguranță absolută, nu „curat garantat”', () => {
    const { result } = assess('https://magazin-de-biciclete-brasov.ro/');
    expect(result.level).toBe('SAFE');
    expect(result.summary).toMatch(/Nu au fost identificați/);
    expect(result.recommendation).toMatch(/nu garantează/i);
  });
});
