import { describe, it, expect } from 'vitest';
import { validateSnapshot } from '../src/lib/messages.js';
import { analyzeBehavior } from '../src/lib/behavior.js';
import { combinePage, evaluate } from '../src/lib/risk-engine.js';
import { analyzeUrl } from '../src/lib/url-analyzer.js';
import { brandsMentionedIn } from '../src/lib/brands.js';
import { makeLists, cfg } from './helpers.js';

const base = (over = {}) => validateSnapshot({ permissions: {}, api: ['geolocation', 'mediaDevices', 'clipboard', 'notifications'], requests: {}, net: { observed: [], declared: [] }, forms: {}, text: [], hints: {}, ...over }).snapshot;
const ctx = (over = {}) => ({ pageHost: 'exemplu-site.ro', pageScheme: 'https:', urlLevel: 'SAFE', lists: makeLists(), titleBrands: [], ...over });
const find = (b, id) => b.findings.find((f) => f.id === id);
const req = (n = 1, o = {}) => ({ count: n, granted: 0, denied: 0, errors: 0, noGesture: 0, ...o });

describe('permisiuni: API disponibil ≠ cerere ≠ acordat ≠ utilizare confirmată', () => {
  it('doar API disponibil: fără constatare, nivel „api-available", utilizare neconfirmată', () => {
    const b = analyzeBehavior(base(), ctx());
    expect(b.findings).toEqual([]);
    const cam = b.permissions.find((p) => p.key === 'camera');
    expect(cam.level).toBe('api-available'); expect(cam.requested).toBe(false); expect(cam.usageConfirmed).toBe(false);
  });
  it('7. cameră/microfon cerute pe pagină de autentificare: suspect, cu explicație', () => {
    const b = analyzeBehavior(base({ requests: { camera: req(1, { granted: 1 }), microphone: req(1) }, forms: { passwordFields: 1 } }), ctx());
    const cam = find(b, 'perm-camera');
    expect(cam.classification).toBe('SUSPICIOUS');
    expect(cam.explainUser).toMatch(/Dacă aprobi cererea.*imagine video/);
    expect(cam.explainUser).toMatch(/neobișnuită pe o pagină care cere o parolă/);
    expect(cam.technical.level).toBe('access-obtained');
    expect(find(b, 'perm-microphone').technical.level).toBe('requested');
    expect(b.permissions.find((p) => p.key === 'camera').level).toBe('access-obtained');
  });
  it('7b. camera pe o pagină cu <video> este legitimă', () => {
    const b = analyzeBehavior(base({ requests: { camera: req(1, { granted: 1 }), microphone: req(1, { granted: 1 }) }, hints: { hasVideo: true } }), ctx());
    expect(find(b, 'perm-camera').classification).toBe('LEGITIMATE'); expect(b.score).toBe(0);
  });
  it('8. locația: justificată pe hartă, neobișnuită pe pagină simplă de autentificare', () => {
    const map = analyzeBehavior(base({ requests: { geolocation: req(1) }, hints: { hasMap: true } }), ctx());
    expect(find(map, 'perm-geolocation').classification).toBe('LEGITIMATE');
    const login = analyzeBehavior(base({ requests: { geolocation: req(1) }, forms: { passwordFields: 1 } }), ctx());
    const g = find(login, 'perm-geolocation');
    expect(g.classification).toBe('SUSPICIOUS'); expect(g.explainUser).toMatch(/poziția ta/); expect(g.explainUser).toMatch(/neobișnuită/);
  });
  it('cerere refuzată: nu e alarmantă', () => {
    const b = analyzeBehavior(base({ requests: { geolocation: req(1, { denied: 1 }) }, forms: { passwordFields: 1 } }), ctx());
    const g = find(b, 'perm-geolocation'); expect(g.score).toBe(0); expect(g.explainUser).toMatch(/refuzată/);
  });
  it('permisiune deja acordată în browser, fără cerere în pagină, e raportată distinct', () => {
    const b = analyzeBehavior(base({ permissions: { notifications: 'granted' } }), ctx());
    const n = find(b, 'perm-notifications'); expect(n.technical.level).toBe('permission-granted'); expect(n.title).toMatch(/permisiune acordată/);
  });
  it('9. citirea clipboardului: neobișnuită; scrierea unei comenzi: ClickFix, fără a stoca textul', () => {
    const r = analyzeBehavior(base({ requests: { 'clipboard-read': req(2, { granted: 2 }) } }), ctx());
    expect(find(r, 'perm-clipboard-read').classification).toBe('SUSPICIOUS');
    const w = analyzeBehavior(base({ clipboardCommandLike: 1 }), ctx());
    const f = find(w, 'clipboard-command'); expect(f.classification).toBe('SUSPICIOUS'); expect(f.technical.contentStored).toBe(false);
    expect(f.explainUser).toMatch(/nu a fost salvat/);
  });
  it('cerere fără gest al utilizatorului crește suspiciunea', () => {
    const a = analyzeBehavior(base({ requests: { notifications: req(1) } }), ctx());
    const b = analyzeBehavior(base({ requests: { notifications: req(1, { noGesture: 1 }) } }), ctx());
    expect(b.score).toBeGreaterThan(a.score); expect(find(b, 'perm-notifications').explainUser).toMatch(/fără o acțiune evidentă/);
  });
});

describe('formulare și conținut', () => {
  it('10. formular de autentificare suspect: brand în titlu, domeniu neoficial, destinație cross-site', () => {
    const snap = base({ forms: { passwordFields: 1, crossSiteActions: [{ host: 'colector.example.net', hasPassword: true }], submits: [{ host: 'colector.example.net', hasPassword: true }] }, hints: { title: 'Autentificare PayPal - Contul meu' } });
    const b = analyzeBehavior(snap, ctx({ pageHost: 'paypal-verificare-cont.com', titleBrands: brandsMentionedIn('Autentificare PayPal - Contul meu') }));
    for (const id of ['login-impersonation', 'password-form-cross-site', 'password-submit-cross-site']) expect(find(b, id)?.classification, id).toBe('SUSPICIOUS');
    expect(find(b, 'login-impersonation').explainUser).toMatch(/ar putea ajunge la operatorul site-ului/);
    expect(find(b, 'password-submit-cross-site').technical.valuesRead).toBe(false);
  });
  it('10b. autentificare legitimă pe domeniul oficial: fără constatări de imitație', () => {
    const b = analyzeBehavior(base({ forms: { passwordFields: 1 } }), ctx({ pageHost: 'www.paypal.com', titleBrands: brandsMentionedIn('Log in to PayPal') }));
    expect(find(b, 'login-impersonation')).toBeUndefined();
  });
  it('formular cu parolă care trimite către același domeniu înregistrabil nu e cross-site', () => {
    const b = analyzeBehavior(base({ forms: { passwordFields: 1, crossSiteActions: [{ host: 'auth.exemplu-site.ro', hasPassword: true }] } }), ctx());
    expect(find(b, 'password-form-cross-site')).toBeUndefined();
  });
  it('parolă / card pe HTTP', () => {
    const b = analyzeBehavior(base({ forms: { passwordFields: 1, cardFields: 2 } }), ctx({ pageScheme: 'http:' }));
    expect(find(b, 'password-over-http')).toBeTruthy(); expect(find(b, 'card-over-http')).toBeTruthy();
  });
  it('mesaje scareware / comenzi / dezactivare protecții', () => {
    const b = analyzeBehavior(base({ text: ['virus-warning', 'run-command', 'disable-protection', 'tech-support', 'extension-install'] }), ctx());
    expect(find(b, 'text-virus-warning').explainUser).toMatch(/nu poate ști/);
    expect(find(b, 'text-extension-install').classification).toBe('POTENTIAL');
    expect(b.score).toBeGreaterThanOrEqual(60);
  });
  it('ferestre repetate fără gest / descărcări programatice', () => {
    const b = analyzeBehavior(base({ windowOpens: { total: 5, noGesture: 4 }, downloads: { total: 1, noGesture: 1 } }), ctx());
    expect(find(b, 'window-opens').classification).toBe('SUSPICIOUS'); expect(find(b, 'page-download').classification).toBe('SUSPICIOUS');
    const calm = analyzeBehavior(base({ windowOpens: { total: 1, noGesture: 0 } }), ctx());
    expect(find(calm, 'window-opens').classification).toBe('POTENTIAL');
  });
});

describe('rețea: domenii terțe', () => {
  const hosts = (n, extra = []) => [...Array.from({ length: n }, (_, i) => ({ host: `cdn${i}.servicii${i}.com`, type: 'script', count: 2 })), ...extra];
  it('15. site legitim cu multe scripturi terțe: rămâne „Risc redus", cu explicație de legitimitate', () => {
    const obs = hosts(18, [{ host: 'www.google-analytics.com', type: 'script', count: 3 }, { host: 'connect.facebook.net', type: 'script', count: 1 }, { host: 'api.stripe.com', type: 'fetch', count: 4, withBody: 4 }]);
    const snap = base({ net: { observed: obs, declared: [] } });
    const b = analyzeBehavior(snap, ctx());
    expect(find(b, 'many-third-parties').classification).toBe('LEGITIMATE');
    expect(find(b, 'trackers').explainUser).toMatch(/nu indică, singur, o amenințare/);
    expect(find(b, 'third-party-data-sends').explainUser).toMatch(/nu poate determina ce date conțin/);
    const url = evaluate({ analysis: analyzeUrl('https://exemplu-site.ro/'), reputation: [], config: cfg });
    const page = combinePage(url, b, cfg);
    expect(page.level).toBe('SAFE'); expect(page.confirmed).toBe(false);
  });
  it('observat vs dedus: separate în rezultat și în clasificare', () => {
    const lists = makeLists();
    const snap = base({ net: { observed: [{ host: 'confirmed-malware.sentinel-test.example', type: 'script', count: 1 }], declared: [{ host: 'confirmed-phishing.sentinel-test.example', kind: 'iframe' }, { host: 'cdn.exemplu-ok.com', kind: 'script' }] } });
    const b = analyzeBehavior(snap, ctx({ lists }));
    const obs = b.findings.find((f) => f.id.startsWith('third-party-confirmed-'));
    const decl = b.findings.find((f) => f.id.startsWith('third-party-declared-listed-'));
    expect(obs.classification).toBe('CONFIRMED'); expect(obs.evidence).toBe('observed');
    expect(decl.classification).toBe('SUSPICIOUS'); expect(decl.evidence).toBe('declared'); expect(decl.explainUser).toMatch(/neconfirmat/);
    expect(b.thirdParties.observed.map((x) => x.registrable)).toContain('sentinel-test.example');
    expect(b.thirdParties.declaredOnly.map((x) => x.registrable)).toEqual(expect.arrayContaining(['exemplu-ok.com']));
    const url = evaluate({ analysis: analyzeUrl('https://exemplu-site.ro/'), reputation: [], config: cfg });
    const page = combinePage(url, b, cfg);
    expect(page.level).toBe('DANGEROUS'); expect(page.confirmed).toBe(true);
  });
  it('doar referința declarată către un domeniu listat NU face pagina „confirmată"', () => {
    const snap = base({ net: { observed: [], declared: [{ host: 'confirmed-phishing.sentinel-test.example', kind: 'script' }] } });
    const b = analyzeBehavior(snap, ctx());
    const page = combinePage(evaluate({ analysis: analyzeUrl('https://exemplu-site.ro/'), reputation: [], config: cfg }), b, cfg);
    expect(page.confirmed).toBe(false); expect(page.level).toBe('SUSPICIOUS');
  });
  it('domeniul propriu și subdomeniile lui nu sunt „terțe"', () => {
    const b = analyzeBehavior(base({ net: { observed: [{ host: 'static.exemplu-site.ro', type: 'script', count: 1 }], declared: [] } }), ctx());
    expect(b.thirdParties.observed).toEqual([]);
  });
  it('16. fără date: rezultat gol, nu inventat', () => {
    const b = analyzeBehavior(base(), ctx());
    expect(b.findings).toEqual([]); expect(b.score).toBe(0);
  });
});

describe('comportament nu escaladează la DANGEROUS fără confirmare', () => {
  it('scor comportamental maxim pe un domeniu SAFE ⇒ cel mult SUSPICIOUS', () => {
    const snap = base({ requests: { geolocation: req(5, { granted: 5, noGesture: 5 }), camera: req(1, { granted: 1 }), 'clipboard-read': req(3, { granted: 3 }) }, clipboardCommandLike: 5, text: ['virus-warning', 'run-command'], windowOpens: { total: 9, noGesture: 9 }, forms: { passwordFields: 2 } });
    const b = analyzeBehavior(snap, ctx());
    const page = combinePage(evaluate({ analysis: analyzeUrl('https://exemplu-site.ro/'), reputation: [], config: cfg }), b, cfg);
    expect(b.score).toBeGreaterThan(60); expect(page.level).toBe('SUSPICIOUS'); expect(page.confirmed).toBe(false);
  });
});
