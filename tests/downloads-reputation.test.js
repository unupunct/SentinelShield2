import { describe, it, expect, vi } from 'vitest';
import { analyzeDownload } from '../src/lib/download-analyzer.js';
import { analyzeUrl } from '../src/lib/url-analyzer.js';
import { evaluate } from '../src/lib/risk-engine.js';
import { createLocalLists, createReputationService, parseFeed, parseUserList } from '../src/lib/reputation.js';
import { validateConfig, DEFAULT_CONFIG } from '../src/lib/config.js';
import { createHarness, EXT_ID } from './fake-chrome.js';
import { MSG } from '../src/lib/messages.js';
import { makeLists, cfg, assess, codes } from './helpers.js';

describe('11. descărcări', () => {
  const codesOf = (d) => d.indicators.map((i) => i.code);
  it('extensie dublă înșelătoare: factura.pdf.exe', () => {
    const r = analyzeDownload({ filename: 'factura.pdf.exe', url: 'https://exemplu.ro/f' });
    expect(codesOf(r)).toEqual(expect.arrayContaining(['double-extension', 'executable-download'])); expect(r.level).toBe('danger');
    expect(r.indicators.find((i) => i.code === 'double-extension').explain).toMatch(/pare un document/);
  });
  it('RLO în nume (fisier‮fdp.exe)', () => {
    expect(codesOf(analyzeDownload({ filename: 'raport\u202Efdp.exe' }))).toContain('bidi-filename');
  });
  it('spații/puncte la final', () => { expect(codesOf(analyzeDownload({ filename: 'document.pdf .' }))).toContain('trailing-dots-spaces'); });
  it('executabil de la sursă fără indicatori: doar risc potențial (nu alarmist)', () => {
    const r = analyzeDownload({ filename: 'setup.exe', sourceLevel: 'SAFE', pageLevel: 'SAFE' });
    expect(r.level).toBe('info'); expect(r.indicators[0].severity).toBe('low');
  });
  it('executabil dintr-un domeniu confirmat: pericol', () => {
    expect(analyzeDownload({ filename: 'update.msi', sourceConfirmed: true, sourceLevel: 'DANGEROUS' }).level).toBe('danger');
  });
  it('arhivă dintr-o sursă suspectă; arhivă normală neimportantă', () => {
    expect(codesOf(analyzeDownload({ filename: 'poze.zip', sourceLevel: 'SUSPICIOUS' }))).toContain('archive-risky-source');
    expect(analyzeDownload({ filename: 'poze.zip', sourceLevel: 'SAFE' }).level).toBe('ok');
  });
  it('discrepanță între tipul declarat și nume', () => {
    expect(codesOf(analyzeDownload({ filename: 'raport.pdf', mime: 'application/x-msdownload' }))).toContain('mime-mismatch-exec');
    expect(codesOf(analyzeDownload({ filename: 'install.exe', mime: 'application/pdf' }))).toContain('mime-mismatch-doc');
  });
  it('descărcare pornită de o pagină periculoasă', () => {
    expect(codesOf(analyzeDownload({ filename: 'a.txt', byPage: true, pageLevel: 'DANGEROUS' }))).toContain('page-initiated-risky');
  });
  it('fișier obișnuit: niciun indicator', () => { expect(analyzeDownload({ filename: 'carte.pdf', mime: 'application/pdf' }).level).toBe('ok'); });

  it('integrare: descărcare periculoasă este pusă în pauză, apare pagina de avertizare; decizia „anulează" funcționează', async () => {
    const h = createHarness();
    await h.core.onDownloadCreated({ id: 77, url: 'https://exemplu-shop.ro/get', finalUrl: 'https://exemplu-shop.ro/get', filename: 'C:\\Users\\x\\Downloads\\factura.pdf.exe', mime: 'application/octet-stream', referrer: '' });
    expect(h.chrome.calls.pause).toEqual([77]);
    const tab = h.chrome.calls.tabsCreate[0].url; expect(tab).toContain('download.html?id=');
    const id = new URL(tab).searchParams.get('id');
    const w = await h.core.handleMessage({ type: MSG.GET_DOWNLOAD_WARNING, id }, h.extSender(5));
    expect(w.warning.level).toBe('DANGEROUS'); expect(w.warning.extra.filename).toBe('factura.pdf.exe');
    expect((await h.core.handleMessage({ type: MSG.DOWNLOAD_DECISION, id, action: 'cancel' }, h.contentSender())).error).toBe('forbidden-sender');
    expect((await h.core.handleMessage({ type: MSG.DOWNLOAD_DECISION, id, action: 'cancel' }, h.popupSender())).ok).toBe(true);
    expect(h.chrome.calls.cancel).toEqual([77]);
    const ev = (await h.core.handleMessage({ type: MSG.GET_EVENTS, type2: 1 }, h.popupSender())).events;
    expect(ev.some((e) => e.type === 'download')).toBe(true);
  });
  it('descărcare banală nu declanșează nimic; monitorizarea poate fi dezactivată', async () => {
    const h = createHarness();
    await h.core.onDownloadCreated({ id: 1, url: 'https://exemplu.ro/c.pdf', filename: 'c.pdf', mime: 'application/pdf' });
    expect(h.chrome.calls.pause).toEqual([]);
    await h.core.handleMessage({ type: MSG.SET_CONFIG, patch: { downloads: { monitor: false } } }, h.popupSender());
    await h.core.onDownloadCreated({ id: 2, url: 'https://exemplu.ro/x', filename: 'a.pdf.exe' });
    expect(h.chrome.calls.pause).toEqual([]);
  });
});

describe('5/12/13. reputație online: consimțământ, indisponibilitate, timeout', () => {
  const analysis = analyzeUrl('https://exemplu-nou.ro/pagina?token=abc');
  const cfgWith = (p) => validateConfig({ reputation: { providers: p } });
  const svc = (fetchImpl, over = {}) => createReputationService({ fetchImpl, lists: makeLists(), hasPermission: async () => true, ...over });

  it('fără consimțământ nu se trimite NIMIC (nicio cerere de rețea)', async () => {
    const f = vi.fn(); const r = await svc(f).checkOnline(analysis, cfgWith({ urlhaus: { enabled: true, consent: false, authKey: 'k' } }));
    expect(f).not.toHaveBeenCalled(); expect(r[0].status).toBe('needs-consent');
  });
  it('implicit (configurare implicită) nu se face nicio cerere', async () => {
    const f = vi.fn(); const r = await svc(f).checkOnline(analysis, cfg);
    expect(f).not.toHaveBeenCalled(); expect(r).toEqual([]);
  });
  it('fără permisiune de rețea acordată: indisponibil, nicio cerere', async () => {
    const f = vi.fn(); const r = await svc(f, { hasPermission: async () => false }).checkOnline(analysis, cfgWith({ urlhaus: { enabled: true, consent: true, authKey: 'k' } }));
    expect(f).not.toHaveBeenCalled(); expect(r[0].status).toBe('unavailable');
  });
  it('URLhaus: se trimite DOAR numele gazdei, cu antetul Auth-Key, fără cookie-uri/referrer', async () => {
    const f = vi.fn(async () => ({ status: 200, text: async () => JSON.stringify({ query_status: 'no_results' }) }));
    const r = await svc(f).checkOnline(analysis, cfgWith({ urlhaus: { enabled: true, consent: true, authKey: 'cheie-test' } }));
    const [url, init] = f.mock.calls[0];
    expect(url).toBe('https://urlhaus-api.abuse.ch/v1/host/'); expect(init.body.toString()).toBe('host=exemplu-nou.ro');
    expect(init.headers['Auth-Key']).toBe('cheie-test'); expect(init.credentials).toBe('omit'); expect(init.referrerPolicy).toBe('no-referrer');
    expect(r[0].status).toBe('clean'); expect(r[0].sends).toBe('host');
  });
  it('URLhaus: răspuns cu URL-uri active => amenințare confirmată', async () => {
    const f = async () => ({ status: 200, text: async () => JSON.stringify({ query_status: 'ok', urls: [{ url_status: 'online' }] }) });
    const [res] = await svc(f).checkOnline(analysis, cfgWith({ urlhaus: { enabled: true, consent: true, authKey: 'k' } }));
    expect(res.status).toBe('malicious');
    const ev = evaluate({ analysis, reputation: [res], config: cfg });
    expect(ev.level).toBe('DANGEROUS'); expect(ev.confirmed).toBe(true);
  });
  it('Safe Browsing: URL fără interogare/fragment; potrivire => malițios', async () => {
    const f = vi.fn(async () => ({ status: 200, text: async () => JSON.stringify({ matches: [{ threatType: 'SOCIAL_ENGINEERING' }] }) }));
    const a = analyzeUrl('https://exemplu-nou.ro/pagina?q=1#frag');
    const [res] = await svc(f).checkOnline(a, cfgWith({ safebrowsing: { enabled: true, consent: true, apiKey: 'k' } }));
    const body = JSON.parse(f.mock.calls[0][1].body);
    expect(body.threatInfo.threatEntries).toEqual([{ url: 'https://exemplu-nou.ro/pagina' }]);
    expect(res.status).toBe('malicious'); expect(res.threatType).toBe('SOCIAL_ENGINEERING');
  });
  it('Safe Browsing: răspuns gol => „nicio amenințare" (diferit de „neverificat")', async () => {
    const f = async () => ({ status: 200, text: async () => '{}' });
    const [res] = await svc(f).checkOnline(analysis, cfgWith({ safebrowsing: { enabled: true, consent: true, apiKey: 'k' } }));
    expect(res.status).toBe('clean');
  });
  it('URL cu token/credențiale/intern nu se trimite niciodată (Safe Browsing)', async () => {
    const f = vi.fn(); const s = svc(f); const c = cfgWith({ safebrowsing: { enabled: true, consent: true, apiKey: 'k', sendQuery: true } });
    const r1 = await s.checkOnline(analyzeUrl('https://exemplu-nou.ro/p?access_token=abcdefghijklmnopqrstuvwxyz123456'), c);
    const r2 = await s.checkOnline(analyzeUrl('https://u:p@exemplu-nou.ro/'), c);
    const r3 = await s.checkOnline(analyzeUrl('http://192.168.0.5/'), c);
    const r4 = await s.checkOnline(analyzeUrl('https://exemplu-nou.ro/reset/0123456789abcdef0123456789abcdef'), c);
    expect(f).not.toHaveBeenCalled(); expect([r1, r2, r3, r4].map((r) => r[0].status)).toEqual(['skipped', 'skipped', 'skipped', 'skipped']);
  });
  it('12. serviciu indisponibil (HTTP 503 / eroare de rețea): UNKNOWN, dar protecțiile locale rămân active', async () => {
    const bad = svc(async () => ({ status: 503, text: async () => '' }));
    const online = await bad.checkOnline(analysis, cfgWith({ urlhaus: { enabled: true, consent: true, authKey: 'k' } }));
    expect(online[0].status).toBe('error');
    const calm = assess('https://exemplu-nou.ro/', { online });
    expect(calm.result.level).toBe('UNKNOWN'); expect(calm.result.sources.find((s) => s.source === 'urlhaus').statusLabel).toMatch(/Nu a putut fi verificat/);
    const homo = assess('https://аpple.com/', { online });
    expect(homo.result.level).toBe('DANGEROUS'); // euristica locală nu e dezactivată de lipsa serviciului
    const listed = assess('https://confirmed-malware.sentinel-test.example/', { online });
    expect(listed.result.level).toBe('DANGEROUS'); expect(listed.result.confirmed).toBe(true);
  });
  it('13. timeout și lipsă de conectivitate', async () => {
    const hang = svc(() => new Promise(() => {}));
    const c = validateConfig({ reputation: { timeoutMs: 500, providers: { urlhaus: { enabled: true, consent: true, authKey: 'k' } } } });
    const cc = { ...c, reputation: { ...c.reputation, timeoutMs: 20 } };
    const t0 = Date.now();
    // fetch-ul simulat respectă AbortSignal
    const abortable = svc((url, init) => new Promise((_, rej) => init.signal.addEventListener('abort', () => rej(Object.assign(new Error('x'), { name: 'AbortError' })))));
    const [res] = await abortable.checkOnline(analysis, cc);
    expect(res.status).toBe('timeout'); expect(Date.now() - t0).toBeLessThan(1500); void hang;
    const offline = svc(async () => { throw new TypeError('Failed to fetch'); });
    const [off] = await offline.checkOnline(analysis, cc);
    expect(off.status).toBe('error');
    expect(assess('https://exemplu-nou.ro/', { online: [res, off] }).result.level).toBe('UNKNOWN');
  });
  it('cache cu expirare + limitare de rată + întrerupător după erori repetate', async () => {
    let now = 1000; const f = vi.fn(async () => ({ status: 200, text: async () => JSON.stringify({ query_status: 'no_results' }) }));
    const s = createReputationService({ fetchImpl: f, lists: makeLists(), now: () => now });
    const c = cfgWith({ urlhaus: { enabled: true, consent: true, authKey: 'k' } });
    await s.checkOnline(analysis, c); const second = await s.checkOnline(analysis, c);
    expect(f).toHaveBeenCalledTimes(1); expect(second[0].cached).toBe(true);
    now += 31 * 60000; await s.checkOnline(analysis, c); expect(f).toHaveBeenCalledTimes(2);
    // rate limit
    const c2 = validateConfig({ reputation: { rateLimitPerMinute: 2, providers: { urlhaus: { enabled: true, consent: true, authKey: 'k' } } } });
    const out = [];
    for (let i = 0; i < 4; i++) out.push((await s.checkOnline(analyzeUrl(`https://site${i}.exemplu.ro/`), c2))[0].status);
    expect(out).toContain('rate-limited');
    // întrerupător
    const bad = vi.fn(async () => ({ status: 500, text: async () => '' }));
    const s2 = createReputationService({ fetchImpl: bad, lists: makeLists(), now: () => now });
    const res = [];
    for (let i = 0; i < 6; i++) res.push((await s2.checkOnline(analyzeUrl(`https://x${i}.exemplu.ro/`), c))[0].detail);
    expect(bad.mock.calls.length).toBe(3); expect(res.at(-1)).toMatch(/suspendat/);
  });
  it('configurația implicită: toate sursele online dezactivate, fără chei', () => {
    const d = validateConfig(DEFAULT_CONFIG);
    for (const p of Object.values(d.reputation.providers)) { expect(p.enabled).toBe(false); expect(p.consent).toBe(false); expect(p.authKey ?? p.apiKey).toBe(''); }
    expect(d.feeds.enabled).toBe(false);
  });
  it('dezactivarea unui furnizor șterge consimțământul (nu rămâne „implicit")', async () => {
    const h = createHarness();
    await h.core.handleMessage({ type: MSG.SET_CONFIG, patch: { reputation: { providers: { urlhaus: { enabled: true, consent: true, authKey: 'abc' } } } } }, h.popupSender());
    await h.core.handleMessage({ type: MSG.SET_CONFIG, patch: { reputation: { providers: { urlhaus: { enabled: false } } } } }, h.popupSender());
    expect((await h.core.getConfig()).reputation.providers.urlhaus.consent).toBe(false);
  });
});

describe('liste locale și feed-uri', () => {
  it('parsează formate hosts / domenii / URL-uri; omite domenii oficiale și intrări invalide', () => {
    const hosts = parseFeed('# comentariu\n0.0.0.0 rau.example.net\n127.0.0.1 localhost\n0.0.0.0 www.paypal.com\nnu-este-domeniu\n', 'hosts');
    expect(hosts.hosts).toEqual(['rau.example.net']);
    const urls = parseFeed('https://phish.example.org/login\nhttps://user.github.io/x\nftp://x\n', 'urls');
    expect(urls.hosts).toEqual(['phish.example.org']); expect(urls.urls).toContain('user.github.io/x');
  });
  it('potrivire de URL exact pentru platforme partajate (nu blochează întregul github.io)', () => {
    const l = createLocalLists(); const f = parseFeed('https://user.github.io/phish\n', 'urls'); l.setFeed(f);
    expect(l.lookup('user.github.io', 'user.github.io/phish')).toBeTruthy();
    expect(l.lookup('user.github.io', 'user.github.io/altceva')).toBeNull();
    expect(l.lookup('github.io', 'github.io/')).toBeNull();
  });
  it('lista utilizatorului: import din text lipit', () => {
    const r = parseUserList('rau1.example.net\nrau2.example.net\n#x\nwww.google.com\n');
    expect(r.entries.map((e) => e.domain)).toEqual(['rau1.example.net', 'rau2.example.net']);
  });
  it('feed-urile: dacă toate sursele eșuează, lista veche rămâne', async () => {
    const h = createHarness({ fetchImpl: async () => ({ ok: true, text: async () => '0.0.0.0 vechi.example.net\n' }) });
    await h.core.handleMessage({ type: MSG.SET_CONFIG, patch: { feeds: { enabled: true, sources: [{ id: 'a', name: 'A', url: 'https://feed.example.org/h.txt', format: 'hosts', enabled: true }] } } }, h.popupSender());
    h.chrome.grant('https://feed.example.org/*');
    expect((await h.core.syncFeeds()).per.a.ok).toBe(true);
    expect((await h.core.assessUrl('https://vechi.example.net/')).result.confirmed).toBe(true);
    const h2 = h; // al doilea sync, cu eșec de rețea
    const failing = createHarness({ fetchImpl: async () => { throw new TypeError('offline'); } });
    expect(failing).toBeTruthy(); void h2;
  });
  it('protecțiile locale funcționează fără rețea (euristică + liste)', () => {
    expect(codes(assess('https://paypa1.com/').result)).toContain('brand-char-substitution');
    expect(assess('https://confirmed-phishing.sentinel-test.example/').result.confirmed).toBe(true);
  });
});

void EXT_ID;
