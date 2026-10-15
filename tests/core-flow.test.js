import { describe, it, expect } from 'vitest';
import { createHarness, warnId, EXT_ID } from './fake-chrome.js';
import { MSG } from '../src/lib/messages.js';

const CONFIRMED = 'https://confirmed-malware.sentinel-test.example/payload';

async function warnedTab(h, url = CONFIRMED, tabId = 1) {
  await h.core.onBeforeNavigate({ tabId, frameId: 0, url });
  const wu = h.warnUrl();
  expect(wu).toBeTruthy();
  return warnId(wu);
}

describe('pagina de avertizare înainte de navigare', () => {
  it('amenințare confirmată: tab-ul este redirecționat către pagina locală de avertizare', async () => {
    const h = createHarness();
    const id = await warnedTab(h);
    expect(h.chrome.calls.tabsUpdate[0].url).toMatch(new RegExp(`^chrome-extension://${EXT_ID}/src/pages/warning/warning.html\\?id=`));
    expect(h.chrome.calls.tabsUpdate[0].url).not.toContain('malware'); // URL-ul destinației NU este în parametrii paginii de avertizare
    const r = await h.core.handleMessage({ type: MSG.GET_WARNING, id }, h.extSender());
    expect(r.ok).toBe(true);
    expect(r.warning.confirmed).toBe(true);
    expect(r.warning.level).toBe('DANGEROUS');
    expect(r.warning.sources[0].status).toBe('malicious');
    expect(r.warning.userExplanation).toMatch(/identificat/);
    expect(r.warning.bypass.mode).toBe('typed');
  });

  it('un URL legitim nu declanșează avertizare', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://www.google.com/' });
    expect(h.warnUrl()).toBeUndefined();
  });

  it('6. redirecționare de server către un domeniu confirmat: avertizare + indicator de redirecționare', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://link-scurt.example-news.ro/abc' });
    expect(h.warnUrl()).toBeUndefined();
    await h.core.onCommitted({ tabId: 1, frameId: 0, url: CONFIRMED, transitionQualifiers: ['server_redirect'] });
    const wu = h.warnUrl(); expect(wu).toBeTruthy();
    const r = await h.core.handleMessage({ type: MSG.GET_WARNING, id: warnId(wu) }, h.extSender());
    expect(r.warning.indicators.map((i) => i.code)).toContain('redirect-to-flagged');
    const events = (await h.core.handleMessage({ type: MSG.GET_EVENTS }, h.popupSender())).events;
    expect(events[0].level).toBe('DANGEROUS');
  });

  it('6b. parametru de redirecționare către un domeniu confirmat', async () => {
    const h = createHarness();
    const { result } = await h.core.assessUrl('https://site-legit.ro/out?url=' + encodeURIComponent(CONFIRMED));
    expect(result.indicators.map((i) => i.code)).toEqual(expect.arrayContaining(['redirect-parameter', 'redirect-to-flagged']));
    expect(result.level).toBe('DANGEROUS');
  });

  it('subcadrele (frameId≠0) nu produc avertizare pe tab-ul principal', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 5, url: CONFIRMED });
    expect(h.warnUrl()).toBeUndefined();
  });
});

describe('17. încercări de ocolire a paginii de avertizare', () => {
  it('„continuă" prea devreme este respins', async () => {
    const h = createHarness(); const id = await warnedTab(h);
    await h.core.handleMessage({ type: MSG.GET_WARNING, id }, h.extSender());
    const r = await h.core.handleMessage({ type: MSG.GRANT_PASS, id, confirmation: 'confirmed-malware.sentinel-test.example' }, h.extSender());
    expect(r).toEqual({ ok: false, error: 'too-soon' });
  });
  it('confirmare greșită respinsă; confirmare corectă după timpul de gândire acceptată o singură dată', async () => {
    const h = createHarness(); const id = await warnedTab(h);
    await h.core.handleMessage({ type: MSG.GET_WARNING, id }, h.extSender());
    h.clock.advance(9000);
    expect((await h.core.handleMessage({ type: MSG.GRANT_PASS, id, confirmation: 'altceva.ro' }, h.extSender())).error).toBe('confirmation-mismatch');
    const ok = await h.core.handleMessage({ type: MSG.GRANT_PASS, id, confirmation: 'CONFIRMED-malware.sentinel-test.example' }, h.extSender());
    expect(ok.ok).toBe(true);
    expect(h.chrome.calls.tabsUpdate.at(-1).url).toBe(CONFIRMED);
    expect((await h.core.handleMessage({ type: MSG.GRANT_PASS, id, confirmation: 'confirmed-malware.sentinel-test.example' }, h.extSender())).error).toBe('already-used');
  });
  it('după continuare, navigarea în aceeași origine nu mai avertizează, altă origine da; continuarea e jurnalizată', async () => {
    const h = createHarness(); const id = await warnedTab(h);
    await h.core.handleMessage({ type: MSG.GET_WARNING, id }, h.extSender()); h.clock.advance(9000);
    await h.core.handleMessage({ type: MSG.GRANT_PASS, id, confirmation: 'confirmed-malware.sentinel-test.example' }, h.extSender());
    const before = h.chrome.calls.tabsUpdate.length;
    h.clock.advance(5000);
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: CONFIRMED + '?x=1' });
    expect(h.chrome.calls.tabsUpdate.length).toBe(before); // are permis
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://confirmed-phishing.sentinel-test.example/' });
    expect(h.chrome.calls.tabsUpdate.length).toBe(before + 1); // altă origine: avertizare
    await h.core.onBeforeNavigate({ tabId: 2, frameId: 0, url: CONFIRMED });
    expect(h.chrome.calls.tabsUpdate.length).toBe(before + 2); // altă filă: avertizare
    const ev = (await h.core.handleMessage({ type: MSG.GET_EVENTS }, h.popupSender())).events;
    expect(ev.some((e) => e.action === 'user-continued')).toBe(true);
  });
  it('permisul expiră după TTL', async () => {
    const h = createHarness(); const id = await warnedTab(h);
    await h.core.handleMessage({ type: MSG.GET_WARNING, id }, h.extSender()); h.clock.advance(9000);
    await h.core.handleMessage({ type: MSG.GRANT_PASS, id, confirmation: 'confirmed-malware.sentinel-test.example' }, h.extSender());
    h.clock.advance(11 * 60000);
    const n = h.chrome.calls.tabsUpdate.length;
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: CONFIRMED });
    expect(h.chrome.calls.tabsUpdate.length).toBe(n + 1);
  });
  it('un site / content script nu poate acorda permis, citi avertizări sau schimba setări', async () => {
    const h = createHarness(); const id = await warnedTab(h);
    for (const msg of [{ type: MSG.GET_WARNING, id }, { type: MSG.GRANT_PASS, id, confirmation: 'x' }, { type: MSG.ADD_EXCEPTION, host: 'confirmed-malware.sentinel-test.example', scheme: 'https', kind: 'confirmed', acknowledged: true }, { type: MSG.SET_CONFIG, patch: { protection: { enabled: false } } }, { type: MSG.CLEAR_EVENTS }, { type: MSG.GET_CONFIG }]) {
      for (const sender of [h.webSender(), h.contentSender(1, 'https://confirmed-malware.sentinel-test.example/')]) {
        expect((await h.core.handleMessage(msg, sender)).error, `${msg.type}`).toBe('forbidden-sender');
      }
    }
    expect((await h.core.handleMessage({ type: MSG.GET_EXCEPTIONS }, h.popupSender())).exceptions).toEqual([]);
    expect((await h.core.getConfig()).protection.enabled).toBe(true);
  });
  it('avertizarea nu funcționează din subcadru (anti-clickjacking) și nici din altă filă', async () => {
    const h = createHarness(); const id = await warnedTab(h, CONFIRMED, 1);
    expect((await h.core.handleMessage({ type: MSG.GET_WARNING, id }, h.extSender(1, 3))).error).toBe('frame-not-allowed');
    expect((await h.core.handleMessage({ type: MSG.GET_WARNING, id }, h.extSender(99, 0))).error).toBe('wrong-tab');
    h.clock.advance(9000);
    expect((await h.core.handleMessage({ type: MSG.GRANT_PASS, id, confirmation: 'confirmed-malware.sentinel-test.example' }, h.extSender(99, 0))).error).toBe('wrong-tab');
  });
  it('conținutul avertizării nu depinde de parametrii URL (id invalid / inexistent)', async () => {
    const h = createHarness();
    expect((await h.core.handleMessage({ type: MSG.GET_WARNING, id: '<img src=x onerror=alert(1)>' }, h.extSender())).error).toBe('invalid-payload');
    expect((await h.core.handleMessage({ type: MSG.GET_WARNING, id: 'deadbeef-dead-beef' }, h.extSender())).error).toBe('not-found');
  });
  it('politica „niciodată" blochează continuarea pentru amenințări confirmate', async () => {
    const h = createHarness();
    await h.core.handleMessage({ type: MSG.SET_CONFIG, patch: { policy: { confirmedBypass: 'never' } } }, h.popupSender());
    const id = await warnedTab(h);
    await h.core.handleMessage({ type: MSG.GET_WARNING, id }, h.extSender()); h.clock.advance(20000);
    expect((await h.core.handleMessage({ type: MSG.GRANT_PASS, id, confirmation: 'confirmed-malware.sentinel-test.example' }, h.extSender())).error).toBe('policy-denies');
  });
  it('„Înapoi la siguranță" navighează la pagina nouă și jurnalizează', async () => {
    const h = createHarness(); const id = await warnedTab(h);
    expect((await h.core.handleMessage({ type: MSG.GO_SAFE, id }, h.extSender())).ok).toBe(true);
    expect(h.chrome.calls.tabsUpdate.at(-1).url).toBe('chrome://newtab/');
  });
});

describe('excepții (liste de încredere)', () => {
  it('excepția pentru amenințare confirmată cere confirmare explicită; una euristică nu o anulează', async () => {
    const h = createHarness();
    const host = 'confirmed-malware.sentinel-test.example';
    expect((await h.core.handleMessage({ type: MSG.ADD_EXCEPTION, host, scheme: 'https', kind: 'heuristic' }, h.popupSender())).error).toBe('confirmed-requires-ack');
    expect((await h.core.handleMessage({ type: MSG.ADD_EXCEPTION, host, scheme: 'https', kind: 'confirmed', acknowledged: true, ttlDays: 7 }, h.popupSender())).ok).toBe(true);
    const { result } = await h.core.assessUrl(`https://${host}/`);
    expect(result.level).toBe('DANGEROUS'); expect(result.confirmed).toBe(true); expect(result.warn).toBe(false);
    // protocolul diferit și subdomeniile NU sunt acoperite
    expect((await h.core.assessUrl(`http://${host}/`)).result.warn).toBe(true);
    expect((await h.core.assessUrl(`https://sub.${host}/`)).result.warn).toBe(true);
    // ștergere
    await h.core.handleMessage({ type: MSG.REMOVE_EXCEPTION, host, scheme: 'https' }, h.popupSender());
    expect((await h.core.assessUrl(`https://${host}/`)).result.warn).toBe(true);
  });
  it('excepție euristică: dezactivează avertizarea, indicatorii rămân vizibili; expiră', async () => {
    const h = createHarness();
    const url = 'https://paypal-secure-login.com/signin';
    expect((await h.core.assessUrl(url)).result.level).not.toBe('SAFE');
    await h.core.handleMessage({ type: MSG.ADD_EXCEPTION, host: 'paypal-secure-login.com', scheme: 'https', kind: 'heuristic', ttlDays: 1 }, h.popupSender());
    const r = (await h.core.assessUrl(url)).result;
    expect(r.exception.kind).toBe('heuristic'); expect(r.warn).toBe(false); expect(r.indicators.length).toBeGreaterThan(0);
    h.clock.advance(2 * 86400000);
    expect((await h.core.assessUrl(url)).result.exception).toBeNull();
  });
});

describe('14. mesaje manipulate între content script și service worker', () => {
  const good = { permissions: {}, api: ['geolocation'], requests: {}, net: { observed: [], declared: [] }, forms: {}, text: [], hints: {} };
  it('acceptă observație validă de la propriul content script', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example-shop.ro/' });
    expect((await h.core.handleMessage({ type: MSG.OBSERVATION, snapshot: good }, h.contentSender())).ok).toBe(true);
  });
  it.each([
    ['expeditor fără id de extensie', (h) => h.webSender()],
    ['expeditor fără tab', () => ({ id: EXT_ID, url: 'https://x.ro/', frameId: 0 })],
    ['expeditor cu URL non-web', () => ({ id: EXT_ID, url: 'file:///etc/passwd', tab: { id: 1 }, frameId: 0 })]
  ])('respinge: %s', async (_n, mk) => {
    const h = createHarness();
    const r = await h.core.handleMessage({ type: MSG.OBSERVATION, snapshot: good }, mk(h));
    expect(r.ok).toBe(false);
  });
  it('respinge mesaje malformate / tipuri necunoscute / payload-uri ostile', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example-shop.ro/' });
    for (const m of [null, 'str', 42, {}, { type: 7 }, { type: 'ss.nope' }, { type: MSG.OBSERVATION, snapshot: 'x' }, { type: MSG.OBSERVATION, snapshot: null }, { type: MSG.OBSERVATION }]) {
      expect((await h.core.handleMessage(m, h.contentSender())).ok).toBe(false);
    }
    const r = await h.core.handleMessage({ type: 'ss.nope' }, h.popupSender()); expect(r.error).toBe('unknown-type');
  });
  it('sanitizează câmpurile: valori ostile sunt eliminate sau limitate, câmpurile necunoscute ignorate', async () => {
    const { validateSnapshot } = await import('../src/lib/messages.js');
    const r = validateSnapshot({
      __proto__: { polluted: true }, isAdmin: true, clipboardCommandLike: 1e12, api: ['geolocation', '<script>', 5],
      requests: { geolocation: { count: -5, granted: 'x', denied: 1e9 }, evil: { count: 1 } },
      net: { observed: [{ host: '<img src=x onerror=alert(1)>', type: 'script', count: 1 }, { host: 'cdn.example.com', type: 'nu-exista', count: 3, withBody: 2 }, { host: 'a'.repeat(300) }], declared: [{ host: 'javascript:alert(1)', kind: 'script' }] },
      forms: { passwordFields: 9999999, crossSiteActions: [{ host: 'ok.example.com', hasPassword: 'yes' }, { host: '../../etc' }] },
      text: ['virus-warning', 'rm -rf /'], hints: { title: 'Titlu‮\u0000 periculos'.padEnd(500, 'x'), hasMap: 'true' }
    });
    expect(r.ok).toBe(true);
    const s = r.snapshot;
    expect(s.api).toEqual(['geolocation']);
    expect(s.requests.evil).toBeUndefined();
    expect(s.requests.geolocation.count).toBe(0); expect(s.requests.geolocation.denied).toBe(1000);
    expect(s.clipboardCommandLike).toBe(1000);
    expect(s.net.observed).toEqual([{ host: 'cdn.example.com', type: 'other', count: 3, withBody: 2 }]);
    expect(s.net.declared).toEqual([]);
    expect(s.forms.passwordFields).toBe(500);
    expect(s.forms.crossSiteActions).toEqual([{ host: 'ok.example.com', hasPassword: false }]);
    expect(s.text).toEqual(['virus-warning']);
    expect(s.hints.title.length).toBe(120); expect(s.hints.title).not.toMatch(/[‮\u0000]/); expect(s.hints.hasMap).toBe(false);
    expect(s.polluted).toBeUndefined(); expect(s.isAdmin).toBeUndefined();
  });
  it('limitare de rată per tab (flood)', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example-shop.ro/' });
    let limited = 0;
    for (let i = 0; i < 60; i++) if ((await h.core.handleMessage({ type: MSG.OBSERVATION, snapshot: good }, h.contentSender())).error === 'rate-limited') limited++;
    expect(limited).toBeGreaterThan(10);
  });
  it('observația de la un document de altă origine decât navigarea curentă este ignorată (document vechi / spoofing)', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example-shop.ro/' });
    expect((await h.core.handleMessage({ type: MSG.OBSERVATION, snapshot: good }, h.contentSender(1, 'https://alt-site.ro/'))).error).toBe('stale-document');
  });
  it('observațiile falsificate nu pot produce „amenințare confirmată" pe un domeniu legitim', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://example-shop.ro/' });
    const evil = { ...good, requests: { geolocation: { count: 999, granted: 999, denied: 0, errors: 0, noGesture: 999 }, 'clipboard-read': { count: 999, granted: 999, denied: 0, errors: 0, noGesture: 999 } }, clipboardCommandLike: 1000, text: ['virus-warning', 'run-command', 'disable-protection'], windowOpens: { total: 999, noGesture: 999 }, forms: { passwordFields: 3 } };
    await h.core.handleMessage({ type: MSG.OBSERVATION, snapshot: evil }, h.contentSender());
    const rep = await h.core.handleMessage({ type: MSG.GET_TAB_REPORT, tabId: 1, url: 'https://example-shop.ro/' }, h.popupSender());
    expect(rep.confirmed).toBe(false);
    expect(['SUSPICIOUS', 'SAFE']).toContain(rep.level); // plafonat: comportamentul singur nu depășește „Suspect"
    expect(rep.level).not.toBe('DANGEROUS');
  });
});

describe('18. tokenuri și parametri sensibili', () => {
  it('jurnalul nu conține tokenuri, credențiale sau fragmente', async () => {
    const h = createHarness();
    const url = 'https://admin:Parola123@paypal-secure-login.com/signin?access_token=abcdefghijklmnopqrstuvwxyz123456&session=SID99&q=cautare#id_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig';
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url });
    const events = (await h.core.handleMessage({ type: MSG.GET_EVENTS }, h.popupSender())).events;
    expect(events.length).toBeGreaterThan(0);
    const dump = JSON.stringify(events) + JSON.stringify(await h.chrome.storage.local.get(null));
    for (const secret of ['Parola123', 'abcdefghijklmnopqrstuvwxyz123456', 'SID99', 'eyJhbGciOiJIUzI1NiJ9', 'id_token']) expect(dump, secret).not.toContain(secret);
    expect(dump).toContain('cautare'); // parametrii nesensibili rămân (mod implicit)
  });
  it('modul „doar domeniu" elimină și parametrii nesensibili', async () => {
    const h = createHarness();
    await h.core.handleMessage({ type: MSG.SET_CONFIG, patch: { privacy: { logUrlMode: 'host-only' } } }, h.popupSender());
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://paypal-secure-login.com/signin?q=cautare' });
    const events = (await h.core.handleMessage({ type: MSG.GET_EVENTS }, h.popupSender())).events;
    expect(events[0].url).toBe('https://paypal-secure-login.com/');
  });
  it('exportul nu conține chei API', async () => {
    const h = createHarness();
    await h.core.handleMessage({ type: MSG.SET_CONFIG, patch: { reputation: { providers: { urlhaus: { enabled: true, consent: true, authKey: 'SECRET-KEY-ABC123456789' } } } } }, h.popupSender());
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://paypal-secure-login.com/' });
    const exp = JSON.stringify((await h.core.handleMessage({ type: MSG.EXPORT_EVENTS, detail: 'full' }, h.popupSender())).data);
    const cfg = JSON.stringify(await h.core.handleMessage({ type: MSG.GET_CONFIG }, h.popupSender()));
    expect(exp).not.toContain('SECRET-KEY'); expect(cfg).not.toContain('SECRET-KEY'); // nici UI-ul nu primește cheia înapoi
  });
  it('statistici fără date => total 0 (nimic inventat)', async () => {
    const h = createHarness();
    const s = (await h.core.handleMessage({ type: MSG.GET_STATS }, h.popupSender())).stats;
    expect(s.total).toBe(0); expect(s.analyzed).toBe(0); expect(s.topIndicators).toEqual([]);
  });
  it('paginile cu risc redus nu sunt jurnalizate (doar contorizate)', async () => {
    const h = createHarness();
    await h.core.onBeforeNavigate({ tabId: 1, frameId: 0, url: 'https://www.google.com/search?q=secret-query' });
    const s = (await h.core.handleMessage({ type: MSG.GET_STATS }, h.popupSender())).stats;
    expect(s.total).toBe(0); expect(s.analyzed).toBe(1);
    expect(JSON.stringify(await h.chrome.storage.local.get(null))).not.toContain('secret-query');
  });
});
