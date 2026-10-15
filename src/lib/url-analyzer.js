// Analiza URL-urilor: normalizare + indicatori euristici explicabili.
// Funcție pură: nu face cereri de rețea și nu accesează URL-ul analizat.
import { hostToUnicode } from './punycode.js';
import { splitHost, isIPv4, isIPv6, isPrivateIp, isInternalHost } from './psl.js';
import { scriptsOf, confusableChars, skeleton, leetVariants, editDistance } from './confusables.js';
import { BRANDS, isOfficialFor, isAnyOfficial } from './brands.js';

export const Severity = Object.freeze({ INFO: 'info', LOW: 'low', MEDIUM: 'medium', HIGH: 'high' });
/** Clasificarea unui indicator (cele cinci categorii cerute de produs). */
export const Classification = Object.freeze({
  CONFIRMED: 'CONFIRMED',       // amenințare confirmată (doar din surse de reputație)
  SUSPICIOUS: 'SUSPICIOUS',     // comportament suspect
  POTENTIAL: 'POTENTIAL',       // risc potențial
  LEGITIMATE: 'LEGITIMATE',     // comportament observat, dar legitim
  INSUFFICIENT: 'INSUFFICIENT'  // informații insuficiente
});

const SHORTENERS = new Set(['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 't.ly', 'rb.gy', 'tiny.cc', 'lnkd.in', 'bl.ink', 'v.gd', 'shorte.st', 'adf.ly', 'qr.ae', 'soo.gd', 'clck.ru', 'u.to', 'x.co']);
const ABUSED_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'link', 'gq', 'tk', 'ml', 'ga', 'cf', 'work', 'rest', 'country', 'kim', 'support', 'loan', 'men', 'download', 'racing', 'review', 'stream', 'science', 'party', 'date', 'cam', 'icu', 'buzz', 'monster', 'cyou', 'sbs', 'cfd', 'lol']);
const REDIRECT_PARAMS = /^(url|u|uri|link|redirect|redirect_uri|redirect_url|redir|return|returnto|return_to|returnurl|next|goto|go|dest|destination|continue|target|to|out|forward|callback|r)$/i;
const PHISH_KEYWORDS = /(log-?in|sign-?in|signin|account|verif(y|ication|icare)|secure|securi(ty|tate)|update|confirm|password|passwd|parola|wallet|billing|banking|authenticat|recover|unlock|suspend|cont-?ul|autentificare)/gi;
const DEFAULT_PORTS = { 'http:': '80', 'https:': '443' };

function ind(code, severity, classification, title, explain, technical = {}) {
  return { code, category: 'url', severity, classification, title, explain, technical };
}

/** Extrage autoritatea brută (între `//` și primul `/?#`) pentru a detecta obfuscări pe care parserul URL le normalizează. */
function rawAuthority(raw) {
  const m = /^[a-z][a-z0-9+.-]*:[\\/]{2}([^\\/?#]*)/i.exec(raw.trim());
  return m ? m[1] : '';
}

function rawHostFromAuthority(auth) {
  const at = auth.lastIndexOf('@');
  let h = at >= 0 ? auth.slice(at + 1) : auth;
  if (!h.startsWith('[')) h = h.replace(/:\d*$/, '');
  return h;
}

function isObfuscatedIp(rawHost) {
  if (!/^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$/i.test(rawHost)) return false;
  const parts = rawHost.split('.');
  const canonical = parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
  return !canonical;
}

function hostKeywordsCount(text) {
  const m = text.match(PHISH_KEYWORDS);
  return m ? new Set(m.map((s) => s.toLowerCase())).size : 0;
}

function tryParse(str, base) {
  try { return new URL(str, base); } catch { return null; }
}

/** Parametrii de navigare/redirecționare care conțin URL-uri către alt domeniu. */
function extractRedirectTargets(u, selfRegistrable) {
  const targets = [];
  const consider = (name, value) => {
    if (!REDIRECT_PARAMS.test(name) || !value || value.length > 2048) return;
    let candidate = value;
    for (let i = 0; i < 2; i++) { // inclusiv valori codate de două ori
      if (/^https?%3a/i.test(candidate) || /%2f%2f/i.test(candidate)) {
        try { candidate = decodeURIComponent(candidate); } catch { break; }
      }
    }
    const t = /^(https?:)?\/\//i.test(candidate) ? tryParse(candidate.startsWith('//') ? 'https:' + candidate : candidate) : null;
    if (!t || !/^https?:$/.test(t.protocol)) return;
    const host = t.hostname.toLowerCase().replace(/\.$/, '');
    const reg = splitHost(host).registrable;
    targets.push({ param: name.toLowerCase(), url: t.href, host, registrable: reg, crossSite: reg !== selfRegistrable });
  };
  for (const [k, v] of u.searchParams) consider(k, v);
  if (u.hash.length > 1) {
    const hp = new URLSearchParams(u.hash.slice(1).replace(/^[/?]/, ''));
    for (const [k, v] of hp) consider(k, v);
  }
  return targets.slice(0, 5);
}

function brandIndicators(parts, hostAscii, out, uParts) {
  const { registrable, suffix, subdomain, labels } = parts;
  if (parts.isIp) return;
  // Comparațiile cu brandurile se fac pe forma Unicode a etichetei (nu pe xn--...)
  const uReg = uParts.registrable;
  const regLabel = uReg.slice(0, uReg.length - uParts.suffix.length - 1) || labels[0];
  const regSkel = skeleton(regLabel);
  const allLabels = labels.slice(0, labels.length - suffix.split('.').length);
  const seen = new Set();
  const add = (i) => { if (!seen.has(i.code + i.technical.brand)) { seen.add(i.code + i.technical.brand); out.push(i); } };

  for (const brand of BRANDS) {
    if (isOfficialFor(brand, registrable)) continue; // domeniu oficial: nicio verificare de imitație
    const L = brand.label;
    const tech = (extra) => ({ brand: brand.name, officialDomains: brand.domains.slice(0, 4), registrable, ...extra });

    // 1. Aceeași etichetă, alt sufix (paypal.xyz)
    if (regLabel === L && L.length >= 4) {
      add(ind('brand-name-other-tld', Severity.MEDIUM, Classification.SUSPICIOUS,
        `Folosește numele „${brand.name}” sub alt domeniu`,
        `Adresa conține numele „${brand.name}”, dar domeniul real este ${registrable}, nu unul dintre domeniile oficiale ale serviciului. Verifică adresa înainte de a introduce date.`, tech()));
      continue;
    }
    // 2. Brand în subdomeniu sau în altă etichetă a gazdei (paypal.com.evil.ru, login.paypal.evil.com)
    const dotted = brand.domains.find((d) => hostAscii.includes(d + '.') || hostAscii.includes('.' + d + '-'));
    const subdomainHasBrand = subdomain && subdomain.split('.').some((l) => l === L || l.split('-').includes(L));
    if (dotted || (subdomainHasBrand && L.length >= 4)) {
      add(ind('brand-in-subdomain', Severity.HIGH, Classification.SUSPICIOUS,
        `Numele „${brand.name}” apare în subdomeniu, nu în domeniul real`,
        `Partea importantă a unei adrese este domeniul de la final. Aici domeniul real este ${registrable}, iar „${brand.name}” apare doar ca subdomeniu pentru a părea oficial.`, tech({ subdomain })));
      continue;
    }
    // 3. Brand ca token sau prefix/sufix în eticheta înregistrabilă (paypal-secure.com)
    const tokens = regLabel.split('-');
    const contains = tokens.includes(L) || (L.length >= 6 && (regLabel.startsWith(L) || regLabel.endsWith(L)) && regLabel !== L);
    if (contains && L.length >= 3) {
      add(ind('brand-in-domain', Severity.MEDIUM, Classification.SUSPICIOUS,
        `Domeniul conține numele „${brand.name}” dar nu este cel oficial`,
        `Numele „${brand.name}” este inclus într-un domeniu diferit (${registrable}). Atacatorii folosesc des combinații precum „${L}-securizat” pentru a părea legitimi.`, tech()));
      continue;
    }
    // 4. Homograf / scheletul unicode egal cu brandul
    if (regSkel === L && regLabel !== L && L.length >= 3) {
      add(ind('homograph-brand', Severity.HIGH, Classification.SUSPICIOUS,
        `Domeniul imită „${brand.name}” prin caractere asemănătoare`,
        `Domeniul pare să scrie „${brand.name}”, dar folosește caractere care arată la fel ca literele obișnuite (sau diacritice adăugate). Domeniul real este diferit de cel oficial.`, tech({ skeleton: regSkel })));
      continue;
    }
    // 5. Substituiri „leet” (paypa1, g00gle, rnicrosoft)
    if (leetVariants(regLabel).includes(L) && L.length >= 4) {
      add(ind('brand-char-substitution', Severity.HIGH, Classification.SUSPICIOUS,
        `Domeniul imită „${brand.name}” prin substituirea unor caractere`,
        `În adresă, unele litere par înlocuite cu cifre sau combinații asemănătoare (ex. „1” în loc de „l”, „rn” în loc de „m”) astfel încât să semene cu „${brand.name}”.`, tech()));
      continue;
    }
    // 6. Typosquatting (distanță de editare 1)
    if (L.length >= 5 && editDistance(regSkel, L, 2) === 1 && regLabel !== L) {
      add(ind('brand-typosquat', Severity.MEDIUM, Classification.SUSPICIOUS,
        `Domeniul seamănă foarte mult cu „${brand.name}”`,
        `Domeniul ${registrable} diferă doar printr-o literă de numele „${brand.name}”. Greșelile de tastare sunt exploatate frecvent de site-uri false.`, tech({ distance: 1 })));
      continue;
    }
  }
  void allLabels;
}

function idnIndicators(hostAscii, unicodeInfo, parts, out) {
  const { unicode, ok } = unicodeInfo;
  if (!hostAscii.split('.').some((l) => l.startsWith('xn--'))) return;
  if (!ok) {
    out.push(ind('invalid-punycode', Severity.MEDIUM, Classification.SUSPICIOUS, 'Cod Punycode invalid în domeniu',
      'Domeniul conține o etichetă „xn--” care nu poate fi decodată corect. Acest lucru este neobișnuit și poate indica o adresă construită intenționat să încurce.', { host: hostAscii }));
    return;
  }
  out.push(ind('idn-domain', Severity.INFO, Classification.POTENTIAL, 'Domeniu cu caractere internaționale (IDN)',
    'Adresa conține caractere non-ASCII (de exemplu diacritice sau alte alfabete). Este frecvent legitim, dar poate fi folosit și pentru imitații.', { unicode, punycode: hostAscii }));
  let mixed = false;
  const detail = [];
  for (const label of unicode.split('.')) {
    const scripts = scriptsOf(label);
    if (scripts.length > 1) { mixed = true; detail.push({ label, scripts }); }
  }
  if (mixed) {
    const chars = confusableChars(unicode.replace(/\./g, '')).slice(0, 6);
    out.push(ind('mixed-script', Severity.HIGH, Classification.SUSPICIOUS, 'Amestec de alfabete în același nume',
      'O parte din domeniu combină litere din alfabete diferite (de exemplu latin și chirilic). Browserele legitime rareori au nevoie de așa ceva; este o tehnică clasică de atac homograf.', { labels: detail, confusableChars: chars }));
  }
  void parts;
}

/**
 * Analizează un URL.
 * @param {string} raw
 * @param {{}} [opts]
 */
export function analyzeUrl(raw, opts = {}) {
  const indicators = [];
  const base = { input: typeof raw === 'string' ? raw.slice(0, 4096) : '', ok: false, indicators, redirectTargets: [] };
  if (typeof raw !== 'string' || !raw.trim()) return { ...base, error: 'empty', skipped: 'invalid' };
  const input = raw.trim();
  if (input.length > 8192) return { ...base, error: 'too-long', skipped: 'invalid' };
  const u = tryParse(input);
  if (!u) return { ...base, error: 'unparseable', skipped: 'invalid' };

  const scheme = u.protocol;
  if (['chrome:', 'chrome-extension:', 'about:', 'edge:', 'view-source:', 'devtools:', 'chrome-untrusted:'].includes(scheme)) {
    return { ...base, ok: true, scheme, normalized: u.href, skipped: 'internal' };
  }
  if (!/^https?:$/.test(scheme)) {
    const sev = ['javascript:', 'data:', 'vbscript:'].includes(scheme) ? Severity.HIGH : scheme === 'ftp:' ? Severity.LOW : Severity.INFO;
    indicators.push(ind('unusual-scheme', sev, sev === Severity.INFO ? Classification.POTENTIAL : Classification.SUSPICIOUS,
      `Schemă de adresă neobișnuită (${scheme})`,
      sev === Severity.HIGH
        ? 'Adresa conține cod sau date direct în URL în loc să indice un site. Aceasta este o schemă folosită des în atacuri și nu ar trebui deschisă din surse necunoscute.'
        : 'Adresa nu folosește HTTP/HTTPS. Extensia analizează în detaliu doar site-urile web obișnuite.', { scheme }));
    return { ...base, ok: true, scheme, normalized: u.href.slice(0, 300), isWeb: false, indicators };
  }

  const hostAscii = u.hostname.toLowerCase().replace(/\.$/, '');
  const parts = splitHost(hostAscii);
  const unicodeInfo = hostToUnicode(hostAscii);
  const internal = isInternalHost(hostAscii);
  const authority = rawAuthority(input);
  const rawHost = rawHostFromAuthority(authority);
  const pathAndQuery = decodeSafe(u.pathname + ' ' + u.search);
  const kwCount = hostKeywordsCount(hostAscii.replace(/\./g, ' ') + ' ' + pathAndQuery);
  const tld = parts.suffix.split('.').pop();

  const result = {
    ...base, ok: true, scheme, isWeb: true,
    normalized: `${u.protocol}//${u.host}${u.pathname}${u.search}`,
    origin: u.origin,
    hostAscii, hostUnicode: unicodeInfo.unicode, punycode: hostAscii !== unicodeInfo.unicode ? hostAscii : null,
    registrable: parts.registrable, suffix: parts.suffix, subdomain: parts.subdomain, sharedHosting: parts.sharedHosting,
    port: u.port || DEFAULT_PORTS[scheme], isIp: parts.isIp, internal, hadCredentials: !!(u.username || u.password),
    keywordCount: kwCount
  };

  // --- Credențiale încorporate și „@" înșelător ---
  if (u.username || u.password) {
    const looksLikeHost = /^(https?:\/\/)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/.*)?$/i.test(decodeSafe(u.username));
    if (looksLikeHost) {
      indicators.push(ind('at-sign-deception', Severity.HIGH, Classification.SUSPICIOUS,
        'Caracterul „@” ascunde destinația reală',
        `Tot ce apare înainte de „@” este ignorat la alegerea site-ului. Adresa pare să trimită către „${decodeSafe(u.username).slice(0, 60)}”, dar site-ul deschis este de fapt ${hostAscii}.`, { shownAs: decodeSafe(u.username).slice(0, 80), realHost: hostAscii }));
    } else {
      indicators.push(ind('embedded-credentials', Severity.MEDIUM, Classification.SUSPICIOUS,
        'Adresa conține utilizator/parolă încorporate',
        'Adresele cu nume de utilizator sau parolă în ele sunt rar folosite legitim astăzi și pot fi folosite pentru a distrage atenția de la domeniul real.', { hasPassword: !!u.password }));
    }
  } else if (/@|%40/i.test(u.pathname + u.search)) {
    indicators.push(ind('at-in-path', Severity.LOW, Classification.POTENTIAL, 'Caracterul „@” în calea adresei',
      'În calea sau parametrii adresei apare „@”. De obicei este nevăzut ca problemă, dar poate fi folosit pentru a face adresa să arate ca o adresă de e-mail sau alt domeniu.', {}));
  }

  // --- IP ---
  const obfuscated = isObfuscatedIp(rawHost);
  if (parts.isIp) {
    if (obfuscated) {
      indicators.push(ind('ip-obfuscated', Severity.HIGH, Classification.SUSPICIOUS, 'Adresă IP scrisă într-un format ascuns',
        `Adresa folosește un IP codificat neobișnuit („${rawHost.slice(0, 40)}”) care se transformă în ${hostAscii}. Acest tip de scriere este folosit pentru a ascunde destinația.`, { raw: rawHost.slice(0, 60), resolved: hostAscii }));
    } else if (isPrivateIp(hostAscii)) {
      indicators.push(ind('ip-private', Severity.INFO, Classification.LEGITIMATE, 'Adresă din rețeaua locală',
        'Adresa indică un dispozitiv din rețeaua locală sau acest calculator. Este normal pentru routere, servere locale și dezvoltare.', { host: hostAscii }));
    } else {
      const ctx = scheme === 'http:' || kwCount > 0 || (u.port && !['80', '443'].includes(u.port));
      indicators.push(ind('ip-host', ctx ? Severity.MEDIUM : Severity.LOW, Classification.SUSPICIOUS,
        'Site accesat direct prin adresă IP',
        ctx ? 'Site-urile legitime folosesc de obicei nume de domeniu. Adresa IP combinată cu HTTP, port neobișnuit sau cuvinte legate de autentificare este un tipar întâlnit în phishing.'
          : 'Site-ul este accesat direct prin IP, nu printr-un nume de domeniu. Nu este o dovadă, dar este neobișnuit pentru site-uri publice.', { host: hostAscii }));
    }
  }
  if (!parts.isIp && /%/.test(rawHost)) {
    indicators.push(ind('encoded-host', Severity.MEDIUM, Classification.SUSPICIOUS, 'Nume de domeniu cu caractere codificate procentual',
      'Numele gazdei conține secvențe „%xx”, care nu apar în adrese normale și pot masca domeniul real.', { raw: rawHost.slice(0, 80) }));
  }

  // --- IDN / homograf / brand ---
  if (!parts.isIp) {
    idnIndicators(hostAscii, unicodeInfo, parts, indicators);
    brandIndicators(parts, hostAscii, indicators, splitHost(unicodeInfo.unicode));
  }

  // --- Structura domeniului ---
  if (!parts.isIp && !internal) {
    const depth = parts.subdomain ? parts.subdomain.split('.').length : 0;
    if (depth >= 4) indicators.push(ind('excessive-subdomains', Severity.LOW, Classification.POTENTIAL, 'Foarte multe subdomenii', `Adresa are ${depth} niveluri de subdomeniu. Atacatorii folosesc subdomenii lungi pentru ca domeniul real să nu fie observat.`, { depth }));
    const uP = splitHost(unicodeInfo.unicode);
    const regLabel = uP.registrable.slice(0, uP.registrable.length - uP.suffix.length - 1);
    if ((regLabel.match(/-/g) || []).length >= 3) indicators.push(ind('many-hyphens', Severity.LOW, Classification.POTENTIAL, 'Domeniu cu multe cratime', 'Domeniile lungi cu multe cratime sunt frecvente în campanii de phishing, dar există și excepții legitime.', { registrable: parts.registrable }));
    if (hostAscii.length > 60) indicators.push(ind('long-host', Severity.LOW, Classification.POTENTIAL, 'Nume de domeniu neobișnuit de lung', 'Un nume de gazdă foarte lung poate ascunde partea semnificativă a adresei.', { length: hostAscii.length }));
    if (ABUSED_TLDS.has(tld)) indicators.push(ind('abused-tld', Severity.LOW, Classification.POTENTIAL, `Extensie de domeniu (.${tld}) folosită frecvent în abuzuri`, `Extensia .${tld} apare des în campanii malițioase, dar este folosită și legitim. Nu este o dovadă în sine.`, { tld }));
    if (parts.sharedHosting) indicators.push(ind('shared-hosting', Severity.INFO, Classification.POTENTIAL, `Găzduit pe o platformă partajată (${parts.suffix})`, 'Oricine își poate crea un site pe această platformă. Reputația platformei nu garantează conținutul acestui site.', { platform: parts.suffix }));
  }
  if (SHORTENERS.has(parts.registrable)) {
    indicators.push(ind('url-shortener', Severity.LOW, Classification.POTENTIAL, 'Link scurtat: destinația finală este ascunsă',
      'Serviciile de scurtare ascund adresa reală. Sentinel Shield nu urmează automat linkul pentru a-l verifica, deci destinația nu poate fi evaluată în prealabil.', { service: parts.registrable }));
  }

  // --- Port, HTTP, lungime, parametri ---
  if (u.port && !['80', '443'].includes(u.port) && !internal && !parts.isIp) {
    indicators.push(ind('nonstandard-port', Severity.LOW, Classification.POTENTIAL, `Port neobișnuit (${u.port})`, 'Site-urile publice folosesc de obicei porturile standard. Un port diferit nu este periculos în sine.', { port: u.port }));
  }
  if (scheme === 'http:' && !internal) {
    indicators.push(ind('insecure-http', kwCount > 0 ? Severity.LOW : Severity.INFO, Classification.POTENTIAL, 'Conexiune necriptată (HTTP)',
      kwCount > 0 ? 'Conexiunea nu este criptată, iar adresa conține cuvinte legate de autentificare/cont. Datele introduse ar putea fi interceptate pe rețea.' : 'Conexiunea nu este criptată. Nu înseamnă că site-ul este malițios, dar datele trimise pot fi interceptate.', { scheme }));
  }
  if (input.length > 2000) indicators.push(ind('very-long-url', Severity.LOW, Classification.POTENTIAL, 'Adresă foarte lungă', 'Adresele extrem de lungi sunt uneori folosite pentru a ascunde destinația sau pentru a transporta date.', { length: input.length }));

  // --- Redirecționări prin parametri ---
  const targets = extractRedirectTargets(u, parts.registrable);
  result.redirectTargets = targets;
  const cross = targets.filter((t) => t.crossSite);
  if (cross.length) {
    indicators.push(ind('redirect-parameter', Severity.MEDIUM, Classification.SUSPICIOUS, 'Parametru care poate duce către alt domeniu',
      `Adresa conține un parametru („${cross[0].param}”) care indică ${cross[0].host}. Redirecționările deschise sunt folosite pentru a trimite victima de pe un domeniu de încredere către unul controlat de atacator.`, { targets: cross.map((t) => ({ param: t.param, host: t.host })) }));
  }

  // --- Combinații ---
  const brandHit = indicators.some((i) => /^brand-|^homograph/.test(i.code));
  const weak = indicators.filter((i) => ['abused-tld', 'many-hyphens', 'insecure-http', 'ip-host', 'excessive-subdomains', 'shared-hosting', 'nonstandard-port'].includes(i.code)).length;
  if (kwCount >= 1 && (brandHit || weak >= 1) && !internal) {
    indicators.push(ind('phishing-combination', brandHit ? Severity.MEDIUM : Severity.LOW, Classification.SUSPICIOUS, 'Combinație de indicatori asociată phishingului',
      'Adresa conține cuvinte legate de autentificare/cont, împreună cu alte semnale neobișnuite. Niciunul nu este decisiv separat, dar împreună seamănă cu tiparul paginilor false de login.', { keywords: kwCount, brandHit, weakSignals: weak }));
  } else if (kwCount >= 3 && !internal) {
    indicators.push(ind('phishing-keywords', Severity.LOW, Classification.POTENTIAL, 'Multe cuvinte asociate autentificării în adresă', 'Adresa conține mai multe cuvinte tipice paginilor de cont/verificare. Este un semnal slab.', { keywords: kwCount }));
  }

  result.isBrandOfficial = isAnyOfficial(parts.registrable);
  void opts;
  return result;
}

function decodeSafe(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}
