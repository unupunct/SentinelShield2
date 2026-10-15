/**
 * SentinelShield2 - phishingRules.
 *
 * Fiecare regulă este declarativă și conține:
 * - `id`        : identificator stabil (apare în UI și în rapoarte);
 * - `family`    : grup de deduplicare (mai mulți indicatori din aceeași
 *                 familie NU se însumează: se păstrează ponderea maximă);
 * - `severity`  : severitatea indicatorului;
 * - `weight`    : contribuția la scorul de risc (0-100, vezi riskScorer);
 * - `why`       : de ce contează indicatorul;
 * - `limits`    : limita / falsul pozitiv posibil (afișat utilizatorului);
 * - `detect`    : funcție pură care primește contextul și întoarce null sau dovezi;
 * - `explain`   : text în română, explicabil, despre ce anume s-a observat.
 *
 * Regulile NU decid nivelul final de risc și NU etichetează o amenințare ca
 * "confirmată". Acest lucru se face exclusiv de `riskScorer`, pe baza unor
 * dovezi din surse de reputație configurate explicit de utilizator.
 */

import { SEVERITY } from '../shared/constants.js';
import { truncate } from '../shared/validators.js';

/** Praguri interne, documentate, folosite de mai multe reguli. */
export const RULE_THRESHOLDS = Object.freeze({
  LONG_URL: 200,
  LONG_HOST: 40,
  MAX_SUBDOMAINS: 3,
  MANY_HYPHENS: 4,
  MANY_ENCODED: 12,
  ABNORMAL_PORTS_ALLOWED: Object.freeze([80, 443, 8080, 8443]),
});

/**
 * Ajutor: formatează o listă scurtă pentru textul explicativ.
 * @param {string[]} items
 * @param {number} [max]
 * @returns {string}
 */
function listItems(items, max = 6) {
  const values = items.filter(Boolean).slice(0, max);
  if (values.length === 0) return '';
  if (values.length === 1) return values[0];
  return `${values.slice(0, -1).join(', ')} și ${values[values.length - 1]}`;
}

/** @type {ReadonlyArray<object>} */
export const RULES = Object.freeze([
  // ---------------------------------------------------------------------
  // Scheme de URL
  // ---------------------------------------------------------------------
  {
    id: 'URL-001',
    family: 'scheme.dangerous',
    category: 'url',
    title: 'Schemă de URL periculoasă',
    severity: SEVERITY.CRITICAL,
    weight: 65,
    why: 'Schemele `javascript:` și `data:` pot executa cod sau pot afișa conținut falsificat în locul adresei reale. Sunt folosite frecvent în linkuri de phishing trimise prin e-mail sau mesaje.',
    limits: 'Se aplică doar adreselor introduse sau verificate explicit. Browserul blochează de obicei astfel de scheme la navigarea normală.',
    detect: ({ facts }) => (facts.isDangerousScheme ? { evidence: { scheme: facts.scheme } } : null),
    explain: ({ facts }) => `Adresa nu folosește o schemă web normală, ci \`${facts.scheme}:\`, care poate executa cod sau poate afișa conținut înșelător.`,
    recommendation: 'Nu deschide acest link. Copiază adresa într-un motor de căutare sau verifică sursa mesajului.',
  },
  {
    id: 'URL-002',
    family: 'scheme.soft_suspicious',
    category: 'url',
    title: 'Schemă neobișnuită pentru un link web',
    severity: SEVERITY.LOW,
    weight: 15,
    why: 'Scheme precum `blob:` sau `about:` sunt legitime în aplicații web, dar sunt neobișnuite într-un link primit de la altcineva.',
    limits: 'În mod normal aceste scheme nu pot fi trimise prin e-mail sau mesaje; prezența lor poate fi rezultatul unei copieri incomplete.',
    detect: ({ facts }) => (facts.isSoftSuspiciousScheme ? { evidence: { scheme: facts.scheme } } : null),
    explain: ({ facts }) => `Adresa folosește schema \`${facts.scheme}:\`, care nu este o adresă web obișnuită.`,
    recommendation: 'Verifică de unde provine linkul înainte de a-l folosi.',
  },
  {
    id: 'URL-003',
    family: 'scheme.insecure_http',
    category: 'url',
    title: 'Conexiune necriptată (HTTP)',
    severity: SEVERITY.INFO,
    weight: 5,
    why: 'Fără HTTPS, traficul poate fi citit sau modificat pe rețea. Este o problemă de confidențialitate, nu o dovadă de phishing.',
    limits: 'Multe site-uri vechi, dar legitime, folosesc încă HTTP. Acest indicator, singur, NU înseamnă că site-ul este periculos.',
    detect: ({ facts }) => (facts.isHttp ? { evidence: { scheme: 'http' } } : null),
    explain: () => 'Adresa folosește HTTP, fără criptare. Datele trimise pot fi interceptate, dar site-ul nu este automat periculos.',
    recommendation: 'Evită să introduci date personale sau bancare pe o conexiune HTTP.',
  },

  // ---------------------------------------------------------------------
  // Gazda (host) - structura domeniului
  // ---------------------------------------------------------------------
  {
    id: 'HOST-001',
    family: 'host.ip_literal',
    category: 'domain',
    title: 'Se folosește o adresă IP în locul unui nume de domeniu',
    severity: SEVERITY.HIGH,
    weight: 30,
    why: 'Paginile de phishing folosesc des adrese IP pentru a evita reputația unui domeniu și pentru a ascunde proprietarul. Site-urile publice legitime folosesc de obicei nume de domeniu.',
    limits: 'Aplicații interne, routere și servicii de dezvoltare folosesc legitim adrese IP.',
    detect: ({ facts }) => (facts.isIp && !facts.isPrivateIp ? { evidence: { host: facts.asciiHost } } : null),
    explain: ({ facts }) => `Adresa nu folosește un nume de domeniu, ci adresa IP directă ${facts.asciiHost}.`,
    recommendation: 'Nu introduce date personale. Verifică dacă îți este comunicată oficial această adresă IP.',
  },
  {
    id: 'HOST-002',
    family: 'host.ip_literal',
    category: 'domain',
    title: 'Adresă IP din rețeaua locală',
    severity: SEVERITY.MEDIUM,
    weight: 12,
    why: 'Un IP privat indică de obicei un dispozitiv din rețeaua ta (router, NAS, imprimantă) sau un mediu de test.',
    limits: 'Este normal pentru echipamentele locale. Devine suspect doar dacă a fost primit într-un mesaj ca link către un serviciu public.',
    detect: ({ facts }) => (facts.isIp && facts.isPrivateIp ? { evidence: { host: facts.asciiHost } } : null),
    explain: ({ facts }) => `Adresa este un IP din rețeaua locală (${facts.asciiHost}), de obicei un dispozitiv de acasă sau din birou.`,
    recommendation: 'Continuă doar dacă știi la ce dispozitiv din rețeaua ta corespunde adresa.',
  },
  {
    id: 'HOST-003',
    family: 'host.punycode',
    category: 'domain',
    title: 'Domeniu codificat Punycode',
    severity: SEVERITY.LOW,
    weight: 15,
    suppressedBy: ['domain.brand_homoglyph', 'host.mixed_script'],
    why: 'Domeniile internaționalizate sunt corecte tehnic (ex. münchen.de), dar codificarea ascunde forma reală a adresei, iar unii atacatori o folosesc pentru caractere care arată identic cu litere latine.',
    limits: 'Foarte multe domenii legitime, în special în afara spațiului latin, folosesc Punycode. Singur, acest indicator NU înseamnă pericol.',
    detect: ({ facts }) => (facts.hasPunycode ? { evidence: { labels: facts.punycodeLabels, unicodeHost: facts.unicodeHost } } : null),
    explain: ({ facts }) => `Domeniul este afișat de browser ca \`${facts.asciiHost}\`, dar forma reală este \`${facts.unicodeHost}\`.`,
    recommendation: 'Compară cu atenție forma reală a domeniului (cea cu diacritice) cu adresa pe care o așteptai.',
  },
  {
    id: 'HOST-004',
    family: 'host.mixed_script',
    category: 'domain',
    title: 'Litere din alfabete diferite amestecate în domeniu',
    severity: SEVERITY.HIGH,
    weight: 40,
    suppressedBy: ['domain.brand_homoglyph'],
    why: 'Amestecarea literelor latine cu litere chirilice sau grecești care arată identic este tehnica standard de tip homograph, folosită pentru a imita un domeniu real.',
    limits: 'Anumite limbi folosesc legitim mai multe alfabete, dar este rar în interiorul aceleiași etichete de domeniu.',
    detect: ({ domain }) => (domain.mixedScriptLabels.length > 0 ? { evidence: { labels: domain.mixedScriptLabels } } : null),
    explain: ({ domain }) => `Eticheta \`${domain.mixedScriptLabels.map((m) => m.label).join(', ')}\` combină litere din alfabete diferite (${listItems([...new Set(domain.mixedScriptLabels.flatMap((m) => m.scripts))])}).`,
    recommendation: 'Nu introduce date de autentificare pe acest domeniu până nu verifici adresa oficială.',
  },
  {
    id: 'HOST-005',
    family: 'host.control_chars',
    category: 'domain',
    title: 'Caractere de control sau invizibile în adresă',
    severity: SEVERITY.HIGH,
    weight: 40,
    why: 'Caracterele de control și cele de direcție (ex. U+202E) pot inversa vizual textul adresei, ascunzând terminația reală a domeniului.',
    limits: 'Poate apărea și prin copiere defectuoasă din documente sau aplicații care nu filtrează textul.',
    detect: ({ facts }) => {
      const hidden = [...facts.controlChars, ...facts.invisibleEncoded];
      return hidden.length > 0 ? { evidence: { chars: hidden.map((c) => c.codePoint) } } : null;
    },
    explain: ({ facts }) => {
      const hidden = [...facts.controlChars, ...facts.invisibleEncoded];
      const encodedCount = facts.invisibleEncoded.length;
      const suffix = encodedCount > 0
        ? ` ${encodedCount} dintre ele sunt ascunse prin codificare procentuală (ex. %00 sau %E2%80%AE).`
        : '';
      return `Adresa conține ${hidden.length} caracter(e) de control, invizibile sau care pot schimba ordinea de afișare a textului.${suffix}`;
    },
    recommendation: 'Nu te încredea în formă afișată a adresei. Rescrie manual domeniul de la sursa oficială.',
  },
  {
    id: 'HOST-006',
    family: 'host.encoded_host',
    category: 'domain',
    title: 'Caractere codificate procentual în numele domeniului',
    severity: SEVERITY.HIGH,
    weight: 30,
    why: 'Un domeniu normal nu are nevoie de codificare procentuală. Codificarea în gazdă poate ascunde caractere reale sau poate încerca să păcălească filtrele.',
    limits: 'Poate proveni dintr-un link rupt la copiere. Browserul modern refuză în general navigarea către un astfel de host.',
    detect: ({ facts }) => {
      const encoded = [...facts.encodedInHost, ...(facts.rawEncodedHost ? [{ char: '%xx' }] : [])];
      return encoded.length > 0 ? { evidence: { sequences: encoded.map((c) => c.char) } } : null;
    },
    explain: () => 'Numele domeniului conține secvențe codificate precum %2F sau %00, ceea ce este neobișnuit pentru o adresă web validă.',
    recommendation: 'Nu deschide acest link. Cere expeditorului o adresă scrisă normal.',
  },
  {
    id: 'HOST-007',
    family: 'host.credentials',
    category: 'url',
    title: 'Credențiale incluse în adresă',
    severity: SEVERITY.HIGH,
    weight: 35,
    why: 'Forma `https://utilizator@domeniu/` este folosită pentru a induce în eroare: utilizatorul crede că vede domeniul de dinaintea simbolului @, dar host-ul real este cel de după.',
    limits: 'Unele servicii tehnice folosesc legitim astfel de adrese, dar este rar în linkuri publice.',
    detect: ({ facts }) => (facts.hasCredentials ? { evidence: { hasUsername: facts.hasUsername } } : null),
    explain: ({ facts }) => `Adresa conține un text înaintea simbolului @ (utilizator${facts.hasUsername ? '' : ' sau parolă'}), iar domeniul real este cel de după el: ${facts.asciiHost}.`,
    recommendation: 'Verifică doar partea de după simbolul @. Aceea este site-ul real.',
  },
  {
    id: 'HOST-008',
    family: 'host.abnormal_port',
    category: 'url',
    title: 'Port de rețea neobișnuit',
    severity: SEVERITY.LOW,
    weight: 8,
    why: 'Serviciile web publice folosesc de obicei portul 443 sau 80. Alte porturi pot indica un serviciu improvizat de atacator.',
    limits: 'Porturi precum 8080 sau 8443 sunt normale în dezvoltare și în aplicații interne.',
    detect: ({ facts }) => {
      if (facts.port === null) return null;
      if (RULE_THRESHOLDS.ABNORMAL_PORTS_ALLOWED.includes(facts.port)) return null;
      return { evidence: { port: facts.port } };
    },
    explain: ({ facts }) => `Adresa folosește portul ${facts.port}, diferit de porturile web obișnuite (80, 443).`,
    recommendation: 'Continuă doar dacă recunoști serviciul care rulează pe acest port.',
  },
  {
    id: 'HOST-009',
    family: 'host.excessive_encoding',
    category: 'url',
    title: 'Adresă cu multe caractere codificate',
    severity: SEVERITY.LOW,
    weight: 12,
    why: 'Codificarea excesivă este folosită pentru a ascunde conținutul adresei și pentru a ocoli filtrele care caută cuvinte suspicioase.',
    limits: 'Adresele cu diacritice, spații sau caractere speciale sunt codificate legitim.',
    detect: ({ facts }) => (facts.percentEncodedCount >= RULE_THRESHOLDS.MANY_ENCODED
      ? { evidence: { count: facts.percentEncodedCount } } : null),
    explain: ({ facts }) => `Adresa conține ${facts.percentEncodedCount} secvențe codificate (ex. %20, %2F), ceea ce face dificil de citit conținutul real.`,
    recommendation: 'Verifică domeniul, nu textul codificat din restul adresei.',
  },
  {
    id: 'HOST-010',
    family: 'host.double_encoding',
    category: 'url',
    title: 'Codificare dublă a caracterelor',
    severity: SEVERITY.MEDIUM,
    weight: 20,
    why: 'Codificarea dublă (%2520) este o tehnică clasică de ocolire a filtrelor de securitate.',
    limits: 'Poate apărea accidental când un link deja codificat este codificat din nou de un sistem.',
    detect: ({ facts }) => (facts.hasDoubleEncoding ? { evidence: { href: truncate(facts.href, 120) } } : null),
    explain: () => 'Adresa conține caractere codificate de două ori (ex. %25 urmat de alte cifre), o tehnică de ocolire a filtrelor.',
    recommendation: 'Nu deschide linkul. Solicită o adresă scrisă normal.',
  },
  {
    id: 'HOST-011',
    family: 'host.deep_subdomains',
    category: 'domain',
    title: 'Număr mare de subdomenii',
    severity: SEVERITY.LOW,
    weight: 15,
    why: 'Lanțurile lungi de subdomenii sunt folosite pentru a ascunde domeniul real la finalul adresei: `brand.com.altceva.example.org`.',
    limits: 'Multe companii și servicii cloud folosesc legitim subdomenii adânci. NU este, singur, un semn de pericol.',
    detect: ({ facts }) => (facts.subdomainLabels.length >= RULE_THRESHOLDS.MAX_SUBDOMAINS && !facts.isIp
      ? { evidence: { labels: facts.subdomainLabels } } : null),
    explain: ({ facts }) => `Adresa are ${facts.subdomainLabels.length} niveluri înaintea domeniului principal (${listItems(facts.subdomainLabels)}). Domeniul real este \`${facts.registrableDomain}\`.`,
    recommendation: 'Citește adresa de la dreapta la stânga: numai partea de dinaintea primei bare oblice contează.',
  },
  {
    id: 'HOST-012',
    family: 'host.long_hostname',
    category: 'domain',
    title: 'Nume de domeniu foarte lung',
    severity: SEVERITY.INFO,
    weight: 10,
    why: 'Numele lungi sunt greu de verificat vizual și pot ascunde cuvinte care par de încredere.',
    limits: 'Există numeroase domenii corporate lungi, complet legitime.',
    detect: ({ facts }) => (facts.asciiHost.length > RULE_THRESHOLDS.LONG_HOST
      ? { evidence: { length: facts.asciiHost.length } } : null),
    explain: ({ facts }) => `Numele de domeniu are ${facts.asciiHost.length} caractere, ceea ce îngreunează verificarea vizuală.`,
    recommendation: 'Compară domeniul cu sursa oficială, caracter cu caracter.',
  },
  {
    id: 'HOST-013',
    family: 'host.many_hyphens',
    category: 'domain',
    title: 'Numeroase cratime în numele de domeniu',
    severity: SEVERITY.LOW,
    weight: 8,
    why: 'Domeniile de tip `secure-login-banca-ta.example` folosesc cratime pentru a insera cuvinte de încredere în adresă.',
    limits: 'Foarte multe domenii legitime conțin cratime.',
    detect: ({ facts }) => (facts.hyphenCount >= RULE_THRESHOLDS.MANY_HYPHENS
      ? { evidence: { count: facts.hyphenCount } } : null),
    explain: ({ facts }) => `Domeniul conține ${facts.hyphenCount} cratime, ceea ce este neobișnuit de multe.`,
    recommendation: 'Verifică numele real al domeniului, nu cuvintele adăugate în el.',
  },
  {
    id: 'HOST-014',
    family: 'host.risky_tld',
    category: 'domain',
    title: 'Terminație de domeniu frecvent abuzată',
    severity: SEVERITY.LOW,
    weight: 10,
    why: 'Anumite terminații sunt folosite des în campanii de phishing pentru că sunt ieftine sau gratuite, iar reputația lor este slabă.',
    limits: 'Această observație NU este o dovadă. Numeroase site-uri legitime folosesc aceste terminații. Indicatorul este intenționat cu pondere mică.',
    detect: ({ facts }) => (facts.isRiskyTld ? { evidence: { tld: facts.tld } } : null),
    explain: ({ facts }) => `Domeniul folosește terminația \`.${facts.tld}\`, care apare frecvent în rapoartele de phishing. Aceasta nu este, prin sine, o dovadă de pericol.`,
    recommendation: 'Verifică cine este proprietarul domeniului dacă îți solicită date personale.',
  },
  {
    id: 'HOST-015',
    family: 'host.trailing_dot',
    category: 'domain',
    title: 'Punct final neobișnuit în domeniu',
    severity: SEVERITY.LOW,
    weight: 10,
    why: 'Un punct final poate face ca adresa să pară diferită de domeniul real sau poate ocoli filtrele simple.',
    limits: 'Punctul final este valid tehnic (rădăcina DNS) și apare rar în adrese legitim copiate din configurații.',
    detect: ({ facts }) => (facts.trailingDot ? { evidence: { host: facts.asciiHost } } : null),
    explain: ({ facts }) => `Adresa conține un punct final după domeniu (\`${facts.asciiHost}\`).`,
    recommendation: 'Verifică domeniul fără punctul final.',
  },

  // ---------------------------------------------------------------------
  // Cale, parametri, context
  // ---------------------------------------------------------------------
  {
    id: 'PATH-001',
    family: 'path.sensitive_keyword',
    category: 'path',
    title: 'Cuvinte asociate autentificării sau plăților în adresă',
    severity: SEVERITY.LOW,
    weight: 12,
    why: 'Cuvinte precum `login`, `verify`, `account`, `secure` sau `password` apar în adresele paginilor care colectează date de autentificare, deci și în cele de phishing.',
    limits: 'Site-urile legitime folosesc exact aceleași cuvinte. Ponderea este intenționat mică, pentru a evita alarmele false.',
    detect: ({ facts }) => (facts.hasSensitiveKeyword
      ? { evidence: { keywords: [...new Set(facts.keywordMatches.map((k) => k.keyword))], zones: facts.keywordZones } }
      : null),
    explain: ({ facts }) => `Adresa conține cuvinte folosite frecvent în pagini de autentificare (${listItems([...new Set(facts.keywordMatches.map((k) => k.keyword))], 4)}). Acest lucru este normal pe site-urile oficiale.`,
    recommendation: 'Verifică domeniul înainte de a introduce utilizatorul și parola.',
  },
  {
    id: 'PATH-002',
    family: 'path.sensitive_keyword',
    category: 'path',
    title: 'Cuvinte de autentificare pe un domeniu cu indicatori de risc',
    severity: SEVERITY.HIGH,
    weight: 30,
    why: 'Combinația dintre o pagină care cere autentificare și un domeniu care imită un brand, folosește un IP sau un domeniu codificat este tiparul clasic al phishingului.',
    limits: 'Chiar și aici, un proprietar legitim ar putea folosi un domeniu neobișnuit (ex. testare, rebranding).',
    detect: ({ facts, domain }) => {
      if (!facts.hasSensitiveKeyword) return null;
      const riskyHost = domain.riskMatches.length > 0
        || facts.isIp
        || facts.hasPunycode
        || facts.controlChars.length > 0
        || facts.invisibleEncoded.length > 0;
      if (!riskyHost) return null;
      return {
        evidence: {
          keywords: [...new Set(facts.keywordMatches.map((k) => k.keyword))],
          host: facts.asciiHost,
        },
      };
    },
    explain: ({ facts, domain }) => `Adresa cere date de autentificare (${listItems([...new Set(facts.keywordMatches.map((k) => k.keyword))], 3)}) pe un domeniu care are deja indicatori de risc${domain.primaryBrandMatch ? ` (seamănă cu brandul „${domain.primaryBrandMatch.brand}”)` : ''}.`,
    recommendation: 'Nu introduce parola sau datele bancare. Accesează site-ul scriind adresa oficială manual.',
  },
  {
    id: 'PATH-003',
    family: 'path.redirect_param',
    category: 'path',
    title: 'Parametru care poate redirecționa către alt site',
    severity: SEVERITY.LOW,
    weight: 12,
    why: 'Parametrii de tip `url=`, `redirect=`, `next=` sunt folosiți de atacatori pentru a transforma un site cunoscut într-o trambulină către pagina de phishing.',
    limits: 'În mod normal, redirecționările sunt legitim folosite după autentificare sau după părăsirea unui cont. Prezența unui astfel de parametru nu este o dovadă.',
    detect: ({ facts }) => (facts.hasRedirectParam ? { evidence: { params: facts.redirectParams } } : null),
    explain: ({ facts }) => `Adresa conține parametri de redirecționare (${listItems(facts.redirectParams, 3)}), care pot trimite browserul către alt site.`,
    recommendation: 'Verifică unde ajungi după încărcarea paginii, înainte de a introduce date.',
  },
  {
    id: 'PATH-004',
    family: 'path.redirect_param',
    category: 'path',
    title: 'Redirecționare către un alt domeniu, în parametru',
    severity: SEVERITY.MEDIUM,
    weight: 25,
    why: 'Când valoarea parametrului este o adresă completă către alt domeniu, linkul afișat nu corespunde destinației reale.',
    limits: 'Serviciile de autentificare federată (SSO) fac legitim exact acest lucru.',
    detect: ({ facts }) => {
      const target = facts.params.find((p) => p.isRedirect && /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(p.value));
      if (!target) return null;
      let host = '';
      try {
        host = new URL(target.value).hostname.toLowerCase();
      } catch {
        host = '';
      }
      if (!host || host === facts.asciiHost || host.endsWith(`.${facts.registrableDomain}`)) return null;
      return { evidence: { param: target.key, targetHost: host } };
    },
    explain: ({ facts }) => {
      const target = facts.params.find((p) => p.isRedirect && /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(p.value));
      return `Parametrul \`${target?.key}\` trimite către alt domeniu decât cel afișat în adresă.`;
    },
    recommendation: 'Compară domeniul din link cu destinația reală înainte de a introduce date.',
  },
  {
    id: 'URL-004',
    family: 'url.shortener',
    category: 'url',
    title: 'Link scurtat',
    severity: SEVERITY.LOW,
    weight: 10,
    why: 'Serviciile de scurtare ascund destinația reală, deci nu poți verifica unde ajungi.',
    limits: 'Scurtarea este folosită masiv și legitim (rețele sociale, marketing). NU este un semn de phishing prin sine.',
    detect: ({ facts }) => (facts.isUrlShortener ? { evidence: { host: facts.asciiHost } } : null),
    explain: ({ facts }) => `Adresa folosește serviciul de scurtare \`${facts.asciiHost}\`, care ascunde destinația reală.`,
    recommendation: 'Extinde linkul într-un serviciu de verificare sau deschide-l doar după ce vezi domeniul destinație.',
  },
  {
    id: 'URL-005',
    family: 'url.very_long',
    category: 'url',
    title: 'Adresă neobișnuit de lungă',
    severity: SEVERITY.INFO,
    weight: 6,
    why: 'Adresele foarte lungi sunt dificil de verificat și pot ascunde informații utile în mijlocul șirului.',
    limits: 'Adresele aplicațiilor web moderne sunt frecvent foarte lungi și complet legitime.',
    detect: ({ facts }) => (facts.hrefLength > RULE_THRESHOLDS.LONG_URL
      ? { evidence: { length: facts.hrefLength } } : null),
    explain: ({ facts }) => `Adresa are ${facts.hrefLength} caractere, ceea ce face verificarea vizuală dificilă.`,
    recommendation: 'Verifică doar domeniul principal al adresei.',
  },
  {
    id: 'PRIV-001',
    family: 'privacy.tracking_params',
    category: 'path',
    title: 'Parametri de urmărire prezenți',
    severity: SEVERITY.INFO,
    weight: 4,
    why: 'Parametrii de tip `utm_*` sau `fbclid` sunt folosiți pentru a urmări cine a distribuit linkul. Nu indică phishing, dar sunt relevante pentru confidențialitate.',
    limits: 'Sunt adăugați automat de majoritatea platformelor de marketing.',
    detect: ({ facts }) => (facts.hasTracking ? { evidence: { params: facts.trackingParams } } : null),
    explain: ({ facts }) => `Adresa conține parametri de urmărire (${listItems(facts.trackingParams, 3)}), care permit identificarea sursei vizitei.`,
    recommendation: 'Nu este un motiv de îngrijorare de securitate. Poți elimina parametrii dacă vrei mai multă confidențialitate.',
  },

  // ---------------------------------------------------------------------
  // Domeniu - imitații de brand
  // ---------------------------------------------------------------------
  {
    id: 'DOM-001',
    family: 'domain.brand_homoglyph',
    category: 'domain',
    title: 'Domeniu care imită un brand prin caractere vizual identice',
    severity: SEVERITY.HIGH,
    weight: 55,
    why: 'Se folosesc litere din alt alfabet (ex. chirilic `а`) pentru a obține un domeniu care arată identic cu cel oficial.',
    limits: 'Poate apărea legitim în limbi care folosesc alt alfabet, dar nu combinat cu forma latină a unui brand cunoscut.',
    detect: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'homoglyph');
      return match ? { evidence: { ...match } } : null;
    },
    explain: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'homoglyph');
      return `Domeniul \`${match?.label}\` folosește caractere care arată ca literele latine, dar nu sunt: vizual pare a fi „${match?.brand}”, însă este scris cu caractere din alt alfabet.`;
    },
    recommendation: 'Nu introduce utilizatorul, parola sau date bancare. Scrie manual adresa oficială a serviciului.',
  },
  {
    id: 'DOM-002',
    family: 'domain.brand_digit_substitution',
    category: 'domain',
    title: 'Domeniu care imită un brand prin cifre în locul literelor',
    severity: SEVERITY.HIGH,
    weight: 50,
    why: 'Înlocuirea literelor cu cifre (ex. `g00gle`, `paypa1`) produce o adresă care la o privire rapidă pare cea oficială.',
    limits: 'Aproape sigur un domeniu de test al proprietarului, dar nu este tiparul folosit de site-urile oficiale.',
    detect: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'digit_substitution');
      return match ? { evidence: { ...match } } : null;
    },
    explain: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'digit_substitution');
      return `Domeniul \`${match?.label}\` seamănă cu „${match?.brand}”, dar folosește cifre în locul unor litere.`;
    },
    recommendation: 'Nu introduce date de autentificare. Verifică adresa caracter cu caracter.',
  },
  {
    id: 'DOM-003',
    family: 'domain.brand_typosquat',
    category: 'domain',
    title: 'Domeniu cu o greșeală de scriere față de un brand cunoscut',
    severity: SEVERITY.MEDIUM,
    weight: 45,
    why: 'O literă lipsă, în plus sau schimbată este tiparul clasic de typosquatting, exploatând greșelile de tastare ale utilizatorilor.',
    limits: 'Domenii legitime pot diferi printr-o singură literă de un brand. Indicatorul este moderat și trebuie confirmat de utilizator.',
    detect: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'typosquat');
      return match ? { evidence: { ...match } } : null;
    },
    explain: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'typosquat');
      return `Domeniul \`${match?.label}\` diferă prin ${match?.distance} caracter(e) de numele serviciului „${match?.brand}”, ceea ce poate fi o greșeală de tastare sau o imitație intenționată.`;
    },
    recommendation: 'Verifică adresa oficială înainte de a introduce date.',
  },
  {
    id: 'DOM-004',
    family: 'domain.brand_in_subdomain',
    category: 'domain',
    title: 'Numele unui brand folosit ca subdomeniu al altui domeniu',
    severity: SEVERITY.HIGH,
    weight: 45,
    why: 'Adresa `brand.com.altcineva.example` este citită greșit de majoritatea oamenilor: domeniul real este cel de la final.',
    limits: 'Unii furnizori legitimi găzduiesc clienți pe subdomenii, dar rareori cu numele exact al unui brand global.',
    detect: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'brand_in_subdomain');
      return match ? { evidence: { ...match } } : null;
    },
    explain: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'brand_in_subdomain');
      return `„${match?.brand}” apare înaintea domeniului real \`${domain.registrableDomain}\`, deci adresa seamănă cu numele unui serviciu cunoscut, dar folosește o altă terminație. Ar putea fi o încercare de a imita site-ul original.`;
    },
    recommendation: 'Nu introduce parola sau datele bancare până nu verifici adresa oficială a serviciului.',
  },
  {
    id: 'DOM-005',
    family: 'domain.brand_embedded',
    category: 'domain',
    title: 'Nume de brand inclus în alt nume de domeniu',
    severity: SEVERITY.MEDIUM,
    weight: 35,
    why: 'Adăugarea unor cuvinte de încredere lângă numele unui brand (`paypal-secure`, `apple-support`) sugerează o pagină oficială inexistentă.',
    limits: 'Companii legitime folosesc astfel de nume pentru servicii suplimentare; lista de domenii oficiale nu este completă.',
    detect: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'embedded_in_label');
      return match ? { evidence: { ...match } } : null;
    },
    explain: ({ domain }) => {
      const match = domain.riskMatches.find((m) => m.kind === 'embedded_in_label');
      return `Domeniul conține numele „${match?.brand}” împreună cu alte cuvinte (\`${match?.label}\`), tipar frecvent folosit pentru a părea o pagină oficială.`;
    },
    recommendation: 'Accesează serviciul scriind adresa oficială în bara de adrese.',
  },
  {
    id: 'DOM-006',
    family: 'domain.brand_literal',
    category: 'domain',
    title: 'Nume de brand folosit pe un domeniu neoficial',
    severity: SEVERITY.INFO,
    weight: 0,
    why: 'Informație de context: numele unui serviciu cunoscut apare în domeniu. Multe companii au domenii regionale legitime (ex. google.ro).',
    limits: 'Nu este un indicator de risc și nu contribuie la scor. Este afișat doar pentru transparență.',
    detect: ({ domain }) => (domain.informationalMatches.length > 0
      ? { evidence: { brands: domain.informationalMatches.map((m) => m.brand) } }
      : null),
    explain: ({ domain }) => `Domeniul folosește numele serviciului „${domain.informationalMatches[0]?.brand}”, dar nu este domeniul oficial pe care îl cunoști. Verifică dacă este o pagină regională legitimă.`,
    recommendation: 'Compară domeniul cu adresa oficială indicată pe documentele sau aplicația serviciului.',
  },
]);

/** Index pentru căutare rapidă după id. */
export const RULES_BY_ID = Object.freeze(
  Object.fromEntries(RULES.map((rule) => [rule.id, rule])),
);

/**
 * Evaluează toate regulile asupra unui context.
 *
 * Deduplicarea se face în două etape, ambele deterministe:
 * 1. `family`: doi indicatori din aceeași familie nu se însumează (vezi riskScorer);
 * 2. `suppressedBy`: dacă un indicator mai puternic care descrie ACEEAȘI
 *    caracteristică este prezent, indicatorul slab este marcat ca atenuat,
 *    primește pondere 0 și rămâne vizibil pentru transparență.
 *
 * @param {{ facts: object, domain: object }} context
 * @returns {Array<object>} indicatorii detectați, în ordinea regulilor
 */
export function evaluateRules(context) {
  if (!context?.facts || !context?.domain) {
    throw new TypeError('evaluateRules necesită contextul { facts, domain }.');
  }
  const indicators = [];
  for (const rule of RULES) {
    let detection = null;
    try {
      detection = rule.detect(context);
    } catch (error) {
      // O regulă defectă nu trebuie să blocheze analiza: este raportată ca atare.
      detection = {
        evidence: { ruleError: String(error?.message ?? error) },
        weight: 0,
        severity: SEVERITY.INFO,
      };
    }
    if (!detection) continue;

    let explanation = '';
    try {
      explanation = rule.explain(context, detection) ?? '';
    } catch (error) {
      explanation = `Explicația nu a putut fi generată (${String(error?.message ?? error)}).`;
    }

    indicators.push({
      ruleId: rule.id,
      family: rule.family,
      category: rule.category,
      title: rule.title,
      severity: detection.severity ?? rule.severity,
      weight: detection.weight ?? rule.weight,
      detail: explanation,
      evidence: detection.evidence ?? {},
      why: rule.why,
      limits: rule.limits,
      recommendation: rule.recommendation ?? '',
      suppressedBy: rule.suppressedBy ?? [],
      suppressed: false,
    });
  }

  const activeFamilies = new Set(indicators.filter((i) => i.weight > 0).map((i) => i.family));
  return indicators.map((indicator) => {
    if (indicator.suppressedBy.length === 0) return indicator;
    const stronger = indicator.suppressedBy.find((family) => activeFamilies.has(family));
    if (!stronger) return indicator;
    return {
      ...indicator,
      suppressed: true,
      suppressedByFamily: stronger,
      weight: 0,
    };
  });
}
