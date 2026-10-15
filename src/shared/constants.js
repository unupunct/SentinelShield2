/**
 * SentinelShield2 - shared constants.
 *
 * Acest modul NU atinge nicio API Chrome: este importat atât de service worker,
 * cât și de paginile de UI, cât și de testele Node.
 *
 * Principiu de proiectare: toate valorile de risc sunt explicite și centralizate
 * aici, pentru ca scorul să fie determinist și ușor de revizuit.
 */

/** Nivelurile de risc afișate utilizatorului. Ordinea contează (crescător). */
export const RISK_LEVELS = Object.freeze({
  NONE: 'none',
  LOW: 'low',
  MODERATE: 'moderate',
  HIGH: 'high',
  CONFIRMED_DANGEROUS: 'confirmed_dangerous',
});

/** Ordinea numerică a nivelurilor, folosită pentru comparații (ex. pragul de avertizare). */
export const RISK_ORDER = Object.freeze({
  [RISK_LEVELS.NONE]: 0,
  [RISK_LEVELS.LOW]: 1,
  [RISK_LEVELS.MODERATE]: 2,
  [RISK_LEVELS.HIGH]: 3,
  [RISK_LEVELS.CONFIRMED_DANGEROUS]: 4,
});

/** Etichete în română pentru nivelurile de risc. */
export const RISK_LABELS = Object.freeze({
  [RISK_LEVELS.NONE]: 'Fără indicatori evidenți de risc',
  [RISK_LEVELS.LOW]: 'Risc scăzut',
  [RISK_LEVELS.MODERATE]: 'Risc moderat',
  [RISK_LEVELS.HIGH]: 'Risc ridicat',
  [RISK_LEVELS.CONFIRMED_DANGEROUS]: 'Periculos confirmat',
});

/** Descriere scurtă a fiecărui nivel, pentru tooltip-uri și pagini de detalii. */
export const RISK_DESCRIPTIONS = Object.freeze({
  [RISK_LEVELS.NONE]: 'Nu am identificat indicii cunoscute de phishing pentru această adresă.',
  [RISK_LEVELS.LOW]: 'Există indicii minore, frecvente și pe site-uri legitime.',
  [RISK_LEVELS.MODERATE]: 'Mai mulți indicatori se combină. Verifică adresa înainte de a introduce date.',
  [RISK_LEVELS.HIGH]: 'Indicatorii sunt puternic asociați cu pagini de phishing. Nu introduce date.',
  [RISK_LEVELS.CONFIRMED_DANGEROUS]:
    'O sursă de reputație configurată de tine a raportat această adresă ca malițioasă.',
});

/**
 * Precizare obligatorie afișată lângă nivelul NONE: absența indicatorilor
 * nu este o garanție de siguranță.
 */
export const NO_SIGNAL_CAVEAT =
  'Absența indicatorilor cunoscuți NU este o garanție de siguranță. Analiza este euristică și locală.';

/** Severitățile unui indicator individual. */
export const SEVERITY = Object.freeze({
  INFO: 'info',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
});

/** Praguri de scor -> nivel de risc (doar pentru indicatori euristici). */
export const SCORE_THRESHOLDS = Object.freeze([
  { min: 50, level: RISK_LEVELS.HIGH },
  { min: 20, level: RISK_LEVELS.MODERATE },
  { min: 1, level: RISK_LEVELS.LOW },
  { min: 0, level: RISK_LEVELS.NONE },
]);

/** Scorul maxim acumulabil din indicatori euristici. */
export const MAX_HEURISTIC_SCORE = 100;

/** Nivelul minim de risc care declanșează pagina de avertizare, implicit. */
export const DEFAULT_WARNING_LEVEL = RISK_LEVELS.MODERATE;

/** Cheile folosite în chrome.storage.local. */
export const STORAGE_KEYS = Object.freeze({
  SETTINGS: 'sentinel.settings',
  ALLOWLIST: 'sentinel.allowlist',
  BLOCKLIST: 'sentinel.blocklist',
});

/** Versiunea schemei de stocare, pentru migrări viitoare. */
export const STORAGE_SCHEMA_VERSION = 1;

/** Sursa unei intrări din liste. */
export const ENTRY_SOURCE = Object.freeze({
  USER: 'user',
  LOCAL_RULE: 'local_rule',
  EXTERNAL: 'external',
});

/** Tipurile de listă. */
export const LIST_TYPES = Object.freeze({
  ALLOW: 'allowlist',
  BLOCK: 'blocklist',
});

/** Setările implicite. Confidențialitate implicită: totul local, nimic extern. */
export const DEFAULT_SETTINGS = Object.freeze({
  schemaVersion: STORAGE_SCHEMA_VERSION,
  warningLevel: DEFAULT_WARNING_LEVEL,
  navigationCheckEnabled: false,
  reputation: {
    enabled: false,
    provider: 'none',
    endpoint: '',
    timeoutMs: 4000,
    hostnameOnly: true,
    confirmMalicious: false,
    apiKey: '',
  },
  privacy: {
    storeLastAnalysis: true,
    redactQueryInEvidence: true,
  },
});

/** Numele providerilor de reputație acceptați de adaptor. */
export const REPUTATION_PROVIDERS = Object.freeze({
  NONE: 'none',
  CUSTOM_HTTP: 'custom_http',
});

/**
 * Branduri țintite frecvent de phishing. Formele sunt normalizate ASCII,
 * litere mici, fără spații. Lista este intenționat conservatoare: fiecare
 * intrare poate produce un fals pozitiv, de aceea este folosită doar împreună
 * cu distanța de editare / homoglife / poziția în subdomeniu.
 */
export const BRANDS = Object.freeze([
  // Servicii globale
  'google', 'gmail', 'youtube', 'android', 'chromebook',
  'facebook', 'instagram', 'whatsapp', 'messenger',
  'microsoft', 'outlook', 'office365', 'onedrive', 'sharepoint', 'azure',
  'apple', 'icloud', 'itunes',
  'amazon', 'prime',
  'paypal', 'netflix', 'linkedin', 'dropbox', 'adobe', 'docusign',
  'twitter', 'steam', 'discord', 'telegram', 'tiktok', 'snapchat',
  // Financiar
  'binance', 'coinbase', 'kraken', 'metamask', 'revolut', 'payoneer', 'wise', 'stripe',
  // România
  'bcr', 'bancatransilvania', 'btdi', 'raiffeisen', 'brd', 'cec', 'unicredit',
  'anaf', 'ghiseul', 'posta', 'postaromana', 'vodafone', 'orange', 'digi', 'emag',
  // Logistică / utilități
  'dhl', 'fedex', 'gls', 'cargus', 'enel', 'eon', 'electrica',
  // Portaluri de identitate
  'okta', 'duosecurity',
]);

/**
 * Domenii registrabile care CONȚIN legitim numele unui brand. Fără această
 * listă, regula de "brand inclus în etichetă" ar produce fals pozitive pe
 * domenii oficiale (ex. `googleapis.com`, `microsoftonline.com`).
 *
 * Lista este evident incompletă. Limita este documentată în README: un domeniu
 * legitim care lipsește de aici poate primi un indicator de risc scăzut, iar
 * utilizatorul îl poate adăuga în allowlist.
 */
export const KNOWN_LEGIT_BRAND_DOMAINS = Object.freeze([
  'google.com', 'googleapis.com', 'googleusercontent.com', 'googlesource.com',
  'googleblog.com', 'googledomains.com', 'youtube-nocookie.com', 'googlegroups.com',
  'microsoft.com', 'microsoftonline.com', 'microsoftstore.com', 'windowsupdate.com',
  'apple.com', 'icloud.com', 'amazon.com', 'amazonaws.com', 'amazoncognito.com',
  'paypal.com', 'paypalobjects.com', 'netflix.com', 'linkedin.com', 'dropbox.com',
  'adobe.com', 'docusign.com', 'twitter.com', 'x.com', 'steamcommunity.com',
  'discord.com', 'telegram.org', 'tiktok.com', 'snapchat.com',
  'binance.com', 'coinbase.com', 'kraken.com', 'metamask.io', 'revolut.com',
  'payoneer.com', 'wise.com', 'stripe.com', 'okta.com', 'duosecurity.com',
  'bcr.ro', 'bancatransilvania.ro', 'btdi.ro', 'raiffeisen.ro', 'brd.ro',
  'cec.ro', 'ing.ro', 'unicredit.ro', 'anaf.ro', 'ghiseul.ro', 'posta-romana.ro',
  'vodafone.ro', 'orange.ro', 'digi.ro', 'emag.ro', 'dhl.com', 'fedex.com',
  'gls-group.eu', 'cargus.ro', 'enel.ro', 'eon.ro', 'electrica.ro',
]);

/** Cuvinte care apar des în pagini de phishing. Singure NU sunt dovadă. */
export const SENSITIVE_KEYWORDS = Object.freeze([
  'login', 'log-in', 'signin', 'sign-in', 'signon',
  'verify', 'verification', 'verificare', 'confirm', 'confirmation',
  'account', 'account-update', 'cont', 'contul',
  'secure', 'security', 'securizat', 'securitate',
  'password', 'passwd', 'parola',
  'update', 'unlock', 'unblock', 'reactivate', 'recovery', 'reset',
  'authenticate', 'authentication', 'authorize', 'auth',
  'billing', 'invoice', 'payment', 'pay', 'plata', 'wallet', 'portofel',
  'bank', 'banca', 'banking', 'card', 'iban', 'swift',
  'webscr', 'suspend', 'suspended', 'restricted', 'limited', 'blocked',
]);

/**
 * TLD-uri frecvent abuzate. Pondere mică și marcate explicit ca euristice:
 * multe site-uri legitime folosesc aceste TLD-uri.
 */
export const RISKY_TLDS = Object.freeze([
  'zip', 'mov', 'kim', 'country', 'cricket', 'science', 'work', 'party',
  'gq', 'cf', 'ml', 'tk', 'ga', 'top', 'xyz', 'click', 'link', 'live',
  'icu', 'cam', 'rest', 'buzz', 'monster', 'quest', 'sbs', 'cyou',
]);

/** Servicii de scurtare. Folosite și legitim; indicator doar informativ. */
export const URL_SHORTENERS = Object.freeze([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
  'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly', 'tiny.cc', 'bit.do',
  's.id', 'shorte.st', 'bl.ink', 'clck.ru', 'trib.al',
]);

/** Parametri de urmărire. Nu indică phishing, dar pot expune date în loguri. */
export const TRACKING_PARAMS = Object.freeze([
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id',
  'fbclid', 'gclid', 'msclkid', 'dclid', 'yclid', 'twclid', 'igshid',
  'mc_eid', 'mc_cid', '_ga', '_gl', 'ref', 'ref_src', 'trk', 'wt_mc',
]);

/** Parametri care pot indica o redirecționare (folosiți și legitim). */
export const REDIRECT_PARAMS = Object.freeze([
  'url', 'uri', 'redirect', 'redirect_uri', 'redirect_url', 'redir',
  'continue', 'next', 'goto', 'dest', 'destination', 'target',
  'return', 'returnurl', 'return_url', 'returnto', 'out', 'link', 'u', 'to',
]);

/**
 * Parametri a căror valoare este redactată din dovezi și loguri, pentru că
 * poate conține tokenuri, sesiuni sau date sensibile.
 */
export const SENSITIVE_PARAMS = Object.freeze([
  'password', 'passwd', 'pwd', 'token', 'access_token', 'refresh_token',
  'id_token', 'api_key', 'apikey', 'key', 'secret', 'client_secret',
  'session', 'sessionid', 'session_id', 'sid', 'auth', 'authorization',
  'code', 'signature', 'sig', 'hash', 'otp', 'pin', 'cvv', 'card',
  'iban', 'ssn', 'cnp', 'email', 'username',
]);

/**
 * Scheme considerate periculoase.
 * `blob` și `filesystem` sunt tratate separat, cu pondere mai mică, pentru că
 * sunt legitime în anumite contexte (aplicații web).
 */
export const DANGEROUS_SCHEMES = Object.freeze([
  'javascript', 'data', 'vbscript', 'file',
]);

export const SOFT_SUSPICIOUS_SCHEMES = Object.freeze([
  'blob', 'filesystem', 'about', 'chrome', 'chrome-extension',
]);

/**
 * Sufixe publice cu două niveluri, tratate corect la calculul domeniului
 * registrabil (eTLD+1). Lista NU este Public Suffix List completa; este o
 * aproximare documentată, suficientă pentru a evita confuzii de tip
 * `evil.co.uk` vs `co.uk`.
 */
export const MULTI_PART_SUFFIXES = Object.freeze([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
  'com.br', 'com.cn', 'com.hk', 'com.sg', 'com.mx', 'com.ar', 'com.tr',
  'com.ro', 'org.ro', 'net.ro', 'info.ro', 'nom.ro', 'nt.ro',
  'co.za', 'co.in', 'co.kr', 'co.il', 'com.pl', 'com.ua', 'co.at',
  'gov.ro', 'edu.ro', 'as.ro', 'tm.ro', 'arts.ro', 'firm.ro',
  'store.ro', 'rec.ro', 'shopping.ro', 'law.ro', 'med.ro',
]);

/** Limite tehnice / de detecție comunicate explicit în UI și în README. */
export const DETECTION_LIMITS = Object.freeze([
  'Analiza este euristică și locală: nu poate confirma intenția proprietarului unui site.',
  'HTTPS nu este o garanție de siguranță; HTTP nu este, prin el însuși, periculos.',
  'Domeniile noi, necunoscute sau cu multe subdomenii NU sunt automat raportate ca periculoase.',
  'Listele de branduri și de cuvinte-cheie sunt incomplete prin natura lor.',
  'Extensia nu poate inspecta conținutul formularelor, parolele sau cookie-urile și nici nu încearcă.',
  'Monitorizarea navigării nu poate opri sincron o navigare deja inițiată; este o intervenție ulterioară, cel mai bun efort.',
  'Permisiunile web observate sunt cele raportate de API-ul browserului, nu o dovadă de acces efectiv la date.',
]);

/** Mesaje standard de incertitudine atașate verdictului. */
export const UNCERTAINTY_NOTES = Object.freeze({
  heuristic: 'Rezultatul se bazează pe reguli euristice și poate conține fals pozitive.',
  allowlisted: 'Domeniul este pe lista ta de încredere; verificările euristice au fost reduse.',
  blocklisted: 'Domeniul este pe lista ta de blocare; riscul este afișat ca ridicat din alegerea ta.',
  confirmed: 'Amenințarea provine dintr-o sursă de reputație configurată de tine, nu din euristică.',
  noReputation: 'Nu s-a folosit nicio sursă de reputație externă: verdictul "periculos" nu poate fi confirmat.',
});
