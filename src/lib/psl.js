// Determinarea domeniului înregistrabil (eTLD+1) fără Public Suffix List completă.
// LIMITARE DOCUMENTATĂ: lista de mai jos este un subset. Pentru sufixe necunoscute se folosește ultima etichetă.
// Platformele de găzduire partajată sunt tratate ca sufixe publice, pentru a nu atribui un site de pe github.io
// "reputației" github.io în ansamblu.

const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'com.br', 'net.br', 'org.br', 'gov.br',
  'com.ar', 'com.mx', 'com.co', 'com.pe', 'com.ve', 'com.ec', 'com.uy', 'com.tr', 'org.tr', 'net.tr',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.hk', 'com.tw', 'com.sg', 'com.my', 'com.ph', 'com.vn', 'com.pk',
  'co.in', 'net.in', 'org.in', 'co.id', 'co.kr', 'or.kr', 'co.th', 'co.il', 'co.za', 'org.za',
  'com.ng', 'com.eg', 'com.sa', 'com.ua', 'com.pl', 'net.pl', 'org.pl', 'com.ro', 'org.ro', 'net.ro', 'nt.ro',
  'info.ro', 'store.ro', 'tm.ro', 'firme.ro', 'www.ro', 'com.ru', 'com.gr', 'com.pt', 'com.es', 'com.de'
]);

const SHARED_HOSTING_SUFFIXES = new Set([
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app', 'herokuapp.com',
  'web.app', 'firebaseapp.com', 'blogspot.com', 'wordpress.com', 'weebly.com', 'wixsite.com',
  'azurewebsites.net', 'cloudfront.net', 's3.amazonaws.com', 'appspot.com', 'glitch.me', 'repl.co',
  'onrender.com', 'fly.dev', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'duckdns.org',
  'no-ip.org', 'ddns.net', 'myshopify.com', 'square.site', 'carrd.co', 'webflow.io', 'framer.website',
  'surge.sh', 'neocities.org', '000webhostapp.com', 'infinityfreeapp.com', 'r2.dev', 'ipfs.dweb.link'
]);

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIPv4(host) {
  const m = IPV4.exec(host);
  return !!m && m.slice(1).every((p) => Number(p) <= 255);
}

export function isIPv6(host) {
  return host.startsWith('[') && host.endsWith(']');
}

export function isPrivateIp(host) {
  if (isIPv6(host)) {
    const h = host.slice(1, -1).toLowerCase();
    return h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80');
  }
  if (!isIPv4(host)) return false;
  const [a, b] = host.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/** Gazde interne (fără sufix public): nu se trimit niciodată către servicii externe. */
export function isInternalHost(host) {
  if (!host) return true;
  if (isIPv4(host) || isIPv6(host)) return isPrivateIp(host);
  if (!host.includes('.')) return true;
  return /\.(local|localhost|internal|lan|home|corp|intranet|test|invalid|example)$/.test(host) && !/\.example\.(com|org|net)$/.test(host) && !/^example\.(com|org|net)$/.test(host);
}

/**
 * @param {string} host hostname ASCII, minuscule, fără punct final.
 * @returns {{registrable:string, suffix:string, subdomain:string, labels:string[], sharedHosting:boolean, isIp:boolean}}
 */
export function splitHost(host) {
  const labels = host.split('.');
  if (isIPv4(host) || isIPv6(host)) {
    return { registrable: host, suffix: '', subdomain: '', labels, sharedHosting: false, isIp: true };
  }
  let suffixLabels = 1;
  for (let n = Math.min(3, labels.length - 1); n >= 2; n--) {
    const cand = labels.slice(-n).join('.');
    if (MULTI_LABEL_SUFFIXES.has(cand) || SHARED_HOSTING_SUFFIXES.has(cand)) { suffixLabels = n; break; }
  }
  const sharedHosting = suffixLabels > 1 && SHARED_HOSTING_SUFFIXES.has(labels.slice(-suffixLabels).join('.'));
  const take = Math.min(labels.length, suffixLabels + 1);
  const registrable = labels.slice(-take).join('.');
  const suffix = labels.slice(-suffixLabels).join('.');
  const subdomain = labels.slice(0, labels.length - take).join('.');
  return { registrable, suffix, subdomain, labels, sharedHosting, isIp: false };
}

export function registrableDomain(host) {
  return splitHost(host).registrable;
}
