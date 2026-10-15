// Branduri frecvent imitate în phishing și domeniile lor oficiale.
// `ccTld: true` = brandul folosește domenii naționale (google.ro, amazon.de etc.), deci eticheta + orice ccTLD de 2 litere
// este considerată oficială. Lista este un set inițial, extensibil din cod; NU este exhaustivă.

/** [nume, eticheta principală, [domenii oficiale înregistrabile], ccTld] */
const RAW = [
  ['PayPal', 'paypal', ['paypal.com', 'paypal.me', 'paypalobjects.com'], false],
  ['Google', 'google', ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'goo.gl', 'g.co', 'youtube.com', 'youtu.be', 'gmail.com', 'withgoogle.com'], true],
  ['Microsoft', 'microsoft', ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com', 'office365.com', 'azure.com', 'bing.com', 'xbox.com', 'msn.com', 'sharepoint.com', 'windows.com', 'skype.com', 'onedrive.com'], false],
  ['Apple', 'apple', ['apple.com', 'icloud.com', 'itunes.com', 'me.com', 'mzstatic.com'], false],
  ['Amazon', 'amazon', ['amazon.com', 'amazonaws.com', 'amazon.co.uk', 'amazon.ro', 'amzn.to', 'aws.amazon.com', 'primevideo.com', 'audible.com'], true],
  ['Facebook / Meta', 'facebook', ['facebook.com', 'fb.com', 'fb.me', 'fbcdn.net', 'meta.com', 'messenger.com', 'whatsapp.com', 'instagram.com'], false],
  ['Instagram', 'instagram', ['instagram.com', 'cdninstagram.com'], false],
  ['WhatsApp', 'whatsapp', ['whatsapp.com', 'whatsapp.net', 'wa.me'], false],
  ['Netflix', 'netflix', ['netflix.com', 'nflxvideo.net', 'nflximg.net'], false],
  ['LinkedIn', 'linkedin', ['linkedin.com', 'licdn.com', 'lnkd.in'], false],
  ['GitHub', 'github', ['github.com', 'github.io', 'githubusercontent.com', 'githubassets.com'], false],
  ['Dropbox', 'dropbox', ['dropbox.com', 'dropboxusercontent.com', 'db.tt'], false],
  ['DocuSign', 'docusign', ['docusign.com', 'docusign.net'], false],
  ['Adobe', 'adobe', ['adobe.com', 'adobelogin.com', 'typekit.net'], false],
  ['Binance', 'binance', ['binance.com', 'binance.us'], false],
  ['Coinbase', 'coinbase', ['coinbase.com'], false],
  ['MetaMask', 'metamask', ['metamask.io'], false],
  ['Twitter / X', 'twitter', ['twitter.com', 'x.com', 't.co', 'twimg.com'], false],
  ['Steam', 'steampowered', ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'], false],
  ['Spotify', 'spotify', ['spotify.com', 'scdn.co'], false],
  ['DHL', 'dhl', ['dhl.com', 'dhl.de'], true],
  ['FedEx', 'fedex', ['fedex.com'], false],
  ['UPS', 'ups', ['ups.com'], false],
  ['Revolut', 'revolut', ['revolut.com', 'revolut.me'], false],
  ['Wise', 'wise', ['wise.com', 'transferwise.com'], false],
  ['Visa', 'visa', ['visa.com'], false],
  ['Mastercard', 'mastercard', ['mastercard.com'], false],
  // România
  ['ANAF', 'anaf', ['anaf.ro', 'mfinante.gov.ro'], false],
  ['Poșta Română', 'posta-romana', ['posta-romana.ro', 'posta.ro', 'cargus.ro'], false],
  ['FAN Courier', 'fancourier', ['fancourier.ro'], false],
  ['Sameday', 'sameday', ['sameday.ro'], false],
  ['Banca Transilvania', 'bancatransilvania', ['bancatransilvania.ro', 'bt24.ro', 'btpay.ro'], false],
  ['BCR', 'bcr', ['bcr.ro', 'georgebcr.ro'], false],
  ['BRD', 'brd', ['brd.ro'], false],
  ['ING România', 'ing', ['ing.ro', 'ing.com', 'ing.nl', 'ing.de'], false],
  ['Raiffeisen', 'raiffeisen', ['raiffeisen.ro', 'raiffeisenbank.at'], false],
  ['CEC Bank', 'cec', ['cec.ro'], false],
  ['eMAG', 'emag', ['emag.ro', 'emag.hu', 'emag.bg'], false],
  ['OLX', 'olx', ['olx.ro', 'olx.pl', 'olx.bg', 'olx.com'], false],
  ['Digi', 'digi', ['digi.ro', 'digi.hu', 'digimobil.es'], false],
  ['Orange', 'orange', ['orange.ro', 'orange.com', 'orange.fr', 'orange.es'], false],
  ['Vodafone', 'vodafone', ['vodafone.ro', 'vodafone.com', 'vodafone.co.uk'], false]
];

export const BRANDS = RAW.map(([name, label, domains, ccTld]) => ({ name, label, domains, ccTld }));

const OFFICIAL = new Set(BRANDS.flatMap((b) => b.domains));

/** E domeniul înregistrabil unul oficial pentru brandul dat (sau, dacă brandul e `ccTld`, label+ccTLD)? */
export function isOfficialFor(brand, registrable) {
  if (brand.domains.includes(registrable)) return true;
  if (brand.ccTld) {
    const parts = registrable.split('.');
    if (parts[0] === brand.label && ((parts.length === 2 && parts[1].length === 2) || (parts.length === 3 && parts[1] === 'co' && parts[2].length === 2) || (parts.length === 3 && parts[1] === 'com' && parts[2].length === 2))) return true;
  }
  return false;
}

export function isAnyOfficial(registrable) {
  return OFFICIAL.has(registrable) || BRANDS.some((b) => isOfficialFor(b, registrable));
}

/** Brandul pentru un domeniu oficial (sau null). */
export function brandOfOfficial(registrable) {
  return BRANDS.find((b) => isOfficialFor(b, registrable)) ?? null;
}

/** Brandurile al căror nume apare în text (ex. titlul paginii), ca token întreg. */
export function brandsMentionedIn(text) {
  const t = ` ${String(text).toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ')} `;
  return BRANDS.filter((b) => b.label.length >= 3 && t.includes(` ${b.label.replace(/-/g, ' ')} `));
}
