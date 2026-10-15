// Analiza metadatelor unei descărcări. NU scanează conținutul fișierului și NU îl execută niciodată.
// Ce NU putem face cu API-urile unei extensii: citirea octeților fișierului descărcat (deci nu verificăm „magic bytes”)
// sau rularea unui antivirus. Verificăm doar nume, tip MIME declarat, sursă și context.
import { splitHost } from './psl.js';

const EXECUTABLE = new Set(['exe', 'msi', 'scr', 'bat', 'cmd', 'com', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'jar', 'lnk', 'pif', 'reg', 'dll', 'cpl', 'msix', 'appx', 'msp', 'apk', 'dmg', 'pkg', 'app', 'sh', 'run', 'appimage', 'deb', 'rpm', 'crx', 'xpi', 'iqy', 'slk', 'chm', 'docm', 'xlsm', 'pptm']);
const ARCHIVE = new Set(['zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'iso', 'img', 'vhd', 'cab', 'ace']);
const DOCUMENT = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'jpg', 'jpeg', 'png', 'gif', 'mp3', 'mp4', 'csv']);
const MIME_EXEC = /^(application\/(x-msdownload|x-msdos-program|x-dosexec|vnd\.microsoft\.portable-executable|x-sh|x-bat|java-archive|x-msi|vnd\.android\.package-archive|x-apple-diskimage|hta|x-ms-installer)|text\/x-shellscript)/i;
const MIME_DOC = /^(application\/(pdf|msword|vnd\.openxmlformats|vnd\.ms-excel|vnd\.ms-powerpoint)|image\/|audio\/|video\/|text\/plain)/i;

export function extensionsOf(filename) {
  const base = filename.split(/[\\/]/).pop() ?? '';
  const clean = base.replace(/[\s.]+$/, '');
  const parts = clean.split('.');
  return { base, clean, exts: parts.length > 1 ? parts.slice(1).map((e) => e.toLowerCase()) : [] };
}

function ind(code, severity, classification, title, explain, technical = {}) { return { code, category: 'download', severity, classification, title, explain, technical }; }

/**
 * @param {{filename:string, url?:string, finalUrl?:string, referrer?:string, mime?:string, sourceLevel?:string, sourceConfirmed?:boolean, pageLevel?:string, byPage?:boolean}} d
 * @returns {{level:'ok'|'info'|'warn'|'danger', indicators:object[], summary:string}}
 */
export function analyzeDownload(d) {
  const out = [];
  const { base, clean, exts } = extensionsOf(d.filename || '');
  const last = exts[exts.length - 1] ?? '';
  const isExec = EXECUTABLE.has(last);
  const isArchive = ARCHIVE.has(last);
  const srcBad = d.sourceConfirmed || d.sourceLevel === 'DANGEROUS';
  const srcSusp = d.sourceLevel === 'SUSPICIOUS';
  const pageBad = d.pageLevel === 'DANGEROUS';
  const pageSusp = d.pageLevel === 'SUSPICIOUS';

  if (/[‪-‮⁦-⁩]/.test(base)) out.push(ind('bidi-filename', 'high', 'SUSPICIOUS', 'Nume de fișier cu caractere de direcție ascunse', 'Numele fișierului conține caractere Unicode care inversează afișarea textului (tehnica „RLO”) pentru a face un executabil să pară alt tip de fișier.', { filename: clean.slice(0, 80) }));
  if (clean !== base) out.push(ind('trailing-dots-spaces', 'medium', 'SUSPICIOUS', 'Nume de fișier cu spații/puncte la final', 'Spațiile sau punctele de la finalul numelui pot ascunde extensia reală pe unele sisteme.', {}));
  if (exts.length >= 2 && DOCUMENT.has(exts[exts.length - 2]) && (isExec || isArchive)) {
    out.push(ind('double-extension', 'high', 'SUSPICIOUS', `Extensie dublă înșelătoare (.${exts[exts.length - 2]}.${last})`, `Fișierul pare un document („.${exts[exts.length - 2]}”), dar tipul real este „.${last}”, un tip care poate rula cod. Extensiile duble sunt folosite pentru a păcăli utilizatorii.`, { extensions: exts }));
  } else if (exts.length >= 3 && (isExec || isArchive)) {
    out.push(ind('multiple-extensions', 'medium', 'SUSPICIOUS', 'Fișier cu mai multe extensii', 'Numele conține mai multe extensii succesive; ultima este cea efectivă.', { extensions: exts }));
  }
  if (isExec) {
    const sev = srcBad || pageBad ? 'high' : srcSusp || pageSusp || d.byPage ? 'medium' : 'low';
    out.push(ind('executable-download', sev, sev === 'low' ? 'POTENTIAL' : 'SUSPICIOUS', `Fișier executabil / cu cod (.${last})`, sev === 'low'
      ? 'Acest tip de fișier poate rula cod pe dispozitivul tău. Poate fi legitim (de exemplu un program pe care ai vrut să îl instalezi); deschide-l doar dacă ai încredere în sursă.'
      : 'Fișierul poate rula cod și provine dintr-o sursă sau pagină cu indicatori de risc. Evită deschiderea lui.', { extension: last }));
  }
  if (isArchive && (srcBad || srcSusp || pageBad || pageSusp)) {
    out.push(ind('archive-risky-source', srcBad || pageBad ? 'high' : 'medium', 'SUSPICIOUS', `Arhivă (.${last}) dintr-o sursă cu reputație proastă`, 'Arhivele sunt folosite pentru a ascunde fișiere periculoase de scanere. Sursa acesteia prezintă indicatori de risc.', { extension: last }));
  }
  if (d.mime) {
    if (MIME_EXEC.test(d.mime) && !isExec) out.push(ind('mime-mismatch-exec', 'high', 'SUSPICIOUS', 'Tipul declarat de server nu corespunde numelui', `Serverul declară un tip executabil (${d.mime.slice(0, 50)}), dar numele fișierului sugerează „.${last || 'fără extensie'}”.`, { mime: d.mime.slice(0, 60), extension: last }));
    else if (isExec && MIME_DOC.test(d.mime)) out.push(ind('mime-mismatch-doc', 'medium', 'SUSPICIOUS', 'Tipul declarat nu corespunde extensiei executabile', `Serverul declară un tip de document (${d.mime.slice(0, 50)}), dar numele are extensie executabilă „.${last}”.`, { mime: d.mime.slice(0, 60) }));
  }
  if (srcBad) out.push(ind('source-confirmed', 'high', 'CONFIRMED', 'Sursa descărcării este listată ca periculoasă', 'Domeniul din care provine fișierul apare ca periculos într-o sursă de reputație.', {}));
  else if (d.byPage && (pageBad || pageSusp)) out.push(ind('page-initiated-risky', pageBad ? 'high' : 'medium', 'SUSPICIOUS', 'Descărcare pornită de o pagină cu indicatori de risc', 'Descărcarea a fost inițiată de o pagină evaluată ca suspectă sau periculoasă.', {}));

  const level = out.some((i) => i.severity === 'high') ? 'danger' : out.some((i) => i.severity === 'medium') ? 'warn' : out.length ? 'info' : 'ok';
  const summary = level === 'danger' ? 'Descărcare cu risc ridicat' : level === 'warn' ? 'Descărcare care necesită atenție' : level === 'info' ? 'Descărcare cu risc potențial' : 'Nu au fost identificați indicatori în metadate';
  return { level, indicators: out, summary, filename: clean.slice(0, 120), extension: last, host: safeHost(d.finalUrl || d.url) };
}

function safeHost(u) { try { return splitHost(new URL(u).hostname).registrable; } catch { return null; } }
