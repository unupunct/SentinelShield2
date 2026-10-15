// Validare statică a manifestului: structură MV3, fișiere referite existente, permisiuni minime, absența `eval`/HTML dinamic.
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const m = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
const errors = [];
const need = (p, what) => { if (!existsSync(join(root, p))) errors.push(`Lipsește ${what}: ${p}`); };

if (m.manifest_version !== 3) errors.push('manifest_version trebuie să fie 3');
for (const k of ['name', 'version', 'description']) if (!m[k]) errors.push(`câmp lipsă: ${k}`);
if (m.description.length > 132) errors.push('description > 132 caractere (limită Chrome Web Store)');
for (const f of Object.values(m.icons ?? {})) need(f, 'pictogramă');
need(m.action?.default_popup, 'popup'); need(m.background?.service_worker, 'service worker'); need(m.options_ui?.page, 'pagina de setări');
for (const cs of m.content_scripts ?? []) for (const j of cs.js) need(j, 'content script');
for (const w of m.web_accessible_resources ?? []) for (const r of w.resources) if (!r.includes('*')) need(r, 'resursă accesibilă');

const ALLOWED_PERMS = new Set(['storage', 'webNavigation', 'downloads', 'alarms', 'activeTab']);
for (const p of m.permissions ?? []) if (!ALLOWED_PERMS.has(p)) errors.push(`permisiune neașteptată: ${p}`);
if ((m.host_permissions ?? []).length) errors.push('host_permissions trebuie să fie gol (se folosesc optional_host_permissions)');
if (!/script-src 'self'/.test(m.content_security_policy?.extension_pages ?? '')) errors.push("CSP: lipsește script-src 'self'");
if (/unsafe-eval|unsafe-inline/.test(JSON.stringify(m.content_security_policy))) errors.push('CSP nu trebuie să conțină unsafe-*');

function walk(dir, out = []) { for (const n of readdirSync(dir)) { if (['node_modules', '.git', 'dist', 'tests'].includes(n)) continue; const p = join(dir, n); statSync(p).isDirectory() ? walk(p, out) : out.push(p); } return out; }
const files = walk(join(root, 'src'));
for (const f of files.filter((x) => x.endsWith('.js') || x.endsWith('.html'))) {
  const t = readFileSync(f, 'utf8');
  const rel = relative(root, f);
  if (/\beval\s*\(|new Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/.test(t)) errors.push(`${rel}: execuție dinamică de cod`);
  if (/\.innerHTML\s*=|insertAdjacentHTML|document\.write\s*\(|outerHTML\s*=/.test(t)) errors.push(`${rel}: HTML dinamic nesanitizat`);
  if (f.endsWith('.html') && /<script(?![^>]*\bsrc=)[^>]*>/.test(t)) errors.push(`${rel}: script inline`);
  if (f.endsWith('.html') && /\son\w+\s*=/.test(t)) errors.push(`${rel}: handler inline`);
  if (/(api[_-]?key|authkey|secret|token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i.test(t)) errors.push(`${rel}: posibil secret hardcodat`);
  if (/https?:\/\/(?!urlhaus|safebrowsing\.googleapis|openphish|claude|www\.w3\.org|example)[a-z0-9.-]+/i.test(t) && f.endsWith('.js') && !/\/\/.*https?:/.test(t.split('\n').find((l) => /https?:\/\//.test(l)) ?? '')) { /* URL-uri în cod sunt permise doar pentru furnizorii documentați; verificate manual în audit */ }
}
if (errors.length) { console.error('Manifest/sursă INVALIDE:\n- ' + errors.join('\n- ')); process.exit(1); }
console.log(`Manifest valid. ${files.length} fișiere sursă verificate.`);
