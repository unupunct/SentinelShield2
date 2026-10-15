/**
 * SentinelShield2 - validarea manifestului și a codului sursă.
 *
 * Reia, într-un script independent de teste, verificările esențiale:
 * - manifest Manifest V3 valid, fără chei MV2;
 * - permisiuni minime, acces larg doar opțional;
 * - CSP fără cod de la distanță / eval;
 * - fișierele referențiate există;
 * - codul sursă nu folosește `innerHTML`, `eval`, `new Function`, `document.write`.
 *
 * Poate fi rulat cu `npm run validate` sau importat din `build.mjs`.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** @param {string} dir @returns {string[]} */
function listFiles(dir) {
  const results = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) results.push(...listFiles(full));
    else results.push(full);
  }
  return results;
}

/**
 * Validează manifestul și sursele.
 * @returns {{ errors: string[], warnings: string[] }}
 */
export function validate() {
  const errors = [];
  const warnings = [];
  const fail = (message) => errors.push(message);

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
  } catch (error) {
    return { errors: [`manifest.json nu poate fi citit: ${error.message}`], warnings };
  }

  if (manifest.manifest_version !== 3) fail('manifest_version trebuie să fie 3.');
  if (!manifest.name) fail('manifest.name lipsește.');
  if (!manifest.version) fail('manifest.version lipsește.');

  if (manifest.background?.scripts) fail('manifest.background.scripts (MV2) nu este permis.');
  if (manifest.browser_action) fail('manifest.browser_action (MV2) nu este permis.');
  if (manifest.page_action) fail('manifest.page_action (MV2) nu este permis.');
  if (manifest.content_scripts) warnings.push('content_scripts este declarat; verifică dacă este necesar (least privilege).');

  const required = ['storage', 'activeTab', 'scripting', 'contextMenus'];
  for (const permission of required) {
    if (!manifest.permissions?.includes(permission)) fail(`Permisiunea necesară "${permission}" lipsește.`);
  }
  for (const forbidden of ['tabs', 'history', 'cookies', 'webRequest', 'proxy', 'management']) {
    if (manifest.permissions?.includes(forbidden)) fail(`Permisiunea "${forbidden}" nu ar trebui solicitată.`);
  }
  if (manifest.host_permissions) fail('host_permissions nu trebuie solicitat implicit; folosește optional_host_permissions.');
  if (!manifest.optional_permissions?.includes('webNavigation')) fail('Permisiunea opțională webNavigation lipsește.');

  const csp = manifest.content_security_policy?.extension_pages ?? '';
  if (!csp.includes("script-src 'self'")) fail("CSP trebuie să conțină script-src 'self'.");
  if (!csp.includes("object-src 'self'")) fail("CSP trebuie să conțină object-src 'self'.");
  for (const bad of ['unsafe-eval', 'unsafe-inline', 'http:', 'https:']) {
    if (csp.includes(bad)) fail(`CSP conține o directivă interzisă: ${bad}.`);
  }

  const referenced = [
    manifest.background?.service_worker,
    manifest.action?.default_popup,
    manifest.options_ui?.page,
    ...Object.values(manifest.icons ?? {}),
    ...Object.values(manifest.action?.default_icon ?? {}),
  ].filter(Boolean);
  for (const file of referenced) {
    try {
      statSync(join(ROOT, file));
    } catch {
      fail(`Fișierul referențiat în manifest lipsește: ${file}`);
    }
  }

  const srcFiles = listFiles(join(ROOT, 'src'));
  const jsFiles = srcFiles.filter((file) => file.endsWith('.js'));
  const htmlFiles = srcFiles.filter((file) => file.endsWith('.html'));
  const forbiddenPatterns = [
    /\.innerHTML\b/,
    /\.outerHTML\b/,
    /insertAdjacentHTML/,
    /\beval\s*\(/,
    /new\s+Function/,
    /document\.write\s*\(/,
  ];
  for (const file of jsFiles) {
    const source = readFileSync(file, 'utf8');
    for (const pattern of forbiddenPatterns) {
      if (pattern.test(source)) fail(`${file.slice(ROOT.length + 1)} conține un tipar interzis: ${pattern}`);
    }
    if (/console\.log\s*\(/.test(source)) warnings.push(`${file.slice(ROOT.length + 1)} conține console.log.`);
  }
  for (const file of htmlFiles) {
    const source = readFileSync(file, 'utf8');
    if (/(?:src|href)="https?:\/\//i.test(source)) fail(`${file.slice(ROOT.length + 1)} încarcă o resursă externă.`);
    for (const tag of source.match(/<script\b[^>]*>/gi) ?? []) {
      if (!/\bsrc=/.test(tag)) fail(`${file.slice(ROOT.length + 1)} conține un script inline.`);
      if (/https?:\/\//.test(tag)) fail(`${file.slice(ROOT.length + 1)} încarcă un script de la distanță.`);
    }
  }

  return { errors, warnings };
}

/* Rulare directă din linia de comandă. */
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const { errors, warnings } = validate();
  for (const warning of warnings) console.warn(`[avertisment] ${warning}`);
  if (errors.length > 0) {
    for (const error of errors) console.error(`[eroare] ${error}`);
    console.error(`\nValidarea a eșuat cu ${errors.length} erori.`);
    process.exitCode = 1;
  } else {
    console.log(`Validare reușită. ${warnings.length} avertisment(e).`);
  }
}
