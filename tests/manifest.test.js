import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));

/**
 * Listează recursiv fișierele dintr-un director.
 * @param {string} dir
 * @returns {string[]} căi absolute
 */
function listFiles(dir) {
  const results = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) results.push(...listFiles(full));
    else results.push(full);
  }
  return results;
}

/** @param {string} relative */
function readSource(relative) {
  return readFileSync(join(ROOT, relative), 'utf8');
}

const SRC_FILES = listFiles(join(ROOT, 'src'));
const JS_FILES = SRC_FILES.filter((file) => file.endsWith('.js'));
const HTML_FILES = SRC_FILES.filter((file) => file.endsWith('.html'));

describe('manifest.json', () => {
  it('este Manifest V3', () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.name).toBe('SentinelShield2');
    expect(typeof manifest.version).toBe('string');
    expect(manifest.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(typeof manifest.description).toBe('string');
  });

  it('nu folosește chei Manifest V2', () => {
    expect(manifest.background.scripts).toBeUndefined();
    expect(manifest.browser_action).toBeUndefined();
    expect(manifest.page_action).toBeUndefined();
    expect(manifest.content_scripts).toBeUndefined();
    expect(manifest.background.service_worker).toBe('src/background/serviceWorker.js');
    expect(manifest.background.type).toBe('module');
  });

  it('solicită un set minim de permisiuni necesare', () => {
    expect(new Set(manifest.permissions)).toEqual(new Set(['storage', 'activeTab', 'scripting', 'contextMenus']));
    // Nu solicităm permisiuni care ar da acces larg la date sensibile.
    for (const forbidden of ['tabs', 'history', 'cookies', 'webRequest', 'downloads', 'management']) {
      expect(manifest.permissions).not.toContain(forbidden);
    }
    // Accesul la toate site-urile este opțional, nu implicit.
    expect(manifest.host_permissions).toBeUndefined();
    expect(manifest.optional_permissions).toContain('webNavigation');
    expect(manifest.optional_host_permissions).toContain('*://*/*');
  });

  it('are o politică de securitate care interzice codul de la distanță', () => {
    const csp = manifest.content_security_policy.extension_pages;
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'self'");
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('http:');
    expect(csp).not.toContain('https:');
  });

  it('referențiază doar fișiere existente', () => {
    const referenced = [
      manifest.background.service_worker,
      manifest.action.default_popup,
      manifest.options_ui.page,
      ...Object.values(manifest.icons),
      ...Object.values(manifest.action.default_icon),
    ];
    for (const file of referenced) {
      expect(() => statSync(join(ROOT, file)), `lipsește fișierul ${file}`).not.toThrow();
    }
  });
});

describe('cod sursă', () => {
  it('nu conține API-uri care execută cod de la distanță', () => {
    const forbidden = [/\.innerHTML\b/, /\.outerHTML\b/, /insertAdjacentHTML/, /\beval\s*\(/, /new\s+Function/, /document\.write\s*\(/];
    for (const file of JS_FILES) {
      const source = readSource(file.slice(ROOT.length + 1));
      for (const pattern of forbidden) {
        expect(source, `${file} conține ${pattern}`).not.toMatch(pattern);
      }
    }
  });

  it('nu încarcă scripturi de la distanță și nu are scripturi inline', () => {
    for (const file of HTML_FILES) {
      const source = readFileSync(file, 'utf8');
      // Orice tag <script> trebuie să aibă atribut src local și să fie type="module".
      const scriptTags = source.match(/<script\b[^>]*>/gi) ?? [];
      for (const tag of scriptTags) {
        expect(tag).toMatch(/\bsrc=/);
        expect(tag).not.toMatch(/https?:\/\//);
        expect(tag).toMatch(/type="module"/);
      }
      // Nicio resursă externă (imagini, stiluri, scripturi) nu este încărcată.
      expect(source).not.toMatch(/(?:src|href)="https?:\/\//i);
    }
  });

  it('nu conține console.log (doar avertismente și erori)', () => {
    for (const file of JS_FILES) {
      const source = readSource(file.slice(ROOT.length + 1));
      expect(source, `${file} conține console.log`).not.toMatch(/console\.log\s*\(/);
    }
  });
});
