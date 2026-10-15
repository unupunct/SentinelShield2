/**
 * SentinelShield2 - construirea directorului `dist`.
 *
 * Produce `dist/SentinelShield2`, un director gata de încărcat ca extensie
 * "unpacked". Sunt incluse DOAR fișierele necesare la rulare: manifestul,
 * sursele din `src/` și iconițele. Sunt excluse testele, scripturile de build,
 * `node_modules`, `package.json` și fișierele temporare.
 *
 * La final rulează validarea manifestului și a codului sursă.
 */

import { cp, mkdir, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validate } from './validate-manifest.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(ROOT, 'dist');
const OUT = join(DIST, 'SentinelShield2');

/** Extensiile de fișiere incluse în pachetul final. */
const ALLOWED_EXTENSIONS = new Set(['.js', '.html', '.css', '.png', '.svg', '.json']);

/**
 * Copiază recursiv, păstrând doar fișierele cu extensii permise.
 * @param {string} source
 * @param {string} target
 * @returns {Promise<number>} numărul de fișiere copiate
 */
async function copyFiltered(source, target) {
  let count = 0;
  await mkdir(target, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const from = join(source, entry.name);
    const to = join(target, entry.name);
    if (entry.isDirectory()) {
      count += await copyFiltered(from, to);
    } else {
      const dot = entry.name.lastIndexOf('.');
      const extension = dot === -1 ? '' : entry.name.slice(dot).toLowerCase();
      if (!ALLOWED_EXTENSIONS.has(extension)) continue;
      await cp(from, to);
      count += 1;
    }
  }
  return count;
}

/** Punctul de intrare. */
async function build() {
  const { errors, warnings } = validate();
  if (errors.length > 0) {
    for (const error of errors) console.error(`[eroare] ${error}`);
    throw new Error('Construirea a fost oprită: manifestul sau sursele nu trec validarea.');
  }
  for (const warning of warnings) console.warn(`[avertisment] ${warning}`);

  await rm(DIST, { recursive: true, force: true });
  await mkdir(OUT, { recursive: true });

  let files = 0;
  await cp(join(ROOT, 'manifest.json'), join(OUT, 'manifest.json'));
  files += 1;
  files += await copyFiltered(join(ROOT, 'src'), join(OUT, 'src'));
  files += await copyFiltered(join(ROOT, 'assets'), join(OUT, 'assets'));

  await writeFile(
    join(DIST, 'README.txt'),
    [
      'Pachet SentinelShield2 gata de încărcat.',
      '',
      'Încărcare în Chrome:',
      '1. Deschide chrome://extensions',
      '2. Activează "Modul dezvoltator".',
      '3. Apasă "Load unpacked" / "Încarcă extensia neîmpachetată".',
      `4. Selectează directorul: ${OUT}`,
      '',
      'Acest director conține doar fișierele necesare la rulare.',
    ].join('\n'),
    'utf8',
  );

  const size = await totalSize(OUT);
  console.log(`Construire reușită: ${files} fișiere, ${(size / 1024).toFixed(1)} KiB.`);
  console.log(`Director: ${OUT}`);
}

/**
 * Calculează dimensiunea totală a unui director.
 * @param {string} dir
 * @returns {Promise<number>}
 */
async function totalSize(dir) {
  let sum = 0;
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) sum += await totalSize(full);
    else sum += (await stat(full)).size;
  }
  return sum;
}

build().catch((error) => {
  console.error(`Construirea a eșuat: ${error.message}`);
  process.exitCode = 1;
});
