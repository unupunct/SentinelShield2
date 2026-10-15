// Construiește un ZIP instalabil (Developer Mode: dezarhivează și „Load unpacked", sau încarcă ZIP-ul în Chrome Web Store).
// Fără dependențe externe. Conține DOAR fișierele extensiei (nu teste, documentație de dezvoltare sau node_modules).
import { readFileSync, readdirSync, statSync, mkdirSync, writeFileSync } from 'node:fs';
import { deflateRawSync } from 'node:zlib';
import { join, relative, dirname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
const INCLUDE = ['manifest.json', 'src', 'icons', 'data'];

const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };

function walk(p, out = []) {
  const st = statSync(p);
  if (st.isDirectory()) for (const n of readdirSync(p).sort()) walk(join(p, n), out); else out.push(p);
  return out;
}
const files = INCLUDE.flatMap((i) => walk(join(root, i)));

const locals = []; const central = []; let offset = 0;
for (const f of files) {
  const name = Buffer.from(relative(root, f).split(sep).join('/'));
  const data = readFileSync(f);
  const comp = deflateRawSync(data, { level: 9 });
  const crc = crc32(data);
  const dosTime = 0, dosDate = (46 << 9) | (1 << 5) | 1; // 2026-01-01 (reproductibil)
  const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(8, 8); lh.writeUInt16LE(dosTime, 10); lh.writeUInt16LE(dosDate, 12);
  lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26); lh.writeUInt16LE(0, 28);
  locals.push(lh, name, comp);
  const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(8, 10); ch.writeUInt16LE(dosTime, 12); ch.writeUInt16LE(dosDate, 14);
  ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
  central.push(ch, name);
  offset += lh.length + name.length + comp.length;
}
const cd = Buffer.concat(central);
const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
mkdirSync(join(root, 'dist'), { recursive: true });
const outFile = join(root, 'dist', `sentinel-shield-${manifest.version}.zip`);
writeFileSync(outFile, Buffer.concat([...locals, cd, end]));
console.log(`ZIP creat: ${outFile} (${files.length} fișiere)`);
