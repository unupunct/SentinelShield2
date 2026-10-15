// Generează pictogramele extensiei (scut cyan pe fundal închis) fără dependențe externe.
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, pixel) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) { const [r, g, b, a] = pixel(x, y, size); const o = y * (size * 4 + 1) + 1 + x * 4; raw[o] = r; raw[o + 1] = g; raw[o + 2] = b; raw[o + 3] = a; }
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
// Interiorul scutului în coordonate normalizate: x în [-1,1], y în [0,1]
const inShield = (x, y, k) => {
  const top = 0.1 * k + (1 - k) * 0.0, bottom = 0.95;
  if (y < top || y > bottom) return false;
  const t = (y - top) / (bottom - top);
  const half = t < 0.5 ? 0.82 : 0.82 * Math.pow(1 - (t - 0.5) / 0.5, 0.85);
  return Math.abs(x) <= half;
};
function pixel(px, py, size) {
  const SS = 4; let outer = 0, inner = 0, dot = 0;
  for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
    const x = ((px + (sx + 0.5) / SS) / size) * 2 - 1, y = (py + (sy + 0.5) / SS) / size;
    if (inShield(x, y, 1)) outer++;
    if (inShield(x * 1.22, 0.5 + (y - 0.5) * 1.18 - 0.02, 1)) inner++;
    if (Math.hypot(x, (y - 0.5) * 2 + 0.06) < 0.22) dot++;
  }
  const n = SS * SS; const o = outer / n, i = inner / n, d = dot / n;
  if (o === 0) return [0, 0, 0, 0];
  // cyan (#22d3ee) la margine, interior închis, punct portocaliu (#f59e0b)
  let c = [34, 211, 238];
  c = c.map((v, k) => Math.round(v * (1 - i) + [18, 20, 24][k] * i));
  c = c.map((v, k) => Math.round(v * (1 - d) + [245, 158, 11][k] * d));
  return [...c, Math.round(255 * o)];
}
mkdirSync(join(root, 'icons'), { recursive: true });
for (const s of [16, 32, 48, 128]) writeFileSync(join(root, 'icons', `icon${s}.png`), png(s, pixel));
console.log('Pictograme generate: 16, 32, 48, 128');
