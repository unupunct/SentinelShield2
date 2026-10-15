/**
 * Generator de iconițe pentru SentinelShield2.
 *
 * De ce un script propriu: extensia nu trebuie să depindă de unelte externe
 * sau de fișiere binare descărcate. Iconițele sunt PNG-uri RGBA generate
 * determinist, cu `zlib` din Node (fără dependențe).
 *
 * Rulare: node scripts/generate-icons.mjs
 */

import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, '..', 'assets', 'icons');

const COLORS = {
  background: [18, 24, 33, 255], // #121821 - tema întunecată
  shield: [255, 122, 26, 255], // #ff7a1a - accentul portocaliu
  mark: [18, 24, 33, 255], // conturul semnului de verificare
  transparent: [0, 0, 0, 0],
};

/** Tabel CRC32, calculat o singură dată. */
const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

/**
 * @param {Buffer} buffer
 * @returns {number}
 */
function crc32(buffer) {
  let crc = -1;
  for (let i = 0; i < buffer.length; i += 1) {
    crc = CRC_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ -1) >>> 0;
}

/**
 * Construiește un chunk PNG.
 * @param {string} type
 * @param {Buffer} data
 * @returns {Buffer}
 */
function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeBuffer = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 0);
  return Buffer.concat([length, typeBuffer, data, crc]);
}

/**
 * Codifică un buffer RGBA în PNG.
 * @param {Uint8Array} rgba
 * @param {number} width
 * @param {number} height
 * @returns {Buffer}
 */
function encodePng(rgba, width, height) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type: RGBA
  ihdr[10] = 0; // deflate
  ihdr[11] = 0; // filtru adaptiv
  ihdr[12] = 0; // fără interlace

  // Fiecare linie este prefixată cu octetul de filtru (0 = None).
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (width * 4 + 1);
    raw[rowStart] = 0;
    for (let x = 0; x < width * 4; x += 1) {
      raw[rowStart + 1 + x] = rgba[y * width * 4 + x];
    }
  }

  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/**
 * Semnătura geometrică a iconiței, în coordonate normalizate [0,1].
 * @param {number} x
 * @param {number} y
 * @returns {[number, number, number, number]}
 */
function sample(x, y) {
  // Fundal: pătrat cu colțuri rotunjite.
  const radius = 0.22;
  const inset = 0.03;
  const dx = Math.max(0, Math.abs(x - 0.5) - (0.5 - inset - radius));
  const dy = Math.max(0, Math.abs(y - 0.5) - (0.5 - inset - radius));
  const bgDistance = Math.hypot(dx, dy) - radius;
  const insideSquare = bgDistance <= 0;

  // Scut: contur definit prin două arce de cerc și un vârf jos.
  const shieldTop = 0.22;
  const shieldBottom = 0.8;
  const shieldHalfWidth = 0.26;
  let insideShield = false;
  if (y >= shieldTop && y <= 0.58) {
    const t = (y - shieldTop) / (0.58 - shieldTop);
    const halfWidth = shieldHalfWidth * Math.sqrt(1 - t * t * 0.35);
    insideShield = Math.abs(x - 0.5) <= halfWidth;
  } else if (y > 0.58 && y <= shieldBottom) {
    const t = (y - 0.58) / (shieldBottom - 0.58);
    const halfWidth = shieldHalfWidth * 0.7 * (1 - t);
    insideShield = Math.abs(x - 0.5) <= halfWidth;
  }

  // Semnul de verificare, decupat din scut.
  const check = (cx, cy, angle, thickness, length) => {
    const radians = (angle * Math.PI) / 180;
    const px = x - cx;
    const py = y - cy;
    const along = px * Math.cos(radians) + py * Math.sin(radians);
    const across = -px * Math.sin(radians) + py * Math.cos(radians);
    return Math.abs(across) <= thickness && along >= -length / 2 && along <= length / 2;
  };
  const insideCheck = check(0.42, 0.48, 45, 0.035, 0.22) || check(0.6, 0.44, -45, 0.035, 0.32);

  if (!insideSquare) return COLORS.transparent;
  if (insideShield) {
    if (insideCheck) return COLORS.mark;
    return COLORS.shield;
  }
  return COLORS.background;
}

/**
 * Generează un PNG de dimensiunea cerută, cu antialiere prin supraprelevare.
 * @param {number} size
 * @returns {Buffer}
 */
function renderIcon(size) {
  const samples = 4; // 4x4 supraeșantionare
  const rgba = new Uint8Array(size * size * 4);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      for (let sy = 0; sy < samples; sy += 1) {
        for (let sx = 0; sx < samples; sx += 1) {
          const px = (x + (sx + 0.5) / samples) / size;
          const py = (y + (sy + 0.5) / samples) / size;
          const [cr, cg, cb, ca] = sample(px, py);
          const alpha = ca / 255;
          r += cr * alpha;
          g += cg * alpha;
          b += cb * alpha;
          a += ca;
        }
      }
      const total = samples * samples;
      const alphaAverage = a / total;
      const weight = alphaAverage === 0 ? 1 : (alphaAverage / 255) * total;
      const index = (y * size + x) * 4;
      rgba[index] = Math.round(r / weight);
      rgba[index + 1] = Math.round(g / weight);
      rgba[index + 2] = Math.round(b / weight);
      rgba[index + 3] = Math.round(alphaAverage);
    }
  }
  return encodePng(rgba, size, size);
}

mkdirSync(OUT_DIR, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  const file = join(OUT_DIR, `icon${size}.png`);
  writeFileSync(file, renderIcon(size));
  console.log(`scris: ${file}`);
}
