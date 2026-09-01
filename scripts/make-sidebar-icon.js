/**
 * make-sidebar-icon.js — derives a compact sidebar PNG from assets/icon.png.
 * ---------------------------------------------------------------------------
 * The committed app icon is a large artwork file (~1 MB, 1347x1167). Loading
 * that whole image in the renderer just to draw a 34 px badge is wasteful,
 * so this script decodes it (zlib only, no dependencies) and writes a small
 * square PNG with transparent padding:
 *
 *   assets/icon-sidebar.png   256x256, RGBA, for the sidebar / UI
 *
 * Usage: node scripts/make-sidebar-icon.js   (npm run icon:sidebar)
 * ---------------------------------------------------------------------------
 */

'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SRC = path.join(__dirname, '..', 'assets', 'icon.png');
const OUT = path.join(__dirname, '..', 'assets', 'icon-sidebar.png');
const SIZE = 256;

// ---- PNG decode (subset: 8-bit RGB/RGBA, non-interlaced) -------------------

function readChunks(buf) {
  if (buf.readUInt32BE(0) !== 0x89504e47) throw new Error('Not a PNG file');
  let off = 8;
  const chunks = [];
  while (off + 8 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString('ascii', off + 4, off + 8);
    const data = buf.subarray(off + 8, off + 8 + len);
    chunks.push({ type, data });
    off += 12 + len;
    if (type === 'IEND') break;
  }
  return chunks;
}

function decodePng(buf) {
  const chunks = readChunks(buf);
  const ihdr = chunks.find(c => c.type === 'IHDR');
  if (!ihdr) throw new Error('Missing IHDR');
  const width = ihdr.data.readUInt32BE(0);
  const height = ihdr.data.readUInt32BE(4);
  const bitDepth = ihdr.data[8];
  const colorType = ihdr.data[9];
  const interlace = ihdr.data[12];
  if (bitDepth !== 8) throw new Error('Only 8-bit PNG is supported (got ' + bitDepth + ')');
  if (interlace !== 0) throw new Error('Interlaced PNG is not supported');
  const channels = { 0: 1, 2: 3, 4: 2, 6: 4 }[colorType];
  if (!channels) throw new Error('Unsupported PNG color type: ' + colorType);

  const raw = Buffer.concat(chunks.filter(c => c.type === 'IDAT').map(c => c.data));
  const inflated = zlib.inflateSync(raw);

  const stride = width * channels;
  const out = Buffer.alloc(height * stride);
  let pos = 0;
  for (let y = 0; y < height; y++) {
    const filter = inflated[pos++];
    const line = inflated.subarray(pos, pos + stride);
    pos += stride;
    const cur = out.subarray(y * stride, (y + 1) * stride);
    const prev = y > 0 ? out.subarray((y - 1) * stride, y * stride) : null;
    for (let x = 0; x < stride; x++) {
      const a = x >= channels ? cur[x - channels] : 0;
      const b = prev ? prev[x] : 0;
      const c = (prev && x >= channels) ? prev[x - channels] : 0;
      let v = line[x];
      switch (filter) {
        case 0: break;
        case 1: v += a; break;
        case 2: v += b; break;
        case 3: v += (a + b) >> 1; break;
        case 4: {
          const p = a + b - c;
          const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
          v += (pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c);
          break;
        }
        default: throw new Error('Bad PNG filter: ' + filter);
      }
      cur[x] = v & 0xff;
    }
  }
  return { width, height, channels, pixels: out };
}

/** Sample one pixel as RGBA. */
function pixelAt(img, x, y) {
  const i = (y * img.width + x) * img.channels;
  const p = img.pixels;
  if (img.channels >= 3) {
    return [p[i], p[i + 1], p[i + 2], img.channels === 4 ? p[i + 3] : 255];
  }
  return [p[i], p[i], p[i], img.channels === 2 ? p[i + 1] : 255];
}

// ---- PNG encode (8-bit RGBA, non-interlaced) -------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function encodePngRgba(width, height, rgba) {
  const stride = width * 4;
  const raw = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // color type: RGBA
  ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0))
  ]);
}

// ---- Resize (box filter) ---------------------------------------------------

/**
 * Fit the source image into a SIZE x SIZE square, preserving aspect ratio and
 * centering it on a transparent background.
 */
function fitSquare(img, size) {
  const scale = Math.min(size / img.width, size / img.height);
  const dw = Math.max(1, Math.round(img.width * scale));
  const dh = Math.max(1, Math.round(img.height * scale));
  const ox = Math.floor((size - dw) / 2);
  const oy = Math.floor((size - dh) / 2);
  const out = Buffer.alloc(size * size * 4);

  // Box-filter each destination pixel over its source footprint.
  for (let y = 0; y < dh; y++) {
    const sy0 = Math.floor(y * img.height / dh);
    const sy1 = Math.max(sy0 + 1, Math.floor((y + 1) * img.height / dh));
    for (let x = 0; x < dw; x++) {
      const sx0 = Math.floor(x * img.width / dw);
      const sx1 = Math.max(sx0 + 1, Math.floor((x + 1) * img.width / dw));
      let r = 0, g = 0, b = 0, a = 0, n = 0;
      for (let sy = sy0; sy < sy1; sy++) {
        for (let sx = sx0; sx < sx1; sx++) {
          const p = pixelAt(img, sx, sy);
          const alpha = p[3] / 255;
          // Un-premultiply-aware accumulation: weight RGB by alpha.
          r += p[0] * alpha; g += p[1] * alpha; b += p[2] * alpha;
          a += p[3];
          n++;
        }
      }
      if (n === 0) continue;
      const avgA = a / n;
      const inv = avgA > 0 ? 1 / (avgA / 255 * n) : 0;
      const di = ((y + oy) * size + (x + ox)) * 4;
      out[di] = Math.max(0, Math.min(255, Math.round(r * inv)));
      out[di + 1] = Math.max(0, Math.min(255, Math.round(g * inv)));
      out[di + 2] = Math.max(0, Math.min(255, Math.round(b * inv)));
      out[di + 3] = Math.max(0, Math.min(255, Math.round(avgA)));
    }
  }
  return out;
}

// ---- main ------------------------------------------------------------------

(function main() {
  if (!fs.existsSync(SRC)) {
    console.error('Missing source icon: ' + SRC);
    process.exit(1);
  }
  const img = decodePng(fs.readFileSync(SRC));
  console.log('source: ' + img.width + 'x' + img.height + ' (' + img.channels + ' channels)');
  const rgba = fitSquare(img, SIZE);
  const png = encodePngRgba(SIZE, SIZE, rgba);
  fs.writeFileSync(OUT, png);
  console.log('wrote ' + path.relative(process.cwd(), OUT) + ' (' + SIZE + 'x' + SIZE +
    ', ' + (png.length / 1024).toFixed(1) + ' KB)');
})();
