/**
 * make-icon.js — generates assets/icon.png (512x512) with zero dependencies.
 *
 * Pure-Node PNG writer: builds an RGBA pixel buffer, draws the SSHSpan mark
 * (a key inside a rounded-square badge) with distance-field shapes, and
 * encodes a valid PNG (IHDR/IDAT/IEND with CRC32 + zlib deflate).
 *
 * Usage: node scripts/make-icon.js   (package.json script: npm run icon)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZE = 512;

// ---- CRC32 (PNG requirement) ------------------------------------------------
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
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
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

// ---- shape helpers ----------------------------------------------------------
function clamp01(v) { return v < 0 ? 0 : v > 1 ? 1 : v; }
function sdCircle(px, py, cx, cy, r) { return Math.hypot(px - cx, py - cy) - r; }
function sdRing(px, py, cx, cy, r, w) { return Math.abs(Math.hypot(px - cx, py - cy) - r) - w; }
function sdBox(px, py, cx, cy, hw, hh, r) {
  const qx = Math.abs(px - cx) - (hw - r);
  const qy = Math.abs(py - cy) - (hh - r);
  const ax = Math.max(qx, 0), ay = Math.max(qy, 0);
  return Math.hypot(ax, ay) + Math.min(Math.max(qx, qy), 0) - r;
}
function sdVSeg(px, py, x, y0, y1, w) {
  const yy = Math.min(Math.max(py, y0), y1);
  return Math.hypot(px - x, py - yy) - w;
}
function sdHSeg(px, py, y, x0, x1, w) {
  const xx = Math.min(Math.max(px, x0), x1);
  return Math.hypot(px - xx, py - y) - w;
}

// ---- palette ----------------------------------------------------------------
function mix(a, b, t) { return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]; }
const BG_TOP = [24, 31, 46];      // deep navy
const BG_BOTTOM = [10, 13, 20];   // near-black
const ACCENT = [92, 176, 255];    // SSHSpan blue
const ACCENT_DIM = [46, 108, 178];
const INK = [230, 238, 248];

// ---- render -----------------------------------------------------------------
const px = Buffer.alloc(SIZE * SIZE * 4);

for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    const i = (y * SIZE + x) * 4;

    // transparent canvas; badge = rounded square
    const badge = sdBox(x, y, 256, 256, 250, 250, 96);
    if (badge > 1.5) { px[i + 3] = 0; continue; }

    const grad = y / SIZE;
    let col = mix(BG_TOP, BG_BOTTOM, grad);

    // subtle inner vignette ring on the badge edge
    const edgeGlow = clamp01(1 - Math.abs(badge + 10) / 12);
    col = mix(col, ACCENT_DIM, edgeGlow * 0.28);

    // Key mark: bow (ring) top-left, shaft diagonal, two teeth.
    const bowX = 200, bowY = 196, bowR = 66;
    let d = sdRing(x, y, bowX, bowY, bowR, 20);                       // bow ring

    // shaft from bow edge down-right at 45 degrees
    const ux = 0.70710678, uy = 0.70710678;                            // direction
    const sx = bowX + ux * (bowR + 6), sy = bowY + uy * (bowR + 6);   // shaft start
    const ex = sx + ux * 190, ey = sy + uy * 190;                     // shaft end
    // distance point-to-segment
    const abx = ex - sx, aby = ey - sy;
    const t = clamp01(((x - sx) * abx + (y - sy) * aby) / (abx * abx + aby * aby));
    const shaft = Math.hypot(x - (sx + abx * t), y - (sy + aby * t)) - 18;
    d = Math.min(d, shaft);

    // teeth: two short perpendicular stubs near the shaft end
    const pxn = -uy, pyn = ux;                                        // perpendicular
    const t1x = sx + abx * 0.78, t1y = sy + aby * 0.78;
    const t2x = sx + abx * 0.97, t2y = sy + aby * 0.97;
    const tooth1 = Math.hypot((x - t1x) * pxn + (y - t1y) * pyn - 0, (x - t1x) * ux + (y - t1y) * uy - 26) ;
    const seg1 = Math.hypot((x - t1x) - pxn * clamp01(((x - t1x) * pxn + (y - t1y) * pyn) / 52) * 52,
                            (y - t1y) - pyn * clamp01(((x - t1x) * pxn + (y - t1y) * pyn) / 52) * 52) - 13;
    const seg2 = Math.hypot((x - t2x) - pxn * clamp01(((x - t2x) * pxn + (y - t2y) * pyn) / 66) * 66,
                            (y - t2y) - pyn * clamp01(((x - t2x) * pxn + (y - t2y) * pyn) / 66) * 66) - 13;
    d = Math.min(d, Math.min(seg1, seg2));

    const keyMask = clamp01(1.2 - Math.max(d, 0));
    if (d < 0) {
      // key body: accent with a light top-left sheen
      const sheen = clamp01(1 - ((x + y) / (2 * SIZE)));
      col = mix(col, mix(ACCENT, INK, sheen * 0.22), keyMask);
    }

    // soft drop shadow under the key
    const shadowD = sdCircle(x, y + 8, 268, 276, 150);
    if (d > 0) {
      const sh = clamp01(1 - shadowD / 40) * 0.18 * clamp01(d / 26);
      col = [col[0] * (1 - sh), col[1] * (1 - sh), col[2] * (1 - sh)];
    }

    const aa = clamp01(0.75 - badge); // anti-alias the badge edge
    px[i] = Math.round(col[0]);
    px[i + 1] = Math.round(col[1]);
    px[i + 2] = Math.round(col[2]);
    px[i + 3] = Math.round(aa * 255);
  }
}

// ---- PNG encode ---------------------------------------------------------------
const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
for (let y = 0; y < SIZE; y++) {
  raw[y * (SIZE * 4 + 1)] = 0; // filter: none
  px.copy(raw, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);
}
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0);
ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8;   // bit depth
ihdr[9] = 6;   // color type RGBA
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0))
]);

const outDir = path.join(__dirname, '..', 'assets');
fs.mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, 'icon.png');
fs.writeFileSync(outFile, png);
console.log('wrote ' + outFile + ' (' + png.length + ' bytes, ' + SIZE + 'x' + SIZE + ')');
