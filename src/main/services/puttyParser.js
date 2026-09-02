'use strict';

/**
 * puttyParser.js
 * ---------------------------------------------------------------------------
 * PuTTY private key (.ppk) import and export.
 *
 * Supported: PPK version 3 (PuTTY 0.75+, the format puttygen writes today),
 * for RSA, Ed25519 and ECDSA (nistp256/384/521), encrypted or not.
 *
 * File layout (see PuTTY docs, Appendix C):
 *
 *   PuTTY-User-Key-File-3: <algorithm>
 *   Encryption: none | aes256-cbc
 *   Comment: <comment>
 *   Public-Lines: <n>
 *   <n lines of base64: public key in SSH wire format>
 *   Key-Derivation: Argon2d | Argon2i | Argon2id      (only when encrypted)
 *   Argon2-Memory: <KiB>
 *   Argon2-Passes: <n>
 *   Argon2-Parallelism: <n>
 *   Argon2-Salt: <hex>
 *   Private-Lines: <n>
 *   <n lines of base64: private blob, AES-256-CBC encrypted when applicable>
 *   Private-MAC: <hex>
 *
 * Key derivation (v3): Argon2 over the passphrase, tag length 80 bytes,
 * split as AES key (32) || CBC IV (16) || MAC key (32). When unencrypted,
 * all three are zero length and Argon2 is not run (the MAC still covers the
 * file, with an empty key). Argon2 comes from Node's built-in
 * crypto.argon2Sync - no third-party module is loaded. The AES-CBC step the
 * container mandates lives in ppkCipher.js.
 *
 * MAC: HMAC-SHA-256 over
 *   string(algorithm) || string(encryptionType) || string(comment) ||
 *   string(publicBlob) || string(privateBlobPlaintext)
 * where string(x) is an SSH wire string (u32 length prefix + bytes). It is
 * verified timing-safely, always BEFORE any key material is returned, so a
 * wrong passphrase or a tampered file never yields a usable key.
 *
 * Version 2 (PuTTY <= 0.74) is deliberately rejected: its KDF and MAC are
 * built on SHA-1. The error tells the user how to convert the file.
 * ---------------------------------------------------------------------------
 */

const nodeCrypto = require('crypto');
const ppkCipher = require('./ppkCipher');

const HEADER_RE = /^PuTTY-User-Key-File-(\d+):[ \t]*(\S+)[ \t]*$/;
const FIELD_RE = /^([A-Za-z0-9-]+):[ \t]?(.*)$/;

const SUPPORTED_ALGORITHMS = [
  'ssh-rsa',
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521'
];

const COORD_LEN = { nistp256: 32, nistp384: 48, nistp521: 66 };
const CRV_FOR_NIST = { nistp256: 'P-256', nistp384: 'P-384', nistp521: 'P-521' };
const NIST_FOR_CRV = { 'P-256': 'nistp256', 'P-384': 'nistp384', 'P-521': 'nistp521' };

/**
 * PPK header names mapped to numeric Argon2 variant ids. The id (never the
 * raw file string) is what selects the algorithm.
 */
const ARGON2_VARIANTS = { Argon2d: 0, Argon2i: 1, Argon2id: 2 };

/** Defaults used when writing (puttygen's own defaults for v3). */
const DEFAULTS = {
  kdf: 'Argon2id',
  memory: 8192,      // KiB
  passes: 16,
  parallelism: 1
};

const MAX_BLOB_BYTES = 1 << 20;        // 1 MiB - generous for any real key
const MAX_ARGON2_MEMORY_KIB = 1 << 20; // refuse absurd memory requests
const TAG_LEN = 32 + 16 + 32;          // cipher key || IV || MAC key

// ---------------------------------------------------------------------------
// SSH wire helpers
// ---------------------------------------------------------------------------

function sshString(value) {
  const b = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  const out = Buffer.alloc(4 + b.length);
  out.writeUInt32BE(b.length, 0);
  b.copy(out, 4);
  return out;
}

/** Unsigned big-endian buffer -> SSH mpint (minimal two's complement). */
function sshMpint(buf) {
  let i = 0;
  while (i < buf.length && buf[i] === 0) i++;
  let body = buf.subarray(i);
  if (body.length === 0) return Buffer.alloc(4);
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0x00]), body]);
  return sshString(body);
}

function stripLeadingZeros(buf) {
  let i = 0;
  while (i < buf.length && buf[i] === 0) i++;
  return buf.subarray(i);
}

function padLeft(buf, len) {
  if (buf.length >= len) return buf.subarray(buf.length - len);
  return Buffer.concat([Buffer.alloc(len - buf.length), buf]);
}

function b64url(buf) { return buf.toString('base64url'); }

class Reader {
  constructor(buf) {
    if (!Buffer.isBuffer(buf)) throw new Error('Expected a Buffer');
    this.buf = buf;
    this.off = 0;
  }
  u32() {
    if (this.off + 4 > this.buf.length) throw new Error('Truncated key data');
    const v = this.buf.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }
  str() {
    const len = this.u32();
    if (len > MAX_BLOB_BYTES) throw new Error('Implausible field length in key data');
    if (this.off + len > this.buf.length) throw new Error('Truncated key data');
    const v = this.buf.subarray(this.off, this.off + len);
    this.off += len;
    return v;
  }
  /** Read an mpint and return it left-padded to `len` bytes (0 = natural). */
  mpint(len = 0) {
    const raw = stripLeadingZeros(this.str());
    return len > 0 ? padLeft(raw, len) : raw;
  }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  return nodeCrypto.timingSafeEqual(a, b);
}

function hmacSha256(key, data) {
  return nodeCrypto.createHmac('sha256', key).update(data).digest();
}

/**
 * Argon2 key material for PPK v3 (TAG_LEN bytes), using Node's built-in
 * crypto.argon2Sync (Node 22.6+ / 24+). `variantId` is a validated numeric
 * id from ARGON2_VARIANTS; each call site passes a literal algorithm name.
 */
function argon2KeyMaterial(passphrase, variantId, salt, memory, passes, parallelism, outputLen) {
  if (typeof nodeCrypto.argon2Sync !== 'function') {
    throw new Error('PuTTY keys cannot be read or written here: this Node build (' +
      process.version + ') has no built-in Argon2. Node 22.6+ / 24+ is required.');
  }
  const options = {
    message: Buffer.from(String(passphrase), 'utf8'),
    nonce: salt,
    memory,                             // KiB
    passes,
    parallelism,
    tagLength: outputLen
  };
  if (variantId === 2) return Buffer.from(nodeCrypto.argon2Sync('argon2id', options));
  if (variantId === 1) return Buffer.from(nodeCrypto.argon2Sync('argon2i', options));
  if (variantId === 0) return Buffer.from(nodeCrypto.argon2Sync('argon2d', options));
  throw new Error('Unsupported Argon2 variant id: ' + String(variantId));
}

/**
 * Key material for PPK version 2 (SHA-1 based, PuTTY <= 0.74).
 *
 * Cipher key: SHA-1(0 || passphrase) || SHA-1(1 || passphrase), first 32 bytes.
 * IV: all zeroes. MAC key: SHA-1("putty-private-key-file-mac-key" || passphrase).
 *
 * SHA-1 is cryptographically weak and is used here ONLY because the v2 file
 * format mandates it; this code path is read-only. v2 files are imported but
 * never written.
 */
function v2KeyMaterial(passphrase) {
  const pw = Buffer.from(String(passphrase || ''), 'utf8');
  const seq = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    return b;
  };
  const h0 = nodeCrypto.createHash('sha1').update(Buffer.concat([seq(0), pw])).digest();
  const h1 = nodeCrypto.createHash('sha1').update(Buffer.concat([seq(1), pw])).digest();
  const cipherKey = Buffer.concat([h0, h1]).subarray(0, 32);
  const iv = Buffer.alloc(16); // v2 uses a zero IV
  const macKey = nodeCrypto.createHash('sha1')
    .update(Buffer.from('putty-private-key-file-mac-key', 'utf8'))
    .update(pw)
    .digest();
  return { cipherKey, iv, macKey };
}

/** MAC preimage: five SSH strings, as specified in Appendix C. */
function macPreimage(algorithm, encryption, comment, publicBlob, privatePlain) {
  return Buffer.concat([
    sshString(algorithm),
    sshString(encryption),
    sshString(comment),
    sshString(publicBlob),
    sshString(privatePlain)
  ]);
}

/**
 * Validate the Argon2 parameters of an incoming file and return them.
 * Rejects anything malformed, unknown or implausibly expensive.
 */
function readArgon2Params(fields) {
  const kdfName = fields['Key-Derivation'];
  if (!kdfName || !Object.prototype.hasOwnProperty.call(ARGON2_VARIANTS, kdfName)) {
    throw new Error('Unsupported or missing PPK Key-Derivation: ' + String(kdfName) +
      ' (expected Argon2d, Argon2i or Argon2id)');
  }
  const saltHex = fields['Argon2-Salt'];
  if (!saltHex) throw new Error('Encrypted PPK file is missing its Argon2-Salt header.');
  const salt = Buffer.from(saltHex, 'hex');
  if (salt.length === 0) throw new Error('Malformed Argon2 salt in PPK file.');
  const passes = Number(fields['Argon2-Passes']);
  const memory = Number(fields['Argon2-Memory']);
  const parallelism = Number(fields['Argon2-Parallelism']);
  if (!Number.isInteger(passes) || passes <= 0) {
    throw new Error('Malformed Argon2-Passes in PPK file.');
  }
  if (!Number.isInteger(memory) || memory <= 0) {
    throw new Error('Malformed Argon2-Memory in PPK file.');
  }
  if (!Number.isInteger(parallelism) || parallelism <= 0) {
    throw new Error('Malformed Argon2-Parallelism in PPK file.');
  }
  if (memory > MAX_ARGON2_MEMORY_KIB) {
    throw new Error('PPK file requests an implausible amount of Argon2 memory.');
  }
  return { kdfName, variantId: ARGON2_VARIANTS[kdfName], salt, passes, memory, parallelism };
}

// ---------------------------------------------------------------------------
// Key material <-> PPK private blob
// ---------------------------------------------------------------------------

function publicComponents(algorithm, blob) {
  const r = new Reader(blob);
  const name = r.str().toString('ascii');
  if (name !== algorithm) {
    throw new Error('Public key algorithm mismatch (' + name + ' vs ' + algorithm + ')');
  }
  if (algorithm === 'ssh-rsa') {
    return { e: stripLeadingZeros(r.str()), n: stripLeadingZeros(r.str()) };
  }
  if (algorithm === 'ssh-ed25519') {
    return { pub: r.str() };
  }
  const nist = r.str().toString('ascii');
  const L = COORD_LEN[nist];
  if (!L) throw new Error('Unsupported ECDSA curve: ' + nist);
  const Q = r.str();
  if (Q.length !== 1 + 2 * L || Q[0] !== 0x04) throw new Error('Malformed ECDSA point');
  return { curve: nist, Q };
}

function privateJwk(algorithm, pub, privatePlain) {
  const r = new Reader(privatePlain);
  if (algorithm === 'ssh-rsa') {
    const d = stripLeadingZeros(r.mpint());
    const p = stripLeadingZeros(r.mpint());
    const q = stripLeadingZeros(r.mpint());
    const iqmp = stripLeadingZeros(r.mpint());
    const P = BigInt('0x' + (p.toString('hex') || '0'));
    const Q = BigInt('0x' + (q.toString('hex') || '0'));
    const D = BigInt('0x' + (d.toString('hex') || '0'));
    const toBuf = (bn) => {
      let hex = bn.toString(16);
      if (hex.length % 2) hex = '0' + hex;
      return Buffer.from(hex, 'hex');
    };
    return {
      kty: 'RSA',
      n: b64url(pub.n),
      e: b64url(pub.e),
      d: b64url(d),
      p: b64url(p),
      q: b64url(q),
      dp: b64url(stripLeadingZeros(toBuf(D % (P - 1n)))),
      dq: b64url(stripLeadingZeros(toBuf(D % (Q - 1n)))),
      qi: b64url(iqmp)
    };
  }
  if (algorithm === 'ssh-ed25519') {
    const seed = r.mpint(32); // PuTTY stores the 32-byte seed as an mpint
    if (pub.pub.length !== 32) throw new Error('Invalid Ed25519 public key length');
    return { kty: 'OKP', crv: 'Ed25519', x: b64url(pub.pub), d: b64url(seed) };
  }
  const L = COORD_LEN[pub.curve];
  const d = r.mpint(L);
  return {
    kty: 'EC',
    crv: CRV_FOR_NIST[pub.curve],
    x: b64url(pub.Q.subarray(1, 1 + L)),
    y: b64url(pub.Q.subarray(1 + L, 1 + 2 * L)),
    d: b64url(d)
  };
}

function privateBlobFromJwk(jwk) {
  if (jwk.kty === 'RSA') {
    return Buffer.concat([
      sshMpint(Buffer.from(jwk.d, 'base64url')),
      sshMpint(Buffer.from(jwk.p, 'base64url')),
      sshMpint(Buffer.from(jwk.q, 'base64url')),
      sshMpint(Buffer.from(jwk.qi, 'base64url'))
    ]);
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return sshMpint(Buffer.from(jwk.d, 'base64url'));
  }
  if (jwk.kty === 'EC') {
    const nist = NIST_FOR_CRV[jwk.crv];
    if (!nist) throw new Error('Unsupported EC curve: ' + jwk.crv);
    return sshMpint(padLeft(Buffer.from(jwk.d, 'base64url'), COORD_LEN[nist]));
  }
  throw new Error('Unsupported key type for PPK export: ' + jwk.kty);
}

function publicBlobFromJwk(jwk) {
  if (jwk.kty === 'RSA') {
    return Buffer.concat([
      sshString('ssh-rsa'),
      sshMpint(Buffer.from(jwk.e, 'base64url')),
      sshMpint(Buffer.from(jwk.n, 'base64url'))
    ]);
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return Buffer.concat([
      sshString('ssh-ed25519'),
      sshString(Buffer.from(jwk.x, 'base64url'))
    ]);
  }
  if (jwk.kty === 'EC') {
    const nist = NIST_FOR_CRV[jwk.crv];
    if (!nist) throw new Error('Unsupported EC curve: ' + jwk.crv);
    const L = COORD_LEN[nist];
    const Q = Buffer.concat([
      Buffer.from([0x04]),
      padLeft(Buffer.from(jwk.x, 'base64url'), L),
      padLeft(Buffer.from(jwk.y, 'base64url'), L)
    ]);
    return Buffer.concat([
      sshString('ecdsa-sha2-' + nist),
      sshString(nist),
      sshString(Q)
    ]);
  }
  throw new Error('Unsupported key type for PPK export: ' + jwk.kty);
}

function algorithmForJwk(jwk) {
  if (jwk.kty === 'RSA') return 'ssh-rsa';
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'ssh-ed25519';
  if (jwk.kty === 'EC') {
    const nist = NIST_FOR_CRV[jwk.crv];
    if (!nist) throw new Error('Unsupported EC curve: ' + jwk.crv);
    return 'ecdsa-sha2-' + nist;
  }
  throw new Error('Unsupported key type for PPK: ' + (jwk.kty || 'unknown'));
}

// ---------------------------------------------------------------------------
// File structure
// ---------------------------------------------------------------------------

function normalizeLines(text) {
  // PuTTY writes LF but tolerates CRLF and CR on input; normalize to LF.
  return String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
}

function parseStructure(text) {
  const lines = normalizeLines(text);
  const header = HEADER_RE.exec(lines[0] || '');
  if (!header) {
    throw new Error('Not a PuTTY private key file (expected a "PuTTY-User-Key-File-N:" header).');
  }
  const version = Number(header[1]);
  const algorithm = header[2];
  // v2 (PuTTY <= 0.74) is accepted for IMPORT only: its KDF and MAC are
  // SHA-1 based, which is weak but mandated by the format, and reading an
  // existing legacy file is safer than telling users to hunt down an old
  // tool. Export always writes v3.
  if (version !== 2 && version !== 3) {
    throw new Error('Unsupported PPK file version: ' + version +
      ' (supported: 2 and 3)');
  }
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new Error('Unsupported PPK key algorithm: ' + algorithm +
      ' (supported: ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256/384/521)');
  }

  const fields = {};
  let publicBlob = null;
  let privateBlob = null;
  let i = 1;
  while (i < lines.length) {
    const fm = FIELD_RE.exec(lines[i] || '');
    if (!fm) { i++; continue; }
    const key = fm[1];
    const value = fm[2];
    if (key === 'Public-Lines' || key === 'Private-Lines') {
      const count = Number(value);
      if (!Number.isInteger(count) || count < 0) throw new Error('Malformed ' + key + ' header.');
      if (count > MAX_BLOB_BYTES) throw new Error(key + ' section is implausibly large.');
      const decoded = Buffer.from(lines.slice(i + 1, i + 1 + count).join(''), 'base64');
      i += 1 + count;
      if (decoded.length === 0) throw new Error('Empty ' + key + ' section.');
      if (key === 'Public-Lines') publicBlob = decoded;
      else privateBlob = decoded;
      continue;
    }
    fields[key] = value;
    i++;
  }

  if (!publicBlob) throw new Error('PPK file has no public key section.');
  if (!privateBlob) throw new Error('PPK file has no private key section.');
  if (!fields['Private-MAC']) throw new Error('PPK file has no Private-MAC.');

  const encryption = fields.Encryption || 'none';
  if (encryption !== 'none' && encryption !== 'aes256-cbc') {
    throw new Error('Unsupported PPK encryption type: ' + encryption);
  }
  return { version, algorithm, encryption, comment: fields.Comment || '', fields, publicBlob, privateBlob };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** True when `text` looks like a PPK file (used to route imports). */
function isPPK(text) {
  return /^\s*PuTTY-User-Key-File-\d+:/.test(String(text || ''));
}

/**
 * Parse a PPK file.
 * @param {string} text raw file contents
 * @param {string} [passphrase] required when the file is encrypted
 * @returns {Promise<{ keyObject, comment, algorithm, version, encrypted }>}
 */
async function parsePPK(text, passphrase) {
  const ppk = parseStructure(text);
  const pw = String(passphrase || '');
  const isV2 = ppk.version === 2;

  if (ppk.encryption === 'none') {
    // v3 MACs with an empty key; v2 uses a plain SHA-1 hash of the blob.
    const expected = Buffer.from(ppk.fields['Private-MAC'], 'hex');
    const actual = isV2
      ? nodeCrypto.createHash('sha1').update(ppk.privateBlob).digest()
      : hmacSha256(Buffer.alloc(0),
        macPreimage(ppk.algorithm, ppk.encryption, ppk.comment, ppk.publicBlob, ppk.privateBlob));
    if (!timingSafeEqual(expected, actual)) {
      throw new Error('PPK integrity check failed - the file is corrupt or has been tampered with.');
    }
    return buildResult(ppk, ppk.privateBlob);
  }

  if (!pw) throw new Error('This PuTTY key is encrypted; enter its passphrase.');
  if (ppk.privateBlob.length === 0 || ppk.privateBlob.length % ppkCipher.BLOCK !== 0) {
    throw new Error('Encrypted private key section is not a whole number of AES blocks.');
  }

  let cipherKey, iv, macKey;
  if (isV2) {
    const km = v2KeyMaterial(pw);
    cipherKey = km.cipherKey;
    iv = km.iv;
    macKey = km.macKey;
  } else {
    const params = readArgon2Params(ppk.fields);
    const material = argon2KeyMaterial(pw, params.variantId, params.salt,
      params.memory, params.passes, params.parallelism, TAG_LEN);
    cipherKey = material.subarray(0, 32);
    iv = material.subarray(32, 48);
    macKey = material.subarray(48, 80);
  }

  const plain = await ppkCipher.decrypt(cipherKey, iv, ppk.privateBlob);

  // Verify the MAC over the DECRYPTED plaintext (padding included) before
  // exposing any key material. v2 uses HMAC-SHA-1, v3 HMAC-SHA-256.
  const expected = Buffer.from(ppk.fields['Private-MAC'], 'hex');
  const preimage = macPreimage(ppk.algorithm, ppk.encryption, ppk.comment, ppk.publicBlob, plain);
  const actual = isV2
    ? nodeCrypto.createHmac('sha1', macKey).update(preimage).digest()
    : hmacSha256(macKey, preimage);
  if (!timingSafeEqual(expected, actual)) {
    throw new Error('Incorrect passphrase, or the file is corrupt or has been tampered with.');
  }
  return buildResult(ppk, plain);
}

function buildResult(ppk, privatePlain) {
  const pub = publicComponents(ppk.algorithm, ppk.publicBlob);
  const jwk = privateJwk(ppk.algorithm, pub, privatePlain);
  let keyObject;
  try {
    keyObject = nodeCrypto.createPrivateKey({ key: jwk, format: 'jwk' });
  } catch (e) {
    throw new Error('Could not reconstruct the private key from this PPK file: ' + e.message);
  }
  return {
    keyObject,
    comment: ppk.comment,
    algorithm: ppk.algorithm,
    version: ppk.version,
    encrypted: ppk.encryption !== 'none'
  };
}

/**
 * Serialize a private key to PPK v3 text.
 * @param {import('crypto').KeyObject} privateKeyObj
 * @param {{ comment?: string, passphrase?: string, kdf?: string,
 *           memory?: number, passes?: number, parallelism?: number }} [opts]
 * @returns {Promise<string>} the .ppk file contents (LF line endings)
 */
async function serializePPK(privateKeyObj, opts = {}) {
  if (!privateKeyObj || typeof privateKeyObj.export !== 'function') {
    throw new Error('A private KeyObject is required.');
  }
  if (privateKeyObj.type !== 'private') throw new Error('A private key is required for PPK export.');
  const jwk = privateKeyObj.export({ format: 'jwk' });
  const algorithm = algorithmForJwk(jwk);

  // Comments may not contain CR or LF.
  const comment = String(opts.comment || '').replace(/[\r\n]+/g, ' ').trim();

  const publicBlob = publicBlobFromJwk(jwk);
  const privateBody = privateBlobFromJwk(jwk);

  const passphrase = String(opts.passphrase || '');
  const encryption = passphrase ? 'aes256-cbc' : 'none';

  let lines = [
    'PuTTY-User-Key-File-3: ' + algorithm,
    'Encryption: ' + encryption,
    'Comment: ' + comment,
    'Public-Lines: ' + b64LineCount(publicBlob.length)
  ];
  lines = lines.concat(b64Lines(publicBlob));

  let privateBlob;
  let macKey = Buffer.alloc(0);
  // The MAC covers the plaintext private data (random padding included), not
  // the ciphertext - see Appendix C, "Private-MAC".
  let macInput = privateBody;

  if (passphrase) {
    const kdfName = opts.kdf || DEFAULTS.kdf;
    if (!Object.prototype.hasOwnProperty.call(ARGON2_VARIANTS, kdfName)) {
      throw new Error('Unsupported Argon2 variant: ' + String(kdfName));
    }
    const variantId = ARGON2_VARIANTS[kdfName];
    const memory = Number(opts.memory) > 0 ? Number(opts.memory) : DEFAULTS.memory;
    const passes = Number(opts.passes) > 0 ? Number(opts.passes) : DEFAULTS.passes;
    const parallelism = Number(opts.parallelism) > 0 ? Number(opts.parallelism) : DEFAULTS.parallelism;
    const salt = nodeCrypto.randomBytes(16);
    const material = argon2KeyMaterial(passphrase, variantId, salt,
      memory, passes, parallelism, TAG_LEN);
    const cipherKey = material.subarray(0, 32);
    const iv = material.subarray(32, 48);
    macKey = material.subarray(48, 80);

    // Pad with random bytes to the AES block size, as PuTTY does.
    const padLen = (ppkCipher.BLOCK - (privateBody.length % ppkCipher.BLOCK)) % ppkCipher.BLOCK;
    const padded = padLen
      ? Buffer.concat([privateBody, nodeCrypto.randomBytes(padLen)])
      : privateBody;
    privateBlob = await ppkCipher.encrypt(cipherKey, iv, padded);
    macInput = padded;

    lines.push('Key-Derivation: ' + kdfName);
    lines.push('Argon2-Memory: ' + memory);
    lines.push('Argon2-Passes: ' + passes);
    lines.push('Argon2-Parallelism: ' + parallelism);
    lines.push('Argon2-Salt: ' + salt.toString('hex'));
  } else {
    privateBlob = privateBody;
  }

  lines.push('Private-Lines: ' + b64LineCount(privateBlob.length));
  lines = lines.concat(b64Lines(privateBlob));

  const mac = hmacSha256(macKey,
    macPreimage(algorithm, encryption, comment, publicBlob, macInput));
  lines.push('Private-MAC: ' + mac.toString('hex'));

  return lines.join('\n') + '\n';
}

/** PuTTY wraps base64 at 64 characters per line. */
function b64Lines(buf) {
  const b64 = buf.toString('base64');
  const out = [];
  for (let i = 0; i < b64.length; i += 64) out.push(b64.slice(i, i + 64));
  return out.length ? out : [''];
}

function b64LineCount(byteLen) {
  return Math.ceil((4 * Math.ceil(byteLen / 3)) / 64);
}

module.exports = {
  parsePPK,
  serializePPK,
  isPPK,
  DEFAULTS,
  internals: {
    sshString,
    sshMpint,
    macPreimage,
    publicComponents,
    privateJwk,
    publicBlobFromJwk,
    privateBlobFromJwk,
    algorithmForJwk,
    parseStructure,
    readArgon2Params,
    argon2KeyMaterial,
    normalizeLines
  }
};
