/**
 * opensshParser.js
 * ---------------------------------------------------------------------------
 * Parser and serializer for the OpenSSH new-format private key file
 * ("openssh-key-v1", see PROTOCOL.key in the OpenSSH source tree).
 *
 * Parsing supports:
 *   - ciphers: none, aes256-ctr, aes256-gcm, chacha20-poly1305@openssh.com
 *   - kdf:     bcrypt (real bcrypt-pbkdf, compatible with ssh-keygen output)
 *   - types:   rsa, ed25519, ecdsa (nistp256/384/521)
 *
 * Serialization supports:
 *   - none (unencrypted) and aes256-ctr + bcrypt KDF (passphrase protected),
 *     matching what ssh-keygen -p produces by default.
 *
 * All key material is exchanged with the rest of the app as Node crypto
 * KeyObject instances; no third-party big-number or ASN.1 code is used.
 * ---------------------------------------------------------------------------
 */

'use strict';

const crypto = require('crypto');
const bcryptPbkdf = require('bcrypt-pbkdf');

const MAGIC = 'openssh-key-v1\u0000';
const BCRYPT_ROUNDS = 16; // ssh-keygen default

/* ------------------------------------------------------------------------
 * SSH wire helpers
 * ---------------------------------------------------------------------- */

function sshStr(s) {
  const b = Buffer.isBuffer(s) ? s : Buffer.from(s, 'utf8');
  const out = Buffer.alloc(4 + b.length);
  out.writeUInt32BE(b.length, 0);
  b.copy(out, 4);
  return out;
}

function sshU32(n) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(n >>> 0, 0);
  return out;
}

/** Unsigned big-endian buffer -> SSH mpint (minimal two's complement). */
function sshMpint(buf) {
  let i = 0;
  while (i < buf.length && buf[i] === 0) i++;
  let b = buf.subarray(i);
  if (b.length === 0) return Buffer.alloc(4);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return sshStr(b);
}

class Reader {
  constructor(buf) { this.buf = buf; this.off = 0; }
  u32() {
    if (this.off + 4 > this.buf.length) throw new Error('Truncated key data');
    const v = this.buf.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }
  str() {
    const len = this.u32();
    if (this.off + len > this.buf.length) throw new Error('Truncated key data');
    const v = this.buf.subarray(this.off, this.off + len);
    this.off += len;
    return v;
  }
  rest() { return this.buf.subarray(this.off); }
}

function b64url(buf) { return buf.toString('base64url'); }
function padLeft(buf, len) {
  if (buf.length >= len) return buf.subarray(buf.length - len);
  return Buffer.concat([Buffer.alloc(len - buf.length), buf]);
}
/** Encode an unsigned big-endian buffer for JWK, dropping a leading sign byte. */
function jwkInt(buf) {
  let b = buf;
  while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  return b.toString('base64url');
}
/** Convert a BigInt to an unsigned big-endian buffer. */
function bigintToBuf(bn) {
  let hex = bn.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

const COORD_LEN = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };
const CRV_TO_NIST = { 'P-256': 'nistp256', 'P-384': 'nistp384', 'P-521': 'nistp521' };
const NIST_TO_CRV = { nistp256: 'P-256', nistp384: 'P-384', nistp521: 'P-521' };

/* ------------------------------------------------------------------------
 * Cipher table for encrypted private sections
 * ---------------------------------------------------------------------- */

const CIPHERS = {
  'none': { keyLen: 0, ivLen: 0, blockSize: 8 },
  'aes256-ctr': { keyLen: 32, ivLen: 16, blockSize: 16 },
  'aes256-gcm': { keyLen: 32, ivLen: 12, blockSize: 16, tagLen: 16 },
  'chacha20-poly1305@openssh.com': { keyLen: 64, ivLen: 0, blockSize: 8, tagLen: 16 }
};

function bcryptKdf(passphrase, salt, rounds, keyLen) {
  const pw = Buffer.from(passphrase || '', 'utf8');
  const out = Buffer.alloc(keyLen);
  bcryptPbkdf.pbkdf(pw, pw.length, salt, salt.length, out, out.length, rounds);
  return out;
}

/* ------------------------------------------------------------------------
 * Parsing
 * ---------------------------------------------------------------------- */

function decodeBody(pem) {
  const text = String(pem || '').trim();
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('-----'));
  if (!/BEGIN OPENSSH PRIVATE KEY/.test(text)) {
    throw new Error('Not an OpenSSH private key block');
  }
  return Buffer.from(lines.join(''), 'base64');
}

function decryptPrivateSection(ciphername, kdfname, kdfOptions, encrypted, passphrase) {
  if (ciphername === 'none') {
    if (kdfname !== 'none' || kdfOptions.length !== 0) {
      throw new Error('Inconsistent cipher/KDF options for unencrypted key');
    }
    return encrypted;
  }
  if (kdfname !== 'bcrypt') throw new Error('Unsupported KDF: ' + kdfname);
  const info = CIPHERS[ciphername];
  if (!info) throw new Error('Unsupported cipher: ' + ciphername);
  if (passphrase === undefined || passphrase === null || passphrase === '') {
    throw new Error('This key is encrypted; a passphrase is required.');
  }

  // kdf options: string salt, uint32 rounds
  const r = new Reader(kdfOptions);
  const salt = Buffer.from(r.str());
  const rounds = r.u32();
  const keymat = bcryptKdf(passphrase, salt, rounds, info.keyLen + info.ivLen);
  const key = keymat.subarray(0, info.keyLen);
  const iv = keymat.subarray(info.keyLen, info.keyLen + info.ivLen);

  if (ciphername === 'chacha20-poly1305@openssh.com') {
    // Layout: [4-byte encrypted length][payload ciphertext][16-byte tag]
    // - header key (second 32 bytes) decrypts the length field (counter 0)
    // - main key (first 32 bytes) decrypts the payload (counter 1)
    // - poly1305 tag covers encrypted length || payload ciphertext
    // seqnr/nonce is zero for private key files.
    if (encrypted.length < 4 + 16) throw new Error('Truncated encrypted section');
    const mainKey = key.subarray(0, 32);
    const headerKey = key.subarray(32, 64);
    const encLen = encrypted.subarray(0, 4);
    const tag = encrypted.subarray(encrypted.length - 16);
    const ct = encrypted.subarray(4, encrypted.length - 16);

    const lenDec = crypto.createCipheriv('chacha20', headerKey, Buffer.concat([Buffer.alloc(4), Buffer.alloc(12)]));
    const payloadLen = lenDec.update(encLen).readUInt32BE(0);
    if (payloadLen !== ct.length) throw new Error('Corrupt encrypted section (length mismatch)');

    const dec = crypto.createDecipheriv('chacha20-poly1305', mainKey, Buffer.alloc(12), { authTagLength: 16 });
    dec.setAAD(encLen);
    dec.setAuthTag(tag);
    return Buffer.concat([dec.update(ct), dec.final()]);
  }

  if (ciphername === 'aes256-gcm') {
    const tag = encrypted.subarray(encrypted.length - 16);
    const ct = encrypted.subarray(0, encrypted.length - 16);
    const dec = crypto.createDecipheriv('aes-256-gcm', key, iv); // OpenSSL name
    dec.setAuthTag(tag);
    return Buffer.concat([dec.update(ct), dec.final()]);
  }

  // aes256-ctr (and any future plain stream cipher)
  const opensslName = ciphername.replace(/^aes(\d+)-/, 'aes-$1-'); // aes256-ctr -> aes-256-ctr
  const dec = crypto.createDecipheriv(opensslName, key, iv);
  return Buffer.concat([dec.update(encrypted), dec.final()]);
}

function buildPrivateKeyObject(typeName, r) {
  if (typeName === 'ssh-rsa') {
    const n = Buffer.from(r.str());
    const e = Buffer.from(r.str());
    const d = Buffer.from(r.str());
    const iqmp = Buffer.from(r.str());
    const p = Buffer.from(r.str());
    const q = Buffer.from(r.str());
    const P = BigInt('0x' + (p.toString('hex') || '0'));
    const Q = BigInt('0x' + (q.toString('hex') || '0'));
    const D = BigInt('0x' + (d.toString('hex') || '0'));
    const dp = D % (P - 1n);
    const dq = D % (Q - 1n);
    const jwk = {
      kty: 'RSA',
      n: jwkInt(n), e: jwkInt(e), d: jwkInt(d),
      p: jwkInt(p), q: jwkInt(q),
      dp: jwkInt(bigintToBuf(dp)), dq: jwkInt(bigintToBuf(dq)), qi: jwkInt(iqmp)
    };
    return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  }
  if (typeName === 'ssh-ed25519') {
    const pub = Buffer.from(r.str());
    const priv = Buffer.from(r.str()); // 64 bytes: seed || pub
    if (pub.length !== 32 || priv.length !== 64) throw new Error('Malformed ed25519 key');
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(pub), d: b64url(priv.subarray(0, 32)) };
    return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  }
  if (typeName.startsWith('ecdsa-sha2-')) {
    const curve = r.str().toString('ascii');
    const Q = Buffer.from(r.str());
    const d = Buffer.from(r.str());
    const crv = NIST_TO_CRV[curve];
    if (!crv) throw new Error('Unsupported ECDSA curve: ' + curve);
    if (Q.length < 1 || Q[0] !== 4) throw new Error('Unsupported EC point encoding');
    const L = COORD_LEN[crv];
    const x = Q.subarray(1, 1 + L);
    const y = Q.subarray(1 + L, 1 + 2 * L);
    const jwk = { kty: 'EC', crv, x: b64url(x), y: b64url(y), d: b64url(padLeft(d, L)) };
    return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  }
  throw new Error('Unsupported key type in OpenSSH file: ' + typeName);
}

/**
 * Parse an openssh-key-v1 private key.
 * @param {string} pem  Raw file contents.
 * @param {string} [passphrase]  Required when the key is encrypted.
 * @returns {{ keyObject: import('crypto').KeyObject, comment: string,
 *             ciphername: string, kdfname: string }}
 */
function parseOpenSSHPrivateKey(pem, passphrase) {
  const body = decodeBody(pem);
  if (body.subarray(0, MAGIC.length).toString('latin1') !== MAGIC) {
    throw new Error('Bad OpenSSH private key magic');
  }
  const r = new Reader(body.subarray(MAGIC.length));
  const ciphername = r.str().toString('ascii');
  const kdfname = r.str().toString('ascii');
  const kdfOptions = Buffer.from(r.str());
  const nkeys = r.u32();
  if (nkeys !== 1) throw new Error('Expected exactly one key, found ' + nkeys);
  r.str(); // public key blob (we regenerate it from the private material)
  const encryptedSection = Buffer.from(r.str());

  const section = decryptPrivateSection(ciphername, kdfname, kdfOptions, encryptedSection, passphrase);

  // Plaintext section: u32 checkint, u32 checkint, key fields, comment, padding
  const p = new Reader(section);
  const check1 = p.u32();
  const check2 = p.u32();
  if (check1 !== check2) {
    throw new Error('Incorrect passphrase (check integer mismatch).');
  }
  const typeName = p.str().toString('ascii');
  const keyObject = buildPrivateKeyObject(typeName, p);
  const comment = p.str().toString('utf8');
  return { keyObject, comment, ciphername, kdfname };
}

/* ------------------------------------------------------------------------
 * Serialization
 * ---------------------------------------------------------------------- */

function publicBlobFromJwk(jwk) {
  if (jwk.kty === 'RSA') {
    return Buffer.concat([
      sshStr('ssh-rsa'),
      sshMpint(Buffer.from(jwk.e, 'base64url')),
      sshMpint(Buffer.from(jwk.n, 'base64url'))
    ]);
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return Buffer.concat([sshStr('ssh-ed25519'), sshStr(Buffer.from(jwk.x, 'base64url'))]);
  }
  if (jwk.kty === 'EC') {
    const nist = CRV_TO_NIST[jwk.crv];
    if (!nist) throw new Error('Unsupported curve: ' + jwk.crv);
    const L = COORD_LEN[jwk.crv];
    const Q = Buffer.concat([
      Buffer.from([4]),
      padLeft(Buffer.from(jwk.x, 'base64url'), L),
      padLeft(Buffer.from(jwk.y, 'base64url'), L)
    ]);
    return Buffer.concat([sshStr('ecdsa-sha2-' + nist), sshStr(nist), sshStr(Q)]);
  }
  throw new Error('Unsupported key type');
}

function privateFieldsFromJwk(jwk) {
  if (jwk.kty === 'RSA') {
    return Buffer.concat([
      sshStr('ssh-rsa'),
      sshMpint(Buffer.from(jwk.n, 'base64url')),
      sshMpint(Buffer.from(jwk.e, 'base64url')),
      sshMpint(Buffer.from(jwk.d, 'base64url')),
      sshMpint(Buffer.from(jwk.qi, 'base64url')),
      sshMpint(Buffer.from(jwk.p, 'base64url')),
      sshMpint(Buffer.from(jwk.q, 'base64url'))
    ]);
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    const pub = Buffer.from(jwk.x, 'base64url');
    const seed = Buffer.from(jwk.d, 'base64url');
    return Buffer.concat([sshStr('ssh-ed25519'), sshStr(pub), sshStr(Buffer.concat([seed, pub]))]);
  }
  if (jwk.kty === 'EC') {
    const nist = CRV_TO_NIST[jwk.crv];
    if (!nist) throw new Error('Unsupported curve: ' + jwk.crv);
    const L = COORD_LEN[jwk.crv];
    const Q = Buffer.concat([
      Buffer.from([4]),
      padLeft(Buffer.from(jwk.x, 'base64url'), L),
      padLeft(Buffer.from(jwk.y, 'base64url'), L)
    ]);
    return Buffer.concat([
      sshStr('ecdsa-sha2-' + nist),
      sshStr(nist),
      sshStr(Q),
      sshMpint(Buffer.from(jwk.d, 'base64url'))
    ]);
  }
  throw new Error('Unsupported key type');
}

/**
 * Serialize a private KeyObject into the OpenSSH new format.
 * @param {import('crypto').KeyObject} privateKeyObj
 * @param {{ comment?: string, passphrase?: string, rounds?: number }} opts
 * @returns {string} PEM-armored openssh-key-v1 file contents.
 */
function serializeOpenSSHPrivateKey(privateKeyObj, opts = {}) {
  const comment = String(opts.comment || '');
  const passphrase = opts.passphrase || '';
  const rounds = Number(opts.rounds) > 0 ? Number(opts.rounds) : BCRYPT_ROUNDS;
  const jwk = privateKeyObj.export({ format: 'jwk' });
  const pubBlob = publicBlobFromJwk(jwk);

  // Plaintext private section: checkint twice, fields, comment, padding.
  const check = crypto.randomBytes(4);
  let section = Buffer.concat([check, check, privateFieldsFromJwk(jwk), sshStr(comment)]);

  let ciphername = 'none';
  let kdfname = 'none';
  let kdfOptions = Buffer.alloc(0);
  let blockSize = 8;

  if (passphrase) {
    ciphername = 'aes256-ctr';
    kdfname = 'bcrypt';
    blockSize = 16;
    const salt = crypto.randomBytes(16);
    kdfOptions = Buffer.concat([sshStr(salt), sshU32(rounds)]);
    const keymat = bcryptKdf(passphrase, salt, rounds, 32 + 16);
    const key = keymat.subarray(0, 32);
    const iv = keymat.subarray(32, 48);
    // pad to cipher block size (1, 2, 3, ... as OpenSSH does)
    let pad = 0;
    const padded = [];
    padded.push(section);
    while ((section.length + pad) % blockSize !== 0) pad++;
    if (pad > 0) {
      const padBytes = Buffer.alloc(pad);
      for (let i = 0; i < pad; i++) padBytes[i] = (i + 1) & 0xff;
      section = Buffer.concat([section, padBytes]);
    }
    const enc = crypto.createCipheriv('aes-256-ctr', key, iv);
    section = Buffer.concat([enc.update(section), enc.final()]);
  } else {
    // pad to 8
    let pad = 0;
    while ((section.length + pad) % 8 !== 0) pad++;
    if (pad > 0) {
      const padBytes = Buffer.alloc(pad);
      for (let i = 0; i < pad; i++) padBytes[i] = (i + 1) & 0xff;
      section = Buffer.concat([section, padBytes]);
    }
  }

  const body = Buffer.concat([
    Buffer.from(MAGIC, 'latin1'),
    sshStr(ciphername),
    sshStr(kdfname),
    sshStr(kdfOptions),
    sshU32(1),
    sshStr(pubBlob),
    sshStr(section)
  ]);

  const b64 = body.toString('base64');
  const lines = b64.match(/.{1,70}/g) || [];
  return '-----BEGIN OPENSSH PRIVATE KEY-----\n' + lines.join('\n') +
         '\n-----END OPENSSH PRIVATE KEY-----\n';
}

module.exports = {
  parseOpenSSHPrivateKey,
  serializeOpenSSHPrivateKey,
  // exported for tests
  _internals: { bcryptKdf, CIPHERS, Reader, sshStr, sshMpint }
};
