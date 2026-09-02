/**
 * keyService.js
 * ---------------------------------------------------------------------------
 * SSH key lifecycle: generation, import, export, fingerprinting, and
 * authorized_keys formatting. Built entirely on Node's native 'crypto'
 * module (no third-party crypto dependencies):
 *
 *   - generateKeyPairSync for RSA / Ed25519 / ECDSA (nistp256/384/521)
 *   - JWK as the internal interchange format
 *   - OpenSSH wire-format encoding for public keys and fingerprints
 *
 * Fingerprints are computed exactly like ssh-keygen -lf:
 *   SHA256:<base64(sha256(SSH public key wire blob))>  (no padding)
 * ---------------------------------------------------------------------------
 */

'use strict';

const crypto = require('crypto');
const { parseOpenSSHPrivateKey, serializeOpenSSHPrivateKey } = require('./opensshParser');
const puttyParser = require('./puttyParser');

const VALID_TYPES = ['rsa', 'ed25519', 'ecdsa'];

/** nist name -> OpenSSL curve name (for generation) */
const CURVE_FOR_NIST = {
  nistp256: 'prime256v1',
  nistp384: 'secp384r1',
  nistp521: 'secp521r1'
};

/** JWK crv -> SSH nist name */
const NIST_FOR_CRV = {
  'P-256': 'nistp256',
  'P-384': 'nistp384',
  'P-521': 'nistp521'
};

/** JWK crv -> uncompressed coordinate byte length */
const COORD_LEN = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };

// ---------------------------------------------------------------------------
// SSH wire-format helpers
// ---------------------------------------------------------------------------

/** Encode an SSH "string": u32 length prefix + raw bytes. */
function sshString(value) {
  const b = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  const out = Buffer.alloc(4 + b.length);
  out.writeUInt32BE(b.length, 0);
  b.copy(out, 4);
  return out;
}

/** Encode an SSH "mpint" from an unsigned big-endian buffer. */
function sshMpint(buf) {
  let i = 0;
  while (i < buf.length && buf[i] === 0) i++;
  let body = buf.subarray(i);
  if (body.length === 0) return Buffer.alloc(4); // canonical zero
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0x00]), body]);
  return sshString(body);
}

function b64urlBuf(s) {
  return Buffer.from(s, 'base64url');
}

function padLeft(buf, len) {
  if (buf.length >= len) return buf;
  return Buffer.concat([Buffer.alloc(len - buf.length), buf]);
}

/**
 * Build the SSH public-key wire blob from a JWK.
 * Returns { typeName, blob }.
 */
function sshBlobFromJwk(jwk) {
  if (jwk.kty === 'RSA') {
    const blob = Buffer.concat([
      sshString('ssh-rsa'),
      sshMpint(b64urlBuf(jwk.e)),
      sshMpint(b64urlBuf(jwk.n))
    ]);
    return { typeName: 'ssh-rsa', blob };
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    const blob = Buffer.concat([
      sshString('ssh-ed25519'),
      sshString(b64urlBuf(jwk.x))
    ]);
    return { typeName: 'ssh-ed25519', blob };
  }
  if (jwk.kty === 'EC') {
    const nist = NIST_FOR_CRV[jwk.crv];
    if (!nist) throw new Error('Unsupported EC curve: ' + jwk.crv);
    const L = COORD_LEN[jwk.crv];
    const Q = Buffer.concat([
      Buffer.from([0x04]),
      padLeft(b64urlBuf(jwk.x), L),
      padLeft(b64urlBuf(jwk.y), L)
    ]);
    const typeName = 'ecdsa-sha2-' + nist;
    const blob = Buffer.concat([
      sshString(typeName),
      sshString(nist),
      sshString(Q)
    ]);
    return { typeName, blob };
  }
  throw new Error('Unsupported JWK key type: ' + jwk.kty);
}

/**
 * Rebuild a public KeyObject from an SSH public-key wire blob.
 */
function publicKeyFromSshBlob(blob) {
  let off = 0;
  const read = () => {
    if (off + 4 > blob.length) throw new Error('Truncated SSH key blob');
    const len = blob.readUInt32BE(off);
    off += 4;
    if (off + len > blob.length) throw new Error('Truncated SSH key blob');
    const v = blob.subarray(off, off + len);
    off += len;
    return v;
  };
  const typeName = read().toString('ascii');
  let jwk;
  if (typeName === 'ssh-rsa') {
    const e = read();
    const n = read();
    jwk = { kty: 'RSA', n: n.toString('base64url'), e: e.toString('base64url') };
  } else if (typeName === 'ssh-ed25519') {
    const x = read();
    if (x.length !== 32) throw new Error('Invalid Ed25519 public key length');
    jwk = { kty: 'OKP', crv: 'Ed25519', x: x.toString('base64url') };
  } else if (typeName.startsWith('ecdsa-sha2-')) {
    const curve = read().toString('ascii');
    const Q = read();
    const crv = { nistp256: 'P-256', nistp384: 'P-384', nistp521: 'P-521' }[curve];
    if (!crv) throw new Error('Unsupported ECDSA curve: ' + curve);
    const L = COORD_LEN[crv];
    if (Q.length !== 1 + 2 * L || Q[0] !== 0x04) {
      throw new Error('Malformed ECDSA point encoding');
    }
    jwk = {
      kty: 'EC',
      crv,
      x: Q.subarray(1, 1 + L).toString('base64url'),
      y: Q.subarray(1 + L, 1 + 2 * L).toString('base64url')
    };
  } else {
    throw new Error('Unsupported SSH key type: ' + typeName);
  }
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

/**
 * SSH fingerprint (ssh-keygen -lf compatible) of a public wire blob.
 */
function fingerprintFromBlob(blob) {
  const digest = crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
  return 'SHA256:' + digest;
}

/** Derive { type, bits } from a public KeyObject. */
function keyMeta(publicKeyObj) {
  const t = publicKeyObj.asymmetricKeyType;
  if (t === 'rsa' || t === 'rsa-pss') {
    const details = publicKeyObj.asymmetricKeyDetails || {};
    return { type: 'rsa', bits: details.modulusLength || 0 };
  }
  if (t === 'ed25519') return { type: 'ed25519', bits: 256 };
  if (t === 'ec') {
    const curve = (publicKeyObj.asymmetricKeyDetails || {}).namedCurve;
    const bits = { prime256v1: 256, secp384r1: 384, secp521r1: 521 }[curve] || 0;
    return { type: 'ecdsa', bits };
  }
  throw new Error('Unsupported key type: ' + t);
}

// ---------------------------------------------------------------------------
// Record builders
// ---------------------------------------------------------------------------

/**
 * Build a key record (the shape stored in the database) from a key pair.
 */
function buildRecord(privateKeyObj, publicKeyObj, comment) {
  const meta = keyMeta(publicKeyObj);
  const { blob } = sshBlobFromJwk(publicKeyObj.export({ format: 'jwk' }));
  const authorizedKey = sshLine(publicKeyObj, comment);
  return {
    id: crypto.randomUUID(),
    type: meta.type,
    bits: meta.bits,
    comment: comment || '',
    privateKeyPem: privateKeyObj.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKeyObj.export({ type: 'spki', format: 'pem' }).toString(),
    publicAuthorizedKey: authorizedKey,
    fingerprint: fingerprintFromBlob(blob),
    encrypted: 0,
    createdAt: Date.now(),
    updatedAt: Date.now()
  };
}

/** Public-only record (imported from a public key / authorized_keys line). */
function buildPublicOnlyRecord(publicKeyObj, comment) {
  const meta = keyMeta(publicKeyObj);
  const { blob } = sshBlobFromJwk(publicKeyObj.export({ format: 'jwk' }));
  return {
    id: crypto.randomUUID(),
    type: meta.type,
    bits: meta.bits,
    comment: comment || '',
    privateKeyPem: '',
    publicKeyPem: publicKeyObj.export({ type: 'spki', format: 'pem' }).toString(),
    publicAuthorizedKey: sshLine(publicKeyObj, comment),
    fingerprint: fingerprintFromBlob(blob),
    encrypted: 0,
    publicOnly: true,
    createdAt: Date.now(),
    updatedAt: Date.now()
  };
}

/** authorized_keys style single line for a public KeyObject. */
function sshLine(publicKeyObj, comment) {
  const { typeName, blob } = sshBlobFromJwk(publicKeyObj.export({ format: 'jwk' }));
  let line = typeName + ' ' + blob.toString('base64');
  if (comment) line += ' ' + comment;
  return line;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function normalizeType(type) {
  const t = String(type || '').toLowerCase();
  if (VALID_TYPES.includes(t)) return t;
  throw new Error('Unsupported key type: ' + type);
}

/**
 * Generate a new key pair.
 * @param {{type:string, bits?:number, curve?:string, comment?:string}} opts
 */
function generate(opts = {}) {
  const type = normalizeType(opts.type);
  const comment = String(opts.comment || '').trim();
  let keypair;
  if (type === 'rsa') {
    const bits = Number(opts.bits) || 4096;
    if (!Number.isInteger(bits) || bits < 2048 || bits > 8192) {
      throw new Error('RSA key size must be between 2048 and 8192 bits.');
    }
    keypair = crypto.generateKeyPairSync('rsa', {
      modulusLength: bits,
      publicExponent: 0x10001
    });
  } else if (type === 'ed25519') {
    keypair = crypto.generateKeyPairSync('ed25519');
  } else {
    const nist = opts.curve && CURVE_FOR_NIST[opts.curve] ? opts.curve : 'nistp256';
    keypair = crypto.generateKeyPairSync('ec', { namedCurve: CURVE_FOR_NIST[nist] });
  }
  return buildRecord(keypair.privateKey, keypair.publicKey, comment);
}

/**
 * Import key material. Accepts:
 *   - PEM private keys (PKCS#8, PKCS#1, SEC1), optionally passphrase-protected
 *   - PEM public keys (SPKI)
 *   - authorized_keys public lines ("ssh-ed25519 AAAA... comment")
 * Returns a key record; public-only imports have privateKeyPem === ''.
 */
function parsePem(text, passphrase) {
  const t = String(text || '').trim();
  if (!t) throw new Error('No key material provided.');

  // Public one-liner? (authorized_keys / ssh-keygen .pub style)
  const firstLine = t.split(/\r?\n/)[0].trim();
  if (/^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/=]+/.test(firstLine)) {
    const parts = firstLine.split(/\s+/);
    let blob;
    try {
      blob = Buffer.from(parts[1], 'base64');
    } catch (e) {
      throw new Error('Malformed base64 in public key line.');
    }
    const pub = publicKeyFromSshBlob(blob);
    return buildPublicOnlyRecord(pub, parts.slice(2).join(' '));
  }

  // Try PEM private key first (handles encrypted PEM when passphrase given).
  let privateKeyObj = null;
  let privateErr = null;
  try {
    privateKeyObj = crypto.createPrivateKey({
      key: t,
      format: 'pem',
      passphrase: passphrase || undefined
    });
  } catch (e) {
    privateErr = e;
  }
  if (privateKeyObj) {
    const publicKeyObj = crypto.createPublicKey(privateKeyObj);
    return buildRecord(privateKeyObj, publicKeyObj, '');
  }

  // Maybe a public-key PEM?
  try {
    const publicKeyObj = crypto.createPublicKey({ key: t, format: 'pem' });
    return buildPublicOnlyRecord(publicKeyObj, '');
  } catch (e) {
    throw new Error(
      'Unable to parse key material' +
      (privateErr && /passphrase|bad decrypt|encrypted/i.test(String(privateErr.message))
        ? ' (check the passphrase for this encrypted key)'
        : '.')
    );
  }
}

/**
 * Import an OpenSSH new-format private key file (openssh-key-v1),
 * optionally passphrase protected.
 */
function parseOpenSshFile(pem, passphrase) {
  const parsed = parseOpenSSHPrivateKey(pem, passphrase);
  const publicKeyObj = crypto.createPublicKey(parsed.keyObject);
  const record = buildRecord(parsed.keyObject, publicKeyObj, parsed.comment || '');
  return record;
}

/**
 * Import a PuTTY private key file (.ppk, version 3 only).
 * Passphrase-protected files require a passphrase; version 2 files are
 * rejected with guidance because their KDF and MAC are SHA-1 based.
 */
async function parsePuttyFile(text, passphrase) {
  const parsed = await puttyParser.parsePPK(text, passphrase);
  const publicKeyObj = crypto.createPublicKey(parsed.keyObject);
  return buildRecord(parsed.keyObject, publicKeyObj, parsed.comment || '');
}

/** True when `text` looks like a PuTTY .ppk file. */
function isPuttyKey(text) {
  return puttyParser.isPPK(text);
}

/**
 * Export a private key as OpenSSH new format.
 * With a passphrase the key is encrypted (aes256-ctr + bcrypt KDF);
 * without one it is written unencrypted.
 */
function toOpenSSHPrivateKey(privateKeyPem, opts = {}) {
  const keyObject = crypto.createPrivateKey(privateKeyPem);
  return serializeOpenSSHPrivateKey(keyObject, {
    comment: opts.comment || '',
    passphrase: opts.passphrase || ''
  });
}

/**
 * Export a private key as a PuTTY .ppk file (version 3).
 * With a passphrase the key is encrypted (aes256-cbc + Argon2id);
 * without one it is written unencrypted.
 */
async function toPuttyPrivateKey(privateKeyPem, opts = {}) {
  const keyObject = crypto.createPrivateKey(privateKeyPem);
  return puttyParser.serializePPK(keyObject, {
    comment: opts.comment || '',
    passphrase: opts.passphrase || ''
  });
}

/**
 * Export a private key as PKCS#8 PEM. With a passphrase the PEM is
 * encrypted (AES-256-CBC, PBES2).
 */
function toPkcs8PrivateKey(privateKeyPem, passphrase) {
  const keyObject = crypto.createPrivateKey(privateKeyPem);
  if (passphrase) {
    return keyObject
      .export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase })
      .toString();
  }
  return keyObject.export({ type: 'pkcs8', format: 'pem' }).toString();
}

/** authorized_keys line for a stored public-key PEM or a public KeyObject. */
function toAuthorizedKey(publicKeyPem, comment) {
  let publicKeyObj;
  if (typeof publicKeyPem === 'object' && publicKeyPem !== null && typeof publicKeyPem.export === 'function') {
    // Already a KeyObject. Accept public keys directly; derive from private keys.
    publicKeyObj = publicKeyPem.type === 'private' ? crypto.createPublicKey(publicKeyPem) : publicKeyPem;
  } else {
    publicKeyObj = crypto.createPublicKey(publicKeyPem);
  }
  return sshLine(publicKeyObj, comment || '');
}

/** Fingerprint of a stored public-key PEM (ssh-keygen compatible). */
function fingerprintOf(publicKeyPem) {
  const publicKeyObj = crypto.createPublicKey(publicKeyPem);
  const { blob } = sshBlobFromJwk(publicKeyObj.export({ format: 'jwk' }));
  return fingerprintFromBlob(blob);
}

module.exports = {
  generate,
  parsePem,
  parseOpenSshFile,
  parsePuttyFile,
  isPuttyKey,
  toOpenSSHPrivateKey,
  toPuttyPrivateKey,
  toPkcs8PrivateKey,
  toAuthorizedKey,
  fingerprintOf,
  // exported for tests and advanced consumers
  internals: {
    sshBlobFromJwk,
    publicKeyFromSshBlob,
    fingerprintFromBlob,
    sshString,
    sshMpint
  }
};
