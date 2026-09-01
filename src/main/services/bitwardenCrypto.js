/**
 * bitwardenCrypto.js
 * ---------------------------------------------------------------------------
 * The minimal subset of the Bitwarden client-side crypto stack needed to
 * store SSH key items in a Bitwarden-compatible vault (Bitwarden cloud or
 * Vaultwarden):
 *
 *   1. Master key derivation from email + master password
 *      (PBKDF2-SHA256 or Argon2id, per the server's prelogin answer).
 *   2. The login password hash sent to /identity/connect/token
 *      (PBKDF2-SHA256 over the master key, 1 iteration, password as salt).
 *   3. Master-key stretching via HKDF-Expand (SHA-256, info "enc"/"mac")
 *      into a 64-byte symmetric key — used to unwrap the account's user key.
 *   4. EncString encryption/decryption with the current Bitwarden wire
 *      format "2.<iv>|<ct>|<mac>". The format is protocol-mandated:
 *      AES-256-CBC for confidentiality with an encrypt-then-MAC HMAC-SHA256
 *      seal over iv||ct that is verified (timing-safe) BEFORE decryption.
 *      The block cipher runs through WebCrypto SubtleCrypto — the same
 *      primitive the official Bitwarden clients use.
 *
 * Only HMAC-verified decryptions succeed; every cipher field we send is
 * encrypted locally — the server only ever sees ciphertext.
 *
 * Note: SubtleCrypto is async, so encryptString/decryptString/deriveMasterKey
 * return Promises. The sync engine is already async, so this is transparent.
 * ---------------------------------------------------------------------------
 */

'use strict';

const nodeCrypto = require('crypto');

/** WebCrypto SubtleCrypto (Node 18+ / Electron). */
const subtle = nodeCrypto.webcrypto.subtle;

const ENC_TYPE = 2; // AesCbc256_HmacSha256_B64 — the only encString type we read/write

/** PBKDF2-HMAC-SHA256 helper (sync). */
function pbkdf2Sha256(passwordBuf, saltBuf, iterations, length) {
  return nodeCrypto.pbkdf2Sync(passwordBuf, saltBuf, iterations, length, 'sha256');
}

/**
 * Derive the 32-byte master key from the master password and account email.
 * kdf: { kdfType: 0, iterations } for PBKDF2 or
 *      { kdfType: 1, iterations, memory (KiB), parallelism } for Argon2id.
 * Argon2id is provided by hash-wasm (pure WASM — no native build, matching
 * this project's dependency policy).
 */
async function deriveMasterKey(password, email, kdf) {
  const pw = Buffer.from(String(password), 'utf8');
  const salt = Buffer.from(String(email).trim().toLowerCase(), 'utf8');
  const type = Number(kdf && kdf.kdfType) || 0;
  if (type === 0) {
    const iterations = Number(kdf && kdf.iterations) || 600000;
    return pbkdf2Sha256(pw, salt, iterations, 32);
  }
  if (type === 1) {
    // Lazy require: only accounts configured for Argon2id ever load it.
    const { argon2id } = require('hash-wasm');
    return Buffer.from(await argon2id({
      password: pw,
      salt,
      parallelism: Number(kdf && kdf.parallelism) || 4,
      iterations: Number(kdf && kdf.iterations) || 3,
      memorySize: Number(kdf && kdf.memory) || 64, // KiB
      hashLength: 32,
      outputType: 'binary'
    }));
  }
  throw new Error('Unsupported Bitwarden KDF type: ' + type);
}

/**
 * The password hash used for /identity/connect/token:
 * PBKDF2-SHA256(masterKey, salt = master password, 1 iteration), base64.
 */
function masterPasswordHash(masterKey, password) {
  return pbkdf2Sha256(masterKey, Buffer.from(String(password), 'utf8'), 1, 32).toString('base64');
}

/**
 * HKDF-Expand only (RFC 5869, N <= 1 for SHA-256 inputs of 32 bytes) —
 * Bitwarden expands the master key directly, without the Extract step.
 */
function hkdfExpandSha256(prk, info, length) {
  const hashLen = 32;
  if (prk.length < hashLen) throw new Error('HKDF-Expand: PRK too short');
  if (length > 255 * hashLen) throw new Error('HKDF-Expand: length too large');
  const infoBuf = Buffer.isBuffer(info) ? info : Buffer.from(info, 'utf8');
  const blocks = Math.ceil(length / hashLen);
  let t = Buffer.alloc(0);
  const okm = [];
  for (let i = 1; i <= blocks; i++) {
    t = nodeCrypto.createHmac('sha256', prk)
      .update(Buffer.concat([t, infoBuf, Buffer.from([i])]))
      .digest();
    okm.push(t);
  }
  return Buffer.concat(okm).subarray(0, length);
}

/**
 * Stretch a 32-byte master key into a 64-byte symmetric key
 * (enc key || mac key) the way Bitwarden clients do.
 */
function stretchMasterKey(masterKey) {
  return Buffer.concat([
    hkdfExpandSha256(masterKey, 'enc', 32),
    hkdfExpandSha256(masterKey, 'mac', 32)
  ]);
}

/** Split a 64-byte key into { encKey, macKey }. */
function splitKey64(key) {
  if (key.length === 64) return { encKey: key.subarray(0, 32), macKey: key.subarray(32, 64) };
  throw new Error('Invalid symmetric key length: ' + key.length);
}

function hmacSha256(macKey, data) {
  return nodeCrypto.createHmac('sha256', macKey).update(data).digest();
}

/** Constant-time Buffer equality. */
function timingSafeEq(a, b) {
  if (a.length !== b.length) return false;
  return nodeCrypto.timingSafeEqual(a, b);
}

/** Import a 32-byte AES key once per operation. */
function importAesKey(encKey) {
  return subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
}

/**
 * Encrypt raw bytes with a 64-byte key, producing a type-2 encString.
 * (Counterpart of decryptToBytes; item fields use the UTF-8 variant below.)
 */
async function encryptBytes(plaintext, key64) {
  const { encKey, macKey } = splitKey64(key64);
  const iv = nodeCrypto.randomBytes(16);
  const aesKey = await importAesKey(encKey);
  const ct = Buffer.from(await subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, plaintext));
  const mac = hmacSha256(macKey, Buffer.concat([iv, ct]));
  return '2.' + [iv, ct, mac].map(b => b.toString('base64')).join('|');
}

/**
 * Encrypt plaintext (string) with a 64-byte key, producing an encString:
 *   "2.<base64 iv>|<base64 ct>|<base64 mac>"
 */
async function encryptString(plaintext, key64) {
  const { encKey, macKey } = splitKey64(key64);
  const iv = nodeCrypto.randomBytes(16);
  const aesKey = await importAesKey(encKey);
  const ct = Buffer.from(await subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, Buffer.from(String(plaintext), 'utf8')));
  const mac = hmacSha256(macKey, Buffer.concat([iv, ct]));
  return '2.' + [iv, ct, mac].map(b => b.toString('base64')).join('|');
}

/**
 * Parse an encString into its parts. Only the current type-2 format is
 * accepted; legacy type 0/1 items (pre-2018 clients) are rejected with a
 * clear error instead of silently mishandled.
 */
function parseEncString(s) {
  const str = String(s || '');
  const dot = str.indexOf('.');
  if (dot < 1) throw new Error('Malformed encString (missing type)');
  const type = Number(str.slice(0, dot));
  if (type !== ENC_TYPE) {
    throw new Error('Unsupported encString type ' + type + ' (only type 2 is supported)');
  }
  const parts = str.slice(dot + 1).split('|');
  if (parts.length !== 3) throw new Error('Malformed encString (expected iv|ct|mac)');
  const iv = Buffer.from(parts[0], 'base64');
  const ct = Buffer.from(parts[1], 'base64');
  const mac = Buffer.from(parts[2], 'base64');
  if (iv.length !== 16) throw new Error('Bad IV length in encString');
  if (mac.length !== 32) throw new Error('Bad MAC length in encString');
  return { type, iv, ct, mac };
}

/**
 * Decrypt an encString with a 64-byte symmetric key and return the RAW
 * plaintext bytes (HMAC verified timing-safely before decryption).
 */
async function decryptToBytes(encString, key64) {
  const { encKey, macKey } = splitKey64(key64);
  const { iv, ct, mac } = parseEncString(encString);
  const expectedMac = hmacSha256(macKey, Buffer.concat([iv, ct]));
  if (!timingSafeEq(expectedMac, mac)) throw new Error('EncString HMAC verification failed');
  const aesKey = await importAesKey(encKey);
  return Buffer.from(await subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ct));
}

/**
 * Decrypt an encString whose plaintext is UTF-8 text (vault item fields).
 * Throws on any MAC mismatch.
 */
async function decryptString(encString, key64) {
  const pt = await decryptToBytes(encString, key64);
  return pt.toString('utf8');
}

module.exports = {
  ENC_TYPE,
  deriveMasterKey,
  masterPasswordHash,
  hkdfExpandSha256,
  stretchMasterKey,
  encryptString,
  encryptBytes,
  decryptString,
  decryptToBytes,
  parseEncString,
  pbkdf2Sha256,
  internals: { splitKey64, hmacSha256, timingSafeEq }
};
