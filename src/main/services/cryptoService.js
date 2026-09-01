/**
 * cryptoService.js
 * ---------------------------------------------------------------------------
 * AES-256-GCM symmetric encryption for private keys at rest, plus scrypt-based
 * key derivation and a master-password verification hash.
 *
 * Wire format for an encrypted blob (all base64url):
 *   base64url( salt || iv || tag || ciphertext )
 *
 * Security notes:
 *   - Keys are derived with scrypt (N=2^16, r=8, p=1) over a 16-byte salt.
 *   - AES-256-GCM with a 12-byte random IV and 16-byte auth tag.
 *   - The master password is never persisted; only a verification hash is.
 * ---------------------------------------------------------------------------
 */

'use strict';

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const SCRYPT_N = 1 << 16; // 65536 — stronger offline brute-force cost for the master password (v1.0.0)
const SCRYPT_R = 8;
const SCRYPT_P = 1;

/**
 * Derive a 32-byte AES key from a password + salt using scrypt.
 */
function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 256 * 1024 * 1024
  });
}

/**
 * Encrypt `plaintext` (string or Buffer) with `password`.
 * Returns a base64url string.
 */
function encrypt(plaintext, password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  cipher.setAAD(Buffer.from('sshspan-aad'));
  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const enc = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([salt, iv, tag, enc]);
  return blob.toString('base64url');
}

/**
 * Decrypt a base64url blob produced by `encrypt`.
 * Throws on authentication failure.
 */
function decrypt(blobB64, password) {
  const blob = Buffer.from(blobB64, 'base64url');
  if (blob.length < SALT_LEN + IV_LEN + TAG_LEN) {
    throw new Error('Encrypted blob is malformed or truncated.');
  }
  let offset = 0;
  const salt = blob.subarray(offset, offset + SALT_LEN); offset += SALT_LEN;
  const iv = blob.subarray(offset, offset + IV_LEN); offset += IV_LEN;
  const tag = blob.subarray(offset, offset + TAG_LEN); offset += TAG_LEN;
  const ciphertext = blob.subarray(offset);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAAD(Buffer.from('sshspan-aad'));
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return out.toString('utf8');
}

/**
 * Create a verification hash so we can confirm the master password later
 * without storing it.
 * @returns {hash: string, salt: string}
 */
function createVerification(password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const hash = crypto.scryptSync(password, salt, 32, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 256 * 1024 * 1024
  });
  return { hash: hash.toString('base64url'), salt: salt.toString('base64url') };
}

/**
 * Verify a password against a stored verification hash.
 */
function verifyPassword(password, storedHash, storedSalt) {
  const salt = Buffer.from(storedSalt, 'base64url');
  const expected = crypto.scryptSync(password, salt, 32, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 256 * 1024 * 1024
  });
  const actual = Buffer.from(storedHash, 'base64url');
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

/**
 * Generate a random hex token (for API-style use or recovery codes).
 */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = {
  encrypt,
  decrypt,
  createVerification,
  verifyPassword,
  randomToken,
  constants: { SALT_LEN, IV_LEN, TAG_LEN, KEY_LEN }
};
