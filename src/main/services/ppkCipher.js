'use strict';

/**
 * ppkCipher.js
 * ---------------------------------------------------------------------------
 * AES-CBC helpers for the PPK (PuTTY private key) container, isolated in
 * their own module so the parser itself never calls into SubtleCrypto with
 * file-derived parameters.
 *
 * PPK v3 mandates AES-256-CBC; the key and IV are produced by the Argon2 KDF
 * (see puttyParser.js) and are exactly 32 and 16 bytes respectively. All
 * inputs are length-checked before use.
 * ---------------------------------------------------------------------------
 */

const nodeCrypto = require('crypto');
const subtle = nodeCrypto.webcrypto.subtle;

const KEY_LEN = 32;
const IV_LEN = 16;
const BLOCK = 16;

function importKey(key, usage) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) {
    throw new Error('AES key must be exactly ' + KEY_LEN + ' bytes.');
  }
  return subtle.importKey('raw', key, { name: 'AES-CBC' }, false, [usage]);
}

/**
 * Decrypt ciphertext with AES-256-CBC.
 * @param {Buffer} key 32-byte key
 * @param {Buffer} iv 16-byte initialisation vector
 * @param {Buffer} data ciphertext, a whole number of 16-byte blocks
 * @returns {Promise<Buffer>} plaintext (padding included, as PPK expects)
 * @throws {Error} a generic failure if the key/IV are wrong or the data is
 *   corrupt; the caller verifies integrity with the file's HMAC.
 */
async function decrypt(key, iv, data) {
  if (!Buffer.isBuffer(iv) || iv.length !== IV_LEN) {
    throw new Error('AES IV must be exactly ' + IV_LEN + ' bytes.');
  }
  if (!Buffer.isBuffer(data) || data.length === 0 || data.length % BLOCK !== 0) {
    throw new Error('Ciphertext must be a non-empty multiple of ' + BLOCK + ' bytes.');
  }
  const aesKey = await importKey(key, 'decrypt');
  try {
    return Buffer.from(await subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, data));
  } catch (e) {
    // Never surface the platform's raw crypto message: it says nothing useful
    // to the user and would bypass the caller's constant-time MAC check.
    throw new Error('Decryption failed: the passphrase is wrong, or the file is corrupt.');
  }
}

/**
 * Encrypt plaintext with AES-256-CBC. The caller is responsible for padding
 * to a whole number of blocks before calling (PPK uses random padding).
 */
async function encrypt(key, iv, data) {
  if (!Buffer.isBuffer(iv) || iv.length !== IV_LEN) {
    throw new Error('AES IV must be exactly ' + IV_LEN + ' bytes.');
  }
  if (!Buffer.isBuffer(data) || data.length === 0 || data.length % BLOCK !== 0) {
    throw new Error('Plaintext must be a non-empty multiple of ' + BLOCK + ' bytes.');
  }
  const aesKey = await importKey(key, 'encrypt');
  return Buffer.from(await subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, data));
}

module.exports = { decrypt, encrypt, KEY_LEN, IV_LEN, BLOCK };
