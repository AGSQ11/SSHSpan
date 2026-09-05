//! Bitwarden cryptographic operations — 1:1 port of bitwardenCrypto.js
//!
//! Implements the minimal subset of Bitwarden's client-side crypto stack:
//!   1. Master key derivation (PBKDF2-SHA256 or Argon2id per server prelogin)
//!   2. Password hash for /identity/connect/token (PBKDF2-SHA256, 1 iter)
//!   3. HKDF-Expand stretching (master key → 64-byte enc+mac key)
//!   4. EncString type 2: AES-256-CBC + HMAC-SHA256 ("2.<iv>|<ct>|<mac>")
//!
//! Only HMAC-verified decryptions succeed; every cipher field we send is
//! encrypted locally — the server only ever sees ciphertext.

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use base64ct::{Base64, Encoding};

use crate::crypto::utils::constant_time_eq;

// ─── KDF parameters from prelogin ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub kdf_type: u32,      // 0 = PBKDF2, 1 = Argon2id
    pub iterations: u32,    // PBKDF2 iterations or Argon2 iterations
    pub memory: u32,        // Argon2 memory in KiB (ignored for PBKDF2)
    pub parallelism: u32,   // Argon2 parallelism (ignored for PBKDF2)
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { kdf_type: 0, iterations: 600_000, memory: 0, parallelism: 0 }
    }
}

// ─── Master key derivation ──────────────────────────────────────────────

/// Derive the 32-byte master key from the master password and account email.
///
/// kdf_type 0: PBKDF2-HMAC-SHA256 with email (lowercased) as salt.
/// kdf_type 1: Argon2id with email (lowercased) as salt.
pub fn derive_master_key(password: &str, email: &str, kdf: &KdfParams) -> anyhow::Result<[u8; 32]> {
    let pw = password.as_bytes();
    let salt = email.trim().to_lowercase();
    let salt_bytes = salt.as_bytes();

    match kdf.kdf_type {
        0 => {
            let iterations = if kdf.iterations > 0 { kdf.iterations } else { 600_000 };
            Ok(pbkdf2_hmac_array::<Sha256, 32>(pw, salt_bytes, iterations))
        }
        1 => {
            use argon2::{Argon2, Algorithm, Version, Params};
            let params = Params::new(
                kdf.memory.max(64),    // minimum 64 KiB
                kdf.iterations.max(3), // minimum 3
                kdf.parallelism.max(4),
                Some(32),
            ).map_err(|e| anyhow::anyhow!("Argon2 param error: {e}"))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = [0u8; 32];
            argon2.hash_password_into(pw, salt_bytes, &mut key)
                .map_err(|e| anyhow::anyhow!("Argon2 derivation failed: {e}"))?;
            Ok(key)
        }
        other => anyhow::bail!("Unsupported Bitwarden KDF type: {other}"),
    }
}

// ─── Password hash for token request ────────────────────────────────────

/// The password hash sent to `/identity/connect/token`:
/// PBKDF2-HMAC-SHA256(masterKey, salt = master password, 1 iteration), base64.
pub fn master_password_hash(master_key: &[u8; 32], password: &str) -> String {
    let hash: [u8; 32] = pbkdf2_hmac_array::<Sha256, 32>(master_key, password.as_bytes(), 1);
    Base64::encode_string(&hash)
}

// ─── HKDF stretching ────────────────────────────────────────────────────

/// HKDF-Expand only (RFC 5869, SHA-256). Bitwarden expands the master key
/// directly without the Extract step.
/// HKDF-Expand only (RFC 5869) — Bitwarden expands the master key directly
/// without the Extract step, exactly like the Electron original:
/// T(1) = HMAC(PRK, info || 0x01), T(i) = HMAC(PRK, T(i-1) || info || i)
fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    const HASH_LEN: usize = 32;
    assert!(prk.len() >= HASH_LEN, "HKDF-Expand: PRK too short");
    assert!(length <= 255 * HASH_LEN, "HKDF-Expand: length too large");
    let blocks = length.div_ceil(HASH_LEN);
    let mut out = Vec::with_capacity(blocks * HASH_LEN);
    let mut t: Vec<u8> = Vec::new(); // T(0) = empty
    for i in 1..=blocks {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prk).expect("HMAC accepts any key size");
        mac.update(&t);
        mac.update(info);
        mac.update(&[i as u8]);
        t = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
    }
    out.truncate(length);
    out
}

/// Stretch a 32-byte master key into a 64-byte symmetric key
/// (enc key || mac key) the way Bitwarden clients do.
pub fn stretch_master_key(master_key: &[u8; 32]) -> [u8; 64] {
    let enc = hkdf_expand_sha256(master_key, b"enc", 32);
    let mac = hkdf_expand_sha256(master_key, b"mac", 32);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&enc);
    out[32..].copy_from_slice(&mac);
    out
}

/// Split a 64-byte stretched key into (enc_key, mac_key).
fn split_key64(key: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&key[..32]);
    mac.copy_from_slice(&key[32..]);
    (enc, mac)
}

// ─── EncString type 2 ───────────────────────────────────────────────────

const ENC_TYPE: u32 = 2; // AesCbc256_HmacSha256_B64

/// Parsed components of a type-2 EncString.
struct ParsedEncString {
    iv: Vec<u8>,
    ct: Vec<u8>,
    mac: Vec<u8>,
}

/// Parse an EncString "2.<iv>|<ct>|<mac>" into its parts.
fn parse_enc_string(s: &str) -> anyhow::Result<ParsedEncString> {
    let dot = s.find('.').ok_or_else(|| anyhow::anyhow!("Malformed encString (missing type)"))?;
    let typ: u32 = s[..dot].parse().map_err(|_| anyhow::anyhow!("Malformed encString type"))?;
    if typ != ENC_TYPE {
        anyhow::bail!("Unsupported encString type {typ} (only type {ENC_TYPE} is supported)");
    }
    let parts: Vec<&str> = s[dot + 1..].split('|').collect();
    if parts.len() != 3 {
        anyhow::bail!("Malformed encString (expected iv|ct|mac)");
    }
    let iv = Base64::decode_vec(parts[0]).map_err(|e| anyhow::anyhow!("Bad IV base64: {e}"))?;
    let ct = Base64::decode_vec(parts[1]).map_err(|e| anyhow::anyhow!("Bad CT base64: {e}"))?;
    let mac = Base64::decode_vec(parts[2]).map_err(|e| anyhow::anyhow!("Bad MAC base64: {e}"))?;
    if iv.len() != 16 { anyhow::bail!("Bad IV length: {} (expected 16)", iv.len()); }
    if mac.len() != 32 { anyhow::bail!("Bad MAC length: {} (expected 32)", mac.len()); }
    Ok(ParsedEncString { iv, ct, mac })
}

/// Encrypt plaintext (string) with a 64-byte stretched key, producing a
/// type-2 encString: `"2.<b64iv>|<b64ct>|<b64mac>"`.
pub fn encrypt_string(plaintext: &str, key64: &[u8; 64]) -> anyhow::Result<String> {
    let (enc_key, mac_key) = split_key64(key64);
    let iv = generate_iv();
    let pt = plaintext.as_bytes();

    // AES-256-CBC encrypt with PKCS7 padding
    let mut buf = pt.to_vec();
    let pt_len = buf.len();
    buf.resize(pt_len + 16, 0); // space for padding
    let ct = cbc::Encryptor::<Aes256>::new(&enc_key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|e| anyhow::anyhow!("AES-CBC encrypt failed: {e}"))?;
    let ct = ct.to_vec();

    // HMAC-SHA256 over IV || CT
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key)
        .map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
    hmac.update(&iv);
    hmac.update(&ct);
    let mac = hmac.finalize().into_bytes();

    Ok(format!("2.{}|{}|{}",
        Base64::encode_string(&iv),
        Base64::encode_string(&ct),
        Base64::encode_string(&mac),
    ))
}

/// Encrypt raw bytes with a 64-byte stretched key.
pub fn encrypt_bytes(plaintext: &[u8], key64: &[u8; 64]) -> anyhow::Result<String> {
    let (enc_key, mac_key) = split_key64(key64);
    let iv = generate_iv();

    let mut buf = plaintext.to_vec();
    let pt_len = buf.len();
    buf.resize(pt_len + 16, 0);
    let ct = cbc::Encryptor::<Aes256>::new(&enc_key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|e| anyhow::anyhow!("AES-CBC encrypt failed: {e}"))?;
    let ct = ct.to_vec();

    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key)
        .map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
    hmac.update(&iv);
    hmac.update(&ct);
    let mac = hmac.finalize().into_bytes();

    Ok(format!("2.{}|{}|{}",
        Base64::encode_string(&iv),
        Base64::encode_string(&ct),
        Base64::encode_string(&mac),
    ))
}

/// Decrypt an encString with a 64-byte stretched key, returning raw bytes.
/// HMAC is verified timing-safely BEFORE decryption.
pub fn decrypt_to_bytes(enc_string: &str, key64: &[u8; 64]) -> anyhow::Result<Vec<u8>> {
    let (enc_key, mac_key) = split_key64(key64);
    let parsed = parse_enc_string(enc_string)?;

    // Verify HMAC
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key)
        .map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
    hmac.update(&parsed.iv);
    hmac.update(&parsed.ct);
    let computed_mac = hmac.finalize().into_bytes();

    if !constant_time_eq(&computed_mac, &parsed.mac) {
        anyhow::bail!("EncString HMAC verification failed");
    }

    // Decrypt. decrypt_padded_mut returns a slice of `buf` with the PKCS7
    // padding already removed, but it does NOT resize the buffer — returning
    // `buf` wholesale would leak the trailing pad block (e.g. a 64-byte user
    // key whose ciphertext ends in a full 0x10x16 pad block would come back
    // as 80 bytes). Return the unpadded slice instead.
    let mut buf = parsed.ct;
    let pt = cbc::Decryptor::<Aes256>::new(&enc_key.into(), (&*parsed.iv).into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| anyhow::anyhow!("AES-CBC decrypt failed (bad padding or corrupt data)"))?;
    Ok(pt.to_vec())
}

/// Decrypt an encString whose plaintext is UTF-8 text (vault item fields).
pub fn decrypt_string(enc_string: &str, key64: &[u8; 64]) -> anyhow::Result<String> {
    let pt = decrypt_to_bytes(enc_string, key64)?;
    String::from_utf8(pt).map_err(|e| anyhow::anyhow!("Decrypted text is not valid UTF-8: {e}"))
}

/// Generate a random 16-byte IV for AES-CBC.
fn generate_iv() -> [u8; 16] {
    use rand::RngCore;
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stretch_master_key_matches_electron_hkdf_expand() {
        // master key = 0x00..0x1f; vectors computed with the Electron
        // bitwardenCrypto.js hkdfExpandSha256 (expand-only, no Extract).
        let mut mk = [0u8; 32];
        for (i, b) in mk.iter_mut().enumerate() { *b = i as u8; }
        let stretched = stretch_master_key(&mk);
        assert_eq!(
            hex(&stretched[..32]),
            "9c5639fac602366b486253191cb7900d7d8e3a1514676b118d5803a11dd97213",
            "enc half of the stretched key must match Electron expand-only HKDF"
        );
        assert_eq!(
            hex(&stretched[32..]),
            "cce388b4ac0f05edee78d40dcbe78a7715640de75ed9ba06942fb42398d6b1f1",
            "mac half of the stretched key must match Electron expand-only HKDF"
        );
    }

    #[test]
    fn decrypt_strips_full_pkcs7_pad_block() {
        // Regression test: a plaintext whose length is a multiple of 16 gets a
        // whole extra 0x10-pad block in the ciphertext. Decryption must return
        // the original length, not leak the pad block (previously a 64-byte
        // user key came back as 80 bytes, which broke profile.key unwrapping).
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() { *b = (i % 251) as u8; }
        let pt: Vec<u8> = (0..64u8).collect(); // 64 bytes = block-aligned
        let enc = encrypt_bytes(&pt, &key).unwrap();
        assert!(enc.starts_with("2."), "encBytes must produce a type-2 encString");

        let dec = decrypt_to_bytes(&enc, &key).unwrap();
        assert_eq!(dec.len(), pt.len(), "pad block must be stripped");
        assert_eq!(dec, pt, "round-trip must be exact");

        // Sanity: the same wrapped key, decoded as base64 ct, really is 80 bytes.
        let ct_b64 = enc.split('.').nth(1).unwrap().split('|').nth(1).unwrap();
        let ct = base64ct::Base64::decode_vec(ct_b64).unwrap();
        assert_eq!(ct.len(), 80, "64B plaintext must encrypt to 80B ciphertext");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
