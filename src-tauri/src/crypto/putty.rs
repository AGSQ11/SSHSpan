//! PuTTY PPK (v2 and v3) parsing and serialization.
//!
//! Implemented directly against the authoritative spec in PuTTY's own
//! manual, Appendix C ("PPK file format"):
//! <https://the.earth.li/~sgtatham/putty/0.81/htmldoc/AppendixC.html>
//!
//! Two details are easy to get wrong and silently produce keys real PuTTY
//! can't open (or can't decrypt files PuTTY wrote):
//!
//! 1. **v3 key derivation is a single Argon2 call**, not three independent
//!    hashes. The tag length equals cipher-key + IV + MAC-key (32+16+32=80
//!    bytes for aes256-cbc), and the output is split in that order.
//! 2. **CBC padding is random, not PKCS#7.** PuTTY pads the plaintext to a
//!    block boundary with random bytes before encrypting; the reader is
//!    expected to parse exactly the fields it needs from the front of the
//!    decrypted buffer and ignore the trailing padding. Attempting PKCS#7
//!    unpadding on this data fails (or worse, silently corrupts) for real
//!    PuTTY-written files.
//!
//! The private-key wire fields once decrypted (RSA: d,p,q,iqmp; EC/EdDSA:
//! a single mpint scalar) are converted into an `ssh_key::PrivateKey` so
//! all downstream export/fingerprint logic is shared with the OpenSSH path.

use aes::Aes256;
use argon2::{
    Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version,
};
use base64ct::{Base64, Encoding};
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use ssh_key::{
    private::{
        EcdsaKeypair, EcdsaPrivateKey, Ed25519Keypair, Ed25519PrivateKey, KeypairData, RsaKeypair,
        RsaPrivateKey as SshRsaPrivateKey,
    },
    Mpint, PrivateKey, PublicKey,
};

use crate::crypto::keys::{KeyType, PrivateKeyData};
use crate::crypto::utils::{constant_time_eq, generate_random_vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PpkVersion {
    V2,
    V3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Argon2Flavour {
    D,
    I,
    Id,
}

#[derive(Debug)]
struct ParsedPpk {
    version: PpkVersion,
    algorithm_name: String,
    encrypted: bool,
    comment: String,
    public_blob: Vec<u8>,
    private_blob: Vec<u8>, // possibly still encrypted
    mac: Vec<u8>,          // hex-decoded
    argon2_flavour: Argon2Flavour,
    argon2_memory_kb: u32,
    argon2_passes: u32,
    argon2_parallelism: u32,
    argon2_salt: Vec<u8>,
}

/// Detect whether the given text looks like a PPK file at all (used by the
/// import command to route between OpenSSH / PPK parsers).
pub fn looks_like_ppk(data: &str) -> bool {
    data.trim_start().starts_with("PuTTY-User-Key-File-")
}

// ─── Argon2 parameter bounds (DoS hardening) ────────────────────────────────
//
// These fields come straight from the file being imported. Without upper
// bounds, a crafted .ppk can claim e.g. 4 TiB of Argon2 memory or billions
// of passes and turn a mere import into a memory/CPU denial of service.
// PuTTY's own defaults are far below these caps (memory ~8 MiB, passes 1-4,
// parallelism 1, 16-byte salt), so legitimate keys are unaffected.

/// Maximum accepted `Argon2-Memory` value, in KiB (1 GiB).
const ARGON2_MAX_MEMORY_KIB: u32 = 1_048_576;
/// Maximum accepted `Argon2-Passes` value.
const ARGON2_MAX_PASSES: u32 = 256;
/// Maximum accepted `Argon2-Parallelism` value.
const ARGON2_MAX_PARALLELISM: u32 = 64;
/// Maximum accepted `Argon2-Salt` hex-string length (64 decoded bytes).
const ARGON2_MAX_SALT_HEX_LEN: usize = 128;

fn validate_argon2_memory(memory_kb: u32) -> anyhow::Result<()> {
    if memory_kb == 0 {
        anyhow::bail!("Argon2-Memory must be at least 1 KiB");
    }
    if memory_kb > ARGON2_MAX_MEMORY_KIB {
        anyhow::bail!("Argon2-Memory too large ({memory_kb} KiB; max {ARGON2_MAX_MEMORY_KIB} KiB)");
    }
    Ok(())
}

fn validate_argon2_passes(passes: u32) -> anyhow::Result<()> {
    if passes == 0 {
        anyhow::bail!("Argon2-Passes must be at least 1");
    }
    if passes > ARGON2_MAX_PASSES {
        anyhow::bail!("Argon2-Passes too large ({passes}; max {ARGON2_MAX_PASSES})");
    }
    Ok(())
}

fn validate_argon2_parallelism(parallelism: u32) -> anyhow::Result<()> {
    if parallelism == 0 {
        anyhow::bail!("Argon2-Parallelism must be at least 1");
    }
    if parallelism > ARGON2_MAX_PARALLELISM {
        anyhow::bail!("Argon2-Parallelism too large ({parallelism}; max {ARGON2_MAX_PARALLELISM})");
    }
    Ok(())
}

fn validate_argon2_salt_len(salt_len: usize) -> anyhow::Result<()> {
    if salt_len == 0 {
        anyhow::bail!("Argon2-Salt must not be empty");
    }
    if salt_len > ARGON2_MAX_SALT_HEX_LEN / 2 {
        anyhow::bail!(
            "Argon2-Salt too long ({salt_len} bytes; max {} bytes)",
            ARGON2_MAX_SALT_HEX_LEN / 2
        );
    }
    Ok(())
}

/// Full cross-field check (used as defense in depth after parsing an
/// encrypted v3 file).
fn validate_argon2_params(
    memory_kb: u32,
    passes: u32,
    parallelism: u32,
    salt_len: usize,
) -> anyhow::Result<()> {
    validate_argon2_memory(memory_kb)?;
    validate_argon2_passes(passes)?;
    validate_argon2_parallelism(parallelism)?;
    validate_argon2_salt_len(salt_len)?;
    Ok(())
}

fn parse_ppk_file(data: &str) -> anyhow::Result<ParsedPpk> {
    let lines: Vec<&str> = data.lines().collect();
    if lines.is_empty() {
        anyhow::bail!("Empty PPK file");
    }
    let first = lines[0];
    let version = if first.starts_with("PuTTY-User-Key-File-3:") {
        PpkVersion::V3
    } else if first.starts_with("PuTTY-User-Key-File-2:") {
        PpkVersion::V2
    } else {
        anyhow::bail!("Not a PuTTY private key file, or an unsupported PPK version (only v2/v3 are supported)");
    };
    let algorithm_name = first.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();

    let mut encrypted = false;
    let mut comment = String::new();
    let mut public_blob = Vec::new();
    let mut private_blob = Vec::new();
    let mut mac = Vec::new();
    let mut argon2_flavour = Argon2Flavour::Id;
    let mut argon2_memory_kb = 8192u32;
    let mut argon2_passes = 1u32;
    let mut argon2_parallelism = 1u32;
    let mut argon2_salt = Vec::new();

    let mut i = 1usize;
    while i < lines.len() {
        let line = lines[i];
        if let Some(v) = line.strip_prefix("Encryption:") {
            encrypted = v.trim() != "none";
        } else if let Some(v) = line.strip_prefix("Comment:") {
            comment = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Public-Lines:") {
            let n: usize = v
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Bad Public-Lines count"))?;
            let b64: String = lines
                .get(i + 1..i + 1 + n)
                .ok_or_else(|| anyhow::anyhow!("Truncated public key section"))?
                .concat();
            public_blob = Base64::decode_vec(&b64)
                .map_err(|e| anyhow::anyhow!("Bad public key base64: {e}"))?;
            i += n;
        } else if let Some(v) = line.strip_prefix("Key-Derivation:") {
            argon2_flavour = match v.trim() {
                "Argon2d" => Argon2Flavour::D,
                "Argon2i" => Argon2Flavour::I,
                "Argon2id" => Argon2Flavour::Id,
                other => anyhow::bail!("Unknown Argon2 flavour: {other}"),
            };
        } else if let Some(v) = line.strip_prefix("Argon2-Memory:") {
            argon2_memory_kb = v
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Bad Argon2-Memory"))?;
            validate_argon2_memory(argon2_memory_kb)?;
        } else if let Some(v) = line.strip_prefix("Argon2-Passes:") {
            argon2_passes = v
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Bad Argon2-Passes"))?;
            validate_argon2_passes(argon2_passes)?;
        } else if let Some(v) = line.strip_prefix("Argon2-Parallelism:") {
            argon2_parallelism = v
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Bad Argon2-Parallelism"))?;
            validate_argon2_parallelism(argon2_parallelism)?;
        } else if let Some(v) = line.strip_prefix("Argon2-Salt:") {
            // Cap the hex string BEFORE decoding: a multi-megabyte salt line
            // would otherwise allocate unconditionally.
            let salt_hex = v.trim();
            if salt_hex.len() > ARGON2_MAX_SALT_HEX_LEN {
                anyhow::bail!(
                    "Argon2-Salt too long ({} hex chars; max {ARGON2_MAX_SALT_HEX_LEN})",
                    salt_hex.len()
                );
            }
            argon2_salt =
                hex::decode(salt_hex).map_err(|e| anyhow::anyhow!("Bad Argon2-Salt hex: {e}"))?;
            validate_argon2_salt_len(argon2_salt.len())?;
        } else if let Some(v) = line.strip_prefix("Private-Lines:") {
            let n: usize = v
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("Bad Private-Lines count"))?;
            let b64: String = lines
                .get(i + 1..i + 1 + n)
                .ok_or_else(|| anyhow::anyhow!("Truncated private key section"))?
                .concat();
            private_blob = Base64::decode_vec(&b64)
                .map_err(|e| anyhow::anyhow!("Bad private key base64: {e}"))?;
            i += n;
        } else if let Some(v) = line.strip_prefix("Private-MAC:") {
            mac = hex::decode(v.trim()).map_err(|e| anyhow::anyhow!("Bad Private-MAC hex: {e}"))?;
        }
        i += 1;
    }

    if public_blob.is_empty() {
        anyhow::bail!("PPK file has no public key data");
    }

    // Defense in depth for encrypted v3 files: the per-field checks above
    // run at parse time, but only when Argon2 fields are actually present.
    // Encrypted v3 keys always carry all four fields, so a complete
    // cross-field check here catches any combination that slipped through
    // (e.g. a file whose only KDF field is a salt). Unencrypted files and
    // v2 files legitimately have no Argon2 parameters at all.
    if version == PpkVersion::V3 && encrypted {
        validate_argon2_params(
            argon2_memory_kb,
            argon2_passes,
            argon2_parallelism,
            argon2_salt.len(),
        )?;
    }

    Ok(ParsedPpk {
        version,
        algorithm_name,
        encrypted,
        comment,
        public_blob,
        private_blob,
        mac,
        argon2_flavour,
        argon2_memory_kb,
        argon2_passes,
        argon2_parallelism,
        argon2_salt,
    })
}

// ─── Key derivation ─────────────────────────────────────────────────────────

/// PPK v3 (Appendix C.4): a *single* Argon2 call whose tag length is
/// cipher_key_len + iv_len + mac_key_len; output split in that order.
fn derive_v3(
    parsed: &ParsedPpk,
    passphrase: &str,
) -> anyhow::Result<([u8; 32], [u8; 16], [u8; 32])> {
    let algo = match parsed.argon2_flavour {
        Argon2Flavour::D => Argon2Algorithm::Argon2d,
        Argon2Flavour::I => Argon2Algorithm::Argon2i,
        Argon2Flavour::Id => Argon2Algorithm::Argon2id,
    };
    let params = Argon2Params::new(
        parsed.argon2_memory_kb,
        parsed.argon2_passes,
        parsed.argon2_parallelism,
        Some(80),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let argon2 = Argon2::new(algo, Argon2Version::V0x13, params);

    let mut output = [0u8; 80];
    argon2
        .hash_password_into(passphrase.as_bytes(), &parsed.argon2_salt, &mut output)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {e}"))?;

    let mut cipher_key = [0u8; 32];
    let mut iv = [0u8; 16];
    let mut mac_key = [0u8; 32];
    cipher_key.copy_from_slice(&output[0..32]);
    iv.copy_from_slice(&output[32..48]);
    mac_key.copy_from_slice(&output[48..80]);
    Ok((cipher_key, iv, mac_key))
}

/// PPK v2 (Appendix C.5.1): two SHA-1 hashes of (seq || passphrase)
/// concatenated and truncated to 32 bytes; IV is all-zero; MAC key is a
/// single SHA-1 of a fixed string + passphrase.
fn derive_v2(passphrase: &str) -> ([u8; 32], [u8; 16], [u8; 20]) {
    let mut h0 = Sha1::new();
    h0.update(0u32.to_be_bytes());
    h0.update(passphrase.as_bytes());
    let d0 = h0.finalize();

    let mut h1 = Sha1::new();
    h1.update(1u32.to_be_bytes());
    h1.update(passphrase.as_bytes());
    let d1 = h1.finalize();

    let mut cipher_key = [0u8; 32];
    cipher_key[..20].copy_from_slice(&d0);
    cipher_key[20..32].copy_from_slice(&d1[..12]);

    let iv = [0u8; 16];

    let mut hm = Sha1::new();
    hm.update(b"putty-private-key-file-mac-key");
    hm.update(passphrase.as_bytes());
    let mac_key: [u8; 20] = hm.finalize().into();

    (cipher_key, iv, mac_key)
}

// ─── MAC ────────────────────────────────────────────────────────────────────

fn ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn mac_preimage(parsed: &ParsedPpk, plaintext_private_blob: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    ssh_string(&mut buf, parsed.algorithm_name.as_bytes());
    ssh_string(
        &mut buf,
        if parsed.encrypted {
            b"aes256-cbc"
        } else {
            b"none"
        },
    );
    ssh_string(&mut buf, parsed.comment.as_bytes());
    ssh_string(&mut buf, &parsed.public_blob);
    ssh_string(&mut buf, plaintext_private_blob);
    buf
}

fn verify_mac_v3(
    parsed: &ParsedPpk,
    mac_key: &[u8; 32],
    plaintext_private_blob: &[u8],
) -> anyhow::Result<()> {
    if parsed.mac.is_empty() {
        return Ok(());
    }
    let preimage = mac_preimage(parsed, plaintext_private_blob);
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC accepts any key size");
    mac.update(&preimage);
    let computed = mac.finalize().into_bytes();
    if !constant_time_eq(&computed, &parsed.mac) {
        anyhow::bail!("Incorrect passphrase (MAC verification failed).");
    }
    Ok(())
}

fn verify_mac_v2(
    parsed: &ParsedPpk,
    mac_key: &[u8; 20],
    plaintext_private_blob: &[u8],
) -> anyhow::Result<()> {
    if parsed.mac.is_empty() {
        return Ok(());
    }
    let preimage = mac_preimage(parsed, plaintext_private_blob);
    let mut mac = Hmac::<Sha1>::new_from_slice(mac_key).expect("HMAC accepts any key size");
    mac.update(&preimage);
    let computed = mac.finalize().into_bytes();
    if !constant_time_eq(&computed, &parsed.mac) {
        anyhow::bail!("Incorrect passphrase (MAC verification failed).");
    }
    Ok(())
}

// ─── CBC (NO padding removal — PuTTY pads with random bytes, not PKCS#7) ──

fn cbc_decrypt_no_padding(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> anyhow::Result<Vec<u8>> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    if ciphertext.len() % 16 != 0 {
        anyhow::bail!("Encrypted PPK private key section is not block-aligned");
    }
    let mut buf = ciphertext.to_vec();
    cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| anyhow::anyhow!("PPK CBC decrypt failed: {e:?}"))?;
    Ok(buf)
}

fn cbc_encrypt_no_padding(
    plaintext_padded: &mut [u8],
    key: &[u8],
    iv: &[u8],
) -> anyhow::Result<()> {
    let len = plaintext_padded.len();
    if len == 0 {
        return Ok(());
    }
    cbc::Encryptor::<Aes256>::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(plaintext_padded, len)
        .map_err(|e| anyhow::anyhow!("PPK CBC encrypt failed: {e:?}"))?;
    Ok(())
}

// ─── mpint helpers for the private-blob wire format ────────────────────────

fn read_mpint_bytes(buf: &[u8], pos: &mut usize) -> anyhow::Result<Vec<u8>> {
    if *pos + 4 > buf.len() {
        anyhow::bail!("Truncated PPK private key data");
    }
    let len = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + len > buf.len() {
        anyhow::bail!("Truncated PPK private key data");
    }
    let bytes = buf[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(bytes)
}

fn write_mpint_bytes(out: &mut Vec<u8>, mpint: &Mpint) {
    ssh_string(out, mpint.as_bytes());
}

/// Left-pad (or strip a single disambiguating leading zero) an mpint's raw
/// bytes to an exact fixed width, e.g. to recover a 32-byte Ed25519 seed
/// or an N-byte ECDSA scalar from PuTTY's arbitrary-precision-integer
/// encoding of it.
fn mpint_to_fixed_be(mpint_bytes: &[u8], width: usize) -> anyhow::Result<Vec<u8>> {
    let trimmed = if mpint_bytes.len() > width && mpint_bytes[0] == 0 {
        &mpint_bytes[1..]
    } else {
        mpint_bytes
    };
    if trimmed.len() > width {
        anyhow::bail!(
            "PPK scalar is wider than expected ({} > {width} bytes)",
            trimmed.len()
        );
    }
    let mut out = vec![0u8; width - trimmed.len()];
    out.extend_from_slice(trimmed);
    Ok(out)
}

/// Build the type-specific `KeypairData` from the (already decrypted)
/// private blob per Appendix C.3, paired with the public key parsed from
/// the file's public-lines section.
fn build_keypair_data(
    parsed: &ParsedPpk,
    plaintext_private_blob: &[u8],
) -> anyhow::Result<(KeyType, KeypairData)> {
    let public_key = PublicKey::from_bytes(&parsed.public_blob)
        .map_err(|e| anyhow::anyhow!("Invalid public key data in PPK file: {e}"))?;

    let mut pos = 0usize;

    match parsed.algorithm_name.as_str() {
        "ssh-rsa" => {
            let rsa_pub = public_key
                .key_data()
                .rsa()
                .ok_or_else(|| {
                    anyhow::anyhow!("PPK header says ssh-rsa but public blob isn't RSA")
                })?
                .clone();
            let d = read_mpint_bytes(plaintext_private_blob, &mut pos)?;
            let p = read_mpint_bytes(plaintext_private_blob, &mut pos)?;
            let q = read_mpint_bytes(plaintext_private_blob, &mut pos)?;
            let iqmp = read_mpint_bytes(plaintext_private_blob, &mut pos)?;
            let private = SshRsaPrivateKey {
                d: Mpint::from_bytes(&d).map_err(|e| anyhow::anyhow!(e))?,
                iqmp: Mpint::from_bytes(&iqmp).map_err(|e| anyhow::anyhow!(e))?,
                p: Mpint::from_bytes(&p).map_err(|e| anyhow::anyhow!(e))?,
                q: Mpint::from_bytes(&q).map_err(|e| anyhow::anyhow!(e))?,
            };
            Ok((
                KeyType::Rsa,
                KeypairData::Rsa(RsaKeypair {
                    public: rsa_pub,
                    private,
                }),
            ))
        }
        "ssh-ed25519" => {
            let scalar = read_mpint_bytes(plaintext_private_blob, &mut pos)?;
            let seed = mpint_to_fixed_be(&scalar, 32)?;
            let seed_arr: [u8; 32] = seed
                .try_into()
                .map_err(|_| anyhow::anyhow!("Bad Ed25519 seed length"))?;
            let private = Ed25519PrivateKey::from_bytes(&seed_arr);
            let keypair: Ed25519Keypair = private.into();
            Ok((KeyType::Ed25519, KeypairData::Ed25519(keypair)))
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let ecdsa_pub = public_key
                .key_data()
                .ecdsa()
                .ok_or_else(|| {
                    anyhow::anyhow!("PPK header says ECDSA but public blob isn't ECDSA")
                })?
                .clone();
            let scalar = read_mpint_bytes(plaintext_private_blob, &mut pos)?;

            let (key_type, keypair) = match &ecdsa_pub {
                ssh_key::public::EcdsaPublicKey::NistP256(point) => {
                    let bytes = mpint_to_fixed_be(&scalar, 32)?;
                    let sk = p256::SecretKey::from_slice(&bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid P-256 scalar: {e}"))?;
                    let private: EcdsaPrivateKey<32> = sk.into();
                    (
                        KeyType::EcdsaP256,
                        EcdsaKeypair::NistP256 {
                            public: point.clone(),
                            private,
                        },
                    )
                }
                ssh_key::public::EcdsaPublicKey::NistP384(point) => {
                    let bytes = mpint_to_fixed_be(&scalar, 48)?;
                    let sk = p384::SecretKey::from_slice(&bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid P-384 scalar: {e}"))?;
                    let private: EcdsaPrivateKey<48> = sk.into();
                    (
                        KeyType::EcdsaP384,
                        EcdsaKeypair::NistP384 {
                            public: point.clone(),
                            private,
                        },
                    )
                }
                ssh_key::public::EcdsaPublicKey::NistP521(point) => {
                    let bytes = mpint_to_fixed_be(&scalar, 66)?;
                    let sk = p521::SecretKey::from_slice(&bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid P-521 scalar: {e}"))?;
                    let private: EcdsaPrivateKey<66> = sk.into();
                    (
                        KeyType::EcdsaP521,
                        EcdsaKeypair::NistP521 {
                            public: point.clone(),
                            private,
                        },
                    )
                }
            };
            Ok((key_type, KeypairData::Ecdsa(keypair)))
        }
        other => anyhow::bail!("Unsupported PPK key algorithm: {other}"),
    }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Import a PuTTY .ppk file (v2 or v3, encrypted or not) into our
/// standard `PrivateKeyData`, ready for storage/export like any other key.
pub fn import_ppk(data: &str, passphrase: Option<&str>) -> anyhow::Result<PrivateKeyData> {
    let parsed = parse_ppk_file(data)?;
    let pass = passphrase.unwrap_or("");

    let plaintext_private_blob = if parsed.encrypted {
        match parsed.version {
            PpkVersion::V3 => {
                let (cipher_key, iv, mac_key) = derive_v3(&parsed, pass)?;
                let plaintext = cbc_decrypt_no_padding(&parsed.private_blob, &cipher_key, &iv)?;
                verify_mac_v3(&parsed, &mac_key, &plaintext)?;
                plaintext
            }
            PpkVersion::V2 => {
                let (cipher_key, iv, mac_key) = derive_v2(pass);
                let plaintext = cbc_decrypt_no_padding(&parsed.private_blob, &cipher_key, &iv)?;
                verify_mac_v2(&parsed, &mac_key, &plaintext)?;
                plaintext
            }
        }
    } else {
        parsed.private_blob.clone()
    };

    let (key_type, keypair_data) = build_keypair_data(&parsed, &plaintext_private_blob)?;
    let private_key =
        PrivateKey::new(keypair_data, parsed.comment.clone()).map_err(|e| anyhow::anyhow!(e))?;

    let private_bytes = private_key
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e))?
        .to_vec();
    let public_bytes = private_key
        .public_key()
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e))?
        .to_vec();

    Ok(PrivateKeyData::new(
        key_type,
        private_bytes,
        public_bytes,
        parsed.comment,
    ))
}

/// Export a key to PuTTY PPK v3 format, optionally encrypted with a
/// passphrase (Argon2id, PuTTY's own default flavour).
pub fn export_ppk(key_data: &PrivateKeyData, passphrase: Option<&str>) -> anyhow::Result<String> {
    let private_key =
        PrivateKey::from_bytes(&key_data.private_key).map_err(|e| anyhow::anyhow!(e))?;
    let algorithm_name = key_data.key_type.algorithm_name();

    let mut out = String::new();
    out.push_str(&format!("PuTTY-User-Key-File-3: {algorithm_name}\n"));

    let pass = passphrase.filter(|p| !p.is_empty());
    out.push_str(&format!(
        "Encryption: {}\n",
        if pass.is_some() { "aes256-cbc" } else { "none" }
    ));
    out.push_str(&format!("Comment: {}\n", key_data.comment));

    let pub_b64 = Base64::encode_string(&key_data.public_key);
    write_lines_section(&mut out, "Public-Lines", &pub_b64);

    let private_blob = encode_private_blob(private_key.key_data())?;

    let (private_out, mac): (Vec<u8>, Vec<u8>) = if let Some(pass) = pass {
        let memory_kb = 8192;
        let passes = 4;
        let parallelism = 1;
        let salt = generate_random_vec(16);

        out.push_str("Key-Derivation: Argon2id\n");
        out.push_str(&format!("Argon2-Memory: {memory_kb}\n"));
        out.push_str(&format!("Argon2-Passes: {passes}\n"));
        out.push_str(&format!("Argon2-Parallelism: {parallelism}\n"));
        out.push_str(&format!("Argon2-Salt: {}\n", hex::encode(&salt)));

        let params = Argon2Params::new(memory_kb, passes, parallelism, Some(80))
            .map_err(|e| anyhow::anyhow!(e))?;
        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, params);
        let mut kdf_out = [0u8; 80];
        argon2
            .hash_password_into(pass.as_bytes(), &salt, &mut kdf_out)
            .map_err(|e| anyhow::anyhow!(e))?;
        let cipher_key = &kdf_out[0..32];
        let iv = &kdf_out[32..48];
        let mac_key = &kdf_out[48..80];

        // Pad to a block boundary with random bytes — PuTTY does NOT use
        // PKCS#7 here (see module docs).
        let mut padded = private_blob.clone();
        let pad_len = (16 - (padded.len() % 16)) % 16;
        padded.extend(generate_random_vec(pad_len));
        cbc_encrypt_no_padding(&mut padded, cipher_key, iv)?;

        let mut mac_key_arr = [0u8; 32];
        mac_key_arr.copy_from_slice(mac_key);
        let parsed_for_mac = ParsedPpk {
            version: PpkVersion::V3,
            algorithm_name: algorithm_name.to_string(),
            encrypted: true,
            comment: key_data.comment.clone(),
            public_blob: key_data.public_key.clone(),
            private_blob: Vec::new(),
            mac: Vec::new(),
            argon2_flavour: Argon2Flavour::Id,
            argon2_memory_kb: memory_kb,
            argon2_passes: passes,
            argon2_parallelism: parallelism,
            argon2_salt: salt,
        };
        let preimage = mac_preimage(&parsed_for_mac, &private_blob);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&mac_key_arr).expect("HMAC accepts any key size");
        mac.update(&preimage);
        (padded, mac.finalize().into_bytes().to_vec())
    } else {
        let parsed_for_mac = ParsedPpk {
            version: PpkVersion::V3,
            algorithm_name: algorithm_name.to_string(),
            encrypted: false,
            comment: key_data.comment.clone(),
            public_blob: key_data.public_key.clone(),
            private_blob: Vec::new(),
            mac: Vec::new(),
            argon2_flavour: Argon2Flavour::Id,
            argon2_memory_kb: 0,
            argon2_passes: 0,
            argon2_parallelism: 0,
            argon2_salt: Vec::new(),
        };
        // Unencrypted files still carry a MAC; the key material is
        // zero-length per the spec ("If encryption-type is none, then all
        // three of these pieces of data have zero length").
        let preimage = mac_preimage(&parsed_for_mac, &private_blob);
        let mut mac = Hmac::<Sha256>::new_from_slice(&[]).expect("HMAC accepts empty key");
        mac.update(&preimage);
        (private_blob.clone(), mac.finalize().into_bytes().to_vec())
    };

    let priv_b64 = Base64::encode_string(&private_out);
    write_lines_section(&mut out, "Private-Lines", &priv_b64);
    out.push_str(&format!("Private-MAC: {}\n", hex::encode(&mac)));

    Ok(out)
}

fn write_lines_section(out: &mut String, header: &str, b64: &str) {
    let lines: Vec<&[u8]> = b64.as_bytes().chunks(64).collect();
    out.push_str(&format!("{header}: {}\n", lines.len()));
    for chunk in lines {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
}

/// Encode the private-key wire fields per Appendix C.3 (unencrypted, no
/// padding — that's layered on separately during export).
fn encode_private_blob(keypair: &KeypairData) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    match keypair {
        KeypairData::Rsa(kp) => {
            write_mpint_bytes(&mut out, &kp.private.d);
            write_mpint_bytes(&mut out, &kp.private.p);
            write_mpint_bytes(&mut out, &kp.private.q);
            write_mpint_bytes(&mut out, &kp.private.iqmp);
        }
        KeypairData::Ed25519(kp) => {
            let seed = kp.private.to_bytes();
            let mpint = Mpint::from_positive_bytes(&seed).map_err(|e| anyhow::anyhow!(e))?;
            write_mpint_bytes(&mut out, &mpint);
        }
        KeypairData::Ecdsa(kp) => {
            let scalar = kp.private_key_bytes();
            let mpint = Mpint::from_positive_bytes(scalar).map_err(|e| anyhow::anyhow!(e))?;
            write_mpint_bytes(&mut out, &mpint);
        }
        _ => anyhow::bail!("Unsupported key type for PPK export"),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_rejects_oversized_memory() {
        // 4294967295 KiB would be ~4 TiB of Argon2 memory (u32::MAX).
        let err = validate_argon2_params(u32::MAX, 4, 1, 16)
            .expect_err("oversized memory must be rejected");
        assert!(err.to_string().contains("Argon2-Memory too large"));
    }

    #[test]
    fn validator_rejects_zero_and_oversized_passes() {
        assert!(validate_argon2_params(8192, 0, 1, 16).is_err());
        let err = validate_argon2_params(8192, 257, 1, 16).expect_err("passes > 256 rejected");
        assert!(err.to_string().contains("Argon2-Passes too large"));
    }

    #[test]
    fn validator_rejects_zero_and_oversized_parallelism() {
        assert!(validate_argon2_params(8192, 4, 0, 16).is_err());
        let err = validate_argon2_params(8192, 4, 65, 16).expect_err("parallelism > 64 rejected");
        assert!(err.to_string().contains("Argon2-Parallelism too large"));
    }

    #[test]
    fn validator_rejects_empty_and_oversized_salt() {
        assert!(validate_argon2_params(8192, 4, 1, 0).is_err());
        let err = validate_argon2_params(8192, 4, 1, 65).expect_err("salt > 64 bytes rejected");
        assert!(err.to_string().contains("Argon2-Salt too long"));
    }

    #[test]
    fn validator_accepts_boundaries_and_putty_defaults() {
        // Exactly at the caps: 1 GiB memory, 256 passes, 64 parallelism,
        // 64-byte salt.
        assert!(validate_argon2_params(1_048_576, 256, 64, 64).is_ok());
        // PuTTY's own defaults (8 MiB / 4 passes / 1 lane / 16-byte salt).
        assert!(validate_argon2_params(8192, 4, 1, 16).is_ok());
        // Minimal valid values.
        assert!(validate_argon2_params(1, 1, 1, 1).is_ok());
    }

    /// Minimal v3 PPK header skeleton that reaches the Argon2 validation
    /// during parsing. The public blob is a placeholder; parsing fails on
    /// Argon2 bounds long before any key material is needed.
    fn ppk_header_with_argon2(
        memory: &str,
        passes: &str,
        parallelism: &str,
        salt_hex: &str,
    ) -> String {
        format!(
            "PuTTY-User-Key-File-3: ssh-ed25519\n\
             Encryption: aes256-cbc\n\
             Comment: test\n\
             Public-Lines: 1\n\
             AAAA\n\
             Key-Derivation: Argon2id\n\
             Argon2-Memory: {memory}\n\
             Argon2-Passes: {passes}\n\
             Argon2-Parallelism: {parallelism}\n\
             Argon2-Salt: {salt_hex}\n"
        )
    }

    #[test]
    fn parse_rejects_huge_argon2_memory_before_any_kdf() {
        // u32::MAX KiB (~4 TiB) is in-range for the u32 parse but far past
        // the 1 GiB cap; it must be rejected at parse time, before any
        // Argon2 allocation.
        let data = ppk_header_with_argon2("4294967295", "4", "1", &"ab".repeat(16));
        let err = parse_ppk_file(&data).expect_err("huge memory must be rejected at parse time");
        assert!(err.to_string().contains("Argon2-Memory too large"));
    }

    #[test]
    fn parse_rejects_out_of_range_memory_as_bad_value() {
        // 99999999999 doesn't fit in u32 at all; rejected during parsing.
        let data = ppk_header_with_argon2("99999999999", "4", "1", &"ab".repeat(16));
        let err = parse_ppk_file(&data).expect_err("out-of-range memory must be rejected");
        assert!(err.to_string().contains("Bad Argon2-Memory"));
    }

    #[test]
    fn parse_rejects_huge_salt_before_decoding() {
        // 5 KB of hex (2.5 KB decoded) — far past the 128-hex-char cap.
        let data = ppk_header_with_argon2("8192", "4", "1", &"ab".repeat(2500));
        let err = parse_ppk_file(&data).expect_err("huge salt must be rejected at parse time");
        assert!(err.to_string().contains("Argon2-Salt too long"));
    }

    #[test]
    fn parse_rejects_zero_memory() {
        let data = ppk_header_with_argon2("0", "4", "1", &"ab".repeat(16));
        let err = parse_ppk_file(&data).expect_err("zero memory must be rejected");
        assert!(err.to_string().contains("Argon2-Memory must be at least"));
    }

    #[test]
    fn parse_accepts_sane_argon2_parameters() {
        // PuTTY's own defaults must sail through parsing (the file is
        // incomplete as a key, but Argon2 validation itself must pass).
        let data = ppk_header_with_argon2("8192", "4", "1", &"ab".repeat(16));
        let parsed = match parse_ppk_file(&data) {
            Ok(p) => p,
            Err(e) => panic!("sane Argon2 parameters must not be rejected: {e}"),
        };
        assert_eq!(parsed.argon2_memory_kb, 8192);
        assert_eq!(parsed.argon2_passes, 4);
        assert_eq!(parsed.argon2_parallelism, 1);
        assert_eq!(parsed.argon2_salt.len(), 16);
    }

    #[test]
    fn parse_accepts_boundary_memory_exactly_1_gib() {
        let data = ppk_header_with_argon2("1048576", "4", "1", &"ab".repeat(16));
        let parsed = match parse_ppk_file(&data) {
            Ok(p) => p,
            Err(e) => panic!("1 GiB memory boundary must be accepted: {e}"),
        };
        assert_eq!(parsed.argon2_memory_kb, 1_048_576);
    }
}
