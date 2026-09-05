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
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use argon2::{Argon2, Algorithm as Argon2Algorithm, Version as Argon2Version, Params as Argon2Params};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use base64ct::{Base64, Encoding};
use ssh_key::{
    private::{EcdsaKeypair, EcdsaPrivateKey, Ed25519Keypair, Ed25519PrivateKey, KeypairData, RsaKeypair, RsaPrivateKey as SshRsaPrivateKey},
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
            let n: usize = v.trim().parse().map_err(|_| anyhow::anyhow!("Bad Public-Lines count"))?;
            let b64: String = lines.get(i + 1..i + 1 + n).ok_or_else(|| anyhow::anyhow!("Truncated public key section"))?.concat();
            public_blob = Base64::decode_vec(&b64).map_err(|e| anyhow::anyhow!("Bad public key base64: {e}"))?;
            i += n;
        } else if let Some(v) = line.strip_prefix("Key-Derivation:") {
            argon2_flavour = match v.trim() {
                "Argon2d" => Argon2Flavour::D,
                "Argon2i" => Argon2Flavour::I,
                "Argon2id" => Argon2Flavour::Id,
                other => anyhow::bail!("Unknown Argon2 flavour: {other}"),
            };
        } else if let Some(v) = line.strip_prefix("Argon2-Memory:") {
            argon2_memory_kb = v.trim().parse().map_err(|_| anyhow::anyhow!("Bad Argon2-Memory"))?;
        } else if let Some(v) = line.strip_prefix("Argon2-Passes:") {
            argon2_passes = v.trim().parse().map_err(|_| anyhow::anyhow!("Bad Argon2-Passes"))?;
        } else if let Some(v) = line.strip_prefix("Argon2-Parallelism:") {
            argon2_parallelism = v.trim().parse().map_err(|_| anyhow::anyhow!("Bad Argon2-Parallelism"))?;
        } else if let Some(v) = line.strip_prefix("Argon2-Salt:") {
            argon2_salt = hex::decode(v.trim()).map_err(|e| anyhow::anyhow!("Bad Argon2-Salt hex: {e}"))?;
        } else if let Some(v) = line.strip_prefix("Private-Lines:") {
            let n: usize = v.trim().parse().map_err(|_| anyhow::anyhow!("Bad Private-Lines count"))?;
            let b64: String = lines.get(i + 1..i + 1 + n).ok_or_else(|| anyhow::anyhow!("Truncated private key section"))?.concat();
            private_blob = Base64::decode_vec(&b64).map_err(|e| anyhow::anyhow!("Bad private key base64: {e}"))?;
            i += n;
        } else if let Some(v) = line.strip_prefix("Private-MAC:") {
            mac = hex::decode(v.trim()).map_err(|e| anyhow::anyhow!("Bad Private-MAC hex: {e}"))?;
        }
        i += 1;
    }

    if public_blob.is_empty() {
        anyhow::bail!("PPK file has no public key data");
    }

    Ok(ParsedPpk {
        version, algorithm_name, encrypted, comment, public_blob, private_blob, mac,
        argon2_flavour, argon2_memory_kb, argon2_passes, argon2_parallelism, argon2_salt,
    })
}

// ─── Key derivation ─────────────────────────────────────────────────────────

/// PPK v3 (Appendix C.4): a *single* Argon2 call whose tag length is
/// cipher_key_len + iv_len + mac_key_len; output split in that order.
fn derive_v3(parsed: &ParsedPpk, passphrase: &str) -> anyhow::Result<([u8; 32], [u8; 16], [u8; 32])> {
    let algo = match parsed.argon2_flavour {
        Argon2Flavour::D => Argon2Algorithm::Argon2d,
        Argon2Flavour::I => Argon2Algorithm::Argon2i,
        Argon2Flavour::Id => Argon2Algorithm::Argon2id,
    };
    let params = Argon2Params::new(parsed.argon2_memory_kb, parsed.argon2_passes, parsed.argon2_parallelism, Some(80))
        .map_err(|e| anyhow::anyhow!(e))?;
    let argon2 = Argon2::new(algo, Argon2Version::V0x13, params);

    let mut output = [0u8; 80];
    argon2.hash_password_into(passphrase.as_bytes(), &parsed.argon2_salt, &mut output)
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
    ssh_string(&mut buf, if parsed.encrypted { b"aes256-cbc" } else { b"none" });
    ssh_string(&mut buf, parsed.comment.as_bytes());
    ssh_string(&mut buf, &parsed.public_blob);
    ssh_string(&mut buf, plaintext_private_blob);
    buf
}

fn verify_mac_v3(parsed: &ParsedPpk, mac_key: &[u8; 32], plaintext_private_blob: &[u8]) -> anyhow::Result<()> {
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

fn verify_mac_v2(parsed: &ParsedPpk, mac_key: &[u8; 20], plaintext_private_blob: &[u8]) -> anyhow::Result<()> {
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

fn cbc_encrypt_no_padding(plaintext_padded: &mut [u8], key: &[u8], iv: &[u8]) -> anyhow::Result<()> {
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
        anyhow::bail!("PPK scalar is wider than expected ({} > {width} bytes)", trimmed.len());
    }
    let mut out = vec![0u8; width - trimmed.len()];
    out.extend_from_slice(trimmed);
    Ok(out)
}

/// Build the type-specific `KeypairData` from the (already decrypted)
/// private blob per Appendix C.3, paired with the public key parsed from
/// the file's public-lines section.
fn build_keypair_data(parsed: &ParsedPpk, plaintext_private_blob: &[u8]) -> anyhow::Result<(KeyType, KeypairData)> {
    let public_key = PublicKey::from_bytes(&parsed.public_blob)
        .map_err(|e| anyhow::anyhow!("Invalid public key data in PPK file: {e}"))?;

    let mut pos = 0usize;

    match parsed.algorithm_name.as_str() {
        "ssh-rsa" => {
            let rsa_pub = public_key.key_data().rsa().ok_or_else(|| anyhow::anyhow!("PPK header says ssh-rsa but public blob isn't RSA"))?.clone();
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
            Ok((KeyType::Rsa, KeypairData::Rsa(RsaKeypair { public: rsa_pub, private })))
        }
        "ssh-ed25519" => {
            let scalar = read_mpint_bytes(plaintext_private_blob, &mut pos)?;
            let seed = mpint_to_fixed_be(&scalar, 32)?;
            let seed_arr: [u8; 32] = seed.try_into().map_err(|_| anyhow::anyhow!("Bad Ed25519 seed length"))?;
            let private = Ed25519PrivateKey::from_bytes(&seed_arr);
            let keypair: Ed25519Keypair = private.into();
            Ok((KeyType::Ed25519, KeypairData::Ed25519(keypair)))
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let ecdsa_pub = public_key.key_data().ecdsa().ok_or_else(|| anyhow::anyhow!("PPK header says ECDSA but public blob isn't ECDSA"))?.clone();
            let scalar = read_mpint_bytes(plaintext_private_blob, &mut pos)?;

            let (key_type, keypair) = match &ecdsa_pub {
                ssh_key::public::EcdsaPublicKey::NistP256(point) => {
                    let bytes = mpint_to_fixed_be(&scalar, 32)?;
                    let sk = p256::SecretKey::from_slice(&bytes).map_err(|e| anyhow::anyhow!("Invalid P-256 scalar: {e}"))?;
                    let private: EcdsaPrivateKey<32> = sk.into();
                    (KeyType::EcdsaP256, EcdsaKeypair::NistP256 { public: point.clone(), private })
                }
                ssh_key::public::EcdsaPublicKey::NistP384(point) => {
                    let bytes = mpint_to_fixed_be(&scalar, 48)?;
                    let sk = p384::SecretKey::from_slice(&bytes).map_err(|e| anyhow::anyhow!("Invalid P-384 scalar: {e}"))?;
                    let private: EcdsaPrivateKey<48> = sk.into();
                    (KeyType::EcdsaP384, EcdsaKeypair::NistP384 { public: point.clone(), private })
                }
                ssh_key::public::EcdsaPublicKey::NistP521(point) => {
                    let bytes = mpint_to_fixed_be(&scalar, 66)?;
                    let sk = p521::SecretKey::from_slice(&bytes).map_err(|e| anyhow::anyhow!("Invalid P-521 scalar: {e}"))?;
                    let private: EcdsaPrivateKey<66> = sk.into();
                    (KeyType::EcdsaP521, EcdsaKeypair::NistP521 { public: point.clone(), private })
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
    let private_key = PrivateKey::new(keypair_data, parsed.comment.clone()).map_err(|e| anyhow::anyhow!(e))?;

    let private_bytes = private_key.to_bytes().map_err(|e| anyhow::anyhow!(e))?.to_vec();
    let public_bytes = private_key.public_key().to_bytes().map_err(|e| anyhow::anyhow!(e))?.to_vec();

    Ok(PrivateKeyData::new(key_type, private_bytes, public_bytes, parsed.comment))
}

/// Export a key to PuTTY PPK v3 format, optionally encrypted with a
/// passphrase (Argon2id, PuTTY's own default flavour).
pub fn export_ppk(key_data: &PrivateKeyData, passphrase: Option<&str>) -> anyhow::Result<String> {
    let private_key = PrivateKey::from_bytes(&key_data.private_key).map_err(|e| anyhow::anyhow!(e))?;
    let algorithm_name = key_data.key_type.algorithm_name();

    let mut out = String::new();
    out.push_str(&format!("PuTTY-User-Key-File-3: {algorithm_name}\n"));

    let pass = passphrase.filter(|p| !p.is_empty());
    out.push_str(&format!("Encryption: {}\n", if pass.is_some() { "aes256-cbc" } else { "none" }));
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

        let params = Argon2Params::new(memory_kb, passes, parallelism, Some(80)).map_err(|e| anyhow::anyhow!(e))?;
        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, params);
        let mut kdf_out = [0u8; 80];
        argon2.hash_password_into(pass.as_bytes(), &salt, &mut kdf_out).map_err(|e| anyhow::anyhow!(e))?;
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
            version: PpkVersion::V3, algorithm_name: algorithm_name.to_string(), encrypted: true,
            comment: key_data.comment.clone(), public_blob: key_data.public_key.clone(),
            private_blob: Vec::new(), mac: Vec::new(), argon2_flavour: Argon2Flavour::Id,
            argon2_memory_kb: memory_kb, argon2_passes: passes, argon2_parallelism: parallelism,
            argon2_salt: salt,
        };
        let preimage = mac_preimage(&parsed_for_mac, &private_blob);
        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key_arr).expect("HMAC accepts any key size");
        mac.update(&preimage);
        (padded, mac.finalize().into_bytes().to_vec())
    } else {
        let parsed_for_mac = ParsedPpk {
            version: PpkVersion::V3, algorithm_name: algorithm_name.to_string(), encrypted: false,
            comment: key_data.comment.clone(), public_blob: key_data.public_key.clone(),
            private_blob: Vec::new(), mac: Vec::new(), argon2_flavour: Argon2Flavour::Id,
            argon2_memory_kb: 0, argon2_passes: 0, argon2_parallelism: 0, argon2_salt: Vec::new(),
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
