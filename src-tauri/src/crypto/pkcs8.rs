//! PKCS#8 DER encoding for exported keys.
//!
//! `ssh-key` doesn't cover PKCS#8 (it's an SSH-format-only crate), so this
//! module extracts the raw key material from a reconstructed
//! `ssh_key::PrivateKey`/`PublicKey` and builds real PKCS#8
//! (`PrivateKeyInfo`) / SPKI (`SubjectPublicKeyInfo`) DER:
//!
//! - RSA / P-256 / P-384 / P-521: delegated to the respective RustCrypto
//!   crates' own `EncodePrivateKey`/`EncodePublicKey` implementations.
//! - Ed25519: RFC 8410 has no library support in our dependency tree, so
//!   it's hand-encoded here against the RFC's exact ASN.1 layout (the
//!   private key octets are a *double*-wrapped OCTET STRING — a detail
//!   that's easy to get wrong and produce keys other tools reject).

use crate::crypto::keys::PrivateKeyData;
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;

pub fn private_key_to_pkcs8_der(key_data: &PrivateKeyData) -> anyhow::Result<Vec<u8>> {
    let sk = ssh_key::PrivateKey::from_bytes(&key_data.private_key)
        .map_err(|e| anyhow::anyhow!("Invalid stored private key: {e}"))?;

    match sk.key_data() {
        KeypairData::Rsa(kp) => rsa_private_to_pkcs8(kp),
        KeypairData::Ed25519(kp) => Ok(ed25519_private_to_pkcs8(&kp.private.to_bytes())),
        KeypairData::Ecdsa(kp) => ecdsa_private_to_pkcs8(kp),
        _ => anyhow::bail!("Unsupported key type for PKCS#8 export"),
    }
}

pub fn public_key_to_spki_der(key_data: &PrivateKeyData) -> anyhow::Result<Vec<u8>> {
    let pk = ssh_key::PublicKey::from_bytes(&key_data.public_key)
        .map_err(|e| anyhow::anyhow!("Invalid stored public key: {e}"))?;

    match pk.key_data() {
        KeyData::Rsa(rsa_pub) => rsa_public_to_spki(rsa_pub),
        KeyData::Ed25519(ed_pub) => Ok(ed25519_public_to_spki(&ed_pub.0)),
        KeyData::Ecdsa(ecdsa_pub) => ecdsa_public_to_spki(ecdsa_pub),
        _ => anyhow::bail!("Unsupported key type for PKCS#8 export"),
    }
}

// ─── RSA ─────────────────────────────────────────────────────────────────

fn rsa_private_to_pkcs8(kp: &ssh_key::private::RsaKeypair) -> anyhow::Result<Vec<u8>> {
    use pkcs8::EncodePrivateKey;
    use rsa::BigUint;

    let n = BigUint::from_bytes_be(
        kp.public
            .n
            .as_positive_bytes()
            .ok_or_else(|| anyhow::anyhow!("Negative RSA modulus"))?,
    );
    let e = BigUint::from_bytes_be(
        kp.public
            .e
            .as_positive_bytes()
            .ok_or_else(|| anyhow::anyhow!("Negative RSA exponent"))?,
    );
    let d = BigUint::from_bytes_be(
        kp.private
            .d
            .as_positive_bytes()
            .ok_or_else(|| anyhow::anyhow!("Negative RSA d"))?,
    );
    let p = BigUint::from_bytes_be(
        kp.private
            .p
            .as_positive_bytes()
            .ok_or_else(|| anyhow::anyhow!("Negative RSA p"))?,
    );
    let q = BigUint::from_bytes_be(
        kp.private
            .q
            .as_positive_bytes()
            .ok_or_else(|| anyhow::anyhow!("Negative RSA q"))?,
    );

    let private_key = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct RSA key: {e}"))?;

    let der = private_key.to_pkcs8_der().map_err(|e| anyhow::anyhow!(e))?;
    Ok(der.as_bytes().to_vec())
}

fn rsa_public_to_spki(pub_key: &ssh_key::public::RsaPublicKey) -> anyhow::Result<Vec<u8>> {
    use pkcs8::EncodePublicKey;
    use rsa::BigUint;

    let n = BigUint::from_bytes_be(
        pub_key
            .n
            .as_positive_bytes()
            .ok_or_else(|| anyhow::anyhow!("Negative RSA modulus"))?,
    );
    let e = BigUint::from_bytes_be(
        pub_key
            .e
            .as_positive_bytes()
            .ok_or_else(|| anyhow::anyhow!("Negative RSA exponent"))?,
    );

    let public_key = rsa::RsaPublicKey::new(n, e).map_err(|e| anyhow::anyhow!(e))?;
    let der = public_key
        .to_public_key_der()
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(der.as_bytes().to_vec())
}

// ─── ECDSA (P-256 / P-384 / P-521) ─────────────────────────────────────────

fn ecdsa_private_to_pkcs8(kp: &ssh_key::private::EcdsaKeypair) -> anyhow::Result<Vec<u8>> {
    use pkcs8::EncodePrivateKey;

    let scalar = kp.private_key_bytes();
    match kp {
        ssh_key::private::EcdsaKeypair::NistP256 { .. } => {
            let sk = p256::SecretKey::from_slice(scalar).map_err(|e| anyhow::anyhow!(e))?;
            Ok(sk
                .to_pkcs8_der()
                .map_err(|e| anyhow::anyhow!(e))?
                .as_bytes()
                .to_vec())
        }
        ssh_key::private::EcdsaKeypair::NistP384 { .. } => {
            let sk = p384::SecretKey::from_slice(scalar).map_err(|e| anyhow::anyhow!(e))?;
            Ok(sk
                .to_pkcs8_der()
                .map_err(|e| anyhow::anyhow!(e))?
                .as_bytes()
                .to_vec())
        }
        ssh_key::private::EcdsaKeypair::NistP521 { .. } => {
            let sk = p521::SecretKey::from_slice(scalar).map_err(|e| anyhow::anyhow!(e))?;
            Ok(sk
                .to_pkcs8_der()
                .map_err(|e| anyhow::anyhow!(e))?
                .as_bytes()
                .to_vec())
        }
    }
}

fn ecdsa_public_to_spki(pub_key: &ssh_key::public::EcdsaPublicKey) -> anyhow::Result<Vec<u8>> {
    use pkcs8::EncodePublicKey;

    let sec1 = pub_key.as_sec1_bytes();
    match pub_key {
        ssh_key::public::EcdsaPublicKey::NistP256(_) => {
            let pk = p256::PublicKey::from_sec1_bytes(sec1).map_err(|e| anyhow::anyhow!(e))?;
            Ok(pk
                .to_public_key_der()
                .map_err(|e| anyhow::anyhow!(e))?
                .as_bytes()
                .to_vec())
        }
        ssh_key::public::EcdsaPublicKey::NistP384(_) => {
            let pk = p384::PublicKey::from_sec1_bytes(sec1).map_err(|e| anyhow::anyhow!(e))?;
            Ok(pk
                .to_public_key_der()
                .map_err(|e| anyhow::anyhow!(e))?
                .as_bytes()
                .to_vec())
        }
        ssh_key::public::EcdsaPublicKey::NistP521(_) => {
            let pk = p521::PublicKey::from_sec1_bytes(sec1).map_err(|e| anyhow::anyhow!(e))?;
            Ok(pk
                .to_public_key_der()
                .map_err(|e| anyhow::anyhow!(e))?
                .as_bytes()
                .to_vec())
        }
    }
}

// ─── Ed25519 (hand-encoded per RFC 8410) ───────────────────────────────────

/// Ed25519 AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 }
fn ed25519_algorithm_id() -> Vec<u8> {
    der_sequence(&der_oid(&[1, 3, 101, 112]))
}

/// RFC 8410 §7: PrivateKeyInfo.privateKey is an OCTET STRING whose content
/// is itself the DER encoding of `CurvePrivateKey ::= OCTET STRING`, i.e.
/// the raw 32-byte seed is wrapped in OCTET STRING *twice*.
fn ed25519_private_to_pkcs8(seed32: &[u8]) -> Vec<u8> {
    let curve_private_key = der_octet_string(seed32); // inner OCTET STRING
    let private_key_field = der_octet_string(&curve_private_key); // outer OCTET STRING
    let version = der_integer_u8(0);
    let alg_id = ed25519_algorithm_id();

    let mut content = Vec::new();
    content.extend(version);
    content.extend(alg_id);
    content.extend(private_key_field);
    der_sequence(&content)
}

/// RFC 8410 §4: SubjectPublicKeyInfo.subjectPublicKey BIT STRING directly
/// contains the raw 32-byte public key (single-wrapped, unlike the private
/// key above).
fn ed25519_public_to_spki(pubkey32: &[u8]) -> Vec<u8> {
    let alg_id = ed25519_algorithm_id();
    let bit_string = der_bit_string(pubkey32);

    let mut content = Vec::new();
    content.extend(alg_id);
    content.extend(bit_string);
    der_sequence(&content)
}

// ─── PBES2 EncryptedPrivateKeyInfo (RFC 8018 / RFC 5958) ────────────────────

/// OID for PBES2 (RFC 8018 §A.4): 1.2.840.113549.1.5.13
const OID_PBES2: &[u32] = &[1, 2, 840, 113549, 1, 5, 13];
/// OID for PBKDF2 (RFC 8018 §A.2): 1.2.840.113549.1.5.12
const OID_PBKDF2: &[u32] = &[1, 2, 840, 113549, 1, 5, 12];
/// OID for aes256-CBC (NIST AES): 2.16.840.1.101.3.4.1.42
const OID_AES256_CBC: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
/// OID for hmacWithSHA256 (RFC 8018 §B.2): 1.2.840.113549.2.9
const OID_HMAC_WITH_SHA256: &[u32] = &[1, 2, 840, 113549, 2, 9];

/// Build a DER-encoded RFC 8018 PBES2 `EncryptedPrivateKeyInfo` (RFC 5958 §3):
///
/// ```text
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///   encryptionAlgorithm AlgorithmIdentifier,  -- id-PBES2 + PBES2-params
///   encryptedData        OCTET STRING }
///
/// PBES2-params ::= SEQUENCE {
///   keyDerivationFunc AlgorithmIdentifier,    -- id-PBKDF2 + PBKDF2-params
///   encryptionScheme  AlgorithmIdentifier }   -- id-aes256-CBC + IV
///
/// PBKDF2-params ::= SEQUENCE {
///   salt            OCTET STRING,
///   iterationCount  INTEGER,
///   prf             AlgorithmIdentifier }     -- id-hmacWithSHA256
/// ```
///
/// All parameters (salt, iteration count, IV) are serialized so any
/// standards-compliant consumer (`openssl pkcs8`, PuTTYgen, ...) can decrypt
/// the ciphertext given only the passphrase.
pub fn encrypt_private_key_info_pbes2_der(
    salt: &[u8],
    iterations: u32,
    iv: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if iv.len() != 16 {
        anyhow::bail!("AES-256-CBC IV must be 16 bytes, got {}", iv.len());
    }

    // prf AlgorithmIdentifier (no parameters, per RFC 8018 examples)
    let prf_alg_id = der_sequence(&der_oid(OID_HMAC_WITH_SHA256));

    // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER,
    //                               prf AlgorithmIdentifier }
    let mut pbkdf2_params = Vec::new();
    pbkdf2_params.extend(der_octet_string(salt));
    pbkdf2_params.extend(der_integer_u64(iterations as u64));
    pbkdf2_params.extend(&prf_alg_id);
    let pbkdf2_params = der_sequence(&pbkdf2_params);

    // keyDerivationFunc AlgorithmIdentifier
    let mut kdf_alg_id = Vec::new();
    kdf_alg_id.extend(der_oid(OID_PBKDF2));
    kdf_alg_id.extend(&pbkdf2_params);
    let kdf_alg_id = der_sequence(&kdf_alg_id);

    // encryptionScheme AlgorithmIdentifier: id-aes256-CBC + IV OCTET STRING
    let mut enc_scheme = Vec::new();
    enc_scheme.extend(der_oid(OID_AES256_CBC));
    enc_scheme.extend(der_octet_string(iv));
    let enc_scheme = der_sequence(&enc_scheme);

    // PBES2-params
    let mut pbes2_params = Vec::new();
    pbes2_params.extend(&kdf_alg_id);
    pbes2_params.extend(&enc_scheme);
    let pbes2_params = der_sequence(&pbes2_params);

    // encryptionAlgorithm AlgorithmIdentifier: id-PBES2 + PBES2-params
    let mut alg_id = Vec::new();
    alg_id.extend(der_oid(OID_PBES2));
    alg_id.extend(&pbes2_params);
    let alg_id = der_sequence(&alg_id);

    // EncryptedPrivateKeyInfo
    let mut epki = Vec::new();
    epki.extend(&alg_id);
    epki.extend(der_octet_string(ciphertext));
    Ok(der_sequence(&epki))
}

// ─── Minimal DER primitives (sequence/octet-string/bit-string/integer/oid) ─
// Only what's needed above; all lengths here are small so short-form
// length encoding is used, with a long-form fallback for correctness.

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let be = len.to_be_bytes();
        let first_nonzero = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let trimmed = &be[first_nonzero..];
        let mut out = vec![0x80 | trimmed.len() as u8];
        out.extend_from_slice(trimmed);
        out
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_tlv(0x30, content)
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(0x04, content)
}

fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut c = vec![0u8]; // 0 unused bits
    c.extend_from_slice(content);
    der_tlv(0x03, &c)
}

fn der_integer_u8(v: u8) -> Vec<u8> {
    der_tlv(0x02, &[v])
}

/// DER INTEGER from a non-negative u64 (minimal big-endian, with a leading
/// zero byte when the high bit of the top byte would make it look negative).
fn der_integer_u64(v: u64) -> Vec<u8> {
    if v == 0 {
        return der_tlv(0x02, &[0]);
    }
    let be = v.to_be_bytes();
    let first_nonzero = be.iter().position(|&b| b != 0).unwrap();
    let trimmed = &be[first_nonzero..];
    if trimmed[0] & 0x80 != 0 {
        let mut content = vec![0u8];
        content.extend_from_slice(trimmed);
        der_tlv(0x02, &content)
    } else {
        der_tlv(0x02, trimmed)
    }
}

fn der_oid(arcs: &[u32]) -> Vec<u8> {
    let mut content = Vec::new();
    let first = 40 * arcs[0] + arcs[1];
    content.push(first as u8);
    for &arc in &arcs[2..] {
        if arc == 0 {
            content.push(0);
            continue;
        }
        let mut stack = Vec::new();
        let mut v = arc;
        while v > 0 {
            stack.push((v & 0x7f) as u8);
            v >>= 7;
        }
        stack.reverse();
        let last = stack.len() - 1;
        for (i, b) in stack.into_iter().enumerate() {
            content.push(if i < last { b | 0x80 } else { b });
        }
    }
    der_tlv(0x06, &content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_oid_matches_rfc8410() {
        // Known encoding: 06 03 2B 65 70
        assert_eq!(
            der_oid(&[1, 3, 101, 112]),
            vec![0x06, 0x03, 0x2B, 0x65, 0x70]
        );
    }

    #[test]
    fn ed25519_private_der_structure() {
        let seed = [0x11u8; 32];
        let der = ed25519_private_to_pkcs8(&seed);
        // SEQUENCE(46) { INTEGER 0, SEQUENCE{OID 1.3.101.112}, OCTET STRING{ OCTET STRING(32){seed} } }
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[1], 46); // content length (short form)
        assert_eq!(&der[2..5], &[0x02, 0x01, 0x00]); // INTEGER 0
                                                     // AlgorithmIdentifier TLV (header 2 + content 5 = 7 bytes)
        assert_eq!(&der[5..12], &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]);
        // privateKey OCTET STRING starts after the 2-byte SEQUENCE header
        // plus version(3) plus AlgorithmIdentifier(7) = index 12.
        let outer = 12;
        assert_eq!(der[outer], 0x04);
        assert_eq!(der[outer + 1], 34); // wraps CurvePrivateKey
        assert_eq!(der[outer + 2], 0x04); // CurvePrivateKey OCTET STRING
        assert_eq!(der[outer + 3], 32);
        assert_eq!(&der[outer + 4..outer + 4 + 32], &seed);
        assert_eq!(der.len(), outer + 4 + 32); // 48 total
    }
}
