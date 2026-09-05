//! Key generation, fingerprinting, and serialization
//!
//! Generation, OpenSSH parsing/serialization, and fingerprinting are
//! delegated to the audited `ssh-key` crate (RustCrypto) rather than
//! hand-rolled wire-format encoding, so RSA/ECDSA/Ed25519 keys this app
//! produces are byte-correct and parseable by real `ssh-keygen`/OpenSSH.
//! PKCS#8 and PuTTY PPK export still need custom encoding since `ssh-key`
//! doesn't cover those; that logic lives here and in `crypto::putty`.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::utils::{generate_random_vec, ssh_fingerprint_sha256, ssh_fingerprint_md5};
use base64ct::{Base64, Encoding};
use ssh_key::{
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair},
    rand_core::OsRng,
    Algorithm, EcdsaCurve, LineEnding, PrivateKey,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Rsa,
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

impl KeyType {
    /// SSH wire-format algorithm name (as used in `ssh-rsa AAAA...` lines).
    pub fn algorithm_name(self) -> &'static str {
        match self {
            KeyType::Rsa => "ssh-rsa",
            KeyType::Ed25519 => "ssh-ed25519",
            KeyType::EcdsaP256 => "ecdsa-sha2-nistp256",
            KeyType::EcdsaP384 => "ecdsa-sha2-nistp384",
            KeyType::EcdsaP521 => "ecdsa-sha2-nistp521",
        }
    }

    fn from_ssh_key_algorithm(alg: &Algorithm) -> anyhow::Result<Self> {
        match alg {
            Algorithm::Rsa { .. } => Ok(KeyType::Rsa),
            Algorithm::Ed25519 => Ok(KeyType::Ed25519),
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 } => Ok(KeyType::EcdsaP256),
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 } => Ok(KeyType::EcdsaP384),
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 } => Ok(KeyType::EcdsaP521),
            other => anyhow::bail!("Unsupported key algorithm: {:?}", other),
        }
    }

    /// Stable string tag used for DB storage / IPC (distinct from the
    /// SSH wire algorithm name).
    pub fn db_tag(self) -> &'static str {
        match self {
            KeyType::Rsa => "rsa",
            KeyType::Ed25519 => "ed25519",
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::EcdsaP384 => "ecdsa-p384",
            KeyType::EcdsaP521 => "ecdsa-p521",
        }
    }

    pub fn from_db_tag(tag: &str) -> anyhow::Result<Self> {
        match tag {
            "rsa" => Ok(KeyType::Rsa),
            "ed25519" => Ok(KeyType::Ed25519),
            "ecdsa" | "ecdsa-p256" => Ok(KeyType::EcdsaP256),
            "ecdsa-p384" => Ok(KeyType::EcdsaP384),
            "ecdsa-p521" => Ok(KeyType::EcdsaP521),
            other => anyhow::bail!("Unknown key type: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyFormat {
    OpenSsh,
    Pkcs8,
    Putty,
    Rfc4716,
}

/// A generated or imported key pair.
///
/// `private_key` holds the raw SSH wire-format private key
/// (`ssh_key::PrivateKey::to_bytes()`, always unencrypted at this layer —
/// encryption at rest is the vault's job) and `public_key` holds the raw
/// SSH wire-format public key blob (`ssh_key::PublicKey::to_bytes()`),
/// i.e. exactly the bytes that appear base64-encoded in an
/// `authorized_keys` line.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeyData {
    pub key_type: KeyType,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub comment: String,
}

impl PrivateKeyData {
    pub fn new(key_type: KeyType, private_key: impl Into<Vec<u8>>, public_key: impl Into<Vec<u8>>, comment: String) -> Self {
        Self { key_type, private_key: private_key.into(), public_key: public_key.into(), comment }
    }

    /// Reconstruct the `ssh_key::PrivateKey` this data represents.
    fn to_ssh_key(&self) -> anyhow::Result<PrivateKey> {
        PrivateKey::from_bytes(&self.private_key).map_err(|e| anyhow::anyhow!("Invalid stored private key: {e}"))
    }
}

/// Generate a new key pair of the given type.
///
/// `bits` only applies to RSA (clamped to 2048-16384; default 3072).
pub fn generate_key_pair(key_type: KeyType, bits: Option<u32>, comment: String) -> anyhow::Result<PrivateKeyData> {
    let mut rng = OsRng;

    let keypair_data: KeypairData = match key_type {
        KeyType::Rsa => {
            let bits = bits.unwrap_or(3072).clamp(2048, 16384) as usize;
            KeypairData::Rsa(RsaKeypair::random(&mut rng, bits).map_err(|e| anyhow::anyhow!(e))?)
        }
        KeyType::Ed25519 => KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)),
        KeyType::EcdsaP256 => {
            KeypairData::Ecdsa(EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP256).map_err(|e| anyhow::anyhow!(e))?)
        }
        KeyType::EcdsaP384 => {
            KeypairData::Ecdsa(EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP384).map_err(|e| anyhow::anyhow!(e))?)
        }
        KeyType::EcdsaP521 => {
            KeypairData::Ecdsa(EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP521).map_err(|e| anyhow::anyhow!(e))?)
        }
    };

    let private_key = PrivateKey::new(keypair_data, comment.clone()).map_err(|e| anyhow::anyhow!(e))?;
    let private_bytes = private_key.to_bytes().map_err(|e| anyhow::anyhow!(e))?.to_vec();
    let public_bytes = private_key.public_key().to_bytes().map_err(|e| anyhow::anyhow!(e))?.to_vec();

    Ok(PrivateKeyData::new(key_type, private_bytes, public_bytes, comment))
}

/// Import a key from an OpenSSH-formatted PEM private key (`-----BEGIN
/// OPENSSH PRIVATE KEY-----`). Handles encrypted and plaintext keys.
pub fn import_openssh_private(pem: &str, passphrase: Option<&str>) -> anyhow::Result<PrivateKeyData> {
    let mut key = PrivateKey::from_openssh(pem).map_err(|e| anyhow::anyhow!("Failed to parse OpenSSH key: {e}"))?;
    if key.is_encrypted() {
        let pass = passphrase.ok_or_else(|| anyhow::anyhow!("This key is encrypted; a passphrase is required."))?;
        key = key.decrypt(pass).map_err(|_| anyhow::anyhow!("Incorrect passphrase, or the key file is corrupted."))?;
    }

    let key_type = KeyType::from_ssh_key_algorithm(&key.algorithm())?;
    let comment = key.comment().to_string();
    let private_bytes = key.to_bytes().map_err(|e| anyhow::anyhow!(e))?.to_vec();
    let public_bytes = key.public_key().to_bytes().map_err(|e| anyhow::anyhow!(e))?.to_vec();

    Ok(PrivateKeyData::new(key_type, private_bytes, public_bytes, comment))
}

/// Compute SSH fingerprint (SHA-256) - matches `ssh-keygen -lf` exactly.
pub fn compute_fingerprint_sha256(public_key: &[u8]) -> String {
    ssh_fingerprint_sha256(public_key)
}

/// Compute SSH fingerprint (MD5) - for legacy compatibility
pub fn compute_fingerprint_md5(public_key: &[u8]) -> String {
    ssh_fingerprint_md5(public_key)
}

/// Export private key in various formats
pub fn export_private_key(
    key_data: &PrivateKeyData,
    format: KeyFormat,
    passphrase: Option<&str>,
) -> anyhow::Result<String> {
    match format {
        KeyFormat::OpenSsh => export_openssh_private(key_data, passphrase),
        KeyFormat::Pkcs8 => export_pkcs8_private(key_data, passphrase),
        KeyFormat::Putty => export_putty_private(key_data, passphrase),
        KeyFormat::Rfc4716 => export_rfc4716_private(key_data, passphrase),
    }
}

/// Export public key in various formats
pub fn export_public_key(
    key_data: &PrivateKeyData,
    format: KeyFormat,
) -> anyhow::Result<String> {
    match format {
        KeyFormat::OpenSsh => export_openssh_public(key_data),
        KeyFormat::Pkcs8 => export_pkcs8_public(key_data),
        KeyFormat::Rfc4716 => export_rfc4716_public(key_data),
        KeyFormat::Putty => export_putty_public(key_data),
    }
}

/// Export as OpenSSH format, optionally encrypted with a passphrase
/// (aes256-ctr + bcrypt KDF, matching modern `ssh-keygen` defaults).
fn export_openssh_private(key_data: &PrivateKeyData, passphrase: Option<&str>) -> anyhow::Result<String> {
    let key = key_data.to_ssh_key()?;
    let key = match passphrase {
        Some(pass) if !pass.is_empty() => {
            let mut rng = OsRng;
            key.encrypt(&mut rng, pass).map_err(|e| anyhow::anyhow!(e))?
        }
        _ => key,
    };
    Ok(key.to_openssh(LineEnding::LF).map_err(|e| anyhow::anyhow!(e))?.to_string())
}

fn export_openssh_public(key_data: &PrivateKeyData) -> anyhow::Result<String> {
    let b64 = Base64::encode_string(&key_data.public_key);
    Ok(format!("{} {} {}", key_data.key_type.algorithm_name(), b64, key_data.comment).trim_end().to_string())
}

/// Export as PKCS#8 format (SPKI public / PrivateKeyInfo private PEM)
fn export_pkcs8_private(key_data: &PrivateKeyData, passphrase: Option<&str>) -> anyhow::Result<String> {
    let der = crate::crypto::pkcs8::private_key_to_pkcs8_der(key_data)?;
    if let Some(pass) = passphrase.filter(|p| !p.is_empty()) {
        encrypt_pkcs8_with_passphrase(&der, pass)
    } else {
        pem_wrap("PRIVATE KEY", &der)
    }
}

fn export_pkcs8_public(key_data: &PrivateKeyData) -> anyhow::Result<String> {
    let der = crate::crypto::pkcs8::public_key_to_spki_der(key_data)?;
    pem_wrap("PUBLIC KEY", &der)
}

fn pem_wrap(label: &str, der: &[u8]) -> anyhow::Result<String> {
    let b64 = Base64::encode_string(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    Ok(out)
}

/// Export as PuTTY PPK format
fn export_putty_private(key_data: &PrivateKeyData, passphrase: Option<&str>) -> anyhow::Result<String> {
    crate::crypto::putty::export_ppk(key_data, passphrase)
}

fn export_putty_public(key_data: &PrivateKeyData) -> anyhow::Result<String> {
    export_rfc4716_public(key_data)
}

/// Export as RFC 4716 format
fn export_rfc4716_private(_key_data: &PrivateKeyData, _passphrase: Option<&str>) -> anyhow::Result<String> {
    anyhow::bail!("RFC 4716 private key export not supported (not part of the RFC 4716 spec; OpenSSH doesn't support it either).");
}

fn export_rfc4716_public(key_data: &PrivateKeyData) -> anyhow::Result<String> {
    let openssh_pub = export_openssh_public(key_data)?;
    let parts: Vec<&str> = openssh_pub.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid OpenSSH public key");
    }
    let base64_key = parts[1];
    let comment = parts.get(2).map(|s| s.to_string()).unwrap_or_else(|| key_data.comment.clone());

    let mut output = String::new();
    output.push_str("---- BEGIN SSH2 PUBLIC KEY ----\n");
    output.push_str(&format!("Comment: \"{}\"\n", comment));
    output.push_str(&format!("{}\n", base64_key));
    output.push_str("---- END SSH2 PUBLIC KEY ----\n");
    Ok(output)
}

/// Encrypt PKCS#8 DER private key with a passphrase (PBES2 style, AES-256-CBC)
fn encrypt_pkcs8_with_passphrase(pkcs8_der: &[u8], passphrase: &str) -> anyhow::Result<String> {
    use aes::Aes256;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    use pbkdf2::pbkdf2_hmac_array;
    use sha2::Sha256;

    let salt = generate_random_vec(16);
    let key: [u8; 32] = pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), &salt, 100_000);
    let iv: [u8; 16] = pbkdf2_hmac_array::<Sha256, 16>(passphrase.as_bytes(), &salt, 100_000);

    let mut buf = pkcs8_der.to_vec();
    let pt_len = buf.len();
    buf.resize(pt_len + 16, 0);
    let ct = cbc::Encryptor::<Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|e| anyhow::anyhow!(e))?;
    let ct = ct.to_vec();

    let mut pem = String::new();
    pem.push_str("-----BEGIN ENCRYPTED PRIVATE KEY-----\n");
    pem.push_str("Proc-Type: 4,ENCRYPTED\n");
    pem.push_str(&format!("DEK-Info: AES-256-CBC,{}\n\n", hex::encode(iv)));
    let b64 = Base64::encode_string(&ct);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END ENCRYPTED PRIVATE KEY-----\n");
    Ok(pem)
}
