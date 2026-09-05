//! Vault encryption using AES-256-GCM
//! Replaces cryptoService.js AES-256-GCM implementation

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    Argon2, Algorithm, Version, Params,
};
use base64ct::{Base64, Encoding};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::utils::generate_random_vec;

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl VaultKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive vault key from master password using Argon2id
    /// Matches Node.js crypto.scryptSync with N=65536, r=8, p=1
    pub fn derive_from_password(password: &str, salt: &[u8]) -> anyhow::Result<Self> {
        // Use Argon2id with parameters matching scrypt N=65536, r=8, p=1
        let params = Params::new(65536, 3, 4, Some(32)).map_err(|e| anyhow::anyhow!(e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut hash = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt, &mut hash).map_err(|e| anyhow::anyhow!(e))?;

        Ok(Self(hash))
    }

    /// Derive encryption key from vault key using HKDF
    pub fn derive_encryption_key(&self, context: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hk.expand(context, &mut okm).map_err(|e| anyhow::anyhow!(e)).expect("HKDF expand failed");
        okm
    }

    /// Derive authentication key from vault key using HKDF
    pub fn derive_auth_key(&self, context: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hk.expand(&[context, b"auth"].concat(), &mut okm).map_err(|e| anyhow::anyhow!(e)).expect("HKDF expand failed");
        okm
    }
}

/// Encrypted vault data structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedVault {
    pub version: u32,
    pub salt: String,        // Base64 encoded
    pub nonce: String,       // Base64 encoded
    pub ciphertext: String,  // Base64 encoded
    pub auth_tag: String,    // Base64 encoded (for verification)
}

impl EncryptedVault {
    /// Encrypt vault data with master password
    pub fn encrypt(data: &[u8], password: &str) -> anyhow::Result<Self> {
        let salt = generate_random_vec(32);
        let vault_key = VaultKey::derive_from_password(password, &salt)?;
        let enc_key = vault_key.derive_encryption_key(b"vault-encryption");

        let cipher = Aes256Gcm::new_from_slice(&enc_key)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| anyhow::anyhow!(e))?;

        // AES-GCM returns ciphertext || auth_tag combined
        let (ciphertext, auth_tag) = ciphertext.split_at(ciphertext.len() - 16);

        Ok(Self {
            version: 1,
            salt: Base64::encode_string(&salt),
            nonce: Base64::encode_string(nonce.as_slice()),
            ciphertext: Base64::encode_string(ciphertext),
            auth_tag: Base64::encode_string(auth_tag),
        })
    }

    /// Decrypt vault data with master password
    pub fn decrypt(&self, password: &str) -> anyhow::Result<Vec<u8>> {
        let salt = Base64::decode_vec(&self.salt)?;
        let nonce = Base64::decode_vec(&self.nonce)?;
        let ciphertext = Base64::decode_vec(&self.ciphertext)?;
        let auth_tag = Base64::decode_vec(&self.auth_tag)?;

        // Combine ciphertext and auth_tag for AES-GCM
        let mut combined = ciphertext;
        combined.extend_from_slice(&auth_tag);

        let vault_key = VaultKey::derive_from_password(password, &salt)?;
        let enc_key = vault_key.derive_encryption_key(b"vault-encryption");

        let cipher = Aes256Gcm::new_from_slice(&enc_key)?;
        let nonce = Nonce::from_slice(&nonce);

        let plaintext = cipher.decrypt(nonce, combined.as_ref())
            .map_err(|_| anyhow::anyhow!("Decryption failed: invalid password or corrupted data"))?;

        Ok(plaintext)
    }

    /// Verify password without full decryption (for quick unlock check)
    pub fn verify_password(&self, password: &str) -> bool {
        self.decrypt(password).is_ok()
    }
}

/// Encrypt arbitrary data with the vault (master) password and serialize
/// to a self-contained JSON string, ready for a TEXT database column.
/// This is what actually protects private key material at rest — every
/// call to `seal` re-derives the key via Argon2id with a fresh random
/// salt, so it's deliberately not cheap; only call it for single-key
/// operations (generate/import/export/deploy), never in a list/loop.
pub fn seal(password: &str, data: &[u8]) -> anyhow::Result<String> {
    let enc = EncryptedVault::encrypt(data, password)?;
    Ok(serde_json::to_string(&enc)?)
}

/// Reverse of [`seal`].
pub fn unseal(password: &str, sealed: &str) -> anyhow::Result<Vec<u8>> {
    let enc: EncryptedVault = serde_json::from_str(sealed)
        .map_err(|e| anyhow::anyhow!("Corrupted vault entry: {e}"))?;
    enc.decrypt(password)
}