//! Vault encryption using AES-256-GCM
//! Replaces cryptoService.js AES-256-GCM implementation

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
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
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut hash)
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(Self(hash))
    }

    /// Derive encryption key from vault key using HKDF
    pub fn derive_encryption_key(&self, context: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hk.expand(context, &mut okm)
            .map_err(|e| anyhow::anyhow!(e))
            .expect("HKDF expand failed");
        okm
    }

    /// Derive authentication key from vault key using HKDF
    pub fn derive_auth_key(&self, context: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hk.expand(&[context, b"auth"].concat(), &mut okm)
            .map_err(|e| anyhow::anyhow!(e))
            .expect("HKDF expand failed");
        okm
    }
}

/// AES-256-GCM nonce length, in bytes. `Nonce::from_slice` panics on any
/// other length, so every decrypt path checks against this first.
const NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length, in bytes.
const TAG_LEN: usize = 16;

/// Encrypted vault data structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedVault {
    pub version: u32,
    pub salt: String,       // Base64 encoded
    pub nonce: String,      // Base64 encoded
    pub ciphertext: String, // Base64 encoded
    pub auth_tag: String,   // Base64 encoded (for verification)
}

impl EncryptedVault {
    /// Encrypt vault data with master password
    pub fn encrypt(data: &[u8], password: &str) -> anyhow::Result<Self> {
        let salt = generate_random_vec(32);
        let vault_key = VaultKey::derive_from_password(password, &salt)?;
        let enc_key = vault_key.derive_encryption_key(b"vault-encryption");

        let cipher = Aes256Gcm::new_from_slice(&enc_key)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| anyhow::anyhow!(e))?;

        // AES-GCM returns ciphertext || auth_tag combined
        let (ciphertext, auth_tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);

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

        // Validate the fixed-size fields BEFORE handing them to the cipher.
        // `Nonce::from_slice` PANICS on anything that is not exactly 12
        // bytes, and this blob can come from a file: vault_backup_restore
        // unseals whatever string a chosen backup carries, so a crafted (or
        // merely corrupted) file crashed the command instead of reporting a
        // bad backup. The Bitwarden parser next door validates every length
        // of a far less trusted input; the app's own format validated none.
        if nonce.len() != NONCE_LEN {
            anyhow::bail!(
                "Malformed vault blob: nonce is {} bytes, expected {NONCE_LEN}",
                nonce.len()
            );
        }
        if salt.is_empty() {
            anyhow::bail!("Malformed vault blob: empty salt");
        }
        // GCM needs at least its tag; a shorter combined buffer would be
        // rejected by the cipher anyway, but say so plainly.
        if auth_tag.len() != TAG_LEN {
            anyhow::bail!(
                "Malformed vault blob: auth tag is {} bytes, expected {TAG_LEN}",
                auth_tag.len()
            );
        }

        // Combine ciphertext and auth_tag for AES-GCM
        let mut combined = ciphertext;
        combined.extend_from_slice(&auth_tag);

        let vault_key = VaultKey::derive_from_password(password, &salt)?;
        let enc_key = vault_key.derive_encryption_key(b"vault-encryption");

        let cipher = Aes256Gcm::new_from_slice(&enc_key)?;
        let nonce = Nonce::from_slice(&nonce);

        let plaintext = cipher.decrypt(nonce, combined.as_ref()).map_err(|_| {
            anyhow::anyhow!("Decryption failed: invalid password or corrupted data")
        })?;

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
    let enc: EncryptedVault =
        serde_json::from_str(sealed).map_err(|e| anyhow::anyhow!("Corrupted vault entry: {e}"))?;
    enc.decrypt(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blob whose fixed-size fields are the wrong length must come back as
    /// an error, not a panic. `vault_backup_restore` unseals whatever a
    /// user-chosen backup file contains, so this is reachable from outside.
    #[test]
    fn malformed_blob_lengths_are_rejected_not_panicked_on() {
        let blob = |nonce_len: usize, tag_len: usize, salt_len: usize| {
            serde_json::json!({
                "version": 1,
                "salt": Base64::encode_string(&vec![0u8; salt_len]),
                "nonce": Base64::encode_string(&vec![0u8; nonce_len]),
                "ciphertext": Base64::encode_string(&[0u8; 8]),
                "auth_tag": Base64::encode_string(&vec![0u8; tag_len]),
            })
            .to_string()
        };
        for (n, t, s, what) in [
            (4, TAG_LEN, 32, "short nonce"),
            (0, TAG_LEN, 32, "empty nonce"),
            (32, TAG_LEN, 32, "long nonce"),
            (NONCE_LEN, 4, 32, "short auth tag"),
            (NONCE_LEN, TAG_LEN, 0, "empty salt"),
        ] {
            let err =
                unseal("pw", &blob(n, t, s)).expect_err(&format!("{what} should be rejected"));
            assert!(
                err.to_string().contains("Malformed vault blob"),
                "{what}: unexpected error {err}"
            );
        }
    }

    /// The happy path still round-trips, so the new checks are not rejecting
    /// blobs this code writes itself.
    #[test]
    fn seal_unseal_round_trips() {
        let sealed = seal("correct horse", b"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap();
        assert_eq!(
            unseal("correct horse", &sealed).unwrap(),
            b"-----BEGIN OPENSSH PRIVATE KEY-----"
        );
        assert!(unseal("wrong", &sealed).is_err());
    }
}
