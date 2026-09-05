//! Bitwarden client — 1:1 port of bitwardenClient.js
//!
//! Password-based auth via the standard Bitwarden API:
//!   POST /identity/accounts/prelogin  → KDF parameters
//!   POST /identity/connect/token      → access + refresh token (password grant)
//!   GET  /api/sync                    → profile.key, folders, ciphers
//!   POST /api/folders                 → create the sync folder
//!   POST /api/ciphers                 → create an item
//!   PUT  /api/ciphers/{id}            → update an item
//!
//! Also includes the SSRF guard (see ssrf.rs) and the two-way sync service.

pub mod ssrf;
pub mod sync;

use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use base64ct::Base64;

use crate::crypto::bitwarden::{self, KdfParams};
use crate::bitwarden::ssrf::resolve_safe_server_url;

const REQUEST_TIMEOUT_MS: u64 = 30_000;
const CLIENT_ID: &str = "cli";        // first-party client id
const DEVICE_TYPE: &str = "14";       // SDK

// ─── Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    #[serde(default)]
    pub profile: Option<SyncProfile>,
    #[serde(default)]
    pub folders: Vec<SyncFolder>,
    #[serde(default)]
    pub ciphers: Vec<SyncCipher>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProfile {
    pub email: Option<String>,
    pub name: Option<String>,
    pub key: Option<String>,  // encrypted user key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncFolder {
    pub id: String,
    pub name: Option<String>, // encrypted
    #[serde(rename = "revisionDate", default)]
    pub revision_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCipher {
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: u32,
    #[serde(rename = "organizationId", default)]
    pub organization_id: Option<String>,
    #[serde(rename = "folderId", default)]
    pub folder_id: Option<String>,
    pub name: Option<String>, // encrypted
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(rename = "sshKey", default)]
    pub ssh_key: Option<SshKeyBlock>,
    #[serde(rename = "revisionDate", default)]
    pub revision_date: Option<String>,
    #[serde(rename = "deletedDate", default)]
    pub deleted_date: Option<String>,
    #[serde(rename = "creationDate", default)]
    pub creation_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyBlock {
    #[serde(rename = "privateKey", default)]
    pub private_key: Option<String>, // encrypted
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<String>,  // encrypted
    #[serde(rename = "keyFingerprint", default)]
    pub key_fingerprint: Option<String>, // encrypted
}

// ─── BitwardenClient ────────────────────────────────────────────────────

pub struct BitwardenClient {
    http: HttpClient,
    pub base_url: String,
    server_url: String,
    email: String,
    master_password: String,
    device_id: String,
    pub access_token: Option<String>,
    refresh_token: Option<String>,
    token_expires_at: u64,
    pub master_key: Option<[u8; 32]>,
    pub stretched_key: Option<[u8; 64]>,
    pub user_key: Option<[u8; 64]>,
}

impl BitwardenClient {
    pub fn new(
        server_url: &str,
        email: &str,
        master_password: &str,
        device_id: &str,
    ) -> Result<Self> {
        let http = HttpClient::builder()
            .timeout(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS))
            .build()?;

        Ok(Self {
            http,
            base_url: String::new(),
            server_url: server_url.to_string(),
            email: email.to_string(),
            master_password: master_password.to_string(),
            device_id: device_id.to_string(),
            access_token: None,
            refresh_token: None,
            token_expires_at: 0,
            master_key: None,
            stretched_key: None,
            user_key: None,
        })
    }

    /// Validate URL (incl. DNS), derive the master key, and authenticate.
    /// Returns the prelogin KDF config used.
    pub async fn connect(&mut self) -> Result<KdfParams> {
        self.base_url = resolve_safe_server_url(&self.server_url)?;
        if !self.email.contains('@') {
            anyhow::bail!("A valid account email is required.");
        }
        if self.master_password.is_empty() {
            anyhow::bail!("The vault master password is required.");
        }

        let kdf = self.prelogin().await?;
        self.master_key = Some(bitwarden::derive_master_key(
            &self.master_password, &self.email, &kdf,
        )?);
        self.stretched_key = Some(bitwarden::stretch_master_key(self.master_key.as_ref().unwrap()));
        self.login_with_password().await?;
        Ok(kdf)
    }

    async fn prelogin(&self) -> Result<KdfParams> {
        let url = format!("{}/identity/accounts/prelogin", self.base_url);
        let resp = self.http.post(&url)
            .json(&serde_json::json!({ "email": self.email }))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Server prelogin failed (HTTP {}).", resp.status());
        }
        // Read the body tolerantly and pick only the fields we need — PBKDF2
        // accounts send kdfMemory/kdfParallelism as explicit null.
        let data: serde_json::Value = resp.json().await?;
        let num = |k: &str| data.get(k).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        Ok(KdfParams {
            kdf_type: num("kdf"),
            iterations: num("kdfIterations"),
            memory: num("kdfMemory"),
            parallelism: num("kdfParallelism"),
        })
    }

    async fn token_request(&mut self, body: &[(&str, &str)]) -> Result<()> {
        let url = format!("{}/identity/connect/token", self.base_url);
        let resp = self.http.post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(body)
            .send()
            .await?;

        // Read the body tolerantly first — a failed login returns a JSON
        // error page that must not crash decoding. Non-JSON bodies are fine.
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let data: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);

        if !status.is_success() {
            if data.get("TwoFactorProviders").map_or(false, |v| !v.is_null()) {
                anyhow::bail!(
                    "This account has two-factor login enabled, which SSHSpan does not support yet. \
                     Use a dedicated account without 2FA for the sync."
                );
            }
            let detail = data.get("error_description").and_then(|v| v.as_str())
                .or_else(|| data.get("error").and_then(|v| v.as_str()))
                .unwrap_or("");
            let suffix = if detail.is_empty() {
                format!(" (HTTP {}).", status)
            } else {
                format!(": {}", detail)
            };
            anyhow::bail!("Vault login failed{} Check the server URL, account email and master password.", suffix);
        }

        self.access_token = Some(
            data.get("access_token").and_then(|v| v.as_str()).map(String::from)
                .ok_or_else(|| anyhow::anyhow!("Token response did not include an access token."))?
        );
        let token_preview = self.access_token.as_ref().map(|t| {
            let parts: Vec<&str> = t.split('.').collect();
            if parts.len() >= 2 {
                format!("{}...{} ({} chars total)", &parts[0][..10.min(parts[0].len())], &parts[parts.len()-1][parts[parts.len()-1].len()-8..], t.len())
            } else {
                format!("{} chars", t.len())
            }
        }).unwrap_or_default();
        eprintln!("token: {token_preview}");
        self.refresh_token = data.get("refresh_token").and_then(|v| v.as_str()).map(String::from);
        let expires_in = data.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(3600);
        self.token_expires_at = now_millis() + expires_in * 1000 - 60_000;
        Ok(())
    }

    async fn login_with_password(&mut self) -> Result<()> {
        let master_key = *self.master_key.as_ref().unwrap();
        let hash = bitwarden::master_password_hash(&master_key, &self.master_password);
        let email = self.email.clone();
        let device_id = self.device_id.clone();

        self.token_request(&[
            ("grant_type", "password"),
            ("username", &email),
            ("password", &hash),
            ("scope", "api offline_access"),
            ("client_id", CLIENT_ID),
            ("deviceType", DEVICE_TYPE),
            ("deviceIdentifier", &device_id),
            ("deviceName", "SSHSpan"),
        ]).await
    }

    async fn ensure_token(&mut self) -> Result<()> {
        if self.access_token.is_none() {
            anyhow::bail!("Not logged in.");
        }
        if now_millis() < self.token_expires_at {
            return Ok(());
        }
        let refresh = match self.refresh_token.take() {
            Some(r) => r,
            None => anyhow::bail!("Session expired and no refresh token is available."),
        };
        match self.token_request(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", CLIENT_ID),
        ]).await {
            Ok(()) => Ok(()),
            Err(_) => {
                self.access_token = None;
                anyhow::bail!("Session expired and could not be refreshed. Sync again to re-authenticate.");
            }
        }
    }

    /// Authenticated /api request with one transparent token-refresh retry.
    async fn api_request(&mut self, method: &str, path: &str, body: Option<&serde_json::Value>) -> Result<serde_json::Value> {
        for attempt in 0..2u32 {
            self.ensure_token().await?;
            let url = format!("{}{}", self.base_url, path);
            let token = self.access_token.clone().unwrap_or_default();
            let mut req = self.http.request(
                method.parse().unwrap(),
                &url,
            ).header("Authorization", format!("Bearer {token}"))
             .header("Content-Type", "application/json")
             .header("Bitwarden-Client-Version", "2024.12.0");

            if let Some(body) = body {
                req = req.json(body);
            }

            let resp = req.send().await?;
            if resp.status().as_u16() == 401 && attempt == 0 {
                self.token_expires_at = 0; // force refresh
                continue;
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let detail = resp.text().await.unwrap_or_default();
                anyhow::bail!("Vault request {method} {path} failed (HTTP {status}): {detail}");
            }
            return resp.json().await.map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"));
        }
        anyhow::bail!("Vault request failed after token refresh.");
    }

    /// Full vault sync; decrypts the account user key and folder names.
    pub async fn sync(&mut self) -> Result<SyncResponse> {
        let data = self.api_request("GET", "/api/sync", None).await?;
        let profile = data.get("profile").and_then(|p| p.as_object());

        // Decrypt user key from profile
        if let Some(profile_key) = profile.and_then(|p| p.get("key")).and_then(|k| k.as_str()) {
            let stretched = *self.stretched_key.as_ref().unwrap();
            let user_key_bytes = bitwarden::decrypt_to_bytes(profile_key, &stretched)?;

            match user_key_bytes.len() {
                64 => {
                    // Modern v1 user key: raw enc(32) || mac(32).
                    let mut uk = [0u8; 64];
                    uk.copy_from_slice(&user_key_bytes);
                    self.user_key = Some(uk);
                }
                88 => {
                    // Legacy: the 64-byte key stored as base64 text.
                    use base64ct::Encoding;
                    let text = std::str::from_utf8(&user_key_bytes)
                        .map_err(|_| anyhow::anyhow!("Account key is not valid UTF-8"))?;
                    let decoded = Base64::decode_vec(text.trim())
                        .map_err(|_| anyhow::anyhow!("Account key base64 decode failed"))?;
                    if decoded.len() != 64 {
                        anyhow::bail!("Account key decoded to an unexpected length ({}).", decoded.len());
                    }
                    let mut uk = [0u8; 64];
                    uk.copy_from_slice(&decoded);
                    self.user_key = Some(uk);
                }
                other => {
                    // Diagnostics: dump the full plaintext so an unknown
                    // account-key format can be identified precisely.
                    let full_hex: String = user_key_bytes.iter()
                        .map(|b| format!("{b:02x}")).collect();
                    let printable = user_key_bytes.iter().take(96)
                        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'=');
                    let last_byte = *user_key_bytes.last().unwrap_or(&0);
                    anyhow::bail!(
                        "Unsupported account key format (length {}) hex={} ascii={} last_byte={}",
                        other, full_hex, printable, last_byte
                    );
                }
            }
        } else {
            anyhow::bail!("The account profile has no encryption key (Key Connector accounts are not supported).");
        }

        // Decrypt folder names
        let user_key = self.user_key.as_ref().unwrap();
        let mut folders = Vec::new();
        for f in data.get("folders").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let id = f.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name_enc = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let name = self.decrypt_field_inner(name_enc, user_key).unwrap_or_default();
            let revision_date = f.get("revisionDate").and_then(|v| v.as_str()).map(String::from);
            folders.push(SyncFolder { id, name: Some(name), revision_date });
        }

        let ciphers_raw = data.get("ciphers").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let mut ciphers = Vec::with_capacity(ciphers_raw.len());
        for (i, c) in ciphers_raw.into_iter().enumerate() {
            match serde_json::from_value::<SyncCipher>(c) {
                Ok(cipher) => ciphers.push(cipher),
                Err(e) => eprintln!("sync: skipped cipher at index {i}: {e}"),
            }
        }

        let profile_out = data.get("profile").and_then(|p| {
            Some(SyncProfile {
                email: p.get("email").and_then(|v| v.as_str()).map(String::from),
                name: p.get("name").and_then(|v| v.as_str()).map(String::from),
                key: None, // don't expose encrypted key
            })
        }).unwrap_or(SyncProfile { email: Some(self.email.clone()), name: None, key: None });

        Ok(SyncResponse { profile: Some(profile_out), folders, ciphers })
    }

    /// Decrypt an encrypted field string with the user key.
    pub fn decrypt_field(&self, enc_string: &str) -> Result<String> {
        let user_key = self.user_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not logged in (no user key)"))?;
        self.decrypt_field_inner(enc_string, user_key)
    }

    fn decrypt_field_inner(&self, enc_string: &str, user_key: &[u8; 64]) -> Result<String> {
        bitwarden::decrypt_string(enc_string, user_key)
    }

    /// Encrypt a plaintext string with the user key.
    pub fn encrypt_field(&self, plaintext: &str) -> Result<String> {
        let user_key = self.user_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not logged in (no user key)"))?;
        bitwarden::encrypt_string(plaintext, user_key)
    }

    pub async fn create_folder(&mut self, name: &str) -> Result<serde_json::Value> {
        let encrypted_name = self.encrypt_field(name)?;
        self.api_request("POST", "/api/folders", Some(&serde_json::json!({
            "name": encrypted_name
        }))).await
    }

    pub async fn create_cipher(&mut self, cipher: &serde_json::Value) -> Result<serde_json::Value> {
        self.api_request("POST", "/api/ciphers", Some(cipher)).await
    }

    pub async fn update_cipher(&mut self, id: &str, cipher: &serde_json::Value) -> Result<serde_json::Value> {
        let path = format!("/api/ciphers/{}", urlencoding::encode(id));
        self.api_request("PUT", &path, Some(cipher)).await
    }

    pub fn close(&mut self) {
        self.access_token = None;
        self.refresh_token = None;
        self.master_key = None;
        self.stretched_key = None;
        self.user_key = None;
    }
}

/// Best-effort anonymous server probe used by "Test connection".
pub async fn probe_server_version(base_url: &str) -> Option<String> {
    let client = HttpClient::builder()
        .timeout(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS))
        .build()
        .ok()?;
    let url = format!("{}/api/config", base_url);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() { return None; }
    let data: serde_json::Value = resp.json().await.ok()?;
    data.get("version").and_then(|v| v.as_str()).map(String::from)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
