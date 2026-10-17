//! Bitwarden client - 1:1 port of bitwardenClient.js
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

use anyhow::Result;
use base64ct::Base64;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};

use crate::bitwarden::ssrf::resolve_safe_server_url;
use crate::crypto::bitwarden::{self, KdfParams};

const REQUEST_TIMEOUT_MS: u64 = 30_000;
/// Hard cap on any single response body. A malicious or misbehaving vault
/// server could otherwise stream an unbounded body into memory and OOM the
/// app (`resp.json()` / `resp.text()` read everything). 50 MB is orders of
/// magnitude above what any Bitwarden identity/API endpoint legitimately
/// returns (a full vault sync is typically well under a few MB).
const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;
const CLIENT_ID: &str = "cli"; // first-party client id
const DEVICE_TYPE: &str = "14"; // SDK

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
    pub key: Option<String>, // encrypted user key
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
    #[serde(default)]
    pub login: Option<LoginBlock>,
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
    pub public_key: Option<String>, // encrypted
    #[serde(rename = "keyFingerprint", default)]
    pub key_fingerprint: Option<String>, // encrypted
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginUri {
    pub uri: Option<String>, // encrypted
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginBlock {
    #[serde(default)]
    pub username: Option<String>, // encrypted
    #[serde(default)]
    pub password: Option<String>, // encrypted
    #[serde(rename = "uris", default)]
    pub uris: Option<Vec<LoginUri>>,
}

// ─── BitwardenClient ────────────────────────────────────────────────────

pub struct BitwardenClient {
    http: HttpClient,
    pub base_url: String,
    server_url: String,
    email: String,
    master_password: zeroize::Zeroizing<String>,
    device_id: String,
    pub access_token: Option<zeroize::Zeroizing<String>>,
    refresh_token: Option<zeroize::Zeroizing<String>>,
    token_expires_at: u64,
    pub master_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    pub stretched_key: Option<zeroize::Zeroizing<[u8; 64]>>,
    pub user_key: Option<zeroize::Zeroizing<[u8; 64]>>,
}

impl Drop for BitwardenClient {
    fn drop(&mut self) {
        // Clear every in-memory secret when the client is dropped: master
        // key, stretched key, user key, access/refresh tokens. The master
        // password is zeroized by its own `Zeroizing` wrapper on drop;
        // replacing it here also covers the still-live client during drop.
        // This mirrors the `Zeroize`/`ZeroizeOnDrop` pattern used by the
        // vault/master-password code (see crypto/vault.rs).
        self.close();
    }
}

impl BitwardenClient {
    pub fn new(
        server_url: &str,
        email: &str,
        master_password: &str,
        device_id: &str,
    ) -> Result<Self> {
        // SSRF hardening: never follow redirects. resolve_safe_server_url()
        // validates the initial URL (scheme, no userinfo, DNS resolution,
        // no private/link-local/loopback targets), but reqwest's default
        // policy silently follows up to 20 redirects - a malicious or
        // compromised vault server could 302 to http://169.254.169.254/
        // or http://127.0.0.1/ and the client would follow it, leaking the
        // Bearer token and request body to an internal target. The official
        // Bitwarden identity/API endpoints do not redirect in normal
        // operation, so any 3xx here is treated as an error instead.
        // DNS rebinding (TOCTOU) fix: resolve_safe_server_url() validates the
        // DNS answer at check time, but reqwest re-resolves at connect time.
        // The guarded resolver applies the same private/reserved-address
        // filtering at connect time, so a rebound DNS answer pointing at an
        // internal host can never be dialed (see ssrf.rs).
        let http = HttpClient::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS))
            .dns_resolver(ssrf::guarded_resolver())
            // Explicit rather than implied: Cargo.toml already removes the
            // native-tls backend, and this makes a re-added `default-tls`
            // feature a compile error here instead of a silent switch back
            // to OpenSSL.
            .use_rustls_tls()
            .build()?;

        Ok(Self {
            http,
            base_url: String::new(),
            server_url: server_url.to_string(),
            email: email.to_string(),
            master_password: zeroize::Zeroizing::new(master_password.to_string()),
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
        let result = self.connect_inner().await;
        if result.is_err() {
            // Never leave the raw master password in memory on a failed connect.
            self.master_password = zeroize::Zeroizing::new(String::new());
        }
        result
    }

    async fn connect_inner(&mut self) -> Result<KdfParams> {
        // The URL check resolves the host with the system resolver, which
        // blocks: run it on the blocking pool, not on an async worker (A7-48).
        let server_url = self.server_url.clone();
        self.base_url =
            tokio::task::spawn_blocking(move || resolve_safe_server_url(&server_url)).await??;
        if !self.email.contains('@') {
            anyhow::bail!("A valid account email is required.");
        }
        if self.master_password.is_empty() {
            anyhow::bail!("The vault master password is required.");
        }

        let kdf = self.prelogin().await?;
        self.master_key =
            Some(master_key_off_thread(&self.master_password, &self.email, &kdf).await?);
        self.stretched_key = Some(zeroize::Zeroizing::new(bitwarden::stretch_master_key(
            self.master_key.as_ref().unwrap(),
        )));
        self.login_with_password().await?;
        Ok(kdf)
    }

    async fn prelogin(&self) -> Result<KdfParams> {
        let url = format!("{}/identity/accounts/prelogin", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "email": self.email }))
            .send()
            .await?;

        reject_redirect(resp.status())?;
        if !resp.status().is_success() {
            anyhow::bail!("Server prelogin failed (HTTP {}).", resp.status());
        }
        // Read the body tolerantly and pick only the fields we need.
        let data: serde_json::Value = read_body_capped_json(resp).await?;
        kdf_from_prelogin(&data)
    }

    async fn token_request(&mut self, body: &[(&str, &str)]) -> Result<()> {
        let url = format!("{}/identity/connect/token", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(body)
            .send()
            .await?;

        reject_redirect(resp.status())?;

        // Read the body tolerantly first - a failed login returns a JSON
        // error page that must not crash decoding. Non-JSON bodies are fine.
        let status = resp.status();
        let text = read_body_capped_text(resp).await.unwrap_or_default();
        let data: serde_json::Value =
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);

        if !status.is_success() {
            anyhow::bail!("{}", login_failure_message(status, &data));
        }

        self.access_token = Some(zeroize::Zeroizing::new(
            data.get("access_token")
                .and_then(|v| v.as_str())
                .map(String::from)
                .ok_or_else(|| {
                    anyhow::anyhow!("Token response did not include an access token.")
                })?,
        ));
        self.refresh_token = data
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(|s| zeroize::Zeroizing::new(s.to_string()));
        let expires_in = data
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        self.token_expires_at = now_millis() + expires_in * 1000 - 60_000;
        Ok(())
    }

    async fn login_with_password(&mut self) -> Result<()> {
        let master_key = **self.master_key.as_ref().unwrap();
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
        ])
        .await
    }

    async fn ensure_token(&mut self) -> Result<()> {
        if self.access_token.is_none() {
            anyhow::bail!("Not logged in.");
        }
        if now_millis() < self.token_expires_at {
            return Ok(());
        }
        // Don't consume the refresh token until the request succeeds: a
        // transient network failure must not lock the user out of the vault.
        // token_request() only overwrites refresh_token on success, so on
        // failure the old token stays in place and the next sync retries.
        let refresh = match self.refresh_token.clone() {
            Some(r) => r,
            None => anyhow::bail!("Session expired and no refresh token is available."),
        };
        match self
            .token_request(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", CLIENT_ID),
            ])
            .await
        {
            Ok(()) => Ok(()),
            Err(_) => {
                self.access_token = None;
                anyhow::bail!(
                    "Session expired and could not be refreshed. Sync again to re-authenticate."
                );
            }
        }
    }

    /// Authenticated /api request with one transparent token-refresh retry.
    async fn api_request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        for attempt in 0..2u32 {
            self.ensure_token().await?;
            let url = format!("{}{}", self.base_url, path);
            let token = self
                .access_token
                .as_ref()
                .map(|t| t.as_str().to_string())
                .unwrap_or_default();
            let mut req = self
                .http
                .request(method.parse().unwrap(), &url)
                .header("Authorization", format!("Bearer {token}"))
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
            reject_redirect(resp.status())?;
            if !resp.status().is_success() {
                let status = resp.status();
                let detail = error_detail(&read_body_capped_text(resp).await.unwrap_or_default());
                anyhow::bail!("Vault request {method} {path} failed (HTTP {status}): {detail}");
            }
            return read_body_capped_json(resp).await;
        }
        anyhow::bail!("Vault request failed after token refresh.");
    }

    /// Full vault sync; decrypts the account user key and folder names.
    pub async fn sync(&mut self) -> Result<SyncResponse> {
        let data = self.api_request("GET", "/api/sync", None).await?;
        let profile = data.get("profile").and_then(|p| p.as_object());

        // Decrypt user key from profile
        if let Some(profile_key) = profile.and_then(|p| p.get("key")).and_then(|k| k.as_str()) {
            let stretched = **self.stretched_key.as_ref().unwrap();
            let user_key_bytes = bitwarden::decrypt_to_bytes(profile_key, &stretched)?;

            match user_key_bytes.len() {
                64 => {
                    // Modern v1 user key: raw enc(32) || mac(32).
                    let mut uk = [0u8; 64];
                    uk.copy_from_slice(&user_key_bytes);
                    self.user_key = Some(zeroize::Zeroizing::new(uk));
                }
                88 => {
                    // Legacy: the 64-byte key stored as base64 text.
                    use base64ct::Encoding;
                    let text = std::str::from_utf8(&user_key_bytes)
                        .map_err(|_| anyhow::anyhow!("Account key is not valid UTF-8"))?;
                    let decoded = Base64::decode_vec(text.trim())
                        .map_err(|_| anyhow::anyhow!("Account key base64 decode failed"))?;
                    if decoded.len() != 64 {
                        anyhow::bail!(
                            "Account key decoded to an unexpected length ({}).",
                            decoded.len()
                        );
                    }
                    let mut uk = [0u8; 64];
                    uk.copy_from_slice(&decoded);
                    self.user_key = Some(zeroize::Zeroizing::new(uk));
                }
                other => {
                    // Diagnostics must NOT include the key material itself -
                    // report only the length and a short non-reversible digest.
                    use sha2::{Digest, Sha256};
                    let digest = Sha256::digest(&user_key_bytes);
                    let digest_prefix: String =
                        digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
                    let printable = user_key_bytes
                        .iter()
                        .take(96)
                        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'=');
                    let last_byte = *user_key_bytes.last().unwrap_or(&0);
                    anyhow::bail!(
                        "Unsupported account key format (length {}) sha256_prefix={} ascii={} last_byte={}",
                        other,
                        digest_prefix,
                        printable,
                        last_byte
                    );
                }
            }
        } else {
            anyhow::bail!("The account profile has no encryption key (Key Connector accounts are not supported).");
        }

        // Decrypt folder names
        let user_key = **self.user_key.as_ref().unwrap();
        let mut folders = Vec::new();
        for f in data
            .get("folders")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let id = f
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name_enc = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let name = self
                .decrypt_field_inner(name_enc, &user_key)
                .unwrap_or_default();
            let revision_date = f
                .get("revisionDate")
                .and_then(|v| v.as_str())
                .map(String::from);
            folders.push(SyncFolder {
                id,
                name: Some(name),
                revision_date,
            });
        }

        let ciphers_raw = data
            .get("ciphers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut ciphers = Vec::with_capacity(ciphers_raw.len());
        for (i, c) in ciphers_raw.into_iter().enumerate() {
            match serde_json::from_value::<SyncCipher>(c) {
                Ok(cipher) => ciphers.push(cipher),
                Err(e) => eprintln!("sync: skipped cipher at index {i}: {e}"),
            }
        }

        let profile_out = data
            .get("profile")
            .and_then(|p| {
                Some(SyncProfile {
                    email: p.get("email").and_then(|v| v.as_str()).map(String::from),
                    name: p.get("name").and_then(|v| v.as_str()).map(String::from),
                    key: None, // don't expose encrypted key
                })
            })
            .unwrap_or(SyncProfile {
                email: Some(self.email.clone()),
                name: None,
                key: None,
            });

        Ok(SyncResponse {
            profile: Some(profile_out),
            folders,
            ciphers,
        })
    }

    /// Decrypt an encrypted field string with the user key.
    pub fn decrypt_field(&self, enc_string: &str) -> Result<String> {
        let user_key = self
            .user_key
            .as_ref()
            .map(|k| **k)
            .ok_or_else(|| anyhow::anyhow!("Not logged in (no user key)"))?;
        self.decrypt_field_inner(enc_string, &user_key)
    }

    fn decrypt_field_inner(&self, enc_string: &str, user_key: &[u8; 64]) -> Result<String> {
        bitwarden::decrypt_string(enc_string, user_key)
    }

    /// Encrypt a plaintext string with the user key.
    pub fn encrypt_field(&self, plaintext: &str) -> Result<String> {
        let user_key = self
            .user_key
            .as_ref()
            .map(|k| **k)
            .ok_or_else(|| anyhow::anyhow!("Not logged in (no user key)"))?;
        bitwarden::encrypt_string(plaintext, &user_key)
    }

    pub async fn create_folder(&mut self, name: &str) -> Result<serde_json::Value> {
        let encrypted_name = self.encrypt_field(name)?;
        self.api_request(
            "POST",
            "/api/folders",
            Some(&serde_json::json!({
                "name": encrypted_name
            })),
        )
        .await
    }

    pub async fn update_folder(&mut self, id: &str, name: &str) -> Result<serde_json::Value> {
        let encrypted_name = self.encrypt_field(name)?;
        let path = format!("/api/folders/{}", urlencoding::encode(id));
        self.api_request(
            "PUT",
            &path,
            Some(&serde_json::json!({
                "name": encrypted_name
            })),
        )
        .await
    }

    pub async fn create_cipher(&mut self, cipher: &serde_json::Value) -> Result<serde_json::Value> {
        self.api_request("POST", "/api/ciphers", Some(cipher)).await
    }

    pub async fn update_cipher(
        &mut self,
        id: &str,
        cipher: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = format!("/api/ciphers/{}", urlencoding::encode(id));
        self.api_request("PUT", &path, Some(cipher)).await
    }

    /// Wipe every in-memory secret: keys and tokens are zeroized in place
    /// (the `Some(...)` stays, but the contents are all-zero), and the master
    /// password is replaced, dropping (and thereby zeroizing) the old value.
    pub fn close(&mut self) {
        use zeroize::Zeroize;
        if let Some(t) = self.access_token.as_mut() {
            t.zeroize();
        }
        if let Some(t) = self.refresh_token.as_mut() {
            t.zeroize();
        }
        if let Some(k) = self.master_key.as_mut() {
            k.zeroize();
        }
        if let Some(k) = self.stretched_key.as_mut() {
            k.zeroize();
        }
        if let Some(k) = self.user_key.as_mut() {
            k.zeroize();
        }
        self.master_password = zeroize::Zeroizing::new(String::new());
    }
}

/// What `bitwarden_get_config` shows the renderer: the saved settings and the
/// last result, and whether a master password is stored - never the sealed
/// password itself. Without `hasMasterPassword` the form showed an empty
/// field after Save and a missing password only surfaced at the next sync
/// (A5-35).
pub fn config_view(config: &crate::db::BitwardenConfig) -> serde_json::Value {
    serde_json::json!({
        "server_url": config.server_url,
        "email": config.email,
        "folder_name": config.folder_name,
        "servers_folder_name": config.servers_folder_name,
        "last_sync": config.last_sync.map(|d| d.to_rfc3339()),
        "last_result": config
            .last_result
            .as_ref()
            .and_then(|r| serde_json::from_str::<serde_json::Value>(r).ok()),
        "hasMasterPassword": config
            .master_password
            .as_deref()
            .is_some_and(|sealed| !sealed.is_empty()),
        // The stored destination is the one the user allowed to receive
        // uploads (false also when none is stored).
        "confirmed": config.confirmed(),
    })
}

/// The account `bitwarden_test_connection` logs in to.
pub struct TestTarget {
    pub server_url: String,
    pub email: String,
    pub master_password: zeroize::Zeroizing<String>,
}

/// Whether two account emails name the same account (trimmed, case-folded).
fn same_account(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

/// Whether `server_url` (already normalized) and `email` are the saved ones -
/// the only server and account the SAVED master password may be sent to.
fn is_saved_endpoint(saved: &crate::db::BitwardenConfig, server_url: &str, email: &str) -> bool {
    saved.server_url.as_deref() == Some(server_url)
        && saved
            .email
            .as_deref()
            .is_some_and(|saved_email| same_account(saved_email, email))
}

/// The account to test: each field as typed into the form when it was given
/// (not blank), the saved setting otherwise (A2-52). "Test connection" used
/// to read only the saved settings, so testing a form before saving it
/// failed, and testing an edited URL reported success for the OLD server.
/// `normalize_url` is the save-time URL check (`resolve_safe_server_url`), so
/// the server compared and returned is the normalized one. The saved password
/// is unsealed (`unseal_saved`) only when no password was typed AND the server
/// and account are the saved ones: a compromised renderer must not be able to
/// send the saved master password's hash to a server of its choosing.
pub fn resolve_test_target(
    saved: &crate::db::BitwardenConfig,
    server_url: Option<String>,
    email: Option<String>,
    master_password: Option<zeroize::Zeroizing<String>>,
    normalize_url: impl Fn(&str) -> std::result::Result<String, String>,
    unseal_saved: impl FnOnce(&str) -> std::result::Result<zeroize::Zeroizing<String>, String>,
) -> std::result::Result<TestTarget, String> {
    let given = |value: Option<String>| {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let server_url = given(server_url)
        .or_else(|| given(saved.server_url.clone()))
        .ok_or_else(|| "Enter the server URL to test the connection.".to_string())?;
    let server_url = normalize_url(&server_url)?;
    let email = given(email)
        .or_else(|| given(saved.email.clone()))
        .ok_or_else(|| "Enter the account email to test the connection.".to_string())?;
    let master_password = match master_password.filter(|pw| !pw.is_empty()) {
        Some(typed) => typed,
        None => {
            let sealed = saved
                .master_password
                .as_deref()
                .filter(|sealed| !sealed.is_empty())
                .ok_or_else(|| {
                    "Enter the vault master password to test the connection.".to_string()
                })?;
            if !is_saved_endpoint(saved, &server_url, &email) {
                return Err(
                    "Enter the vault master password to test a different server or account.".into(),
                );
            }
            unseal_saved(sealed)?
        }
    };
    Ok(TestTarget {
        server_url,
        email,
        master_password,
    })
}

/// Whether saving these settings without a new password may keep the stored
/// one: only for the same server and account. A changed URL or email
/// with no new password is refused - the old password is never kept for a
/// different endpoint, and dropping it silently would surprise the user at
/// the next sync. `server_url` is normalized.
pub fn check_save_keeps_password(
    saved: &crate::db::BitwardenConfig,
    server_url: &str,
    email: &str,
    new_password_given: bool,
) -> std::result::Result<(), String> {
    let has_stored = saved
        .master_password
        .as_deref()
        .is_some_and(|sealed| !sealed.is_empty());
    if new_password_given || !has_stored || is_saved_endpoint(saved, server_url, email) {
        Ok(())
    } else {
        Err("Enter the master password for the new server or account.".into())
    }
}

/// The error for a refused login (`token_request`), from the status and the
/// server's JSON answer. The server's text is cut like every other vault
/// error detail ([`error_detail`]); it used to be quoted whole.
fn login_failure_message(status: reqwest::StatusCode, data: &serde_json::Value) -> String {
    if data
        .get("TwoFactorProviders")
        .map_or(false, |v| !v.is_null())
    {
        return "This account has two-factor login enabled, which SSHSpan does not support yet. \
                Use a dedicated account without 2FA for the sync."
            .to_string();
    }
    let detail = data
        .get("error_description")
        .and_then(|v| v.as_str())
        .or_else(|| data.get("error").and_then(|v| v.as_str()))
        .unwrap_or("");
    let suffix = if detail.is_empty() {
        format!(" (HTTP {}).", status)
    } else {
        format!(": {}", error_detail(detail))
    };
    format!("Vault login failed{suffix} Check the server URL, account email and master password.")
}

/// What a sync-settings save writes: the URL (already normalized by the
/// save-time check), the account email, a newly sealed master password
/// (`None` = keep the stored one) and the folder names.
pub struct BitwardenSave {
    pub server_url: String,
    pub email: String,
    pub sealed_password: Option<String>,
    pub folder_name: String,
    pub servers_folder_name: String,
}

/// What a sync-settings save refuses when the account is not one email
/// address ([`bitwarden_account`]).
pub(crate) const ACCOUNT_NOT_ONE_EMAIL: &str =
    "Enter the Bitwarden account as one email address, like name@example.com.";

/// Longest account a sync-settings save accepts, in characters: the longest
/// email address.
const MAX_ACCOUNT_CHARS: usize = 254;

/// Characters an email address of a Bitwarden account never needs: they
/// quote, comment, group or separate - and in the question and the refusal
/// that name the account, they could make free text read as part of it.
const ACCOUNT_PUNCTUATION: &str = "()<>[]\"',;:\\";

/// The account of a sync-settings save, checked and trimmed: one email
/// address - one token of at most [`MAX_ACCOUNT_CHARS`] characters, exactly
/// one "@" between a local part and a domain, and no whitespace, control,
/// format or direction character or [`ACCOUNT_PUNCTUATION`]. The account is
/// named in the native question and in the sync's refusal, and only an "@"
/// was required: an "account" of free text added words to what the user was
/// asked ("... (me@example.com) only to check the connection - nothing is
/// uploaded until you press Sync now (ok) when it syncs. Allow?").
pub(crate) fn bitwarden_account(email: &str) -> std::result::Result<String, String> {
    let account = email.trim();
    let one_token = account.chars().all(|c| {
        !c.is_whitespace()
            && !c.is_control()
            && !crate::assistant::is_disguising(c)
            && !ACCOUNT_PUNCTUATION.contains(c)
    });
    let one_at = matches!(
        account.split('@').collect::<Vec<_>>()[..],
        [local, domain] if !local.is_empty() && !domain.is_empty()
    );
    if one_token && one_at && account.chars().count() <= MAX_ACCOUNT_CHARS {
        Ok(account.to_string())
    } else {
        Err(ACCOUNT_NOT_ONE_EMAIL.to_string())
    }
}

/// Apply a save to `current` - the settings as stored when the save is
/// written. The account must be one email address ([`bitwarden_account`]).
/// The stored password is only kept for its own server and account
/// ([`check_save_keeps_password`] against `current`, not against a copy read
/// earlier), and only a newly sealed password is written.
pub fn apply_bitwarden_save(
    current: &mut crate::db::BitwardenConfig,
    save: BitwardenSave,
) -> Result<()> {
    let email = bitwarden_account(&save.email).map_err(anyhow::Error::msg)?;
    check_save_keeps_password(
        current,
        &save.server_url,
        &email,
        save.sealed_password.is_some(),
    )
    .map_err(anyhow::Error::msg)?;
    current.server_url = Some(save.server_url);
    current.email = Some(email);
    if let Some(sealed) = save.sealed_password {
        current.master_password = Some(sealed);
    }
    current.folder_name = Some(save.folder_name);
    current.servers_folder_name = Some(save.servers_folder_name);
    if current.device_id.is_none() {
        current.device_id = Some(uuid::Uuid::new_v4().to_string());
    }
    // Saved settings always carry the row: no destination is allowed until a
    // question allows one (the startup migration fills only the settings it
    // found from before destinations had to be allowed).
    if current.confirmed_destination.is_none() {
        current.confirmed_destination = Some(String::new());
    }
    Ok(())
}

// ─── The master-key derivation: on the blocking pool, two at a time ───────

/// How many Bitwarden master-key derivations run at once, app-wide - Test
/// connection and sync alike. Each is Argon2id with the account's memory
/// (often 32 or 64 MiB, up to the 1 GiB ceiling, 16 passes at most) or
/// PBKDF2: parallel sign-ins must not take every worker and gigabytes of
/// memory.
const KDF_PERMITS: usize = 2;

/// How long a sign-in waits for a derivation to come free.
const KDF_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a sign-in says when no derivation came free in time.
pub(crate) const KDF_BUSY: &str =
    "Another Bitwarden sign-in is still running. Try again when it has finished.";

/// The derivations that may run at once ([`KDF_PERMITS`]).
static KDF_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(KDF_PERMITS);

/// The master key of `email` and `password` under `kdf`, derived on the
/// blocking pool once one of the [`KDF_SLOTS`] is free
/// ([`on_kdf_slot`]). It used to run inline on the async worker of the
/// sign-in.
async fn master_key_off_thread(
    password: &str,
    email: &str,
    kdf: &KdfParams,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    // Copies for the trip to the pool; the password's is wiped on drop.
    let password = zeroize::Zeroizing::new(password.to_string());
    let email = email.to_string();
    let kdf = kdf.clone();
    on_kdf_slot(&KDF_SLOTS, KDF_PERMIT_WAIT, move || {
        master_key_on_pool(&password, &email, &kdf).map(zeroize::Zeroizing::new)
    })
    .await?
}

/// [`bitwarden::derive_master_key`], for the blocking pool only (tests
/// check where it runs).
fn master_key_on_pool(password: &str, email: &str, kdf: &KdfParams) -> Result<[u8; 32]> {
    crate::commands::on_pool_only("Bitwarden master-key derivation");
    bitwarden::derive_master_key(password, email, kdf)
}

/// Run `work` - a key derivation - on the blocking pool once one of `slots`
/// is free, waiting at most `wait` for it ([`KDF_BUSY`] otherwise). The slot
/// goes with the work, so it comes free when the derivation ends - even when
/// the caller stopped waiting for it: a blocking task cannot be cancelled.
async fn on_kdf_slot<T: Send + 'static>(
    slots: &'static tokio::sync::Semaphore,
    wait: std::time::Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    let slot = match tokio::time::timeout(wait, slots.acquire()).await {
        Ok(Ok(slot)) => slot,
        // Timed out - or closed, which these slots never are.
        Ok(Err(_)) | Err(_) => anyhow::bail!(KDF_BUSY),
    };
    crate::commands::spawn_on_pool(move || {
        let _slot = slot;
        work()
    })
    .await
    .map_err(|e| anyhow::anyhow!("background task failed: {e}"))
}

// ─── The KDF of the account, from the prelogin answer ──────────────────────

/// The KDF parameters of a prelogin answer (`kdf`, `kdfIterations`,
/// `kdfMemory`, `kdfParallelism`; PBKDF2 accounts send the last two as
/// explicit null), clamped at BOTH ends by KDF type
/// ([`crate::crypto::bitwarden::clamp_kdf_params`]): floors stop a malicious
/// server from weakening the derivation, ceilings stop it from turning a sync
/// into an unbounded local CPU/RAM burn (the cost is paid during derivation,
/// which no HTTP timeout covers).
///
/// `kdfMemory` is in MiB, as Bitwarden and Vaultwarden send it (the official
/// SDK derives with `memory * 1024` KiB); [`KdfParams::memory`] is in KiB, so
/// it is converted here. It used to be taken as KiB: a 64 MiB account was
/// clamped up from "64 KiB" to the 16 MiB floor and derived the wrong master
/// key.
fn kdf_from_prelogin(data: &serde_json::Value) -> Result<KdfParams> {
    // A number above u32::MAX ends at u32::MAX - and so at the ceiling -
    // not narrowed: 2^32 + 16 MiB used to become 16 MiB.
    let num = |k: &str| {
        data.get(k)
            .and_then(|v| v.as_u64())
            .map_or(0, |v| u32::try_from(v).unwrap_or(u32::MAX))
    };
    crate::crypto::bitwarden::clamp_kdf_params(
        num("kdf"),
        num("kdfIterations"),
        crate::crypto::bitwarden::argon2_memory_kib(num("kdfMemory")),
        num("kdfParallelism"),
    )
}

// ─── The destination of the uploads, allowed in a native question ───────────

/// The question about uploading to the stored destination
/// ([`settle_destination`]).
pub(crate) struct PendingDestination {
    /// The destination asked about ([`crate::db::BitwardenConfig::destination`]):
    /// allowed only while the settings still have exactly this one.
    pub(crate) destination: String,
    pub(crate) prompt: crate::commands::CredentialPrompt,
    /// The host the question names (cleaned and capped).
    pub(crate) host: String,
}

/// How the question about a [`PendingDestination`] ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DestinationOutcome {
    pub(crate) confirmed: bool,
    pub(crate) warning: Option<String>,
}

/// The host and the account of `config` as a question or a message quotes
/// them: the host as the URL parser holds it (with a port that is not the
/// default), both cleaned of control, format and direction characters and
/// capped ([`crate::commands::dialog_text`]).
fn quoted_destination(config: &crate::db::BitwardenConfig) -> Option<(String, String)> {
    let url = config.server_url.as_deref()?;
    let email = config.email.as_deref()?;
    let host = url::Url::parse(url)
        .map(|u| crate::commands::host_label(&u))
        .unwrap_or_else(|_| url.to_string());
    Some((
        crate::commands::dialog_text(&host, 120),
        crate::commands::dialog_text(email, 128),
    ))
}

/// The account allowed before, when the stored destination is another
/// account's: the account of the allowed destination
/// ([`crate::db::BitwardenConfig::confirmed_destination`]), cleaned and
/// capped like the account in the question. `None` when nothing is allowed,
/// or the same account (on another server, say) was.
fn previous_account(config: &crate::db::BitwardenConfig) -> Option<String> {
    let allowed = config
        .confirmed_destination
        .as_deref()
        .filter(|d| !d.is_empty())?;
    let [_, email]: [String; 2] = serde_json::from_str(allowed).ok()?;
    let current = config.email.as_deref()?.trim().to_lowercase();
    (email != current).then(|| crate::commands::dialog_text(&email, 128))
}

/// The question for the destination `config` stores; `None` while no
/// server URL or account email is stored. The account is its subject, on a
/// line of its own: the host came first, and a look-alike account on a
/// familiar host read as the user's own ("vault.bitwarden.com
/// (me.example.com@gmail.com)"). When another account was allowed before,
/// the question says so.
pub(crate) fn pending_destination(
    config: &crate::db::BitwardenConfig,
) -> Option<PendingDestination> {
    let destination = config.destination()?;
    let (host, account) = quoted_destination(config)?;
    let address = crate::commands::dialog_text(config.server_url.as_deref().unwrap_or(""), 200);
    let previous = previous_account(config)
        .map(|before| format!("This is not the account allowed before ({before}).\n"))
        .unwrap_or_default();
    Some(PendingDestination {
        destination,
        prompt: crate::commands::CredentialPrompt {
            title: "SSHSpan - Sync with Bitwarden?".to_string(),
            message: format!(
                "SSHSpan will upload your SSH private keys and saved server passwords to this Bitwarden account when it syncs:\n\nAccount: {account}\nServer: {host}\nAddress: {address}\n\n{previous}Allow?"
            ),
        },
        host,
    })
}

/// What a sync refuses while the stored destination is not the allowed one,
/// before any network call; `None` when it may run (or when no destination is
/// stored - the sync says what is missing). It names the account first, as
/// the question does.
pub(crate) fn sync_refusal(config: &crate::db::BitwardenConfig) -> Option<String> {
    if config.confirmed() {
        return None;
    }
    let (host, account) = quoted_destination(config)?;
    Some(format!(
        "Bitwarden sync is off until you allow it to upload your keys and passwords to the account {account} on {host}. Use \"Allow syncing...\" in Settings > Bitwarden."
    ))
}

/// What a save or "Allow syncing..." answers while the last question about
/// uploading, to `host`, was answered "Don't allow" or "Cancel" less than
/// [`crate::commands::CREDENTIAL_DECLINE_BACKOFF`] ago, whatever server or
/// account is asked about now: nothing is asked, and the sync stays off.
fn declined_lately_warning(host: &str) -> String {
    format!(
        "Bitwarden sync stays off, because uploading to {host} was declined a moment ago. Wait 30 seconds, then use \"Allow syncing...\" in Settings > Bitwarden."
    )
}

/// What a save or "Allow syncing..." answers when another question about
/// sending a credential is still open.
pub(crate) const DESTINATION_QUESTION_OPEN: &str = "Bitwarden sync stays off, because another question about sending a credential was still open. Answer it, then use \"Allow syncing...\" in Settings > Bitwarden.";

/// ... when the vault was locked while the question was open.
pub(crate) const DESTINATION_LOCKED_WHILE_ASKED: &str = "Bitwarden sync stays off, because the vault was locked while you were deciding. Unlock it, then use \"Allow syncing...\" in Settings > Bitwarden.";

/// ... when the server or the account changed while the question was open.
pub(crate) const DESTINATION_MOVED_WHILE_ASKED: &str = "Bitwarden sync stays off, because the server or account changed while you were deciding. Use \"Allow syncing...\" in Settings > Bitwarden to be asked about the new one.";

/// ... when a master-password change was running.
pub(crate) const DESTINATION_REENCRYPTING: &str = "Bitwarden sync stays off, because the vault was being re-encrypted. Use \"Allow syncing...\" in Settings > Bitwarden when that has finished.";

/// ... when the answer could not be stored.
pub(crate) const DESTINATION_NOT_STORED: &str = "Bitwarden sync stays off, because allowing it could not be stored. Use \"Allow syncing...\" in Settings > Bitwarden to be asked again.";

/// Ask about `pending` - in production the native dialog, on the blocking
/// pool - and, when allowed, record the destination as the allowed one
/// ([`confirm_destination`]). A "no", or an "Allow" sooner than a second
/// after the question opened, leaves the sync off - and switches it off
/// again if an earlier "Allow" allowed this very destination meanwhile
/// ([`decline_destination`]). Both answers are audited
/// (`sync.destination_allowed` / `sync.destination_declined`) with the host,
/// never an account, a password or a sealed value. The MCP credential
/// questions work the same way (`assistant::mcp::settle_binding`).
///
/// One question at a time (`questions`, app-wide): while another is open,
/// nothing is asked and the sync stays off. The turn lasts until the answer
/// is written, so answers are written in the order they were asked. After
/// "Don't allow" or "Cancel", no question about uploading is asked for 30
/// seconds, whatever server or account it names
/// ([`crate::commands::QuestionKind::BitwardenDestination`];
/// [`declined_lately_warning`] names the one declined): a renderer that asks
/// again and again - about one destination, or a made-up one each time -
/// until a tired user gives in, gets that answer instead of a dialog.
pub(crate) fn settle_destination(
    db: &crate::db::Database,
    rotation: &crate::commands::VaultRotationLock,
    questions: &crate::commands::CredentialQuestions,
    at_save: &crate::commands::VaultAtSave<'_>,
    pending: PendingDestination,
    ask: crate::commands::ConfirmCredential<'_>,
) -> DestinationOutcome {
    use crate::commands::CredentialAnswer;
    let not_confirmed = |warning: String| DestinationOutcome {
        confirmed: false,
        warning: Some(warning),
    };
    let Some(_turn) = questions.begin() else {
        return not_confirmed(DESTINATION_QUESTION_OPEN.into());
    };
    let kind = crate::commands::QuestionKind::BitwardenDestination;
    if let Some(declined) = questions.declined_lately(kind) {
        return not_confirmed(declined_lately_warning(&declined));
    }
    let answer = ask(&pending.prompt);
    if answer == CredentialAnswer::NotAllowed {
        questions.record_decline(kind, &pending.host);
    }
    let detail = format!("host={}", pending.host);
    if answer != CredentialAnswer::Allowed {
        decline_destination(db, rotation, &pending);
        let host = &pending.host;
        let (detail, warning) = match answer {
            CredentialAnswer::TooQuick => (
                format!("{detail} answered=too-quickly"),
                format!(
                    "Bitwarden sync stays off, because the question about uploading to {host} was answered within a second of opening - too fast to be a decision. Use \"Allow syncing...\" in Settings > Bitwarden to be asked again."
                ),
            ),
            _ => (
                detail,
                format!(
                    "Bitwarden sync stays off, because uploading your keys and passwords to {host} was not allowed. Use \"Allow syncing...\" in Settings > Bitwarden to be asked again."
                ),
            ),
        };
        crate::commands::audit_or_log(db, "sync.destination_declined", None, &detail);
        return not_confirmed(warning);
    }
    match confirm_destination(db, rotation, at_save, &pending) {
        Ok(()) => {
            crate::commands::audit_or_log(db, "sync.destination_allowed", None, &detail);
            DestinationOutcome {
                confirmed: true,
                warning: None,
            }
        }
        Err(warning) => not_confirmed(warning),
    }
}

/// Record `pending` as the allowed destination - only while the settings
/// still have exactly that destination, only while the vault is still
/// unlocked in the generation of the save or of the "Allow syncing..." click
/// (an "Allow" given to a locked vault counts for nothing), both checked
/// inside the transaction that writes, and not while a master-password
/// change runs (the write rewrites every settings row). Why it was not
/// recorded comes back as the warning to show; a database error is logged,
/// not shown.
fn confirm_destination(
    db: &crate::db::Database,
    rotation: &crate::commands::VaultRotationLock,
    at_save: &crate::commands::VaultAtSave<'_>,
    pending: &PendingDestination,
) -> std::result::Result<(), String> {
    let _rotation = rotation
        .try_shared()
        .map_err(|_| DESTINATION_REENCRYPTING.to_string())?;
    db.update_bitwarden_config(|config| {
        if !at_save.unchanged() {
            anyhow::bail!(DESTINATION_LOCKED_WHILE_ASKED);
        }
        if config.destination().as_deref() != Some(pending.destination.as_str()) {
            anyhow::bail!(DESTINATION_MOVED_WHILE_ASKED);
        }
        config.confirmed_destination = Some(pending.destination.clone());
        Ok(())
    })
    .map_err(|e| {
        let text = e.to_string();
        if text == DESTINATION_LOCKED_WHILE_ASKED || text == DESTINATION_MOVED_WHILE_ASKED {
            text
        } else {
            log::warn!("[sshspan-sync] could not store an allowed sync destination: {text}");
            DESTINATION_NOT_STORED.to_string()
        }
    })
}

/// [`decline_destination`]'s transaction when there is nothing to switch off.
const NOTHING_TO_SWITCH_OFF: &str = "nothing to switch off";

/// A "no" to `pending` - or an "Allow" too soon: the sync stays off, and is
/// switched off again if this very destination was allowed (by an earlier
/// question, or an "Allow syncing..." asked again). The questions are
/// answered one at a time and in order, so the later "no" stands. Another
/// destination allowed before is left alone: it is not the stored one, so
/// nothing is uploaded to it until the settings point back at it. Nothing is
/// written while a master-password change runs, and a failure is logged.
fn decline_destination(
    db: &crate::db::Database,
    rotation: &crate::commands::VaultRotationLock,
    pending: &PendingDestination,
) {
    let Ok(_rotation) = rotation.try_shared() else {
        log::warn!(
            "[sshspan-sync] a declined sync destination was not written: the vault is being re-encrypted"
        );
        return;
    };
    let switched = db.update_bitwarden_config(|config| {
        if config.confirmed_destination.as_deref() != Some(pending.destination.as_str()) {
            anyhow::bail!(NOTHING_TO_SWITCH_OFF);
        }
        config.confirmed_destination = Some(String::new());
        Ok(())
    });
    if let Err(e) = switched {
        if e.to_string() != NOTHING_TO_SWITCH_OFF {
            log::warn!("[sshspan-sync] could not store a declined sync destination: {e}");
        }
    }
}

/// Save the sync settings: `prepare` does the slow part (the URL check, the
/// seal) and returns what to write; the write is then ONE transaction that
/// re-reads the settings and checks the save against them - nothing
/// read before the slow part is written back.
pub async fn save_bitwarden_settings(
    db: &crate::db::Database,
    prepare: impl std::future::Future<Output = std::result::Result<BitwardenSave, String>>,
) -> std::result::Result<(), String> {
    let save = prepare.await?;
    db.update_bitwarden_config(|current| apply_bitwarden_save(current, save))
        .map_err(|e| e.to_string())
}

// ─── Response hardening helpers ─────────────────────────────────────────

/// Reject redirect responses. The client is built with
/// `redirect::Policy::none()`, so a 3xx lands here instead of being
/// silently followed (see the SSRF notes in `BitwardenClient::new`).
/// The Bitwarden identity/API endpoints never redirect in normal operation;
/// a 3xx means either a misconfigured reverse proxy or something hostile.
fn reject_redirect(status: reqwest::StatusCode) -> Result<()> {
    if status.is_redirection() {
        anyhow::bail!(
            "Vault server returned a redirect (HTTP {}), which is not allowed. \
             Check the server URL - the vault server must serve the Bitwarden \
             API directly without redirects.",
            status
        );
    }
    Ok(())
}

/// Read a response body into a byte buffer, enforcing [`MAX_RESPONSE_BYTES`].
/// The cap is checked against `Content-Length` up front (fast rejection) and
/// against the accumulated bytes during streaming, so an oversized body stops
/// the read instead of exhausting memory - even when the server lies about
/// (or omits) `Content-Length`.
async fn read_body_capped(mut resp: reqwest::Response) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > MAX_RESPONSE_BYTES {
            anyhow::bail!(
                "Vault server response too large ({len} bytes, limit {MAX_RESPONSE_BYTES})."
            );
        }
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            anyhow::bail!(
                "Vault server response exceeded the {} byte limit.",
                MAX_RESPONSE_BYTES
            );
        }
    }
    Ok(body)
}

/// Longest server text an error message keeps.
const MAX_ERROR_DETAIL_CHARS: usize = 300;

/// A vault server's error body, as it goes into an error message: cut to
/// [`MAX_ERROR_DETAIL_CHARS`] characters (on a character boundary) with an
/// ellipsis. The whole body - up to the 50 MiB read cap - used to land in the
/// error, the sync result's `errors` and the stored last result.
fn error_detail(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(MAX_ERROR_DETAIL_CHARS).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// Read a response body as text with the size cap enforced.
async fn read_body_capped_text(resp: reqwest::Response) -> Result<String> {
    let bytes = read_body_capped(resp).await?;
    String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("Vault server response is not valid UTF-8."))
}

/// Read and parse a JSON response body with the size cap enforced.
async fn read_body_capped_json(resp: reqwest::Response) -> Result<serde_json::Value> {
    let text = read_body_capped_text(resp).await?;
    serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic reqwest Response with the given status, headers and
    /// body - no network needed. reqwest 0.12 implements
    /// `From<http::Response<T>> for Response`, so unit tests can exercise
    /// the hardening helpers directly.
    fn make_response(status: u16, headers: &[(&str, &str)], body: Vec<u8>) -> reqwest::Response {
        let mut builder = http::Response::builder().status(status);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(body).unwrap().into()
    }

    #[tokio::test]
    async fn redirect_statuses_are_rejected() {
        for status in [301u16, 302, 303, 307, 308] {
            let resp = make_response(status, &[], b"moved".to_vec());
            // Simulate what api_request/prelogin/token_request do before
            // reading the body.
            let err = reject_redirect(resp.status()).unwrap_err();
            assert!(
                err.to_string().contains("redirect"),
                "status {status} must be rejected as a redirect"
            );
        }
    }

    #[test]
    fn non_redirect_statuses_pass_the_guard() {
        assert!(reject_redirect(reqwest::StatusCode::OK).is_ok());
        assert!(reject_redirect(reqwest::StatusCode::UNAUTHORIZED).is_ok());
        assert!(reject_redirect(reqwest::StatusCode::BAD_REQUEST).is_ok());
    }

    #[tokio::test]
    async fn body_within_cap_is_read_intact() {
        let body = b"{\"kdf\":1,\"kdfIterations\":600000}".to_vec();
        let resp = make_response(200, &[("content-length", "31")], body.clone());
        let bytes = read_body_capped(resp).await.unwrap();
        assert_eq!(bytes, body);
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        // A body one byte over the cap must fail the read. Note that a
        // synthetic reqwest Response built from a Full body reports an exact
        // size hint, so this exercises whichever guard fires first: the
        // content_length() pre-check or the streaming accumulation check.
        // Either way the read must not buffer the oversized body.
        let oversized = (MAX_RESPONSE_BYTES + 1) as usize;
        let resp = make_response(200, &[], vec![b'x'; oversized]);
        let err = read_body_capped(resp).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("too large") || msg.contains("exceeded"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn exactly_at_cap_is_allowed() {
        let at_cap = MAX_RESPONSE_BYTES as usize;
        let resp = make_response(200, &[], vec![0u8; at_cap]);
        let bytes = read_body_capped(resp).await.unwrap();
        assert_eq!(bytes.len(), at_cap);
    }

    #[tokio::test]
    async fn capped_json_parses_normal_payloads() {
        let resp = make_response(
            200,
            &[("content-type", "application/json")],
            b"{\"access_token\":\"t\",\"refresh_token\":\"r\",\"expires_in\":3600}".to_vec(),
        );
        let data = read_body_capped_json(resp).await.unwrap();
        assert_eq!(data.get("access_token").unwrap(), "t");
    }

    #[test]
    fn close_zeroizes_key_and_token_fields() {
        // The fields are populated through normal code paths (connect/
        // token_request/sync); this verifies close() clears whatever is in
        // them. Zeroizing<T> zeroizes T in place, so the Some(_) stays while
        // the contents become all-zero / empty.
        let mut client = BitwardenClient::new(
            "https://vault.example.com",
            "user@example.com",
            "correct horse battery staple",
            "device",
        )
        .unwrap();
        // Simulate a logged-in state without network access: these are the
        // exact assignments the real code paths make (modulo Zeroizing::new).
        client.master_key = Some(zeroize::Zeroizing::new([0xA5u8; 32]));
        client.stretched_key = Some(zeroize::Zeroizing::new([0x5Au8; 64]));
        client.user_key = Some(zeroize::Zeroizing::new([0xC3u8; 64]));
        client.access_token = Some(zeroize::Zeroizing::new("at-secret".to_string()));
        client.refresh_token = Some(zeroize::Zeroizing::new("rt-secret".to_string()));

        client.close();

        assert!(
            client
                .master_key
                .as_ref()
                .map(|k| k.iter().all(|&b| b == 0))
                .unwrap_or(true),
            "master key must be zero after close()"
        );
        assert!(
            client
                .stretched_key
                .as_ref()
                .map(|k| k.iter().all(|&b| b == 0))
                .unwrap_or(true),
            "stretched key must be zero after close()"
        );
        assert!(
            client
                .user_key
                .as_ref()
                .map(|k| k.iter().all(|&b| b == 0))
                .unwrap_or(true),
            "user key must be zero after close()"
        );
        assert!(
            client
                .access_token
                .as_ref()
                .map(|t| t.is_empty())
                .unwrap_or(true),
            "access token must be zeroed after close()"
        );
        assert!(
            client
                .refresh_token
                .as_ref()
                .map(|t| t.is_empty())
                .unwrap_or(true),
            "refresh token must be zeroed after close()"
        );
        assert!(client.master_password.is_empty());
    }

    fn saved_config() -> crate::db::BitwardenConfig {
        crate::db::BitwardenConfig {
            server_url: Some("https://vault.saved.example".into()),
            email: Some("saved@example.com".into()),
            master_password: Some("sealed-blob".into()),
            folder_name: Some("SSHSpan_Keys".into()),
            servers_folder_name: None,
            device_id: Some("device".into()),
            last_sync: None,
            last_result: None,
            confirmed_destination: None,
        }
    }

    #[test]
    fn config_view_reports_a_stored_master_password_without_returning_it() {
        // A5-35: the form could not tell whether a password was stored.
        let view = config_view(&saved_config());
        assert_eq!(view["hasMasterPassword"], true);
        assert_eq!(view["server_url"], "https://vault.saved.example");
        assert!(view.get("master_password").is_none());
        assert!(
            !view.to_string().contains("sealed-blob"),
            "the sealed password never reaches the renderer"
        );
        let mut none = saved_config();
        none.master_password = None;
        assert_eq!(config_view(&none)["hasMasterPassword"], false);
        let mut empty = saved_config();
        empty.master_password = Some(String::new());
        assert_eq!(config_view(&empty)["hasMasterPassword"], false);
    }

    #[test]
    fn test_connection_uses_the_form_values_before_the_saved_ones() {
        use zeroize::Zeroizing;
        // A2-52: "Test connection" before "Save" tested the OLD settings.
        let saved = saved_config();
        let target = resolve_test_target(
            &saved,
            Some(" https://vault.form.example ".into()),
            Some("form@example.com".into()),
            Some(Zeroizing::new("form-pw".into())),
            |url: &str| Ok(url.trim_end_matches('/').to_string()),
            |_| panic!("a password typed into the form must not unseal the saved one"),
        )
        .unwrap();
        assert_eq!(target.server_url, "https://vault.form.example");
        assert_eq!(target.email, "form@example.com");
        assert_eq!(target.master_password.as_str(), "form-pw");

        // Blank form fields fall back to the saved settings.
        let target = resolve_test_target(
            &saved,
            Some("   ".into()),
            None,
            Some(Zeroizing::new(String::new())),
            |url: &str| Ok(url.trim_end_matches('/').to_string()),
            |sealed| {
                assert_eq!(sealed, "sealed-blob");
                Ok(Zeroizing::new("saved-pw".into()))
            },
        )
        .unwrap();
        assert_eq!(target.server_url, "https://vault.saved.example");
        assert_eq!(target.email, "saved@example.com");
        assert_eq!(target.master_password.as_str(), "saved-pw");

        // A first-time form with nothing saved yet names what is missing.
        let blank = crate::db::BitwardenConfig::default();
        let missing = |url: Option<&str>, email: Option<&str>, pw: Option<&str>| {
            resolve_test_target(
                &blank,
                url.map(String::from),
                email.map(String::from),
                pw.map(|p| Zeroizing::new(p.to_string())),
                |url: &str| Ok(url.trim_end_matches('/').to_string()),
                |_| unreachable!("nothing is saved"),
            )
            .err()
            .unwrap()
        };
        assert!(missing(None, Some("a@b.example"), Some("p")).contains("server URL"));
        assert!(missing(Some("https://v.example"), None, Some("p")).contains("email"));
        assert!(
            missing(Some("https://v.example"), Some("a@b.example"), None)
                .contains("master password")
        );
    }

    #[test]
    fn saved_password_is_only_unsealed_for_the_saved_server_and_account() {
        use zeroize::Zeroizing;
        // A compromised renderer typed its own server (or account) and let
        // the SAVED master password log in there.
        let saved = saved_config();
        for (url, email) in [
            (Some("https://evil.example"), None),
            (None, Some("someone-else@example.com")),
        ] {
            let err = resolve_test_target(
                &saved,
                url.map(String::from),
                email.map(String::from),
                None::<Zeroizing<String>>,
                |url: &str| Ok(url.trim_end_matches('/').to_string()),
                |sealed| -> std::result::Result<Zeroizing<String>, String> {
                    panic!("the saved password must not be unsealed for {sealed}")
                },
            )
            .err()
            .unwrap();
            assert!(err.contains("different server or account"), "{err}");
        }
    }

    fn fix2_db() -> crate::db::Database {
        let db = crate::db::Database::open_at(
            std::env::temp_dir().join(format!("sshspan-test-{}.db", uuid::Uuid::new_v4())),
        )
        .unwrap();
        db.save_bitwarden_config(&saved_config()).unwrap();
        db
    }

    fn save_for(url: &str, email: &str, sealed: Option<&str>) -> BitwardenSave {
        BitwardenSave {
            server_url: url.into(),
            email: email.into(),
            sealed_password: sealed.map(String::from),
            folder_name: "SSHSpan_Keys".into(),
            servers_folder_name: "SSHSpan_Servers".into(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_password_less_save_keeps_a_password_stored_meanwhile() {
        // The save wrote back the sealed password it had read before
        // its URL check, over the one another save had just stored.
        let db = fix2_db();
        let other = db.clone();
        save_bitwarden_settings(&db, async move {
            other
                .update_bitwarden_config(|current| {
                    current.master_password = Some("sealed-new".into());
                    Ok(())
                })
                .unwrap();
            Ok(save_for(
                "https://vault.saved.example",
                "saved@example.com",
                None,
            ))
        })
        .await
        .unwrap();
        assert_eq!(
            db.load_bitwarden_config()
                .unwrap()
                .master_password
                .as_deref(),
            Some("sealed-new")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_endpoint_check_uses_the_settings_as_stored_at_write_time() {
        // Another save moved the settings to a new server (with its own
        // password) while this password-less save of the OLD server ran: the
        // new password must not be kept for the old server.
        let db = fix2_db();
        let other = db.clone();
        let err = save_bitwarden_settings(&db, async move {
            other
                .update_bitwarden_config(|current| {
                    current.server_url = Some("https://vault.new.example".into());
                    current.master_password = Some("sealed-new".into());
                    Ok(())
                })
                .unwrap();
            Ok(save_for(
                "https://vault.saved.example",
                "saved@example.com",
                None,
            ))
        })
        .await
        .unwrap_err();
        assert_eq!(
            err,
            "Enter the master password for the new server or account."
        );
        let stored = db.load_bitwarden_config().unwrap();
        assert_eq!(
            stored.server_url.as_deref(),
            Some("https://vault.new.example")
        );
        assert_eq!(stored.master_password.as_deref(), Some("sealed-new"));
    }

    #[test]
    fn a_login_refusal_quotes_at_most_a_short_server_text() {
        // token_request used to put the server's error_description into the
        // error uncapped.
        let data = serde_json::json!({ "error_description": "x".repeat(100_000) });
        let message = login_failure_message(reqwest::StatusCode::BAD_REQUEST, &data);
        assert!(message.starts_with("Vault login failed: "), "{message}");
        assert!(message.chars().count() < 500, "{}", message.len());
        assert!(message.contains('…'));
        let short = serde_json::json!({ "error": "invalid_grant" });
        assert_eq!(
            login_failure_message(reqwest::StatusCode::BAD_REQUEST, &short),
            "Vault login failed: invalid_grant Check the server URL, account email and master password."
        );
    }

    #[test]
    fn a_changed_server_or_account_needs_its_own_password() {
        // On save, a changed URL or email with no new password must not keep
        // the old sealed password for the new endpoint.
        let saved = saved_config();
        assert!(check_save_keeps_password(
            &saved,
            "https://vault.saved.example",
            " SAVED@example.com ",
            false
        )
        .is_ok());
        for (url, email) in [
            ("https://vault.other.example", "saved@example.com"),
            ("https://vault.saved.example", "other@example.com"),
        ] {
            let err = check_save_keeps_password(&saved, url, email, false).unwrap_err();
            assert_eq!(
                err,
                "Enter the master password for the new server or account."
            );
            assert!(check_save_keeps_password(&saved, url, email, true).is_ok());
        }
        let mut nothing_stored = saved_config();
        nothing_stored.master_password = None;
        assert!(check_save_keeps_password(
            &nothing_stored,
            "https://other.example",
            "x@y.example",
            false
        )
        .is_ok());
    }

    #[test]
    fn vault_error_details_are_cut_short() {
        // A whole response body (up to 50 MiB) went into errors and the
        // stored last result.
        let long = "é".repeat(5_000);
        let detail = error_detail(&long);
        assert!(
            detail.chars().count() <= MAX_ERROR_DETAIL_CHARS + 1,
            "{}",
            detail.len()
        );
        assert!(detail.ends_with('…'));
        assert_eq!(error_detail("short"), "short");
    }

    #[test]
    fn drop_clears_key_fields() {
        // Drop must route through close() (same zeroization) without
        // panicking. The actual in-place clearing of each field is proven by
        // close_zeroizes_key_and_token_fields; here a client with populated
        // secrets is dropped and the test asserts drop completed.
        let mut client = BitwardenClient::new(
            "https://vault.example.com",
            "user@example.com",
            "correct horse battery staple",
            "device",
        )
        .unwrap();
        client.master_key = Some(zeroize::Zeroizing::new([0xA5u8; 32]));
        client.stretched_key = Some(zeroize::Zeroizing::new([0x5Au8; 64]));
        client.user_key = Some(zeroize::Zeroizing::new([0xC3u8; 64]));
        client.access_token = Some(zeroize::Zeroizing::new("at-secret".to_string()));
        client.refresh_token = Some(zeroize::Zeroizing::new("rt-secret".to_string()));
        drop(client); // Drop → close() → zeroized; must not panic.
    }

    /// Bitwarden and Vaultwarden send `kdfMemory` in MiB - the official SDK
    /// derives with `memory * 1024` KiB - and it was taken as KiB: a 32 MiB
    /// account was clamped up to "16 MiB" and derived the wrong master key,
    /// so no Argon2id account could log in unless it used exactly 16 MiB.
    /// The known answers of the official SDK (bitwarden/sdk-internal,
    /// crates/bitwarden-crypto, commit eb9e208b: keys/kdf.rs
    /// `test_master_key_derive_argon2`, keys/master_key.rs
    /// `test_password_hash_argon2id`; both Argon2id, 4 iterations, 32 MiB,
    /// parallelism 2), reached through the prelogin numbers.
    #[test]
    fn fw_r9_the_argon2id_memory_of_a_prelogin_is_in_mib() {
        use crate::crypto::bitwarden::{derive_master_key, master_password_hash};
        let prelogin = serde_json::json!({
            "kdf": 1, "kdfIterations": 4, "kdfMemory": 32, "kdfParallelism": 2,
        });
        let kdf = kdf_from_prelogin(&prelogin).unwrap();
        let key = derive_master_key("67t9b5g67$%Dh89n", "test_key", &kdf).unwrap();
        let hash = master_password_hash(
            &derive_master_key("asdfasdf", "test_salt", &kdf).unwrap(),
            "asdfasdf",
        );
        assert_eq!(
            (key, hash.as_str()),
            (
                [
                    207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20,
                    147, 237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242
                ],
                "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ="
            ),
            "the master key of the SDK's test_master_key_derive_argon2, and the hash of its \
             test_password_hash_argon2id"
        );
        assert_eq!(kdf.memory, 32 * 1024, "32 MiB, in KiB");
        // The floor and the ceiling, in the same unit: 16 MiB and 1 GiB. A
        // number whose KiB do not fit ends at the ceiling: 4 TiB is 2^32
        // KiB - wrapped round, it would be 0, and so the floor.
        for (mib, kib) in [
            (0_u64, 16 * 1024),
            (15, 16 * 1024),
            (16, 16 * 1024),
            (64, 64 * 1024),
            (1024, 1024 * 1024),
            (1025, 1024 * 1024),
            (4 * 1024 * 1024, 1024 * 1024),
            (u64::from(u32::MAX), 1024 * 1024),
        ] {
            let kdf = kdf_from_prelogin(&serde_json::json!({
                "kdf": 1, "kdfIterations": 3, "kdfMemory": mib, "kdfParallelism": 4,
            }))
            .unwrap();
            assert_eq!(kdf.memory, kib, "kdfMemory {mib} MiB");
        }
        // PBKDF2 as before: its iterations, and no memory or parallelism.
        let pbkdf2 = kdf_from_prelogin(&serde_json::json!({
            "kdf": 0, "kdfIterations": 600_000, "kdfMemory": null, "kdfParallelism": null,
        }))
        .unwrap();
        assert_eq!(
            (
                pbkdf2.kdf_type,
                pbkdf2.iterations,
                pbkdf2.memory,
                pbkdf2.parallelism
            ),
            (0, 600_000, 0, 0)
        );
    }

    // ── The account is one email address, and the question leads with it ──

    /// The account was checked only for an "@", so a renderer's "account"
    /// added words to the question and the refusal. One email address now:
    /// one token, at most 254 characters, exactly one "@" between a local
    /// part and a domain, nothing that quotes, comments, separates or hides.
    #[test]
    fn fw_s1_the_account_is_one_email_address() {
        for (given, kept) in [
            ("me@example.com", "me@example.com"),
            ("  me@example.com\n", "me@example.com"),
            ("me.example.com@gmail.com", "me.example.com@gmail.com"),
            (
                "first.last+sync@sub.example.org",
                "first.last+sync@sub.example.org",
            ),
            ("jürgen@exämple.de", "jürgen@exämple.de"),
        ] {
            assert_eq!(bitwarden_account(given).as_deref(), Ok(kept), "{given:?}");
        }
        let longest = format!("{}@example.com", "a".repeat(254 - 12));
        assert_eq!(bitwarden_account(&longest).as_deref(), Ok(longest.as_str()));
        let mut refused = vec![
            "me@example.com) only to check the connection - nothing is uploaded until you press Sync now (ok".to_string(),
            "me @example.com".to_string(),
            "me@example.com x".to_string(),
            "me@exam\tple.com".to_string(),
            "me@@example.com".to_string(),
            "a@b@example.com".to_string(),
            "@example.com".to_string(),
            "me@".to_string(),
            "me".to_string(),
            String::new(),
            format!("{longest}m"),
            "me@exa\u{202e}moc.elpm".to_string(),
            "me\u{200b}@example.com".to_string(),
            "me@example.com\u{0}".to_string(),
            "me@example.com\u{7f}".to_string(),
        ];
        for c in ACCOUNT_PUNCTUATION.chars() {
            refused.push(format!("m{c}e@example.com"));
        }
        for given in refused {
            assert_eq!(
                bitwarden_account(&given),
                Err(ACCOUNT_NOT_ONE_EMAIL.to_string()),
                "{given:?}"
            );
        }
    }

    /// The question led with the host, and a look-alike account on a
    /// familiar host read as the user's own ("vault.bitwarden.com
    /// (me.example.com@gmail.com)"). The account is the subject now, on a
    /// line of its own; when another account was allowed before, the
    /// question says so. The refusal of a sync names the account first too.
    #[test]
    fn fw_s1_the_question_names_the_account_first() {
        let config =
            |url: &str, email: &str, allowed: Option<(&str, &str)>| crate::db::BitwardenConfig {
                server_url: Some(url.into()),
                email: Some(email.into()),
                confirmed_destination: Some(
                    allowed
                        .map(|(u, e)| serde_json::to_string(&[u, e]).unwrap())
                        .unwrap_or_default(),
                ),
                ..crate::db::BitwardenConfig::default()
            };
        let look_alike = config(
            "https://vault.bitwarden.com",
            "me.example.com@gmail.com",
            None,
        );
        let pending = pending_destination(&look_alike).unwrap();
        assert_eq!(pending.prompt.title, "SSHSpan - Sync with Bitwarden?");
        assert_eq!(
            pending.prompt.message,
            "SSHSpan will upload your SSH private keys and saved server passwords to this \
             Bitwarden account when it syncs:\n\nAccount: me.example.com@gmail.com\nServer: \
             vault.bitwarden.com\nAddress: https://vault.bitwarden.com\n\nAllow?"
        );
        assert_eq!(
            sync_refusal(&look_alike).as_deref(),
            Some(
                "Bitwarden sync is off until you allow it to upload your keys and passwords to \
                 the account me.example.com@gmail.com on vault.bitwarden.com. Use \"Allow \
                 syncing...\" in Settings > Bitwarden."
            )
        );
        // Another account was allowed before.
        let switched = config(
            "https://vault.bitwarden.com",
            "me.example.com@gmail.com",
            Some(("https://vault.bitwarden.com", "me@example.com")),
        );
        assert_eq!(
            pending_destination(&switched).unwrap().prompt.message,
            "SSHSpan will upload your SSH private keys and saved server passwords to this \
             Bitwarden account when it syncs:\n\nAccount: me.example.com@gmail.com\nServer: \
             vault.bitwarden.com\nAddress: https://vault.bitwarden.com\n\nThis is not the \
             account allowed before (me@example.com).\nAllow?"
        );
        // The same account on another server: no such line.
        let moved = config(
            "https://vault.example.org",
            "Me@Example.com",
            Some(("https://vault.bitwarden.com", "me@example.com")),
        );
        assert!(
            pending_destination(&moved)
                .unwrap()
                .prompt
                .message
                .ends_with("\n\nAllow?"),
            "same account"
        );
    }

    /// A prelogin number above `u32::MAX` was narrowed with `as` before it
    /// was clamped: 2^32 + 16 MiB of memory became 16 MiB, and the same for
    /// the iterations and the parallelism. A huge number ends at the ceiling.
    #[test]
    fn fw_r13_a_prelogin_number_above_u32_ends_at_the_ceiling() {
        let huge = u64::from(u32::MAX) + 1;
        let kdf = kdf_from_prelogin(&serde_json::json!({
            "kdf": 1,
            "kdfIterations": huge + 3,
            "kdfMemory": huge + 16,
            "kdfParallelism": huge + 1,
        }))
        .unwrap();
        assert_eq!(
            (kdf.iterations, kdf.memory, kdf.parallelism),
            (
                crate::crypto::bitwarden::ARGON2_MAX_ITERATIONS,
                crate::crypto::bitwarden::ARGON2_MAX_MEMORY_KIB,
                crate::crypto::bitwarden::ARGON2_MAX_PARALLELISM,
            )
        );
        let pbkdf2 = kdf_from_prelogin(&serde_json::json!({
            "kdf": 0, "kdfIterations": huge + 600_000,
        }))
        .unwrap();
        assert_eq!(
            pbkdf2.iterations,
            crate::crypto::bitwarden::PBKDF2_MAX_ITERATIONS
        );
        // An unknown KDF type beyond u32 is refused, not read as another.
        assert!(kdf_from_prelogin(&serde_json::json!({ "kdf": huge })).is_err());
    }

    // ── The master key is derived on the blocking pool, two at a time ──

    /// The derivation ran inline on the async worker of the sign-in. Now
    /// that the memory is read in MiB, as the server means it - often 32 or
    /// 64 MiB, up to 1 GiB - parallel sign-ins could take every worker. It
    /// runs on the blocking pool now (`on_pool_only` fails here otherwise)
    /// and still derives the master key of the official SDK's vector.
    #[tokio::test(flavor = "multi_thread")]
    async fn fw_s3_the_master_key_is_derived_on_the_blocking_pool() {
        let kdf = kdf_from_prelogin(&serde_json::json!({
            "kdf": 1, "kdfIterations": 4, "kdfMemory": 32, "kdfParallelism": 2,
        }))
        .unwrap();
        let key = master_key_off_thread("67t9b5g67$%Dh89n", "test_key", &kdf)
            .await
            .unwrap();
        assert_eq!(
            *key,
            [
                207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147,
                237, 47, 246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242
            ]
        );
        // The sign-in reaches the derivation only that way.
        let source = include_str!("mod.rs");
        let production = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        // A body ends at the first closing brace at its own indentation.
        let body = |signature: &str, end: &str| {
            let start = production.find(signature).unwrap();
            let rest = &production[start..];
            &rest[..rest.find(end).unwrap()]
        };
        assert!(body("    async fn connect_inner(", "\n    }\n").contains("master_key_off_thread("));
        assert!(
            body("\nasync fn master_key_off_thread(", "\n}\n")
                .contains("on_kdf_slot(&KDF_SLOTS, KDF_PERMIT_WAIT,"),
            "through the app's slots"
        );
        let derive_calls = production.matches("derive_master_key(").count();
        assert_eq!(
            derive_calls,
            body("\nfn master_key_on_pool(", "\n}\n")
                .matches("derive_master_key(")
                .count(),
            "derive_master_key is called only in master_key_on_pool"
        );
        assert_eq!(derive_calls, 1);
    }

    /// At most two derivations at once, app-wide: six sign-ins on six
    /// workers still run them two by two, each on the blocking pool. (Each
    /// waits a little for a second one to run beside it, so the two really
    /// overlap on a loaded machine; more than two would overlap as well.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn fw_s3_at_most_two_derivations_run_at_once() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::time::{Duration, Instant};
        static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(KDF_PERMITS);
        static RUNNING: AtomicUsize = AtomicUsize::new(0);
        static MOST: AtomicUsize = AtomicUsize::new(0);
        let sign_ins: Vec<_> = (0..6)
            .map(|_| {
                tokio::spawn(on_kdf_slot(&SLOTS, Duration::from_secs(120), || {
                    crate::commands::on_pool_only("test derivation");
                    MOST.fetch_max(RUNNING.fetch_add(1, SeqCst) + 1, SeqCst);
                    let started = Instant::now();
                    while RUNNING.load(SeqCst) < 2 && started.elapsed() < Duration::from_secs(5) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                    MOST.fetch_max(RUNNING.load(SeqCst), SeqCst);
                    RUNNING.fetch_sub(1, SeqCst);
                }))
            })
            .collect();
        for sign_in in sign_ins {
            sign_in.await.expect("the sign-in task").expect("derived");
        }
        assert_eq!(MOST.load(SeqCst), 2, "two at once, never more");
    }

    /// A sign-in that finds no derivation free within the wait gives up with
    /// a plain sentence, and runs nothing; once one is free, it runs.
    #[tokio::test(flavor = "multi_thread")]
    async fn fw_s3_a_sign_in_that_finds_no_free_derivation_is_refused() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(KDF_PERMITS);
        static RAN: AtomicBool = AtomicBool::new(false);
        let first = SLOTS.acquire().await.unwrap();
        let _second = SLOTS.acquire().await.unwrap();
        let err = on_kdf_slot(&SLOTS, std::time::Duration::from_millis(200), || {
            RAN.store(true, SeqCst)
        })
        .await
        .expect_err("no derivation is free");
        assert_eq!(err.to_string(), KDF_BUSY);
        assert!(!RAN.load(SeqCst), "nothing ran");
        drop(first);
        let seven = on_kdf_slot(&SLOTS, std::time::Duration::from_secs(30), || 7)
            .await
            .unwrap();
        assert_eq!(seven, 7);
        // The app's: two derivations at once, and a wait of 30 seconds.
        assert_eq!(
            (KDF_PERMITS, KDF_PERMIT_WAIT),
            (2, std::time::Duration::from_secs(30))
        );
    }
}
