//! All Tauri IPC commands
//! Each handler wraps the backend services and returns Result<T, String>.
//! Frontend calls them via `invoke('command_name', { key: value })`.

pub mod server;
pub mod sftp;
pub mod terminal;
pub mod updater;

use std::fs;
use directories::ProjectDirs;
use tauri::AppHandle;
use tauri::Manager;
use uuid::Uuid;

use crate::config::SshConfigService;
use crate::crypto::keys;
use crate::crypto::keys::{KeyFormat, KeyType};
use crate::db::{self, KeyRecord};
use crate::ssh::SshService;
use crate::AppState;
use base64ct::Encoding;

// ─── helpers ────────────────────────────────────────────────────────────────

/// Error type for Tauri commands. Wraps String and implements From<anyhow::Error>
/// so the `?` operator works on crypto functions that return anyhow::Result.
#[derive(Debug)]
pub struct CmdError(pub String);

impl std::fmt::Display for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CmdError {}
impl From<CmdError> for tauri::ipc::InvokeError {
    fn from(e: CmdError) -> Self {
        tauri::ipc::InvokeError::from(e.0)
    }
}

impl From<anyhow::Error> for CmdError {
    fn from(e: anyhow::Error) -> Self {
        CmdError(e.to_string())
    }
}
impl From<String> for CmdError {
    fn from(e: String) -> Self {
        CmdError(e)
    }
}
impl From<&str> for CmdError {
    fn from(e: &str) -> Self {
        CmdError(e.to_string())
    }
}

impl From<std::io::Error> for CmdError {
    fn from(e: std::io::Error) -> Self {
        CmdError(e.to_string())
    }
}
impl From<reqwest::Error> for CmdError {
    fn from(e: reqwest::Error) -> Self {
        CmdError(e.to_string())
    }
}

type CmdResult<T> = Result<T, CmdError>;

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// In-memory vault password accessor. Returns the password wrapped in
/// `Zeroizing` so every per-command copy is wiped on drop, matching the
/// store's own hygiene (the store holds the canonical `Zeroizing` copy; each
/// command previously cloned a plain `String` that lived until free).
fn vault_password(app: &AppHandle) -> CmdResult<zeroize::Zeroizing<String>> {
    Ok(app
        .state::<VaultPasswordStore>()
        .get()
        .map(zeroize::Zeroizing::new)
        .unwrap_or_default())
}

/// In-memory vault password (set on unlock, cleared on lock).
/// Wrapped in `Zeroizing` so the password is wiped from memory when the
/// store replaces or drops it, not just left as freed heap bytes.
pub struct VaultPasswordStore {
    password: std::sync::Mutex<Option<zeroize::Zeroizing<String>>>,
}

impl VaultPasswordStore {
    pub fn new() -> Self {
        Self {
            password: std::sync::Mutex::new(None),
        }
    }
    pub fn get(&self) -> Option<String> {
        self.password
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| p.to_string())
    }
    pub fn set(&self, p: String) {
        *self.password.lock().unwrap() = Some(zeroize::Zeroizing::new(p));
    }
    pub fn clear(&self) {
        *self.password.lock().unwrap() = None;
    }
}

/// In-process throttle for master-password verification. After 5 consecutive
/// failures every further attempt is delayed (30 s, doubling per additional
/// failure, capped at 15 min), so IPC-driven password guessing is slowed to
/// Argon2id-plus-backoff speed even for a local caller. This is defense in
/// depth, not the primary control: the at-rest Argon2id hash resists offline
/// guessing regardless, and an attacker able to restart the app clears this
/// in-memory state — but also loses nothing, since there is nothing to gain
/// from the IPC path that the DB file does not offer offline.
pub struct UnlockThrottle {
    state: std::sync::Mutex<ThrottleState>,
}

#[derive(Default)]
struct ThrottleState {
    consecutive_failures: u32,
    locked_until: Option<std::time::Instant>,
}

impl UnlockThrottle {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(ThrottleState::default()),
        }
    }

    /// Err while the throttle is cooling down after repeated failures.
    fn check(&self) -> Result<(), String> {
        let s = self.state.lock().unwrap();
        if let Some(until) = s.locked_until {
            let now = std::time::Instant::now();
            if now < until {
                let secs = (until - now).as_secs() + 1;
                return Err(format!(
                    "Too many failed attempts. Try again in {secs} second(s)."
                ));
            }
        }
        Ok(())
    }

    fn record_failure(&self) {
        let mut s = self.state.lock().unwrap();
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        if s.consecutive_failures >= 5 {
            // 5th failure: 30 s; each further failure doubles it, capped at 15 min.
            let extra = (s.consecutive_failures - 5).min(5) as u32;
            let delay = std::time::Duration::from_secs((30u64 << extra).min(900));
            s.locked_until = Some(std::time::Instant::now() + delay);
        }
    }

    fn record_success(&self) {
        *self.state.lock().unwrap() = ThrottleState::default();
    }
}

// ─── Master password hashing (Argon2id) ─────────────────────────────────────

const MASTER_HASH_KEY: &str = "master.hash";

/// True when the stored value is an Argon2 PHC-format hash (vs. the legacy
/// plaintext era, which stored the raw password under the same key).
fn is_argon2_hash(s: &str) -> bool {
    s.starts_with("$argon2")
}

/// Hash a master password with Argon2id (crate defaults: m=19 MiB, t=2, p=1).
fn hash_master_password(password: &str) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Verify a master password against the stored value. Transparently handles
/// the legacy plaintext era: on a plaintext match, re-hashes in place so the
/// stored value is upgraded to Argon2id on the first successful unlock.
fn verify_master_password(db: &db::Database, password: &str) -> Result<bool, String> {
    let stored = db.get_config(MASTER_HASH_KEY).unwrap_or_default();
    let Some(stored) = stored.filter(|s| !s.is_empty()) else {
        return Ok(false);
    };
    if is_argon2_hash(&stored) {
        use argon2::password_hash::PasswordVerifier;
        let parsed = argon2::PasswordHash::new(&stored).map_err(|e| e.to_string())?;
        Ok(argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    } else {
        let ok = stored == password;
        if ok {
            let hashed = hash_master_password(password)?;
            db.set_config(MASTER_HASH_KEY, &hashed)
                .map_err(|e| e.to_string())?;
            let _ = db.add_audit(
                "vault.hash_upgraded",
                None,
                "Plaintext verifier upgraded to Argon2id",
            );
        }
        Ok(ok)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  VAULT commands
// ═════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn vault_status(app: AppHandle) -> CmdResult<serde_json::Value> {
    let has_vault = app
        .state::<AppState>()
        .db
        .get_config(MASTER_HASH_KEY)
        .map(|h| h.as_ref().map_or(false, |s| !s.is_empty()))
        .unwrap_or(false);

    let unlocked = app.state::<VaultPasswordStore>().get().is_some();

    Ok(serde_json::json!({ "hasVault": has_vault, "unlocked": unlocked }))
}

/// Create a new vault. Stores an Argon2id verification hash and unlocks in one step.
#[tauri::command]
pub fn vault_create(app: AppHandle, password: String) -> CmdResult<serde_json::Value> {
    if password.len() < 8 {
        return Err("Master password must be at least 8 characters.".into());
    }
    if app
        .state::<AppState>()
        .db
        .get_config(MASTER_HASH_KEY)
        .map(|h| h.as_ref().map_or(false, |s| !s.is_empty()))
        .unwrap_or(false)
    {
        return Err("A vault already exists on this machine.".into());
    }

    let db = &app.state::<AppState>().db;
    let hashed = hash_master_password(&password).map_err(CmdError::from)?;
    db.set_config(MASTER_HASH_KEY, &hashed)
        .map_err(|e| e.to_string())?;
    db.set_config("vault.created", &now())
        .map_err(|e| e.to_string())?;
    db.add_audit("vault.created", None, "Vault created")
        .map_err(|e| e.to_string())?;

    // Vault is immediately unlocked after creation
    app.state::<VaultPasswordStore>().set(password);

    Ok(serde_json::json!({ "ok": true }))
}

/// Unlock an existing vault by verifying the password against the stored
/// Argon2id hash (or upgrading a legacy plaintext verifier in place).
/// Consecutive failures engage the [`UnlockThrottle`] backoff.
#[tauri::command]
pub fn vault_unlock(app: AppHandle, password: String) -> CmdResult<serde_json::Value> {
    let throttle = app.state::<UnlockThrottle>();
    throttle.check().map_err(CmdError::from)?;
    let stored = app
        .state::<AppState>()
        .db
        .get_config(MASTER_HASH_KEY)
        .unwrap_or_default();
    if stored.as_ref().map_or(true, |s| s.is_empty()) {
        return Err("No vault exists. Create one first.".into());
    }
    let ok = verify_master_password(&app.state::<AppState>().db, &password)
        .map_err(|e| e.to_string())?;
    if !ok {
        throttle.record_failure();
        app.state::<AppState>()
            .db
            .add_audit("vault.unlock_failed", None, "Failed attempt")
            .map_err(|e| e.to_string())?;
        return Err("Incorrect master password.".into());
    }
    throttle.record_success();
    app.state::<AppState>()
        .db
        .add_audit("vault.unlock", None, "")
        .map_err(|e| e.to_string())?;
    app.state::<VaultPasswordStore>().set(password);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn vault_lock(app: AppHandle) -> CmdResult<serde_json::Value> {
    // Kill every live interactive SSH session BEFORE clearing the master
    // password; sessions that survive into a locked vault would otherwise be
    // using unsealed key material with no way to re-derive it.
    app.state::<std::sync::Arc<crate::ssh_client::SessionRegistry>>()
        .kill_all();
    app.state::<crate::sftp::EditRegistry>().stop_all();
    app.state::<crate::sftp::KeepaliveRegistry>().stop_all();
    app.state::<VaultPasswordStore>().clear();
    app.state::<AppState>()
        .db
        .add_audit("vault.lock", None, "")
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn vault_change_password(
    app: AppHandle,
    current_password: String,
    new_password: String,
) -> CmdResult<serde_json::Value> {
    if new_password.len() < 8 {
        return Err("New master password must be at least 8 characters.".into());
    }
    // The current-password check is a password guess too — throttle it with
    // the same counter as unlock attempts.
    let throttle = app.state::<UnlockThrottle>();
    throttle.check().map_err(CmdError::from)?;
    let stored = app
        .state::<AppState>()
        .db
        .get_config(MASTER_HASH_KEY)
        .unwrap_or_default();
    if stored.as_ref().map_or(true, |s| s.is_empty()) {
        return Err("No vault exists. Create one first.".into());
    }
    let ok = verify_master_password(&app.state::<AppState>().db, &current_password)
        .map_err(|e| e.to_string())?;
    if !ok {
        throttle.record_failure();
        return Err("Current master password is incorrect.".into());
    }
    throttle.record_success();

    let db = &app.state::<AppState>().db;
    let keys = db.list_keys().map_err(|e| e.to_string())?;
    let servers = db.list_servers().map_err(|e| e.to_string())?;
    // Everything is re-encrypted in memory first; if any record fails to
    // unseal, the whole change is aborted and nothing is persisted.
    let migration = migrate_vault_records(keys, servers, &current_password, &new_password)?;

    let hashed = hash_master_password(&new_password).map_err(CmdError::from)?;
    for key in &migration.keys {
        db.update_key(key).map_err(|e| e.to_string())?;
    }
    for server in &migration.servers {
        db.update_server(server).map_err(|e| e.to_string())?;
    }
    db.set_config(MASTER_HASH_KEY, &hashed)
        .map_err(|e| e.to_string())?;
    let reencrypted = migration.keys.len() as u32;
    db.add_audit(
        "vault.password_changed",
        None,
        &format!(
            "Re-encrypted {reencrypted} key(s), {} saved server password(s)",
            migration.servers.len()
        ),
    )
    .map_err(|e| e.to_string())?;
    app.state::<VaultPasswordStore>().set(new_password);
    Ok(serde_json::json!({ "ok": true, "reencrypted": reencrypted }))
}

/// Result of re-sealing all vault-protected records with a new password.
#[derive(Debug)]
struct VaultMigration {
    keys: Vec<KeyRecord>,
    /// Only servers that actually had a saved password to re-seal.
    servers: Vec<db::ServerRecord>,
}

/// Unseal every stored private key and saved server password with the current
/// vault password and re-seal them with the new one, in memory. Any unseal
/// failure aborts the whole migration (nothing is persisted by this function).
fn migrate_vault_records(
    keys: Vec<KeyRecord>,
    servers: Vec<db::ServerRecord>,
    current_password: &str,
    new_password: &str,
) -> CmdResult<VaultMigration> {
    let mut migrated_keys = Vec::with_capacity(keys.len());
    for mut key in keys {
        let plaintext =
            match crate::crypto::vault::unseal(current_password, &key.private_key_encrypted) {
                Ok(bytes) => bytes,
                Err(e) => return Err(format!("Cannot re-encrypt key {}: {e}", key.id).into()),
            };
        key.private_key_encrypted =
            crate::crypto::vault::seal(new_password, &plaintext).map_err(|e| e.to_string())?;
        key.updated_at = chrono::Utc::now();
        migrated_keys.push(key);
    }

    // Saved server passwords are sealed with the same vault password, so they
    // must be re-sealed too — otherwise every stored server password becomes
    // unrecoverable after the change.
    let mut migrated_servers = Vec::with_capacity(servers.len());
    for mut server in servers {
        if let Some(sealed_pw) = server.saved_password.as_ref() {
            let plaintext = match crate::crypto::vault::unseal(current_password, sealed_pw) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(format!(
                        "Cannot re-encrypt saved password for server {}: {e}",
                        server.name
                    )
                    .into());
                }
            };
            server.saved_password =
                Some(crate::crypto::vault::seal(new_password, &plaintext).map_err(CmdError::from)?);
            server.updated_at = chrono::Utc::now();
            migrated_servers.push(server);
        }
    }

    Ok(VaultMigration {
        keys: migrated_keys,
        servers: migrated_servers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-process SQLite database against a temp file, exercising the real
    /// migrations and the real insert/update/list methods.
    fn test_db() -> db::Database {
        db::Database::open_at(
            std::env::temp_dir().join(format!("sshspan-test-{}.db", uuid::Uuid::new_v4())),
        )
        .expect("failed to open test database")
    }

    fn sample_server(id: &str, saved_password: Option<&str>, vault_pw: &str) -> db::ServerRecord {
        db::ServerRecord {
            id: id.to_string(),
            name: format!("server-{id}"),
            host: "10.0.0.1".into(),
            port: 22,
            username: "root".into(),
            key_id: None,
            pem_path: None,
            auth_method: "password".into(),
            saved_password: saved_password
                .map(|p| crate::crypto::vault::seal(vault_pw, p.as_bytes()).expect("seal failed")),
            category_id: None,
            color: None,
            last_connected_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            bitwarden_id: None,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
        }
    }

    fn sample_key(id: &str, vault_pw: &str) -> KeyRecord {
        KeyRecord {
            id: id.to_string(),
            name: format!("key-{id}"),
            key_type: "ed25519".into(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake test".into(),
            private_key_encrypted: crate::crypto::vault::seal(vault_pw, b"fake-private-key")
                .expect("seal failed"),
            fingerprint_sha256: "SHA256:fake".into(),
            fingerprint_md5: "MD5:fake".into(),
            comment: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deployed: false,
            deploy_path: None,
            bitwarden_id: None,
            bitwarden_sync: false,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
            category_ids: Vec::new(),
        }
    }

    /// Changing the master password must re-seal saved server passwords, and
    /// the re-sealed values must persist through the real db update path.
    #[test]
    fn change_password_reencrypts_saved_server_passwords() {
        let db = test_db();
        let old_pw = "old-master-pw";
        let new_pw = "new-master-pw";

        db.insert_server(&sample_server("srv-a", Some("s3cret-password"), old_pw))
            .unwrap();
        db.insert_server(&sample_server("srv-b", None, old_pw))
            .unwrap();
        db.insert_key(&sample_key("key-a", old_pw)).unwrap();

        let keys = db.list_keys().unwrap();
        let servers = db.list_servers().unwrap();
        let migration = migrate_vault_records(keys, servers, old_pw, new_pw).unwrap();
        assert_eq!(migration.keys.len(), 1);
        assert_eq!(
            migration.servers.len(),
            1,
            "only srv-a had a saved password"
        );
        for server in &migration.servers {
            db.update_server(server).unwrap();
        }
        for key in &migration.keys {
            db.update_key(key).unwrap();
        }

        // Re-read from the db: the sealed blob must have changed and must
        // unseal with the NEW password, not the old one.
        let stored = db.list_servers().unwrap();
        let srv_a = stored.iter().find(|s| s.id == "srv-a").unwrap();
        let plain = crate::crypto::vault::unseal(new_pw, srv_a.saved_password.as_ref().unwrap())
            .expect("saved password must unseal with the NEW master password");
        assert_eq!(plain, b"s3cret-password");
        assert!(
            crate::crypto::vault::unseal(old_pw, srv_a.saved_password.as_ref().unwrap()).is_err(),
            "saved password must NOT unseal with the OLD master password"
        );

        // Server without a saved password is untouched (still None, not migrated).
        let srv_b = stored.iter().find(|s| s.id == "srv-b").unwrap();
        assert!(srv_b.saved_password.is_none());

        // Keys are re-sealed too.
        let key = db.get_key("key-a").unwrap().unwrap();
        let key_plain = crate::crypto::vault::unseal(new_pw, &key.private_key_encrypted).unwrap();
        assert_eq!(key_plain, b"fake-private-key");
    }

    /// A corrupted/unopenable sealed value must abort the whole migration —
    /// no silent plaintext fallback, no partial re-encryption.
    #[test]
    fn change_password_aborts_on_unsealable_blob() {
        let db = test_db();
        let mut server = sample_server("srv-bad", Some("pw"), "old-master-pw");
        // Simulate a record sealed under a DIFFERENT (unknown) password.
        server.saved_password =
            Some(crate::crypto::vault::seal("some-other-password", b"pw").expect("seal failed"));
        db.insert_server(&server).unwrap();

        let keys = db.list_keys().unwrap();
        let servers = db.list_servers().unwrap();
        let err = migrate_vault_records(keys, servers, "old-master-pw", "new-master-pw")
            .expect_err("migration must fail");
        assert!(
            err.0.contains("srv-bad"),
            "error must name the server: {}",
            err.0
        );

        // Nothing was persisted — the stored blob still fails with the old pw.
        let stored = db.get_server("srv-bad").unwrap().unwrap();
        assert!(crate::crypto::vault::unseal(
            "old-master-pw",
            stored.saved_password.as_ref().unwrap()
        )
        .is_err());
    }

    /// The plaintext fallback is gone: raw (non-JSON) key material must be
    /// rejected instead of silently passed through.
    #[test]
    fn change_password_rejects_plaintext_key_records() {
        let mut key = sample_key("key-plain", "old-master-pw");
        key.private_key_encrypted = "RAWKEYMATERIAL-not-json".into();

        let result = migrate_vault_records(vec![key], Vec::new(), "old-master-pw", "new-master-pw");
        assert!(
            result.is_err(),
            "must not treat encrypted column as plaintext"
        );
    }

    /// Throttle: 4 failures keep the gate open; the 5th engages a cooldown;
    /// a success resets it.
    #[test]
    fn unlock_throttle_backoff_progression() {
        let t = UnlockThrottle::new();
        for _ in 0..4 {
            t.record_failure();
        }
        assert!(
            t.check().is_ok(),
            "4 consecutive failures must not engage the cooldown"
        );
        t.record_failure();
        assert!(
            t.check().is_err(),
            "5 consecutive failures must engage the cooldown"
        );
        t.record_success();
        assert!(t.check().is_ok(), "a success must reset the throttle");
    }

    /// Relative paths are rejected for backup export.
    #[test]
    fn validate_export_path_rejects_relative() {
        assert!(validate_export_path("relative.txt").is_err());
    }

    /// Paths pointing back into the app data dir are rejected.
    #[test]
    fn validate_export_path_rejects_app_data_dir() {
        use directories::ProjectDirs;
        let app_data = ProjectDirs::from("org", "sshspan", "SSHSpan")
            .expect("project dirs")
            .data_dir()
            .to_path_buf();
        let target = app_data.join("backup.json");
        assert!(validate_export_path(&target.display().to_string()).is_err());
    }

    /// An absolute path outside the app data / system dirs is accepted.
    #[test]
    fn validate_export_path_accepts_good_path() {
        let tmp = std::env::temp_dir().join("sshspan-export-test.txt");
        assert!(validate_export_path(&tmp.display().to_string()).is_ok());
    }
}

#[tauri::command]
pub fn vault_export(app: AppHandle) -> CmdResult<serde_json::Value> {
    let _pw = vault_password(&app)?;
    let keys = app
        .state::<AppState>()
        .db
        .list_keys()
        .map_err(|e| e.to_string())?;
    let exported: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| {
            serde_json::json!({
                "id": k.id, "name": k.name, "key_type": k.key_type,
                "public_key": k.public_key, "private_key_encrypted": k.private_key_encrypted,
                "fingerprint_sha256": k.fingerprint_sha256, "comment": k.comment,
            })
        })
        .collect();
    Ok(serde_json::json!({ "keys": exported }))
}

#[tauri::command]
pub fn vault_import(app: AppHandle, keys: Vec<serde_json::Value>) -> CmdResult<serde_json::Value> {
    let _pw = vault_password(&app)?;
    let mut imported = 0;
    for item in &keys {
        // Imported names become Host aliases in ~/.ssh/config — a name that
        // can't be a single Host token is sanitized instead of rejecting the
        // whole import (same mapping the Bitwarden sync uses).
        let raw_name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("imported")
            .to_string();
        let name = if keys::validate_key_name(&raw_name).is_ok() {
            raw_name
        } else {
            let sanitized = keys::sanitize_key_name(&raw_name);
            let _ = app.state::<AppState>().db.add_audit(
                "keys.name_sanitized",
                None,
                &format!("{raw_name:?} -> {sanitized:?}"),
            );
            sanitized
        };
        let key_record = KeyRecord {
            id: item
                .get("id")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            name,
            key_type: item
                .get("key_type")
                .and_then(|v| v.as_str())
                .unwrap_or("rsa")
                .to_string(),
            public_key: item
                .get("public_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            private_key_encrypted: item
                .get("private_key_encrypted")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            fingerprint_sha256: item
                .get("fingerprint_sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            fingerprint_md5: item
                .get("fingerprint_md5")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            comment: item
                .get("comment")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deployed: false,
            deploy_path: None,
            bitwarden_id: None,
            bitwarden_sync: false,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
            category_ids: Vec::new(),
        };
        if app.state::<AppState>().db.insert_key(&key_record).is_ok() {
            imported += 1;
        }
    }
    Ok(serde_json::json!({ "ok": true, "imported": imported }))
}

// ─── Vault backup / restore ────────────────────────────────────────────────

/// Serialize the whole vault (keys + categories + links + servers +
/// known_hosts + settings) and seal the payload with the current vault
/// password. The inner key blobs are sealed with the same password, so a
/// backup can only be restored with the master password that was current
/// when it was created (or by supplying that password at restore time).
#[tauri::command]
pub fn vault_backup_create(app: AppHandle) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let db = &app.state::<AppState>().db;

    let keys = db.list_keys_with_categories().map_err(|e| e.to_string())?;
    let categories = db.list_categories().map_err(|e| e.to_string())?;
    let servers = db.list_servers().map_err(|e| e.to_string())?;
    let known_hosts = db.list_known_hosts().map_err(|e| e.to_string())?;

    let settings: serde_json::Map<String, serde_json::Value> = [
        "autoLockMinutes",
        "sshKeysDir",
        "sshConfigPath",
        "theme",
        "confirmDelete",
        "autoUpdateCheck",
    ]
    .iter()
    .filter_map(|k| {
        db.get_config(&format!("setting.{k}"))
            .ok()
            .flatten()
            .map(|v| (k.to_string(), serde_json::json!(v)))
    })
    .collect();

    let payload = serde_json::json!({
        "keys": keys,
        "categories": categories,
        "servers": servers,
        "known_hosts": known_hosts,
        "settings": settings,
    });
    let payload_str = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let sealed =
        crate::crypto::vault::seal(&pw, payload_str.as_bytes()).map_err(|e| e.to_string())?;

    let document = serde_json::json!({
        "format": "sshspan-backup",
        "version": 1,
        "created": now(),
        "sealed": sealed,
    });
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("sshspan-backup-{stamp}.json");
    let count = serde_json::json!({
        "keys": keys.len(), "categories": categories.len(),
        "servers": servers.len(), "knownHosts": known_hosts.len(),
    });
    let _ = db.add_audit("vault.backup_created", None, &count.to_string());
    Ok(serde_json::json!({ "json": document, "filename": filename, "counts": count }))
}

/// Restore a backup document. The outer envelope is unsealed with the current
/// vault password; on failure the caller may supply the password that was
/// current when the backup was taken, and key blobs + saved server passwords
/// are then re-sealed with the current one so everything becomes usable.
#[tauri::command]
pub fn vault_backup_restore(
    app: AppHandle,
    payload_json: String,
    backup_password: Option<String>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let doc: serde_json::Value = serde_json::from_str(&payload_json).map_err(|e| e.to_string())?;
    if doc.get("format").and_then(|v| v.as_str()) != Some("sshspan-backup") {
        return Err("Not an SSHSpan backup file.".into());
    }
    let Some(sealed) = doc.get("sealed").and_then(|v| v.as_str()) else {
        return Err("Backup file is missing its sealed payload.".into());
    };

    let mut reused_backup_password = false;
    let plaintext = match crate::crypto::vault::unseal(&pw, sealed) {
        Ok(bytes) => bytes,
        Err(_) => {
            let bp = backup_password.as_deref().filter(|p| !p.is_empty())
                .ok_or_else(|| "This backup was created with a different master password. Enter that password to restore it.".to_string())?;
            reused_backup_password = true;
            crate::crypto::vault::unseal(bp, sealed)
                .map_err(|_| "Backup password is incorrect.".to_string())?
        }
    };
    let mut data: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|_| "Backup payload is corrupted.".to_string())?;

    // If the backup came from a different (older) password, re-seal key
    // material and saved server passwords with the current one. A blob that
    // cannot be decrypted with the backup password NOR the current one is
    // deliberately EXCLUDED (keys) or BLANKED (server passwords) instead of
    // being imported: importing it would strand it — unopenable once the old
    // backup password is discarded. Every exclusion is counted and surfaced
    // in the result and the audit log.
    let mut reseal_failures: u32 = 0;
    if reused_backup_password {
        let bp = backup_password.as_deref().unwrap_or_default().to_string();
        if let Some(arr) = data.get_mut("keys").and_then(|v| v.as_array_mut()) {
            let mut keep: Vec<serde_json::Value> = Vec::with_capacity(arr.len());
            for k in arr.drain(..) {
                let Some(blob) = k
                    .get("private_key_encrypted")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    keep.push(k);
                    continue;
                };
                if let Ok(plain) = crate::crypto::vault::unseal(&bp, &blob) {
                    match crate::crypto::vault::seal(&pw, &plain) {
                        Ok(resealed) => {
                            let mut k = k;
                            k["private_key_encrypted"] = serde_json::json!(resealed);
                            keep.push(k);
                        }
                        // Sealing failed: the blob is readable under the old
                        // password only, which is being discarded — excluded.
                        Err(_) => reseal_failures += 1,
                    }
                } else if crate::crypto::vault::unseal(&pw, &blob).is_ok() {
                    // Already usable with the current password (mixed-era
                    // backup): keep as-is.
                    keep.push(k);
                } else {
                    // Readable under neither password: a stranded blob.
                    reseal_failures += 1;
                }
            }
            *arr = keep;
        }
        if let Some(arr) = data.get_mut("servers").and_then(|v| v.as_array_mut()) {
            for sv in arr.iter_mut() {
                let Some(blob) = sv
                    .get("saved_password")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    continue;
                };
                if let Ok(plain) = crate::crypto::vault::unseal(&bp, &blob) {
                    if let Ok(resealed) = crate::crypto::vault::seal(&pw, &plain) {
                        sv["saved_password"] = serde_json::json!(resealed);
                        continue;
                    }
                }
                if crate::crypto::vault::unseal(&pw, &blob).is_ok() {
                    // Already usable with the current password: keep as-is.
                    continue;
                }
                // Unreadable under either password: drop the saved password
                // (the server record itself is kept) rather than importing a
                // stranded blob.
                sv["saved_password"] = serde_json::Value::Null;
                reseal_failures += 1;
            }
        }
    }

    let counts = app
        .state::<AppState>()
        .db
        .restore_backup(&data)
        .map_err(|e| e.to_string())?;
    let _ =
        app.state::<AppState>()
            .db
            .add_audit("vault.backup_restored", None, &counts.to_string());
    // A restore can silently swap stored host keys for hosts the user already
    // trusts; that deserves its own visible audit entry.
    if counts
        .get("knownHostsReplaced")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        > 0
    {
        let _ = app.state::<AppState>().db.add_audit(
            "known_hosts.restored_replaced",
            None,
            &format!(
                "{} host key(s) replaced by restore",
                counts
                    .get("knownHostsReplaced")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            ),
        );
    }
    if reseal_failures > 0 {
        let _ = app.state::<AppState>().db.add_audit(
            "vault.restore_reseal_skipped",
            None,
            &format!(
                "{reseal_failures} entrie(s) unreadable under the backup password were skipped (keys excluded, saved passwords blanked)"
            ),
        );
    }
    Ok(serde_json::json!({
        "ok": true,
        "counts": counts,
        "passwordReLinked": reused_backup_password,
        "resealFailures": reseal_failures,
    }))
}

// ─── File save helpers (backup export / generic) ───────────────────────────

/// Native save-file dialog; returns the chosen path (or canceled). The chosen
/// path is registered in the `DialogPathStore` so that `system_write_text_file`
/// only ever writes where the user explicitly picked in a native dialog.
#[tauri::command]
pub fn system_pick_save_path(
    app: AppHandle,
    title: Option<String>,
    default_name: Option<String>,
) -> CmdResult<serde_json::Value> {
    use tauri_plugin_dialog::DialogExt;
    let result = app
        .dialog()
        .file()
        .set_title(title.unwrap_or_else(|| "Save file".into()))
        .set_file_name(default_name.as_deref().unwrap_or("file.txt"))
        .blocking_save_file();
    match result {
        Some(path) => {
            let path_str = path.to_string();
            app.state::<DialogPathStore>().allow(&path_str);
            Ok(serde_json::json!({ "canceled": false, "path": path_str }))
        }
        None => Ok(serde_json::json!({ "canceled": true })),
    }
}

/// Paths the user explicitly picked in a native save dialog during this
/// session. `system_write_text_file` requires membership, so a compromised
/// renderer cannot use the write command against arbitrary user-writable
/// locations (Startup folders, shell rc files, …) — only paths a human
/// approved in the OS dialog.
pub struct DialogPathStore(std::sync::Mutex<std::collections::HashSet<String>>);

impl DialogPathStore {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(std::collections::HashSet::new()))
    }
    fn allow(&self, path: &str) {
        self.0.lock().unwrap().insert(path.to_string());
    }
    fn is_allowed(&self, path: &str) -> bool {
        self.0.lock().unwrap().contains(path)
    }
}

/// Write UTF-8 text to an absolute path (used for vault backup export). The
/// path must have been returned by `system_pick_save_path` in this session
/// AND must pass the absolute/app-data/system checks — both gates, so the
/// write target is always a human-approved dialog choice.
#[tauri::command]
pub fn system_write_text_file(
    app: AppHandle,
    path: String,
    contents: String,
) -> CmdResult<serde_json::Value> {
    validate_export_path(&path)?;
    if !app.state::<DialogPathStore>().is_allowed(&path) {
        return Err(
            "Write target must be a path chosen in a save dialog this session.".into(),
        );
    }
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&path, contents).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

/// Reject paths that are not absolute or that would write into the app data
/// directory / system directories. Used by the limited number of commands that
/// accept a renderer-supplied local filesystem target.
fn validate_export_path(path: &str) -> CmdResult<()> {
    let p = std::path::Path::new(path);
    if !p.is_absolute() {
        return Err("Path must be absolute.".into());
    }

    let normalized = p
        .canonicalize()
        .unwrap_or_else(|_| p.to_path_buf());

    if let Some(app_data) = ProjectDirs::from("org", "sshspan", "SSHSpan") {
        let app_data_dir = app_data.data_dir();
        if normalized.starts_with(app_data_dir) {
            return Err("Writing into the application data directory is not allowed.".into());
        }
    }

    if is_system_path(&normalized) {
        return Err("Writing into a system directory is not allowed.".into());
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn is_system_path(p: &std::path::Path) -> bool {
    if let Some(s) = p.as_os_str().to_str() {
        let lower = s.to_lowercase();
        if lower.starts_with("C:\\windows") || lower.starts_with("C:\\program files") {
            return true;
        }
        if let Ok(windir) = std::env::var("WINDIR") {
            let windir_norm = std::path::Path::new(&windir)
                .canonicalize()
                .unwrap_or_else(|_| std::path::Path::new(&windir).to_path_buf());
            if let Ok(canonical) = p.canonicalize() {
                if canonical.starts_with(windir_norm) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn is_system_path(p: &std::path::Path) -> bool {
    if let Ok(canonical) = p.canonicalize() {
        let system_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc", "/lib", "/lib64", "/usr/lib", "/usr/lib64"];
        for dir in &system_dirs {
            if canonical.starts_with(dir) {
                return true;
            }
        }
    }
    false
}

// ═════════════════════════════════════════════════════════════════════════════
//  KEY commands
// ═════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn key_list(app: AppHandle) -> CmdResult<serde_json::Value> {
    let keys = app
        .state::<AppState>()
        .db
        .list_keys_with_categories()
        .map_err(|e| e.to_string())?;
    let sanitized: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| {
            serde_json::json!({
                "id": k.id, "name": k.name, "key_type": k.key_type,
                "public_key": k.public_key,
                "fingerprint_sha256": k.fingerprint_sha256, "fingerprint_md5": k.fingerprint_md5,
                "comment": k.comment, "created_at": k.created_at.to_rfc3339(),
                "deployed": k.deployed, "bitwarden_sync": k.bitwarden_sync,
                "has_private": !k.private_key_encrypted.is_empty(),
                "category_ids": k.category_ids,
            })
        })
        .collect();
    Ok(serde_json::json!({ "keys": sanitized }))
}

#[tauri::command]
pub fn key_get(app: AppHandle, id: String) -> CmdResult<serde_json::Value> {
    let k = app
        .state::<AppState>()
        .db
        .get_key_with_categories(&id)
        .map_err(|e| e.to_string())?;
    match k {
        Some(key) => {
            // Resolve the first category into a breadcrumb path (depth-first, sorted).
            let path = if let Some(first) = key.category_ids.first() {
                let all = app
                    .state::<AppState>()
                    .db
                    .list_categories()
                    .map_err(|e| e.to_string())?;
                let mut by_id: std::collections::HashMap<String, db::Category> =
                    all.into_iter().map(|c| (c.id.clone(), c)).collect();
                let mut path = Vec::new();
                let mut cur: Option<String> = Some(first.clone());
                while let Some(id) = cur {
                    if let Some(cat) = by_id.remove(&id) {
                        path.push(cat.name.clone());
                        cur = cat.parent_id;
                    } else {
                        break;
                    }
                }
                path.reverse();
                path
            } else {
                Vec::new()
            };
            Ok(serde_json::json!({
                "id": key.id, "name": key.name, "key_type": key.key_type,
                "public_key": key.public_key,
                "fingerprint_sha256": key.fingerprint_sha256, "fingerprint_md5": key.fingerprint_md5,
                "comment": key.comment, "created_at": key.created_at.to_rfc3339(),
                "deployed": key.deployed, "deploy_path": key.deploy_path,
                "bitwarden_sync": key.bitwarden_sync,
                "has_private": !key.private_key_encrypted.is_empty(),
                "category_ids": key.category_ids,
                "inherited_category_path": path,
            }))
        }
        None => Err("Key not found.".into()),
    }
}

/// Parse an `authorized_keys`-style line ("algo base64 comment") back into
/// the raw SSH wire-format public key bytes stored in `KeyRecord.public_key`.
fn parse_openssh_public_line(line: &str) -> Result<Vec<u8>, String> {
    let b64 = line
        .split_whitespace()
        .nth(1)
        .ok_or("Malformed stored public key")?;
    base64ct::Base64::decode_vec(b64).map_err(|e| format!("Malformed stored public key: {e}"))
}

/// Reconstruct a `PrivateKeyData` for a stored key, decrypting the private
/// half with the (already-verified) vault password.
fn load_private_key_data(
    _app: &AppHandle,
    key: &KeyRecord,
    vault_pw: &str,
) -> Result<keys::PrivateKeyData, String> {
    let key_type = KeyType::from_db_tag(&key.key_type).map_err(|e| e.to_string())?;
    let private_bytes = crate::crypto::vault::unseal(vault_pw, &key.private_key_encrypted)
        .map_err(|_| "Failed to decrypt this key \u{2014} the vault password may have changed since it was stored.".to_string())?;
    let public_bytes = parse_openssh_public_line(&key.public_key)?;
    Ok(keys::PrivateKeyData::new(
        key_type,
        private_bytes,
        public_bytes,
        key.comment.clone(),
    ))
}

#[tauri::command]
pub fn key_generate(
    app: AppHandle,
    key_type: String,
    bits: Option<u32>,
    name: Option<String>,
    comment: Option<String>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }

    let kt = KeyType::from_db_tag(&key_type).map_err(|e| e.to_string())?;
    let comment_str = comment.clone().unwrap_or_default();
    let name_str =
        name.unwrap_or_else(|| format!("{}-{}", key_type, &Uuid::new_v4().to_string()[..8]));
    // Names become Host aliases in ~/.ssh/config — reject anything that could
    // break out of a single Host token before it ever reaches the vault.
    keys::validate_key_name(&name_str)?;

    let key_data =
        keys::generate_key_pair(kt, bits, comment_str.clone()).map_err(|e| e.to_string())?;
    let public_openssh =
        keys::export_public_key(&key_data, KeyFormat::OpenSsh).map_err(|e| e.to_string())?;
    let fingerprint = keys::compute_fingerprint_sha256(&key_data.public_key);
    let sealed_private =
        crate::crypto::vault::seal(&pw, &key_data.private_key).map_err(|e| e.to_string())?;

    let key_record = KeyRecord {
        id: Uuid::new_v4().to_string(),
        name: name_str.clone(),
        key_type: kt.db_tag().to_string(),
        public_key: public_openssh,
        private_key_encrypted: sealed_private,
        fingerprint_sha256: fingerprint.clone(),
        fingerprint_md5: keys::compute_fingerprint_md5(&key_data.public_key),
        comment: comment_str,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        deployed: false,
        deploy_path: None,
        bitwarden_id: None,
        bitwarden_sync: false,
        bitwarden_revision_ts: None,
        bitwarden_updated_at: None,
        category_ids: Vec::new(),
    };

    app.state::<AppState>()
        .db
        .insert_key(&key_record)
        .map_err(|e| e.to_string())?;
    app.state::<AppState>()
        .db
        .add_audit("keys.created", Some(&key_record.id), &name_str)?;

    Ok(serde_json::json!({ "ok": true, "id": key_record.id, "fingerprint": fingerprint }))
}

#[tauri::command]
pub fn key_import(
    app: AppHandle,
    pem: String,
    name: Option<String>,
    comment: Option<String>,
    passphrase: Option<String>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let pem = pem.trim();

    let mut key_data = if pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        keys::import_openssh_private(pem, passphrase.as_deref()).map_err(|e| e.to_string())?
    } else if crate::crypto::putty::looks_like_ppk(pem) {
        crate::crypto::putty::import_ppk(pem, passphrase.as_deref()).map_err(|e| e.to_string())?
    } else {
        return Err("Unsupported key format. Expected an OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----) or a PuTTY .ppk file.".into());
    };

    if let Some(c) = comment {
        key_data.comment = c;
    }

    let public_openssh =
        keys::export_public_key(&key_data, KeyFormat::OpenSsh).map_err(|e| e.to_string())?;
    let fingerprint = keys::compute_fingerprint_sha256(&key_data.public_key);
    let fingerprint_md5 = keys::compute_fingerprint_md5(&key_data.public_key);

    // Dedupe by fingerprint so the same key can't be imported twice.
    let existing = app
        .state::<AppState>()
        .db
        .list_keys()
        .map_err(|e| e.to_string())?;
    if let Some(dup) = existing
        .iter()
        .find(|k| k.fingerprint_sha256 == fingerprint)
    {
        return Err(format!("This key already exists in the vault as \"{}\".", dup.name).into());
    }

    let name_str = name.unwrap_or_else(|| format!("imported-{}", &Uuid::new_v4().to_string()[..8]));
    // Names become Host aliases in ~/.ssh/config — reject anything that could
    // break out of a single Host token before it ever reaches the vault.
    keys::validate_key_name(&name_str)?;
    let sealed_private =
        crate::crypto::vault::seal(&pw, &key_data.private_key).map_err(|e| e.to_string())?;

    let key_record = KeyRecord {
        id: Uuid::new_v4().to_string(),
        name: name_str.clone(),
        key_type: key_data.key_type.db_tag().to_string(),
        public_key: public_openssh,
        private_key_encrypted: sealed_private,
        fingerprint_sha256: fingerprint,
        fingerprint_md5,
        comment: key_data.comment.clone(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        deployed: false,
        deploy_path: None,
        bitwarden_id: None,
        bitwarden_sync: false,
        bitwarden_revision_ts: None,
        bitwarden_updated_at: None,
        category_ids: Vec::new(),
    };

    app.state::<AppState>()
        .db
        .insert_key(&key_record)
        .map_err(|e| e.to_string())?;
    app.state::<AppState>().db.add_audit(
        "keys.imported",
        Some(&key_record.id),
        &key_record.name,
    )?;

    Ok(serde_json::json!({ "ok": true, "id": key_record.id }))
}

/// Export a key's PUBLIC material to the renderer. PRIVATE formats are
/// deliberately refused here: decrypted private-key text must not pass
/// through the WebView (it would live in renderer memory and any renderer
/// compromise could read it). Use [`key_export_to_file`], which serializes
/// straight to a user-chosen file without the data ever entering IPC.
#[tauri::command]
pub fn key_export(
    app: AppHandle,
    id: String,
    format: String,
    passphrase: Option<String>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }

    let key = app
        .state::<AppState>()
        .db
        .get_key(&id)
        .map_err(|e| e.to_string())?;
    let key = key.ok_or_else(|| "Key not found.".to_string())?;

    // Public formats take no passphrase; the parameter is kept so the
    // renderer's export payload shape is unchanged across formats.
    let _ = passphrase;

    if format != "public" && format != "authorized_keys" && format != "public-pem" {
        let _ = app.state::<AppState>().db.add_audit(
            "keys.export_refused",
            Some(&id),
            &format!("private format {format} requested via renderer export IPC"),
        );
        return Err(CmdError(
            "Private-key export must be saved directly to a file \
             (use the export dialog) so key material stays out of the UI process."
                .into(),
        ));
    }

    let data = match format.as_str() {
        "public" | "authorized_keys" => key.public_key.clone(),
        "public-pem" => {
            let key_data = load_private_key_data(&app, &key, &pw)?;
            keys::export_public_key(&key_data, KeyFormat::Pkcs8).map_err(|e| e.to_string())?
        }
        _ => unreachable!("format restricted above"),
    };

    let _ = app.state::<AppState>().db.add_audit(
        "keys.exported",
        Some(&id),
        &format!("public material, format {format}"),
    );

    Ok(serde_json::json!({ "data": data }))
}

/// Private-key export extensions, mirroring the renderer's map.
fn private_export_extension(format: &str) -> &'static str {
    match format {
        "ppk" => ".ppk",
        "pkcs8" | "pkcs8-encrypted" => ".pem",
        _ => "", // openssh-private: no extension, matching ssh-keygen convention
    }
}

/// Export a PRIVATE key straight to a user-chosen file. The PEM text is
/// serialized in the backend and written to the path the user picks in the
/// native save dialog — the key material never crosses the IPC boundary into
/// the renderer. The file is written 0600 from the first byte on Unix; on
/// Windows the current-user-only ACL is attempted and a failure is logged
/// (exports may legitimately target volumes that cannot store ACLs, unlike
/// the deploy destination, where a restriction failure is fatal).
#[tauri::command]
pub fn key_export_to_file(
    app: AppHandle,
    id: String,
    format: String,
    passphrase: Option<String>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    match format.as_str() {
        "openssh-private" | "ppk" | "pkcs8" | "pkcs8-encrypted" => {}
        other => {
            return Err(CmdError(format!(
                "Format \"{other}\" is public material; use the regular export path."
            )))
        }
    }

    let key = app
        .state::<AppState>()
        .db
        .get_key(&id)
        .map_err(|e| e.to_string())?;
    let key = key.ok_or_else(|| "Key not found.".to_string())?;

    let key_data = load_private_key_data(&app, &key, &pw)?;
    let pass = passphrase.as_deref().filter(|p| !p.is_empty());
    let data = match format.as_str() {
        "openssh-private" => keys::export_private_key(&key_data, KeyFormat::OpenSsh, pass),
        "pkcs8" | "pkcs8-encrypted" => keys::export_private_key(&key_data, KeyFormat::Pkcs8, pass),
        "ppk" => keys::export_private_key(&key_data, KeyFormat::Putty, pass),
        _ => unreachable!("format restricted above"),
    }
    .map_err(|e| e.to_string())?;

    use tauri_plugin_dialog::DialogExt;
    let default_name = format!("{}{}", key.name, private_export_extension(&format));
    let picked = app
        .dialog()
        .file()
        .set_title("Export private key")
        .set_file_name(&default_name)
        .blocking_save_file();
    let Some(path) = picked else {
        return Ok(serde_json::json!({ "canceled": true }));
    };
    let path_str = path.to_string();
    // The dialog choice is the user's approval; keep the absolute/app-data/
    // system checks as a backstop (a dialog path is always absolute, but the
    // app-data guard also protects the vault DB from being overwritten).
    validate_export_path(&path_str)?;

    use std::io::Write as _;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&path_str)
        .map_err(|e| CmdError(format!("Could not create export file: {e}")))?;
    file.write_all(data.as_bytes())
        .map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    drop(file);

    #[cfg(unix)]
    {
        // mode() only applies at creation; reassert for a pre-existing file.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path_str)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path_str, perms)?;
    }
    #[cfg(windows)]
    {
        if let Err(e) = crate::ssh::restrict_windows_file(&std::path::PathBuf::from(&path_str)) {
            log::warn!(
                "[sshspan-keys] could not restrict ACLs on export {}: {e} \
                 (the destination may be a filesystem without ACL support)",
                path_str
            );
        }
    }

    let _ = app.state::<AppState>().db.add_audit(
        "keys.exported",
        Some(&id),
        &format!("private material, format {format} -> {path_str}"),
    );

    Ok(serde_json::json!({ "ok": true, "canceled": false, "path": path_str }))
}

#[tauri::command]
pub fn key_delete(app: AppHandle, id: String) -> CmdResult<serde_json::Value> {
    app.state::<AppState>()
        .db
        .delete_key(&id)
        .map_err(|e| e.to_string())?;
    app.state::<AppState>()
        .db
        .add_audit("keys.deleted", Some(&id), "")?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn key_fingerprint(app: AppHandle, id: String) -> CmdResult<serde_json::Value> {
    let key = app
        .state::<AppState>()
        .db
        .get_key(&id)
        .map_err(|e| e.to_string())?;
    let key = key.ok_or_else(|| "Key not found.".to_string())?;
    Ok(serde_json::json!({ "sha256": key.fingerprint_sha256, "md5": key.fingerprint_md5 }))
}

#[tauri::command]
pub fn key_deploy(
    app: AppHandle,
    ids: Vec<String>,
    passphrase: Option<String>,
    strict_host_key: Option<bool>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }

    let mut results = Vec::new();
    for id in &ids {
        let key = app
            .state::<AppState>()
            .db
            .get_key(id)
            .map_err(|e| e.to_string())?;
        let key = key.ok_or_else(|| format!("Key not found: {}", id))?;

        let key_data = load_private_key_data(&app, &key, &pw)?;
        let openssh_private = keys::export_private_key(
            &key_data,
            KeyFormat::OpenSsh,
            passphrase.as_deref().filter(|p| !p.is_empty()),
        )
        .map_err(|e| e.to_string())?;
        let openssh_public =
            keys::export_public_key(&key_data, KeyFormat::OpenSsh).map_err(|e| e.to_string())?;

        let result = SshService::deploy_key(
            &key.name,
            &openssh_private,
            &openssh_public,
            Some(&key.name),
            None,
            None,
            None,
            strict_host_key,
        )
        .map_err(|e| e.to_string())?;

        let mut updated = key.clone();
        updated.deployed = true;
        updated.deploy_path = Some(result.private_key_path.clone());
        updated.updated_at = chrono::Utc::now();
        app.state::<AppState>()
            .db
            .update_key(&updated)
            .map_err(|e| e.to_string())?;

        results.push(serde_json::json!({
            "id": id, "name": key.name, "file": result.private_key_path,
        }));
    }
    app.state::<AppState>().db.add_audit(
        "keys.deployed",
        None,
        &format!("{} key(s)", results.len()),
    )?;
    Ok(serde_json::json!({ "ok": true, "keys": results }))
}

#[tauri::command]
pub fn key_remove_deployed(app: AppHandle, id: String) -> CmdResult<serde_json::Value> {
    let key = app
        .state::<AppState>()
        .db
        .get_key(&id)
        .map_err(|e| e.to_string())?;
    let key = key.ok_or_else(|| "Key not found.".to_string())?;

    if let Some(deploy_path) = &key.deploy_path {
        let _ = fs::remove_file(deploy_path);
        let _ = fs::remove_file(format!("{}.pub", deploy_path));
    }
    let mut updated = key;
    updated.deployed = false;
    updated.deploy_path = None;
    updated.updated_at = chrono::Utc::now();
    app.state::<AppState>()
        .db
        .update_key(&updated)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

// ═════════════════════════════════════════════════════════════════════════════
//  CATEGORY commands + key↔category bridge
// ═════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn category_list(app: AppHandle) -> CmdResult<serde_json::Value> {
    let db = &app.state::<AppState>().db;
    let categories = db.list_categories().map_err(|e| e.to_string())?;
    let kc_map = db.all_key_categories().map_err(|e| e.to_string())?;
    let host_orphans = db
        .list_servers()
        .map_err(|e| e.to_string())?
        .iter()
        .any(|s| s.category_id.is_none());
    let orphans = db
        .list_keys_with_categories()
        .map_err(|e| e.to_string())?
        .iter()
        .any(|k| k.category_ids.is_empty());
    let map_for_js: serde_json::Map<String, serde_json::Value> = kc_map
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v)))
        .collect();
    Ok(serde_json::json!({
        "categories": categories,
        "allKeyCategories": serde_json::Value::Object(map_for_js),
        "orphans": orphans,
        "hostOrphans": host_orphans,
    }))
}

#[tauri::command]
pub fn category_create(
    app: AppHandle,
    name: String,
    parent_id: Option<String>,
    color: Option<String>,
    scope: Option<String>,
) -> CmdResult<db::Category> {
    let db = &app.state::<AppState>().db;
    let scope = scope.unwrap_or_else(|| "key".to_string());
    if scope != "key" && scope != "host" {
        return Err("Category scope must be key or host.".into());
    }
    if let Some(parent) = parent_id.as_deref() {
        if db
            .get_category(parent)
            .map_err(|e| e.to_string())?
            .map(|p| p.scope != scope)
            .unwrap_or(true)
        {
            return Err("A category parent must use the same key/host scope.".into());
        }
    }
    let now = chrono::Utc::now();
    // sort_index = max sibling + 1
    let max_si: i64 = db
        .list_categories()
        .map_err(|e| e.to_string())?
        .iter()
        .filter(|c| c.parent_id == parent_id && c.scope == scope)
        .map(|c| c.sort_index)
        .max()
        .unwrap_or(-1);
    let cat = db::Category {
        id: Uuid::new_v4().to_string(),
        name,
        parent_id,
        scope,
        color,
        sort_index: max_si + 1,
        created_at: now,
        updated_at: now,
    };
    db.insert_category(&cat).map_err(|e| e.to_string())?;
    db.add_audit(
        "category.created",
        None,
        &format!("{} ({})", cat.name, cat.id),
    )
    .map_err(|e| e.to_string())?;
    Ok(cat)
}

#[tauri::command]
pub fn category_rename(app: AppHandle, id: String, name: String) -> CmdResult<serde_json::Value> {
    let db = &app.state::<AppState>().db;
    let mut c = db
        .get_category(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Category not found.".to_string())?;
    c.name = name;
    c.updated_at = chrono::Utc::now();
    db.update_category(&c).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn category_reparent(
    app: AppHandle,
    id: String,
    new_parent_id: Option<String>,
    sort_index: Option<i64>,
) -> CmdResult<serde_json::Value> {
    let db = &app.state::<AppState>().db;
    let mut c = db
        .get_category(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Category not found.".to_string())?;
    // Cycle check: walk up from new_parent_id; reject if we encounter `id`.
    if let Some(np) = &new_parent_id {
        if np == &id {
            return Err("A category cannot be its own parent.".into());
        }
        let mut cur: Option<String> = Some(np.clone());
        let cats = db.list_categories().map_err(|e| e.to_string())?;
        let by_id: std::collections::HashMap<String, db::Category> =
            cats.into_iter().map(|c| (c.id.clone(), c)).collect();
        while let Some(cur_id) = cur {
            if cur_id == id {
                return Err("That move would create a cycle.".into());
            }
            cur = by_id.get(&cur_id).and_then(|c| c.parent_id.clone());
        }
    }
    if let Some(parent) = new_parent_id.as_deref() {
        if db
            .get_category(parent)
            .map_err(|e| e.to_string())?
            .map(|p| p.scope != c.scope)
            .unwrap_or(true)
        {
            return Err("A category cannot be moved across key/host scopes.".into());
        }
    }
    c.parent_id = new_parent_id;
    if let Some(si) = sort_index {
        c.sort_index = si;
    }
    c.updated_at = chrono::Utc::now();
    db.update_category(&c).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn category_delete(app: AppHandle, id: String) -> CmdResult<serde_json::Value> {
    let db = &app.state::<AppState>().db;
    let reassigned = db.delete_category(&id).map_err(|e| e.to_string())?;
    db.add_audit("category.deleted", None, &id)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true, "reassigned": reassigned }))
}

#[tauri::command]
pub fn key_set_categories(
    app: AppHandle,
    key_id: String,
    category_ids: Vec<String>,
) -> CmdResult<serde_json::Value> {
    let db = &app.state::<AppState>().db;
    // Validate every category exists and belongs to the key scope.
    let known: std::collections::HashSet<String> = db
        .list_categories()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|c| c.scope == "key")
        .map(|c| c.id)
        .collect();
    for cid in &category_ids {
        if !known.contains(cid) {
            return Err(format!("Unknown category: {cid}").into());
        }
    }
    db.set_key_categories(&key_id, &category_ids)
        .map_err(|e| e.to_string())?;
    db.add_audit(
        "key.categories_set",
        Some(&key_id),
        &category_ids.len().to_string(),
    )
    .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn key_create_with_categories(
    app: AppHandle,
    key_type: String,
    bits: Option<u32>,
    name: Option<String>,
    comment: Option<String>,
    category_ids: Option<Vec<String>>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let kt = KeyType::from_db_tag(&key_type).map_err(|e| e.to_string())?;
    let comment_str = comment.clone().unwrap_or_default();
    let name_str =
        name.unwrap_or_else(|| format!("{}-{}", key_type, &Uuid::new_v4().to_string()[..8]));
    // Names become Host aliases in ~/.ssh/config — reject anything that could
    // break out of a single Host token before it ever reaches the vault.
    keys::validate_key_name(&name_str)?;

    let key_data =
        keys::generate_key_pair(kt, bits, comment_str.clone()).map_err(|e| e.to_string())?;
    let public_openssh =
        keys::export_public_key(&key_data, KeyFormat::OpenSsh).map_err(|e| e.to_string())?;
    let fingerprint = keys::compute_fingerprint_sha256(&key_data.public_key);
    let sealed_private =
        crate::crypto::vault::seal(&pw, &key_data.private_key).map_err(|e| e.to_string())?;

    let cats = category_ids.unwrap_or_default();
    let valid_ids: std::collections::HashSet<String> = app
        .state::<AppState>()
        .db
        .list_categories()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|c| c.scope == "key")
        .map(|c| c.id)
        .collect();
    if cats.iter().any(|id| !valid_ids.contains(id)) {
        return Err("Keys can only use key categories.".into());
    }
    let key_record = KeyRecord {
        id: Uuid::new_v4().to_string(),
        name: name_str.clone(),
        key_type: kt.db_tag().to_string(),
        public_key: public_openssh,
        private_key_encrypted: sealed_private,
        fingerprint_sha256: fingerprint.clone(),
        fingerprint_md5: keys::compute_fingerprint_md5(&key_data.public_key),
        comment: comment_str,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        deployed: false,
        deploy_path: None,
        bitwarden_id: None,
        bitwarden_sync: false,
        bitwarden_revision_ts: None,
        bitwarden_updated_at: None,
        category_ids: Vec::new(),
    };

    let db = &app.state::<AppState>().db;
    db.insert_key_with_categories(&key_record, &cats)
        .map_err(|e| e.to_string())?;
    db.add_audit("keys.created", Some(&key_record.id), &name_str)?;
    Ok(serde_json::json!({ "ok": true, "id": key_record.id, "fingerprint": fingerprint }))
}

// ═════════════════════════════════════════════════════════════════════════════
//  SSH CONFIG commands
// ═════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn ssh_config_read() -> CmdResult<serde_json::Value> {
    let config_service = SshConfigService::new().map_err(|e| e.to_string())?;
    let config = config_service.read().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "hosts": config.hosts }))
}

#[tauri::command]
pub fn ssh_config_write(content: String) -> CmdResult<serde_json::Value> {
    let config = crate::config::SshConfig::parse(&content);
    let config_service = SshConfigService::new().map_err(|e| e.to_string())?;
    config_service.write(&config).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn ssh_config_list_hosts() -> CmdResult<serde_json::Value> {
    let config_service = SshConfigService::new().map_err(|e| e.to_string())?;
    let config = config_service.read().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "hosts": config.hosts }))
}

// ═════════════════════════════════════════════════════════════════════════════
//  BITWARDEN commands
// ═════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn bitwarden_get_config(app: AppHandle) -> CmdResult<serde_json::Value> {
    let config = app
        .state::<AppState>()
        .db
        .load_bitwarden_config()
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "server_url": config.server_url,
        "email": config.email,
        "folder_name": config.folder_name,
        "servers_folder_name": config.servers_folder_name,
        "last_sync": config.last_sync.map(|d| d.to_rfc3339()),
        "last_result": config.last_result.as_ref().and_then(|r| serde_json::from_str::<serde_json::Value>(r).ok()),
    }))
}

#[tauri::command]
pub fn bitwarden_save_config(
    app: AppHandle,
    server_url: String,
    email: String,
    master_password: Option<String>,
    folder_name: Option<String>,
    servers_folder_name: Option<String>,
) -> CmdResult<serde_json::Value> {
    if vault_password(&app)?.is_empty() {
        return Err("Vault is locked.".into());
    }
    let pw = vault_password(&app)?;

    // SSRF-validate the server URL at save time
    let validated_url =
        crate::bitwarden::ssrf::resolve_safe_server_url(&server_url).map_err(|e| e.to_string())?;

    let email = email.trim().to_string();
    if !email.contains('@') {
        return Err("Enter the account email of your vault.".into());
    }

    let db = &app.state::<AppState>().db;
    let mut config = db.load_bitwarden_config().map_err(|e| e.to_string())?;
    config.server_url = Some(validated_url);
    config.email = Some(email);
    if let Some(mp) = master_password.filter(|s| !s.is_empty()) {
        // Seal the Bitwarden master password with the SSHSpan vault password
        let sealed = crate::crypto::vault::seal(&pw, mp.as_bytes()).map_err(|e| e.to_string())?;
        config.master_password = Some(sealed);
    }
    config.folder_name = Some(folder_name.unwrap_or_else(|| "SSHSpan_Keys".to_string()));
    config.servers_folder_name =
        Some(servers_folder_name.unwrap_or_else(|| "SSHSpan_Servers".to_string()));
    if config.device_id.is_none() {
        config.device_id = Some(Uuid::new_v4().to_string());
    }
    db.save_bitwarden_config(&config)
        .map_err(|e| e.to_string())?;
    db.add_audit("sync.config", None, "saved")
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub async fn bitwarden_test_connection(app: AppHandle) -> CmdResult<serde_json::Value> {
    let config = app
        .state::<AppState>()
        .db
        .load_bitwarden_config()
        .map_err(|e| e.to_string())?;
    let server_url = config
        .server_url
        .ok_or_else(|| "No server URL configured.".to_string())?;
    let email = config
        .email
        .ok_or_else(|| "No email configured.".to_string())?;
    let mp_sealed = config
        .master_password
        .ok_or_else(|| "No master password stored. Re-save the sync settings.".to_string())?;

    let pw = vault_password(&app)?;
    let master_password =
        String::from_utf8(crate::crypto::vault::unseal(&pw, &mp_sealed).map_err(|_| {
            "Failed to decrypt stored Bitwarden password. Re-save the sync settings.".to_string()
        })?)
        .map_err(|_| "Stored Bitwarden password is corrupted.".to_string())?;

    let device_id = config
        .device_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let base_url =
        crate::bitwarden::ssrf::resolve_safe_server_url(&server_url).map_err(|e| e.to_string())?;

    let mut client =
        crate::bitwarden::BitwardenClient::new(&server_url, &email, &master_password, &device_id)
            .map_err(|e| e.to_string())?;
    let kdf = client.connect().await.map_err(|e| e.to_string())?;
    let remote = client.sync().await.map_err(|e| e.to_string())?;
    let ssh_count = remote
        .ciphers
        .iter()
        .filter(|c| c.cipher_type == 5 && c.deleted_date.is_none())
        .count();
    let folders: Vec<String> = remote
        .folders
        .iter()
        .map(|f| f.name.clone().unwrap_or_default())
        .collect();
    let account = remote
        .profile
        .as_ref()
        .and_then(|p| p.email.clone())
        .unwrap_or(email);
    client.close();

    Ok(serde_json::json!({
        "ok": true,
        "server": base_url,
        "account": account,
        "kdf": { "type": kdf.kdf_type, "iterations": kdf.iterations },
        "sshItemCount": ssh_count,
        "folders": folders,
    }))
}

#[tauri::command]
pub async fn bitwarden_sync(
    app: AppHandle,
    allow_remote_overwrite: Option<bool>,
) -> CmdResult<serde_json::Value> {
    let config = app
        .state::<AppState>()
        .db
        .load_bitwarden_config()
        .map_err(|e| e.to_string())?;
    let server_url = config
        .server_url
        .ok_or_else(|| "No server URL configured.".to_string())?;
    let email = config
        .email
        .ok_or_else(|| "No email configured.".to_string())?;
    let mp_sealed = config
        .master_password
        .ok_or_else(|| "No master password stored. Re-save the sync settings.".to_string())?;
    let folder_name = config
        .folder_name
        .unwrap_or_else(|| "SSHSpan_Keys".to_string());
    let servers_folder_name = config
        .servers_folder_name
        .clone()
        .unwrap_or_else(|| "SSHSpan_Servers".to_string());

    let pw = vault_password(&app)?;
    let master_password = String::from_utf8(
        crate::crypto::vault::unseal(&pw, &mp_sealed)
            .map_err(|_| "Failed to decrypt stored Bitwarden password.".to_string())?,
    )
    .map_err(|_| "Stored Bitwarden password is corrupted.".to_string())?;

    let device_id = config
        .device_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let db = app.state::<AppState>().db.clone();

    // run_sync is async (network + DB). The DB layer internally hops onto a
    // blocking thread when called from within the async runtime, so awaiting
    // it directly here is safe and does not nest a tokio runtime.
    let result = crate::bitwarden::sync::run_sync(
        &server_url,
        &email,
        &master_password,
        &device_id,
        &folder_name,
        &servers_folder_name,
        &db,
        &pw,
        allow_remote_overwrite.unwrap_or(false),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Store sync result
    let mut config = db.load_bitwarden_config().map_err(|e| e.to_string())?;
    config.last_sync = Some(chrono::Utc::now());
    config.last_result = Some(serde_json::to_string(&result).unwrap_or_default());
    db.save_bitwarden_config(&config)
        .map_err(|e| e.to_string())?;

    Ok(result)
}

// ═════════════════════════════════════════════════════════════════════════════
//  AUDIT LOG commands
// ═════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn audit_list(app: AppHandle, limit: Option<i64>) -> CmdResult<serde_json::Value> {
    let records = app
        .state::<AppState>()
        .db
        .list_audit(limit.unwrap_or(200))
        .map_err(|e| e.to_string())?;
    let rows: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "event": r.action,
                "keyId": r.key_id,
                "detail": r.details,
                "ts": r.timestamp.to_rfc3339(),
            })
        })
        .collect();
    Ok(serde_json::json!({ "rows": rows }))
}

// ═════════════════════════════════════════════════════════════════════════════
//  SETTINGS commands
// ═════════════════════════════════════════════════════════════════════════════

#[tauri::command]
pub fn settings_get(app: AppHandle) -> CmdResult<serde_json::Value> {
    let keys = [
        "autoLockMinutes",
        "sshKeysDir",
        "sshConfigPath",
        "theme",
        "confirmDelete",
        "autoUpdateCheck",
        "sftpParallel",
        "sftpShowHidden",
        "sftpDualPane",
        // FileZilla-parity transfer behavior (renderer mirror only works
        // in-session unless these load at startup).
        "sftpConflictUpload",
        "sftpConflictDownload",
        "sftpPreserveTs",
        "sftpCmpMode",
        "sftpResumeDefault",
        "terminalScrollback",
        "terminalBackspace",
        "terminalHomeEnd",
        "terminalAppCursorKeys",
        "terminalAppKeypad",
        "terminalBell",
        "terminalKeepaliveSeconds",
        "confirmMultiLinePaste",
    ];
    let mut settings = serde_json::Map::new();
    for key in &keys {
        if let Some(val) = app
            .state::<AppState>()
            .db
            .get_config(&format!("setting.{}", key))
            .map_err(|e| e.to_string())?
        {
            settings.insert(key.to_string(), serde_json::Value::String(val));
        }
    }
    Ok(serde_json::Value::Object(settings))
}

#[tauri::command]
pub fn settings_set(app: AppHandle, key: String, value: String) -> CmdResult<serde_json::Value> {
    if key.starts_with("bwSync.") {
        return Err("Bitwarden sync settings must be changed via the sync settings dialog.".into());
    }
    app.state::<AppState>()
        .db
        .set_config(&format!("setting.{}", key), &value)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

// ═════════════════════════════════════════════════════════════════════════════
//  SYSTEM commands
// ═════════════════════════════════════════════════════════════════════════════

/// Contract: `system_open_external` accepts ONLY a staged temp file under the
/// app's own `sshspan-edit` staging directory — the exact contract the
/// renderer's single call site uses (the local path returned by
/// `sftp_open_for_edit` / Send-to staging). URIs (`https:`, `file:`,
/// `ms-settings:`, …) are rejected, and so is every path outside the staging
/// dir: unrestricted `opener::open` would otherwise hand arbitrary schemes —
/// or ShellExecute any on-disk executable — to the OS shell. A single-letter
/// drive prefix (`C:\…` or `C:/…` on Windows) is a path, not a URI scheme.
#[tauri::command]
pub fn system_open_external(url: String) -> CmdResult<serde_json::Value> {
    let p = std::path::Path::new(&url);
    if !p.is_absolute() {
        return Err("system_open_external only accepts absolute local file paths.".into());
    }
    // Reject URI schemes: `^[a-zA-Z][a-zA-Z0-9+.-]*:` before any path
    // separator, except a 1-char drive letter (Windows `C:`).
    let prefix_before_sep = url
        .split(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or("");
    if let Some(scheme_end) = prefix_before_sep.find(':') {
        let scheme = &prefix_before_sep[..scheme_end];
        if scheme.len() != 1 || !scheme.chars().next().unwrap().is_ascii_alphabetic() {
            return Err("system_open_external does not accept URLs, only local file paths.".into());
        }
    }
    // Staging-dir containment: canonicalize both sides so `..` segments and
    // temp-dir aliases (8.3 names, subst drives) cannot smuggle a path past
    // the prefix check. The staged file always exists before the renderer is
    // handed its path, so a failed canonicalize here is a refusal.
    let staging = crate::sftp::edit_temp_dir();
    let staging_canon = staging
        .canonicalize()
        .map_err(|e| CmdError(format!("Staging directory unavailable: {e}")))?;
    let resolved = p
        .canonicalize()
        .map_err(|_| CmdError("system_open_external: path does not exist.".into()))?;
    if !resolved.starts_with(&staging_canon) {
        return Err(
            "system_open_external only opens files staged by SSHSpan.".into(),
        );
    }
    if !resolved.is_file() {
        return Err("system_open_external: path is not a regular file.".into());
    }
    opener::open(&resolved).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn system_show_item_in_folder(path: String) -> CmdResult<serde_json::Value> {
    let p = std::path::Path::new(&path);
    let dir = p.parent().unwrap_or(p);
    opener::open(dir).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

/// Open an http(s) URL from the terminal in the system browser. The xterm
/// web-links addon only linkifies http(s) URLs; this backend check enforces
/// the same scheme allowlist so no other scheme can ever reach the OS shell
/// from a terminal click, even if a future renderer change linkifies more.
#[tauri::command]
pub fn system_open_url(url: String) -> CmdResult<serde_json::Value> {
    let parsed = url::Url::parse(url.trim()).map_err(|_| CmdError("Not a valid URL.".into()))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err(CmdError("Only http(s) URLs can be opened.".into()));
    }
    opener::open(parsed.as_str()).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn system_select_file(app: AppHandle, title: Option<String>) -> CmdResult<serde_json::Value> {
    use tauri_plugin_dialog::DialogExt;
    let result = app
        .dialog()
        .file()
        .set_title(title.unwrap_or_else(|| "Select file".into()))
        .blocking_pick_file();
    match result {
        Some(path) => {
            let path_str = path.to_string();
            let content = fs::read_to_string(&path_str).map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "canceled": false, "path": path_str,
                "name": std::path::Path::new(&path_str).file_name().and_then(|n| n.to_str()).unwrap_or(""),
                "text": content
            }))
        }
        None => Ok(serde_json::json!({ "canceled": true })),
    }
}
