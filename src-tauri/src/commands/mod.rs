//! All Tauri IPC commands
//! Each handler wraps the backend services and returns Result<T, String>.
//! Frontend calls them via `invoke('command_name', { key: value })`.

pub mod server;
pub mod sftp;
pub mod terminal;
pub mod updater;

use std::fs;
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

fn vault_password(app: &AppHandle) -> CmdResult<String> {
    Ok(app
        .state::<VaultPasswordStore>()
        .get()
        .map(|s| s.to_string())
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
#[tauri::command]
pub fn vault_unlock(app: AppHandle, password: String) -> CmdResult<serde_json::Value> {
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
        app.state::<AppState>()
            .db
            .add_audit("vault.unlock_failed", None, "Failed attempt")
            .map_err(|e| e.to_string())?;
        return Err("Incorrect master password.".into());
    }
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
        return Err("Current master password is incorrect.".into());
    }

    let db = &app.state::<AppState>().db;
    let keys = db.list_keys().map_err(|e| e.to_string())?;
    let mut migrated = Vec::with_capacity(keys.len());
    for mut key in keys {
        let plaintext = match crate::crypto::vault::unseal(&current_password, &key.private_key_encrypted) {
            Ok(bytes) => bytes,
            Err(_e) if !key.private_key_encrypted.trim_start().starts_with('{') => {
                // Pre-vault-encryption records stored raw key bytes as text.
                key.private_key_encrypted.as_bytes().to_vec()
            }
            Err(e) => return Err(format!("Cannot re-encrypt key {}: {e}", key.id).into()),
        };
        key.private_key_encrypted =
            crate::crypto::vault::seal(&new_password, &plaintext).map_err(|e| e.to_string())?;
        key.updated_at = chrono::Utc::now();
        migrated.push(key);
    }

    let hashed = hash_master_password(&new_password).map_err(CmdError::from)?;
    for key in &migrated {
        db.update_key(key).map_err(|e| e.to_string())?;
    }
    db.set_config(MASTER_HASH_KEY, &hashed)
        .map_err(|e| e.to_string())?;
    let reencrypted = migrated.len() as u32;
    db.add_audit(
        "vault.password_changed",
        None,
        &format!("Re-encrypted {reencrypted} key(s)"),
    )
    .map_err(|e| e.to_string())?;
    app.state::<VaultPasswordStore>().set(new_password);
    Ok(serde_json::json!({ "ok": true, "reencrypted": reencrypted }))
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
        let key_record = KeyRecord {
            id: item
                .get("id")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            name: item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("imported")
                .to_string(),
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
    // material and saved server passwords with the current one.
    if reused_backup_password {
        let bp = backup_password.as_deref().unwrap_or_default().to_string();
        if let Some(arr) = data.get_mut("keys").and_then(|v| v.as_array_mut()) {
            for k in arr.iter_mut() {
                if let Some(blob) = k
                    .get("private_key_encrypted")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                {
                    if let Ok(plain) = crate::crypto::vault::unseal(&bp, &blob) {
                        if let Ok(resealed) = crate::crypto::vault::seal(&pw, &plain) {
                            k["private_key_encrypted"] = serde_json::json!(resealed);
                        }
                    }
                }
            }
        }
        if let Some(arr) = data.get_mut("servers").and_then(|v| v.as_array_mut()) {
            for sv in arr.iter_mut() {
                if let Some(blob) = sv
                    .get("saved_password")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                {
                    if let Ok(plain) = crate::crypto::vault::unseal(&bp, &blob) {
                        if let Ok(resealed) = crate::crypto::vault::seal(&pw, &plain) {
                            sv["saved_password"] = serde_json::json!(resealed);
                        }
                    }
                }
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
    Ok(
        serde_json::json!({ "ok": true, "counts": counts, "passwordReLinked": reused_backup_password }),
    )
}

// ─── File save helpers (backup export / generic) ───────────────────────────

/// Native save-file dialog; returns the chosen path (or canceled).
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
        Some(path) => Ok(serde_json::json!({ "canceled": false, "path": path.to_string() })),
        None => Ok(serde_json::json!({ "canceled": true })),
    }
}

/// Write UTF-8 text to an absolute path (used for vault backup export).
#[tauri::command]
pub fn system_write_text_file(path: String, contents: String) -> CmdResult<serde_json::Value> {
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&path, contents).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
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

    if format == "public" || format == "authorized_keys" {
        return Ok(serde_json::json!({ "data": key.public_key }));
    }

    let key_data = load_private_key_data(&app, &key, &pw)?;
    let pass = passphrase.as_deref().filter(|p| !p.is_empty());

    let data = match format.as_str() {
        "openssh-private" => keys::export_private_key(&key_data, KeyFormat::OpenSsh, pass),
        "pkcs8" | "pkcs8-encrypted" => keys::export_private_key(&key_data, KeyFormat::Pkcs8, pass),
        "ppk" => keys::export_private_key(&key_data, KeyFormat::Putty, pass),
        "public-pem" => keys::export_public_key(&key_data, KeyFormat::Pkcs8),
        _ => return Err(CmdError(format!("Unknown export format: {}", format)).into()),
    }
    .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({ "data": data }))
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
    }))
}

#[tauri::command]
pub fn category_create(
    app: AppHandle,
    name: String,
    parent_id: Option<String>,
    color: Option<String>,
) -> CmdResult<db::Category> {
    let db = &app.state::<AppState>().db;
    let now = chrono::Utc::now();
    // sort_index = max sibling + 1
    let max_si: i64 = db
        .list_categories()
        .map_err(|e| e.to_string())?
        .iter()
        .filter(|c| c.parent_id == parent_id)
        .map(|c| c.sort_index)
        .max()
        .unwrap_or(-1);
    let cat = db::Category {
        id: Uuid::new_v4().to_string(),
        name,
        parent_id,
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
    // Validate every category exists (otherwise sync / typos could create dangling join rows).
    let known: std::collections::HashSet<String> = db
        .list_categories()
        .map_err(|e| e.to_string())?
        .into_iter()
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

    let key_data =
        keys::generate_key_pair(kt, bits, comment_str.clone()).map_err(|e| e.to_string())?;
    let public_openssh =
        keys::export_public_key(&key_data, KeyFormat::OpenSsh).map_err(|e| e.to_string())?;
    let fingerprint = keys::compute_fingerprint_sha256(&key_data.public_key);
    let sealed_private =
        crate::crypto::vault::seal(&pw, &key_data.private_key).map_err(|e| e.to_string())?;

    let cats = category_ids.unwrap_or_default();
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
pub async fn bitwarden_sync(app: AppHandle) -> CmdResult<serde_json::Value> {
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

#[tauri::command]
pub fn system_open_external(url: String) -> CmdResult<serde_json::Value> {
    opener::open(&url).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn system_show_item_in_folder(path: String) -> CmdResult<serde_json::Value> {
    let p = std::path::Path::new(&path);
    let dir = p.parent().unwrap_or(p);
    opener::open(dir).map_err(|e| e.to_string())?;
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
