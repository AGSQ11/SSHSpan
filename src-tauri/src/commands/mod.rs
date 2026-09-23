//! All Tauri IPC commands
//! Each handler wraps the backend services and returns Result<T, String>.
//! Frontend calls them via `invoke('command_name', { key: value })`.

pub mod server;
pub mod sftp;
pub mod terminal;
pub mod updater;

use directories::ProjectDirs;
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

/// In-memory vault password accessor. Returns the password wrapped in
/// `Zeroizing` so every per-command copy is wiped on drop, matching the
/// store's own hygiene (the store holds the canonical `Zeroizing` copy; each
/// command previously cloned a plain `String` that lived until free).
pub(crate) fn vault_password(app: &AppHandle) -> CmdResult<zeroize::Zeroizing<String>> {
    Ok(app
        .state::<VaultPasswordStore>()
        .get()
        .map(zeroize::Zeroizing::new)
        .unwrap_or_default())
}

/// Monotonic vault generation, bumped at the very start of every lock.
///
/// Long-running secret-consuming operations (SSH connect, SFTP open, key
/// export, Bitwarden sync) capture the generation BEFORE their first network
/// await and re-check it at every secret-consuming/committing boundary. A
/// lock bumps the counter BEFORE tearing anything down, so an in-progress
/// operation that crosses the lock observes a changed generation and aborts
/// instead of registering a session or exporting a secret into the locked
/// state. This closes the race the audit's F2 describes: clearing the
/// password store alone does not revoke copies a pending task already holds.
pub struct VaultGeneration(std::sync::atomic::AtomicU64);

impl VaultGeneration {
    pub fn new() -> Self {
        Self(std::sync::atomic::AtomicU64::new(0))
    }
    /// Current generation value.
    pub fn current(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// Advance to a new generation (called on lock, before teardown).
    pub fn bump(&self) -> u64 {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
    }
    /// True when `captured` is still the current generation AND the vault is
    /// unlocked. Both halves are required: a captured generation from a
    /// previous unlock session must never authorize a later one.
    pub fn is_current(&self, captured: u64, unlocked: bool) -> bool {
        unlocked && self.current() == captured
    }
}

/// Capture the current generation for a pending secret-consuming operation.
/// Returns the generation only when the vault is unlocked; callers pair it
/// with [`VaultGeneration::is_current`] / [`require_generation_current`].
pub fn capture_vault_generation(app: &AppHandle) -> CmdResult<u64> {
    if vault_password(app)?.is_empty() {
        return Err(CmdError("Vault is locked.".into()));
    }
    Ok(app.state::<VaultGeneration>().current())
}

/// Abort a pending operation if the vault was locked (generation bumped) or
/// is now locked since `captured` was taken. Called at the point a pending
/// operation is about to commit a side effect (register a session, write an
/// export, apply a sync) after one or more awaits.
pub fn require_generation_current(app: &AppHandle, captured: u64) -> CmdResult<()> {
    let unlocked = !vault_password(app)?.is_empty();
    if !app
        .state::<VaultGeneration>()
        .is_current(captured, unlocked)
    {
        return Err(CmdError(
            "Vault was locked while the operation was in progress.".into(),
        ));
    }
    Ok(())
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
/// in-memory state - but also loses nothing, since there is nothing to gain
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
        // Legacy plaintext verifier (pre-Argon2id vaults): compare in constant
        // time - a short-circuiting `==` on a password would leak the stored
        // verifier byte-by-byte through timing. This path disappears on the
        // first successful unlock, which upgrades it to Argon2id.
        let ok = crate::crypto::utils::constant_time_eq(stored.as_bytes(), password.as_bytes());
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
    lock_vault_internal(&app);
    Ok(serde_json::json!({ "ok": true }))
}

/// Shared teardown for manual lock and the backend idle watchdog: kill every
/// live interactive SSH session BEFORE clearing the master password; sessions
/// that survive into a locked vault would otherwise be using unsealed key
/// material with no way to re-derive it.
pub(crate) fn lock_vault_internal(app: &AppHandle) {
    // Bump the generation FIRST, before any teardown. An in-progress connect,
    // SFTP open, export, or sync that captured the old generation observes the
    // bump at its next commit boundary and aborts, so a pending operation can
    // never register a session or spend a secret into the now-locked vault.
    app.state::<VaultGeneration>().bump();
    app.state::<std::sync::Arc<crate::ssh_client::SessionRegistry>>()
        .kill_all();
    app.state::<crate::sftp::EditRegistry>().stop_all();
    app.state::<crate::sftp::KeepaliveRegistry>().stop_all();
    // SFTP runs on its own channel per session, so killing the shell registry
    // does not close it. Without this the registry kept live handles and every
    // sftp_* command carried on working against a "locked" vault - and the
    // transfer queue carried on writing files.
    app.state::<crate::sftp::SftpRegistry>().clear();
    crate::sftp::queue::pause_all(app);
    app.state::<crate::assistant::AssistantLevels>().clear();
    // MCP sessions die with the vault too: HTTP DELETE with Mcp-Session-Id
    // (405 is valid per spec - ignored), session + status state dropped. The
    // decrypted secrets only ever lived in command frames, which end here.
    crate::assistant::mcp::teardown_all(app);
    app.state::<VaultPasswordStore>().clear();
    let _ = app.state::<AppState>().db.add_audit("vault.lock", None, "");
}

/// Last time the renderer signalled it is alive (`heartbeat` IPC). The
/// backend idle watchdog uses it to enforce `autoLockMinutes` even when the
/// renderer cannot - a hung or crashed webview stops heartbeating, and the
/// vault locks on the Rust side instead of staying unsealed forever.
pub struct ActivityTracker(std::sync::Mutex<std::time::Instant>);

impl ActivityTracker {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(std::time::Instant::now()))
    }
    pub fn touch(&self) {
        *self.0.lock().unwrap() = std::time::Instant::now();
    }
    pub fn elapsed(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(*self.0.lock().unwrap())
    }
}

#[tauri::command]
pub fn heartbeat(app: AppHandle) -> CmdResult<serde_json::Value> {
    app.state::<ActivityTracker>().touch();
    Ok(serde_json::json!({ "ok": true }))
}

/// Background task enforcing the auto-lock setting on the Rust side. The
/// renderer's own timer remains the primary UX path; this watchdog covers
/// the case where the renderer can no longer act (hung/crashed webview,
/// closed window with a tray-resident process). Locks only when the vault is
/// currently unlocked; `autoLockMinutes` of 0/absent disables it, matching
/// the renderer's semantics.
pub(crate) fn spawn_auto_lock_watchdog(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let mins: i64 = app
                .state::<AppState>()
                .db
                .get_config("setting.autoLockMinutes")
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15);
            if mins <= 0 {
                continue;
            }
            let unlocked = app.state::<VaultPasswordStore>().get().is_some();
            if !unlocked {
                continue;
            }
            if app.state::<ActivityTracker>().elapsed()
                >= std::time::Duration::from_secs((mins as u64).saturating_mul(60))
            {
                log::info!("[sshspan-vault] backend idle watchdog locked the vault after {mins} min without renderer activity");
                lock_vault_internal(&app);
                // Best effort: tell the renderer so its UI reflects the lock.
                let _ = tauri::Emitter::emit(&app, "vault-locked-by-watchdog", ());
            }
        }
    });
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
    // The current-password check is a password guess too - throttle it with
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
    let mut migration = migrate_vault_records(keys, servers, &current_password, &new_password)?;

    // The stored Bitwarden master password is sealed with the SAME vault
    // password, so it must be re-sealed too - otherwise sync silently strands
    // on the old password after a rotation (F6). Re-seal it in memory here so
    // it commits in the same transaction below. A missing/unconfigured
    // credential is fine (None); an unsealable one aborts the whole change.
    let bw_config = db.load_bitwarden_config().map_err(|e| e.to_string())?;
    migration.bitwarden_master_password = match bw_config.master_password.as_ref() {
        Some(sealed) => {
            let plain = crate::crypto::vault::unseal(&current_password, sealed)
                .map_err(|e| format!("Cannot re-encrypt the stored Bitwarden password: {e}"))?;
            Some(crate::crypto::vault::seal(&new_password, &plain).map_err(CmdError::from)?)
        }
        None => None,
    };

    // The AI assistant's provider API key is sealed with the same vault
    // password; it must rotate in the same transaction or every assistant
    // call fails at unseal after the change while has_api_key still says
    // true. Same rule as the Bitwarden credential above: missing is fine,
    // unsealable aborts the whole change.
    let assistant_config = db.load_assistant_config().map_err(|e| e.to_string())?;
    migration.assistant_api_key = match assistant_config.api_key.as_ref() {
        Some(sealed) => {
            let plain = crate::crypto::vault::unseal(&current_password, sealed)
                .map_err(|e| format!("Cannot re-encrypt the stored AI assistant API key: {e}"))?;
            Some(crate::crypto::vault::seal(&new_password, &plain).map_err(CmdError::from)?)
        }
        None => None,
    };

    // MCP server auth secrets are sealed with the same vault password; each
    // must rotate in the same transaction or every MCP call fails at unseal
    // after the change. Same rule as the assistant key: missing is fine, an
    // unsealable blob aborts the whole change (in memory, before anything
    // commits). Per-tool pin state rides along untouched - re-approving
    // tools after a password change would be noise, and pin hashes are not
    // password-derived.
    let mcp_servers = db.list_mcp_servers().map_err(|e| e.to_string())?;
    let mut rotated_mcp = Vec::with_capacity(mcp_servers.len());
    for mut record in mcp_servers {
        if let Some(sealed) = record.auth_secret.as_ref() {
            let plain = crate::crypto::vault::unseal(&current_password, sealed).map_err(|e| {
                format!(
                    "Cannot re-encrypt the MCP auth secret for '{}': {e}",
                    record.name
                )
            })?;
            record.auth_secret =
                Some(crate::crypto::vault::seal(&new_password, &plain).map_err(CmdError::from)?);
        }
        rotated_mcp.push(record);
    }

    let hashed = hash_master_password(&new_password).map_err(CmdError::from)?;
    // Single transaction: every re-sealed record, the Bitwarden credential,
    // and the verifier commit together or not at all (F3). A crash or I/O
    // error part-way rolls back to the complete old state instead of leaving
    // the vault split across two passwords.
    db.apply_vault_rotation(
        &migration.keys,
        &migration.servers,
        migration.bitwarden_master_password.as_deref(),
        migration.assistant_api_key.as_deref(),
        &rotated_mcp,
        &hashed,
    )
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
    /// Re-sealed Bitwarden master password (None when sync is not configured).
    /// Filled in by the caller after `migrate_vault_records` runs.
    bitwarden_master_password: Option<String>,
    /// Re-sealed AI assistant API key (None when the assistant is not
    /// configured). Filled in by the caller, same rule as above.
    assistant_api_key: Option<String>,
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
    // must be re-sealed too - otherwise every stored server password becomes
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
        bitwarden_master_password: None,
        assistant_api_key: None,
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

    /// A corrupted/unopenable sealed value must abort the whole migration -
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

        // Nothing was persisted - the stored blob still fails with the old pw.
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

    /// Regression for the Windows verbatim-prefix guard bypass: a file that
    /// ALREADY EXISTS inside the app data dir canonicalizes to a
    /// `\\?\`-prefixed path under std::fs::canonicalize, which never matched
    /// the plain app-data prefix - the guard fired only for not-yet-existing
    /// paths. The anchor must hold for existing targets too (this is the
    /// vault-overwrite case). Writes a throwaway file inside the app data
    /// dir and removes it again.
    #[test]
    fn validate_export_path_rejects_existing_app_data_file() {
        use directories::ProjectDirs;
        let dir = ProjectDirs::from("org", "sshspan", "SSHSpan")
            .expect("project dirs")
            .data_dir()
            .to_path_buf();
        let _ = std::fs::create_dir_all(&dir);
        let target = dir.join("sshspan-guard-test.json");
        std::fs::write(&target, b"").expect("create guard-test file");
        let result = validate_export_path(&target.display().to_string());
        let _ = std::fs::remove_file(&target);
        assert!(
            result.is_err(),
            "an existing file inside the app data dir must be rejected"
        );
    }

    /// The app data dir itself is not a legal write target.
    #[test]
    fn validate_export_path_rejects_app_data_dir_itself() {
        use directories::ProjectDirs;
        let app_data = ProjectDirs::from("org", "sshspan", "SSHSpan")
            .expect("project dirs")
            .data_dir()
            .to_path_buf();
        assert!(validate_export_path(&app_data.display().to_string()).is_err());
    }

    /// System-directory protection must also cover paths that do not exist
    /// yet: the old Unix branch skipped the check entirely when
    /// canonicalize() failed on the not-yet-created path.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn is_system_path_covers_nonexistent_paths() {
        assert!(is_system_path(std::path::Path::new("/etc/sshspan-new")));
        assert!(is_system_path(std::path::Path::new(
            "/etc/does-not-exist/nested/file"
        )));
        assert!(!is_system_path(std::path::Path::new(
            "/etc-backup/sshspan-new"
        )));
    }

    /// Windows: the literal branches still match, and a non-existent path
    /// under the Windows directory is protected by the literal fallback.
    #[cfg(target_os = "windows")]
    #[test]
    fn is_system_path_covers_nonexistent_paths() {
        assert!(is_system_path(std::path::Path::new(
            "C:\\Windows\\sshspan-new"
        )));
        assert!(is_system_path(std::path::Path::new(
            "C:\\Windows\\System32\\x.dll"
        )));
        assert!(is_system_path(std::path::Path::new("C:\\Program Files\\x")));
        assert!(!is_system_path(std::path::Path::new(
            "C:\\Windows-backup\\x"
        )));
    }

    /// An absolute path outside the app data / system dirs is accepted. The
    /// fixture is anchored at the current directory rather than temp_dir:
    /// on some machines %TEMP% itself lives under the Windows directory,
    /// which the (correct) system-dir guard rejects.
    #[test]
    fn validate_export_path_accepts_good_path() {
        let good = std::env::current_dir()
            .expect("cwd")
            .join("sshspan-export-test.txt");
        assert!(validate_export_path(&good.display().to_string()).is_ok());
    }

    /// Every key the renderer writes through `settings_set` must be in the
    /// allowlist, or the write is rejected and - because the call sites catch -
    /// silently resets on the next launch. `sftpShowOwnerCols` shipped in that
    /// exact state: the Columns toggle wrote it, the backend refused it, and
    /// nothing surfaced the error.
    #[test]
    fn settings_allowlist_covers_every_renderer_written_key() {
        let renderer = [
            "sftpShowOwnerCols",
            "sftpParallel",
            "sftpShowHidden",
            "sftpDualPane",
            "sftpConflictUpload",
            "sftpConflictDownload",
            "sftpPreserveTs",
            "sftpCmpMode",
            "sftpResumeDefault",
            "sftpMaxBps",
            "sftpVerifyTransfers",
            "autoLockMinutes",
            "autoUpdateCheck",
            "confirmDelete",
            "confirmMultiLinePaste",
            "uiScale",
            "terminalScrollback",
            "terminalBell",
            "terminalBackspace",
            "terminalHomeEnd",
            "terminalAppCursorKeys",
            "terminalAppKeypad",
        ];
        for key in renderer {
            assert!(
                SETTINGS_KEYS.contains(&key),
                "{key} is written by the renderer but absent from SETTINGS_KEYS"
            );
        }
    }

    /// The per-server local-directory family is addressed by prefix, so it is
    /// valid even though it is not in the fixed list - and a bare prefix with
    /// no server id is not.
    #[test]
    fn settings_allowlist_accepts_prefixed_local_dir_family() {
        let known = |key: &str| {
            SETTINGS_KEYS.contains(&key)
                || (key.starts_with(SFTP_LOCAL_DIR_PREFIX)
                    && key.len() > SFTP_LOCAL_DIR_PREFIX.len())
        };
        assert!(known("sftpLocalDir:server-1"));
        assert!(!known(SFTP_LOCAL_DIR_PREFIX));
        assert!(!known("bwSync.masterPassword"));
    }

    /// A backup taken by an older build can carry keys this build no longer
    /// recognises. They must be dropped before `restore_backup` writes every
    /// key of the payload into the `config` table, which also holds the
    /// Bitwarden secrets.
    #[test]
    fn backup_settings_sanitizer_drops_unknown_keys() {
        let mut settings = serde_json::Map::new();
        settings.insert("sftpParallel".into(), serde_json::json!("4"));
        settings.insert("sftpLocalDir:server-1".into(), serde_json::json!("/tmp"));
        // Removed in this change, and a key that was never a setting at all.
        settings.insert("theme".into(), serde_json::json!("dark"));
        settings.insert("bwSync.masterPassword".into(), serde_json::json!("secret"));

        let dropped = sanitize_backup_settings(&mut settings);

        assert_eq!(dropped, 2);
        assert!(settings.contains_key("sftpParallel"));
        assert!(settings.contains_key("sftpLocalDir:server-1"));
        assert!(!settings.contains_key("theme"));
        assert!(!settings.contains_key("bwSync.masterPassword"));
    }
}

/// NOT REGISTERED in `generate_handler!`, deliberately.
///
/// It returns every key's `private_key_encrypted` blob to the webview. The
/// blobs are sealed with the master password, so this is not plaintext key
/// material - but it hands a compromised renderer the entire keystore to
/// attack offline, and nothing in the shipped UI ever called it. Registering
/// it again needs a reason and a review; `vault_backup_create` is the
/// supported export path and keeps the material in the backend.
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

/// NOT REGISTERED in `generate_handler!`, deliberately - the counterpart to
/// `vault_export`, and likewise never called by the shipped UI. It writes
/// caller-supplied key records straight into the vault; `vault_backup_restore`
/// is the reviewed import path.
#[tauri::command]
pub fn vault_import(app: AppHandle, keys: Vec<serde_json::Value>) -> CmdResult<serde_json::Value> {
    let _pw = vault_password(&app)?;
    let mut imported = 0;
    for item in &keys {
        // Imported names become Host aliases in ~/.ssh/config - a name that
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
    // MCP servers travel with the backup (sealed auth secret included, same
    // vault password as everything else). They come back INERT on restore
    // (confirmed=false, all tools disabled) - see `restore_backup`.
    let mcp_servers = db.list_mcp_servers().map_err(|e| e.to_string())?;

    let settings = collect_settings(&db)?;

    let payload = serde_json::json!({
        "keys": keys,
        "categories": categories,
        "servers": servers,
        "known_hosts": known_hosts,
        "settings": settings,
        "mcpServers": mcp_servers,
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
    // being imported: importing it would strand it - unopenable once the old
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
                        // password only, which is being discarded - excluded.
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
        // MCP auth secrets get the same treatment. The entry itself is kept
        // (and restored inert regardless); only a stranded sealed secret is
        // dropped so it cannot outlive the backup password that could open
        // it. Env-var-sourced auth stores no secret, so there is nothing to
        // re-seal there.
        if let Some(arr) = data.get_mut("mcpServers").and_then(|v| v.as_array_mut()) {
            for m in arr.iter_mut() {
                let Some(blob) = m
                    .get("auth_secret")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    continue;
                };
                if let Ok(plain) = crate::crypto::vault::unseal(&bp, &blob) {
                    if let Ok(resealed) = crate::crypto::vault::seal(&pw, &plain) {
                        m["auth_secret"] = serde_json::json!(resealed);
                        continue;
                    }
                }
                if crate::crypto::vault::unseal(&pw, &blob).is_ok() {
                    continue;
                }
                m["auth_secret"] = serde_json::Value::Null;
                reseal_failures += 1;
            }
        }
    }

    // Prune settings the allowlist does not recognise BEFORE the payload
    // reaches `restore_backup`, which writes each key straight into the
    // `config` table (the table that also holds the Bitwarden secrets) inside
    // its transaction. An older build's backup is the realistic source of an
    // unknown key here.
    let dropped_settings = data
        .get_mut("settings")
        .and_then(|v| v.as_object_mut())
        .map(sanitize_backup_settings)
        .unwrap_or(0);

    let counts = app
        .state::<AppState>()
        .db
        .restore_backup(&data)
        .map_err(|e| e.to_string())?;
    let _ =
        app.state::<AppState>()
            .db
            .add_audit("vault.backup_restored", None, &counts.to_string());
    if dropped_settings > 0 {
        let _ = app.state::<AppState>().db.add_audit(
            "vault.restore_settings_skipped",
            None,
            &format!("{dropped_settings} unknown setting(s) ignored on restore"),
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
/// NOTE: async on purpose. Tauri runs a synchronous command on the MAIN
/// thread, and tauri-plugin-dialog's `blocking_*` helpers deadlock when
/// called from there - the window stops responding and never repaints, which
/// is what "Create Backup freezes the whole program" was. An async command
/// runs on the async runtime instead, where blocking for the user's answer is
/// safe.
pub async fn system_pick_save_path(
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
/// locations (Startup folders, shell rc files, ...) - only paths a human
/// approved in the OS dialog.
pub struct DialogPathStore(std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>);

/// How long a dialog-approved path stays writable. The backup-export flow
/// uses the path within seconds of picking it, so a generous window covers
/// retries without leaving the grant alive for the whole session.
const DIALOG_PATH_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

impl DialogPathStore {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(std::collections::HashMap::new()))
    }
    fn allow(&self, path: &str) {
        let mut guard = self.0.lock().unwrap();
        let now = std::time::Instant::now();
        // Prune expired entries so the map cannot grow unboundedly.
        guard.retain(|_, granted| now.duration_since(*granted) < DIALOG_PATH_TTL);
        guard.insert(path.to_string(), now);
    }
    /// Consume a grant: a dialog pick authorises exactly ONE write.
    ///
    /// SECURITY: checking without consuming meant a path approved for a
    /// legitimate backup export stayed writable for the rest of the grant
    /// window, so a compromised renderer could wait for a real export and then
    /// rewrite that file with contents of its own. The grant is removed
    /// whether or not it had expired, so a stale entry cannot be retried.
    fn consume(&self, path: &str) -> bool {
        let mut guard = self.0.lock().unwrap();
        match guard.remove(path) {
            Some(granted) => std::time::Instant::now().duration_since(granted) < DIALOG_PATH_TTL,
            None => false,
        }
    }
}

/// Write UTF-8 text to an absolute path (used for vault backup export). The
/// path must have been returned by `system_pick_save_path` in this session
/// AND must pass the absolute/app-data/system checks - both gates, so the
/// write target is always a human-approved dialog choice.
///
/// The write goes through `write_secret_file` (0600 at create time, replace
/// rather than truncate, fail-closed Windows ACL). Its only caller exports
/// the vault backup, which carries every private key and saved server
/// password sealed under the master password plus plaintext structure -
/// server names, hosts, usernames. `fs::write` used to leave that at
/// `0666 & ~umask`, i.e. 0644 on a normal desktop and 0664 (group-WRITABLE)
/// under umask 002, so any other local account could copy it and attack the
/// Argon2id blob offline. The helper for exactly this already existed and
/// this path simply was not using it.
#[tauri::command]
pub fn system_write_text_file(
    app: AppHandle,
    path: String,
    contents: String,
) -> CmdResult<serde_json::Value> {
    validate_export_path(&path)?;
    if !app.state::<DialogPathStore>().consume(&path) {
        return Err("Write target must be a path chosen in a save dialog this session.".into());
    }
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    crate::ssh::write_secret_file(std::path::Path::new(&path), contents.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

/// Component-wise, path-aware prefix test used by every local-target guard.
/// On Windows the comparison is CASE-INSENSITIVE (NTFS/ReFS preserve case
/// but ignore it, so `c:\users\...` and `C:\Users\...` are the same
/// directory - a case-sensitive `starts_with` would let a hostile renderer
/// bypass the app-data guard by merely changing case). On Unix it is
/// `Path::starts_with` verbatim.
#[cfg(target_os = "windows")]
pub(crate) fn path_starts_with(p: &std::path::Path, base: &std::path::Path) -> bool {
    let lower_components = |path: &std::path::Path| -> Vec<String> {
        path.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let (pc, bc) = (lower_components(p), lower_components(base));
    pc.len() >= bc.len() && pc[..bc.len()] == bc[..]
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn path_starts_with(p: &std::path::Path, base: &std::path::Path) -> bool {
    p.starts_with(base)
}

/// Reject paths that are not absolute or that would write into the app data
/// directory / system directories. Used by the limited number of commands that
/// accept a renderer-supplied local filesystem target.
fn validate_export_path(path: &str) -> CmdResult<()> {
    let p = std::path::Path::new(path);
    if !p.is_absolute() {
        return Err("Path must be absolute.".into());
    }

    // dunce::canonicalize (not std::fs::canonicalize): on Windows std returns
    // a `\\?\`-prefixed path, and `Path::starts_with` compares prefix
    // components exactly, so a verbatim path NEVER matches the plain
    // `C:\Users\...` app-data dir - the guard would only fire for paths that
    // do not exist yet. dunce returns the plain form for existing paths, so
    // both the exists and not-exists cases compare against the same shape.
    let normalized = dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());

    if let Some(app_data) = ProjectDirs::from("org", "sshspan", "SSHSpan") {
        let app_data_dir = app_data.data_dir();
        // Normalize the anchor the same way so a junctioned/symlinked app-data
        // dir still matches.
        let app_data_norm =
            dunce::canonicalize(app_data_dir).unwrap_or_else(|_| app_data_dir.to_path_buf());
        if path_starts_with(&normalized, &app_data_norm)
            || path_starts_with(&normalized, app_data_dir)
        {
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
    // Same normalization rule as validate_export_path: canonicalize when the
    // path exists, keep the literal form when it does not, never carry the
    // `\\?\` verbatim prefix into the comparison. Comparisons are
    // component-wise (`Path::starts_with`) so e.g. "C:\Program Filesx" cannot
    // prefix-match "C:\Program Files".
    let normalized = dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());

    let mut protected: Vec<std::path::PathBuf> = vec![
        std::path::PathBuf::from("C:\\Windows"),
        std::path::PathBuf::from("C:\\Program Files"),
        std::path::PathBuf::from("C:\\Program Files (x86)"),
    ];
    for var in [
        "WINDIR",
        "ProgramFiles",
        "ProgramW6432",
        "ProgramFiles(x86)",
    ] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                protected.push(std::path::PathBuf::from(v));
            }
        }
    }
    protected
        .iter()
        .map(|d| dunce::canonicalize(d).unwrap_or_else(|_| d.clone()))
        .any(|d| path_starts_with(&normalized, &d))
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn is_system_path(p: &std::path::Path) -> bool {
    // dunce::canonicalize on Unix is std::fs::canonicalize, but keeping the
    // same fall-through shape as the Windows branch: a path that does not
    // exist (yet) is checked in its literal form instead of skipping the
    // check entirely.
    let normalized = dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let system_dirs = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/etc",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
    ];
    system_dirs
        .iter()
        .map(std::path::Path::new)
        .any(|d| normalized.starts_with(d))
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
    // Names become Host aliases in ~/.ssh/config - reject anything that could
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
    // Names become Host aliases in ~/.ssh/config - reject anything that could
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
/// native save dialog - the key material never crosses the IPC boundary into
/// the renderer. The file is written 0600 from the first byte on Unix; on
/// Windows the current-user-only ACL is attempted and a failure is logged
/// (exports may legitimately target volumes that cannot store ACLs, unlike
/// the deploy destination, where a restriction failure is fatal).
#[tauri::command]
/// NOTE: async on purpose. Tauri runs a synchronous command on the MAIN
/// thread, and tauri-plugin-dialog's `blocking_*` helpers deadlock when
/// called from there - the window stops responding and never repaints, which
/// is what "Create Backup freezes the whole program" was. An async command
/// runs on the async runtime instead, where blocking for the user's answer is
/// safe.
pub async fn key_export_to_file(
    app: AppHandle,
    id: String,
    format: String,
    passphrase: Option<String>,
) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    // Capture the generation before the (decrypt → dialog → write) sequence:
    // the save dialog blocks on user input for an unbounded time, during
    // which the vault could be locked. Re-checked before the write below.
    let generation = capture_vault_generation(&app)?;
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
    // Zeroizing: the serialized private key is wiped from this frame once
    // written, not left as freed heap (secret-wiping hardening).
    let data = zeroize::Zeroizing::new(
        match format.as_str() {
            "openssh-private" => keys::export_private_key(&key_data, KeyFormat::OpenSsh, pass),
            "pkcs8" | "pkcs8-encrypted" => {
                keys::export_private_key(&key_data, KeyFormat::Pkcs8, pass)
            }
            "ppk" => keys::export_private_key(&key_data, KeyFormat::Putty, pass),
            _ => unreachable!("format restricted above"),
        }
        .map_err(|e| e.to_string())?,
    );

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
    // The dialog has closed; if the vault was locked while the user decided,
    // do not write private material decrypted under the now-locked vault.
    require_generation_current(&app, generation)?;
    let path_str = path.to_string();
    // The dialog choice is the user's approval; keep the absolute/app-data/
    // system checks as a backstop (a dialog path is always absolute, but the
    // app-data guard also protects the vault DB from being overwritten).
    validate_export_path(&path_str)?;

    // One helper for every secret we write to disk (export + deploy), so the
    // "mode() only applies at creation" trap cannot be reintroduced in one
    // place and not the other. It replaces any existing file and create_new's
    // it at 0600, and on Windows fails closed if the ACL cannot be tightened.
    crate::ssh::write_secret_file(std::path::Path::new(&path_str), data.as_bytes())
        .map_err(|e| CmdError(e.to_string()))?;

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

/// Rename a stored key. There was previously no way to change a key's name
/// after creation at all.
///
/// SECURITY: the name is used verbatim as a `Host` alias when the SSH config
/// is written, so it goes through the same `validate_key_name` gate as
/// creation and import - a rename must not be a way to smuggle in whitespace
/// or newlines and inject config directives. Nothing else about the key is
/// touched; the private material is not decrypted or re-encrypted to rename.
#[tauri::command]
pub fn key_rename(app: AppHandle, id: String, name: String) -> CmdResult<serde_json::Value> {
    let name = name.trim().to_string();
    crate::crypto::keys::validate_key_name(&name).map_err(CmdError)?;

    let state = app.state::<AppState>();
    let mut key = state
        .db
        .get_key(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Key not found.".to_string())?;

    if key.name == name {
        return Ok(serde_json::json!({ "ok": true, "name": name }));
    }
    let previous = key.name.clone();
    key.name = name.clone();
    key.updated_at = chrono::Utc::now();
    state.db.update_key(&key).map_err(|e| e.to_string())?;
    state
        .db
        .add_audit("keys.renamed", Some(&id), &format!("{previous} -> {name}"))?;
    Ok(serde_json::json!({ "ok": true, "name": name }))
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
    // Deleting local files is a privileged side effect; refuse while locked.
    if vault_password(&app)?.is_empty() {
        return Err("Vault is locked.".into());
    }
    let key = app
        .state::<AppState>()
        .db
        .get_key(&id)
        .map_err(|e| e.to_string())?;
    let key = key.ok_or_else(|| "Key not found.".to_string())?;

    if let Some(deploy_path) = &key.deploy_path {
        // Only ever delete inside the managed SSH directory (~/.ssh). The
        // stored path is normally produced by deploy_key, but a pre-F9 backup
        // restore (or direct DB tampering) could have written an arbitrary
        // path here; authenticated encryption of a backup does not make its
        // local deployment paths trustworthy. Canonicalize the parent so
        // `..`/junction games cannot escape, then require containment before
        // touching the filesystem.
        let candidate = std::path::Path::new(deploy_path);
        let managed = dirs::home_dir().map(|h| h.join(".ssh"));
        let contained = match (&managed, candidate.parent()) {
            (Some(m), Some(parent)) => {
                let m_norm = dunce::canonicalize(m).unwrap_or_else(|_| m.clone());
                let p_norm = dunce::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
                p_norm.starts_with(&m_norm)
            }
            _ => false,
        };
        if contained {
            let _ = fs::remove_file(deploy_path);
            let _ = fs::remove_file(format!("{}.pub", deploy_path));
        } else {
            // Refuse to delete outside the managed directory; still clear the
            // record so the UI no longer reports a phantom deployment.
            log::warn!(
                "[sshspan-keys] key_remove_deployed: refusing to delete {deploy_path} (outside managed ~/.ssh); clearing the deployment record only"
            );
            let _ = app.state::<AppState>().db.add_audit(
                "keys.undeploy_refused",
                Some(&id),
                "stored deploy_path outside managed directory; record cleared, file untouched",
            );
        }
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
    // Names become Host aliases in ~/.ssh/config - reject anything that could
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

/// NOT REGISTERED in `generate_handler!`, deliberately.
///
/// `SshConfig::parse` round-trips unknown directives through `extra`, so this
/// let a caller write ANY ssh_config directive - ProxyCommand, IdentityFile,
/// StrictHostKeyChecking no - into the managed config, with no vault gate at
/// all. The UI writes that file only through `key_deploy`, which validates
/// what it interpolates.
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
        // Wrap in Zeroizing immediately: the plaintext Bitwarden master
        // password must be wiped from this frame once sealed, not left as
        // freed heap (secret-wiping hardening).
        let mp = zeroize::Zeroizing::new(mp);
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
    // Zeroizing: the decrypted Bitwarden master password is wiped on drop.
    let master_password = zeroize::Zeroizing::new(
        String::from_utf8(crate::crypto::vault::unseal(&pw, &mp_sealed).map_err(|_| {
            "Failed to decrypt stored Bitwarden password. Re-save the sync settings.".to_string()
        })?)
        .map_err(|_| "Stored Bitwarden password is corrupted.".to_string())?,
    );

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
    // Zeroizing: the decrypted Bitwarden master password is wiped on drop.
    let master_password = zeroize::Zeroizing::new(
        String::from_utf8(
            crate::crypto::vault::unseal(&pw, &mp_sealed)
                .map_err(|_| "Failed to decrypt stored Bitwarden password.".to_string())?,
        )
        .map_err(|_| "Stored Bitwarden password is corrupted.".to_string())?,
    );

    let device_id = config
        .device_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let db = app.state::<AppState>().db.clone();

    // Capture the vault generation so a lock mid-sync cancels the run at the
    // next mutation boundary (sync pushes/pulls secrets; it must not continue
    // after the vault that authorized it has locked). Same predicate as
    // require_generation_current: the closure must be FALSE while the vault
    // stays unlocked and the generation is unchanged. The first version of
    // this closure negated the unlocked flag (an extra `!`), which made every
    // healthy sync abort with "Vault was locked" before any network work.
    let generation = capture_vault_generation(&app)?;
    let app_for_cancel = app.clone();
    let cancelled = move || require_generation_current(&app_for_cancel, generation).is_err();

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
        &cancelled,
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
    // `total` distinguishes "this is everything" from "this is the newest page
    // of many" - the table is capped at AUDIT_RETENTION_ROWS, so the page the
    // UI requests can be a strict subset of what exists.
    let total = app
        .state::<AppState>()
        .db
        .count_audit()
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "rows": rows, "total": total }))
}

/// Wipe the audit log. Records the clear itself as the first new row, so an
/// empty-looking log still shows that it was emptied (and when).
#[tauri::command]
pub fn audit_clear(app: AppHandle) -> CmdResult<serde_json::Value> {
    let removed = app
        .state::<AppState>()
        .db
        .clear_audit()
        .map_err(|e| e.to_string())?;
    let _ = app.state::<AppState>().db.add_audit(
        "audit.cleared",
        None,
        &format!("{removed} entrie(s) removed by the user"),
    );
    Ok(serde_json::json!({ "ok": true, "removed": removed }))
}

// ═════════════════════════════════════════════════════════════════════════════
//  SETTINGS commands
// ═════════════════════════════════════════════════════════════════════════════

/// Key prefix for the per-server default local directory (`sftpLocalDir:<id>`).
/// Shared by `settings_get`'s prefix read and `settings_set`'s validation so
/// the two can never disagree about what the family is called.
const SFTP_LOCAL_DIR_PREFIX: &str = "sftpLocalDir:";

/// Every setting key the app reads. `settings_get` returns these (plus the
/// `sftpLocalDir:` family) and `settings_set` accepts only these, so the two
/// cannot drift and the renderer cannot write keys nothing will ever read.
///
/// A key belongs here only if something actually reads it back. Four keys used
/// to sit in this list with no reader anywhere - `theme` and `sshKeysDir` /
/// `sshConfigPath` (the real paths are derived at runtime by `system_paths`)
/// were never consumed, and `terminalKeepaliveSeconds` became inert when
/// keepalives moved to the SSH protocol layer. They were accepted, persisted
/// and copied into every backup while doing nothing, so a renderer writing one
/// got a silent success for a no-op. Removed rather than left as decoration.
const SETTINGS_KEYS: &[&str] = &[
    "autoLockMinutes",
    "confirmDelete",
    "autoUpdateCheck",
    "sftpParallel",
    "sftpShowHidden",
    "sftpDualPane",
    "sftpShowOwnerCols",
    // FileZilla-parity transfer behavior (renderer mirror only works
    // in-session unless these load at startup).
    "sftpConflictUpload",
    "sftpConflictDownload",
    "sftpPreserveTs",
    "sftpCmpMode",
    "sftpResumeDefault",
    "sftpMaxBps",
    "sftpVerifyTransfers",
    "uiScale",
    "terminalScrollback",
    "terminalBackspace",
    "terminalHomeEnd",
    "terminalAppCursorKeys",
    "terminalAppKeypad",
    "terminalBell",
    "confirmMultiLinePaste",
];

/// The real on-disk locations, so the UI can state them instead of guessing.
///
/// The Settings pane and the deploy confirmation used to hard-code three
/// paths, and all three were wrong: the database was named as
/// `~/.sshspan/sshspan.db` (actually the platform data dir), deployed keys as
/// `~/.sshspan/keys/<id>` (actually `~/.ssh/sshspan_<name>`), and the managed
/// SSH config as `~/.ssh/config` (actually the app config dir). Users make
/// security decisions on those strings - what StrictHostKeyChecking applies
/// to, what to back up, what to wipe - so a wrong one is a real defect, not a
/// typo. Deriving them here means they cannot drift again.
#[tauri::command]
pub fn system_paths(app: AppHandle) -> CmdResult<serde_json::Value> {
    let db = app.state::<AppState>().db.db_path.display().to_string();
    let ssh_config = crate::config::ssh_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let deploy_dir = crate::config::get_ssh_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".into());
    Ok(serde_json::json!({
        "database": db,
        "sshConfig": ssh_config,
        "deployDir": deploy_dir,
    }))
}

/// Read every persisted setting into one map: the `SETTINGS_KEYS` allowlist
/// plus the `sftpLocalDir:` family (one key per server id, so it cannot live in
/// the fixed list). Shared by `settings_get` and the vault backup so the two
/// can never disagree about what "the settings" are - the backup used to carry
/// a hand-written list of six keys, three of which nothing read, and restore
/// dropped the whole map on the floor.
fn collect_settings(
    db: &crate::db::Database,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let mut settings = serde_json::Map::new();
    for key in SETTINGS_KEYS {
        if let Some(val) = db
            .get_config(&format!("setting.{}", key))
            .map_err(|e| e.to_string())?
        {
            settings.insert(key.to_string(), serde_json::Value::String(val));
        }
    }
    for (key, val) in db
        .list_config_prefix(&format!("setting.{SFTP_LOCAL_DIR_PREFIX}"))
        .map_err(|e| e.to_string())?
    {
        if let Some(bare) = key.strip_prefix("setting.") {
            settings.insert(bare.to_string(), serde_json::Value::String(val));
        }
    }
    Ok(settings)
}

/// Drop settings a backup should not be allowed to seed. `restore_backup`
/// writes every key in the payload straight into the `config` table - the same
/// table that holds the Bitwarden secrets - so the payload has to pass the
/// allowlist `settings_set` enforces before it gets there. A backup is
/// authenticated, but it can have been taken by an older build (which is how
/// the four since-removed keys would arrive), and a key nothing reads is
/// exactly the decoration this list exists to keep out. Returns the number of
/// keys dropped.
fn sanitize_backup_settings(settings: &mut serde_json::Map<String, serde_json::Value>) -> usize {
    let before = settings.len();
    settings.retain(|key, _| {
        SETTINGS_KEYS.contains(&key.as_str())
            || (key.starts_with(SFTP_LOCAL_DIR_PREFIX) && key.len() > SFTP_LOCAL_DIR_PREFIX.len())
    });
    before - settings.len()
}

#[tauri::command]
pub fn settings_get(app: AppHandle) -> CmdResult<serde_json::Value> {
    let settings = collect_settings(&app.state::<AppState>().db)?;
    Ok(serde_json::Value::Object(settings))
}

#[tauri::command]
pub fn settings_set(app: AppHandle, key: String, value: String) -> CmdResult<serde_json::Value> {
    if key.starts_with("bwSync.") {
        return Err("Bitwarden sync settings must be changed via the sync settings dialog.".into());
    }
    // Allowlist, not a denylist: `settings_get` only ever reads the keys in
    // SETTINGS_KEYS plus the sftpLocalDir: family, so anything else written
    // here is unreadable clutter at best. Accepting arbitrary keys let a
    // compromised renderer write unbounded rows into the same `config` table
    // that holds the Bitwarden secrets, which is worth refusing outright.
    let known = SETTINGS_KEYS.contains(&key.as_str())
        || (key.starts_with(SFTP_LOCAL_DIR_PREFIX) && key.len() > SFTP_LOCAL_DIR_PREFIX.len());
    if !known {
        return Err(format!("Unknown setting: {key}").into());
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
/// app's own `sshspan-edit` staging directory - the exact contract the
/// renderer's single call site uses (the local path returned by
/// `sftp_open_for_edit` / Send-to staging). URIs (`https:`, `file:`,
/// `ms-settings:`, ...) are rejected, and so is every path outside the staging
/// dir: unrestricted `opener::open` would otherwise hand arbitrary schemes -
/// or ShellExecute any on-disk executable - to the OS shell. A single-letter
/// drive prefix (`C:\...` or `C:/...` on Windows) is a path, not a URI scheme.
#[tauri::command]
pub fn system_open_external(url: String) -> CmdResult<serde_json::Value> {
    let p = std::path::Path::new(&url);
    if !p.is_absolute() {
        return Err("system_open_external only accepts absolute local file paths.".into());
    }
    // Reject URI schemes: `^[a-zA-Z][a-zA-Z0-9+.-]*:` before any path
    // separator, except a 1-char drive letter (Windows `C:`).
    let prefix_before_sep = url.split(|c| c == '/' || c == '\\').next().unwrap_or("");
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
        return Err("system_open_external only opens files staged by SSHSpan.".into());
    }
    if !resolved.is_file() {
        return Err("system_open_external: path is not a regular file.".into());
    }
    // Enforce the inert-extension policy AT THE OPENER, not just in the
    // staging flow. The staging flow names files safely, but the renderer
    // controls which staged path it passes here: without this check a
    // compromised renderer could `sftp_stage_path` + `sftp_download` remote
    // bytes into `<staging>/x.exe` and have the OS shell EXECUTE it via this
    // command. Only extensions whose OS handler is an editor/viewer (the
    // staging allowlist) may be handed to the shell; everything else is
    // refused before any OS call. This is the backend-owned boundary the
    // audit's executable-staging chain broke through.
    if !crate::sftp::path_has_inert_extension(&resolved) {
        return Err(
            "system_open_external refuses to open non-text staged files (possible executable)."
                .into(),
        );
    }
    opener::open(&resolved).map_err(|e| e.to_string())?;
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
/// NOTE: async on purpose. Tauri runs a synchronous command on the MAIN
/// thread, and tauri-plugin-dialog's `blocking_*` helpers deadlock when
/// called from there - the window stops responding and never repaints, which
/// is what "Create Backup freezes the whole program" was. An async command
/// runs on the async runtime instead, where blocking for the user's answer is
/// safe.
pub async fn system_select_file(
    app: AppHandle,
    title: Option<String>,
) -> CmdResult<serde_json::Value> {
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
