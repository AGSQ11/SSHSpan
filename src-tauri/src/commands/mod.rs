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
use crate::ssh::{
    DeployFiles, DeployHostFields, DeployKey, DeployPlan, DeployTarget, RecordedDeployment,
    SshService,
};
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

/// In-memory vault password accessor: a `Zeroizing` copy, wiped when the
/// command drops it (the store holds the canonical `Zeroizing` copy and hands
/// out only `Zeroizing` ones); empty while the vault is locked. Callers that
/// only need to know whether the vault is unlocked use
/// [`VaultPasswordStore::is_set`] and make no copy at all.
pub(crate) fn vault_password(app: &AppHandle) -> CmdResult<zeroize::Zeroizing<String>> {
    Ok(app.state::<VaultPasswordStore>().get().unwrap_or_default())
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
    /// A copy of the password for one command. It is `Zeroizing` from the
    /// moment it is made (A6-11): this used to hand out a plain `String`,
    /// which `vault_password` wrapped only afterwards and the boolean callers
    /// (`vault_status`, the auto-lock watchdog every 30 s) dropped unwiped.
    pub fn get(&self) -> Option<zeroize::Zeroizing<String>> {
        self.password
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| zeroize::Zeroizing::new(p.as_str().to_owned()))
    }
    /// Whether the vault is unlocked, without copying the password out.
    pub fn is_set(&self) -> bool {
        self.password.lock().unwrap().is_some()
    }
    pub fn set(&self, p: String) {
        *self.password.lock().unwrap() = Some(zeroize::Zeroizing::new(p));
    }
    pub fn clear(&self) {
        *self.password.lock().unwrap() = None;
    }
}

/// What a command that writes sealed vault data returns while a
/// master-password change is re-encrypting the vault.
pub(crate) const VAULT_REENCRYPTING: &str =
    "The vault is being re-encrypted - try again when it finishes.";

/// Serialises a master-password change against every other write of sealed
/// vault data (C1).
///
/// The change re-seals a snapshot of every key, saved server password, MCP
/// secret and stored credential, then commits them with the new verifier. Off
/// the main thread that takes long enough for other commands to run in
/// between, and two kinds of writes would then be lost: a record sealed with
/// the OLD password after the snapshot (unreadable once the new password is
/// in place - and every later change would fail on it), and a whole row read
/// before the commit and written back after it (its old-sealed blob replacing
/// the re-sealed one). So the change holds this lock for WRITING from before
/// the snapshot until the new password is installed, and every command that
/// seals with the master password or rewrites a whole key/server/MCP row
/// holds it for READING. Readers never wait: while a change runs or is queued
/// they fail at once with [`VAULT_REENCRYPTING`] - a synchronous command runs
/// on the main thread and must not block it.
///
/// A tokio lock rather than `std::sync::RwLock`: the Bitwarden sync and the
/// MCP connect/call/remove commands interleave network awaits with their DB
/// writes, so they hold the read guard across awaits - and a std guard is
/// `!Send`, which an async command's future cannot hold. The change itself
/// takes the write side on its blocking worker, with a time limit.
#[derive(Default)]
pub struct VaultRotationLock(tokio::sync::RwLock<()>);

impl VaultRotationLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read access for one command that writes sealed data, or
    /// [`VAULT_REENCRYPTING`] at once if a master-password change holds (or
    /// waits for) the lock. Never blocks.
    pub fn try_shared(&self) -> CmdResult<tokio::sync::RwLockReadGuard<'_, ()>> {
        self.0
            .try_read()
            .map_err(|_| CmdError(VAULT_REENCRYPTING.into()))
    }

    /// Write access for a master-password change. It queues like `write()` -
    /// from the moment it waits, new readers are refused - but gives up after
    /// `limit` with [`ROTATION_LOCK_BUSY`]: a sync or MCP call that keeps its
    /// read guard must not leave the change hanging without a word. It
    /// blocks the calling thread (on a private current-thread runtime that
    /// only drives the timer and this wait), so it must only run on a
    /// blocking worker - never on the main thread or inside async code.
    fn exclusive_within(
        &self,
        limit: std::time::Duration,
    ) -> CmdResult<tokio::sync::RwLockWriteGuard<'_, ()>> {
        let waiter = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|e| CmdError(format!("Could not wait for the vault lock: {e}")))?;
        // Built INSIDE block_on: the timer must belong to `waiter` (an
        // argument expression would be evaluated outside its context).
        waiter
            .block_on(async { tokio::time::timeout(limit, self.0.write()).await })
            .map_err(|_| CmdError(ROTATION_LOCK_BUSY.into()))
    }
}

/// [`VaultRotationLock::try_shared`] for a command that has an `AppHandle`.
/// Hold the returned guard until the command's last write.
pub(crate) fn rotation_shared(app: &AppHandle) -> CmdResult<tokio::sync::RwLockReadGuard<'_, ()>> {
    app.state::<VaultRotationLock>().inner().try_shared()
}

/// Refuse a vault mutation or a security-policy change while the vault is
/// locked (A6-08). Locking is the control for an unattended machine; it has to
/// protect the vault's integrity and its security settings, not only reads of
/// secret material.
fn require_unlocked(vault: &VaultPasswordStore) -> CmdResult<()> {
    if vault.is_set() {
        Ok(())
    } else {
        Err("Vault is locked.".into())
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

/// Minimum master-password length the messages promise ("at least 8
/// characters").
const MIN_MASTER_PASSWORD_CHARS: usize = 8;

/// Counts characters, not UTF-8 bytes (A7-52): `String::len()` let a
/// 3-character CJK or a 2-emoji password through as "8 characters".
fn master_password_long_enough(password: &str) -> bool {
    password.chars().count() >= MIN_MASTER_PASSWORD_CHARS
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

    let unlocked = app.state::<VaultPasswordStore>().is_set();

    Ok(serde_json::json!({ "hasVault": has_vault, "unlocked": unlocked }))
}

/// Create a new vault. Stores an Argon2id verification hash and unlocks in one step.
#[tauri::command]
pub fn vault_create(app: AppHandle, password: String) -> CmdResult<serde_json::Value> {
    if !master_password_long_enough(&password) {
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
    // MCP sessions die with the vault too: HTTP DELETE with Mcp-Session-Id,
    // carrying the static auth header resolved BEFORE the password store
    // clears below (405 is valid per spec - ignored; other refusals are
    // audited, never swallowed). Session + status state is dropped
    // synchronously; the DELETEs themselves run on the async runtime so the
    // lock path stays nonblocking.
    crate::assistant::mcp::teardown_all(app);
    app.state::<VaultPasswordStore>().clear();
    let _ = app.state::<AppState>().db.add_audit("vault.lock", None, "");
}

/// When the user last did something, as reported by the `heartbeat` IPC. The
/// renderer sends a heartbeat only for real input - a key, a click, the
/// wheel, a touch, typing into a terminal - at most once every few seconds;
/// server output, polls and timers never send one. The backend idle watchdog
/// locks the vault once this is older than `autoLockMinutes`.
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

/// Auto-lock timeout when `autoLockMinutes` is not stored or not readable.
const AUTO_LOCK_DEFAULT_MINUTES: u64 = 15;
/// Largest auto-lock timeout (a day), the Settings field's maximum.
const AUTO_LOCK_MAX_MINUTES: u64 = 1440;

/// Effective auto-lock timeout in minutes for a stored `autoLockMinutes`
/// value; 0 means off. Read exactly like the renderer's `autoLockMinutes()`:
/// absent, blank or anything that is not a whole number (a negative
/// included) is the 15-minute default, an explicit "0" is off, and more than
/// a day is a day. This used to treat a negative as "off" and apply no upper
/// limit, so the watchdog and the renderer disagreed at the edges.
fn effective_auto_lock_minutes(stored: Option<&str>) -> u64 {
    let Some(text) = stored.map(str::trim) else {
        return AUTO_LOCK_DEFAULT_MINUTES;
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return AUTO_LOCK_DEFAULT_MINUTES;
    }
    // Digits only, so the parse can fail only by overflowing: more than a day.
    text.parse::<u64>()
        .map_or(AUTO_LOCK_MAX_MINUTES, |n| n.min(AUTO_LOCK_MAX_MINUTES))
}

/// Backend idle watchdog: locks the vault once no `heartbeat` has arrived for
/// `autoLockMinutes`. The renderer sends a heartbeat only for real user input
/// (see [`ActivityTracker`]), so this is a genuine idle lock, not a liveness
/// check: an idle user's vault locks here even when the renderer's own timer
/// cannot fire (a hung or crashed webview, a window hidden to the tray). The
/// setting is read the way the renderer reads it
/// ([`effective_auto_lock_minutes`]): absent or unreadable is 15 minutes, an
/// explicit "0" is off. Checked every 30 s, and only while the vault is
/// unlocked.
pub(crate) fn spawn_auto_lock_watchdog(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let stored = app
                .state::<AppState>()
                .db
                .get_config("setting.autoLockMinutes")
                .ok()
                .flatten();
            let mins = effective_auto_lock_minutes(stored.as_deref());
            if mins == 0 {
                continue;
            }
            if !app.state::<VaultPasswordStore>().is_set() {
                continue;
            }
            if app.state::<ActivityTracker>().elapsed()
                >= std::time::Duration::from_secs(mins.saturating_mul(60))
            {
                log::info!("[sshspan-vault] backend idle watchdog locked the vault after {mins} min without user activity");
                lock_vault_internal(&app);
                // Best effort: tell the renderer so its UI reflects the lock.
                let _ = tauri::Emitter::emit(&app, "vault-locked-by-watchdog", ());
            }
        }
    });
}

/// Change the master password. Every record sealed with it - keys, saved
/// server passwords, the Bitwarden credential, the assistant API key, MCP
/// secrets - is re-sealed and committed together with the new verifier.
///
/// Async on purpose (A7-13): that is two Argon2id derivations (64 MiB, t=3)
/// per record, and as a synchronous command it all ran on the main thread, so
/// with a hundred keys the window froze for tens of seconds. The work now runs
/// on a blocking worker, under the [`VaultRotationLock`] write lock (C1): the
/// rest of the app stays usable, but nothing can seal or rewrite vault data
/// until the change is committed and the new password installed. If another
/// vault operation (a Bitwarden sync, an MCP call, a backup export or restore,
/// a deploy, another change) still holds that lock after 30 s, the change
/// gives up with [`ROTATION_LOCK_BUSY`] and nothing is changed. A lock (the
/// tray's Lock Vault, the idle watchdog) landing while the records are being
/// re-sealed aborts the change before it commits; one landing after that last
/// check lets the commit finish but leaves the vault locked - the new password
/// is never installed over a lock, and it is the one that unlocks the vault.
#[tauri::command]
pub async fn vault_change_password(
    app: AppHandle,
    current_password: String,
    new_password: String,
) -> CmdResult<serde_json::Value> {
    let current_password = zeroize::Zeroizing::new(current_password);
    let new_password = zeroize::Zeroizing::new(new_password);
    if !master_password_long_enough(&new_password) {
        return Err("New master password must be at least 8 characters.".into());
    }
    let generation = app.state::<VaultGeneration>().current();
    let worker = app.clone();
    let reencrypted = run_blocking(move || {
        let vault = RotationContext {
            throttle: worker.state::<UnlockThrottle>().inner(),
            lock: worker.state::<VaultRotationLock>().inner(),
            store: worker.state::<VaultPasswordStore>().inner(),
            generations: worker.state::<VaultGeneration>().inner(),
            lock_wait: ROTATION_LOCK_WAIT,
        };
        change_master_password(
            &worker.state::<AppState>().db,
            &vault,
            generation,
            &current_password,
            new_password,
        )
    })
    .await?;
    Ok(serde_json::json!({ "ok": true, "reencrypted": reencrypted }))
}

/// The in-memory vault state a master-password change works with.
struct RotationContext<'a> {
    throttle: &'a UnlockThrottle,
    lock: &'a VaultRotationLock,
    store: &'a VaultPasswordStore,
    generations: &'a VaultGeneration,
    /// How long to wait for running sealed-data writers before giving up.
    lock_wait: std::time::Duration,
}

/// How long a master-password change waits for a running vault operation to
/// release the [`VaultRotationLock`] before it gives up.
const ROTATION_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a master-password change says when it gave up waiting for the lock.
/// The holder can be a sync, an MCP call, a backup export or restore, a
/// deploy or another change, so the message names none of them.
const ROTATION_LOCK_BUSY: &str =
    "Another vault operation is still running - try again when it finishes.";

/// [`vault_change_password`] on its blocking worker, without the
/// `AppHandle`. The write lock is taken before the current-password check
/// and the snapshot (giving up after `lock_wait` with [`ROTATION_LOCK_BUSY`]
/// while a sync or MCP call holds it) and held until the new password is
/// installed, so nothing sealed with the old password can slip in between
/// (C1). Once the rotation has committed nothing can fail the change: the
/// new password is installed FIRST and the audit row is written afterwards,
/// best-effort - a failed audit write used to return an error before the
/// install, leaving the store on the old password over a vault sealed with
/// the new one. (A lock that landed meanwhile leaves the vault locked
/// instead; the new password then unlocks it.)
fn change_master_password(
    db: &db::Database,
    vault: &RotationContext<'_>,
    captured_generation: u64,
    current_password: &str,
    new_password: zeroize::Zeroizing<String>,
) -> CmdResult<u32> {
    let _exclusive = vault.lock.exclusive_within(vault.lock_wait)?;
    let summary =
        rotate_master_password(db, vault.throttle, current_password, &new_password, &|| {
            vault.generations.current() == captured_generation
        })?;
    install_rotated_password(
        vault.store,
        vault.generations,
        captured_generation,
        new_password,
    );
    if let Err(e) = db.add_audit(
        "vault.password_changed",
        None,
        &format!(
            "Re-encrypted {} key(s), {} saved server password(s)",
            summary.keys, summary.server_passwords
        ),
    ) {
        log::warn!(
            "[sshspan-vault] the master password was changed, but its audit row could not be written: {e}"
        );
    }
    Ok(summary.keys)
}

/// What a committed master-password change re-sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RotationSummary {
    keys: u32,
    server_passwords: u32,
}

/// Run vault work that is too slow for the main thread - Argon2id once per
/// record, file I/O - on Tauri's blocking pool, and hand back its result.
async fn run_blocking<T, F>(work: F) -> CmdResult<T>
where
    F: FnOnce() -> CmdResult<T> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|e| CmdError(format!("Background task failed: {e}")))?
}

/// The rotation itself (the caller holds the write lock): verify the current
/// password, snapshot and re-seal every sealed value in memory, then commit
/// them with the new verifier in one transaction - unless `still_current()`
/// reports a lock in the meantime, in which case nothing is written. The
/// commit is conditional and touches only the sealed values (see
/// [`db::Database::apply_vault_rotation`]). Nothing after the commit can
/// fail: installing the password and auditing are the caller's.
fn rotate_master_password(
    db: &db::Database,
    throttle: &UnlockThrottle,
    current_password: &str,
    new_password: &str,
    still_current: &dyn Fn() -> bool,
) -> CmdResult<RotationSummary> {
    // The current-password check is a password guess too - throttle it with
    // the same counter as unlock attempts.
    throttle.check().map_err(CmdError::from)?;
    let stored = db.get_config(MASTER_HASH_KEY).unwrap_or_default();
    if stored.as_ref().map_or(true, |s| s.is_empty()) {
        return Err("No vault exists. Create one first.".into());
    }
    let ok = verify_master_password(db, current_password).map_err(|e| e.to_string())?;
    if !ok {
        throttle.record_failure();
        return Err("Current master password is incorrect.".into());
    }
    throttle.record_success();

    let keys = db.list_keys().map_err(|e| e.to_string())?;
    let servers = db.list_servers().map_err(|e| e.to_string())?;
    // Everything is re-encrypted in memory first; if any record fails to
    // unseal, the whole change is aborted and nothing is persisted.
    let migration = migrate_vault_records(keys, servers, current_password, new_password)?;

    // The stored Bitwarden master password is sealed with the SAME vault
    // password, so it must be re-sealed too - otherwise sync silently strands
    // on the old password after a rotation (F6). Re-seal it in memory here so
    // it commits in the same transaction below. A missing/unconfigured
    // credential is fine (None); an unsealable one aborts the whole change.
    let bw_config = db.load_bitwarden_config().map_err(|e| e.to_string())?;
    let bitwarden_master_password = match bw_config.master_password {
        Some(sealed) => {
            let plain = zeroize::Zeroizing::new(
                crate::crypto::vault::unseal(current_password, &sealed)
                    .map_err(|e| format!("Cannot re-encrypt the stored Bitwarden password: {e}"))?,
            );
            let resealed =
                crate::crypto::vault::seal(new_password, &plain).map_err(CmdError::from)?;
            Some((sealed, resealed))
        }
        None => None,
    };

    // The AI assistant's provider API key is sealed with the same vault
    // password; it must rotate in the same transaction or every assistant
    // call fails at unseal after the change while has_api_key still says
    // true. Same rule as the Bitwarden credential above: missing is fine,
    // unsealable aborts the whole change.
    let assistant_config = db.load_assistant_config().map_err(|e| e.to_string())?;
    let assistant_api_key = match assistant_config.api_key {
        Some(sealed) => {
            let plain = zeroize::Zeroizing::new(
                crate::crypto::vault::unseal(current_password, &sealed).map_err(|e| {
                    format!("Cannot re-encrypt the stored AI assistant API key: {e}")
                })?,
            );
            let resealed =
                crate::crypto::vault::seal(new_password, &plain).map_err(CmdError::from)?;
            Some((sealed, resealed))
        }
        None => None,
    };

    // MCP server auth secrets are sealed with the same vault password; each
    // must rotate in the same transaction or every MCP call fails at unseal
    // after the change. Same rule as the assistant key: missing is fine, an
    // unsealable blob aborts the whole change (in memory, before anything
    // commits). Only the secret is replaced - per-tool pin state is left as
    // the record holds it at commit time (pin hashes are not
    // password-derived).
    let mut mcp_secrets = Vec::new();
    for record in db.list_mcp_servers().map_err(|e| e.to_string())? {
        let Some(sealed) = record.auth_secret else {
            continue;
        };
        let plain = zeroize::Zeroizing::new(
            crate::crypto::vault::unseal(current_password, &sealed).map_err(|e| {
                format!(
                    "Cannot re-encrypt the MCP auth secret for '{}': {e}",
                    record.name
                )
            })?,
        );
        mcp_secrets.push(db::ResealedSecret {
            id: record.id,
            new: crate::crypto::vault::seal(new_password, &plain).map_err(CmdError::from)?,
            old: sealed,
        });
    }

    let rotation = db::VaultRotation {
        keys: migration.keys,
        server_passwords: migration.servers,
        mcp_secrets,
        bitwarden_master_password,
        assistant_api_key,
        master_hash: hash_master_password(new_password).map_err(CmdError::from)?,
    };
    // A lock while the records were being re-sealed (seconds per record)
    // aborts here, before anything commits - the rule for every operation
    // that crosses a lock.
    if !still_current() {
        return Err("Vault was locked while the operation was in progress.".into());
    }
    // Single transaction: every re-sealed value, the credentials and the
    // verifier commit together or not at all (F3). A crash or I/O error
    // part-way rolls back to the complete old state instead of leaving the
    // vault split across two passwords; so does a row that changed since the
    // snapshot (C1).
    db.apply_vault_rotation(&rotation)
        .map_err(|e| e.to_string())?;
    Ok(RotationSummary {
        keys: rotation.keys.len() as u32,
        server_passwords: rotation.server_passwords.len() as u32,
    })
}

/// Make the new master password the unlocked one after a committed rotation -
/// unless the vault was locked while the rotation ran. Set first, then check:
/// `lock_vault_internal` bumps the generation before it clears the store, so a
/// lock that lands in between either clears what was just set or has already
/// bumped the generation this check sees.
fn install_rotated_password(
    store: &VaultPasswordStore,
    generation: &VaultGeneration,
    captured: u64,
    new_password: zeroize::Zeroizing<String>,
) {
    store.set(new_password.as_str().to_owned());
    if generation.current() != captured {
        store.clear();
    }
}

/// Every key blob and saved server password, re-sealed with a new password
/// (in memory, nothing persisted yet).
#[derive(Debug)]
struct VaultMigration {
    keys: Vec<db::ResealedSecret>,
    /// Only servers that actually had a saved password to re-seal.
    servers: Vec<db::ResealedSecret>,
}

/// Unseal every stored private key and saved server password with the current
/// vault password and re-seal them with the new one, in memory. Any unseal
/// failure aborts the whole migration (nothing is persisted by this function).
/// Each plaintext lives in a `Zeroizing` buffer, wiped as soon as it has been
/// re-sealed (A6-11). The blob that was read is kept beside its replacement:
/// the commit only writes where it is still in place (C1).
fn migrate_vault_records(
    keys: Vec<KeyRecord>,
    servers: Vec<db::ServerRecord>,
    current_password: &str,
    new_password: &str,
) -> CmdResult<VaultMigration> {
    let mut migrated_keys = Vec::with_capacity(keys.len());
    for key in keys {
        let plaintext = zeroize::Zeroizing::new(
            match crate::crypto::vault::unseal(current_password, &key.private_key_encrypted) {
                Ok(bytes) => bytes,
                Err(e) => return Err(format!("Cannot re-encrypt key {}: {e}", key.id).into()),
            },
        );
        migrated_keys.push(db::ResealedSecret {
            new: crate::crypto::vault::seal(new_password, &plaintext).map_err(|e| e.to_string())?,
            id: key.id,
            old: key.private_key_encrypted,
        });
    }

    // Saved server passwords are sealed with the same vault password, so they
    // must be re-sealed too - otherwise every stored server password becomes
    // unrecoverable after the change.
    let mut migrated_servers = Vec::with_capacity(servers.len());
    for server in servers {
        let Some(sealed_pw) = server.saved_password else {
            continue;
        };
        let plaintext = zeroize::Zeroizing::new(
            match crate::crypto::vault::unseal(current_password, &sealed_pw) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(format!(
                        "Cannot re-encrypt saved password for server {}: {e}",
                        server.name
                    )
                    .into());
                }
            },
        );
        migrated_servers.push(db::ResealedSecret {
            new: crate::crypto::vault::seal(new_password, &plaintext).map_err(CmdError::from)?,
            id: server.id,
            old: sealed_pw,
        });
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
        db.apply_vault_rotation(&db::VaultRotation {
            keys: migration.keys,
            server_passwords: migration.servers,
            master_hash: "NEW-VERIFIER".into(),
            ..db::VaultRotation::default()
        })
        .unwrap();

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

    // ── A6-08: vault mutations and security settings refuse while locked ──

    fn locked_vault() -> VaultPasswordStore {
        VaultPasswordStore::new()
    }

    fn unlocked_vault() -> VaultPasswordStore {
        let vault = VaultPasswordStore::new();
        vault.set("test-master-pw".into());
        vault
    }

    fn assert_refused_while_locked<T: std::fmt::Debug>(result: CmdResult<T>) {
        match result {
            Err(e) => assert_eq!(e.0, "Vault is locked."),
            Ok(v) => panic!("must refuse while the vault is locked, got Ok({v:?})"),
        }
    }

    fn sample_category(id: &str, scope: &str) -> db::Category {
        db::Category {
            id: id.into(),
            name: format!("cat-{id}"),
            parent_id: None,
            scope: scope.into(),
            color: None,
            sort_index: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn key_delete_refuses_while_locked() {
        let db = test_db();
        db.insert_key(&sample_key("k1", "pw")).unwrap();
        assert_refused_while_locked(key_delete_in(&db, &locked_vault(), "k1"));
        assert!(db.get_key("k1").unwrap().is_some(), "the key must survive");
        key_delete_in(&db, &unlocked_vault(), "k1").unwrap();
        assert!(db.get_key("k1").unwrap().is_none());
    }

    #[test]
    fn key_rename_refuses_while_locked() {
        let db = test_db();
        db.insert_key(&sample_key("k1", "pw")).unwrap();
        let rotation = VaultRotationLock::new();
        assert_refused_while_locked(key_rename_in(
            &db,
            &locked_vault(),
            &rotation,
            "k1",
            "renamed",
        ));
        assert_eq!(db.get_key("k1").unwrap().unwrap().name, "key-k1");
        key_rename_in(&db, &unlocked_vault(), &rotation, "k1", "renamed").unwrap();
        assert_eq!(db.get_key("k1").unwrap().unwrap().name, "renamed");
    }

    /// A2-46 / A5-25: a rename onto another key's name - compared without
    /// regard to case - is refused with a message naming that key; changing
    /// the case of a key's own name is not a clash.
    #[test]
    fn key_rename_refuses_another_keys_name_in_any_case() {
        let db = test_db();
        db.insert_key(&sample_key("k1", "pw")).unwrap();
        db.insert_key(&sample_key("k2", "pw")).unwrap();
        let rotation = VaultRotationLock::new();
        let clash = key_rename_in(&db, &unlocked_vault(), &rotation, "k2", "KEY-K1");
        assert_eq!(
            clash.unwrap_err().0,
            "A key named \"key-k1\" already exists. Choose a different name."
        );
        assert_eq!(db.get_key("k2").unwrap().unwrap().name, "key-k2");
        key_rename_in(&db, &unlocked_vault(), &rotation, "k1", "KEY-K1").unwrap();
        assert_eq!(db.get_key("k1").unwrap().unwrap().name, "KEY-K1");
    }

    // ── RU3: key generation, import and export ──

    const PW: &str = "test-master-pw"; // what unlocked_vault() holds

    /// An OpenSSH private key file for import tests.
    fn openssh_key_file(comment: &str) -> String {
        let mut key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        key.set_comment(comment);
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string()
    }

    fn import(
        db: &db::Database,
        pem: &str,
        name: &str,
        comment: Option<&str>,
    ) -> CmdResult<serde_json::Value> {
        key_import_in(
            db,
            &unlocked_vault(),
            &VaultRotationLock::new(),
            pem,
            Some(name.to_string()),
            comment.map(String::from),
            None,
        )
    }

    #[test]
    fn key_import_explains_a_pem_format_it_cannot_read() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        let err = import(&test_db(), pem, "aws", None).unwrap_err();
        assert!(err.0.contains("PKCS#1 RSA private key"), "{}", err.0);
        assert!(err.0.contains("ssh-keygen -p -o -f"), "{}", err.0);
    }

    #[test]
    fn key_import_refuses_a_name_already_in_use() {
        let db = test_db();
        db.insert_key(&sample_key("k1", PW)).unwrap();
        let err = import(&db, &openssh_key_file("x"), "KEY-k1", None).unwrap_err();
        assert_eq!(
            err.0,
            "A key named \"key-k1\" already exists. Choose a different name."
        );
        assert_eq!(db.list_keys().unwrap().len(), 1);
    }

    /// A7-45: a comment typed into the import dialog is cleaned like one
    /// read from the file, so the stored authorized_keys line is one line.
    #[test]
    fn key_import_cleans_comments_from_the_file_and_from_the_dialog() {
        let db = test_db();
        let id = import(&db, &openssh_key_file("file\ncomment"), "one", None).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let stored = db.get_key(&id).unwrap().unwrap();
        assert_eq!(stored.comment, "file comment");
        assert_eq!(stored.public_key.lines().count(), 1);
        let id = import(&db, &openssh_key_file("x"), "two", Some("typed\r\nline")).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let stored = db.get_key(&id).unwrap().unwrap();
        assert_eq!(stored.comment, "typed  line");
        assert_eq!(stored.public_key.lines().count(), 1);
    }

    #[test]
    fn key_import_refuses_while_rotating_or_locked() {
        let db = test_db();
        let rotation = VaultRotationLock::new();
        let busy = rotation
            .exclusive_within(std::time::Duration::from_secs(5))
            .unwrap();
        let pem = openssh_key_file("x");
        let refused = key_import_in(&db, &unlocked_vault(), &rotation, &pem, None, None, None);
        drop(busy);
        assert_eq!(refused.unwrap_err().0, VAULT_REENCRYPTING);
        assert_refused_while_locked(key_import_in(
            &db,
            &locked_vault(),
            &rotation,
            &pem,
            None,
            None,
            None,
        ));
        assert!(db.list_keys().unwrap().is_empty());
    }

    #[test]
    fn new_key_requests_are_checked_before_any_generation() {
        let rsa = NewKey::parse("rsa", Some(1024), Some("k".into()), None, None);
        assert_eq!(
            rsa.err().unwrap().0,
            "RSA key size must be between 2048 and 8192 bits (got 1024)."
        );
        // The dialog sends its RSA size for every type; only RSA uses it.
        let ed = NewKey::parse("ed25519", Some(4096), Some("k".into()), None, None).unwrap();
        assert_eq!((ed.key_type, ed.bits), (KeyType::Ed25519, None));
        let ec = NewKey::parse("ecdsa-nistp384", None, Some("k".into()), None, None).unwrap();
        assert_eq!(ec.key_type, KeyType::EcdsaP384);
        assert!(NewKey::parse("ed25519", None, Some("a b".into()), None, None).is_err());
    }

    #[test]
    fn create_key_refuses_a_name_in_use_and_cleans_the_comment() {
        let db = test_db();
        db.insert_key(&sample_key("k1", PW)).unwrap();
        db.insert_category(&sample_category("c1", "key")).unwrap();
        let rotation = VaultRotationLock::new();
        let request = |name: &str| {
            NewKey::parse(
                "ed25519",
                None,
                Some(name.into()),
                Some("me@host\nx".into()),
                Some(vec!["c1".into()]),
            )
            .unwrap()
        };
        let clash = create_key_in(&db, &unlocked_vault(), &rotation, request("Key-K1"));
        assert_eq!(
            clash.unwrap_err().0,
            "A key named \"key-k1\" already exists. Choose a different name."
        );
        let created = create_key_in(&db, &unlocked_vault(), &rotation, request("fresh")).unwrap();
        let id = created["id"].as_str().unwrap();
        let stored = db.get_key(id).unwrap().unwrap();
        assert_eq!(stored.comment, "me@host x");
        assert_eq!(stored.public_key.lines().count(), 1);
        assert!(crate::crypto::vault::unseal(PW, &stored.private_key_encrypted).is_ok());
        assert_eq!(
            db.list_categories_for_key(id).unwrap(),
            vec!["c1".to_string()]
        );
    }

    /// A2-03 / A7-05 / A5-38: "PKCS#8 PEM, encrypted" without a passphrase
    /// is refused before the save dialog opens - it used to write a
    /// plaintext key and report success.
    #[test]
    fn encrypted_pkcs8_export_needs_a_passphrase() {
        for missing in [None, Some("")] {
            assert_eq!(
                private_export_passphrase("pkcs8-encrypted", missing)
                    .unwrap_err()
                    .0,
                "A passphrase is required for an encrypted PKCS#8 export."
            );
        }
        assert_eq!(
            private_export_passphrase("pkcs8-encrypted", Some("s3cret")).unwrap(),
            Some("s3cret")
        );
        assert_eq!(private_export_passphrase("pkcs8", Some("")).unwrap(), None);
        assert_eq!(private_export_passphrase("ppk", None).unwrap(), None);
        assert!(private_export_passphrase("public", None).is_err());
    }

    // ── RU3: deploy writes what it shows (R3) ──

    fn deploy_target(tag: &str) -> (std::path::PathBuf, crate::ssh::DeployTarget) {
        let root = scratch_dir(&format!("deploy-{tag}"));
        let target = crate::ssh::DeployTarget::new(
            root.join("home").join(".ssh"),
            root.join("config").join("ssh").join("config"),
        );
        (root, target)
    }

    /// A real Ed25519 key sealed with [`PW`], stored under `name`.
    fn insert_real_key(db: &db::Database, id: &str, name: &str) {
        let data = keys::generate_key_pair(KeyType::Ed25519, None, format!("{name}@test")).unwrap();
        let mut record = sample_key(id, PW);
        record.name = name.into();
        record.public_key = keys::export_public_key(&data, KeyFormat::OpenSsh).unwrap();
        record.private_key_encrypted = crate::crypto::vault::seal(PW, &data.private_key).unwrap();
        record.fingerprint_sha256 = keys::compute_fingerprint_sha256(&data.public_key);
        db.insert_key(&record).unwrap();
    }

    fn host_fields() -> crate::ssh::DeployHostFields {
        crate::ssh::DeployHostFields::parse(
            Some("prod".into()),
            Some("web.example.com".into()),
            Some("deploy".into()),
            Some(2222),
            Some(true),
        )
        .unwrap()
    }

    fn deploy(
        db: &db::Database,
        target: &crate::ssh::DeployTarget,
        ids: &[&str],
        fields: &crate::ssh::DeployHostFields,
    ) -> CmdResult<serde_json::Value> {
        let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        key_deploy_in(
            db,
            &unlocked_vault(),
            &VaultRotationLock::new(),
            target,
            &ids,
            None,
            fields,
            &|| Ok(()),
        )
    }

    #[test]
    fn deploy_writes_exactly_the_previewed_stanza_and_records_it() {
        let db = test_db();
        insert_real_key(&db, "k1", "web");
        let (root, target) = deploy_target("preview");
        let ids = vec!["k1".to_string()];
        let preview = key_deploy_preview_in(&db, &target, &ids, &host_fields()).unwrap();
        let result = deploy(&db, &target, &["k1"], &host_fields());
        let written = std::fs::read_to_string(&target.config_path);
        let private = std::fs::read_to_string(target.ssh_dir.join("sshspan_web"));
        let _ = std::fs::remove_dir_all(&root);

        let result = result.unwrap();
        let file = target.ssh_dir.join("sshspan_web").display().to_string();
        assert_eq!(preview["keys"][0]["file"], serde_json::json!(file));
        assert_eq!(preview["keys"][0]["alias"], "prod");
        assert_eq!(preview["keys"][0]["ownedByOtherKey"], false);
        assert_eq!(preview["keys"][0]["overwritesFile"], false);
        assert_eq!(
            preview["configPath"],
            serde_json::json!(target.config_path.display().to_string())
        );
        assert_eq!(
            preview["includeLine"],
            serde_json::json!(target.include_line())
        );
        assert_eq!(result["keys"][0]["file"], serde_json::json!(file));
        assert_eq!(written.unwrap(), preview["configText"].as_str().unwrap());
        let parsed = ssh_key::PrivateKey::from_openssh(private.unwrap()).unwrap();
        let stored = db.get_key("k1").unwrap().unwrap();
        assert_eq!(
            keys::compute_fingerprint_sha256(&parsed.public_key().to_bytes().unwrap()),
            stored.fingerprint_sha256
        );
        assert!(stored.deployed);
        assert_eq!(stored.deploy_path.as_deref(), Some(file.as_str()));
        assert!(db
            .list_audit(10)
            .unwrap()
            .iter()
            .any(|a| a.action == "keys.deployed"));
    }

    /// A2-46 / A7-59: a key whose file is another key's deployed file is
    /// refused, and that file is left alone.
    #[test]
    fn deploy_refuses_a_file_another_key_owns() {
        let db = test_db();
        insert_real_key(&db, "k1", "a.b");
        insert_real_key(&db, "k2", "a_b");
        let (root, target) = deploy_target("collision");
        let first = deploy(
            &db,
            &target,
            &["k1"],
            &crate::ssh::DeployHostFields::default(),
        );
        let before = std::fs::read(target.ssh_dir.join("sshspan_a_b"));
        let ids = vec!["k2".to_string()];
        let preview =
            key_deploy_preview_in(&db, &target, &ids, &crate::ssh::DeployHostFields::default());
        let second = deploy(
            &db,
            &target,
            &["k2"],
            &crate::ssh::DeployHostFields::default(),
        );
        let after = std::fs::read(target.ssh_dir.join("sshspan_a_b"));
        let _ = std::fs::remove_dir_all(&root);

        first.unwrap();
        assert_eq!(preview.unwrap()["keys"][0]["ownedByOtherKey"], true);
        let err = second.unwrap_err().0;
        assert!(err.contains("\"a.b\""), "{err}");
        assert_eq!(
            before.unwrap(),
            after.unwrap(),
            "the first key's file is untouched"
        );
        assert!(!db.get_key("k2").unwrap().unwrap().deployed);
    }

    #[test]
    fn deploy_refuses_while_rotating_or_locked_and_stops_at_a_lock() {
        let db = test_db();
        insert_real_key(&db, "k1", "web");
        let (root, target) = deploy_target("gates");
        let ids = vec!["k1".to_string()];
        let fields = crate::ssh::DeployHostFields::default();
        let rotation = VaultRotationLock::new();
        let busy = rotation
            .exclusive_within(std::time::Duration::from_secs(5))
            .unwrap();
        let rotating = key_deploy_in(
            &db,
            &unlocked_vault(),
            &rotation,
            &target,
            &ids,
            None,
            &fields,
            &|| Ok(()),
        );
        drop(busy);
        let locked = key_deploy_in(
            &db,
            &locked_vault(),
            &rotation,
            &target,
            &ids,
            None,
            &fields,
            &|| Ok(()),
        );
        let lock_midway = key_deploy_in(
            &db,
            &unlocked_vault(),
            &rotation,
            &target,
            &ids,
            None,
            &fields,
            &|| {
                Err(CmdError(
                    "Vault was locked while the operation was in progress.".into(),
                ))
            },
        );
        let written = target.ssh_dir.join("sshspan_web").exists();
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(rotating.unwrap_err().0, VAULT_REENCRYPTING);
        assert_refused_while_locked(locked);
        assert!(lock_midway
            .unwrap_err()
            .0
            .contains("Vault was locked while the operation was in progress."));
        assert!(!written, "nothing may be written after a lock");
    }

    /// A7-22 / A8-24: undeploy removes both files and the Host stanza,
    /// clears the record and audits it.
    #[test]
    fn remove_deployed_removes_files_stanza_and_record() {
        let db = test_db();
        insert_real_key(&db, "k1", "web");
        let (root, target) = deploy_target("undeploy");
        deploy(&db, &target, &["k1"], &host_fields()).unwrap();
        let file = target.ssh_dir.join("sshspan_web").display().to_string();
        let result = key_remove_deployed_in(
            &db,
            &unlocked_vault(),
            &VaultRotationLock::new(),
            &target,
            "k1",
        );
        let config = std::fs::read_to_string(&target.config_path).unwrap_or_default();
        let gone = !std::path::Path::new(&file).exists();
        let _ = std::fs::remove_dir_all(&root);

        let result = result.unwrap();
        assert_eq!(
            result["removed"],
            serde_json::json!([file.clone(), format!("{file}.pub")])
        );
        assert_eq!(result["removedHosts"], serde_json::json!(["prod"]));
        assert_eq!(result["warnings"], serde_json::json!([]));
        assert!(gone);
        assert!(!config.contains("Host prod"), "{config}");
        let stored = db.get_key("k1").unwrap().unwrap();
        assert!(!stored.deployed && stored.deploy_path.is_none());
        assert!(db
            .list_audit(10)
            .unwrap()
            .iter()
            .any(|a| a.action == "keys.undeployed"));
    }

    /// A private key file that cannot be deleted is an error, and the key
    /// stays marked as deployed - the old code dropped the error and cleared
    /// the record while the secret stayed on disk.
    #[test]
    fn remove_deployed_keeps_the_record_when_the_file_cannot_be_removed() {
        let db = test_db();
        insert_real_key(&db, "k1", "web");
        let (root, target) = deploy_target("undeploy-fails");
        let stuck = target.ssh_dir.join("sshspan_web");
        std::fs::create_dir_all(&stuck).unwrap(); // remove_file cannot delete it
        db.set_key_deployment("k1", Some(&stuck.display().to_string()))
            .unwrap();
        let result = key_remove_deployed_in(
            &db,
            &unlocked_vault(),
            &VaultRotationLock::new(),
            &target,
            "k1",
        );
        let _ = std::fs::remove_dir_all(&root);

        assert!(result.unwrap_err().0.contains("still marked as deployed"));
        assert!(db.get_key("k1").unwrap().unwrap().deployed);
        assert!(db
            .list_audit(10)
            .unwrap()
            .iter()
            .any(|a| a.action == "keys.undeploy_failed"));
    }

    /// A recorded path that is not one of SSHSpan's own files in the managed
    /// directory is never deleted (a pre-F9 restore could have planted one);
    /// the record is cleared and the result says why.
    #[test]
    fn remove_deployed_never_deletes_a_file_sshspan_did_not_write() {
        let db = test_db();
        insert_real_key(&db, "k1", "web");
        let (root, target) = deploy_target("undeploy-foreign");
        std::fs::create_dir_all(&target.ssh_dir).unwrap();
        let users_key = target.ssh_dir.join("id_ed25519");
        std::fs::write(&users_key, "THE USER'S OWN KEY").unwrap();
        db.set_key_deployment("k1", Some(&users_key.display().to_string()))
            .unwrap();
        let result = key_remove_deployed_in(
            &db,
            &unlocked_vault(),
            &VaultRotationLock::new(),
            &target,
            "k1",
        );
        let kept = users_key.exists();
        let _ = std::fs::remove_dir_all(&root);

        let result = result.unwrap();
        assert!(kept);
        assert_eq!(result["removed"], serde_json::json!([]));
        assert_eq!(result["warnings"].as_array().unwrap().len(), 1);
        assert!(!db.get_key("k1").unwrap().unwrap().deployed);
        assert_refused_while_locked(key_remove_deployed_in(
            &db,
            &locked_vault(),
            &VaultRotationLock::new(),
            &target,
            "k1",
        ));
    }

    /// Minor 6: undeploying a key that was never deployed changes nothing and
    /// leaves no "keys.undeployed" audit row claiming otherwise.
    #[test]
    fn remove_deployed_of_an_undeployed_key_audits_nothing() {
        let db = test_db();
        insert_real_key(&db, "k1", "web");
        let (root, target) = deploy_target("undeploy-noop");
        let result = key_remove_deployed_in(
            &db,
            &unlocked_vault(),
            &VaultRotationLock::new(),
            &target,
            "k1",
        );
        let _ = std::fs::remove_dir_all(&root);
        let result = result.unwrap();
        assert_eq!(result["removed"], serde_json::json!([]));
        assert!(!db
            .list_audit(10)
            .unwrap()
            .iter()
            .any(|a| a.action.starts_with("keys.undeploy")));
    }

    /// RU1 leftover: the busy message is also what a restore, an export or
    /// another password change produces, so it must not name only two of them.
    #[test]
    fn rotation_busy_message_names_any_vault_operation() {
        assert_eq!(
            ROTATION_LOCK_BUSY,
            "Another vault operation is still running - try again when it finishes."
        );
    }

    #[test]
    fn category_create_refuses_while_locked() {
        let db = test_db();
        let create = |vault: &VaultPasswordStore| {
            category_create_in(&db, vault, "Prod".into(), None, None, Some("key".into()))
        };
        assert_refused_while_locked(create(&locked_vault()));
        assert!(db.list_categories().unwrap().is_empty());
        create(&unlocked_vault()).unwrap();
        assert_eq!(db.list_categories().unwrap().len(), 1);
    }

    #[test]
    fn category_rename_refuses_while_locked() {
        let db = test_db();
        db.insert_category(&sample_category("c1", "key")).unwrap();
        assert_refused_while_locked(category_rename_in(&db, &locked_vault(), "c1", "x".into()));
        assert_eq!(db.get_category("c1").unwrap().unwrap().name, "cat-c1");
        category_rename_in(&db, &unlocked_vault(), "c1", "x".into()).unwrap();
        assert_eq!(db.get_category("c1").unwrap().unwrap().name, "x");
    }

    #[test]
    fn category_reparent_refuses_while_locked() {
        let db = test_db();
        db.insert_category(&sample_category("parent", "key"))
            .unwrap();
        db.insert_category(&sample_category("child", "key"))
            .unwrap();
        let reparent = |vault: &VaultPasswordStore| {
            category_reparent_in(&db, vault, "child".into(), Some("parent".into()), None)
        };
        assert_refused_while_locked(reparent(&locked_vault()));
        assert_eq!(db.get_category("child").unwrap().unwrap().parent_id, None);
        reparent(&unlocked_vault()).unwrap();
        assert_eq!(
            db.get_category("child")
                .unwrap()
                .unwrap()
                .parent_id
                .as_deref(),
            Some("parent")
        );
    }

    #[test]
    fn category_delete_refuses_while_locked() {
        let db = test_db();
        db.insert_category(&sample_category("c1", "host")).unwrap();
        assert_refused_while_locked(category_delete_in(&db, &locked_vault(), "c1"));
        assert!(db.get_category("c1").unwrap().is_some(), "must survive");
        category_delete_in(&db, &unlocked_vault(), "c1").unwrap();
        assert!(db.get_category("c1").unwrap().is_none());
    }

    #[test]
    fn key_set_categories_refuses_while_locked() {
        let db = test_db();
        db.insert_key(&sample_key("k1", "pw")).unwrap();
        db.insert_category(&sample_category("c1", "key")).unwrap();
        let ids = vec!["c1".to_string()];
        assert_refused_while_locked(key_set_categories_in(&db, &locked_vault(), "k1", &ids));
        assert!(db.list_categories_for_key("k1").unwrap().is_empty());
        key_set_categories_in(&db, &unlocked_vault(), "k1", &ids).unwrap();
        assert_eq!(db.list_categories_for_key("k1").unwrap(), ids);
    }

    #[test]
    fn audit_clear_refuses_while_locked() {
        let db = test_db();
        db.add_audit("probe", None, "kept").unwrap();
        assert_refused_while_locked(audit_clear_in(&db, &locked_vault()));
        assert_eq!(db.count_audit().unwrap(), 1, "the audit trail must survive");
        audit_clear_in(&db, &unlocked_vault()).unwrap();
        // Only the marker row of the clear itself remains.
        assert_eq!(db.count_audit().unwrap(), 1);
        assert_eq!(db.list_audit(1).unwrap()[0].action, "audit.cleared");
    }

    #[test]
    fn known_hosts_forget_refuses_while_locked() {
        let db = test_db();
        db.add_known_host("example.com:22", "AAAAhostkey", "SHA256:fp")
            .unwrap();
        let forget = terminal::known_hosts_forget_in;
        assert_refused_while_locked(forget(&db, &locked_vault(), "example.com:22"));
        assert!(
            db.get_known_host("example.com:22").unwrap().is_some(),
            "pin kept"
        );
        forget(&db, &unlocked_vault(), "example.com:22").unwrap();
        assert!(db.get_known_host("example.com:22").unwrap().is_none());
    }

    /// Only the security-relevant settings are locked; display and
    /// file-browser preferences stay writable on a locked vault.
    #[test]
    fn settings_set_refuses_security_settings_while_locked() {
        let db = test_db();
        for (key, value) in [
            ("autoLockMinutes", "0"),
            ("confirmDelete", "false"),
            ("autoUpdateCheck", "false"),
            ("confirmMultiLinePaste", "0"),
        ] {
            assert_refused_while_locked(settings_set_in(&db, &locked_vault(), key, value));
            assert_eq!(
                db.get_config(&format!("setting.{key}")).unwrap(),
                None,
                "{key} must not be written while locked"
            );
            settings_set_in(&db, &unlocked_vault(), key, value).unwrap();
        }
        for (key, value) in [
            ("uiScale", "110"),
            ("sftpShowHidden", "1"),
            ("terminalBell", "sound"),
            ("sftpLocalDir:server-1", "/tmp"),
        ] {
            settings_set_in(&db, &locked_vault(), key, value)
                .unwrap_or_else(|e| panic!("{key} must stay writable while locked: {}", e.0));
        }
    }

    // ── A7-11 / A2-14 / A5-32: settings defaults and value validation ──

    /// Every value the renderer writes through `settings_set` today, per key:
    /// the app.js Settings rows and the sftp.js toggles, conflict dialog and
    /// local-directory default. All of them must be accepted.
    const RENDERER_SETTING_VALUES: &[(&str, &[&str])] = &[
        // String(mins), mins = min(1440, parseInt of /^\d+$/)
        ("autoLockMinutes", &["0", "1", "15", "60", "1440"]),
        // clampUiScale(<select>): options 90..200, clamped to 75..200
        (
            "uiScale",
            &["75", "90", "100", "110", "125", "150", "175", "200"],
        ),
        ("confirmDelete", &["true", "false"]),
        ("confirmMultiLinePaste", &["1", "0"]),
        ("autoUpdateCheck", &["true", "false"]),
        // clamped to 1..4
        ("sftpParallel", &["1", "2", "3", "4"]),
        ("sftpShowHidden", &["1", "0"]),
        // 0 (unlimited) or 1..=1_000_000 x 1024 (KB/s) / 1048576 (MB/s)
        (
            "sftpMaxBps",
            &[
                "0",
                "1024",
                "524288",
                "1048576",
                "1024000000",
                "1048576000000",
            ],
        ),
        ("sftpVerifyTransfers", &["true", "false"]),
        // Settings select ("ask") + the conflict dialog's CONFLICT_ACTIONS
        (
            "sftpConflictUpload",
            &["ask", "overwrite", "skip", "rename", "resume"],
        ),
        (
            "sftpConflictDownload",
            &["ask", "overwrite", "skip", "rename", "resume"],
        ),
        ("sftpResumeDefault", &["ask", "overwrite", "resume"]),
        // clamped to 1000..50000
        ("terminalScrollback", &["1000", "5000", "50000"]),
        ("terminalBell", &["visual", "sound", "silent"]),
        ("terminalBackspace", &["default", "backspace"]),
        ("terminalHomeEnd", &["default", "rxvt"]),
        ("terminalAppCursorKeys", &["default", "disabled"]),
        ("terminalAppKeypad", &["default", "disabled"]),
        ("sftpShowOwnerCols", &["1", "0"]),
        ("sftpPreserveTs", &["1", "0"]),
        ("sftpDualPane", &["1", "0"]),
        // next || '' - empty turns the comparison off
        ("sftpCmpMode", &["size", "mtime", ""]),
        // the local pane's current directory
        (
            "sftpLocalDir:server-1",
            &["/home/me/projects", "C:\\Users\\me\\Downloads"],
        ),
    ];

    /// Values outside each key's domain - what the old allowlist-only check
    /// stored with a success toast.
    const OUT_OF_DOMAIN_SETTING_VALUES: &[(&str, &[&str])] = &[
        (
            "autoLockMinutes",
            &["-5", "", "1.5", "1441", "abc", " 15", "+5", "15 "],
        ),
        ("uiScale", &["74", "201", "", "100%", "1.1"]),
        ("confirmDelete", &["", "yes", "1", "TRUE"]),
        ("confirmMultiLinePaste", &["", "true", "2"]),
        ("autoUpdateCheck", &["", "on", "0"]),
        ("sftpParallel", &["0", "5", "", "two"]),
        ("sftpShowHidden", &["true", "", "yes"]),
        ("sftpMaxBps", &["-1", "", "1e6", "1048576000001"]),
        ("sftpVerifyTransfers", &["1", "", "on"]),
        ("sftpConflictUpload", &["", "replace", "ASK"]),
        ("sftpConflictDownload", &["", "newer"]),
        ("sftpResumeDefault", &["skip", "rename", ""]),
        ("terminalScrollback", &["999", "50001", "", "5k"]),
        ("terminalBell", &["", "beep"]),
        ("terminalBackspace", &["", "delete"]),
        ("terminalHomeEnd", &["", "vt100"]),
        ("terminalAppCursorKeys", &["", "enabled"]),
        ("terminalAppKeypad", &["", "enabled"]),
        ("sftpShowOwnerCols", &["", "true"]),
        ("sftpPreserveTs", &["", "false"]),
        ("sftpDualPane", &["", "yes"]),
        ("sftpCmpMode", &["off", "SIZE", "hash"]),
        ("sftpLocalDir:server-1", &["", "bad\0path"]),
    ];

    #[test]
    fn settings_set_accepts_every_value_the_renderer_writes() {
        let db = test_db();
        let vault = unlocked_vault();
        for (key, values) in RENDERER_SETTING_VALUES {
            for value in *values {
                settings_set_in(&db, &vault, key, value).unwrap_or_else(|e| {
                    panic!("{key} = {value:?} is what the renderer sends: {}", e.0)
                });
                assert_eq!(
                    db.get_config(&format!("setting.{key}")).unwrap().as_deref(),
                    Some(*value)
                );
            }
        }
        // Every allowlisted key has a domain in the table above.
        for key in SETTINGS_KEYS {
            assert!(
                RENDERER_SETTING_VALUES.iter().any(|(k, _)| k == key),
                "{key} has no renderer values in this contract test"
            );
        }
    }

    #[test]
    fn settings_set_rejects_out_of_domain_values() {
        let db = test_db();
        let vault = unlocked_vault();
        for (key, values) in OUT_OF_DOMAIN_SETTING_VALUES {
            for value in *values {
                assert!(
                    settings_set_in(&db, &vault, key, value).is_err(),
                    "{key} = {value:?} must be rejected"
                );
                assert_eq!(
                    db.get_config(&format!("setting.{key}")).unwrap(),
                    None,
                    "{key} = {value:?} must not be stored"
                );
            }
        }
    }

    /// A fresh install has nothing stored; the UI must still be told the
    /// values the backend applies (auto-lock 15 minutes, 4 parallel
    /// transfers), and a stored value always wins over the default.
    #[test]
    fn collect_settings_reports_defaults_when_nothing_is_stored() {
        let db = test_db();
        let fresh = collect_settings(&db).unwrap();
        assert_eq!(fresh.get("autoLockMinutes"), Some(&serde_json::json!("15")));
        assert_eq!(fresh.get("sftpParallel"), Some(&serde_json::json!("4")));

        db.set_config("setting.autoLockMinutes", "0").unwrap();
        db.set_config("setting.sftpParallel", "2").unwrap();
        let stored = collect_settings(&db).unwrap();
        assert_eq!(stored.get("autoLockMinutes"), Some(&serde_json::json!("0")));
        assert_eq!(stored.get("sftpParallel"), Some(&serde_json::json!("2")));
    }

    /// The watchdog reads `autoLockMinutes` exactly like the renderer's
    /// `autoLockMinutes()`: absent / blank / not a whole number (negative
    /// included) is the 15-minute default, "0" is off, at most 1440.
    #[test]
    fn watchdog_reads_auto_lock_minutes_like_the_renderer() {
        for (stored, expected) in [
            (None, 15),
            (Some("15"), 15),
            (Some("0"), 0),
            (Some("1"), 1),
            (Some("1440"), 1440),
            (Some("-5"), 15),
            (Some(""), 15),
            (Some("abc"), 15),
            (Some("1.5"), 15),
            (Some("+5"), 15),
            (Some(" 30 "), 30),
            (Some("5000"), 1440),
            (Some("99999999999999999999999"), 1440),
        ] {
            assert_eq!(
                effective_auto_lock_minutes(stored),
                expected,
                "stored {stored:?}"
            );
        }
    }

    // ── A7-52: master-password length counts characters ──

    #[test]
    fn master_password_length_counts_characters_not_bytes() {
        assert!(!master_password_long_enough("\u{1f511}\u{1f511}")); // 2 chars, 8 bytes
        assert!(!master_password_long_enough("密码密码")); // 4 chars, 12 bytes
        assert!(!master_password_long_enough("ééééééé")); // 7 chars, 14 bytes
        assert!(!master_password_long_enough("short"));
        assert!(master_password_long_enough("éééééééé")); // 8 chars
        assert!(master_password_long_enough("abcdefgh"));
    }

    // ── A6-04 / A7-48: picked files are size-capped before they are read ──

    #[test]
    fn picked_text_files_over_the_cap_are_refused() {
        let dir = std::env::temp_dir().join(format!("sshspan-pick-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.pem");
        std::fs::write(&big, vec![b'a'; (MAX_SELECT_FILE_BYTES + 1) as usize]).unwrap();
        let at_cap = dir.join("at-cap.pem");
        std::fs::write(&at_cap, vec![b'a'; MAX_SELECT_FILE_BYTES as usize]).unwrap();
        let binary = dir.join("key.bin");
        std::fs::write(&binary, [0xff, 0xfe, 0x00, 0x80]).unwrap();

        let refused = read_picked_text_file(&big, MAX_SELECT_FILE_BYTES);
        let accepted = read_picked_text_file(&at_cap, MAX_SELECT_FILE_BYTES);
        let not_text = read_picked_text_file(&binary, MAX_SELECT_FILE_BYTES);
        let _ = std::fs::remove_dir_all(&dir);

        // The file contents are never echoed: an Ok here would be megabytes.
        let err = match refused {
            Err(e) => e,
            Ok(text) => panic!(
                "a file over the cap must be refused, read {} bytes",
                text.len()
            ),
        };
        assert!(
            err.0.contains("4 MiB"),
            "the message names the limit: {}",
            err.0
        );
        assert_eq!(
            accepted.map(|t| t.len()).ok(),
            Some(MAX_SELECT_FILE_BYTES as usize)
        );
        let err = match not_text {
            Err(e) => e,
            Ok(text) => panic!("binary data is not text, read {} bytes", text.len()),
        };
        assert!(
            err.0.contains("not a text file"),
            "clear message: {}",
            err.0
        );
    }

    // ── A6-11: copies of the master password are wiped on drop ──

    #[test]
    fn vault_password_store_hands_out_zeroizing_copies() {
        let store = unlocked_vault();
        let copy: Option<zeroize::Zeroizing<String>> = store.get();
        assert_eq!(copy.as_deref().map(String::as_str), Some("test-master-pw"));
        assert!(store.is_set());
        store.clear();
        assert!(!store.is_set());
        assert!(store.get().is_none());
    }

    // ── A6-03 / A2-48 / R5: backups are written and read by Rust ──

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sshspan-{tag}-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A restore grant (an OPEN-dialog pick waiting for the backup password)
    /// must never authorise a write, a save-dialog grant must never authorise
    /// a restore, and each is good for one use.
    #[test]
    fn restore_grants_are_separate_from_write_grants_and_single_use() {
        let store = DialogPathStore::new();
        store.allow_restore("/home/me/backup.json");
        assert!(!store.consume("/home/me/backup.json"), "not a write grant");
        assert!(store.consume_restore("/home/me/backup.json"));
        assert!(!store.consume_restore("/home/me/backup.json"), "single use");
        store.allow("/home/me/export.csv");
        assert!(
            !store.consume_restore("/home/me/export.csv"),
            "not a restore grant"
        );
        assert!(store.consume("/home/me/export.csv"));
    }

    #[test]
    fn backup_exported_to_a_file_restores_from_that_file() {
        let pw = "file-round-trip-pw";
        let src = test_db();
        src.insert_key(&sample_key("k1", pw)).unwrap();
        let dir = scratch_dir("backup-file");
        let path = dir.join("vault.json");
        let path_str = path.display().to_string();

        let exported = export_backup_to_path(&src, pw, &path_str, &|| Ok(()));
        let text = std::fs::read_to_string(&path);
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o777)
        };
        let dst = test_db();
        let restored = restore_backup_file(&dst, &path, pw, None, &|| Ok(()));
        let _ = std::fs::remove_dir_all(&dir);

        let exported = exported.unwrap();
        assert_eq!(exported["path"], serde_json::json!(path_str));
        assert_eq!(exported["counts"]["keys"], 1);
        let doc: serde_json::Value = serde_json::from_str(&text.unwrap()).unwrap();
        assert_eq!(doc["format"], "sshspan-backup");
        #[cfg(unix)]
        assert_eq!(mode.unwrap(), 0o600, "written through write_secret_file");
        assert!(src
            .list_audit(10)
            .unwrap()
            .iter()
            .any(|a| a.action == "vault.backup_created"));
        match restored.unwrap() {
            RestoreOutcome::Restored(r) => assert_eq!(r["counts"]["keys"], 1),
            other => panic!("expected a restore, got {other:?}"),
        }
        assert!(dst.get_key("k1").unwrap().is_some());
    }

    #[test]
    fn backup_file_from_another_master_password_needs_that_password() {
        let (old_pw, new_pw) = ("backup-era-pw", "current-master-pw");
        let src = test_db();
        src.insert_key(&sample_key("k1", old_pw)).unwrap();
        let dir = scratch_dir("backup-pw");
        let path = dir.join("old.json");
        export_backup_to_path(&src, old_pw, &path.display().to_string(), &|| Ok(())).unwrap();

        let dst = test_db();
        let no_pw = restore_backup_file(&dst, &path, new_pw, None, &|| Ok(()));
        let wrong = restore_backup_file(&dst, &path, new_pw, Some("not-it"), &|| Ok(()));
        let untouched = dst.get_key("k1").unwrap().is_none();
        let right = restore_backup_file(&dst, &path, new_pw, Some(old_pw), &|| Ok(()));
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            matches!(no_pw, Ok(RestoreOutcome::NeedsPassword)),
            "{no_pw:?}"
        );
        assert_eq!(wrong.unwrap_err().0, "Backup password is incorrect.");
        assert!(
            untouched,
            "a missing or wrong backup password restores nothing"
        );
        match right.unwrap() {
            RestoreOutcome::Restored(r) => assert_eq!(r["passwordReLinked"], true),
            other => panic!("expected a restore, got {other:?}"),
        }
        let key = dst.get_key("k1").unwrap().unwrap();
        assert!(
            crate::crypto::vault::unseal(new_pw, &key.private_key_encrypted).is_ok(),
            "re-sealed under the current master password"
        );
    }

    #[test]
    fn oversized_backup_file_is_refused() {
        let dir = scratch_dir("backup-big");
        let path = dir.join("huge.json");
        // Sparse: the size is what matters, not 32 MiB of writes.
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_BACKUP_FILE_BYTES + 1)
            .unwrap();
        let result = restore_backup_file(&test_db(), &path, "pw", None, &|| Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
        let err = result.expect_err("a file over the cap must be refused");
        assert!(
            err.0.contains("32 MiB"),
            "the message names the limit: {}",
            err.0
        );
    }

    /// The vault-generation re-check runs between building and writing: a
    /// lock while the user sat in the save dialog means no file at all.
    #[test]
    fn backup_export_writes_nothing_when_the_vault_locked_meanwhile() {
        let db = test_db();
        let dir = scratch_dir("backup-locked");
        let path = dir.join("vault.json");
        let refused = export_backup_to_path(&db, "pw", &path.display().to_string(), &|| {
            Err(CmdError(
                "Vault was locked while the operation was in progress.".into(),
            ))
        });
        let written = path.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(refused.is_err());
        assert!(!written, "nothing may be written after a lock");
    }

    // ── A7-13: the master-password change runs off the main thread ──

    /// The moved commands do their DB work inside `run_blocking`, i.e. on a
    /// blocking-pool thread of Tauri's runtime; the DB layer's `block()` must
    /// work there too, not only on a plain thread or a runtime worker.
    #[test]
    fn db_work_runs_inside_run_blocking() {
        let db = test_db();
        db.insert_key(&sample_key("k1", "pw")).unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let names = rt
            .block_on(run_blocking(move || {
                let keys = db.list_keys().map_err(|e| e.to_string())?;
                Ok(keys.into_iter().map(|k| k.name).collect::<Vec<_>>())
            }))
            .unwrap();
        assert_eq!(names, vec!["key-k1".to_string()]);
    }

    fn vault_db(master_pw: &str) -> db::Database {
        let db = test_db();
        db.set_config(MASTER_HASH_KEY, &hash_master_password(master_pw).unwrap())
            .unwrap();
        db
    }

    #[test]
    fn password_rotation_reseals_records_and_the_verifier() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.insert_key(&sample_key("k1", old_pw)).unwrap();
        db.insert_server(&sample_server("s1", Some("srv-pw"), old_pw))
            .unwrap();
        let throttle = UnlockThrottle::new();

        let wrong = rotate_master_password(&db, &throttle, "not-it", new_pw, &|| true);
        assert_eq!(
            wrong.unwrap_err().0,
            "Current master password is incorrect."
        );

        let summary = rotate_master_password(&db, &throttle, old_pw, new_pw, &|| true).unwrap();
        assert_eq!(
            summary,
            RotationSummary {
                keys: 1,
                server_passwords: 1
            }
        );
        assert!(verify_master_password(&db, new_pw).unwrap());
        let key = db.get_key("k1").unwrap().unwrap();
        assert!(crate::crypto::vault::unseal(new_pw, &key.private_key_encrypted).is_ok());
        let srv = db.get_server("s1").unwrap().unwrap();
        let saved = crate::crypto::vault::unseal(new_pw, srv.saved_password.as_ref().unwrap());
        assert_eq!(saved.unwrap(), b"srv-pw");
    }

    /// A lock while the records were being re-sealed aborts before anything
    /// commits: the old password still opens everything.
    #[test]
    fn password_rotation_aborts_when_the_vault_locks_mid_way() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.insert_key(&sample_key("k1", old_pw)).unwrap();
        let err = rotate_master_password(&db, &UnlockThrottle::new(), old_pw, new_pw, &|| false)
            .unwrap_err();
        assert_eq!(
            err.0,
            "Vault was locked while the operation was in progress."
        );
        assert!(verify_master_password(&db, old_pw).unwrap());
        let key = db.get_key("k1").unwrap().unwrap();
        assert!(crate::crypto::vault::unseal(old_pw, &key.private_key_encrypted).is_ok());
    }

    /// Off the main thread, a tray "Lock Vault" can land while the rotation
    /// runs. Installing the new password afterwards must not undo that lock.
    #[test]
    fn rotated_password_is_not_installed_after_a_lock() {
        let (store, generation) = (VaultPasswordStore::new(), VaultGeneration::new());
        let captured = generation.current();
        install_rotated_password(&store, &generation, captured, "new-pw".to_string().into());
        assert!(
            store.is_set(),
            "no lock in between: the new password is installed"
        );

        store.clear();
        let captured = generation.current();
        generation.bump(); // the lock
        install_rotated_password(&store, &generation, captured, "new-pw".to_string().into());
        assert!(
            !store.is_set(),
            "a lock during the rotation must stay locked"
        );
    }

    // ── C1: nothing sealed or rewritten meanwhile may be stranded or lost ──

    /// A key sealed with the OLD password while the rotation runs - inserted
    /// here behind every guard's back - must not be stranded: the rotation
    /// aborts with nothing committed, no record is left that the accepted
    /// master password cannot open, and the next rotation succeeds.
    #[test]
    fn rotation_never_strands_a_record_sealed_with_the_old_password_meanwhile() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.insert_key(&sample_key("k1", old_pw)).unwrap();
        let throttle = UnlockThrottle::new();

        let result = rotate_master_password(&db, &throttle, old_pw, new_pw, &|| {
            db.insert_key(&sample_key("late", old_pw)).unwrap();
            true
        });

        let master = if verify_master_password(&db, new_pw).unwrap() {
            new_pw
        } else {
            old_pw
        };
        let unreadable: Vec<String> = db
            .list_keys()
            .unwrap()
            .into_iter()
            .filter(|k| crate::crypto::vault::unseal(master, &k.private_key_encrypted).is_err())
            .map(|k| k.id)
            .collect();
        assert!(
            unreadable.is_empty(),
            "stranded under the master password: {unreadable:?} (rotation: {result:?})"
        );
        assert!(result.is_err(), "the rotation must abort");
        let next = rotate_master_password(&db, &throttle, master, "newer-master-pw", &|| true);
        assert_eq!(next.unwrap().keys, 2, "the next change re-seals both keys");
    }

    /// The commit rewrote every column of every snapshot row, so an edit made
    /// while the rotation ran (a rename here) was silently reverted. Only the
    /// sealed column may change.
    #[test]
    fn rotation_keeps_edits_made_to_other_columns_meanwhile() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.insert_key(&sample_key("k1", old_pw)).unwrap();

        let reencrypted =
            rotate_master_password(&db, &UnlockThrottle::new(), old_pw, new_pw, &|| {
                let mut key = db.get_key("k1").unwrap().unwrap();
                key.name = "renamed-meanwhile".into();
                db.update_key(&key).unwrap();
                true
            })
            .unwrap();

        assert_eq!(reencrypted.keys, 1);
        let key = db.get_key("k1").unwrap().unwrap();
        assert_eq!(key.name, "renamed-meanwhile", "the rename survives");
        assert!(crate::crypto::vault::unseal(new_pw, &key.private_key_encrypted).is_ok());
    }

    /// The MCP step upserted each snapshot record whole, reverting a tool
    /// toggled (or an approval revoked) while the rotation ran. Only the
    /// sealed secret may change.
    #[test]
    fn rotation_rewrites_only_the_mcp_secret() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.save_mcp_server(&db::McpServerRecord {
            id: "m1".into(),
            name: "tools".into(),
            url: "https://mcp.example.com".into(),
            auth_type: "bearer".into(),
            auth_header_name: None,
            auth_secret: Some(crate::crypto::vault::seal(old_pw, b"mcp-secret").unwrap()),
            auth_env_var: None,
            confirmed: true,
            tools: vec![db::McpToolRecord {
                name: "search".into(),
                display_name: None,
                description: String::new(),
                enabled: true,
                auto_approve: true,
                pin_hash: Some("pin".into()),
                current_hash: Some("pin".into()),
                input_schema: None,
                annotations: None,
            }],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();

        rotate_master_password(&db, &UnlockThrottle::new(), old_pw, new_pw, &|| {
            // The user revokes the approval while the rotation runs.
            let mut record = db.get_mcp_server("m1").unwrap().unwrap();
            record.tools[0].enabled = false;
            record.tools[0].auto_approve = false;
            record.tools[0].pin_hash = None;
            db.save_mcp_server(&record).unwrap();
            true
        })
        .unwrap();

        let record = db.get_mcp_server("m1").unwrap().unwrap();
        assert!(
            !record.tools[0].enabled && !record.tools[0].auto_approve,
            "the revoked approval must stay revoked"
        );
        assert_eq!(record.tools[0].pin_hash, None);
        let secret = record.auth_secret.as_deref().unwrap();
        assert_eq!(
            crate::crypto::vault::unseal(new_pw, secret).unwrap(),
            b"mcp-secret"
        );
    }

    /// A guarded writer arriving mid-rotation is turned away at once with the
    /// busy error (instead of sealing with the old password), the rotation
    /// completes, every key opens with the new password, and the guard is
    /// free again afterwards.
    #[test]
    fn rotation_turns_away_guarded_writers_mid_rotation() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.insert_key(&sample_key("k1", old_pw)).unwrap();
        let lock = VaultRotationLock::new();
        let unlocked = unlocked_vault();
        let throttle = UnlockThrottle::new();

        let exclusive = lock
            .exclusive_within(std::time::Duration::from_secs(5))
            .unwrap();
        let refused = std::cell::RefCell::new(Vec::new());
        let reencrypted = rotate_master_password(&db, &throttle, old_pw, new_pw, &|| {
            refused
                .borrow_mut()
                .push(key_rename_in(&db, &unlocked, &lock, "k1", "renamed").map(|_| ()));
            refused.borrow_mut().push(lock.try_shared().map(|_| ()));
            true
        });
        drop(exclusive);

        for attempt in refused.into_inner() {
            assert_eq!(attempt.unwrap_err().0, VAULT_REENCRYPTING);
        }
        assert_eq!(reencrypted.unwrap().keys, 1);
        let key = db.get_key("k1").unwrap().unwrap();
        assert_eq!(key.name, "key-k1", "the refused rename changed nothing");
        assert!(crate::crypto::vault::unseal(new_pw, &key.private_key_encrypted).is_ok());
        key_rename_in(&db, &unlocked, &lock, "k1", "renamed").unwrap();
        let next = rotate_master_password(&db, &throttle, new_pw, "newer-master-pw", &|| true);
        assert_eq!(next.unwrap().keys, 1);
    }

    /// The whole change, as the command runs it: lock, rotate, install the
    /// new password, audit it - and the lock is released afterwards.
    #[test]
    fn change_master_password_installs_the_new_password_and_releases_the_lock() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.insert_key(&sample_key("k1", old_pw)).unwrap();
        let (throttle, lock, store, generations) = (
            UnlockThrottle::new(),
            VaultRotationLock::new(),
            unlocked_vault(),
            VaultGeneration::new(),
        );
        let vault = RotationContext {
            throttle: &throttle,
            lock: &lock,
            store: &store,
            generations: &generations,
            lock_wait: ROTATION_LOCK_WAIT,
        };
        let reencrypted = change_master_password(
            &db,
            &vault,
            generations.current(),
            old_pw,
            new_pw.to_string().into(),
        )
        .unwrap();
        assert_eq!(reencrypted, 1);
        assert_eq!(store.get().as_deref().map(String::as_str), Some(new_pw));
        assert!(lock.try_shared().is_ok(), "the lock is released");
        assert!(db
            .list_audit(10)
            .unwrap()
            .iter()
            .any(|a| a.action == "vault.password_changed"));
    }

    /// Fix 2, MUST B: the export seals the backup with the master password,
    /// so while a change holds the lock it is refused at once and writes no
    /// file; afterwards it works again.
    #[test]
    fn backup_export_is_refused_while_the_master_password_is_being_changed() {
        let db = test_db();
        db.insert_key(&sample_key("k1", "test-master-pw")).unwrap();
        let (lock, store) = (VaultRotationLock::new(), unlocked_vault());
        let dir = scratch_dir("backup-busy");
        let path = dir.join("vault.json");
        let path_str = path.display().to_string();

        let change = lock
            .exclusive_within(std::time::Duration::from_secs(5))
            .unwrap();
        let refused = export_backup_guarded(&db, &lock, &store, &path_str, &|| Ok(()));
        let written_while_busy = path.exists();
        drop(change);
        let exported = export_backup_guarded(&db, &lock, &store, &path_str, &|| Ok(()));
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(refused.unwrap_err().0, VAULT_REENCRYPTING);
        assert!(!written_while_busy, "nothing may be written while busy");
        assert_eq!(exported.unwrap()["counts"]["keys"], 1);
    }

    /// Fix 2, SHOULD 1: a sync or MCP call that keeps its read guard makes the
    /// change give up after the wait, with a message - and before the
    /// current-password check: a wrong password here is never looked at and
    /// costs no throttle failure.
    #[test]
    fn password_change_gives_up_waiting_for_a_running_sync() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.insert_key(&sample_key("k1", old_pw)).unwrap();
        let (throttle, lock, store, generations) = (
            UnlockThrottle::new(),
            VaultRotationLock::new(),
            unlocked_vault(),
            VaultGeneration::new(),
        );
        let vault = RotationContext {
            throttle: &throttle,
            lock: &lock,
            store: &store,
            generations: &generations,
            lock_wait: std::time::Duration::from_millis(200),
        };
        let running_sync = lock.try_shared().unwrap();
        let started = std::time::Instant::now();
        let err = change_master_password(
            &db,
            &vault,
            generations.current(),
            "not-the-current-password",
            new_pw.to_string().into(),
        )
        .unwrap_err();
        drop(running_sync);

        assert_eq!(err.0, ROTATION_LOCK_BUSY);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(throttle.state.lock().unwrap().consecutive_failures, 0);
        assert!(
            verify_master_password(&db, old_pw).unwrap(),
            "nothing changed"
        );
        assert!(
            lock.try_shared().is_ok(),
            "the given-up wait left no writer"
        );
    }

    /// While the change waits for the lock it is queued: new sealed-data
    /// writers are refused at once instead of extending the wait, and it gets
    /// the lock as soon as the running one finishes.
    #[test]
    fn a_waiting_password_change_refuses_new_writers() {
        let lock = VaultRotationLock::new();
        let running_sync = lock.try_shared().unwrap();
        std::thread::scope(|scope| {
            let change = scope.spawn(|| {
                lock.exclusive_within(std::time::Duration::from_secs(10))
                    .map(|_| ())
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while lock.try_shared().is_ok() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the change never queued for the lock"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert_eq!(lock.try_shared().unwrap_err().0, VAULT_REENCRYPTING);
            drop(running_sync);
            change.join().unwrap().unwrap();
        });
        assert!(lock.try_shared().is_ok());
    }

    /// Fix 2, MUST A: once the rotation has committed, the new password must
    /// be installed even if writing the audit row fails - otherwise the store
    /// keeps the OLD password over a vault sealed with the new one, and the
    /// next seal strands its record. Here the audit table is gone.
    #[test]
    fn a_failed_audit_write_after_the_commit_still_installs_the_new_password() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = vault_db(old_pw);
        db.insert_key(&sample_key("k1", old_pw)).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(sqlx::query("DROP TABLE audit_log").execute(&db.pool))
            .unwrap();
        let (throttle, lock, store, generations) = (
            UnlockThrottle::new(),
            VaultRotationLock::new(),
            unlocked_vault(),
            VaultGeneration::new(),
        );
        let vault = RotationContext {
            throttle: &throttle,
            lock: &lock,
            store: &store,
            generations: &generations,
            lock_wait: ROTATION_LOCK_WAIT,
        };
        let result = change_master_password(
            &db,
            &vault,
            generations.current(),
            old_pw,
            new_pw.to_string().into(),
        );
        assert!(verify_master_password(&db, new_pw).unwrap(), "committed");
        assert_eq!(
            store.get().as_deref().map(String::as_str),
            Some(new_pw),
            "the committed password must be installed"
        );
        assert_eq!(result.unwrap(), 1, "a committed change is reported as done");
    }

    /// MINOR 1: a lock that lands during a restore's re-seal (the generation
    /// moved) stops it before anything is committed.
    #[test]
    fn restore_commits_nothing_when_the_vault_locked_meanwhile() {
        let pw = "restore-lock-pw";
        let src = test_db();
        src.insert_key(&sample_key("k1", pw)).unwrap();
        let dir = scratch_dir("restore-locked");
        let path = dir.join("vault.json");
        export_backup_to_path(&src, pw, &path.display().to_string(), &|| Ok(())).unwrap();
        let dst = test_db();
        let result = restore_backup_file(&dst, &path, pw, None, &|| {
            Err(CmdError(
                "Vault was locked while the operation was in progress.".into(),
            ))
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            result.unwrap_err().0,
            "Vault was locked while the operation was in progress."
        );
        assert!(dst.get_key("k1").unwrap().is_none(), "nothing restored");
        assert!(!dst
            .list_audit(10)
            .unwrap()
            .iter()
            .any(|a| a.action == "vault.backup_restored"));
    }

    // ── restored settings go through the same validation as settings_set ──

    #[test]
    fn backup_settings_sanitizer_drops_invalid_values_too() {
        let mut settings = serde_json::Map::new();
        settings.insert("autoLockMinutes".into(), serde_json::json!("-5"));
        settings.insert("sftpParallel".into(), serde_json::json!("9"));
        settings.insert("confirmDelete".into(), serde_json::json!("yes"));
        settings.insert("uiScale".into(), serde_json::json!(110)); // not a string
        settings.insert("terminalBell".into(), serde_json::json!("sound"));

        let dropped = sanitize_backup_settings(&mut settings);

        assert_eq!(dropped, 4);
        assert_eq!(
            settings.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["terminalBell"]
        );
    }

    /// The restore result says how many settings were left out.
    #[test]
    fn restore_result_counts_the_settings_it_dropped() {
        let pw = "restore-settings-pw";
        let payload = serde_json::json!({
            "settings": {
                "autoLockMinutes": "-5",
                "theme": "dark",
                "terminalBell": "sound",
            },
        });
        let doc = serde_json::json!({
            "format": "sshspan-backup",
            "version": 1,
            "sealed": crate::crypto::vault::seal(pw, payload.to_string().as_bytes()).unwrap(),
        });
        let db = test_db();
        match apply_restore(&db, &doc, pw, None, &|| Ok(())).unwrap() {
            RestoreOutcome::Restored(r) => {
                assert_eq!(r["counts"]["settingsDropped"], 2);
                assert_eq!(r["counts"]["settings"], 1);
            }
            other => panic!("expected a restore, got {other:?}"),
        }
        assert_eq!(db.get_config("setting.autoLockMinutes").unwrap(), None);
        assert_eq!(
            db.get_config("setting.terminalBell").unwrap().as_deref(),
            Some("sound")
        );
    }
}

/// NOT REGISTERED in `generate_handler!`, deliberately.
///
/// It returns every key's `private_key_encrypted` blob to the webview. The
/// blobs are sealed with the master password, so this is not plaintext key
/// material - but it hands a compromised renderer the entire keystore to
/// attack offline, and nothing in the shipped UI ever called it. Registering
/// it again needs a reason and a review; `vault_backup_export_to_file` is the
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
/// caller-supplied key records straight into the vault;
/// `vault_backup_restore_from_file` is the reviewed import path.
#[tauri::command]
pub fn vault_import(app: AppHandle, keys: Vec<serde_json::Value>) -> CmdResult<serde_json::Value> {
    let _rotation = rotation_shared(&app)?;
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

/// NOT REGISTERED in `generate_handler!`, deliberately (A6-03 / A2-48, ruling
/// R5).
///
/// It returns the whole sealed backup document to the webview - every sealed
/// key, saved server password and MCP secret under ONE Argon2id envelope -
/// which is the exposure `vault_export` was de-registered for: a compromised
/// renderer could take it for an offline attack on the master password with
/// one call. `vault_backup_export_to_file` builds the same document and writes
/// it to the file the user picks without it ever crossing IPC.
#[tauri::command]
pub fn vault_backup_create(app: AppHandle) -> CmdResult<serde_json::Value> {
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let db = &app.state::<AppState>().db;
    let backup = build_backup_document(db, &pw)?;
    let _ = db.add_audit("vault.backup_created", None, &backup.counts.to_string());
    Ok(serde_json::json!({
        "json": backup.document, "filename": backup.filename, "counts": backup.counts,
    }))
}

/// A sealed vault backup, built in memory and not yet written anywhere.
pub struct BackupDocument {
    /// `{format, version, created, sealed}` - what goes into the file.
    pub document: serde_json::Value,
    /// Suggested file name, `sshspan-backup-<UTC stamp>.json`.
    pub filename: String,
    /// How many of each entity the backup holds.
    pub counts: serde_json::Value,
}

/// Build a vault backup in memory: keys + categories + links + servers +
/// known_hosts + stored settings + MCP servers + SFTP bookmarks, serialized
/// into one payload and sealed with `pw`. The inner key blobs are sealed with
/// the same password, so a backup can only be restored with the master
/// password that was current when it was created (or by supplying that
/// password at restore time). No `AppHandle`, so the backup -> restore round
/// trip is testable against a plain database.
pub fn build_backup_document(db: &db::Database, pw: &str) -> CmdResult<BackupDocument> {
    let keys = db.list_keys_with_categories().map_err(|e| e.to_string())?;
    let categories = db.list_categories().map_err(|e| e.to_string())?;
    let servers = db.list_servers().map_err(|e| e.to_string())?;
    let known_hosts = db.list_known_hosts().map_err(|e| e.to_string())?;
    // MCP servers travel with the backup (sealed auth secret included, same
    // vault password as everything else). They come back INERT on restore
    // (confirmed=false, all tools disabled) - see `restore_backup`.
    let mcp_servers = db.list_mcp_servers().map_err(|e| e.to_string())?;

    let settings = collect_stored_settings(db)?;

    // Per-server SFTP bookmarks live in `config`, outside the settings
    // allowlist, so the backup used to drop them (A7-41). A stored list that
    // does not parse reads back as "no bookmarks" in the file browser, so it
    // is left out rather than copied as garbage.
    let mut sftp_bookmarks = serde_json::Map::new();
    for (key, raw) in db
        .list_config_prefix(db::SFTP_BOOKMARKS_PREFIX)
        .map_err(|e| e.to_string())?
    {
        let Some(server_id) = key.strip_prefix(db::SFTP_BOOKMARKS_PREFIX) else {
            continue;
        };
        if let Ok(list @ serde_json::Value::Array(_)) = serde_json::from_str(&raw) {
            sftp_bookmarks.insert(server_id.to_string(), list);
        }
    }

    let payload = serde_json::json!({
        "keys": keys,
        "categories": categories,
        "servers": servers,
        "known_hosts": known_hosts,
        "settings": settings,
        "mcpServers": mcp_servers,
        "sftpBookmarks": sftp_bookmarks,
    });
    let payload_str = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let sealed =
        crate::crypto::vault::seal(pw, payload_str.as_bytes()).map_err(|e| e.to_string())?;

    let document = serde_json::json!({
        "format": "sshspan-backup",
        "version": 1,
        "created": now(),
        "sealed": sealed,
    });
    let filename = backup_file_name();
    let counts = serde_json::json!({
        "keys": keys.len(), "categories": categories.len(),
        "servers": servers.len(), "knownHosts": known_hosts.len(),
        "sftpBookmarks": sftp_bookmarks.len(),
    });
    Ok(BackupDocument {
        document,
        filename,
        counts,
    })
}

/// `sshspan-backup-<UTC stamp>.json`, the name the save dialog suggests.
fn backup_file_name() -> String {
    format!(
        "sshspan-backup-{}.json",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    )
}

/// Largest backup file a restore will read. A backup is a JSON envelope
/// around the sealed vault - well under this even for a large vault - so a
/// bigger file is refused before it is read into memory.
const MAX_BACKUP_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// Create a vault backup and save it to the file the user picks in the native
/// save dialog, all in Rust (A6-03 / A2-48, ruling R5): the sealed document
/// never reaches the webview. Returns `{ok, canceled: false, path, counts}`,
/// or `{canceled: true}` when the dialog is dismissed.
///
/// The vault generation is captured before the dialog, which can stay open
/// indefinitely, and re-checked before the file is written (the
/// `key_export_to_file` pattern): a lock in between means no file.
#[tauri::command]
/// NOTE: async on purpose. A synchronous command runs on the MAIN thread,
/// where tauri-plugin-dialog's `blocking_*` helpers deadlock (see
/// `system_pick_save_path`); and the Argon2id seal runs on a blocking worker.
pub async fn vault_backup_export_to_file(app: AppHandle) -> CmdResult<serde_json::Value> {
    use tauri_plugin_dialog::DialogExt;
    let generation = capture_vault_generation(&app)?;
    let picked = app
        .dialog()
        .file()
        .set_title("Save vault backup")
        .set_file_name(backup_file_name())
        .blocking_save_file();
    let Some(path) = picked else {
        return Ok(serde_json::json!({ "canceled": true }));
    };
    require_generation_current(&app, generation)?;
    let path = path.to_string();
    let worker = app.clone();
    run_blocking(move || {
        export_backup_guarded(
            &worker.state::<AppState>().db,
            worker.state::<VaultRotationLock>().inner(),
            worker.state::<VaultPasswordStore>().inner(),
            &path,
            &|| require_generation_current(&worker, generation),
        )
    })
    .await
}

/// The export worker's body. Read access to the [`VaultRotationLock`] comes
/// FIRST and is held until the file is written (C1, fix 2): the export reads
/// the master password, lists every sealed row and seals the document with
/// that password, so a master-password change committing in between would
/// produce a backup sealed with the old password around blobs sealed with
/// the new one. While a change runs, the export is refused at once.
fn export_backup_guarded(
    db: &db::Database,
    rotation: &VaultRotationLock,
    store: &VaultPasswordStore,
    path: &str,
    still_current: &dyn Fn() -> CmdResult<()>,
) -> CmdResult<serde_json::Value> {
    let _rotation = rotation.try_shared()?;
    let pw = store.get().unwrap_or_default();
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    export_backup_to_path(db, &pw, path, still_current)
}

/// [`vault_backup_export_to_file`] after the dialog, without the `AppHandle`:
/// build the backup and write it to `path` with `write_secret_file` (0600
/// from the first byte on Unix, owner-only ACL on Windows, fail closed), then
/// audit it. `still_current` is the vault-generation re-check, run after the
/// build and before the write.
fn export_backup_to_path(
    db: &db::Database,
    pw: &str,
    path: &str,
    still_current: &dyn Fn() -> CmdResult<()>,
) -> CmdResult<serde_json::Value> {
    // The dialog choice is the user's approval; the absolute/app-data/system
    // checks stay as a backstop (the app-data guard also keeps the vault DB
    // from being overwritten).
    validate_export_path(path)?;
    let backup = build_backup_document(db, pw)?;
    let text = serde_json::to_string_pretty(&backup.document).map_err(|e| e.to_string())?;
    still_current()?;
    crate::ssh::write_secret_file(std::path::Path::new(path), text.as_bytes())
        .map_err(|e| CmdError(e.to_string()))?;
    let _ = db.add_audit(
        "vault.backup_created",
        None,
        &format!("{} -> {path}", backup.counts),
    );
    Ok(serde_json::json!({
        "ok": true, "canceled": false, "path": path, "counts": backup.counts,
    }))
}

/// Restore a backup from a file, read by Rust (A6-03 / A2-48, ruling R5): the
/// file never passes through the webview.
///
/// With no `path` the native open dialog asks for the file. If the backup is
/// sealed under a different master password and no `backupPassword` came
/// with the call, nothing is restored: the answer is `{needsPassword: true,
/// path}` and that path gets a single-use grant for a few minutes, so the
/// retry - the same call with `path` and `backupPassword` - is accepted for
/// that file only. Otherwise the answer is `{canceled: true}` or the restore
/// result (`ok`, `counts`, `passwordReLinked`, `resealFailures`).
#[tauri::command]
/// NOTE: async on purpose: the dialog must not block the main thread (see
/// `system_pick_save_path`), and reading the file and re-sealing every record
/// (Argon2id each) run on a blocking worker.
pub async fn vault_backup_restore_from_file(
    app: AppHandle,
    path: Option<String>,
    backup_password: Option<String>,
) -> CmdResult<serde_json::Value> {
    use tauri_plugin_dialog::DialogExt;
    let backup_password = backup_password.map(zeroize::Zeroizing::new);
    // Captured before the dialog and re-checked right before the restore
    // commits: a lock in between - during the per-record re-seal included -
    // means nothing is restored into the locked vault.
    let generation = capture_vault_generation(&app)?;
    // A restore writes sealed rows, so it and a master-password change
    // exclude each other (C1): read access to the rotation lock is held from
    // here until the restore has committed. It is taken after the dialog
    // (never across it - the user may take any time there) and, on a retry,
    // BEFORE the single-use grant is spent, so a busy refusal does not cost
    // the user the file they picked.
    let (path, _rotation) = match path {
        None => {
            let picked = app
                .dialog()
                .file()
                .set_title("Restore vault backup")
                .blocking_pick_file();
            let Some(picked) = picked else {
                return Ok(serde_json::json!({ "canceled": true }));
            };
            (picked.to_string(), rotation_shared(&app)?)
        }
        Some(p) => {
            let rotation = rotation_shared(&app)?;
            // Only the file this flow itself offered back with `needsPassword`.
            if !app.state::<DialogPathStore>().consume_restore(&p) {
                return Err(
                    "Choose the backup file again - a restore only reads a file picked in its own dialog, once, within 5 minutes."
                        .into(),
                );
            }
            (p, rotation)
        }
    };
    let worker = app.clone();
    let source = path.clone();
    let outcome = run_blocking(move || {
        let pw = vault_password(&worker)?;
        if pw.is_empty() {
            return Err("Vault is locked.".into());
        }
        restore_backup_file(
            &worker.state::<AppState>().db,
            std::path::Path::new(&source),
            &pw,
            backup_password.as_deref().map(String::as_str),
            &|| require_generation_current(&worker, generation),
        )
    })
    .await?;
    match outcome {
        RestoreOutcome::Restored(result) => Ok(result),
        RestoreOutcome::NeedsPassword => {
            app.state::<DialogPathStore>().allow_restore(&path);
            Ok(serde_json::json!({ "needsPassword": true, "path": path }))
        }
    }
}

/// [`vault_backup_restore_from_file`] after the dialog and the grant, without
/// the `AppHandle`: read the file (capped at [`MAX_BACKUP_FILE_BYTES`]) and
/// restore it. `still_current` is the vault-generation re-check
/// [`apply_restore`] runs right before it commits.
fn restore_backup_file(
    db: &db::Database,
    path: &std::path::Path,
    pw: &str,
    backup_password: Option<&str>,
    still_current: &dyn Fn() -> CmdResult<()>,
) -> CmdResult<RestoreOutcome> {
    let text = read_picked_text_file(path, MAX_BACKUP_FILE_BYTES)?;
    let doc: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| CmdError("Not an SSHSpan backup file.".into()))?;
    apply_restore(db, &doc, pw, backup_password, still_current)
}

/// NOT REGISTERED in `generate_handler!`, deliberately (A6-03 / A2-48, ruling
/// R5) - the counterpart of `vault_backup_create`. It took the backup's text
/// from the webview, which the restore flow only had because
/// `system_select_file` had read the file into it.
/// `vault_backup_restore_from_file` reads the file in Rust instead.
#[tauri::command]
pub fn vault_backup_restore(
    app: AppHandle,
    payload_json: String,
    backup_password: Option<String>,
) -> CmdResult<serde_json::Value> {
    let _rotation = rotation_shared(&app)?;
    let pw = vault_password(&app)?;
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let doc: serde_json::Value = serde_json::from_str(&payload_json).map_err(|e| e.to_string())?;
    match apply_restore(
        &app.state::<AppState>().db,
        &doc,
        &pw,
        backup_password.as_deref(),
        &|| Ok(()),
    )? {
        RestoreOutcome::Restored(result) => Ok(result),
        RestoreOutcome::NeedsPassword => Err(
            "This backup was created with a different master password. Enter that password to restore it."
                .into(),
        ),
    }
}

/// What a restore attempt came to.
#[derive(Debug)]
pub enum RestoreOutcome {
    /// The backup is sealed under a different master password and no backup
    /// password was supplied. Nothing was written.
    NeedsPassword,
    /// The restore committed. The value is the IPC result: `ok`, `counts`,
    /// `passwordReLinked`, `resealFailures`.
    Restored(serde_json::Value),
}

/// Restore a parsed backup document into `db`, as the command layer does,
/// minus the `AppHandle`: `pw` is the current master password, and
/// `backup_password` the one that was current when the backup was taken (only
/// needed when they differ; empty counts as absent). `still_current` is the
/// vault-generation re-check, run right before anything is committed: a lock
/// during a long re-seal must not restore anything into the locked vault.
/// The caller holds read access to the [`VaultRotationLock`] through the
/// restore, so the master password stays current too.
pub fn apply_restore(
    db: &db::Database,
    doc: &serde_json::Value,
    pw: &str,
    backup_password: Option<&str>,
    still_current: &dyn Fn() -> CmdResult<()>,
) -> CmdResult<RestoreOutcome> {
    if doc.get("format").and_then(|v| v.as_str()) != Some("sshspan-backup") {
        return Err("Not an SSHSpan backup file.".into());
    }
    let Some(sealed) = doc.get("sealed").and_then(|v| v.as_str()) else {
        return Err("Backup file is missing its sealed payload.".into());
    };
    let backup_password = backup_password.filter(|p| !p.is_empty());

    let mut reused_backup_password = false;
    let plaintext = match crate::crypto::vault::unseal(pw, sealed) {
        Ok(bytes) => bytes,
        Err(_) => {
            let Some(bp) = backup_password else {
                return Ok(RestoreOutcome::NeedsPassword);
            };
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
        let bp = backup_password.unwrap_or_default();
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
                if let Ok(plain) =
                    crate::crypto::vault::unseal(bp, &blob).map(zeroize::Zeroizing::new)
                {
                    match crate::crypto::vault::seal(pw, &plain) {
                        Ok(resealed) => {
                            let mut k = k;
                            k["private_key_encrypted"] = serde_json::json!(resealed);
                            keep.push(k);
                        }
                        // Sealing failed: the blob is readable under the old
                        // password only, which is being discarded - excluded.
                        Err(_) => reseal_failures += 1,
                    }
                } else if crate::crypto::vault::unseal(pw, &blob).is_ok() {
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
                if let Ok(plain) =
                    crate::crypto::vault::unseal(bp, &blob).map(zeroize::Zeroizing::new)
                {
                    if let Ok(resealed) = crate::crypto::vault::seal(pw, &plain) {
                        sv["saved_password"] = serde_json::json!(resealed);
                        continue;
                    }
                }
                if crate::crypto::vault::unseal(pw, &blob).is_ok() {
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
                if let Ok(plain) =
                    crate::crypto::vault::unseal(bp, &blob).map(zeroize::Zeroizing::new)
                {
                    if let Ok(resealed) = crate::crypto::vault::seal(pw, &plain) {
                        m["auth_secret"] = serde_json::json!(resealed);
                        continue;
                    }
                }
                if crate::crypto::vault::unseal(pw, &blob).is_ok() {
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

    still_current()?;
    let mut counts = db.restore_backup(&data).map_err(|e| e.to_string())?;
    counts["settingsDropped"] = serde_json::json!(dropped_settings);
    let _ = db.add_audit("vault.backup_restored", None, &counts.to_string());
    if dropped_settings > 0 {
        let _ = db.add_audit(
            "vault.restore_settings_skipped",
            None,
            &format!("{dropped_settings} unknown or invalid setting(s) ignored on restore"),
        );
    }
    if reseal_failures > 0 {
        let _ = db.add_audit(
            "vault.restore_reseal_skipped",
            None,
            &format!(
                "{reseal_failures} entrie(s) unreadable under the backup password were skipped (keys excluded, saved passwords blanked)"
            ),
        );
    }
    Ok(RestoreOutcome::Restored(serde_json::json!({
        "ok": true,
        "counts": counts,
        "passwordReLinked": reused_backup_password,
        "resealFailures": reseal_failures,
    })))
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

/// Paths the user explicitly picked in a native dialog during this session,
/// kept per purpose.
///
/// Write grants are save-dialog picks: `system_write_text_file` requires one,
/// so a compromised renderer cannot use the write command against arbitrary
/// user-writable locations (Startup folders, shell rc files, ...) - only paths
/// a human approved in the OS dialog.
///
/// Restore grants are backup files picked in the restore dialog whose restore
/// is waiting for the backup password (`vault_backup_restore_from_file`
/// answered `needsPassword`). They are kept apart on purpose: an OPEN-dialog
/// pick must never become permission to WRITE that file, and a save-dialog
/// pick must never let a restore read some other file.
pub struct DialogPathStore {
    writes: PathGrants,
    restores: PathGrants,
}

/// How long a save-dialog path stays writable. The export flows use the path
/// within seconds of picking it, so a generous window covers retries without
/// leaving the grant alive for the whole session.
const DIALOG_PATH_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How long a picked backup file stays restorable while the user types the
/// password it was made with.
const RESTORE_GRANT_TTL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// One set of dialog grants: path -> when it was granted.
struct PathGrants {
    granted: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    ttl: std::time::Duration,
}

impl PathGrants {
    fn new(ttl: std::time::Duration) -> Self {
        Self {
            granted: std::sync::Mutex::new(std::collections::HashMap::new()),
            ttl,
        }
    }
    fn allow(&self, path: &str) {
        let mut guard = self.granted.lock().unwrap();
        let now = std::time::Instant::now();
        // Prune expired entries so the map cannot grow unboundedly.
        guard.retain(|_, granted| now.duration_since(*granted) < self.ttl);
        guard.insert(path.to_string(), now);
    }
    /// Consume a grant: a dialog pick authorises exactly ONE use.
    ///
    /// SECURITY: checking without consuming meant a path approved for a
    /// legitimate export stayed writable for the rest of the grant window, so
    /// a compromised renderer could wait for a real export and then rewrite
    /// that file with contents of its own. The grant is removed whether or not
    /// it had expired, so a stale entry cannot be retried.
    fn consume(&self, path: &str) -> bool {
        let mut guard = self.granted.lock().unwrap();
        match guard.remove(path) {
            Some(granted) => std::time::Instant::now().duration_since(granted) < self.ttl,
            None => false,
        }
    }
}

impl DialogPathStore {
    pub fn new() -> Self {
        Self {
            writes: PathGrants::new(DIALOG_PATH_TTL),
            restores: PathGrants::new(RESTORE_GRANT_TTL),
        }
    }
    /// Grant one `system_write_text_file` to a save-dialog pick.
    fn allow(&self, path: &str) {
        self.writes.allow(path);
    }
    /// Use up the write grant for `path`; false when there is none (any more).
    fn consume(&self, path: &str) -> bool {
        self.writes.consume(path)
    }
    /// Grant one follow-up restore of a backup file picked in the restore
    /// dialog.
    fn allow_restore(&self, path: &str) {
        self.restores.allow(path);
    }
    /// Use up the restore grant for `path`; false when there is none (any
    /// more).
    fn consume_restore(&self, path: &str) -> bool {
        self.restores.consume(path)
    }
}

/// Write UTF-8 text to an absolute path. The path must have been returned by
/// `system_pick_save_path` in this session AND must pass the
/// absolute/app-data/system checks - both gates, so the write target is
/// always a human-approved dialog choice.
///
/// The write goes through `write_secret_file` (0600 at create time, replace
/// rather than truncate, fail-closed Windows ACL). Its caller is the audit-log
/// CSV export. It used to be the vault backup's writer too, which is why the
/// helper matters: `fs::write` left files at `0666 & ~umask` (0644 on a normal
/// desktop, group-WRITABLE under umask 002). The backup no longer comes
/// through here at all - `vault_backup_export_to_file` writes it from Rust, so
/// the sealed document never crosses IPC.
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
                // The UI copies this as the authorized_keys line (A7-45).
                "public_key": keys::sanitize_public_line(&k.public_key),
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
                // The detail pane's authorized_keys line (A7-45).
                "public_key": keys::sanitize_public_line(&key.public_key),
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

/// [`unseal_key_data`] for callers that hold an `AppHandle` (the terminal's
/// connect path); the handle is not needed.
fn load_private_key_data(
    _app: &AppHandle,
    key: &KeyRecord,
    vault_pw: &str,
) -> Result<keys::PrivateKeyData, String> {
    unseal_key_data(key, vault_pw)
}

/// Reconstruct a `PrivateKeyData` for a stored key, decrypting the private
/// half with the (already-verified) vault password.
fn unseal_key_data(key: &KeyRecord, vault_pw: &str) -> Result<keys::PrivateKeyData, String> {
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

/// Serialises "is this key name free?" with the write that takes it, so two
/// commands racing each other - a double-clicked Create runs twice off the
/// main thread now - cannot both pass the check (A2-46 / A5-25).
static KEY_NAME_WRITES: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Refuse a key name another key already has, compared without regard to
/// case. Existing duplicates in older vaults stay as they are; only a new
/// create, import or rename is refused.
fn ensure_key_name_free(db: &db::Database, name: &str, except_id: Option<&str>) -> CmdResult<()> {
    match db
        .key_name_in_use(name, except_id)
        .map_err(|e| e.to_string())?
    {
        Some(existing) => Err(CmdError(format!(
            "A key named \"{existing}\" already exists. Choose a different name."
        ))),
        None => Ok(()),
    }
}

/// Run `write` - the insert or rename that takes `name` - only if no other
/// key has that name, with the check and the write together under
/// [`KEY_NAME_WRITES`]. The one place create, import and rename go through.
fn write_with_free_key_name<T>(
    db: &db::Database,
    name: &str,
    except_id: Option<&str>,
    write: impl FnOnce() -> anyhow::Result<T>,
) -> CmdResult<T> {
    let _names = KEY_NAME_WRITES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_key_name_free(db, name, except_id)?;
    write().map_err(|e| CmdError(e.to_string()))
}

#[tauri::command]
pub fn key_import(
    app: AppHandle,
    pem: String,
    name: Option<String>,
    comment: Option<String>,
    passphrase: Option<String>,
) -> CmdResult<serde_json::Value> {
    key_import_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        app.state::<VaultRotationLock>().inner(),
        &pem,
        name,
        comment,
        passphrase.as_deref(),
    )
}

/// [`key_import`] without the `AppHandle`. Reads only OpenSSH private keys
/// and PuTTY .ppk files (ruling R9); anything else is refused with a message
/// that names what it is and how to convert it.
fn key_import_in(
    db: &db::Database,
    store: &VaultPasswordStore,
    rotation: &VaultRotationLock,
    pem: &str,
    name: Option<String>,
    comment: Option<String>,
    passphrase: Option<&str>,
) -> CmdResult<serde_json::Value> {
    // Seals with the master password: not while it is being changed (C1).
    let _rotation = rotation.try_shared()?;
    let pw = store.get().unwrap_or_default();
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let pem = pem.trim();

    let mut key_data = if pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        keys::import_openssh_private(pem, passphrase).map_err(|e| e.to_string())?
    } else if crate::crypto::putty::looks_like_ppk(pem) {
        crate::crypto::putty::import_ppk(pem, passphrase).map_err(|e| e.to_string())?
    } else {
        return Err(keys::unsupported_import_message(pem).into());
    };

    if let Some(c) = comment {
        // Cleaned like a comment read from the file (A7-45).
        key_data.comment = keys::sanitize_key_comment(&c);
    }

    let public_openssh =
        keys::export_public_key(&key_data, KeyFormat::OpenSsh).map_err(|e| e.to_string())?;
    let fingerprint = keys::compute_fingerprint_sha256(&key_data.public_key);
    let fingerprint_md5 = keys::compute_fingerprint_md5(&key_data.public_key);

    // Dedupe by fingerprint so the same key can't be imported twice.
    let existing = db.list_keys().map_err(|e| e.to_string())?;
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
    // Checked before the (slow) seal for a quick answer, and again under the
    // lock right before the insert.
    ensure_key_name_free(db, &name_str, None)?;
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

    write_with_free_key_name(db, &key_record.name, None, || db.insert_key(&key_record))?;
    db.add_audit("keys.imported", Some(&key_record.id), &key_record.name)?;

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
        // Re-checked (A7-45): a line stored before import-time comment
        // cleaning could carry a second, injected key line.
        "public" | "authorized_keys" => keys::sanitize_public_line(&key.public_key),
        "public-pem" => {
            let key_data = unseal_key_data(&key, &pw)?;
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

/// The passphrase a private-key export uses, after the format rules: only
/// the private formats come through here, and "pkcs8-encrypted" - the format
/// whose whole point is the passphrase - refuses to run without one (A2-03 /
/// A7-05 / A5-38). It used to fall back to a PLAINTEXT `BEGIN PRIVATE KEY`
/// file and report "Exported pkcs8-encrypted". The other formats encrypt
/// only when a passphrase is given. Checked before the save dialog opens.
fn private_export_passphrase<'a>(
    format: &str,
    passphrase: Option<&'a str>,
) -> CmdResult<Option<&'a str>> {
    match format {
        "openssh-private" | "ppk" | "pkcs8" | "pkcs8-encrypted" => {}
        other => {
            return Err(CmdError(format!(
                "Format \"{other}\" is public material; use the regular export path."
            )))
        }
    }
    let pass = passphrase.filter(|p| !p.is_empty());
    if format == "pkcs8-encrypted" && pass.is_none() {
        return Err("A passphrase is required for an encrypted PKCS#8 export.".into());
    }
    Ok(pass)
}

/// Export a PRIVATE key straight to a user-chosen file. The PEM text is
/// serialized in the backend and written to the path the user picks in the
/// native save dialog - the key material never crosses the IPC boundary into
/// the renderer. The file is owner-only from the first byte: 0600 on Unix; on
/// Windows it is restricted to the current user while still empty, and the
/// export fails - leaving no file - if that is impossible (a volume that
/// cannot store ACLs, say), as for every secret file SSHSpan writes.
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
    if !app.state::<VaultPasswordStore>().is_set() {
        return Err("Vault is locked.".into());
    }
    // Format and passphrase first: an encrypted PKCS#8 export without a
    // passphrase is refused before anything is decrypted or a dialog opens.
    let pass = private_export_passphrase(&format, passphrase.as_deref())?;
    // Capture the generation before the (decrypt → dialog → write) sequence:
    // the save dialog blocks on user input for an unbounded time, during
    // which the vault could be locked. Re-checked before the write below.
    let generation = capture_vault_generation(&app)?;

    let (key, data) = {
        // Read access to the rotation lock while the key is unsealed, so a
        // master-password change in progress gives the "being re-encrypted"
        // answer rather than a failed decryption. Released before the
        // dialog: the user may sit in it for any length of time.
        let _rotation = rotation_shared(&app)?;
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

        let key_data = unseal_key_data(&key, &pw)?;
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
        (key, data)
    };

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
    key_delete_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        &id,
    )
}

/// [`key_delete`] without the `AppHandle`, so its lock gate is testable.
fn key_delete_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    id: &str,
) -> CmdResult<serde_json::Value> {
    require_unlocked(vault)?;
    db.delete_key(id).map_err(|e| e.to_string())?;
    db.add_audit("keys.deleted", Some(id), "")?;
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
    key_rename_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        app.state::<VaultRotationLock>().inner(),
        &id,
        &name,
    )
}

/// [`key_rename`] without the `AppHandle`, so its gates are testable.
fn key_rename_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    rotation: &VaultRotationLock,
    id: &str,
    name: &str,
) -> CmdResult<serde_json::Value> {
    require_unlocked(vault)?;
    // A vault write like the others: not while a master-password change
    // runs (C1). The rename itself touches only the name (`rename_key`), so
    // it can no longer write back a stale row - a deployment recorded by a
    // deploy running off the main thread used to be erased that way.
    let _rotation = rotation.try_shared()?;
    let name = name.trim().to_string();
    crate::crypto::keys::validate_key_name(&name).map_err(CmdError)?;

    let key = db
        .get_key(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Key not found.".to_string())?;

    if key.name == name {
        return Ok(serde_json::json!({ "ok": true, "name": name }));
    }
    // Another key's name, in any case, is refused (A2-46 / A5-25); a change
    // of case to the key's own name is not a clash.
    write_with_free_key_name(db, &name, Some(id), || db.rename_key(id, &name))?;
    db.add_audit("keys.renamed", Some(id), &format!("{} -> {name}", key.name))?;
    Ok(serde_json::json!({ "ok": true, "name": name }))
}

/// Write an audit row for something that already happened. A failure cannot
/// undo the action, so it does not fail the command - but it is logged, not
/// dropped without a trace.
fn audit_or_warn(db: &db::Database, action: &str, key_id: Option<&str>, details: &str) {
    if let Err(e) = db.add_audit(action, key_id, details) {
        log::warn!("[sshspan-keys] could not write the audit row {action}: {e}");
    }
}

/// The keys of a deploy request, each once, in request order. An empty
/// request is fine for the preview (nothing to show) and refused by the deploy.
fn load_deploy_records(db: &db::Database, ids: &[String]) -> CmdResult<Vec<KeyRecord>> {
    let mut seen = std::collections::HashSet::new();
    ids.iter()
        .filter(|id| seen.insert(id.as_str()))
        .map(|id| {
            db.get_key(id)
                .map_err(|e| CmdError(e.to_string()))?
                .ok_or_else(|| CmdError(format!("Key not found: {id}")))
        })
        .collect()
}

/// [`SshService::plan_deploy`] for vault keys: their recorded deployments
/// are what a file must not collide with.
fn plan_key_deploy(
    db: &db::Database,
    target: &DeployTarget,
    records: &[KeyRecord],
    fields: &DeployHostFields,
) -> CmdResult<DeployPlan> {
    let keys: Vec<DeployKey> = records
        .iter()
        .map(|k| DeployKey {
            id: k.id.clone(),
            name: k.name.clone(),
            deploy_path: k.deploy_path.clone(),
        })
        .collect();
    let recorded: Vec<RecordedDeployment> = db
        .list_key_deployments()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(id, name, path)| RecordedDeployment { id, name, path })
        .collect();
    SshService::plan_deploy(target, &keys, &recorded, fields).map_err(|e| CmdError(e.to_string()))
}

/// What a deploy would write, without writing it (ruling R3): per key the
/// alias, the files and whether it will be refused, and `configText` -
/// exactly the stanza text the deploy writes into the managed config, by the
/// same code. The deploy sheet shows this instead of building its own guess
/// (A2-05 / A7-04 / A8-01 / A5-04). Nothing is decrypted.
#[tauri::command]
pub fn key_deploy_preview(
    app: AppHandle,
    ids: Vec<String>,
    host_alias: Option<String>,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    strict_host_key: Option<bool>,
) -> CmdResult<serde_json::Value> {
    let fields = DeployHostFields::parse(host_alias, hostname, user, port, strict_host_key)
        .map_err(CmdError)?;
    let target = DeployTarget::user_default().map_err(|e| CmdError(e.to_string()))?;
    key_deploy_preview_in(&app.state::<AppState>().db, &target, &ids, &fields)
}

/// [`key_deploy_preview`] without the `AppHandle`.
fn key_deploy_preview_in(
    db: &db::Database,
    target: &DeployTarget,
    ids: &[String],
    fields: &DeployHostFields,
) -> CmdResult<serde_json::Value> {
    let records = load_deploy_records(db, ids)?;
    let plan = plan_key_deploy(db, target, &records, fields)?;
    Ok(serde_json::json!({
        "configPath": target.config_path.display().to_string(),
        "sshDir": target.ssh_dir.display().to_string(),
        "includeLine": plan.include_line(),
        "keys": plan.keys,
        "configText": plan.config_text(),
    }))
}

/// Deploy keys: each private key to `~/.ssh/sshspan_<name>` (owner-only),
/// its `.pub` beside it, and a Host stanza into SSHSpan's managed config
/// carrying the HostName / User / Port / alias the sheet collected (R3) -
/// exactly what [`key_deploy_preview`] showed. A key whose file belongs to
/// another key, or is a file SSHSpan did not write for it, is refused rather
/// than overwritten; the others still deploy. Returns `{ok, keys: [{id, name,
/// alias, file, pubFile}], errors: [{id, name, error}], warnings, configPath,
/// includeLine}`; when no key could be deployed it fails with the reasons.
///
/// Async on purpose (A7-13): every key is unsealed (Argon2id) and possibly
/// re-encrypted, which froze the window as a synchronous command. The work
/// runs on a blocking worker under the [`VaultRotationLock`], and a vault lock
/// meanwhile stops it before the next key is decrypted.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn key_deploy(
    app: AppHandle,
    ids: Vec<String>,
    passphrase: Option<String>,
    strict_host_key: Option<bool>,
    host_alias: Option<String>,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
) -> CmdResult<serde_json::Value> {
    let passphrase = passphrase.map(zeroize::Zeroizing::new);
    let fields = DeployHostFields::parse(host_alias, hostname, user, port, strict_host_key)
        .map_err(CmdError)?;
    let target = DeployTarget::user_default().map_err(|e| CmdError(e.to_string()))?;
    let generation = app.state::<VaultGeneration>().current();
    let worker = app.clone();
    run_blocking(move || {
        key_deploy_in(
            &worker.state::<AppState>().db,
            worker.state::<VaultPasswordStore>().inner(),
            worker.state::<VaultRotationLock>().inner(),
            &target,
            &ids,
            passphrase.as_deref().map(String::as_str),
            &fields,
            &|| require_generation_current(&worker, generation),
        )
    })
    .await
}

/// [`key_deploy`] on its blocking worker, without the `AppHandle`.
/// `still_current` is the vault-generation check, run before each key is
/// decrypted.
#[allow(clippy::too_many_arguments)]
fn key_deploy_in(
    db: &db::Database,
    store: &VaultPasswordStore,
    rotation: &VaultRotationLock,
    target: &DeployTarget,
    ids: &[String],
    passphrase: Option<&str>,
    fields: &DeployHostFields,
    still_current: &dyn Fn() -> CmdResult<()>,
) -> CmdResult<serde_json::Value> {
    // Unseals with the master password and records the deployment: taken
    // before the first read, not while a master-password change runs (C1).
    let _rotation = rotation.try_shared()?;
    let pw = store.get().unwrap_or_default();
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let records = load_deploy_records(db, ids)?;
    if records.is_empty() {
        return Err("Select at least one key to deploy.".into());
    }
    let plan = plan_key_deploy(db, target, &records, fields)?;
    let by_id: std::collections::HashMap<&str, &KeyRecord> =
        records.iter().map(|k| (k.id.as_str(), k)).collect();
    let passphrase = passphrase.filter(|p| !p.is_empty());

    let mut outcome = SshService::apply_deploy(&plan, |planned| {
        still_current().map_err(|e| e.0)?;
        let key = by_id[planned.id.as_str()];
        let data = unseal_key_data(key, &pw)?;
        let private_key = zeroize::Zeroizing::new(
            keys::export_private_key(&data, KeyFormat::OpenSsh, passphrase)
                .map_err(|e| e.to_string())?,
        );
        let public_key =
            keys::export_public_key(&data, KeyFormat::OpenSsh).map_err(|e| e.to_string())?;
        Ok(DeployFiles {
            private_key,
            public_key,
        })
    });

    for deployed in &outcome.deployed {
        if let Err(e) = db.set_key_deployment(&deployed.id, Some(&deployed.file)) {
            outcome.warnings.push(format!(
                "{} was written, but the vault could not record the deployment: {e}",
                deployed.file
            ));
        }
    }
    if !outcome.deployed.is_empty() {
        let files: Vec<&str> = outcome.deployed.iter().map(|d| d.file.as_str()).collect();
        audit_or_warn(
            db,
            "keys.deployed",
            None,
            &format!("{} key(s): {}", files.len(), files.join(", ")),
        );
    }
    if !outcome.errors.is_empty() {
        let names: Vec<&str> = outcome.errors.iter().map(|e| e.name.as_str()).collect();
        audit_or_warn(
            db,
            "keys.deploy_failed",
            None,
            &format!("{} key(s) not deployed: {}", names.len(), names.join(", ")),
        );
    }
    if outcome.deployed.is_empty() {
        let reasons: Vec<&str> = outcome.errors.iter().map(|e| e.error.as_str()).collect();
        return Err(CmdError(reasons.join("\n")));
    }
    Ok(serde_json::json!({
        "ok": true,
        "keys": outcome.deployed,
        "errors": outcome.errors,
        "warnings": outcome.warnings,
        "configPath": target.config_path.display().to_string(),
        "includeLine": plan.include_line(),
    }))
}

/// Undo a deployment (A7-22 / A8-16): delete the key's deployed private key
/// and `.pub` and the managed-config stanza that points at them, and clear
/// the record. Returns `{ok, removed: [paths], removedHosts: [aliases],
/// warnings: [...]}`. If the private key file cannot be deleted it fails and
/// the key stays marked as deployed - this used to drop every file error
/// (`let _ = fs::remove_file`) and clear the record anyway, with the secret
/// still on disk, and it never touched the stanza.
#[tauri::command]
pub fn key_remove_deployed(app: AppHandle, id: String) -> CmdResult<serde_json::Value> {
    let target = DeployTarget::user_default().map_err(|e| CmdError(e.to_string()))?;
    key_remove_deployed_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        app.state::<VaultRotationLock>().inner(),
        &target,
        &id,
    )
}

/// [`key_remove_deployed`] without the `AppHandle`.
fn key_remove_deployed_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    rotation: &VaultRotationLock,
    target: &DeployTarget,
    id: &str,
) -> CmdResult<serde_json::Value> {
    // Deleting local files is a privileged side effect; refuse while locked.
    require_unlocked(vault)?;
    // Rewrites the key's deployment columns: taken before the first read,
    // not while a master-password change runs (C1).
    let _rotation = rotation.try_shared()?;
    let key = db
        .get_key(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Key not found.".to_string())?;

    let mut removed = crate::ssh::RemovedDeployment::default();
    let mut undeployed_files = false;
    if let Some(deploy_path) = key.deploy_path.as_deref() {
        // Only a file a deploy writes - `sshspan_*` directly in the managed
        // SSH directory - is ever deleted. The stored path is normally the
        // deploy's own, but a pre-F9 backup restore or a tampered database
        // could point it anywhere, the user's own keys in ~/.ssh included.
        if SshService::is_managed_deploy_path(target, deploy_path) {
            removed = match SshService::remove_key(target, deploy_path) {
                Ok(done) => done,
                Err(e) => {
                    audit_or_warn(db, "keys.undeploy_failed", Some(id), &e);
                    return Err(CmdError(e));
                }
            };
            undeployed_files = true;
        } else {
            log::warn!(
                "[sshspan-keys] key_remove_deployed: refusing to delete {deploy_path} (not a file SSHSpan deploys); clearing the deployment record only"
            );
            audit_or_warn(
                db,
                "keys.undeploy_refused",
                Some(id),
                "stored deploy_path is not an SSHSpan deploy file; record cleared, file untouched",
            );
            removed.warnings.push(format!(
                "{deploy_path} was not deleted: it is not a file SSHSpan deploys into {}. The deployment record was cleared.",
                target.ssh_dir.display()
            ));
        }
    }
    // A key that was never deployed is left as it is: no write, no audit row.
    if key.deployed || key.deploy_path.is_some() {
        db.set_key_deployment(id, None).map_err(|e| e.to_string())?;
    }
    if undeployed_files {
        audit_or_warn(
            db,
            "keys.undeployed",
            Some(id),
            &format!(
                "removed [{}]; Host [{}]",
                removed.removed.join(", "),
                removed.removed_hosts.join(", ")
            ),
        );
    }
    Ok(serde_json::json!({
        "ok": true,
        "removed": removed.removed,
        "removedHosts": removed.removed_hosts,
        "warnings": removed.warnings,
    }))
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
    category_create_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        name,
        parent_id,
        color,
        scope,
    )
}

/// [`category_create`] without the `AppHandle`, so its lock gate is testable.
fn category_create_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    name: String,
    parent_id: Option<String>,
    color: Option<String>,
    scope: Option<String>,
) -> CmdResult<db::Category> {
    require_unlocked(vault)?;
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
    category_rename_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        &id,
        name,
    )
}

/// [`category_rename`] without the `AppHandle`, so its lock gate is testable.
fn category_rename_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    id: &str,
    name: String,
) -> CmdResult<serde_json::Value> {
    require_unlocked(vault)?;
    let mut c = db
        .get_category(id)
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
    category_reparent_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        id,
        new_parent_id,
        sort_index,
    )
}

/// [`category_reparent`] without the `AppHandle`, so its lock gate is
/// testable.
fn category_reparent_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    id: String,
    new_parent_id: Option<String>,
    sort_index: Option<i64>,
) -> CmdResult<serde_json::Value> {
    require_unlocked(vault)?;
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
    category_delete_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        &id,
    )
}

/// [`category_delete`] without the `AppHandle`, so its lock gate is testable.
fn category_delete_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    id: &str,
) -> CmdResult<serde_json::Value> {
    require_unlocked(vault)?;
    let reassigned = db.delete_category(id).map_err(|e| e.to_string())?;
    db.add_audit("category.deleted", None, id)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true, "reassigned": reassigned }))
}

#[tauri::command]
pub fn key_set_categories(
    app: AppHandle,
    key_id: String,
    category_ids: Vec<String>,
) -> CmdResult<serde_json::Value> {
    key_set_categories_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        &key_id,
        &category_ids,
    )
}

/// [`key_set_categories`] without the `AppHandle`, so its lock gate is
/// testable.
fn key_set_categories_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    key_id: &str,
    category_ids: &[String],
) -> CmdResult<serde_json::Value> {
    require_unlocked(vault)?;
    // Validate every category exists and belongs to the key scope.
    let known: std::collections::HashSet<String> = db
        .list_categories()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|c| c.scope == "key")
        .map(|c| c.id)
        .collect();
    for cid in category_ids {
        if !known.contains(cid) {
            return Err(format!("Unknown category: {cid}").into());
        }
    }
    db.set_key_categories(key_id, category_ids)
        .map_err(|e| e.to_string())?;
    db.add_audit(
        "key.categories_set",
        Some(key_id),
        &category_ids.len().to_string(),
    )
    .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "ok": true }))
}

/// A New Key request, checked before any generation starts.
struct NewKey {
    key_type: KeyType,
    /// RSA only: 2048..=8192 ([`keys::rsa_key_bits`]); `None` otherwise.
    bits: Option<u32>,
    name: String,
    comment: String,
    category_ids: Vec<String>,
}

impl NewKey {
    fn parse(
        key_type: &str,
        bits: Option<u32>,
        name: Option<String>,
        comment: Option<String>,
        category_ids: Option<Vec<String>>,
    ) -> CmdResult<Self> {
        let kt = KeyType::from_db_tag(key_type).map_err(|e| e.to_string())?;
        // The dialog sends its RSA size whatever the type; only RSA uses it.
        let bits = match kt {
            KeyType::Rsa => Some(keys::rsa_key_bits(bits).map_err(|e| e.to_string())?),
            _ => None,
        };
        let name =
            name.unwrap_or_else(|| format!("{}-{}", key_type, &Uuid::new_v4().to_string()[..8]));
        // Names become Host aliases in ~/.ssh/config - reject anything that
        // could break out of a single Host token before it reaches the vault.
        keys::validate_key_name(&name)?;
        Ok(Self {
            key_type: kt,
            bits,
            name,
            comment: comment.unwrap_or_default(),
            category_ids: category_ids.unwrap_or_default(),
        })
    }
}

/// Generate a key and store it in the vault with its categories.
///
/// Async on purpose (A7-12): RSA generation takes seconds (4096 bits) to
/// minutes (8192) in pure Rust, and as a synchronous command it ran on the
/// main thread - the window froze ("Not Responding") until it finished. The
/// generation and the Argon2id seal now run on a blocking worker.
#[tauri::command]
pub async fn key_create_with_categories(
    app: AppHandle,
    key_type: String,
    bits: Option<u32>,
    name: Option<String>,
    comment: Option<String>,
    category_ids: Option<Vec<String>>,
) -> CmdResult<serde_json::Value> {
    // Cheap refusals first, before a long prime search.
    if !app.state::<VaultPasswordStore>().is_set() {
        return Err("Vault is locked.".into());
    }
    let request = NewKey::parse(&key_type, bits, name, comment, category_ids)?;
    let worker = app.clone();
    run_blocking(move || {
        create_key_in(
            &worker.state::<AppState>().db,
            worker.state::<VaultPasswordStore>().inner(),
            worker.state::<VaultRotationLock>().inner(),
            request,
        )
    })
    .await
}

/// [`key_create_with_categories`] on its blocking worker, without the
/// `AppHandle`. The key is generated BEFORE the [`VaultRotationLock`] read
/// access is taken - the generation reads nothing from the vault, and a
/// password change should not wait out a prime search - and the seal and the
/// insert happen under it.
fn create_key_in(
    db: &db::Database,
    store: &VaultPasswordStore,
    rotation: &VaultRotationLock,
    request: NewKey,
) -> CmdResult<serde_json::Value> {
    let valid_ids: std::collections::HashSet<String> = db
        .list_categories()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|c| c.scope == "key")
        .map(|c| c.id)
        .collect();
    if request
        .category_ids
        .iter()
        .any(|id| !valid_ids.contains(id))
    {
        return Err("Keys can only use key categories.".into());
    }
    ensure_key_name_free(db, &request.name, None)?;

    let key_data = keys::generate_key_pair(request.key_type, request.bits, request.comment)
        .map_err(|e| e.to_string())?;

    // Seals with the master password: not while it is being changed (C1).
    let _rotation = rotation.try_shared()?;
    let pw = store.get().unwrap_or_default();
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let public_openssh =
        keys::export_public_key(&key_data, KeyFormat::OpenSsh).map_err(|e| e.to_string())?;
    let fingerprint = keys::compute_fingerprint_sha256(&key_data.public_key);
    let sealed_private =
        crate::crypto::vault::seal(&pw, &key_data.private_key).map_err(|e| e.to_string())?;
    let key_record = KeyRecord {
        id: Uuid::new_v4().to_string(),
        name: request.name.clone(),
        key_type: request.key_type.db_tag().to_string(),
        public_key: public_openssh,
        private_key_encrypted: sealed_private,
        fingerprint_sha256: fingerprint.clone(),
        fingerprint_md5: keys::compute_fingerprint_md5(&key_data.public_key),
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

    write_with_free_key_name(db, &key_record.name, None, || {
        db.insert_key_with_categories(&key_record, &request.category_ids)
    })?;
    db.add_audit("keys.created", Some(&key_record.id), &key_record.name)?;
    Ok(serde_json::json!({ "ok": true, "id": key_record.id, "fingerprint": fingerprint }))
}

// ═════════════════════════════════════════════════════════════════════════════
//  SSH CONFIG commands
// ═════════════════════════════════════════════════════════════════════════════

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

/// Hosts for the server dialog's "Config" import (R4). `source`:
/// - `"user"` (the default): the user's own `~/.ssh/config`, read-only -
///   `Include` followed one level, `Match` blocks and wildcard or negated
///   `Host` patterns skipped (see `config::read_user_ssh_config`);
/// - `"managed"`: the file SSHSpan's deploy writes (the old behaviour).
///
/// Returns `{hosts, path}` - the file that was read; a missing file is an
/// empty list. Refused while the vault is locked: the user's config is an
/// inventory of hosts, accounts and key paths. The files are read on the
/// blocking pool, never on the main thread.
#[tauri::command]
pub async fn ssh_config_list_hosts(
    app: AppHandle,
    source: Option<String>,
) -> CmdResult<serde_json::Value> {
    let user = crate::config::user_ssh_config_path().map_err(|e| e.to_string())?;
    let managed = crate::config::ssh_config_path().map_err(|e| e.to_string())?;
    run_blocking(move || {
        ssh_config_hosts_in(
            &app.state::<VaultPasswordStore>(),
            source.as_deref(),
            &user,
            &managed,
        )
    })
    .await
}

/// [`ssh_config_list_hosts`] with the two candidate files given.
fn ssh_config_hosts_in(
    vault: &VaultPasswordStore,
    source: Option<&str>,
    user: &std::path::Path,
    managed: &std::path::Path,
) -> CmdResult<serde_json::Value> {
    require_unlocked(vault)?;
    let unreadable = |path: &std::path::Path, e: anyhow::Error| {
        CmdError(format!("Could not read {}: {e}", path.display()))
    };
    let (hosts, path) = match source.unwrap_or("user") {
        "user" => (
            crate::config::read_user_ssh_config(user).map_err(|e| unreadable(user, e))?,
            user,
        ),
        "managed" => (
            SshConfigService::at(managed.to_path_buf())
                .read()
                .map_err(|e| unreadable(managed, e))?
                .hosts,
            managed,
        ),
        other => {
            return Err(CmdError(format!(
                "Unknown ssh config source {other:?} - expected \"user\" or \"managed\"."
            )))
        }
    };
    Ok(serde_json::json!({ "hosts": hosts, "path": path.display().to_string() }))
}

#[cfg(test)]
mod ssh_config_list_hosts_tests {
    use super::*;

    struct Dir(std::path::PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> (Dir, std::path::PathBuf, std::path::PathBuf) {
        let dir =
            Dir(std::env::temp_dir().join(format!("sshspan-ru4-list-hosts-{}", Uuid::new_v4())));
        std::fs::create_dir_all(&dir.0).unwrap();
        let user = dir.0.join("user-config");
        let managed = dir.0.join("managed-config");
        std::fs::write(
            &user,
            "Host personal\n  HostName personal.example\n  User me\nHost *\n  Port 2222\n",
        )
        .unwrap();
        std::fs::write(
            &managed,
            "Host sshspan-deployed\n  IdentityFile /fixture/sshspan_key\n",
        )
        .unwrap();
        (dir, user, managed)
    }

    fn unlocked() -> VaultPasswordStore {
        let vault = VaultPasswordStore::new();
        vault.set("fixture-master".into());
        vault
    }

    #[test]
    fn ru4_default_source_is_the_users_own_config() {
        let (_dir, user, managed) = fixture();
        for source in [None, Some("user")] {
            let out = ssh_config_hosts_in(&unlocked(), source, &user, &managed).unwrap();
            assert_eq!(out["path"], user.display().to_string());
            assert_eq!(out["hosts"].as_array().unwrap().len(), 1, "{out}");
            assert_eq!(out["hosts"][0]["host"], "personal");
            assert_eq!(out["hosts"][0]["hostname"], "personal.example");
            assert_eq!(out["hosts"][0]["user"], "me");
            assert_eq!(out["hosts"][0]["port"], 2222);
        }
    }

    #[test]
    fn ru4_managed_source_keeps_todays_behaviour() {
        let (_dir, user, managed) = fixture();
        let out = ssh_config_hosts_in(&unlocked(), Some("managed"), &user, &managed).unwrap();
        assert_eq!(out["path"], managed.display().to_string());
        assert_eq!(out["hosts"][0]["host"], "sshspan-deployed");
        assert_eq!(out["hosts"][0]["identity_file"], "/fixture/sshspan_key");
    }

    #[test]
    fn ru4_missing_file_is_empty_and_bad_requests_are_refused() {
        let (dir, user, managed) = fixture();
        let missing = dir.0.join("absent");
        let out = ssh_config_hosts_in(&unlocked(), None, &missing, &managed).unwrap();
        assert_eq!(out["hosts"], serde_json::json!([]));
        assert_eq!(out["path"], missing.display().to_string());
        let err =
            ssh_config_hosts_in(&unlocked(), Some("../etc/passwd"), &user, &managed).unwrap_err();
        assert!(err.0.contains("Unknown ssh config source"), "{}", err.0);
        let locked = VaultPasswordStore::new();
        assert_eq!(
            ssh_config_hosts_in(&locked, None, &user, &managed)
                .unwrap_err()
                .0,
            "Vault is locked."
        );
    }
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
    // Seals the Bitwarden password with the master password: not while that
    // is being changed (C1).
    let _rotation = rotation_shared(&app)?;
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
    // Held for the whole run (C1): the sync seals pulled keys and server
    // passwords with the master password it reads below, between network
    // round trips, and rewrites whole key/server rows - a master-password
    // change must neither start in the middle nor be running when it starts.
    let _rotation = rotation_shared(&app)?;
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
    audit_clear_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
    )
}

/// [`audit_clear`] without the `AppHandle`, so its lock gate is testable.
fn audit_clear_in(db: &db::Database, vault: &VaultPasswordStore) -> CmdResult<serde_json::Value> {
    require_unlocked(vault)?;
    let removed = db.clear_audit().map_err(|e| e.to_string())?;
    let _ = db.add_audit(
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

/// Settings that weaken the vault's protection when changed, so they cannot
/// be changed while it is locked (A6-08): a script in a locked window could
/// otherwise switch the idle lock off (`autoLockMinutes` = 0 disables both the
/// renderer timer and the backend watchdog), drop the delete and multi-line
/// paste confirmations, or the update check. Display, terminal and
/// file-browser preferences stay writable on a locked vault.
const SECURITY_SETTINGS: &[&str] = &[
    "autoLockMinutes",
    "confirmDelete",
    "autoUpdateCheck",
    "confirmMultiLinePaste",
];

/// `sftp::queue::parallel_limit`'s fallback when `sftpParallel` is not stored.
const SFTP_PARALLEL_DEFAULT: u64 = 4;

/// Largest `sftpMaxBps` the Settings row can produce: 1,000,000 MB/s.
const SFTP_MAX_BPS_LIMIT: u64 = 1_000_000 * 1_048_576;

/// Longest value accepted for a `sftpLocalDir:<id>` directory.
const MAX_LOCAL_DIR_SETTING_BYTES: usize = 32 * 1024;

/// The values `settings_set` accepts for one key.
enum SettingDomain {
    /// Digits only (no sign, no spaces), inside `min..=max`.
    Whole { min: u64, max: u64 },
    /// Exactly one of these strings.
    OneOf(&'static [&'static str]),
    /// A local directory: non-empty, no NUL, bounded length.
    LocalDir,
}

/// Each key's domain, taken from what the renderer writes for it - so nothing
/// the UI sends is refused. The booleans are not uniform: some rows write
/// "true"/"false", others "1"/"0", and their readers compare against exactly
/// that spelling, so each key accepts only its own.
fn setting_domain(key: &str) -> Option<SettingDomain> {
    use SettingDomain::{LocalDir, OneOf, Whole};
    const TRUE_FALSE: &[&str] = &["true", "false"];
    const ONE_ZERO: &[&str] = &["1", "0"];
    Some(match key {
        "autoLockMinutes" => Whole {
            min: 0,
            max: AUTO_LOCK_MAX_MINUTES,
        },
        "uiScale" => Whole { min: 75, max: 200 },
        "sftpParallel" => Whole { min: 1, max: 4 },
        "terminalScrollback" => Whole {
            min: 1000,
            max: 50_000,
        },
        "sftpMaxBps" => Whole {
            min: 0,
            max: SFTP_MAX_BPS_LIMIT,
        },
        "confirmDelete" | "autoUpdateCheck" | "sftpVerifyTransfers" => OneOf(TRUE_FALSE),
        "confirmMultiLinePaste"
        | "sftpShowHidden"
        | "sftpShowOwnerCols"
        | "sftpPreserveTs"
        | "sftpDualPane" => OneOf(ONE_ZERO),
        "sftpConflictUpload" | "sftpConflictDownload" => {
            OneOf(&["ask", "overwrite", "skip", "rename", "resume"])
        }
        "sftpResumeDefault" => OneOf(&["ask", "overwrite", "resume"]),
        // "" is how the comparison toggle stores "off".
        "sftpCmpMode" => OneOf(&["", "size", "mtime"]),
        "terminalBell" => OneOf(&["visual", "sound", "silent"]),
        "terminalBackspace" => OneOf(&["default", "backspace"]),
        "terminalHomeEnd" => OneOf(&["default", "rxvt"]),
        "terminalAppCursorKeys" | "terminalAppKeypad" => OneOf(&["default", "disabled"]),
        k if k.starts_with(SFTP_LOCAL_DIR_PREFIX) => LocalDir,
        _ => return None,
    })
}

/// Check a value against its key's domain (A2-14 / A5-32). `settings_set` used
/// to check only the key, so `-5`, `""` or `1.5` for the auto-lock were stored
/// with a success toast. Reads are unaffected: a value an older build stored is
/// still returned as it is, and each reader keeps its own fallback.
fn validate_setting_value(key: &str, value: &str) -> CmdResult<()> {
    let valid = match setting_domain(key) {
        Some(SettingDomain::Whole { min, max }) => {
            !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_digit())
                && value.parse::<u64>().is_ok_and(|n| (min..=max).contains(&n))
        }
        Some(SettingDomain::OneOf(allowed)) => allowed.contains(&value),
        Some(SettingDomain::LocalDir) => {
            !value.is_empty() && value.len() <= MAX_LOCAL_DIR_SETTING_BYTES && !value.contains('\0')
        }
        None => false,
    };
    if valid {
        return Ok(());
    }
    let expected = match setting_domain(key) {
        Some(SettingDomain::Whole { min, max }) => {
            format!("a whole number from {min} to {max}")
        }
        Some(SettingDomain::OneOf(allowed)) => {
            let shown: Vec<String> = allowed.iter().map(|a| format!("\"{a}\"")).collect();
            format!("one of {}", shown.join(", "))
        }
        Some(SettingDomain::LocalDir) => "a directory path".to_string(),
        None => "a known setting".to_string(),
    };
    Err(format!("Invalid value for {key}: expected {expected}.").into())
}

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

/// What `settings_get` returns: every stored setting plus the defaults the
/// backend applies when one is not stored - `autoLockMinutes` "15" (the
/// watchdog's default) and `sftpParallel` "4" (the transfer queue's) - so the
/// renderer shows the value in effect instead of guessing (A7-11 / A8-14). On
/// a fresh install the UI used to show 15 minutes and 2 transfers while
/// auto-lock was off and 4 transfers ran.
fn collect_settings(
    db: &crate::db::Database,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let mut settings = collect_stored_settings(db)?;
    settings
        .entry("autoLockMinutes")
        .or_insert_with(|| AUTO_LOCK_DEFAULT_MINUTES.to_string().into());
    settings
        .entry("sftpParallel")
        .or_insert_with(|| SFTP_PARALLEL_DEFAULT.to_string().into());
    Ok(settings)
}

/// Read every persisted setting into one map: the `SETTINGS_KEYS` allowlist
/// plus the `sftpLocalDir:` family (one key per server id, so it cannot live in
/// the fixed list). Shared by `settings_get` and the vault backup so the two
/// can never disagree about what "the settings" are - the backup used to carry
/// a hand-written list of six keys, three of which nothing read, and restore
/// dropped the whole map on the floor. The backup takes only what is stored
/// (no defaults): restoring it must not pin today's defaults over settings
/// the user set on the target machine.
fn collect_stored_settings(
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
/// exactly the decoration this list exists to keep out. Values get the same
/// per-key check `settings_set` applies ([`validate_setting_value`]), and a
/// value that is not a string is dropped too (it was never stored). Returns
/// the number of entries dropped; the restore result reports it as
/// `counts.settingsDropped`.
fn sanitize_backup_settings(settings: &mut serde_json::Map<String, serde_json::Value>) -> usize {
    let before = settings.len();
    settings.retain(|key, value| {
        let known = SETTINGS_KEYS.contains(&key.as_str())
            || (key.starts_with(SFTP_LOCAL_DIR_PREFIX) && key.len() > SFTP_LOCAL_DIR_PREFIX.len());
        known
            && value
                .as_str()
                .is_some_and(|v| validate_setting_value(key, v).is_ok())
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
    settings_set_in(
        &app.state::<AppState>().db,
        &app.state::<VaultPasswordStore>(),
        &key,
        &value,
    )
}

/// [`settings_set`] without the `AppHandle`, so its validation and lock gate
/// are testable.
fn settings_set_in(
    db: &db::Database,
    vault: &VaultPasswordStore,
    key: &str,
    value: &str,
) -> CmdResult<serde_json::Value> {
    if key.starts_with("bwSync.") {
        return Err("Bitwarden sync settings must be changed via the sync settings dialog.".into());
    }
    // Allowlist, not a denylist: `settings_get` only ever reads the keys in
    // SETTINGS_KEYS plus the sftpLocalDir: family, so anything else written
    // here is unreadable clutter at best. Accepting arbitrary keys let a
    // compromised renderer write unbounded rows into the same `config` table
    // that holds the Bitwarden secrets, which is worth refusing outright.
    let known = SETTINGS_KEYS.contains(&key)
        || (key.starts_with(SFTP_LOCAL_DIR_PREFIX) && key.len() > SFTP_LOCAL_DIR_PREFIX.len());
    if !known {
        return Err(format!("Unknown setting: {key}").into());
    }
    if SECURITY_SETTINGS.contains(&key) {
        require_unlocked(vault)?;
    }
    validate_setting_value(key, value)?;
    db.set_config(&format!("setting.{}", key), value)
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

/// Native open dialog that READS the chosen file and returns its text: the
/// key-import path, the one documented case where private-key text enters the
/// webview. Files over 4 MiB are refused before they are read, and the read
/// runs on a blocking worker (A6-04 / A7-48). Callers that only need a path
/// use `system_pick_file_path`.
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
            let source = path_str.clone();
            let content = run_blocking(move || {
                read_picked_text_file(std::path::Path::new(&source), MAX_SELECT_FILE_BYTES)
            })
            .await?;
            Ok(serde_json::json!({
                "canceled": false, "path": path_str,
                "name": std::path::Path::new(&path_str).file_name().and_then(|n| n.to_str()).unwrap_or(""),
                "text": content
            }))
        }
        None => Ok(serde_json::json!({ "canceled": true })),
    }
}

/// Native open dialog that returns only the chosen path - the file is NOT
/// read (A6-04 / A2-19). The server form's ".pem file" browse used
/// `system_select_file`, which read the private key and shipped its plaintext
/// into the webview just to fill in a path. Returns `{canceled: true}` or
/// `{canceled: false, path, name}`.
#[tauri::command]
/// NOTE: async on purpose - a dialog must not block the main thread (see
/// `system_pick_save_path`).
pub async fn system_pick_file_path(
    app: AppHandle,
    title: Option<String>,
) -> CmdResult<serde_json::Value> {
    use tauri_plugin_dialog::DialogExt;
    let picked = app
        .dialog()
        .file()
        .set_title(title.unwrap_or_else(|| "Select file".into()))
        .blocking_pick_file();
    Ok(match picked {
        Some(path) => {
            let path = path.to_string();
            let name = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            serde_json::json!({ "canceled": false, "path": path, "name": name })
        }
        None => serde_json::json!({ "canceled": true }),
    })
}

/// Largest file `system_select_file` hands to the renderer. Its one caller is
/// key import, and a key file is a few KiB.
const MAX_SELECT_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Read a file the user picked in a native dialog as UTF-8 text, refusing it
/// when it is larger than `cap` bytes. The size is checked before anything is
/// read - the old reader pulled in whatever was picked, a multi-GB file
/// included - and the read itself stops at the cap, so a file that grows after
/// the check still cannot get past it.
fn read_picked_text_file(path: &std::path::Path, cap: u64) -> CmdResult<String> {
    use std::io::Read as _;
    let too_large = || {
        CmdError(format!(
            "That file is larger than {} MiB, so it was not loaded.",
            cap / (1024 * 1024)
        ))
    };
    let file = fs::File::open(path)
        .map_err(|e| CmdError(format!("Could not open {}: {e}", path.display())))?;
    if file.metadata().is_ok_and(|m| m.len() > cap) {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CmdError(format!("Could not read {}: {e}", path.display())))?;
    if bytes.len() as u64 > cap {
        return Err(too_large());
    }
    String::from_utf8(bytes)
        .map_err(|_| CmdError("That file is not a text file (it is not valid UTF-8).".into()))
}
