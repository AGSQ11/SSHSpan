//! Database layer using sqlx with SQLite
//! Replaces database.js (sql.js WASM)

use anyhow::Result;
use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};
use std::collections::HashMap;
use std::path::PathBuf;
use tauri::AppHandle;

fn default_category_scope() -> String {
    "key".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub public_key: String,
    pub private_key_encrypted: String,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub comment: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deployed: bool,
    pub deploy_path: Option<String>,
    pub bitwarden_id: Option<String>,
    pub bitwarden_sync: bool,
    #[serde(default)]
    pub bitwarden_revision_ts: Option<i64>,
    #[serde(default)]
    pub bitwarden_updated_at: Option<i64>,
    /// Category IDs this key belongs to (filled by `list_keys_with_categories` / `get_key_with_categories`).
    #[serde(default)]
    pub category_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    /// `key` categories organize SSH keys; `host` categories organize saved servers.
    #[serde(default = "default_category_scope")]
    pub scope: String,
    pub color: Option<String>,
    pub sort_index: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub action: String,
    pub key_id: Option<String>,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRecord {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Reference to a vault key id (never key material). Null when auth uses a
    /// plain .pem file or password / keyboard-interactive.
    pub key_id: Option<String>,
    pub pem_path: Option<String>,
    /// publickey | password | keyboard-interactive
    pub auth_method: String,
    /// AES-GCM blob sealed with the vault password (only when the user opts to store it).
    pub saved_password: Option<String>,
    pub category_id: Option<String>,
    pub color: Option<String>,
    pub last_connected_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Bitwarden two-way sync metadata
    pub bitwarden_id: Option<String>,
    pub bitwarden_revision_ts: Option<String>,
    pub bitwarden_updated_at: Option<String>,
}

/// What a Bitwarden pull writes into an existing key row
/// ([`Database::apply_pulled_key`]).
#[derive(Debug, Clone)]
pub struct KeyPull {
    pub name: String,
    pub key_type: String,
    pub public_key: String,
    /// Sealed with the vault password.
    pub private_key_encrypted: String,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub comment: String,
    /// The remote copy's revision, epoch milliseconds.
    pub bitwarden_revision_ts: Option<i64>,
}

/// What a Bitwarden pull writes into an existing server row
/// ([`Database::apply_pulled_server`]).
#[derive(Debug, Clone)]
pub struct ServerPull {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    pub key_id: Option<String>,
    pub category_id: Option<String>,
    /// Sealed with the vault password, `None` when the item holds none.
    pub saved_password: Option<String>,
    /// The remote copy's `revisionDate`.
    pub bitwarden_revision_ts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHost {
    pub host: String,
    /// SSH wire-format host public key, base64-encoded.
    pub host_key: String,
    pub fingerprint_sha256: String,
    pub first_seen: DateTime<Utc>,
    /// Where this pin came from: "connection" (the user confirmed a live
    /// first-use handshake) or "imported" (planted by a backup restore and
    /// not yet confirmed against a real connection - untrusted until the
    /// user re-confirms the fingerprint on first use).
    #[serde(default = "default_known_host_source")]
    pub source: String,
}

fn default_known_host_source() -> String {
    "connection".to_string()
}

/// One persisted `sftp::queue::TransferJob` row (the `transfer_queue`
/// table). Deliberately decoupled from `sftp::queue`'s `JobKind`/`JobState`/
/// `ResumeMode` enums - this module has no dependency on `sftp`, and the
/// conversion (stable lowercase/camelCase strings both sides already agree
/// on for `emit_queue`'s wire format) lives in `TransferJob::to_row` and
/// `restore_pending` instead. `id` mirrors `TransferJob.id` (a `u64`, cast to
/// `i64` for SQLite's INTEGER PRIMARY KEY - queue ids never get remotely
/// close to overflowing that).
#[derive(Debug, Clone)]
pub struct QueueJobRow {
    pub id: i64,
    pub kind: String,
    pub session_id: String,
    pub server_name: String,
    pub local_path: String,
    pub remote_path: String,
    pub size: i64,
    pub bytes_done: i64,
    pub state: String,
    pub error: Option<String>,
    pub resume: Option<String>,
    pub preserve_ts: Option<bool>,
    pub target_session_id: Option<String>,
    pub target_server_name: Option<String>,
    pub target_remote_path: Option<String>,
    pub attempts: i64,
    pub verify: Option<bool>,
    /// Saved-server id the job's `session_id` was opened for. Session ids are
    /// per-run, so this is the only thing that lets a Paused/restored job be
    /// matched to a RECONNECTED session of the same server (A7-17). `None` for
    /// rows written before the column existed.
    pub server_id: Option<String>,
    /// ServerCopy only: saved-server id of the TARGET session.
    pub target_server_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwardenConfig {
    pub server_url: Option<String>,
    pub email: Option<String>,
    pub master_password: Option<String>, // sealed JSON blob (encrypted with vault pw)
    pub folder_name: Option<String>,     // keys folder (legacy single-folder default: "SSHSpan")
    pub servers_folder_name: Option<String>, // servers folder (default "SSHSpan_Servers")
    pub device_id: Option<String>,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_result: Option<String>, // JSON sync summary
    /// The destination ([`BitwardenConfig::destination`]) the user allowed
    /// to receive uploads in a native question; `""` while none is. Uploads
    /// go only to that destination ([`BitwardenConfig::confirmed`]).
    pub confirmed_destination: Option<String>,
}

impl Default for BitwardenConfig {
    fn default() -> Self {
        Self {
            server_url: None,
            email: None,
            master_password: None,
            folder_name: None,
            servers_folder_name: None,
            device_id: None,
            last_sync: None,
            last_result: None,
            confirmed_destination: None,
        }
    }
}

impl BitwardenConfig {
    /// Where a sync uploads to: the server URL and the account email (trimmed
    /// and case-folded, as accounts are compared), as one value; `None` while
    /// either is missing.
    pub fn destination(&self) -> Option<String> {
        let url = self.server_url.as_deref()?;
        let email = self.email.as_deref()?;
        serde_json::to_string(&[url, email.trim().to_lowercase().as_str()]).ok()
    }

    /// Whether uploads may go to the stored destination: it is the one the
    /// user allowed. A save that points the sync at any other server or
    /// account leaves it unconfirmed until the question allows that one.
    pub fn confirmed(&self) -> bool {
        self.destination()
            .is_some_and(|destination| self.confirmed_destination.as_deref() == Some(&destination))
    }
}

/// AI assistant provider settings. `api_key` holds the vault-sealed blob
/// (AES-256-GCM via crypto::vault::seal), never the plaintext key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssistantConfig {
    pub provider: Option<String>, // "openai" | "anthropic"
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>, // sealed JSON blob
}

/// One MCP (Model Context Protocol) tool served by an `McpServerRecord`.
///
/// `name` is the REAL name the server used in tools/list; the
/// renderer-exposed name (`mcp__<server>__<tool>`) is derived from it on the
/// fly (deterministic, no second stored spelling to drift out of sync).
///
/// `description` is the display copy, already truncated to the 1024-char cap
/// with a marker - the FULL description only ever exists transiently at
/// fetch time, where it feeds `current_hash`.
///
/// Two hashes, deliberately separate:
/// - `pin_hash`    - the definition the user APPROVED. Set when the tool is
///                   enabled, never touched by a later tools/list.
/// - `current_hash`- the NEWEST definition the server sent. Updated on every
///                   tools/list; a mismatch with `pin_hash` while enabled
///                   disables the tool and audits
///                   `mcp.tool_definition_changed` (definition rug-pull).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolRecord {
    pub name: String,
    pub display_name: Option<String>,
    pub description: String,
    pub enabled: bool,
    pub auto_approve: bool,
    /// SHA-256 (canonical JSON) of the tool definition the user approved.
    pub pin_hash: Option<String>,
    /// SHA-256 (canonical JSON) of the most recently fetched definition.
    pub current_hash: Option<String>,
    /// The tool's `inputSchema` as bounded canonical JSON (object-only, at
    /// most `MAX_INPUT_SCHEMA_BYTES` bytes, keys sorted). Stored so the
    /// model-facing tool list can carry the real per-tool schema; the PIN
    /// hash still covers the full untruncated definition. `None` when the
    /// server sent no schema, a non-object, or one above the cap (views
    /// substitute an empty object schema).
    #[serde(default)]
    pub input_schema: Option<String>,
    /// Server-provided annotations (readOnlyHint, destructiveHint, ...) for
    /// DISPLAY ONLY - never consulted by any gate (a lying server must not
    /// be able to mark its own tool safe).
    pub annotations: Option<serde_json::Value>,
}

/// What one MCP read-modify-write ([`Database::modify_mcp_servers`]) writes.
#[derive(Debug, Clone)]
pub enum McpWrite {
    /// A new record. Inserted - never over an existing row.
    Insert(McpServerRecord),
    /// A record of the snapshot, replaced whole. Never re-creates a record
    /// that is not stored.
    Update(McpServerRecord),
}

/// A configured MCP server (Streamable HTTP transport). `auth_secret` holds
/// a vault-sealed blob, never the plaintext header value; `auth_env_var`
/// stores only the variable NAME - the value is resolved from the process
/// environment at request time and never persisted.
///
/// `confirmed` gates every connect/test: an entry that arrived from a
/// backup restore, sync, or import is stored with `confirmed = false` and
/// must be re-confirmed in the UI (re-save) before any network traffic can
/// send its secret toward the stored URL - otherwise a crafted backup makes
/// the first initialize leak a stored secret or env var to an attacker's
/// URL. A save that binds a secret or env var to a place it was not bound to
/// before is stored with `confirmed = false` too, until the user allows it
/// in a native dialog (`assistant::mcp::settle_binding`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerRecord {
    pub id: String,
    pub name: String,
    pub url: String,
    /// none | bearer | custom_header
    pub auth_type: String,
    pub auth_header_name: Option<String>,
    pub auth_secret: Option<String>,
    pub auth_env_var: Option<String>,
    pub confirmed: bool,
    #[serde(default)]
    pub tools: Vec<McpToolRecord>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct Database {
    pub pool: SqlitePool,

    pub db_path: PathBuf,
}

/// The `keys` columns `row_to_key` reads, NAMED for every key query rather
/// than `SELECT *`. A pooled connection whose schema predates
/// `migrate()`'s ALTER TABLEs prepares `*` against its stale column list,
/// SQLite re-prepares with the new one, and sqlx then indexed past its cached
/// columns ("index out of bounds: the len is 14"). A named column that a stale
/// schema lacks makes SQLite reload the schema instead.
macro_rules! key_columns {
    () => {
        "id, name, key_type, public_key, private_key_encrypted, fingerprint_sha256, \
         fingerprint_md5, comment, created_at, updated_at, deployed, deploy_path, \
         bitwarden_id, bitwarden_sync, bitwarden_revision_ts, bitwarden_updated_at"
    };
}

/// The `servers` columns `row_to_server` reads - see [`key_columns`].
macro_rules! server_columns {
    () => {
        "id, name, host, port, username, key_id, pem_path, auth_method, saved_password, \
         category_id, color, last_connected_at, created_at, updated_at, bitwarden_id, \
         bitwarden_revision_ts, bitwarden_updated_at"
    };
}

/// The `known_hosts` columns `row_to_known_host` reads - see [`key_columns`].
/// With `SELECT *` a pooled connection opened before the upgrade added
/// `source` never saw that column, and its reader's fallback made an
/// unconfirmed backup pin look like a confirmed one.
macro_rules! known_host_columns {
    () => {
        "host, host_key, fingerprint_sha256, first_seen, source"
    };
}

/// How many audit rows to keep. Enforced on every insert (see `add_audit`),
/// which is the only place rows are created, so the table cannot outgrow this
/// regardless of how long the app runs. Sized well above the renderer's
/// 200-row page so the cap is about reclaiming space, not about what the user
/// can see.
pub const AUDIT_RETENTION_ROWS: i64 = 10_000;

use std::sync::OnceLock;

/// Lazily-created, long-lived tokio runtime used by the DB layer when no
/// ambient runtime is available (sync commands, startup). Cached after the
/// first call so subsequent DB hits don't pay the ~300ms runtime-init cost.
fn cached_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME
        .get_or_init(|| tokio::runtime::Runtime::new().expect("Failed to create DB tokio runtime"))
}

/// Reads of the categories table (`list_categories`, `get_category`) per
/// database file - tests only, so a test can bound how often a pass reads
/// them. Keyed by file: every test opens a database of its own.
#[cfg(test)]
static CATEGORY_READS: std::sync::Mutex<Option<HashMap<PathBuf, usize>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn count_category_read(db_path: &std::path::Path) {
    let mut reads = CATEGORY_READS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *reads
        .get_or_insert_with(HashMap::new)
        .entry(db_path.to_path_buf())
        .or_insert(0) += 1;
}

/// Run an async block to completion, blocking the current thread.
///
/// When called from inside a task of the Tauri/tokio async runtime (an async
/// command, the blocking pool) it uses `block_in_place` to run the future on
/// the current worker instead of nesting a runtime. When called from a plain
/// thread (startup, sync commands, tests) it uses a cached runtime to avoid
/// re-creating one per call. When called from the root future of a
/// multi-thread runtime's `block_on` - a runtime is entered but no task
/// runs, as in the body of a `#[tokio::test(flavor = "multi_thread")]` - it
/// waits on a parker of its own ([`block_on_own_parker`]): tokio's nested
/// `block_on` parks on the very parker of that thread's `block_on`, and used
/// up a wake-up meant for another part of the root future that came in
/// meanwhile - which then waited for the next event, forever when there was
/// none (the hung MCP tests of round 6). On a current-thread runtime it does
/// not: that thread drives the runtime's timers and I/O, which would stop
/// while it sleeps on a parker of its own - `block_in_place` refuses there
/// at once, as it always did.
fn block<F: std::future::Future<Output = T>, T>(f: F) -> T {
    if tokio::runtime::Handle::try_current().is_err() {
        return cached_runtime().block_on(f);
    }
    if tokio::task::try_id().is_none()
        && tokio::runtime::Handle::current().runtime_flavor()
            == tokio::runtime::RuntimeFlavor::MultiThread
    {
        return block_on_own_parker(f);
    }
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

/// Drive `f` to completion on this thread, parking with std's own thread
/// parker between polls - not tokio's per-thread one, which the root future
/// of this thread's `block_on` waits on - so no wake-up meant for that root
/// future is ever used up here. The runtime stays entered (`f` may use its
/// timers and spawn), and the coop budget does not apply: `f` runs to the
/// end, as under `block_in_place`.
fn block_on_own_parker<F: std::future::Future>(f: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(std::sync::Arc::new(Unpark(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut f = std::pin::pin!(tokio::task::unconstrained(f));
    loop {
        if let std::task::Poll::Ready(out) = std::future::Future::poll(f.as_mut(), &mut cx) {
            return out;
        }
        std::thread::park();
    }
}

impl Database {
    pub fn new(app: &AppHandle) -> Result<Self> {
        let db_path = get_db_path(app)?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
            // Owner-only on the DIRECTORY too, not just the file below.
            // create_dir_all leaves 0755 under a normal umask, so anything
            // the app drops beside the DB at default permissions is readable
            // by every local account - including SQLite's transient
            // `-journal`, which carries page images of sealed material while
            // a write is in flight.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) =
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                {
                    log::warn!(
                        "[sshspan-db] could not restrict {} to 0700: {e}",
                        parent.display()
                    );
                }
            }
        }
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
        let pool = block(async { SqlitePool::connect(&db_url).await })?;
        // Owner-only permissions on the vault file (Unix). The DB holds the
        // Argon2id verifier and sealed key material; default umasks can leave
        // it world-readable depending on the system.
        //
        // Propagated, not swallowed: this used to be `let _ = ...`, so a
        // failure left the vault at default permissions with no error and no
        // log line - a security property applied best-effort and never
        // verified is one you cannot claim.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    anyhow::anyhow!(
                        "Could not restrict permissions on the vault database {}: {e}",
                        db_path.display()
                    )
                },
            )?;
        }
        let db = Self { pool, db_path };
        db.migrate()?;
        Ok(db)
    }

    /// Open/migrate a database at an explicit path - for tests and tools only.
    /// It skips the owner-only permission tightening [`Database::new`]
    /// applies to the vault file and its directory (and the `SSHSPAN_DB`
    /// override and platform data dir it resolves), so the app must never use
    /// it for a real vault. Public rather than `#[cfg(test)]` so the
    /// integration tests get the real schema instead of hand-copied
    /// `CREATE TABLE`s; hidden from the docs for the same reason.
    #[doc(hidden)]
    pub fn open_at(db_path: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
        let pool = block(async { SqlitePool::connect(&db_url).await })?;
        let db = Self { pool, db_path };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        block(async {
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS keys (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    key_type TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key_encrypted TEXT NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    fingerprint_md5 TEXT NOT NULL,
                    comment TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    deployed INTEGER DEFAULT 0,
                    deploy_path TEXT,
                    bitwarden_id TEXT,
                    bitwarden_sync INTEGER DEFAULT 0
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    key_id TEXT,
                    details TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS bitwarden_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            // AI assistant provider settings. Same key/value shape as
            // bitwarden_config; the api_key row holds the vault-sealed blob,
            // never the plaintext key.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS assistant_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            // MCP servers (Model Context Protocol, Streamable HTTP). Same
            // key/value shape as assistant_config: one row per server with
            // the whole record (including per-tool state) as JSON in `value`.
            // The auth_secret field inside that JSON is a vault-sealed blob,
            // never plaintext. `confirmed` lives inside the JSON too; the
            // extra column duplicates it so an unconfirmed restore can be
            // recognized from the row alone.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS mcp_servers (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    confirmed INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_keys_fingerprint ON keys(fingerprint_sha256)",
            )
            .execute(&self.pool)
            .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_keys_bitwarden_id ON keys(bitwarden_id)")
                .execute(&self.pool)
                .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
                .execute(&self.pool)
                .await?;

            // Migration: add sync metadata columns if missing
            let _ = sqlx::query("ALTER TABLE keys ADD COLUMN bitwarden_revision_ts TEXT")
                .execute(&self.pool)
                .await;
            let _ = sqlx::query("ALTER TABLE keys ADD COLUMN bitwarden_updated_at TEXT")
                .execute(&self.pool)
                .await;

            // Categories: user-defined tree of named nodes that group keys.
            // Arbitrary depth via self-referential parent_id; many-to-many to
            // keys via the key_categories join table.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS categories (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    parent_id   TEXT,
                    scope       TEXT NOT NULL DEFAULT 'key',
                    color       TEXT,
                    sort_index  INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            let _ =
                sqlx::query("ALTER TABLE categories ADD COLUMN scope TEXT NOT NULL DEFAULT 'key'")
                    .execute(&self.pool)
                    .await;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_categories_parent ON categories(parent_id)",
            )
            .execute(&self.pool)
            .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS key_categories (
                    key_id      TEXT NOT NULL,
                    category_id TEXT NOT NULL,
                    PRIMARY KEY (key_id, category_id)
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_key_categories_cat ON key_categories(category_id)",
            )
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_key_categories_key ON key_categories(key_id)",
            )
            .execute(&self.pool)
            .await?;
            // Links to keys that no longer exist: `delete_key` left them
            // behind until it learned to remove them (A7-28), and they kept
            // inflating category counts. The table has no foreign key.
            sqlx::query("DELETE FROM key_categories WHERE key_id NOT IN (SELECT id FROM keys)")
                .execute(&self.pool)
                .await?;

            // Connect: saved SSH servers (PuTTY-style sessions) + trusted host keys.
            // key_id references keys.id; the private key itself is never copied -
            // the reference is resolved + unsealed in-process at connect time.
            // saved_password holds an AES-GCM blob sealed with the vault password,
            // only present when the user opts to store a password.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS servers (
                    id            TEXT PRIMARY KEY,
                    name          TEXT NOT NULL,
                    host          TEXT NOT NULL,
                    port          INTEGER NOT NULL DEFAULT 22,
                    username      TEXT NOT NULL,
                    key_id        TEXT,
                    pem_path      TEXT,
                    auth_method   TEXT NOT NULL DEFAULT 'publickey',
                    saved_password TEXT,
                    category_id   TEXT,
                    color         TEXT,
                    last_connected_at TEXT,
                    created_at    TEXT NOT NULL,
                    updated_at    TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            // Migration: server sync metadata (Bitwarden two-way server sync).
            // Must run after the servers table above exists - on a fresh DB an
            // ALTER TABLE against a not-yet-created table fails silently and
            // the columns never get added.
            let _ = sqlx::query("ALTER TABLE servers ADD COLUMN bitwarden_id TEXT")
                .execute(&self.pool)
                .await;
            let _ = sqlx::query("ALTER TABLE servers ADD COLUMN bitwarden_revision_ts TEXT")
                .execute(&self.pool)
                .await;
            let _ = sqlx::query("ALTER TABLE servers ADD COLUMN bitwarden_updated_at TEXT")
                .execute(&self.pool)
                .await;
            // Existing categories are key-scoped; do not silently reuse them for hosts.
            let _ = sqlx::query("UPDATE servers SET category_id = NULL WHERE category_id IS NOT NULL AND category_id NOT IN (SELECT id FROM categories WHERE scope = 'host')")
                .execute(&self.pool)
                .await;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS known_hosts (
                    host             TEXT PRIMARY KEY,
                    host_key         TEXT NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    first_seen       TEXT NOT NULL
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            // Migration: port-qualify legacy bare-host known_hosts pins.
            // Existing rows stored the host as a bare hostname; all new rows
            // use "host:port" (see `ssh_client::known_host_key`).
            //
            // SECURITY: a pin that does not migrate is not a benign leftover.
            // The lookup key becomes "host:22", the orphaned row never matches,
            // and the next connection to that host takes the *unpinned* branch
            // - turning what should have been a hard mismatch failure into a
            // routine first-trust prompt, which is exactly the downgrade a
            // machine-in-the-middle wants. So this migration is explicit,
            // per-row, and its failures are propagated rather than discarded.
            //
            // Two shapes the old blanket `UPDATE ... WHERE host NOT LIKE '%:%'`
            // got wrong, both regression-tested below:
            //   * an IPv6 literal always contains ':', so it never matched the
            //     predicate and was left orphaned forever;
            //   * if a qualified row for the same host already existed (a
            //     backup restore inserts "host:port" directly) the UPDATE hit
            //     the PRIMARY KEY, SQLite rolled the WHOLE statement back, and
            //     `let _ =` swallowed it - losing every legacy pin at once.
            self.migrate_known_hosts_port_qualify().await?;

            // Migration: track where each known_hosts pin came from. Rows
            // that predate this column were all learned from real
            // connections, so they default to 'connection'. Pins inserted by
            // a backup restore from now on use 'imported' and require the
            // user to re-confirm the fingerprint on first use (see
            // `confirm_imported_known_host`), so a crafted backup cannot
            // silently pre-seed trust for a host the user never contacted.
            let has_source: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pragma_table_info('known_hosts') WHERE name = 'source'",
            )
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);
            if has_source == 0 {
                sqlx::query(
                    "ALTER TABLE known_hosts ADD COLUMN source TEXT NOT NULL DEFAULT 'connection'",
                )
                .execute(&self.pool)
                .await?;
            }

            // Migration (A7-46): one fingerprint form, `SHA256:<unpadded
            // base64>` as `ssh-keygen -lf` prints it, computed from each
            // pinned key. Older rows hold the bare padded form (or, from a
            // backup, whatever text the file carried).
            self.migrate_known_host_fingerprints().await?;
            self.migrate_bitwarden_destination().await?;

            // Transfer queue: survives a restart/crash so a 5,000-file batch
            // isn't silently lost mid-way and its `.part` files left orphaned.
            // `session_id`/`target_session_id` are per-run and stale the
            // moment the app restarts - `sftp::queue::restore_pending` is what
            // turns a restored row into a "needs reconnect" Paused job, not
            // this table's schema.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS transfer_queue (
                    id                  INTEGER PRIMARY KEY,
                    kind                TEXT NOT NULL,
                    session_id          TEXT NOT NULL,
                    server_name         TEXT NOT NULL,
                    local_path          TEXT NOT NULL,
                    remote_path         TEXT NOT NULL,
                    size                INTEGER NOT NULL,
                    bytes_done          INTEGER NOT NULL,
                    state               TEXT NOT NULL,
                    error               TEXT,
                    resume              TEXT,
                    preserve_ts         INTEGER,
                    target_session_id   TEXT,
                    target_server_name  TEXT,
                    target_remote_path  TEXT,
                    attempts            INTEGER NOT NULL DEFAULT 0,
                    verify              INTEGER,
                    updated_at          TEXT NOT NULL,
                    server_id           TEXT,
                    target_server_id    TEXT
                )
                "#,
            )
            .execute(&self.pool)
            .await?;
            // `server_id`/`target_server_id` (A7-17): the saved servers the
            // job's sessions belonged to, which - unlike the per-run session
            // ids - are what a reconnected session can be matched on. Added in
            // place for databases created before they existed; jobs already in
            // such a table simply have NULL and stay un-rebindable.
            for column in ["server_id", "target_server_id"] {
                let has_column: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pragma_table_info('transfer_queue') WHERE name = ?",
                )
                .bind(column)
                .fetch_one(&self.pool)
                .await
                .unwrap_or(0);
                if has_column == 0 {
                    sqlx::query(&format!(
                        "ALTER TABLE transfer_queue ADD COLUMN {column} TEXT"
                    ))
                    .execute(&self.pool)
                    .await?;
                }
            }
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_transfer_queue_state ON transfer_queue(state)",
            )
            .execute(&self.pool)
            .await?;

            // Keys and servers whose category path changed without the row
            // changing - a category renamed, moved or deleted, a key's
            // categories set - until the Bitwarden sync has uploaded the new
            // path ([`Database::category_marks`]). Kept apart from
            // `updated_at`, which says the row itself changed: that one makes
            // "local wins" upload every field, and a category change alone
            // must never upload fields older than Bitwarden's. Machine-local
            // state: not in backups.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS sync_category_marks (
                    kind       TEXT NOT NULL,
                    id         TEXT NOT NULL,
                    changed_at INTEGER NOT NULL,
                    PRIMARY KEY (kind, id)
                )
                "#,
            )
            .execute(&self.pool)
            .await?;

            Ok::<_, anyhow::Error>(())
        })
    }

    // ── Key operations ─────────────────────────────────────────────────────

    pub fn insert_key(&self, key: &KeyRecord) -> Result<()> {
        block(async {
            sqlx::query(
                r#"
                INSERT INTO keys (id, name, key_type, public_key, private_key_encrypted,
                                  fingerprint_sha256, fingerprint_md5, comment, created_at, updated_at,
                                  deployed, deploy_path, bitwarden_id, bitwarden_sync,
                                  bitwarden_revision_ts, bitwarden_updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&key.id)
            .bind(&key.name)
            .bind(&key.key_type)
            .bind(&key.public_key)
            .bind(&key.private_key_encrypted)
            .bind(&key.fingerprint_sha256)
            .bind(&key.fingerprint_md5)
            .bind(&key.comment)
            .bind(key.created_at.to_rfc3339())
            .bind(key.updated_at.to_rfc3339())
            .bind(key.deployed as i64)
            .bind(&key.deploy_path)
            .bind(&key.bitwarden_id)
            .bind(key.bitwarden_sync as i64)
            .bind(key.bitwarden_revision_ts.map(|v| v.to_string()))
            .bind(key.bitwarden_updated_at.map(|v| v.to_string()))
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Delete a key together with its category links, in one transaction
    /// (A7-28): `key_categories` has no foreign key, and links left behind
    /// kept counting the deleted key in every category it had belonged to.
    pub fn delete_key(&self, id: &str) -> Result<()> {
        block(async {
            let mut tx = self.pool.begin().await?;
            sqlx::query("DELETE FROM key_categories WHERE key_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM keys WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    /// The name of another key that already uses `name`, compared without
    /// regard to case, or `None` when the name is free (A2-46 / A5-25: names
    /// had no uniqueness at all). `except_id` is the key being renamed. The
    /// comparison is Unicode-aware, so it is done here rather than with
    /// SQLite's ASCII-only `lower()`.
    pub fn key_name_in_use(&self, name: &str, except_id: Option<&str>) -> Result<Option<String>> {
        let wanted = name.to_lowercase();
        block(async {
            let rows: Vec<(String, String)> = sqlx::query_as("SELECT id, name FROM keys")
                .fetch_all(&self.pool)
                .await?;
            Ok(rows
                .into_iter()
                .find(|(id, existing)| {
                    Some(id.as_str()) != except_id && existing.to_lowercase() == wanted
                })
                .map(|(_, existing)| existing))
        })
    }

    /// Rename a key - the name and `updated_at`, nothing else. A rename used to
    /// write back the whole row it had read, which could erase a deployment
    /// recorded meanwhile by a deploy running off the main thread.
    pub fn rename_key(&self, id: &str, name: &str) -> Result<()> {
        block(async {
            sqlx::query("UPDATE keys SET name = ?, updated_at = ? WHERE id = ?")
                .bind(name)
                .bind(Utc::now().to_rfc3339())
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    /// Record (`Some`) or clear (`None`) where a key is deployed - those two
    /// columns, nothing else: the deploy commands used to write the whole
    /// row back, sealed blob included. Not `updated_at` either: that is the
    /// Bitwarden sync's "changed locally" marker, and a deploy or undeploy
    /// changes nothing the sync uploads - bumping it re-uploaded the key on
    /// the next sync and counted a conflict (A7-23).
    pub fn set_key_deployment(&self, id: &str, deploy_path: Option<&str>) -> Result<()> {
        block(async {
            sqlx::query("UPDATE keys SET deployed = ?, deploy_path = ? WHERE id = ?")
                .bind(deploy_path.is_some() as i64)
                .bind(deploy_path)
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    /// Write a key pulled from Bitwarden into its row: the key material,
    /// name and comment the item carries, the remote revision, and the sync
    /// marks - and nothing else. The sync used to write back the whole row it
    /// had read before its network round trips, which erased a deployment
    /// recorded meanwhile.
    /// Written only while the row is still the one the sync read
    /// (`expected_updated_at`): a rename made while the pull sealed, or a row
    /// deleted meanwhile, is never overwritten - false then, nothing
    /// written.
    pub fn apply_pulled_key(
        &self,
        id: &str,
        pulled: &KeyPull,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<bool> {
        let now = Utc::now();
        block(async {
            // BEGIN IMMEDIATE: the row is read, then written - a deferred
            // transaction was refused at once ("database is locked") when
            // another connection was writing; this one waits.
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let stored: Option<String> =
                sqlx::query_scalar("SELECT updated_at FROM keys WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await?;
            let Some(stored) = stored.filter(|s| same_instant(s, expected_updated_at)) else {
                return Ok(false);
            };
            let res = sqlx::query(
                "UPDATE keys SET name = ?, key_type = ?, public_key = ?, private_key_encrypted = ?, \
                 fingerprint_sha256 = ?, fingerprint_md5 = ?, comment = ?, updated_at = ?, \
                 bitwarden_revision_ts = ?, bitwarden_updated_at = ? WHERE id = ? AND updated_at = ?",
            )
            .bind(&pulled.name)
            .bind(&pulled.key_type)
            .bind(&pulled.public_key)
            .bind(&pulled.private_key_encrypted)
            .bind(&pulled.fingerprint_sha256)
            .bind(&pulled.fingerprint_md5)
            .bind(&pulled.comment)
            .bind(now.to_rfc3339())
            .bind(pulled.bitwarden_revision_ts.map(|v| v.to_string()))
            .bind(now.timestamp_millis().to_string())
            .bind(id)
            .bind(&stored)
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() != 1 {
                return Ok(false);
            }
            tx.commit().await?;
            Ok(true)
        })
    }

    /// Forget a key's Bitwarden link (its item is gone and the key is not
    /// uploaded, e.g. public-only), so the loss is reported once.
    pub fn clear_key_sync_link(&self, id: &str) -> Result<()> {
        block(async {
            sqlx::query(
                "UPDATE keys SET bitwarden_id = NULL, bitwarden_revision_ts = NULL, \
                 bitwarden_updated_at = NULL WHERE id = ?",
            )
            .bind(id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// `(id, name, deploy_path)` of every key with a recorded deployment -
    /// what the deploy collision check compares against.
    pub fn list_key_deployments(&self) -> Result<Vec<(String, String, String)>> {
        block(async {
            Ok(sqlx::query_as(
                "SELECT id, name, deploy_path FROM keys WHERE deploy_path IS NOT NULL",
            )
            .fetch_all(&self.pool)
            .await?)
        })
    }

    /// Update only Bitwarden sync metadata on a key row (lightweight, no full
    /// record needed). `synced_marker_ms` is the `updated_at` of the row the
    /// sync pushed or linked (epoch milliseconds), not the time of this write:
    /// an edit made while the upload was in flight is newer than that marker
    /// and is still uploaded at the next sync (A7-23).
    pub fn update_key_sync_meta(
        &self,
        id: &str,
        bitwarden_id: &str,
        revision_date: Option<&str>,
        synced_marker_ms: i64,
    ) -> Result<()> {
        let rev_ts = revision_date
            .and_then(|rd| chrono::DateTime::parse_from_rfc3339(rd).ok())
            .map(|rd| rd.timestamp_millis().to_string());
        block(async {
            sqlx::query(
                "UPDATE keys SET bitwarden_id = ?, bitwarden_revision_ts = ?, bitwarden_updated_at = ? WHERE id = ?"
            )
            .bind(bitwarden_id)
            .bind(&rev_ts)
            .bind(synced_marker_ms.to_string())
            .bind(id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    pub fn get_key(&self, id: &str) -> Result<Option<KeyRecord>> {
        block(async {
            let row = sqlx::query(concat!(
                "SELECT ",
                key_columns!(),
                " FROM keys WHERE id = ?"
            ))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| Self::row_to_key(r)))
        })
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        block(async {
            let rows = sqlx::query(concat!(
                "SELECT ",
                key_columns!(),
                " FROM keys ORDER BY created_at DESC"
            ))
            .fetch_all(&self.pool)
            .await?;
            Ok(rows.into_iter().map(|r| Self::row_to_key(r)).collect())
        })
    }

    fn row_to_key(row: SqliteRow) -> KeyRecord {
        KeyRecord {
            id: row.get("id"),
            name: row.get("name"),
            key_type: row.get("key_type"),
            public_key: row.get("public_key"),
            private_key_encrypted: row.get("private_key_encrypted"),
            fingerprint_sha256: row.get("fingerprint_sha256"),
            fingerprint_md5: row.get("fingerprint_md5"),
            comment: row.get("comment"),
            created_at: DateTime::parse_from_rfc3339(row.get::<String, _>("created_at").as_str())
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(row.get::<String, _>("updated_at").as_str())
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now()),
            deployed: row.get::<i64, _>("deployed") != 0,
            deploy_path: row.get("deploy_path"),
            bitwarden_id: row.get("bitwarden_id"),
            bitwarden_sync: row.get::<i64, _>("bitwarden_sync") != 0,
            bitwarden_revision_ts: row
                .get::<Option<String>, _>("bitwarden_revision_ts")
                .and_then(|s| s.parse().ok()),
            bitwarden_updated_at: row
                .get::<Option<String>, _>("bitwarden_updated_at")
                .and_then(|s| s.parse().ok()),
            category_ids: Vec::new(), // populated by list_keys_with_categories / get_key_with_categories
        }
    }

    // ── Config operations ──────────────────────────────────────────────────

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        block(async {
            sqlx::query(
                "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
            )
            .bind(key)
            .bind(value)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Store the master-password verifier of a NEW vault under `hash_key`, and
    /// when it was created under `created_key` - in one `BEGIN IMMEDIATE`
    /// transaction, and only if no (non-empty) verifier is stored yet: `false`
    /// when a vault already exists, nothing written. As a check followed by
    /// separate writes, two creates at once (possible since `vault_create`
    /// runs off the main thread) both passed the check, and the second
    /// verifier replaced the first while the first password stayed in memory.
    pub fn create_vault_verifier(
        &self,
        hash_key: &str,
        hash: &str,
        created_key: &str,
        created_at: &str,
    ) -> Result<bool> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let existing: Option<String> =
                sqlx::query_scalar("SELECT value FROM config WHERE key = ?")
                    .bind(hash_key)
                    .fetch_optional(&mut *tx)
                    .await?;
            if existing.is_some_and(|v| !v.is_empty()) {
                return Ok(false);
            }
            let now = Utc::now().to_rfc3339();
            for (key, value) in [(hash_key, hash), (created_key, created_at)] {
                sqlx::query(
                    "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                )
                .bind(key)
                .bind(value)
                .bind(&now)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(true)
        })
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        block(async {
            let row = sqlx::query("SELECT value FROM config WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
            Ok(row.map(|r| r.get("value")))
        })
    }

    /// Every config row whose key starts with `prefix`, as (key, value).
    ///
    /// `settings_get` exposes a fixed allowlist of keys to the renderer so
    /// that secrets living in the same table (`bwSync.*`) can never be read
    /// out through it. That works only for keys known at compile time; a
    /// per-server setting is one key per server id and cannot be enumerated
    /// in advance. This narrows the same boundary to a prefix instead: the
    /// caller names the family it wants, not the whole table.
    ///
    /// `_` and `%` in the prefix are escaped so a key containing either is
    /// matched literally rather than as a LIKE wildcard.
    pub fn list_config_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        let pattern = format!(
            "{}%",
            prefix
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        block(async {
            let rows = sqlx::query(
                "SELECT key, value FROM config WHERE key LIKE ? ESCAPE '\\' ORDER BY key",
            )
            .bind(pattern)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| (r.get("key"), r.get("value")))
                .collect())
        })
    }

    // ── Audit log ──────────────────────────────────────────────────────────

    pub fn add_audit(&self, action: &str, key_id: Option<&str>, details: &str) -> Result<()> {
        block(async {
            sqlx::query(
                "INSERT INTO audit_log (action, key_id, details, timestamp) VALUES (?, ?, ?, ?)",
            )
            .bind(action)
            .bind(key_id)
            .bind(details)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
            // Retention: the table previously grew without bound (nothing ever
            // deleted a row), while the UI could only ever display the newest
            // 200 - so the oldest history was invisible AND unreclaimable.
            // Trim by row count rather than by age: the cap is what the
            // display limit can meaningfully represent, and a quiet install
            // should not lose years of history to a time-based rule.
            sqlx::query(
                "DELETE FROM audit_log WHERE id NOT IN \
                 (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)",
            )
            .bind(AUDIT_RETENTION_ROWS)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Total number of audit rows, so the UI can say how many exist rather
    /// than implying the visible page is everything.
    pub fn count_audit(&self) -> Result<i64> {
        block(async {
            let row = sqlx::query("SELECT COUNT(*) AS n FROM audit_log")
                .fetch_one(&self.pool)
                .await?;
            Ok(row.get::<i64, _>("n"))
        })
    }

    /// Delete every audit row. The audit trail is a local record for the user,
    /// not a tamper-evident log, so the user clearing it is a supported
    /// action - and it is itself recorded (the caller writes the marker row
    /// afterwards) so a cleared log still shows that a clear happened.
    pub fn clear_audit(&self) -> Result<u64> {
        block(async {
            let res = sqlx::query("DELETE FROM audit_log")
                .execute(&self.pool)
                .await?;
            Ok(res.rows_affected())
        })
    }

    pub fn list_audit(&self, limit: i64) -> Result<Vec<AuditRecord>> {
        block(async {
            let rows = sqlx::query(
                "SELECT id, action, key_id, details, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?"
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows
                .into_iter()
                .map(|row| AuditRecord {
                    id: row.get("id"),
                    action: row.get("action"),
                    key_id: row.get("key_id"),
                    details: row.get("details"),
                    timestamp: DateTime::parse_from_rfc3339(
                        row.get::<String, _>("timestamp").as_str(),
                    )
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|| Utc::now()),
                })
                .collect())
        })
    }

    // ── Bitwarden config ───────────────────────────────────────────────────

    /// Change the sync settings in ONE transaction: `update` gets the settings
    /// as stored inside that transaction and edits them - or refuses, and
    /// nothing is written. Every field it leaves set is then written back,
    /// all or nothing. The fields used to be separate autocommit
    /// statements over a pooled connection, so another connection could read
    /// a new server URL beside the OLD sealed password, and a save that failed
    /// part-way kept half its fields; a save that re-wrote a copy read before
    /// a slow step also put back a password another save had just stored.
    ///
    /// `BEGIN IMMEDIATE`: the transaction takes the write lock before it
    /// reads, so a write held by another connection makes it WAIT (busy
    /// timeout). A deferred transaction that read first was refused at once
    /// ("database is locked") when it then tried to write.
    pub fn update_bitwarden_config(
        &self,
        update: impl FnOnce(&mut BitwardenConfig) -> Result<()>,
    ) -> Result<()> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let rows: Vec<(String, String)> =
                sqlx::query_as("SELECT key, value FROM bitwarden_config")
                    .fetch_all(&mut *tx)
                    .await?;
            let mut config = bitwarden_config_from_rows(rows);
            update(&mut config)?;
            write_bitwarden_config(&mut tx, &config).await?;
            tx.commit().await?;
            Ok(())
        })
    }

    /// Replace the stored settings with every set field of `config`, through
    /// [`Database::update_bitwarden_config`]. Tests only: the app changes the
    /// settings as stored inside one transaction, never by writing back a
    /// copy read earlier.
    #[cfg(test)]
    pub(crate) fn save_bitwarden_config(&self, config: &BitwardenConfig) -> Result<()> {
        let config = config.clone();
        self.update_bitwarden_config(move |stored| {
            *stored = config;
            Ok(())
        })
    }

    pub fn load_bitwarden_config(&self) -> Result<BitwardenConfig> {
        block(async {
            // One statement: it sees one committed state of the table.
            let rows: Vec<(String, String)> =
                sqlx::query_as("SELECT key, value FROM bitwarden_config")
                    .fetch_all(&self.pool)
                    .await?;
            Ok(bitwarden_config_from_rows(rows))
        })
    }

    // ── AI assistant config ────────────────────────────────────────────────

    /// Write every field of `config` (`None` deletes the row), all or nothing
    /// (see [`Database::update_assistant_config`]).
    pub fn save_assistant_config(&self, config: &AssistantConfig) -> Result<()> {
        let config = config.clone();
        self.update_assistant_config(move |stored| {
            *stored = config;
            Ok(())
        })
    }

    /// Change the assistant settings in ONE `BEGIN IMMEDIATE` transaction:
    /// `update` gets them as stored inside it and edits them - or refuses,
    /// and nothing is written - and every field is then written back, all or
    /// nothing (`None` deletes the row: clearing the provider must not leave
    /// its key behind). The fields used to be four autocommit statements, so
    /// a save that failed part-way kept a new provider and base URL beside
    /// the OLD sealed key, and a chat reading mid-save could see that mix -
    /// either way the key went to an endpoint it was not saved for (the
    /// same pattern the Bitwarden settings had). The write
    /// lock is taken before the read, so a concurrent writer makes it wait.
    pub fn update_assistant_config<T>(
        &self,
        update: impl FnOnce(&mut AssistantConfig) -> Result<T>,
    ) -> Result<T> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let rows: Vec<(String, String)> =
                sqlx::query_as("SELECT key, value FROM assistant_config")
                    .fetch_all(&mut *tx)
                    .await?;
            let mut config = assistant_config_from_rows(rows);
            let out = update(&mut config)?;
            let fields: [(&str, Option<String>); 4] = [
                ("provider", config.provider),
                ("base_url", config.base_url),
                ("model", config.model),
                ("api_key", config.api_key),
            ];
            let now = Utc::now().to_rfc3339();
            for (key, value) in fields {
                if let Some(v) = value {
                    sqlx::query(
                        "INSERT INTO assistant_config (key, value, updated_at) VALUES (?, ?, ?) \
                         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
                    )
                    .bind(key)
                    .bind(v)
                    .bind(&now)
                    .execute(&mut *tx)
                    .await?;
                } else {
                    sqlx::query("DELETE FROM assistant_config WHERE key = ?")
                        .bind(key)
                        .execute(&mut *tx)
                        .await?;
                }
            }
            tx.commit().await?;
            Ok(out)
        })
    }

    pub fn load_assistant_config(&self) -> Result<AssistantConfig> {
        block(async {
            // One statement: it sees one committed state of the table.
            let rows: Vec<(String, String)> =
                sqlx::query_as("SELECT key, value FROM assistant_config")
                    .fetch_all(&self.pool)
                    .await?;
            Ok(assistant_config_from_rows(rows))
        })
    }

    // ── MCP servers ────────────────────────────────────────────────────────

    /// Upsert one MCP server record (the whole record, tools included, as
    /// JSON). `key` is the record id. Not for read-modify-write: a record
    /// read earlier and written back here replaces whatever was stored
    /// meanwhile - and re-creates a removed one. Changes to a stored record
    /// go through [`Database::modify_mcp_servers`].
    pub fn save_mcp_server(&self, record: &McpServerRecord) -> Result<()> {
        block(async {
            let value = serde_json::to_string(record)?;
            sqlx::query(
                "INSERT INTO mcp_servers (key, value, confirmed, updated_at) VALUES (?, ?, ?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, \
                   confirmed = excluded.confirmed, updated_at = excluded.updated_at",
            )
            .bind(&record.id)
            .bind(value)
            .bind(record.confirmed as i64)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    pub fn get_mcp_server(&self, id: &str) -> Result<Option<McpServerRecord>> {
        block(async {
            let row = sqlx::query("SELECT value FROM mcp_servers WHERE key = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            row.map(|r| serde_json::from_str(&r.get::<String, _>("value")))
                .transpose()
                .map_err(Into::into)
        })
    }

    pub fn list_mcp_servers(&self) -> Result<Vec<McpServerRecord>> {
        block(async {
            let rows = sqlx::query("SELECT value FROM mcp_servers ORDER BY key ASC")
                .fetch_all(&self.pool)
                .await?;
            rows.into_iter()
                .map(|r| serde_json::from_str(&r.get::<String, _>("value")))
                .collect::<Result<Vec<_>, _>>()
                .map_err(Into::into)
        })
    }

    pub fn delete_mcp_server(&self, id: &str) -> Result<bool> {
        block(async {
            let res = sqlx::query("DELETE FROM mcp_servers WHERE key = ?")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(res.rows_affected() > 0)
        })
    }

    /// One read-modify-write of the MCP server records, as ONE `BEGIN
    /// IMMEDIATE` transaction (A7-49): `modify` gets every stored record as
    /// it is at that moment and says what to write - or refuses (`Err`), and
    /// nothing is written. Its decision and the write commit together. A
    /// save, a tool toggle, a connect or a call's tool refresh used to read
    /// the record, decide, then write the whole record back as a separate
    /// statement, so a change committed in between was lost: a revoked
    /// approval came back, a refreshed definition was replaced by the stale
    /// one - and the upsert re-created a server removed meanwhile.
    ///
    /// The write lock is taken before the read, so a write held by another
    /// connection makes this one WAIT (busy timeout) instead of failing, and
    /// `modify` always sees the latest committed state. `modify` runs while
    /// the lock is held: it must be quick and must not touch the database
    /// (seal a secret before, audit after).
    pub fn modify_mcp_servers<T>(
        &self,
        modify: impl FnOnce(&[McpServerRecord]) -> Result<(McpWrite, T)>,
    ) -> Result<T> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let values: Vec<String> =
                sqlx::query_scalar("SELECT value FROM mcp_servers ORDER BY key ASC")
                    .fetch_all(&mut *tx)
                    .await?;
            let records = values
                .iter()
                .map(|value| serde_json::from_str(value))
                .collect::<Result<Vec<McpServerRecord>, _>>()?;
            let (write, out) = modify(&records)?;
            let now = Utc::now().to_rfc3339();
            match write {
                McpWrite::Insert(record) => {
                    sqlx::query(
                        "INSERT INTO mcp_servers (key, value, confirmed, updated_at) \
                         VALUES (?, ?, ?, ?)",
                    )
                    .bind(&record.id)
                    .bind(serde_json::to_string(&record)?)
                    .bind(record.confirmed as i64)
                    .bind(&now)
                    .execute(&mut *tx)
                    .await?;
                }
                McpWrite::Update(record) => {
                    let res = sqlx::query(
                        "UPDATE mcp_servers SET value = ?, confirmed = ?, updated_at = ? \
                         WHERE key = ?",
                    )
                    .bind(serde_json::to_string(&record)?)
                    .bind(record.confirmed as i64)
                    .bind(&now)
                    .bind(&record.id)
                    .execute(&mut *tx)
                    .await?;
                    if res.rows_affected() != 1 {
                        anyhow::bail!("MCP server not found.");
                    }
                }
            }
            tx.commit().await?;
            Ok(out)
        })
    }

    /// Swap each MCP record's sealed `auth_secret` for its re-sealed value in
    /// the caller's transaction - only that field (`json_set`), and only where
    /// the record still holds the blob that was re-sealed. Everything else in
    /// the record (tools, approvals, `confirmed`) stays exactly as it is now:
    /// this used to upsert the whole record as it was read before the
    /// re-seal, reverting a tool approval revoked in the meantime. A record
    /// with a secret the rotation does not know about aborts it. Called only
    /// from [`Database::apply_vault_rotation`].
    async fn rotate_mcp_secrets(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        secrets: &[ResealedSecret],
    ) -> Result<()> {
        for secret in secrets {
            let res = sqlx::query(
                "UPDATE mcp_servers SET value = json_set(value, '$.auth_secret', ?), \
                   updated_at = ? \
                 WHERE key = ? AND json_extract(value, '$.auth_secret') = ?",
            )
            .bind(&secret.new)
            .bind(Utc::now().to_rfc3339())
            .bind(&secret.id)
            .bind(&secret.old)
            .execute(&mut **tx)
            .await?;
            if res.rows_affected() != 1 {
                anyhow::bail!(VAULT_CHANGED_DURING_ROTATION);
            }
        }
        let sealed: Vec<String> = sqlx::query_scalar(
            "SELECT key FROM mcp_servers WHERE json_extract(value, '$.auth_secret') IS NOT NULL",
        )
        .fetch_all(&mut **tx)
        .await?;
        ensure_all_resealed(&sealed, secrets)
    }

    /// Swap one sealed credential row (`key` in the key/value `table`) for its
    /// re-sealed value, only if it still holds the blob that was re-sealed;
    /// with nothing to re-seal, the row must still not exist. Anything else
    /// means it was saved while the rotation ran, which aborts it. Called only
    /// from [`Database::apply_vault_rotation`] with fixed table names.
    async fn rotate_config_secret(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        table: &str,
        key: &str,
        resealed: Option<&(String, String)>,
    ) -> Result<()> {
        match resealed {
            Some((old, new)) => {
                let res = sqlx::query(&format!(
                    "UPDATE {table} SET value = ?, updated_at = ? WHERE key = ? AND value = ?"
                ))
                .bind(new)
                .bind(Utc::now().to_rfc3339())
                .bind(key)
                .bind(old)
                .execute(&mut **tx)
                .await?;
                if res.rows_affected() != 1 {
                    anyhow::bail!(VAULT_CHANGED_DURING_ROTATION);
                }
            }
            None => {
                let present: i64 =
                    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE key = ?"))
                        .bind(key)
                        .fetch_one(&mut **tx)
                        .await?;
                if present != 0 {
                    anyhow::bail!(VAULT_CHANGED_DURING_ROTATION);
                }
            }
        }
        Ok(())
    }

    // ── Category operations ───────────────────────────────────────────────

    /// All categories, ordered for tree display: roots first, then by sibling sort_index, then by name.
    pub fn list_categories(&self) -> Result<Vec<Category>> {
        #[cfg(test)]
        count_category_read(&self.db_path);
        block(async {
            let rows = sqlx::query(
                "SELECT id, name, parent_id, scope, color, sort_index, created_at, updated_at \
                 FROM categories \
                 ORDER BY CASE WHEN parent_id IS NULL THEN 0 ELSE 1 END, sort_index, name",
            )
            .fetch_all(&self.pool)
            .await?;
            Ok(rows.into_iter().map(Self::row_to_category).collect())
        })
    }

    pub fn get_category(&self, id: &str) -> Result<Option<Category>> {
        #[cfg(test)]
        count_category_read(&self.db_path);
        block(async {
            let row = sqlx::query(
                "SELECT id, name, parent_id, scope, color, sort_index, created_at, updated_at FROM categories WHERE id = ?"
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(Self::row_to_category))
        })
    }

    pub fn insert_category(&self, c: &Category) -> Result<()> {
        block(async {
            sqlx::query(
                "INSERT INTO categories (id, name, parent_id, scope, color, sort_index, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&c.id)
            .bind(&c.name)
            .bind(&c.parent_id)
            .bind(&c.scope)
            .bind(&c.color)
            .bind(c.sort_index)
            .bind(c.created_at.to_rfc3339())
            .bind(c.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Move category `id` under `parent` (`None`: the top level) and, when
    /// given, to position `sort_index` - those columns and `updated_at`, in
    /// ONE `BEGIN IMMEDIATE` transaction whose `check` sees every category as
    /// stored inside it and may refuse the move (`Err`, nothing written). The
    /// check and a whole-row write used to be separate steps: two moves at
    /// once (possible since `category_reparent` runs off the main thread)
    /// could each pass the check and together make a parent loop, and a
    /// rename made meanwhile was written back.
    ///
    /// A move to another parent changes the category path of everything
    /// filed in the category or below it, and that path travels in the
    /// Bitwarden items' notes: those keys and servers are marked changed in
    /// the same transaction ([`Self::mark_categories_changed`]). A new
    /// position under the same parent changes no path and marks nothing.
    pub fn move_category(
        &self,
        id: &str,
        parent: Option<&str>,
        sort_index: Option<i64>,
        check: impl FnOnce(&[Category]) -> Result<()>,
    ) -> Result<()> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let all = Self::categories_in(&mut tx).await?;
            check(&all)?;
            let new_parent = all
                .iter()
                .find(|c| c.id == id)
                .is_some_and(|c| c.parent_id.as_deref() != parent);
            let now = Utc::now();
            let res = sqlx::query(
                "UPDATE categories SET parent_id = ?, sort_index = COALESCE(?, sort_index), \
                 updated_at = ? WHERE id = ?",
            )
            .bind(parent)
            .bind(sort_index)
            .bind(now.to_rfc3339())
            .bind(id)
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() != 1 {
                anyhow::bail!("Category not found.");
            }
            if new_parent {
                Self::mark_categories_changed(
                    &mut tx,
                    &category_subtree(&all, id),
                    now.timestamp_millis(),
                )
                .await?;
            }
            tx.commit().await?;
            Ok(())
        })
    }

    /// Rename category `id` - the name and `updated_at`, nothing else - and
    /// mark the keys and servers filed in it or below it changed for the
    /// Bitwarden sync, in ONE `BEGIN IMMEDIATE` transaction. The rename used
    /// to write back the whole row it had read, which undid a move that
    /// committed meanwhile (moves run off the main thread), and it marked
    /// nothing: the items' notes kept the old path, and a pull filed the keys
    /// under it again. The same name again writes nothing. False when there
    /// is no such category.
    pub fn rename_category(&self, id: &str, name: &str) -> Result<bool> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let all = Self::categories_in(&mut tx).await?;
            let Some(current) = all.iter().find(|c| c.id == id) else {
                return Ok(false);
            };
            if current.name == name {
                return Ok(true);
            }
            let now = Utc::now();
            sqlx::query("UPDATE categories SET name = ?, updated_at = ? WHERE id = ?")
                .bind(name)
                .bind(now.to_rfc3339())
                .bind(id)
                .execute(&mut *tx)
                .await?;
            Self::mark_categories_changed(
                &mut tx,
                &category_subtree(&all, id),
                now.timestamp_millis(),
            )
            .await?;
            tx.commit().await?;
            Ok(true)
        })
    }

    /// Give the categories `ordered_ids` the positions 0, 1, 2, ... in that
    /// order (`sort_index` and `updated_at` only - never a parent), in ONE
    /// `BEGIN IMMEDIATE` transaction whose `check` sees every category as
    /// stored inside it and may refuse (`Err`, nothing written).
    pub fn set_category_order(
        &self,
        ordered_ids: &[String],
        check: impl FnOnce(&[Category]) -> Result<()>,
    ) -> Result<()> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let all = Self::categories_in(&mut tx).await?;
            check(&all)?;
            let now = Utc::now().to_rfc3339();
            for (position, id) in ordered_ids.iter().enumerate() {
                let res = sqlx::query(
                    "UPDATE categories SET sort_index = ?, updated_at = ? WHERE id = ?",
                )
                .bind(position as i64)
                .bind(&now)
                .bind(id)
                .execute(&mut *tx)
                .await?;
                if res.rows_affected() != 1 {
                    anyhow::bail!("That category no longer exists.");
                }
            }
            tx.commit().await?;
            Ok(())
        })
    }

    /// Every category, read inside `tx`.
    async fn categories_in(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<Vec<Category>> {
        let rows = sqlx::query(
            "SELECT id, name, parent_id, scope, color, sort_index, created_at, updated_at \
             FROM categories",
        )
        .fetch_all(&mut **tx)
        .await?;
        Ok(rows.into_iter().map(Self::row_to_category).collect())
    }

    /// Mark every key filed in one of `category_ids`, and every server in
    /// one, as having a new category path for the Bitwarden sync, at
    /// `now_ms` ([`Self::category_marks`]), in the caller's transaction:
    /// their category path, which the sync writes into the items' notes,
    /// changed. Not `updated_at`: that says the row itself changed, and made
    /// "local wins" upload every field of it - a saved password older than
    /// the one Bitwarden had - for a category rename.
    async fn mark_categories_changed(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        category_ids: &[String],
        now_ms: i64,
    ) -> Result<()> {
        let ids = serde_json::to_string(category_ids)?;
        sqlx::query(
            "INSERT OR REPLACE INTO sync_category_marks (kind, id, changed_at) \
             SELECT DISTINCT 'key', key_id, ? FROM key_categories \
             WHERE category_id IN (SELECT value FROM json_each(?))",
        )
        .bind(now_ms)
        .bind(&ids)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "INSERT OR REPLACE INTO sync_category_marks (kind, id, changed_at) \
             SELECT 'server', id, ? FROM servers \
             WHERE category_id IN (SELECT value FROM json_each(?))",
        )
        .bind(now_ms)
        .bind(&ids)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Mark key `id` as having a new category path for the Bitwarden sync
    /// ([`Self::category_marks`]): its categories were set.
    pub fn mark_key_categories_changed(&self, id: &str) -> Result<()> {
        block(async {
            sqlx::query(
                "INSERT OR REPLACE INTO sync_category_marks (kind, id, changed_at) \
                 VALUES ('key', ?, ?)",
            )
            .bind(id)
            .bind(Utc::now().timestamp_millis())
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// The rows of `kind` ("key" or "server") whose category path changed
    /// without the row changing, and when (epoch ms), until the Bitwarden
    /// sync has uploaded it ([`Self::clear_category_mark`]).
    pub fn category_marks(&self, kind: &str) -> Result<std::collections::HashMap<String, i64>> {
        block(async {
            let rows: Vec<(String, i64)> =
                sqlx::query_as("SELECT id, changed_at FROM sync_category_marks WHERE kind = ?")
                    .bind(kind)
                    .fetch_all(&self.pool)
                    .await?;
            Ok(rows.into_iter().collect())
        })
    }

    /// [`Self::category_marks`] for one row.
    pub fn category_mark(&self, kind: &str, id: &str) -> Result<Option<i64>> {
        block(async {
            Ok(sqlx::query_scalar(
                "SELECT changed_at FROM sync_category_marks WHERE kind = ? AND id = ?",
            )
            .bind(kind)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
        })
    }

    /// The new category path of `id`, marked at `up_to` or before, is
    /// uploaded: the mark goes - unless the path changed again since.
    pub fn clear_category_mark(&self, kind: &str, id: &str, up_to: i64) -> Result<()> {
        block(async {
            sqlx::query(
                "DELETE FROM sync_category_marks WHERE kind = ? AND id = ? AND changed_at <= ?",
            )
            .bind(kind)
            .bind(id)
            .bind(up_to)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Delete a category, in one transaction. Its children move up to the
    /// deleted node's parent (or become roots), and so do the servers filed
    /// under it - a host category's servers used to keep pointing at the
    /// deleted id, vanishing from every category view and failing to save
    /// until the next launch (A7-28 / A2-54). Its `key_categories` rows are
    /// removed. Returns the ids of the children that were re-parented - only
    /// those: this used to list every category under the parent, siblings
    /// included, and every root of both scopes for a root (A7-40 / A2-31).
    pub fn delete_category(&self, id: &str) -> Result<Vec<String>> {
        block(async {
            // BEGIN IMMEDIATE: reads the parent and the children, then writes;
            // a deferred transaction was refused at once while another
            // connection was writing, instead of waiting.
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let parent: Option<String> =
                sqlx::query_scalar("SELECT parent_id FROM categories WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .flatten();
            let children: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM categories WHERE parent_id = ? ORDER BY sort_index, name",
            )
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
            // Everything filed in the category or below it gets a new
            // category path - the keys losing this category, the servers
            // moved up, the items of the children moved up - which the
            // Bitwarden sync uploads (categories travel in the items' notes,
            // A7-23): marked, before anything is moved. A rename or a move
            // marks what is under the category the same way
            // (`rename_category`, `move_category`).
            let all = Self::categories_in(&mut tx).await?;
            Self::mark_categories_changed(
                &mut tx,
                &category_subtree(&all, id),
                Utc::now().timestamp_millis(),
            )
            .await?;
            sqlx::query("UPDATE categories SET parent_id = ? WHERE parent_id = ?")
                .bind(&parent)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            // A host category's parent is a host category (create/reparent
            // enforce the scope), so the servers stay correctly filed.
            sqlx::query("UPDATE servers SET category_id = ? WHERE category_id = ?")
                .bind(&parent)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM key_categories WHERE category_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM categories WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(children)
        })
    }

    /// Atomically replace the category set for a key. Empty slice = remove all.
    pub fn set_key_categories(&self, key_id: &str, category_ids: &[String]) -> Result<()> {
        block(async {
            let mut tx = self.pool.begin().await?;
            sqlx::query("DELETE FROM key_categories WHERE key_id = ?")
                .bind(key_id)
                .execute(&mut *tx)
                .await?;
            for cat_id in category_ids {
                sqlx::query(
                    "INSERT OR IGNORE INTO key_categories (key_id, category_id) VALUES (?, ?)",
                )
                .bind(key_id)
                .bind(cat_id)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(())
        })
    }

    /// Returns category IDs the given key belongs to.
    pub fn list_categories_for_key(&self, key_id: &str) -> Result<Vec<String>> {
        block(async {
            let rows: Vec<Option<String>> =
                sqlx::query_scalar("SELECT category_id FROM key_categories WHERE key_id = ?")
                    .bind(key_id)
                    .fetch_all(&self.pool)
                    .await?;
            Ok(rows.into_iter().flatten().collect())
        })
    }

    /// Full key_id -> [category_id] map. Used by `category_list` IPC and the
    /// renderer's bulk cache.
    pub fn all_key_categories(&self) -> Result<HashMap<String, Vec<String>>> {
        block(async {
            let rows: Vec<(String, Option<String>)> =
                sqlx::query_as("SELECT key_id, category_id FROM key_categories")
                    .fetch_all(&self.pool)
                    .await?;
            let mut out: HashMap<String, Vec<String>> = HashMap::new();
            for (k, c) in rows {
                if let Some(cat) = c {
                    out.entry(k).or_default().push(cat);
                }
            }
            Ok(out)
        })
    }

    /// Atomically assign categories on key insert (used by `key_create_with_categories`).
    pub fn insert_key_with_categories(
        &self,
        key: &KeyRecord,
        category_ids: &[String],
    ) -> Result<()> {
        block(async {
            let mut tx = self.pool.begin().await?;
            sqlx::query(
                r#"
                INSERT INTO keys (id, name, key_type, public_key, private_key_encrypted,
                                  fingerprint_sha256, fingerprint_md5, comment, created_at, updated_at,
                                  deployed, deploy_path, bitwarden_id, bitwarden_sync,
                                  bitwarden_revision_ts, bitwarden_updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&key.id)
            .bind(&key.name)
            .bind(&key.key_type)
            .bind(&key.public_key)
            .bind(&key.private_key_encrypted)
            .bind(&key.fingerprint_sha256)
            .bind(&key.fingerprint_md5)
            .bind(&key.comment)
            .bind(key.created_at.to_rfc3339())
            .bind(key.updated_at.to_rfc3339())
            .bind(key.deployed as i64)
            .bind(&key.deploy_path)
            .bind(&key.bitwarden_id)
            .bind(key.bitwarden_sync as i64)
            .bind(key.bitwarden_revision_ts.map(|v| v.to_string()))
            .bind(key.bitwarden_updated_at.map(|v| v.to_string()))
            .execute(&mut *tx)
            .await?;
            for cat_id in category_ids {
                sqlx::query(
                    "INSERT OR IGNORE INTO key_categories (key_id, category_id) VALUES (?, ?)",
                )
                .bind(&key.id)
                .bind(cat_id)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(())
        })
    }

    /// All keys, with their category IDs populated. Single bulk query path so
    /// the renderer doesn't have to fan out N+1 calls.
    pub fn list_keys_with_categories(&self) -> Result<Vec<KeyRecord>> {
        block(async {
            let rows = sqlx::query(concat!(
                "SELECT ",
                key_columns!(),
                " FROM keys ORDER BY created_at DESC"
            ))
            .fetch_all(&self.pool)
            .await?;
            let mut keys: Vec<KeyRecord> = rows.into_iter().map(Self::row_to_key).collect();
            let kc_map = self.all_key_categories_inner(&self.pool).await?;
            for k in keys.iter_mut() {
                if let Some(ids) = kc_map.get(&k.id) {
                    k.category_ids = ids.clone();
                }
            }
            Ok(keys)
        })
    }

    pub fn get_key_with_categories(&self, id: &str) -> Result<Option<KeyRecord>> {
        block(async {
            let row = sqlx::query(concat!(
                "SELECT ",
                key_columns!(),
                " FROM keys WHERE id = ?"
            ))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
            let Some(row) = row else {
                return Ok(None);
            };
            let mut k = Self::row_to_key(row);
            let kc_map = self.all_key_categories_inner(&self.pool).await?;
            if let Some(ids) = kc_map.get(&k.id) {
                k.category_ids = ids.clone();
            }
            Ok(Some(k))
        })
    }

    async fn all_key_categories_inner(
        &self,
        pool: &SqlitePool,
    ) -> Result<HashMap<String, Vec<String>>> {
        let rows: Vec<(String, Option<String>)> =
            sqlx::query_as("SELECT key_id, category_id FROM key_categories")
                .fetch_all(pool)
                .await?;
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        for (k, c) in rows {
            if let Some(cat) = c {
                out.entry(k).or_default().push(cat);
            }
        }
        Ok(out)
    }

    fn row_to_category(row: SqliteRow) -> Category {
        Category {
            id: row.get("id"),
            name: row.get("name"),
            parent_id: row.get("parent_id"),
            scope: row.try_get("scope").unwrap_or_else(|_| "key".to_string()),
            color: row.get("color"),
            sort_index: row.get::<i64, _>("sort_index"),
            created_at: DateTime::parse_from_rfc3339(row.get::<String, _>("created_at").as_str())
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(row.get::<String, _>("updated_at").as_str())
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now()),
        }
    }

    /// The slash-joined path of category `id`, top first - the path the
    /// Bitwarden sync writes into an item's notes. Bounded by
    /// [`category_chain`]: on a parent loop (a restored vault can hold one)
    /// it is the categories walked, each once. Empty when `id` does not
    /// exist or the categories cannot be read.
    pub fn category_path_string(&self, id: &str) -> String {
        let all = match self.list_categories() {
            Ok(all) => all,
            Err(e) => {
                log::warn!("[sshspan-db] could not read the categories for a path: {e}");
                return String::new();
            }
        };
        path_in(&parent_map(&all), &name_map(&all), id)
    }

    /// Ensure a category chain of `scope` for the given slash-joined path
    /// exists locally. Returns the leaf category's id. If a node along the
    /// path is missing, it is created with a deterministic id derived from
    /// the path so re-imports converge to the same uuid.
    pub fn ensure_category_path_scoped(&self, path: &str, scope: &str) -> Result<Option<String>> {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return Ok(None);
        }
        // Compute a deterministic id for the *root* based on its segment so
        // re-imports of the same root converge.
        let mut current_parent: Option<String> = None;
        let mut full_path = String::new();
        let mut last_id: Option<String> = None;
        for seg in segments {
            if !full_path.is_empty() {
                full_path.push('/');
            }
            full_path.push_str(seg);
            // Search for a sibling with this parent_id and name.
            let existing: Option<Category> = {
                let rows = self.list_categories()?;
                rows.into_iter()
                    .find(|c| c.name == seg && c.parent_id == current_parent && c.scope == scope)
            };
            if let Some(c) = existing {
                let cid = c.id.clone();
                last_id = Some(cid.clone());
                current_parent = Some(cid);
            } else {
                // Create a new node with a deterministic id from the full path.
                let id = format!("path-{:x}", short_hash(&format!("{scope}/{full_path}")));
                let now = Utc::now();
                let max_si = self
                    .list_categories()?
                    .into_iter()
                    .filter(|c| c.parent_id == current_parent && c.scope == scope)
                    .map(|c| c.sort_index)
                    .max()
                    .unwrap_or(-1);
                let cat = Category {
                    id: id.clone(),
                    name: seg.to_string(),
                    parent_id: current_parent.clone(),
                    scope: scope.to_string(),
                    color: None,
                    sort_index: max_si + 1,
                    created_at: now,
                    updated_at: now,
                };
                self.insert_category(&cat)?;
                last_id = Some(id);
                current_parent = last_id.clone();
            }
        }
        Ok(last_id)
    }

    // ── Server (Connect) operations ────────────────────────────────────────

    fn row_to_server(row: SqliteRow) -> ServerRecord {
        let parse_ts = |s: Option<String>| {
            s.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|d| d.with_timezone(&Utc))
        };
        ServerRecord {
            id: row.get("id"),
            name: row.get("name"),
            host: row.get("host"),
            port: row.get::<i64, _>("port") as u16,
            username: row.get("username"),
            key_id: row.get("key_id"),
            pem_path: row.get("pem_path"),
            auth_method: row.get("auth_method"),
            saved_password: row.get("saved_password"),
            category_id: row.get("category_id"),
            color: row.get("color"),
            last_connected_at: parse_ts(row.get("last_connected_at")),
            created_at: DateTime::parse_from_rfc3339(row.get::<String, _>("created_at").as_str())
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(row.get::<String, _>("updated_at").as_str())
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now()),
            bitwarden_id: row.get("bitwarden_id"),
            bitwarden_revision_ts: row.get("bitwarden_revision_ts"),
            bitwarden_updated_at: row.get("bitwarden_updated_at"),
        }
    }

    pub fn insert_server(&self, s: &ServerRecord) -> Result<()> {
        block(async {
            sqlx::query(
                r#"
                INSERT INTO servers (id, name, host, port, username, key_id, pem_path, auth_method,
                                     saved_password, category_id, color, last_connected_at, created_at, updated_at,
                                     bitwarden_id, bitwarden_revision_ts, bitwarden_updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&s.id).bind(&s.name).bind(&s.host).bind(s.port as i64)
            .bind(&s.username).bind(&s.key_id).bind(&s.pem_path).bind(&s.auth_method)
            .bind(&s.saved_password).bind(&s.category_id).bind(&s.color)
            .bind(s.last_connected_at.map(|d| d.to_rfc3339()))
            .bind(s.created_at.to_rfc3339()).bind(s.updated_at.to_rfc3339())
            .bind(&s.bitwarden_id).bind(&s.bitwarden_revision_ts).bind(&s.bitwarden_updated_at)
            .execute(&self.pool).await?;
            Ok(())
        })
    }

    pub fn update_server(&self, s: &ServerRecord) -> Result<()> {
        block(async { Self::write_server_row(&self.pool, s).await })
    }

    /// Read server `id`, let `update` change it - or refuse it (`Err`:
    /// nothing written) - and write the whole row back, in ONE
    /// `BEGIN IMMEDIATE` transaction: another writer makes this one wait, and
    /// `update` checks the row exactly as it is written. A save used to check
    /// the row it had read before such a writer committed, then wrote over
    /// it. `Ok(None)` when there is no such server. `update` runs while the
    /// write lock is held: it must be quick (seal a password before).
    pub fn modify_server<T>(
        &self,
        id: &str,
        update: impl FnOnce(&mut ServerRecord) -> Result<T>,
    ) -> Result<Option<(ServerRecord, T)>> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let row = sqlx::query(concat!(
                "SELECT ",
                server_columns!(),
                " FROM servers WHERE id = ?"
            ))
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else {
                return Ok(None);
            };
            let mut server = Self::row_to_server(row);
            let out = update(&mut server)?;
            Self::write_server_row(&mut *tx, &server).await?;
            tx.commit().await?;
            Ok(Some((server, out)))
        })
    }

    /// The UPDATE of a whole server row.
    async fn write_server_row<'c, E>(executor: E, s: &ServerRecord) -> Result<()>
    where
        E: sqlx::Executor<'c, Database = sqlx::Sqlite>,
    {
        sqlx::query(
            r#"
            UPDATE servers SET name = ?, host = ?, port = ?, username = ?, key_id = ?, pem_path = ?,
                auth_method = ?, saved_password = ?, category_id = ?, color = ?, last_connected_at = ?, updated_at = ?,
                bitwarden_id = ?, bitwarden_revision_ts = ?, bitwarden_updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&s.name).bind(&s.host).bind(s.port as i64).bind(&s.username)
        .bind(&s.key_id).bind(&s.pem_path).bind(&s.auth_method).bind(&s.saved_password)
        .bind(&s.category_id).bind(&s.color)
        .bind(s.last_connected_at.map(|d| d.to_rfc3339()))
        .bind(s.updated_at.to_rfc3339())
        .bind(&s.bitwarden_id).bind(&s.bitwarden_revision_ts).bind(&s.bitwarden_updated_at)
        .bind(&s.id)
        .execute(executor).await?;
        Ok(())
    }

    pub fn delete_server(&self, id: &str) -> Result<()> {
        block(async {
            sqlx::query("DELETE FROM servers WHERE id = ?")
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    /// Atomically persist a full vault password rotation.
    ///
    /// Re-encryption happens in memory in the caller; this writes the results.
    /// Previously each key/server UPDATE was its own
    /// pool-backed statement and the master verifier was a third write, so an
    /// I/O error or a crash part-way left some rows sealed under the new
    /// password and the rest (plus the verifier) under the old - a vault that
    /// unlocks but cannot decrypt half its contents. And the Bitwarden master
    /// password was never re-sealed at all, stranding sync on the old
    /// password. Here every re-sealed record AND the verifier commit inside a
    /// single SQLite transaction: the database holds either the complete old
    /// state or the complete new state, never a split.
    ///
    /// Each statement writes ONLY the sealed value, and only where the row
    /// still holds the blob the caller re-sealed. The commit used to
    /// rewrite every column of every key and server it had read and upsert
    /// every MCP record whole, so an edit made while the re-seal ran was
    /// silently reverted - and a record sealed with the old password in the
    /// meantime stayed behind, unreadable. Now a row that changed, vanished or
    /// appeared since the snapshot - a sealed key, server password, MCP secret
    /// or credential the caller did not re-seal - rolls the whole rotation
    /// back with [`VAULT_CHANGED_DURING_ROTATION`]: the old password keeps
    /// opening everything and the user simply tries again. (The commands that
    /// write sealed data are also locked out while a rotation runs; this is
    /// the backstop.)
    ///
    /// `BEGIN IMMEDIATE`: the transaction reads (which rows hold sealed
    /// values) between its writes - on a vault without keys it read first -
    /// and a deferred transaction was refused at once ("database is locked")
    /// while another connection was writing.
    pub fn apply_vault_rotation(&self, rotation: &VaultRotation) -> Result<()> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            for key in &rotation.keys {
                let res = sqlx::query(
                    "UPDATE keys SET private_key_encrypted = ? \
                     WHERE id = ? AND private_key_encrypted = ?",
                )
                .bind(&key.new)
                .bind(&key.id)
                .bind(&key.old)
                .execute(&mut *tx)
                .await?;
                if res.rows_affected() != 1 {
                    anyhow::bail!(VAULT_CHANGED_DURING_ROTATION);
                }
            }
            let key_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM keys")
                .fetch_all(&mut *tx)
                .await?;
            ensure_all_resealed(&key_ids, &rotation.keys)?;

            for server in &rotation.server_passwords {
                let res = sqlx::query(
                    "UPDATE servers SET saved_password = ? WHERE id = ? AND saved_password = ?",
                )
                .bind(&server.new)
                .bind(&server.id)
                .bind(&server.old)
                .execute(&mut *tx)
                .await?;
                if res.rows_affected() != 1 {
                    anyhow::bail!(VAULT_CHANGED_DURING_ROTATION);
                }
            }
            let sealed_servers: Vec<String> =
                sqlx::query_scalar("SELECT id FROM servers WHERE saved_password IS NOT NULL")
                    .fetch_all(&mut *tx)
                    .await?;
            ensure_all_resealed(&sealed_servers, &rotation.server_passwords)?;

            // MCP server auth secrets are sealed with the same vault password
            // and must rotate in the same transaction, or every MCP call
            // fails at unseal after the change. The caller re-seals in memory
            // first; an unsealable blob aborts the whole rotation there.
            Self::rotate_mcp_secrets(&mut tx, &rotation.mcp_secrets).await?;
            // The Bitwarden master password is sealed with the SAME vault
            // password; it must rotate in the same transaction or sync is
            // stranded on the old password. Same for the AI assistant's
            // API key: every assistant call would fail at unseal.
            Self::rotate_config_secret(
                &mut tx,
                "bitwarden_config",
                "master_password",
                rotation.bitwarden_master_password.as_ref(),
            )
            .await?;
            Self::rotate_config_secret(
                &mut tx,
                "assistant_config",
                "api_key",
                rotation.assistant_api_key.as_ref(),
            )
            .await?;
            // The verifier rotates last, inside the same transaction: if any
            // earlier statement failed, the whole rotation rolls back and the
            // old password keeps working against untouched rows.
            sqlx::query(
                "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind("master.hash")
            .bind(&rotation.master_hash)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    /// Stamp `last_connected_at` and nothing else. The SSH connect path
    /// used to write back the whole server row it had read before the
    /// handshake, so a master-password change that committed meanwhile had
    /// its re-sealed `saved_password` overwritten with the old blob.
    pub fn touch_server_last_connected(&self, id: &str, at: DateTime<Utc>) -> Result<()> {
        block(async {
            sqlx::query("UPDATE servers SET last_connected_at = ? WHERE id = ?")
                .bind(at.to_rfc3339())
                .bind(id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    /// Record a Bitwarden link on a server row: its item id, the remote
    /// revision and the sync marker - nothing else, so an edit made while the
    /// upload ran is neither reverted nor lost to the next sync (A7-23). The
    /// marker is the pushed row's `updated_at`, or `None`
    /// when the row's state was never uploaded to this item (a re-link found
    /// through the item's notes): the next sync then sees the row as changed
    /// and uploads it.
    pub fn set_server_sync_meta(
        &self,
        id: &str,
        bitwarden_id: &str,
        revision_date: Option<&str>,
        synced_marker: Option<&str>,
    ) -> Result<()> {
        block(async {
            sqlx::query(
                "UPDATE servers SET bitwarden_id = ?, bitwarden_revision_ts = ?, \
                 bitwarden_updated_at = ? WHERE id = ?",
            )
            .bind(bitwarden_id)
            .bind(revision_date)
            .bind(synced_marker)
            .bind(id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Write a server pulled from Bitwarden into its row: what the Login item
    /// carries, the remote revision and the sync marks. The `.pem` path,
    /// colour, last connection and the link stay as the row has them.
    /// Like [`Database::apply_pulled_key`], only while the row is still the
    /// one the sync read; false otherwise.
    pub fn apply_pulled_server(
        &self,
        id: &str,
        pulled: &ServerPull,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        block(async {
            // BEGIN IMMEDIATE: read, then write - see apply_pulled_key.
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let stored: Option<String> =
                sqlx::query_scalar("SELECT updated_at FROM servers WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await?;
            let Some(stored) = stored.filter(|s| same_instant(s, expected_updated_at)) else {
                return Ok(false);
            };
            let res = sqlx::query(
                "UPDATE servers SET name = ?, host = ?, port = ?, username = ?, auth_method = ?, \
                 key_id = ?, category_id = ?, saved_password = ?, updated_at = ?, \
                 bitwarden_revision_ts = ?, bitwarden_updated_at = ? WHERE id = ? AND updated_at = ?",
            )
            .bind(&pulled.name)
            .bind(&pulled.host)
            .bind(pulled.port as i64)
            .bind(&pulled.username)
            .bind(&pulled.auth_method)
            .bind(&pulled.key_id)
            .bind(&pulled.category_id)
            .bind(&pulled.saved_password)
            .bind(&now)
            .bind(&pulled.bitwarden_revision_ts)
            .bind(&now)
            .bind(id)
            .bind(&stored)
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() != 1 {
                return Ok(false);
            }
            tx.commit().await?;
            Ok(true)
        })
    }

    pub fn get_server(&self, id: &str) -> Result<Option<ServerRecord>> {
        block(async {
            let row = sqlx::query(concat!(
                "SELECT ",
                server_columns!(),
                " FROM servers WHERE id = ?"
            ))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| Self::row_to_server(r)))
        })
    }

    pub fn list_servers(&self) -> Result<Vec<ServerRecord>> {
        block(async {
            let rows = sqlx::query(concat!(
                "SELECT ",
                server_columns!(),
                " FROM servers ORDER BY name COLLATE NOCASE ASC"
            ))
            .fetch_all(&self.pool)
            .await?;
            Ok(rows.into_iter().map(|r| Self::row_to_server(r)).collect())
        })
    }

    pub fn get_key_name(&self, key_id: &str) -> Result<Option<(String, String)>> {
        block(async {
            let row = sqlx::query("SELECT name, key_type FROM keys WHERE id = ?")
                .bind(key_id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(match row {
                Some(r) => Some((r.get::<String, _>("name"), r.get::<String, _>("key_type"))),
                None => None,
            })
        })
    }

    // ── Known hosts (host-key TOFU) ────────────────────────────────────────

    fn row_to_known_host(row: SqliteRow) -> KnownHost {
        let host_key: String = row.get("host_key");
        let stored: String = row.get("fingerprint_sha256");
        KnownHost {
            host: row.get("host"),
            // Always the current form, also for a row the migration has not
            // rewritten (yet).
            fingerprint_sha256: crate::ssh_client::known_host_fingerprint(&host_key, &stored),
            host_key,
            first_seen: DateTime::parse_from_rfc3339(row.get::<String, _>("first_seen").as_str())
                .ok()
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|| Utc::now()),
            // A pin whose origin cannot be read is treated as unconfirmed:
            // the user re-confirms it, it is never silently trusted.
            source: row
                .try_get::<String, _>("source")
                .unwrap_or_else(|_| "imported".to_string()),
        }
    }

    /// Once per database (the `config` row [`BITWARDEN_DESTINATION_MIGRATED`]
    /// records it): sync settings stored before destinations had to be
    /// allowed keep syncing - their destination counts as allowed - so an
    /// upgrade asks nothing. After this ran, nothing counts as allowed unless
    /// a question allowed it: a destination saved later without an allowed
    /// one stays off even if its `confirmed_destination` row is missing. A
    /// backup restore writes only `setting.*` and bookmark rows to `config`,
    /// so it can never undo the record of this run.
    async fn migrate_bitwarden_destination(&self) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let done: Option<String> = sqlx::query_scalar("SELECT value FROM config WHERE key = ?")
            .bind(BITWARDEN_DESTINATION_MIGRATED)
            .fetch_optional(&mut *tx)
            .await?;
        if done.is_none() {
            let rows: Vec<(String, String)> =
                sqlx::query_as("SELECT key, value FROM bitwarden_config")
                    .fetch_all(&mut *tx)
                    .await?;
            let mut config = bitwarden_config_from_rows(rows);
            if config.confirmed_destination.is_none() {
                if let Some(destination) = config.destination() {
                    config.confirmed_destination = Some(destination);
                    write_bitwarden_config(&mut tx, &config).await?;
                }
            }
            sqlx::query(
                "INSERT INTO config (key, value, updated_at) VALUES (?, 'done', ?) \
                 ON CONFLICT(key) DO NOTHING",
            )
            .bind(BITWARDEN_DESTINATION_MIGRATED)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Rewrite every stored host-key fingerprint to the current form (see the
    /// call in `migrate()`). Idempotent: a second run finds nothing to change.
    /// The rows are read inside the (`BEGIN IMMEDIATE`) transaction that
    /// rewrites them: read outside it, a pin replaced in between got the
    /// fingerprint of the key it replaced.
    async fn migrate_known_host_fingerprints(&self) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT host, host_key, fingerprint_sha256 FROM known_hosts")
                .fetch_all(&mut *tx)
                .await?;
        for (host, host_key, stored) in rows {
            let current = crate::ssh_client::known_host_fingerprint(&host_key, &stored);
            if current != stored {
                sqlx::query("UPDATE known_hosts SET fingerprint_sha256 = ? WHERE host = ?")
                    .bind(&current)
                    .bind(&host)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Port-qualify legacy bare-host `known_hosts` rows to "host:22".
    ///
    /// Runs inside `migrate()`. Explicit and per-row so that one bad row
    /// cannot silently take the rest of the pins with it - see the call site
    /// for why a lost pin is a security downgrade rather than cosmetic.
    ///
    /// Rules:
    /// * A row already carrying an explicit ":port" suffix is left alone.
    /// * A bare IPv6 literal is bracketed as well as port-qualified, so it
    ///   becomes "[2001:db8::1]:22" - distinguishable from a bare hostname and
    ///   stable under a second run.
    /// * If the destination key is already taken, the legacy row is dropped
    ///   rather than colliding: the existing qualified row is the newer, more
    ///   specific pin, and keeping the orphan would only confuse a later run.
    /// * Idempotent: a second call finds nothing left to do.
    /// * One `BEGIN IMMEDIATE` transaction, the rows read inside it: it checks
    ///   whether a name is taken before it writes, and a deferred transaction
    ///   was refused at once ("database is locked") while another connection
    ///   was writing.
    async fn migrate_known_hosts_port_qualify(&self) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows: Vec<String> = sqlx::query_scalar::<_, String>("SELECT host FROM known_hosts")
            .fetch_all(&mut *tx)
            .await?;
        for old in rows {
            let Some(new) = qualify_legacy_known_host(&old) else {
                continue; // already qualified
            };
            let taken =
                sqlx::query_scalar::<_, String>("SELECT host FROM known_hosts WHERE host = ?")
                    .bind(&new)
                    .fetch_optional(&mut *tx)
                    .await?
                    .is_some();
            if taken {
                sqlx::query("DELETE FROM known_hosts WHERE host = ?")
                    .bind(&old)
                    .execute(&mut *tx)
                    .await?;
                continue;
            }
            sqlx::query("UPDATE known_hosts SET host = ? WHERE host = ?")
                .bind(&new)
                .bind(&old)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Insert a newly-seen host key. Returns false if the host already exists
    /// with a DIFFERENT key (the caller should treat that as a mismatch).
    ///
    /// The check and the insert are one `BEGIN IMMEDIATE` transaction: as two
    /// statements, two first connections to one new host both saw no pin and
    /// the second failed its insert on the primary key instead of comparing
    /// the keys.
    pub fn add_known_host(&self, host: &str, host_key: &str, fingerprint: &str) -> Result<bool> {
        block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let existing =
                sqlx::query_scalar::<_, String>("SELECT host_key FROM known_hosts WHERE host = ?")
                    .bind(host)
                    .fetch_optional(&mut *tx)
                    .await?;
            match existing {
                Some(current) => Ok(current == host_key),
                None => {
                    sqlx::query(
                        "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen, source) VALUES (?, ?, ?, ?, 'connection')"
                    )
                    .bind(host).bind(host_key).bind(fingerprint).bind(chrono::Utc::now().to_rfc3339())
                    .execute(&mut *tx).await?;
                    tx.commit().await?;
                    Ok(true)
                }
            }
        })
    }

    /// Upgrade a pin that was imported from a backup to a confirmed
    /// first-use pin. Only succeeds for rows still marked `imported` whose
    /// stored key equals the presented one - a differing key is a mismatch
    /// the caller must hard-fail on, never upgrade.
    pub fn confirm_imported_known_host(&self, host: &str, presented_key: &str) -> Result<bool> {
        block(async {
            let result = sqlx::query(
                "UPDATE known_hosts SET source = 'connection' \
                 WHERE host = ? AND source = 'imported' AND host_key = ?",
            )
            .bind(host)
            .bind(presented_key)
            .execute(&self.pool)
            .await?;
            Ok(result.rows_affected() > 0)
        })
    }

    /// Returns the stored host-key blob for a host, if any.
    pub fn get_known_host(&self, host: &str) -> Result<Option<KnownHost>> {
        block(async {
            let row = sqlx::query(concat!(
                "SELECT ",
                known_host_columns!(),
                " FROM known_hosts WHERE host = ?"
            ))
            .bind(host)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.map(|r| Self::row_to_known_host(r)))
        })
    }

    pub fn list_known_hosts(&self) -> Result<Vec<KnownHost>> {
        block(async {
            let rows = sqlx::query(concat!(
                "SELECT ",
                known_host_columns!(),
                " FROM known_hosts ORDER BY host COLLATE NOCASE ASC"
            ))
            .fetch_all(&self.pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| Self::row_to_known_host(r))
                .collect())
        })
    }

    pub fn delete_known_host(&self, host: &str) -> Result<()> {
        block(async {
            sqlx::query("DELETE FROM known_hosts WHERE host = ?")
                .bind(host)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    // ── Transfer queue persistence ─────────────────────────────────────────
    // See `sftp::queue` for the in-memory `TransferJob` these rows mirror.
    // Best-effort throughout by convention at the call site (queue.rs logs
    // and swallows a failure here rather than letting it affect a live
    // transfer) - this table is a resiliency feature, not the source of
    // truth for a running app.

    /// Insert or fully overwrite one job's persisted row.
    pub fn upsert_queue_job(&self, row: &QueueJobRow) -> Result<()> {
        block(async {
            sqlx::query(
                r#"
                INSERT INTO transfer_queue (
                    id, kind, session_id, server_name, local_path, remote_path,
                    size, bytes_done, state, error, resume, preserve_ts,
                    target_session_id, target_server_name, target_remote_path,
                    attempts, verify, updated_at, server_id, target_server_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    kind = excluded.kind,
                    session_id = excluded.session_id,
                    server_name = excluded.server_name,
                    local_path = excluded.local_path,
                    remote_path = excluded.remote_path,
                    size = excluded.size,
                    bytes_done = excluded.bytes_done,
                    state = excluded.state,
                    error = excluded.error,
                    resume = excluded.resume,
                    preserve_ts = excluded.preserve_ts,
                    target_session_id = excluded.target_session_id,
                    target_server_name = excluded.target_server_name,
                    target_remote_path = excluded.target_remote_path,
                    attempts = excluded.attempts,
                    verify = excluded.verify,
                    updated_at = excluded.updated_at,
                    server_id = excluded.server_id,
                    target_server_id = excluded.target_server_id
                "#,
            )
            .bind(row.id)
            .bind(&row.kind)
            .bind(&row.session_id)
            .bind(&row.server_name)
            .bind(&row.local_path)
            .bind(&row.remote_path)
            .bind(row.size)
            .bind(row.bytes_done)
            .bind(&row.state)
            .bind(&row.error)
            .bind(&row.resume)
            .bind(row.preserve_ts.map(|b| b as i64))
            .bind(&row.target_session_id)
            .bind(&row.target_server_name)
            .bind(&row.target_remote_path)
            .bind(row.attempts)
            .bind(row.verify.map(|b| b as i64))
            .bind(Utc::now().to_rfc3339())
            .bind(&row.server_id)
            .bind(&row.target_server_id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Delete every Done/Failed/Cancelled row (mirrors `clear_finished`'s
    /// in-memory retain).
    pub fn delete_finished_queue_jobs(&self) -> Result<()> {
        block(async {
            sqlx::query(
                "DELETE FROM transfer_queue WHERE state IN ('done', 'failed', 'cancelled')",
            )
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    /// Jobs left `Queued`/`Active`/`Paused` by a previous run - what
    /// `sftp::queue::restore_pending` reloads at startup.
    ///
    /// The columns are NAMED rather than `SELECT *`: a pooled connection that
    /// loaded the schema before `migrate()` added the `server_id` columns would
    /// otherwise prepare `*` against its stale 18-column view, and sqlx caches
    /// that column count - then panics building the first 20-column row (seen
    /// in the migration test). A named column missing from a stale schema
    /// instead makes SQLite notice the change and re-prepare.
    pub fn list_pending_queue_jobs(&self) -> Result<Vec<QueueJobRow>> {
        block(async {
            let rows = sqlx::query(
                "SELECT id, kind, session_id, server_name, local_path, remote_path, size, \
                 bytes_done, state, error, resume, preserve_ts, target_session_id, \
                 target_server_name, target_remote_path, attempts, verify, server_id, \
                 target_server_id \
                 FROM transfer_queue WHERE state IN ('queued', 'active', 'paused') \
                 ORDER BY id ASC",
            )
            .fetch_all(&self.pool)
            .await?;
            Ok(rows.into_iter().map(Self::row_to_queue_job).collect())
        })
    }

    fn row_to_queue_job(row: SqliteRow) -> QueueJobRow {
        QueueJobRow {
            id: row.get("id"),
            kind: row.get("kind"),
            session_id: row.get("session_id"),
            server_name: row.get("server_name"),
            local_path: row.get("local_path"),
            remote_path: row.get("remote_path"),
            size: row.get("size"),
            bytes_done: row.get("bytes_done"),
            state: row.get("state"),
            error: row.get("error"),
            resume: row.get("resume"),
            preserve_ts: row.get::<Option<i64>, _>("preserve_ts").map(|v| v != 0),
            target_session_id: row.get("target_session_id"),
            target_server_name: row.get("target_server_name"),
            target_remote_path: row.get("target_remote_path"),
            attempts: row.get("attempts"),
            verify: row.get::<Option<i64>, _>("verify").map(|v| v != 0),
            server_id: row.get("server_id"),
            target_server_id: row.get("target_server_id"),
        }
    }

    // ── Backup / restore ───────────────────────────────────────────────────

    /// Upsert every entity from an (already unsealed) backup payload in one
    /// transaction. Existing rows with the same id/host are overwritten -
    /// re-running a restore is safe. Returns per-entity row counts.
    ///
    /// The audit rows for sanitized key names are written only after the
    /// commit (A7-25). They used to go through `add_audit` from inside the
    /// transaction, i.e. through a second pooled connection while this one
    /// held SQLite's write lock: each rename after the first write waited out
    /// the 5 s busy timeout, failed with "database is locked", and the row was
    /// dropped.
    ///
    /// `BEGIN IMMEDIATE`: the restore reads (category and known-host checks)
    /// between its writes - a payload whose first entry is such a check read
    /// first - and a deferred transaction was refused at once ("database is
    /// locked") while another connection was writing.
    pub fn restore_backup(&self, data: &serde_json::Value) -> Result<serde_json::Value> {
        let (counts, renamed) = block(async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let (mut keys_n, mut cats_n, mut kc_n) = (0u32, 0u32, 0u32);
            let (mut servers_n, mut hosts_n, mut settings_n) = (0u32, 0u32, 0u32);
            let mut renamed: Vec<(String, String)> = Vec::new();

            if let Some(arr) = data.get("categories").and_then(|v| v.as_array()) {
                for c in arr {
                    let Some(id) = c
                        .get("id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("imported");
                    let parent = c.get("parent_id").and_then(|v| v.as_str());
                    let scope = c.get("scope").and_then(|v| v.as_str()).unwrap_or("key");
                    let scope = if scope == "host" { "host" } else { "key" };
                    let color = c.get("color").and_then(|v| v.as_str());
                    let sort = c.get("sort_index").and_then(|v| v.as_i64()).unwrap_or(0);
                    let created = c.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
                    let updated = c
                        .get("updated_at")
                        .and_then(|v| v.as_str())
                        .unwrap_or(created);
                    sqlx::query(
                        "INSERT INTO categories (id, name, parent_id, scope, color, sort_index, created_at, updated_at) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                         ON CONFLICT(id) DO UPDATE SET name=excluded.name, parent_id=excluded.parent_id, scope=excluded.scope, \
                           color=excluded.color, sort_index=excluded.sort_index, updated_at=excluded.updated_at",
                    )
                    .bind(id).bind(name).bind(parent).bind(scope).bind(color).bind(sort).bind(created).bind(updated)
                    .execute(&mut *tx).await?;
                    cats_n += 1;
                }
            }

            if let Some(arr) = data.get("keys").and_then(|v| v.as_array()) {
                for k in arr {
                    let Some(id) = k
                        .get("id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    let s = |f: &str| k.get(f).and_then(|v| v.as_str());
                    // Names become Host aliases in ~/.ssh/config - restore
                    // payloads (possibly from older vaults or other sources)
                    // are sanitized rather than rejecting the whole restore.
                    let raw_name = s("name").unwrap_or("imported");
                    let name = if crate::crypto::keys::validate_key_name(raw_name).is_ok() {
                        raw_name.to_string()
                    } else {
                        let sanitized = crate::crypto::keys::sanitize_key_name(raw_name);
                        // Audited after the commit, see the doc comment.
                        renamed.push((raw_name.to_string(), sanitized.clone()));
                        sanitized
                    };
                    sqlx::query(
                        "INSERT INTO keys (id, name, key_type, public_key, private_key_encrypted, \
                           fingerprint_sha256, fingerprint_md5, comment, created_at, updated_at, \
                           deployed, deploy_path, bitwarden_id, bitwarden_sync, \
                           bitwarden_revision_ts, bitwarden_updated_at) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                         ON CONFLICT(id) DO UPDATE SET name=excluded.name, key_type=excluded.key_type, \
                           public_key=excluded.public_key, private_key_encrypted=excluded.private_key_encrypted, \
                           fingerprint_sha256=excluded.fingerprint_sha256, fingerprint_md5=excluded.fingerprint_md5, \
                           comment=excluded.comment, updated_at=excluded.updated_at, \
                           bitwarden_id=excluded.bitwarden_id, \
                           bitwarden_sync=excluded.bitwarden_sync, bitwarden_revision_ts=excluded.bitwarden_revision_ts, \
                           bitwarden_updated_at=excluded.bitwarden_updated_at",
                    )
                    .bind(id)
                    .bind(name)
                    .bind(s("key_type").unwrap_or("rsa"))
                    .bind(s("public_key").unwrap_or(""))
                    .bind(s("private_key_encrypted").unwrap_or(""))
                    .bind(s("fingerprint_sha256").unwrap_or(""))
                    .bind(s("fingerprint_md5").unwrap_or(""))
                    .bind(s("comment").unwrap_or(""))
                    .bind(s("created_at").unwrap_or(""))
                    .bind(s("updated_at").unwrap_or(""))
                    // Machine-local deployment state is NEVER restored from a
                    // backup: `deployed`/`deploy_path` describe a
                    // deployment performed on the machine that WROTE the
                    // backup. Restoring them verbatim lets a crafted backup
                    // point `deploy_path` at any user-writable file, after
                    // which `key_remove_deployed` would delete it. The key
                    // material itself is the portable part; deployment is
                    // local and starts cleared.
                    .bind(0i64)
                    .bind(Option::<String>::None)
                    .bind(s("bitwarden_id"))
                    .bind(k.get("bitwarden_sync").and_then(|v| v.as_bool()).unwrap_or(false) as i64)
                    .bind(backup_sync_ts(k.get("bitwarden_revision_ts")))
                    .bind(backup_sync_ts(k.get("bitwarden_updated_at")))
                    .execute(&mut *tx).await?;
                    keys_n += 1;
                    if let Some(cats) = k.get("category_ids").and_then(|v| v.as_array()) {
                        sqlx::query("DELETE FROM key_categories WHERE key_id = ?")
                            .bind(id)
                            .execute(&mut *tx)
                            .await?;
                        for cid in cats {
                            if let Some(cid) = cid.as_str() {
                                let is_key = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM categories WHERE id = ? AND scope = 'key'")
                                    .bind(cid).fetch_one(&mut *tx).await.unwrap_or(0) > 0;
                                if !is_key {
                                    continue;
                                }
                                sqlx::query("INSERT OR IGNORE INTO key_categories (key_id, category_id) VALUES (?, ?)")
                                    .bind(id).bind(cid).execute(&mut *tx).await?;
                                kc_n += 1;
                            }
                        }
                    }
                }
            }

            if let Some(arr) = data.get("servers").and_then(|v| v.as_array()) {
                for sv in arr {
                    let Some(id) = sv
                        .get("id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    let s = |f: &str| sv.get(f).and_then(|v| v.as_str());
                    let category_id = match s("category_id") {
                        Some(cid)
                            if sqlx::query_scalar::<_, i64>(
                                "SELECT COUNT(*) FROM categories WHERE id = ? AND scope = 'host'",
                            )
                            .bind(cid)
                            .fetch_one(&mut *tx)
                            .await
                            .unwrap_or(0)
                                > 0 =>
                        {
                            Some(cid)
                        }
                        _ => None,
                    };
                    // 17 columns, 17 placeholders, 17 binds. The bitwarden_*
                    // trio was bound with no matching placeholder, and sqlx's
                    // non-macro query() silently drops extra binds (it only
                    // iterates 1..=bind_parameter_count), so a restored
                    // server lost its remote-cipher identity and the next
                    // sync pushed duplicates of it into the vault.
                    sqlx::query(
                        "INSERT INTO servers (id, name, host, port, username, key_id, pem_path, auth_method, \
                           saved_password, category_id, color, last_connected_at, created_at, updated_at, \
                           bitwarden_id, bitwarden_revision_ts, bitwarden_updated_at) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                         ON CONFLICT(id) DO UPDATE SET name=excluded.name, host=excluded.host, port=excluded.port, \
                           username=excluded.username, key_id=excluded.key_id, pem_path=excluded.pem_path, \
                           auth_method=excluded.auth_method, saved_password=excluded.saved_password, \
                           category_id=excluded.category_id, color=excluded.color, \
                           last_connected_at=excluded.last_connected_at, updated_at=excluded.updated_at, \
                           bitwarden_id=excluded.bitwarden_id, bitwarden_revision_ts=excluded.bitwarden_revision_ts, \
                           bitwarden_updated_at=excluded.bitwarden_updated_at",
                    )
                    .bind(id)
                    .bind(s("name").unwrap_or("imported"))
                    .bind(s("host").unwrap_or(""))
                    .bind(sv.get("port").and_then(|v| v.as_i64()).unwrap_or(22))
                    .bind(s("username").unwrap_or("root"))
                    .bind(s("key_id"))
                    .bind(s("pem_path"))
                    .bind(s("auth_method").unwrap_or("publickey"))
                    .bind(s("saved_password"))
                    .bind(category_id)
                    .bind(s("color"))
                    .bind(s("last_connected_at"))
                    .bind(s("created_at").unwrap_or(""))
                    .bind(s("updated_at").unwrap_or(""))
                    .bind(s("bitwarden_id"))
                    .bind(s("bitwarden_revision_ts"))
                    .bind(s("bitwarden_updated_at"))
                    .execute(&mut *tx).await?;
                    servers_n += 1;
                }
            }

            let mut known_hosts_conflicts = 0u32;
            let mut known_hosts_imported = 0u32;
            if let Some(arr) = data.get("known_hosts").and_then(|v| v.as_array()) {
                for h in arr {
                    let Some(host) = h
                        .get("host")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    let host_key = h.get("host_key").and_then(|v| v.as_str()).unwrap_or("");
                    let fp = h
                        .get("fingerprint_sha256")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let seen = h.get("first_seen").and_then(|v| v.as_str()).unwrap_or("");
                    // Security: a backup is untrusted input. A differing pin
                    // for a known host is never overwritten (a malicious
                    // backup could pin an attacker-controlled key) and is
                    // surfaced as a conflict. A pin for an ABSENT host is
                    // inserted marked 'imported' - the trust anchor is only
                    // used after the user re-confirms the fingerprint on
                    // first use (see `confirm_imported_known_host`), so a
                    // crafted backup cannot silently pre-seed trust.
                    let existing_key = sqlx::query_scalar::<_, String>(
                        "SELECT host_key FROM known_hosts WHERE host = ?",
                    )
                    .bind(host)
                    .fetch_optional(&mut *tx)
                    .await?;
                    match existing_key {
                        Some(current) if current != host_key => {
                            known_hosts_conflicts += 1;
                        }
                        Some(_) => {
                            // Already pinned with the same key: keep the
                            // existing row (and its source) untouched.
                            hosts_n += 1;
                        }
                        None => {
                            sqlx::query(
                                "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen, source) \
                                 VALUES (?, ?, ?, ?, 'imported')",
                            )
                            // The fingerprint comes from the key, never
                            // from the backup's text (A7-46).
                            .bind(host).bind(host_key)
                            .bind(crate::ssh_client::known_host_fingerprint(host_key, fp))
                            .bind(seen)
                            .execute(&mut *tx).await?;
                            hosts_n += 1;
                            known_hosts_imported += 1;
                        }
                    }
                }
            }

            if let Some(obj) = data.get("settings").and_then(|v| v.as_object()) {
                for (k, v) in obj {
                    if let Some(val) = v.as_str() {
                        sqlx::query(
                            "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?) \
                             ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                        )
                        .bind(format!("setting.{k}")).bind(val)
                        .bind(chrono::Utc::now().to_rfc3339())
                        .execute(&mut *tx).await?;
                        settings_n += 1;
                    }
                }
            }

            // Per-server SFTP bookmarks (A7-41): `{ "<server id>": [ ... ] }`,
            // written back under the key `sftp_bookmarks_save` uses. Only a
            // JSON array is a bookmark list; anything else is skipped.
            let mut bookmarks_n = 0u32;
            if let Some(obj) = data.get("sftpBookmarks").and_then(|v| v.as_object()) {
                for (server_id, list) in obj {
                    if server_id.is_empty() || !list.is_array() {
                        continue;
                    }
                    sqlx::query(
                        "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?) \
                         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                    )
                    .bind(format!("{SFTP_BOOKMARKS_PREFIX}{server_id}"))
                    .bind(list.to_string())
                    .bind(Utc::now().to_rfc3339())
                    .execute(&mut *tx)
                    .await?;
                    bookmarks_n += 1;
                }
            }

            let mut mcp_n = 0u32;
            if let Some(arr) = data.get("mcpServers").and_then(|v| v.as_array()) {
                for m in arr {
                    let Some(id) = m
                        .get("id")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    // SECURITY: a backup is untrusted input. MCP entries are
                    // restored INERT - `confirmed = false` - no matter what
                    // the payload claims, and every tool is restored disabled
                    // with its pin cleared. Until the user re-confirms the URL
                    // and auth source in the UI (mcp_save_server), no
                    // connect/test can run, so a crafted backup cannot make
                    // the first initialize send a stored secret or env var to
                    // an attacker's URL, and cannot pre-approve a tool.
                    let mut record: McpServerRecord = match serde_json::from_value(m.clone()) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    record.id = id.to_string();
                    record.confirmed = false;
                    for tool in record.tools.iter_mut() {
                        tool.enabled = false;
                        tool.auto_approve = false;
                        tool.pin_hash = None;
                    }
                    let value = serde_json::to_string(&record)?;
                    sqlx::query(
                        "INSERT INTO mcp_servers (key, value, confirmed, updated_at) VALUES (?, ?, 0, ?) \
                         ON CONFLICT(key) DO UPDATE SET value = excluded.value, confirmed = 0, updated_at = excluded.updated_at",
                    )
                    .bind(id)
                    .bind(value)
                    .bind(Utc::now().to_rfc3339())
                    .execute(&mut *tx)
                    .await?;
                    mcp_n += 1;
                }
            }

            tx.commit().await?;
            let counts = serde_json::json!({
                "keys": keys_n, "categories": cats_n, "keyCategoryLinks": kc_n,
                "servers": servers_n, "knownHosts": hosts_n,
                "knownHostsImported": known_hosts_imported,
                "knownHostsConflicts": known_hosts_conflicts, "settings": settings_n,
                "mcpServers": mcp_n, "sftpBookmarks": bookmarks_n,
            });
            Ok::<_, anyhow::Error>((counts, renamed))
        })?;
        for (raw, sanitized) in renamed {
            let _ = self.add_audit(
                "keys.name_sanitized",
                None,
                &format!("{raw:?} -> {sanitized:?}"),
            );
        }
        Ok(counts)
    }
}

/// Config-key prefix of the per-server SFTP bookmark lists (one row per
/// server id), as `sftp_bookmarks_list` / `sftp_bookmarks_save` spell it.
pub const SFTP_BOOKMARKS_PREFIX: &str = "sftp.bookmarks.";

/// The `config` row that records that sync settings stored before
/// destinations had to be allowed were migrated as allowed
/// ([`Database::migrate_bitwarden_destination`]).
pub const BITWARDEN_DESTINATION_MIGRATED: &str = "migration.bitwarden_destination";

/// How many parents a walk up a category's chain follows at most: far
/// beyond any tree a person builds, and a bound even on a corrupt one.
pub const MAX_CATEGORY_DEPTH: usize = 256;

/// Where a category's chain of parents leads ([`category_chain`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CategoryChain {
    /// It reaches a top-level category - or a parent that no longer exists,
    /// which the tree shows at the top level.
    Rooted(Vec<String>),
    /// It has no top: it runs in a loop (a restored vault can hold one,
    /// A2-45), or on past [`MAX_CATEGORY_DEPTH`].
    NoRoot(Vec<String>),
}

impl CategoryChain {
    /// The ids walked, from the start upwards, each once.
    pub fn ids(&self) -> &[String] {
        match self {
            Self::Rooted(ids) | Self::NoRoot(ids) => ids,
        }
    }
}

/// Walk up from category `start` through `categories`, visiting each
/// category at most once and at most [`MAX_CATEGORY_DEPTH`] of them. `start`
/// is the first id walked; an id that is not stored ends the walk at the top
/// level (so an unknown `start` is an empty, rooted chain). The walks this
/// replaces had no visited set: a parent loop never ended them - one of them
/// ran on the main thread and froze the window.
pub fn category_chain(categories: &[Category], start: &str) -> CategoryChain {
    chain_in(&parent_map(categories), start)
}

/// Each category's parent, by id.
fn parent_map(categories: &[Category]) -> HashMap<&str, Option<&str>> {
    categories
        .iter()
        .map(|c| (c.id.as_str(), c.parent_id.as_deref()))
        .collect()
}

/// Each category's name, by id.
fn name_map(categories: &[Category]) -> HashMap<&str, &str> {
    categories
        .iter()
        .map(|c| (c.id.as_str(), c.name.as_str()))
        .collect()
}

/// The path of category `id`: the names along its chain of parents
/// ([`category_chain`]), from the top down, joined with "/".
fn path_in(
    parent_of: &HashMap<&str, Option<&str>>,
    name_of: &HashMap<&str, &str>,
    id: &str,
) -> String {
    let chain = chain_in(parent_of, id);
    let mut names: Vec<&str> = chain
        .ids()
        .iter()
        .filter_map(|cid| name_of.get(cid.as_str()).copied())
        .collect();
    names.reverse();
    names.join("/")
}

/// The path of every category in `categories` - exactly as
/// [`Database::category_path_string`] spells each one - from maps built once:
/// no read per category.
pub fn category_paths(categories: &[Category]) -> HashMap<String, String> {
    let parent_of = parent_map(categories);
    let name_of = name_map(categories);
    categories
        .iter()
        .map(|c| (c.id.clone(), path_in(&parent_of, &name_of, &c.id)))
        .collect()
}

/// [`category_chain`] over a parent map built once.
fn chain_in(parent_of: &HashMap<&str, Option<&str>>, start: &str) -> CategoryChain {
    let mut ids: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut current = Some(start);
    while let Some(id) = current {
        let Some(&parent) = parent_of.get(id) else {
            return CategoryChain::Rooted(ids);
        };
        if ids.len() >= MAX_CATEGORY_DEPTH || !seen.insert(id) {
            return CategoryChain::NoRoot(ids);
        }
        ids.push(id.to_string());
        current = parent;
    }
    CategoryChain::Rooted(ids)
}

/// Category `root` and every category below it in `categories`, each once:
/// the categories whose path a rename or a move of `root` changes. A
/// visited set bounds the walk on a parent loop, which a restored vault can
/// hold (A2-45).
pub fn category_subtree(categories: &[Category], root: &str) -> Vec<String> {
    let mut ids = vec![root.to_string()];
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::from([root]);
    let mut next = 0;
    while next < ids.len() {
        let parent = ids[next].clone();
        for child in categories
            .iter()
            .filter(|c| c.parent_id.as_deref() == Some(parent.as_str()))
        {
            if seen.insert(child.id.as_str()) {
                ids.push(child.id.clone());
            }
        }
        next += 1;
    }
    ids
}

/// A key's Bitwarden revision metadata as a backup carries it. `KeyRecord`
/// serializes both fields as JSON numbers, but restore read them with
/// `as_str()`, which is `None` for a number: every restored key came back with
/// NULL metadata, so the next sync saw it as changed on both sides and
/// overwrote the remote copy (A7-27). A number or a numeric string is stored as
/// text, the way `insert_key` writes it.
fn backup_sync_ts(v: Option<&serde_json::Value>) -> Option<String> {
    let v = v?;
    v.as_i64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
        .map(|n| n.to_string())
}

/// What a master-password change returns when the vault changed under it.
pub const VAULT_CHANGED_DURING_ROTATION: &str =
    "The vault changed while the master password was being changed, so nothing was changed. Try again.";

/// One sealed value re-encrypted by a master-password change: the row it
/// lives in, the blob that was read and re-sealed, and its replacement.
#[derive(Debug, Clone)]
pub struct ResealedSecret {
    pub id: String,
    pub old: String,
    pub new: String,
}

/// Everything a master-password change writes - see
/// [`Database::apply_vault_rotation`].
#[derive(Debug, Default)]
pub struct VaultRotation {
    /// `keys.private_key_encrypted`: one entry per key in the vault.
    pub keys: Vec<ResealedSecret>,
    /// `servers.saved_password`: one entry per server that stores one.
    pub server_passwords: Vec<ResealedSecret>,
    /// The `auth_secret` inside each `mcp_servers` record that stores one.
    pub mcp_secrets: Vec<ResealedSecret>,
    /// The sealed Bitwarden master password, `(old, new)`, if one is stored.
    pub bitwarden_master_password: Option<(String, String)>,
    /// The sealed AI-assistant API key, `(old, new)`, if one is stored.
    pub assistant_api_key: Option<(String, String)>,
    /// The new master-password verifier (Argon2id PHC string).
    pub master_hash: String,
}

/// Every row that holds a sealed value must be one the rotation re-sealed;
/// one it does not know about was sealed while it ran.
fn ensure_all_resealed(rows: &[String], resealed: &[ResealedSecret]) -> Result<()> {
    let known: std::collections::HashSet<&str> = resealed.iter().map(|r| r.id.as_str()).collect();
    if rows.iter().any(|id| !known.contains(id.as_str())) {
        anyhow::bail!(VAULT_CHANGED_DURING_ROTATION);
    }
    Ok(())
}

/// Decide how a legacy `known_hosts.host` value must be rewritten to the
/// "host:port" form every current lookup uses, or `None` when it already is.
///
/// A bare IPv6 literal is the case the old `WHERE host NOT LIKE '%:%'`
/// predicate could never match, because an IPv6 address is *made of* colons.
/// Detect it by shape (two or more colons and no bracket) and bracket it, so
/// the result is unambiguous and a second pass leaves it alone.
pub(crate) fn qualify_legacy_known_host(host: &str) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    // Already qualified: "[v6]:port", or "name:port" with a numeric port.
    if let Some(rest) = host.strip_prefix('[') {
        return if rest.contains("]:") {
            None
        } else {
            Some(format!("{host}:22"))
        };
    }
    let colons = host.matches(':').count();
    match colons {
        0 => Some(format!("{host}:22")),
        // Exactly one colon: "name:port" if the tail parses as a port, else it
        // is something odd - qualify it rather than leave it unreachable.
        1 => {
            let tail = host.rsplit(':').next().unwrap_or("");
            if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
                None
            } else {
                Some(format!("{host}:22"))
            }
        }
        // Two or more colons and no bracket: a bare IPv6 literal.
        _ => Some(format!("[{host}]:22")),
    }
}

/// FNV-1a 32-bit hash of the string, formatted as 8 lowercase hex chars.
/// Used to derive a short deterministic id from a category path.
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: seed a row straight into known_hosts, bypassing add_known_host,
    /// to simulate a pre-migration database.
    fn seed_pin(db: &Database, host: &str, key: &str) {
        block(async {
            sqlx::query(
                "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen) VALUES (?, ?, ?, ?)",
            )
            .bind(host)
            .bind(key)
            .bind("aa:bb:cc")
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(&db.pool)
            .await
            .unwrap();
        });
    }

    fn migration_db(name: &str) -> Database {
        let db_path = std::env::temp_dir().join(format!(
            "sshspan-known-hosts-{name}-{}.db",
            uuid::Uuid::new_v4()
        ));
        Database::open_at(db_path).expect("open test db")
    }

    fn pins(db: &Database) -> Vec<String> {
        let mut v: Vec<String> = db
            .list_known_hosts()
            .expect("list known hosts")
            .into_iter()
            .map(|h| h.host)
            .collect();
        v.sort();
        v
    }

    /// The migration must rewrite legacy bare-host pins to "host:22".
    #[test]
    fn known_hosts_migration_port_qualifies_bare_host() {
        let db = migration_db("bare");
        seed_pin(&db, "example.com", "fake-key-blob");
        db.migrate().expect("migrate should succeed");
        assert_eq!(pins(&db), vec!["example.com:22"]);
    }

    /// Already-qualified pins must not accumulate extra ":22" suffixes.
    #[test]
    fn known_hosts_migration_idempotent_for_qualified_host() {
        let db = migration_db("qualified");
        seed_pin(&db, "example.com:2222", "fake-key-blob");
        db.migrate().expect("migrate should succeed");
        db.migrate().expect("second migrate should be idempotent");
        assert_eq!(pins(&db), vec!["example.com:2222"]);
    }

    /// REGRESSION: a bare IPv6 literal is made of colons, so the old
    /// `WHERE host NOT LIKE '%:%'` predicate never matched it and the pin was
    /// orphaned - every later connection to that host took the unpinned
    /// branch and got a first-trust prompt instead of a mismatch failure.
    #[test]
    fn known_hosts_migration_qualifies_bare_ipv6() {
        let db = migration_db("ipv6");
        seed_pin(&db, "2001:db8::1", "fake-key-blob");
        db.migrate().expect("migrate should succeed");
        assert_eq!(pins(&db), vec!["[2001:db8::1]:22"]);
        // The migrated key must be exactly what a lookup will ask for.
        assert_eq!(
            crate::ssh_client::known_host_key("2001:db8::1", 22),
            "[2001:db8::1]:22"
        );
        assert!(db
            .get_known_host(&crate::ssh_client::known_host_key("2001:db8::1", 22))
            .expect("lookup")
            .is_some());
        db.migrate().expect("second migrate should be idempotent");
        assert_eq!(pins(&db), vec!["[2001:db8::1]:22"]);
    }

    /// REGRESSION: with both "example.com" and "example.com:22" present, the
    /// old blanket UPDATE hit the PRIMARY KEY, SQLite rolled the whole
    /// statement back, and `let _ =` swallowed the error - so EVERY legacy pin
    /// stayed bare and unreachable. The per-row migration must survive the
    /// collision and still migrate the unrelated rows.
    #[test]
    fn known_hosts_migration_survives_key_collision() {
        let db = migration_db("collision");
        seed_pin(&db, "example.com", "legacy-blob");
        seed_pin(&db, "example.com:22", "current-blob");
        seed_pin(&db, "other.example", "other-blob");
        db.migrate().expect("migrate must not fail on a collision");
        assert_eq!(pins(&db), vec!["example.com:22", "other.example:22"]);
        // The existing qualified pin wins; the legacy orphan is dropped.
        let kept = db
            .get_known_host("example.com:22")
            .expect("lookup")
            .expect("pin present");
        assert_eq!(kept.host_key, "current-blob");
    }

    // ── One fingerprint form; named known_hosts columns (A7-46) ─────────────

    fn seed_known_host(db: &Database, host: &str, key: &str, fp: &str, source: &str) {
        block(async {
            sqlx::query(
                "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen, source) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(host)
            .bind(key)
            .bind(fp)
            .bind(Utc::now().to_rfc3339())
            .bind(source)
            .execute(&db.pool)
            .await
            .unwrap();
        });
    }

    fn stored_fingerprints(db: &Database) -> Vec<(String, String)> {
        block(async {
            sqlx::query_as::<_, (String, String)>(
                "SELECT host, fingerprint_sha256 FROM known_hosts ORDER BY host",
            )
            .fetch_all(&db.pool)
            .await
            .unwrap()
        })
    }

    fn b64(s: &str) -> String {
        use base64ct::Encoding;
        base64ct::Base64::encode_string(s.as_bytes())
    }

    fn keygen_fp(s: &str) -> String {
        crate::crypto::utils::ssh_fingerprint_sha256(s.as_bytes())
    }

    fn pre_ru4_fp(s: &str) -> String {
        format!("{}=", &keygen_fp(s)["SHA256:".len()..])
    }

    #[test]
    fn ru4_known_host_fingerprints_migrate_once_to_the_ssh_keygen_form() {
        let db = migration_db("ru4-fingerprints");
        seed_known_host(&db, "a:22", &b64("a"), &pre_ru4_fp("a"), "connection");
        seed_known_host(
            &db,
            "b:22",
            &b64("b"),
            &format!("SHA256:{}", pre_ru4_fp("b")),
            "imported",
        );
        seed_known_host(
            &db,
            "c:22",
            &b64("c"),
            "SHA256:forged-by-a-backup",
            "imported",
        );
        seed_known_host(
            &db,
            "d:22",
            "%%% not base64",
            &pre_ru4_fp("d"),
            "connection",
        );
        seed_known_host(&db, "e:22", "%%% not base64", "aa:bb:cc", "connection");
        db.migrate().unwrap();
        let want: Vec<(String, String)> = [
            ("a:22", keygen_fp("a")),
            ("b:22", keygen_fp("b")),
            ("c:22", keygen_fp("c")),
            ("d:22", keygen_fp("d")),
            ("e:22", "aa:bb:cc".to_string()),
        ]
        .into_iter()
        .map(|(h, f)| (h.to_string(), f))
        .collect();
        assert_eq!(stored_fingerprints(&db), want);
        db.migrate().unwrap();
        assert_eq!(
            stored_fingerprints(&db),
            want,
            "a second run changes nothing"
        );
        let listed: Vec<(String, String)> = db
            .list_known_hosts()
            .unwrap()
            .into_iter()
            .map(|k| (k.host, k.fingerprint_sha256))
            .collect();
        assert_eq!(listed, want);
        // A row in the old form that appears after the migration is read in
        // the new form all the same.
        seed_known_host(&db, "f:22", &b64("f"), &pre_ru4_fp("f"), "connection");
        assert_eq!(
            db.get_known_host("f:22")
                .unwrap()
                .unwrap()
                .fingerprint_sha256,
            keygen_fp("f")
        );
    }

    /// A backup is untrusted input: the fingerprint stored for a restored pin
    /// is computed from its key, not copied from the file.
    #[test]
    fn ru4_restored_known_host_fingerprint_is_computed_from_the_key() {
        let db = migration_db("ru4-restore-fp");
        db.restore_backup(&serde_json::json!({
            "known_hosts": [{
                "host": "r:22",
                "host_key": b64("r"),
                "fingerprint_sha256": "SHA256:forged",
                "first_seen": Utc::now().to_rfc3339(),
            }]
        }))
        .unwrap();
        assert_eq!(
            stored_fingerprints(&db),
            vec![("r:22".to_string(), keygen_fp("r"))]
        );
    }

    /// For known_hosts too: a pooled connection that loaded the
    /// schema before the upgrade added `source` must still read it. With
    /// `SELECT *` such a connection never saw the column, and the reader's
    /// fallback made an unconfirmed backup pin look like a confirmed one.
    #[test]
    fn ru4_known_host_rows_read_on_every_pooled_connection_after_an_upgrade() {
        use sqlx::sqlite::SqlitePoolOptions;
        const CONNECTIONS: u32 = 4;
        let db_path = std::env::temp_dir().join(format!(
            "sshspan-ru4-stale-known-hosts-{}.db",
            uuid::Uuid::new_v4()
        ));
        let url = format!("sqlite:{}?mode=rwc", db_path.display());
        let stamp = Utc::now().to_rfc3339();
        let (pool, stale) = block(async {
            let pool = SqlitePoolOptions::new()
                .max_connections(CONNECTIONS)
                .connect(&url)
                .await
                .unwrap();
            // The table an older release created: no `source` column.
            sqlx::query(
                "CREATE TABLE known_hosts (host TEXT PRIMARY KEY, host_key TEXT NOT NULL, \
                 fingerprint_sha256 TEXT NOT NULL, first_seen TEXT NOT NULL)",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("INSERT INTO known_hosts VALUES ('old.example:22', 'AAAA', 'x', ?)")
                .bind(&stamp)
                .execute(&pool)
                .await
                .unwrap();
            let mut held = Vec::new();
            for _ in 0..CONNECTIONS {
                let mut conn = pool.acquire().await.unwrap();
                sqlx::query("SELECT COUNT(*) FROM known_hosts")
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap();
                held.push(conn);
            }
            drop(held.pop());
            while pool.num_idle() < 1 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            (pool, held)
        });
        let db = Database { pool, db_path };
        db.migrate().expect("upgrade the old database");
        db.restore_backup(&serde_json::json!({
            "known_hosts": [{
                "host": "restored.example:22",
                "host_key": "BBBB",
                "fingerprint_sha256": "x",
                "first_seen": stamp,
            }]
        }))
        .unwrap();
        block(async {
            drop(stale);
            while db.pool.num_idle() < CONNECTIONS as usize {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });

        for _ in 0..CONNECTIONS * 2 {
            let restored = db.get_known_host("restored.example:22").unwrap().unwrap();
            assert_eq!(
                restored.source, "imported",
                "an unconfirmed pin read as confirmed"
            );
            let old = db.get_known_host("old.example:22").unwrap().unwrap();
            assert_eq!(old.source, "connection");
            let all = db.list_known_hosts().unwrap();
            let listed = all
                .iter()
                .find(|k| k.host == "restored.example:22")
                .unwrap();
            assert_eq!(listed.source, "imported");
        }
        block(async { db.pool.close().await });
        let _ = std::fs::remove_file(&db.db_path);
    }

    #[test]
    fn qualify_legacy_known_host_shapes() {
        // Bare hostname / IPv4 -> ":22".
        assert_eq!(
            qualify_legacy_known_host("example.com").as_deref(),
            Some("example.com:22")
        );
        assert_eq!(
            qualify_legacy_known_host("192.0.2.1").as_deref(),
            Some("192.0.2.1:22")
        );
        // Bare IPv6 -> bracketed and qualified.
        assert_eq!(
            qualify_legacy_known_host("::1").as_deref(),
            Some("[::1]:22")
        );
        // Already qualified -> untouched.
        assert_eq!(qualify_legacy_known_host("example.com:2222"), None);
        assert_eq!(qualify_legacy_known_host("[2001:db8::1]:22"), None);
        // Bracketed but portless -> qualified.
        assert_eq!(
            qualify_legacy_known_host("[2001:db8::1]").as_deref(),
            Some("[2001:db8::1]:22")
        );
    }

    fn test_db() -> Database {
        let db_path = std::env::temp_dir().join(format!(
            "sshspan-transfer-queue-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        Database::open_at(db_path).expect("open test db")
    }

    fn sample_row(id: i64, state: &str) -> QueueJobRow {
        QueueJobRow {
            id,
            kind: "upload".to_string(),
            session_id: "sess-1".to_string(),
            server_name: "my-server".to_string(),
            local_path: "/local/a".to_string(),
            remote_path: "/remote/a".to_string(),
            size: 1000,
            bytes_done: 200,
            state: state.to_string(),
            error: None,
            resume: Some("resume".to_string()),
            preserve_ts: Some(true),
            target_session_id: None,
            target_server_name: None,
            target_remote_path: None,
            attempts: 1,
            verify: Some(false),
            server_id: Some("srv-1".to_string()),
            target_server_id: None,
        }
    }

    /// `upsert_queue_job` must both insert a new row and, on a repeat call
    /// with the same id, overwrite it in place rather than duplicating it -
    /// `sftp::queue` relies on this for its throttled progress persistence
    /// (many upserts of the same job over its lifetime).
    #[test]
    fn upsert_queue_job_inserts_then_overwrites_by_id() {
        let db = test_db();
        db.upsert_queue_job(&sample_row(1, "active"))
            .expect("insert");
        let mut updated = sample_row(1, "done");
        updated.bytes_done = 1000;
        db.upsert_queue_job(&updated).expect("overwrite");

        let pending = db.list_pending_queue_jobs().expect("list pending");
        // "done" is not a pending state, so the row shouldn't show up here -
        // proves the second upsert changed the SAME row's state rather than
        // inserting a second one next to it.
        assert!(pending.is_empty());
    }

    /// `list_pending_queue_jobs` returns exactly the Queued/Active/Paused
    /// rows - the set `restore_pending` reloads at startup - and none of the
    /// terminal ones.
    #[test]
    fn list_pending_queue_jobs_filters_by_state() {
        let db = test_db();
        for (id, state) in [
            (1, "queued"),
            (2, "active"),
            (3, "paused"),
            (4, "done"),
            (5, "failed"),
            (6, "cancelled"),
        ] {
            db.upsert_queue_job(&sample_row(id, state)).unwrap();
        }
        let mut pending_ids: Vec<i64> = db
            .list_pending_queue_jobs()
            .expect("list pending")
            .into_iter()
            .map(|r| r.id)
            .collect();
        pending_ids.sort();
        assert_eq!(pending_ids, vec![1, 2, 3]);
    }

    /// `delete_finished_queue_jobs` removes only Done/Failed/Cancelled rows -
    /// what `clear_finished` calls so a restart's `restore_pending` never
    /// resurrects a job the user already cleared.
    #[test]
    fn delete_finished_queue_jobs_only_removes_terminal_states() {
        let db = test_db();
        for (id, state) in [(1, "queued"), (2, "done"), (3, "failed"), (4, "cancelled")] {
            db.upsert_queue_job(&sample_row(id, state)).unwrap();
        }
        db.delete_finished_queue_jobs().expect("delete finished");

        let remaining_ids: Vec<i64> = db
            .list_pending_queue_jobs()
            .expect("list pending")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(remaining_ids, vec![1]);
    }

    /// A round trip through the DB must preserve every field a restored job
    /// needs to reconstruct - including nullable ones (`resume`,
    /// `preserve_ts`, `verify`, the ServerCopy `target_*` triple).
    #[test]
    fn queue_job_round_trip_preserves_all_fields() {
        let db = test_db();
        let mut row = sample_row(42, "paused");
        row.target_session_id = Some("target-sess".to_string());
        row.target_server_name = Some("target-server".to_string());
        row.target_remote_path = Some("/remote/dest".to_string());
        row.target_server_id = Some("srv-2".to_string());
        db.upsert_queue_job(&row).expect("insert");

        let pending = db.list_pending_queue_jobs().expect("list pending");
        assert_eq!(pending.len(), 1);
        let got = &pending[0];
        assert_eq!(got.id, 42);
        assert_eq!(got.kind, "upload");
        assert_eq!(got.session_id, "sess-1");
        assert_eq!(got.server_name, "my-server");
        assert_eq!(got.local_path, "/local/a");
        assert_eq!(got.remote_path, "/remote/a");
        assert_eq!(got.size, 1000);
        assert_eq!(got.bytes_done, 200);
        assert_eq!(got.state, "paused");
        assert_eq!(got.resume.as_deref(), Some("resume"));
        assert_eq!(got.preserve_ts, Some(true));
        assert_eq!(got.target_session_id.as_deref(), Some("target-sess"));
        assert_eq!(got.target_server_name.as_deref(), Some("target-server"));
        assert_eq!(got.target_remote_path.as_deref(), Some("/remote/dest"));
        assert_eq!(got.attempts, 1);
        assert_eq!(got.verify, Some(false));
        // A7-17: the saved-server ids survive, so a restored job can find the
        // reconnected session of the same server.
        assert_eq!(got.server_id.as_deref(), Some("srv-1"));
        assert_eq!(got.target_server_id.as_deref(), Some("srv-2"));
    }

    /// A database from before `server_id` existed must open (the columns are
    /// added in place) and its pending jobs must still load - with no server
    /// id, so they stay Paused until the user re-queues them rather than being
    /// rebound to the wrong server.
    #[test]
    fn migrate_adds_server_id_columns_to_an_old_transfer_queue() {
        use sqlx::Connection;
        // An old database FILE, made by a throwaway connection that is closed
        // before the app opens it - exactly an upgrade launch: the table exists
        // in its previous shape (no server-id columns) with one pending job.
        let db_path = std::env::temp_dir().join(format!(
            "sshspan-old-queue-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        block(async {
            let mut conn =
                sqlx::SqliteConnection::connect(&format!("sqlite:{}?mode=rwc", db_path.display()))
                    .await
                    .unwrap();
            sqlx::query(
                r#"
                CREATE TABLE transfer_queue (
                    id INTEGER PRIMARY KEY, kind TEXT NOT NULL, session_id TEXT NOT NULL,
                    server_name TEXT NOT NULL, local_path TEXT NOT NULL,
                    remote_path TEXT NOT NULL, size INTEGER NOT NULL,
                    bytes_done INTEGER NOT NULL, state TEXT NOT NULL, error TEXT,
                    resume TEXT, preserve_ts INTEGER, target_session_id TEXT,
                    target_server_name TEXT, target_remote_path TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0, verify INTEGER,
                    updated_at TEXT NOT NULL
                )
                "#,
            )
            .execute(&mut conn)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO transfer_queue (id, kind, session_id, server_name, local_path, \
                 remote_path, size, bytes_done, state, attempts, updated_at) \
                 VALUES (7, 'download', 'old-sess', 'old-server', '/l', '/r', 10, 5, 'paused', 0, 'x')",
            )
            .execute(&mut conn)
            .await
            .unwrap();
            conn.close().await.unwrap();
        });

        let db = Database::open_at(db_path).expect("open and migrate an old database");

        let pending = db.list_pending_queue_jobs().expect("list pending");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, 7);
        assert_eq!(pending[0].server_id, None);
        assert_eq!(pending[0].target_server_id, None);
        // ...and the migrated table accepts the new fields.
        let mut row = sample_row(8, "paused");
        row.target_server_id = Some("srv-9".into());
        db.upsert_queue_job(&row).expect("upsert after migrate");
        let got = db
            .list_pending_queue_jobs()
            .unwrap()
            .into_iter()
            .find(|r| r.id == 8)
            .unwrap();
        assert_eq!(got.server_id.as_deref(), Some("srv-1"));
        assert_eq!(got.target_server_id.as_deref(), Some("srv-9"));
    }

    // ── Atomic vault rotation ─────────────────────────────────────────

    fn rotation_key(id: &str, pw: &str) -> KeyRecord {
        KeyRecord {
            id: id.to_string(),
            name: format!("key-{id}"),
            key_type: "ed25519".into(),
            public_key: "ssh-ed25519 AAAAfake".into(),
            private_key_encrypted: crate::crypto::vault::seal(pw, b"priv").unwrap(),
            fingerprint_sha256: "SHA256:f".into(),
            fingerprint_md5: "MD5:f".into(),
            comment: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deployed: false,
            deploy_path: None,
            bitwarden_id: None,
            bitwarden_sync: false,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
            category_ids: Vec::new(),
        }
    }

    /// Regression: a full rotation (keys + the Bitwarden credential +
    /// the verifier) commits in one transaction, so after `apply_vault_rotation`
    /// every record unseals under the NEW password and the old password fails.
    #[test]
    fn apply_vault_rotation_reseals_keys_and_bitwarden_and_verifier() {
        let db = test_db();
        let old_pw = "old-master-pw";
        let new_pw = "new-master-pw";
        db.insert_key(&rotation_key("k1", old_pw)).unwrap();

        // Seed a Bitwarden credential sealed under the OLD password.
        let bw_old_blob = crate::crypto::vault::seal(old_pw, b"bw-master-secret").unwrap();
        let mut cfg = BitwardenConfig::default();
        cfg.master_password = Some(bw_old_blob.clone());
        db.save_bitwarden_config(&cfg).unwrap();
        // And an assistant API key sealed under the OLD password.
        let ai_old_blob = crate::crypto::vault::seal(old_pw, b"sk-assistant-key").unwrap();
        let mut ai = AssistantConfig::default();
        ai.api_key = Some(ai_old_blob.clone());
        db.save_assistant_config(&ai).unwrap();
        // And an MCP server whose auth secret is sealed under the OLD
        // password (the whole record is one JSON row).
        let mcp_old = crate::crypto::vault::seal(old_pw, b"mcp-bearer-secret").unwrap();
        db.save_mcp_server(&McpServerRecord {
            id: "mcp1".into(),
            name: "tools".into(),
            url: "https://mcp.example.com".into(),
            auth_type: "bearer".into(),
            auth_header_name: None,
            auth_secret: Some(mcp_old),
            auth_env_var: None,
            confirmed: true,
            tools: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .unwrap();
        db.set_config("master.hash", "OLD-VERIFIER").unwrap();

        // Rotate: re-seal key + BW cred in memory, commit atomically.
        let key = db.get_key("k1").unwrap().unwrap();
        let plain = crate::crypto::vault::unseal(old_pw, &key.private_key_encrypted).unwrap();
        let key_new = crate::crypto::vault::seal(new_pw, &plain).unwrap();
        let bw_new = crate::crypto::vault::seal(new_pw, b"bw-master-secret").unwrap();
        let ai_new = crate::crypto::vault::seal(new_pw, b"sk-assistant-key").unwrap();
        // MCP: unseal under OLD, re-seal under NEW, in memory, same
        // transaction as everything else.
        let mcp = db.get_mcp_server("mcp1").unwrap().unwrap();
        let mcp_old_blob = mcp.auth_secret.clone().unwrap();
        let mcp_plain = crate::crypto::vault::unseal(old_pw, &mcp_old_blob).unwrap();
        let mcp_new = crate::crypto::vault::seal(new_pw, &mcp_plain).unwrap();
        db.apply_vault_rotation(&VaultRotation {
            keys: vec![ResealedSecret {
                id: "k1".into(),
                old: key.private_key_encrypted.clone(),
                new: key_new,
            }],
            server_passwords: Vec::new(),
            mcp_secrets: vec![ResealedSecret {
                id: "mcp1".into(),
                old: mcp_old_blob,
                new: mcp_new,
            }],
            bitwarden_master_password: Some((bw_old_blob, bw_new)),
            assistant_api_key: Some((ai_old_blob, ai_new)),
            master_hash: "NEW-VERIFIER".into(),
        })
        .unwrap();

        // Key unseals under NEW, not OLD.
        let stored = db.get_key("k1").unwrap().unwrap();
        assert!(crate::crypto::vault::unseal(new_pw, &stored.private_key_encrypted).is_ok());
        assert!(crate::crypto::vault::unseal(old_pw, &stored.private_key_encrypted).is_err());
        // The Bitwarden credential rotated too: NEW unseals, OLD fails.
        let cfg2 = db.load_bitwarden_config().unwrap();
        let mp = cfg2.master_password.unwrap();
        assert_eq!(
            crate::crypto::vault::unseal(new_pw, &mp).unwrap(),
            b"bw-master-secret"
        );
        assert!(crate::crypto::vault::unseal(old_pw, &mp).is_err());
        // The assistant API key rotated in the same transaction: NEW unseals,
        // OLD fails, so the assistant does not strand on the old password.
        let ai2 = db.load_assistant_config().unwrap();
        let sk = ai2.api_key.unwrap();
        assert_eq!(
            crate::crypto::vault::unseal(new_pw, &sk).unwrap(),
            b"sk-assistant-key"
        );
        assert!(crate::crypto::vault::unseal(old_pw, &sk).is_err());
        // The MCP auth secret rotated in the same transaction: NEW unseals,
        // OLD fails, and `confirmed` was not silently flipped.
        let mcp2 = db.get_mcp_server("mcp1").unwrap().unwrap();
        assert_eq!(
            crate::crypto::vault::unseal(new_pw, mcp2.auth_secret.as_deref().unwrap()).unwrap(),
            b"mcp-bearer-secret"
        );
        assert!(
            crate::crypto::vault::unseal(old_pw, mcp2.auth_secret.as_deref().unwrap()).is_err()
        );
        assert!(mcp2.confirmed);
        // Verifier rotated.
        assert_eq!(
            db.get_config("master.hash").unwrap().as_deref(),
            Some("NEW-VERIFIER")
        );
    }

    // ── The rotation commit is conditional and column-precise ───────────

    /// A rotation of the one key `k1` (snapshot taken now), old -> new.
    fn one_key_rotation(db: &Database, old_pw: &str, new_pw: &str) -> VaultRotation {
        let key = db.get_key("k1").unwrap().unwrap();
        let plain = crate::crypto::vault::unseal(old_pw, &key.private_key_encrypted).unwrap();
        VaultRotation {
            keys: vec![ResealedSecret {
                id: "k1".into(),
                old: key.private_key_encrypted,
                new: crate::crypto::vault::seal(new_pw, &plain).unwrap(),
            }],
            master_hash: "NEW-VERIFIER".into(),
            ..VaultRotation::default()
        }
    }

    /// The rotation left nothing behind: old verifier, `k1` still old-sealed.
    fn assert_rolled_back(db: &Database, old_pw: &str, err: anyhow::Error) {
        assert_eq!(err.to_string(), VAULT_CHANGED_DURING_ROTATION);
        assert_eq!(
            db.get_config("master.hash").unwrap().as_deref(),
            Some("OLD-VERIFIER")
        );
        let key = db.get_key("k1").unwrap().unwrap();
        assert!(crate::crypto::vault::unseal(old_pw, &key.private_key_encrypted).is_ok());
    }

    /// A key whose sealed blob is no longer the one that was re-sealed (a
    /// stale full-row write-back landed after the snapshot) rolls the whole
    /// rotation back instead of overwriting it.
    #[test]
    fn apply_vault_rotation_rolls_back_when_a_sealed_row_changed() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = test_db();
        db.set_config("master.hash", "OLD-VERIFIER").unwrap();
        db.insert_key(&rotation_key("k1", old_pw)).unwrap();
        let rotation = one_key_rotation(&db, old_pw, new_pw);
        // Meanwhile: the row is rewritten with another old-password blob.
        let other_blob = rotation_key("k1", old_pw).private_key_encrypted;
        block(async {
            sqlx::query("UPDATE keys SET private_key_encrypted = ? WHERE id = ?")
                .bind(&other_blob)
                .bind("k1")
                .execute(&db.pool)
                .await
        })
        .unwrap();
        let err = db.apply_vault_rotation(&rotation).unwrap_err();
        assert_rolled_back(&db, old_pw, err);
    }

    /// A sealed server password the rotation never saw (saved while it ran)
    /// would be stranded under the old password - roll back instead.
    #[test]
    fn apply_vault_rotation_rolls_back_on_an_unknown_sealed_row() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = test_db();
        db.set_config("master.hash", "OLD-VERIFIER").unwrap();
        db.insert_key(&rotation_key("k1", old_pw)).unwrap();
        let rotation = one_key_rotation(&db, old_pw, new_pw);
        let now = Utc::now();
        db.insert_server(&ServerRecord {
            id: "s-late".into(),
            name: "late".into(),
            host: "example.com".into(),
            port: 22,
            username: "root".into(),
            key_id: None,
            pem_path: None,
            auth_method: "password".into(),
            saved_password: Some(crate::crypto::vault::seal(old_pw, b"pw").unwrap()),
            category_id: None,
            color: None,
            last_connected_at: None,
            created_at: now,
            updated_at: now,
            bitwarden_id: None,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
        })
        .unwrap();
        let err = db.apply_vault_rotation(&rotation).unwrap_err();
        assert_rolled_back(&db, old_pw, err);
    }

    /// A Bitwarden master password saved while the rotation ran (the
    /// rotation saw none to re-seal) rolls it back.
    #[test]
    fn apply_vault_rotation_rolls_back_when_a_credential_appeared() {
        let (old_pw, new_pw) = ("old-master-pw", "new-master-pw");
        let db = test_db();
        db.set_config("master.hash", "OLD-VERIFIER").unwrap();
        db.insert_key(&rotation_key("k1", old_pw)).unwrap();
        let rotation = one_key_rotation(&db, old_pw, new_pw);
        db.save_bitwarden_config(&BitwardenConfig {
            master_password: Some(crate::crypto::vault::seal(old_pw, b"bw").unwrap()),
            ..BitwardenConfig::default()
        })
        .unwrap();
        let err = db.apply_vault_rotation(&rotation).unwrap_err();
        assert_rolled_back(&db, old_pw, err);
    }

    /// The connect path stamps `last_connected_at` alone: a stale in-memory
    /// copy of the row (an old `saved_password`, here) is never written back.
    #[test]
    fn touch_server_last_connected_only_stamps_the_time() {
        let db = test_db();
        let now = Utc::now();
        let server = ServerRecord {
            id: "s1".into(),
            name: "srv".into(),
            host: "example.com".into(),
            port: 22,
            username: "root".into(),
            key_id: None,
            pem_path: None,
            auth_method: "password".into(),
            saved_password: Some("CURRENT-BLOB".into()),
            category_id: None,
            color: None,
            last_connected_at: None,
            created_at: now,
            updated_at: now,
            bitwarden_id: None,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
        };
        db.insert_server(&server).unwrap();
        db.touch_server_last_connected("s1", now).unwrap();
        // The two columns the statement may touch, read directly.
        let (saved, last): (Option<String>, Option<String>) = block(async {
            sqlx::query_as("SELECT saved_password, last_connected_at FROM servers WHERE id = ?")
                .bind("s1")
                .fetch_one(&db.pool)
                .await
        })
        .unwrap();
        assert_eq!(saved.as_deref(), Some("CURRENT-BLOB"));
        assert_eq!(last.as_deref(), Some(now.to_rfc3339().as_str()));
    }

    // ── Restore clears machine-local deployment state ───────────────────

    /// Regression: a backup carrying `deployed`/`deploy_path` must NOT
    /// restore them - deployment is machine-local and a crafted path would
    /// otherwise steer `key_remove_deployed` into deleting an arbitrary file.
    #[test]
    fn restore_backup_discards_deployment_state() {
        let db = test_db();
        let payload = serde_json::json!({
            "keys": [{
                "id": "k-evil",
                "name": "evil",
                "key_type": "ed25519",
                "public_key": "ssh-ed25519 AAAAfake",
                "private_key_encrypted": "x",
                "fingerprint_sha256": "SHA256:f",
                "fingerprint_md5": "MD5:f",
                "comment": "",
                "created_at": "",
                "updated_at": "",
                "deployed": true,
                "deploy_path": "C:\\Users\\victim\\important.txt"
            }]
        });
        db.restore_backup(&payload).unwrap();
        let key = db.get_key("k-evil").unwrap().unwrap();
        assert!(!key.deployed, "restored key must not be marked deployed");
        assert!(
            key.deploy_path.is_none(),
            "restored key must not carry a deployment path"
        );
    }

    #[test]
    fn restore_backup_preserves_server_bitwarden_linkage() {
        // Regression for the silent arity drop: the servers INSERT bound 17
        // values against 14 placeholders, and sqlx's non-macro query()
        // ignores the excess, so bitwarden_id/revision/updated came back
        // NULL after a restore - and the next sync pushed duplicates of
        // every server into the Bitwarden vault.
        let db = test_db();
        let payload = serde_json::json!({
            "servers": [{
                "id": "srv-bw",
                "name": "linked",
                "host": "example.com",
                "port": 22,
                "username": "root",
                "auth_method": "publickey",
                "bitwarden_id": "cipher-123",
                "bitwarden_revision_ts": "2026-09-01T00:00:00Z",
                "bitwarden_updated_at": "2026-09-02T00:00:00Z"
            }]
        });
        db.restore_backup(&payload).unwrap();
        let server = db.get_server("srv-bw").unwrap().expect("server restored");
        assert_eq!(
            server.bitwarden_id.as_deref(),
            Some("cipher-123"),
            "restored server must keep its Bitwarden cipher id"
        );
        assert!(
            server.bitwarden_revision_ts.is_some() && server.bitwarden_updated_at.is_some(),
            "restored server must keep its sync revision metadata"
        );
    }

    // ── A7-28 / A2-54 / A2-31 / A7-40: delete paths leave nothing dangling ──

    fn category(id: &str, parent: Option<&str>, scope: &str) -> Category {
        Category {
            id: id.into(),
            name: format!("cat-{id}"),
            parent_id: parent.map(String::from),
            scope: scope.into(),
            color: None,
            sort_index: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn server_in(id: &str, category_id: Option<&str>) -> ServerRecord {
        ServerRecord {
            id: id.into(),
            name: format!("srv-{id}"),
            host: "example.com".into(),
            port: 22,
            username: "root".into(),
            key_id: None,
            pem_path: None,
            auth_method: "publickey".into(),
            saved_password: None,
            category_id: category_id.map(String::from),
            color: None,
            last_connected_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            bitwarden_id: None,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
        }
    }

    /// A deleted key's category links go with it, so category counts stop
    /// counting a key that no longer exists.
    #[test]
    fn delete_key_removes_its_category_links() {
        let db = test_db();
        db.insert_category(&category("c1", None, "key")).unwrap();
        db.insert_key(&rotation_key("k1", "pw")).unwrap();
        db.insert_key(&rotation_key("k2", "pw")).unwrap();
        db.set_key_categories("k1", &["c1".to_string()]).unwrap();
        db.set_key_categories("k2", &["c1".to_string()]).unwrap();

        db.delete_key("k1").unwrap();

        let links = db.all_key_categories().unwrap();
        assert_eq!(links.get("k1"), None, "the deleted key's links remain");
        assert_eq!(links.get("k2"), Some(&vec!["c1".to_string()]));
    }

    /// Deleting a host category moves its servers to the deleted node's
    /// parent, and `reassigned` names only the children that really moved -
    /// not the siblings (or, for a root, every other root category).
    #[test]
    fn delete_category_moves_servers_up_and_reports_only_moved_children() {
        let db = test_db();
        for c in [
            category("top", None, "host"),
            category("mid", Some("top"), "host"),
            category("leaf", Some("mid"), "host"),
            category("sibling", Some("top"), "host"),
            category("other-root", None, "host"),
            category("key-root", None, "key"),
        ] {
            db.insert_category(&c).unwrap();
        }
        db.insert_server(&server_in("s-mid", Some("mid"))).unwrap();
        db.insert_server(&server_in("s-root", Some("other-root")))
            .unwrap();

        let moved = db.delete_category("mid").unwrap();
        assert_eq!(moved, vec!["leaf".to_string()]);
        let leaf = db.get_category("leaf").unwrap().unwrap();
        assert_eq!(leaf.parent_id.as_deref(), Some("top"));
        let s_mid = db.get_server("s-mid").unwrap().unwrap();
        assert_eq!(s_mid.category_id.as_deref(), Some("top"));

        // A childless root: nothing moved, its servers become uncategorized.
        let moved = db.delete_category("other-root").unwrap();
        assert!(moved.is_empty(), "nothing was re-parented: {moved:?}");
        let s_root = db.get_server("s-root").unwrap().unwrap();
        assert_eq!(s_root.category_id, None);
    }

    /// Minor 3: a rename writes the name (and `updated_at`) only. Deploy now
    /// runs off the main thread, so a rename that wrote back the whole row it
    /// had read could erase a deployment recorded in between.
    #[test]
    fn rename_key_writes_only_the_name() {
        let db = test_db();
        let stale = rotation_key("k1", "pw");
        db.insert_key(&stale).unwrap();
        // Meanwhile a deploy records itself and the blob is re-sealed.
        db.set_key_deployment("k1", Some("/home/u/.ssh/sshspan_k1"))
            .unwrap();
        block(async {
            sqlx::query("UPDATE keys SET private_key_encrypted = 'RESEALED' WHERE id = 'k1'")
                .execute(&db.pool)
                .await
                .unwrap();
        });
        db.rename_key("k1", "renamed").unwrap();
        let key = db.get_key("k1").unwrap().unwrap();
        assert_eq!(key.name, "renamed");
        assert!(key.deployed);
        assert_eq!(key.deploy_path.as_deref(), Some("/home/u/.ssh/sshspan_k1"));
        assert_eq!(key.private_key_encrypted, "RESEALED");
    }

    /// Databases written before the fix already hold links to deleted keys;
    /// the startup migration drops them.
    #[test]
    fn startup_migration_drops_category_links_of_deleted_keys() {
        let db = test_db();
        db.insert_category(&category("c1", None, "key")).unwrap();
        db.insert_key(&rotation_key("k1", "pw")).unwrap();
        db.set_key_categories("k1", &["c1".to_string()]).unwrap();
        db.set_key_categories("ghost", &["c1".to_string()]).unwrap();

        db.migrate().unwrap();

        let links = db.all_key_categories().unwrap();
        assert_eq!(links.get("ghost"), None, "a link to a missing key survived");
        assert_eq!(links.get("k1"), Some(&vec!["c1".to_string()]));
    }

    /// A pooled connection that loaded the schema before the
    /// upgrade added columns must still read key and server rows. With
    /// `SELECT *` sqlx prepares against the stale column list, SQLite
    /// re-prepares with the new one, and sqlx indexed past its cached columns
    /// ("index out of bounds: the len is ..."). Named columns make SQLite
    /// notice the change instead.
    #[test]
    fn key_and_server_rows_read_on_every_pooled_connection_after_an_upgrade() {
        use sqlx::sqlite::SqlitePoolOptions;
        const CONNECTIONS: u32 = 4;
        let db_path =
            std::env::temp_dir().join(format!("sshspan-stale-schema-{}.db", uuid::Uuid::new_v4()));
        let url = format!("sqlite:{}?mode=rwc", db_path.display());
        let stamp = Utc::now().to_rfc3339();
        let (pool, stale) = block(async {
            let pool = SqlitePoolOptions::new()
                .max_connections(CONNECTIONS)
                .connect(&url)
                .await
                .unwrap();
            // The schema an older release created: no Bitwarden sync columns.
            for ddl in [
                "CREATE TABLE keys (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_type TEXT NOT NULL, \
                 public_key TEXT NOT NULL, private_key_encrypted TEXT NOT NULL, \
                 fingerprint_sha256 TEXT NOT NULL, fingerprint_md5 TEXT NOT NULL, comment TEXT DEFAULT '', \
                 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deployed INTEGER DEFAULT 0, \
                 deploy_path TEXT, bitwarden_id TEXT, bitwarden_sync INTEGER DEFAULT 0)",
                "CREATE TABLE servers (id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, \
                 port INTEGER NOT NULL DEFAULT 22, username TEXT NOT NULL, key_id TEXT, pem_path TEXT, \
                 auth_method TEXT NOT NULL DEFAULT 'publickey', saved_password TEXT, category_id TEXT, \
                 color TEXT, last_connected_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
            ] {
                sqlx::query(ddl).execute(&pool).await.unwrap();
            }
            sqlx::query(
                "INSERT INTO keys (id, name, key_type, public_key, private_key_encrypted, \
                 fingerprint_sha256, fingerprint_md5, created_at, updated_at) \
                 VALUES ('k1', 'old-key', 'ed25519', 'ssh-ed25519 AAAA', 'x', 'SHA256:f', 'MD5:f', ?, ?)",
            )
            .bind(&stamp)
            .bind(&stamp)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO servers (id, name, host, username, created_at, updated_at) \
                 VALUES ('s1', 'old-server', 'example.com', 'root', ?, ?)",
            )
            .bind(&stamp)
            .bind(&stamp)
            .execute(&pool)
            .await
            .unwrap();
            // Every connection loads that schema; all but one stay checked
            // out while the upgrade runs, so they keep the stale view.
            let mut held = Vec::new();
            for _ in 0..CONNECTIONS {
                let mut conn = pool.acquire().await.unwrap();
                sqlx::query("SELECT COUNT(*) FROM keys")
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap();
                sqlx::query("SELECT COUNT(*) FROM servers")
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap();
                held.push(conn);
            }
            drop(held.pop());
            while pool.num_idle() < 1 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            (pool, held)
        });
        let db = Database { pool, db_path };
        db.migrate().expect("upgrade the old database");
        block(async {
            drop(stale);
            while db.pool.num_idle() < CONNECTIONS as usize {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });

        // Round-robin over the idle queue: every connection serves reads.
        for _ in 0..CONNECTIONS * 2 {
            assert_eq!(db.get_key("k1").unwrap().unwrap().name, "old-key");
            assert_eq!(db.list_keys().unwrap().len(), 1);
            assert_eq!(db.list_keys_with_categories().unwrap().len(), 1);
            assert!(db.get_key_with_categories("k1").unwrap().is_some());
            assert_eq!(db.get_server("s1").unwrap().unwrap().name, "old-server");
            assert_eq!(db.list_servers().unwrap().len(), 1);
        }
        block(async { db.pool.close().await });
        let _ = std::fs::remove_file(&db.db_path);
    }

    // ── MCP read-modify-write (transactional) ────────────────────────────

    fn mcp_db() -> Database {
        let db_path =
            std::env::temp_dir().join(format!("sshspan-mcp-cap-{}.db", uuid::Uuid::new_v4()));
        Database::open_at(db_path).expect("open test db")
    }

    fn mcp_record(id: &str, tools: &[(&str, bool)]) -> McpServerRecord {
        McpServerRecord {
            id: id.into(),
            name: format!("srv-{id}"),
            url: "https://mcp.example.com".into(),
            auth_type: "none".into(),
            auth_header_name: None,
            auth_secret: None,
            auth_env_var: None,
            confirmed: true,
            tools: tools
                .iter()
                .map(|(n, enabled)| McpToolRecord {
                    name: (*n).into(),
                    display_name: None,
                    description: String::new(),
                    enabled: *enabled,
                    auto_approve: false,
                    pin_hash: None,
                    current_hash: None,
                    input_schema: None,
                    annotations: None,
                })
                .collect(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// The closure sees every stored record, and what it returns is written
    /// in the same transaction; a refusal writes nothing.
    #[test]
    fn modify_mcp_servers_writes_what_the_closure_decides_or_nothing() {
        let db = mcp_db();
        db.save_mcp_server(&mcp_record("a", &[("t1", false)]))
            .unwrap();
        let seen = db
            .modify_mcp_servers(|all| {
                let mut a = all[0].clone();
                a.tools[0].enabled = true;
                Ok((McpWrite::Update(a), all.len()))
            })
            .unwrap();
        assert_eq!(seen, 1);
        assert!(db.get_mcp_server("a").unwrap().unwrap().tools[0].enabled);
        let refused =
            db.modify_mcp_servers(|_| -> Result<(McpWrite, ())> { anyhow::bail!("refused") });
        assert_eq!(refused.unwrap_err().to_string(), "refused");
        assert!(db.get_mcp_server("a").unwrap().unwrap().tools[0].enabled);
        db.modify_mcp_servers(|_| Ok((McpWrite::Insert(mcp_record("b", &[])), ())))
            .unwrap();
        assert_eq!(db.list_mcp_servers().unwrap().len(), 2);
    }

    /// An insert never replaces a stored record, and an update never
    /// re-creates a removed one.
    #[test]
    fn modify_mcp_servers_never_upserts() {
        let db = mcp_db();
        db.save_mcp_server(&mcp_record("a", &[("t1", true)]))
            .unwrap();
        let clash = db
            .modify_mcp_servers(|_| Ok((McpWrite::Insert(mcp_record("a", &[("t1", false)])), ())));
        assert!(clash.is_err(), "an insert over a stored id fails");
        assert!(db.get_mcp_server("a").unwrap().unwrap().tools[0].enabled);
        let gone = db.modify_mcp_servers(|_| Ok((McpWrite::Update(mcp_record("gone", &[])), ())));
        assert_eq!(gone.unwrap_err().to_string(), "MCP server not found.");
        assert!(db.get_mcp_server("gone").unwrap().is_none());
    }

    /// A database call made in the root future of a multi-thread runtime's
    /// `block_on` (the body of a `#[tokio::test(flavor = "multi_thread")]`)
    /// waited in tokio's nested `block_on`, which parks on the parker of
    /// that very `block_on`. A wake-up meant for another part of the root
    /// future that came in during the call was used up there, and the root
    /// future waited for the next event: here for the 30 s timer, in the MCP
    /// tests of round 6 forever. The call parks on a parker of its own now,
    /// and the wake-up is kept.
    #[test]
    fn rw_fix6_a_database_call_in_a_block_on_root_keeps_the_wake_ups_of_others() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (seen, took) = runtime.block_on(async {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let calling = std::sync::Arc::new(AtomicBool::new(false));
            let in_call = calling.clone();
            // Sends while the "database call" below is waiting.
            std::thread::spawn(move || {
                while !in_call.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                std::thread::sleep(std::time::Duration::from_millis(30));
                let _ = tx.send(());
            });
            let started = std::time::Instant::now();
            let seen = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                tokio::select! {
                    biased;
                    _ = rx => true,
                    _ = async {
                        block(async {
                            calling.store(true, Ordering::SeqCst);
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await
                        });
                        std::future::pending::<()>().await
                    } => false,
                }
            })
            .await;
            (seen, started.elapsed())
        });
        assert!(matches!(seen, Ok(true)), "{seen:?}");
        assert!(
            took < std::time::Duration::from_secs(15),
            "the wake-up was lost: seen only after {took:?} (the 30 s timer)"
        );
    }

    /// Sync settings stored before destinations had to be allowed keep
    /// syncing: the one-time startup migration counts their destination as
    /// allowed. After it ran, nothing counts as allowed unless a question
    /// allowed it - a destination whose row went missing neither - and a
    /// backup restore, which never carries the sync settings, changes none
    /// of it.
    #[test]
    fn fw_r1_settings_from_before_keep_syncing_and_nothing_else_is_allowed_by_itself() {
        let db = test_db();
        // A database from before: settings without the row, and no record of
        // the migration.
        block(async {
            for (key, value) in [
                ("server_url", "https://vault.example.com"),
                ("email", "me@example.com"),
                ("master_password", "sealed"),
            ] {
                sqlx::query(
                    "INSERT INTO bitwarden_config (key, value, updated_at) \
                     VALUES (?, ?, '2026-01-01T00:00:00Z')",
                )
                .bind(key)
                .bind(value)
                .execute(&db.pool)
                .await?;
            }
            sqlx::query("DELETE FROM config WHERE key = ?")
                .bind(BITWARDEN_DESTINATION_MIGRATED)
                .execute(&db.pool)
                .await?;
            anyhow::Ok(())
        })
        .unwrap();
        assert!(!db.load_bitwarden_config().unwrap().confirmed());
        db.migrate().unwrap();
        assert!(
            db.load_bitwarden_config().unwrap().confirmed(),
            "settings from before keep syncing"
        );
        // Re-pointed later, its row gone: the migration does not run again.
        block(async {
            sqlx::query(
                "UPDATE bitwarden_config SET value = 'https://elsewhere.example.org' \
                 WHERE key = 'server_url'",
            )
            .execute(&db.pool)
            .await?;
            sqlx::query("DELETE FROM bitwarden_config WHERE key = 'confirmed_destination'")
                .execute(&db.pool)
                .await?;
            anyhow::Ok(())
        })
        .unwrap();
        db.migrate().unwrap();
        assert!(!db.load_bitwarden_config().unwrap().confirmed());
        // A restore, even of a payload that names sync settings.
        let payload = serde_json::json!({
            "settings": {
                "confirmed_destination": "x",
                "bitwarden.server_url": "https://attacker.example",
            },
            "bitwardenConfig": {
                "server_url": "https://attacker.example",
                "confirmed_destination": "[\"https://attacker.example\",\"evil@attacker.example\"]",
            },
        });
        db.restore_backup(&payload).unwrap();
        let after = db.load_bitwarden_config().unwrap();
        assert_eq!(
            after.server_url.as_deref(),
            Some("https://elsewhere.example.org")
        );
        assert!(!after.confirmed());
        db.migrate().unwrap();
        assert!(!db.load_bitwarden_config().unwrap().confirmed());
        assert_eq!(
            db.get_config(BITWARDEN_DESTINATION_MIGRATED)
                .unwrap()
                .as_deref(),
            Some("done")
        );
    }

    /// A save always stores the `confirmed_destination` row, so even a
    /// database whose migration record went missing never takes a
    /// destination saved by this version for one from before.
    #[test]
    fn fw_r1_a_saved_destination_is_never_taken_for_one_from_before() {
        let db = test_db();
        db.update_bitwarden_config(|config| {
            crate::bitwarden::apply_bitwarden_save(
                config,
                crate::bitwarden::BitwardenSave {
                    server_url: "https://attacker.example".into(),
                    email: "evil@attacker.example".into(),
                    sealed_password: Some("sealed".into()),
                    folder_name: "SSHSpan_Keys".into(),
                    servers_folder_name: "SSHSpan_Servers".into(),
                },
            )
        })
        .unwrap();
        block(async {
            sqlx::query("DELETE FROM config WHERE key = ?")
                .bind(BITWARDEN_DESTINATION_MIGRATED)
                .execute(&db.pool)
                .await?;
            anyhow::Ok(())
        })
        .unwrap();
        db.migrate().unwrap();
        let config = db.load_bitwarden_config().unwrap();
        assert_eq!(config.confirmed_destination.as_deref(), Some(""));
        assert!(!config.confirmed());
    }

    /// On a current-thread runtime a database call is not waited for on a
    /// parker of its own ([`block_on_own_parker`]): the runtime's only
    /// thread would sleep there, driving neither its timers nor its I/O. It
    /// keeps the old behaviour - `block_in_place` refuses at once, with
    /// tokio's message - not a silent hang. (The multi-thread side is
    /// `rw_fix6_a_database_call_in_a_block_on_root_keeps_the_wake_ups_of_others`.)
    #[test]
    #[should_panic(expected = "can call blocking only when running on the multi-threaded runtime")]
    fn fw_r7_a_current_thread_runtime_keeps_the_old_behaviour() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async { block(async { 1 }) });
    }
}

fn short_hash(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// The sync settings from their `bitwarden_config` rows (key, value).
fn bitwarden_config_from_rows(rows: Vec<(String, String)>) -> BitwardenConfig {
    let mut config = BitwardenConfig::default();
    for (key, value) in rows {
        match key.as_str() {
            "server_url" => config.server_url = Some(value),
            "email" => config.email = Some(value),
            "master_password" => config.master_password = Some(value),
            "folder_name" => config.folder_name = Some(value),
            "servers_folder_name" => config.servers_folder_name = Some(value),
            "device_id" => config.device_id = Some(value),
            "last_sync" => {
                config.last_sync = DateTime::parse_from_rfc3339(&value)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }
            "last_result" => config.last_result = Some(value),
            "confirmed_destination" => config.confirmed_destination = Some(value),
            _ => {}
        }
    }
    config
}

/// The assistant settings from their `assistant_config` rows (key, value).
fn assistant_config_from_rows(rows: Vec<(String, String)>) -> AssistantConfig {
    let mut config = AssistantConfig::default();
    for (key, value) in rows {
        match key.as_str() {
            "provider" => config.provider = Some(value),
            "base_url" => config.base_url = Some(value),
            "model" => config.model = Some(value),
            "api_key" => config.api_key = Some(value),
            _ => {}
        }
    }
    config
}

/// Upsert every set field of `config` inside `tx`.
async fn write_bitwarden_config(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    config: &BitwardenConfig,
) -> Result<()> {
    let fields: [(&str, Option<String>); 9] = [
        ("server_url", config.server_url.clone()),
        ("email", config.email.clone()),
        ("master_password", config.master_password.clone()),
        ("folder_name", config.folder_name.clone()),
        ("servers_folder_name", config.servers_folder_name.clone()),
        ("device_id", config.device_id.clone()),
        ("last_sync", config.last_sync.map(|d| d.to_rfc3339())),
        ("last_result", config.last_result.clone()),
        (
            "confirmed_destination",
            config.confirmed_destination.clone(),
        ),
    ];
    let now = Utc::now().to_rfc3339();
    for (key, value) in fields {
        if let Some(v) = value {
            sqlx::query(
                "INSERT INTO bitwarden_config (key, value, updated_at) VALUES (?, ?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(key)
            .bind(v)
            .bind(&now)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}
/// Whether a stored RFC 3339 timestamp is the instant `expected` (compared as
/// instants, so formatting differences do not matter).
fn same_instant(stored: &str, expected: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(stored).is_ok_and(|t| t.with_timezone(&Utc) == expected)
}

/// Where the vault database lives (also named in the startup error dialog
/// when it cannot be opened).
pub(crate) fn get_db_path(_app: &AppHandle) -> Result<PathBuf> {
    // Dev/test override: SSHSPAN_DB=<path> isolates a dev instance from the
    // real vault (used by the local e2e rig). Compiled only into debug
    // builds: in a release build, any process that can set this variable at
    // launch could otherwise silently redirect the whole vault to a database
    // it controls (a master-password phishing setup).
    #[cfg(debug_assertions)]
    if let Ok(p) = std::env::var("SSHSPAN_DB") {
        if !p.trim().is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let dirs = ProjectDirs::from("org", "sshspan", "SSHSpan")
        .ok_or_else(|| anyhow::anyhow!("Could not determine app data directory"))?;
    Ok(dirs.data_dir().join("sshspan.db"))
}

#[cfg(test)]
mod ru5_fix2_tests {
    use super::*;

    fn temp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!("sshspan-test-{}.db", uuid::Uuid::new_v4()))
    }

    /// A database whose pool has ONE connection, so a TEMP trigger created on
    /// it applies to every statement the database runs.
    fn single_connection_db(path: &std::path::Path) -> Database {
        let url = format!("sqlite:{}?mode=rwc", path.display());
        let pool = block(async {
            sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
        })
        .unwrap();
        let db = Database {
            pool,
            db_path: path.to_path_buf(),
        };
        db.migrate().unwrap();
        db
    }

    fn settings(url: &str, email: &str, sealed: &str) -> BitwardenConfig {
        BitwardenConfig {
            server_url: Some(url.into()),
            email: Some(email.into()),
            master_password: Some(sealed.into()),
            ..BitwardenConfig::default()
        }
    }

    fn endpoint(config: &BitwardenConfig) -> (Option<String>, Option<String>, Option<String>) {
        (
            config.server_url.clone(),
            config.email.clone(),
            config.master_password.clone(),
        )
    }

    /// Make every write of the stored master password fail on `db`'s only
    /// connection.
    fn refuse_master_password_writes(db: &Database) {
        for event in ["INSERT", "UPDATE"] {
            block(
                sqlx::query(&format!(
                    "CREATE TEMP TRIGGER refuse_mp_{event} BEFORE {event} ON bitwarden_config \
                 WHEN NEW.key = 'master_password' \
                 BEGIN SELECT RAISE(ABORT, 'refused by the test'); END"
                ))
                .execute(&db.pool),
            )
            .unwrap();
        }
    }

    #[test]
    fn a_settings_save_that_fails_part_way_changes_nothing() {
        // The fields used to be separate autocommit statements, so
        // a save that failed after the URL kept the NEW URL with the OLD
        // sealed password.
        let path = temp_db_path();
        let db = single_connection_db(&path);
        db.save_bitwarden_config(&settings("https://a.example", "a@example.com", "sealed-a"))
            .unwrap();
        refuse_master_password_writes(&db);
        let result = db.update_bitwarden_config(|current| {
            current.server_url = Some("https://b.example".into());
            current.email = Some("b@example.com".into());
            current.master_password = Some("sealed-b".into());
            Ok(())
        });
        assert!(result.is_err(), "the refused write must fail the save");
        let stored = db.load_bitwarden_config().unwrap();
        assert_eq!(
            endpoint(&stored),
            (
                Some("https://a.example".into()),
                Some("a@example.com".into()),
                Some("sealed-a".into())
            ),
            "a failed save must leave every field as it was"
        );
    }

    #[test]
    fn readers_never_see_a_mixed_server_account_and_password() {
        // A reader on another connection must see either the old
        // settings or the new ones - never the new URL with the old password.
        let path = temp_db_path();
        let writer = single_connection_db(&path);
        let a = settings("https://a.example", "a@example.com", "sealed-a");
        let b = settings("https://b.example", "b@example.com", "sealed-b");
        writer.save_bitwarden_config(&a).unwrap();
        let reader = Database::open_at(path.clone()).unwrap();

        // Deterministic: a save that fails after its first fields.
        refuse_master_password_writes(&writer);
        let next = b.clone();
        assert!(writer
            .update_bitwarden_config(move |current| {
                *current = next;
                Ok(())
            })
            .is_err());
        assert_eq!(
            endpoint(&reader.load_bitwarden_config().unwrap()),
            endpoint(&a)
        );
        for event in ["INSERT", "UPDATE"] {
            block(sqlx::query(&format!("DROP TRIGGER refuse_mp_{event}")).execute(&writer.pool))
                .unwrap();
        }

        // Concurrent: whole settings switched back and forth while another
        // connection keeps reading.
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = done.clone();
        let (seen_a, seen_b) = (endpoint(&a), endpoint(&b));
        let watcher = std::thread::spawn(move || {
            let mut reads = 0usize;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                let seen = endpoint(&reader.load_bitwarden_config().unwrap());
                assert!(
                    seen == seen_a || seen == seen_b,
                    "a reader saw a mixed tuple: {seen:?}"
                );
                reads += 1;
            }
            reads
        });
        for round in 0..40 {
            let next = if round % 2 == 0 { b.clone() } else { a.clone() };
            writer
                .update_bitwarden_config(move |current| {
                    *current = next;
                    Ok(())
                })
                .unwrap();
        }
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(watcher.join().unwrap() > 0);
    }

    #[test]
    fn a_settings_write_waits_for_another_connections_write() {
        // Round 3: the settings transaction read first and wrote second; with
        // another connection holding a write, SQLite refused the upgrade at
        // once ("database is locked") instead of waiting, so a finished sync
        // failed to store its result and Save could fail for nothing.
        let path = temp_db_path();
        let db = Database::open_at(path.clone()).unwrap();
        db.save_bitwarden_config(&settings("https://a.example", "a@example.com", "sealed-a"))
            .unwrap();
        let holder = hold_a_write(&path, 300);
        let started = std::time::Instant::now();
        db.update_bitwarden_config(|current| {
            current.last_result = Some("{\"ok\":true}".into());
            Ok(())
        })
        .expect("the settings write must wait for the other write, not fail");
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(200),
            "it waited for the other write: {:?}",
            started.elapsed()
        );
        holder.join().unwrap();
        assert_eq!(
            db.load_bitwarden_config().unwrap().last_result.as_deref(),
            Some("{\"ok\":true}")
        );
    }

    /// Hold a write on ANOTHER connection to the database at `path` for `ms`
    /// milliseconds; returns once that connection holds the write lock.
    fn hold_a_write(path: &std::path::Path, ms: u64) -> std::thread::JoinHandle<()> {
        let other = Database::open_at(path.to_path_buf()).unwrap();
        let (held, wait_for_hold) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            block(async {
                let mut conn = other.pool.acquire().await.unwrap();
                sqlx::query("BEGIN IMMEDIATE")
                    .execute(&mut *conn)
                    .await
                    .unwrap();
                sqlx::query(
                    "INSERT INTO config (key, value, updated_at) VALUES ('probe', 'x', 'now') \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                )
                .execute(&mut *conn)
                .await
                .unwrap();
                held.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(ms));
                sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
            })
        });
        wait_for_hold.recv().unwrap();
        holder
    }

    /// A fixed instant the pull fixtures were last changed at.
    fn changed_at() -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_790_000_000_000).unwrap()
    }

    fn pull_fixture_key() -> KeyRecord {
        KeyRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "before-pull".into(),
            key_type: "ed25519".into(),
            public_key: "ssh-ed25519 AAAA before".into(),
            private_key_encrypted: "sealed-before".into(),
            fingerprint_sha256: "SHA256:before".into(),
            fingerprint_md5: "MD5:before".into(),
            comment: String::new(),
            created_at: changed_at(),
            updated_at: changed_at(),
            deployed: false,
            deploy_path: None,
            bitwarden_id: Some("c1".into()),
            bitwarden_sync: true,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
            category_ids: Vec::new(),
        }
    }

    fn pull_fixture_server() -> ServerRecord {
        ServerRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "web".into(),
            host: "before.example.com".into(),
            port: 22,
            username: "root".into(),
            key_id: None,
            pem_path: None,
            auth_method: "password".into(),
            saved_password: None,
            category_id: None,
            color: None,
            last_connected_at: None,
            created_at: changed_at(),
            updated_at: changed_at(),
            bitwarden_id: Some("s1".into()),
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
        }
    }

    #[test]
    fn a_pull_waits_for_another_connections_write() {
        // Round 4: apply_pulled_key / apply_pulled_server read the row and then
        // wrote it in a deferred transaction, so another connection's write
        // made the pull fail at once ("database is locked") instead of waiting.
        let path = temp_db_path();
        let db = Database::open_at(path.clone()).unwrap();
        let key = pull_fixture_key();
        db.insert_key(&key).unwrap();
        let holder = hold_a_write(&path, 300);
        let started = std::time::Instant::now();
        let written = db
            .apply_pulled_key(
                &key.id,
                &KeyPull {
                    name: "pulled".into(),
                    key_type: "ed25519".into(),
                    public_key: "ssh-ed25519 AAAA pulled".into(),
                    private_key_encrypted: "sealed-pulled".into(),
                    fingerprint_sha256: "SHA256:before".into(),
                    fingerprint_md5: "MD5:pulled".into(),
                    comment: String::new(),
                    bitwarden_revision_ts: Some(1),
                },
                key.updated_at,
            )
            .expect("the key pull must wait for the other write, not fail");
        assert!(written);
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(200),
            "it waited for the other write: {:?}",
            started.elapsed()
        );
        holder.join().unwrap();
        assert_eq!(db.get_key(&key.id).unwrap().unwrap().name, "pulled");

        let server = pull_fixture_server();
        db.insert_server(&server).unwrap();
        let holder = hold_a_write(&path, 300);
        let started = std::time::Instant::now();
        let written = db
            .apply_pulled_server(
                &server.id,
                &ServerPull {
                    name: "web".into(),
                    host: "pulled.example.com".into(),
                    port: 2222,
                    username: "ops".into(),
                    auth_method: "password".into(),
                    key_id: None,
                    category_id: None,
                    saved_password: None,
                    bitwarden_revision_ts: None,
                },
                server.updated_at,
            )
            .expect("the server pull must wait for the other write, not fail");
        assert!(written);
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(200),
            "it waited for the other write: {:?}",
            started.elapsed()
        );
        holder.join().unwrap();
        assert_eq!(
            db.get_server(&server.id).unwrap().unwrap().host,
            "pulled.example.com"
        );
    }
}

/// Helpers for the tests of every module that writes through [`Database`].
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// How often `db`'s categories table was read (`list_categories`,
    /// `get_category`) so far.
    pub(crate) fn category_reads(db: &Database) -> usize {
        CATEGORY_READS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|reads| reads.get(&db.db_path).copied())
            .unwrap_or(0)
    }

    /// Run `statements` - SQL and its text binds - on ANOTHER connection to
    /// `db`'s file inside `BEGIN IMMEDIATE`, and keep that write open for
    /// `ms` milliseconds before committing: a concurrent writer caught
    /// mid-commit. Returns once the write lock is held. The connection is a
    /// plain one (`open_at` would run the migrations), on a thread and
    /// runtime of its own, so sync and async tests can both use it.
    pub(crate) fn hold_write_bound(
        db: &Database,
        statements: Vec<(String, Vec<String>)>,
        ms: u64,
    ) -> std::thread::JoinHandle<()> {
        let url = format!("sqlite:{}?mode=rwc", db.db_path.display());
        let (held, wait_for_hold) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let pool = SqlitePool::connect(&url).await.unwrap();
                let mut conn = pool.acquire().await.unwrap();
                sqlx::query("BEGIN IMMEDIATE")
                    .execute(&mut *conn)
                    .await
                    .unwrap();
                for (sql, binds) in &statements {
                    let mut query = sqlx::query(sql);
                    for bind in binds {
                        query = query.bind(bind.as_str());
                    }
                    query.execute(&mut *conn).await.unwrap();
                }
                held.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(ms));
                sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
                drop(conn);
                pool.close().await;
            });
        });
        wait_for_hold.recv().unwrap();
        holder
    }

    /// [`hold_write_bound`] for statements without binds.
    pub(crate) fn hold_write(
        db: &Database,
        statements: &[&str],
        ms: u64,
    ) -> std::thread::JoinHandle<()> {
        let statements = statements
            .iter()
            .map(|sql| (sql.to_string(), Vec::new()))
            .collect();
        hold_write_bound(db, statements, ms)
    }

    /// Run `sql` once, on another connection to `db`'s file - a schema
    /// change, such as a trigger that refuses writes, then holds for every
    /// connection.
    pub(crate) fn execute(db: &Database, sql: &str) {
        hold_write(db, &[sql], 0).join().unwrap();
    }
}

#[cfg(test)]
mod ru6b_tests {
    use super::test_support::hold_write;
    use super::*;
    use std::time::{Duration, Instant};

    fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("sshspan-ru6b-{}.db", uuid::Uuid::new_v4()))
    }

    const PROBE_WRITE: &str =
        "INSERT INTO config (key, value, updated_at) VALUES ('probe', 'x', 'now') \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value";

    fn assert_waited(started: Instant) {
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "it waited for the other write: {:?}",
            started.elapsed()
        );
    }

    // ── Read-then-write transactions take the write lock first ───

    /// A restore whose first statement is a read (a server's category
    /// check) used a deferred transaction: with another connection writing,
    /// SQLite refused its first write at once ("database is locked").
    #[test]
    fn a_restore_that_reads_first_waits_for_another_connections_write() {
        let db = Database::open_at(temp_path()).unwrap();
        let payload = serde_json::json!({
            "servers": [{
                "id": "s1", "name": "web", "host": "web.example.com", "port": 22,
                "username": "root", "category_id": "c1",
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            }],
        });
        let holder = hold_write(&db, &[PROBE_WRITE], 300);
        let started = Instant::now();
        let counts = db
            .restore_backup(&payload)
            .expect("the restore must wait for the other write, not fail");
        assert_waited(started);
        holder.join().unwrap();
        assert_eq!(counts["servers"], 1);
        assert!(db.get_server("s1").unwrap().is_some());
    }

    /// A master-password change on a vault with no keys read first (the
    /// key-id check) and wrote second, in a deferred transaction.
    #[test]
    fn a_rotation_without_keys_waits_for_another_connections_write() {
        let db = Database::open_at(temp_path()).unwrap();
        let mut server = ServerRecord {
            id: "s1".into(),
            name: "web".into(),
            host: "web.example.com".into(),
            port: 22,
            username: "root".into(),
            key_id: None,
            pem_path: None,
            auth_method: "password".into(),
            saved_password: Some("sealed-old".into()),
            category_id: None,
            color: None,
            last_connected_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            bitwarden_id: None,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
        };
        db.insert_server(&server).unwrap();
        let rotation = VaultRotation {
            server_passwords: vec![ResealedSecret {
                id: "s1".into(),
                old: "sealed-old".into(),
                new: "sealed-new".into(),
            }],
            master_hash: "$argon2id$new".into(),
            ..VaultRotation::default()
        };
        let holder = hold_write(&db, &[PROBE_WRITE], 300);
        let started = Instant::now();
        db.apply_vault_rotation(&rotation)
            .expect("the rotation must wait for the other write, not fail");
        assert_waited(started);
        holder.join().unwrap();
        server.saved_password = Some("sealed-new".into());
        assert_eq!(
            db.get_server("s1").unwrap().unwrap().saved_password,
            server.saved_password
        );
    }

    /// The known_hosts port migration checks whether the qualified name is
    /// taken (a read) before it renames a row (a write).
    #[test]
    fn the_known_hosts_port_migration_waits_for_another_connections_write() {
        let db = Database::open_at(temp_path()).unwrap();
        block(async {
            sqlx::query(
                "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen) \
                 VALUES ('legacy.example', 'AAAA', 'SHA256:x', 'now')",
            )
            .execute(&db.pool)
            .await
            .unwrap();
        });
        let holder = hold_write(&db, &[PROBE_WRITE], 300);
        let started = Instant::now();
        block(db.migrate_known_hosts_port_qualify())
            .expect("the migration must wait for the other write, not fail");
        assert_waited(started);
        holder.join().unwrap();
        assert!(db.get_known_host("legacy.example:22").unwrap().is_some());
    }

    /// The fingerprint migration read the rows OUTSIDE its transaction, so a
    /// pin rewritten in between got the fingerprint of the key it replaced.
    #[test]
    fn the_fingerprint_migration_reads_the_rows_it_rewrites_inside_its_transaction() {
        use base64ct::Encoding;
        let db = Database::open_at(temp_path()).unwrap();
        let old_key = base64ct::Base64::encode_string(b"old host key");
        let new_key = base64ct::Base64::encode_string(b"new host key");
        let new_fp = crate::ssh_client::known_host_fingerprint(&new_key, "");
        block(async {
            sqlx::query(
                "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen) \
                 VALUES ('h:22', ?, 'legacy-form', 'now')",
            )
            .bind(&old_key)
            .execute(&db.pool)
            .await
            .unwrap();
        });
        // Another connection re-pins the host while the migration starts.
        let repin = format!(
            "UPDATE known_hosts SET host_key = '{new_key}', fingerprint_sha256 = '{new_fp}' \
             WHERE host = 'h:22'"
        );
        let holder = hold_write(&db, &[&repin], 300);
        block(db.migrate_known_host_fingerprints()).unwrap();
        holder.join().unwrap();
        let pin = db.get_known_host("h:22").unwrap().unwrap();
        assert_eq!(pin.host_key, new_key);
        let stored: String = block(async {
            sqlx::query_scalar("SELECT fingerprint_sha256 FROM known_hosts WHERE host = 'h:22'")
                .fetch_one(&db.pool)
                .await
                .unwrap()
        });
        assert_eq!(stored, new_fp, "the stored fingerprint is the new key's");
    }

    /// The assistant settings were written as four separate statements, so a
    /// save that failed part-way kept the new provider and base URL beside
    /// the OLD sealed key - which a chat then sent to an endpoint it was not
    /// saved for (and a concurrent reader could see that mix mid-save).
    #[test]
    fn an_assistant_settings_save_that_fails_part_way_changes_nothing() {
        let db = Database::open_at(temp_path()).unwrap();
        db.save_assistant_config(&AssistantConfig {
            provider: Some("openai".into()),
            base_url: Some("https://a.example.com/v1".into()),
            model: Some("m-a".into()),
            api_key: Some("sealed-a".into()),
        })
        .unwrap();
        for event in ["INSERT", "UPDATE"] {
            block(
                sqlx::query(&format!(
                    "CREATE TRIGGER refuse_key_{event} BEFORE {event} ON assistant_config \
                     WHEN NEW.key = 'api_key' BEGIN SELECT RAISE(ABORT, 'refused by the test'); END"
                ))
                .execute(&db.pool),
            )
            .unwrap();
        }
        let result = db.save_assistant_config(&AssistantConfig {
            provider: Some("anthropic".into()),
            base_url: Some("https://b.example.com".into()),
            model: Some("m-b".into()),
            api_key: Some("sealed-b".into()),
        });
        assert!(result.is_err(), "the refused key write fails the save");
        let stored = db.load_assistant_config().unwrap();
        assert_eq!(
            (
                stored.provider.as_deref(),
                stored.base_url.as_deref(),
                stored.model.as_deref(),
                stored.api_key.as_deref()
            ),
            (
                Some("openai"),
                Some("https://a.example.com/v1"),
                Some("m-a"),
                Some("sealed-a")
            ),
            "a failed save leaves every field as it was"
        );
    }

    /// The assistant settings save reads the stored settings, then writes
    /// them back: in a deferred transaction another connection's write made
    /// it fail at once ("database is locked") - and had it waited, it would
    /// have written its stale read over that write. It takes the write lock
    /// first, waits, and edits what the other write committed.
    #[test]
    fn an_assistant_settings_save_waits_for_another_connections_write() {
        let db = Database::open_at(temp_path()).unwrap();
        db.save_assistant_config(&AssistantConfig {
            provider: Some("openai".into()),
            base_url: None,
            model: Some("m-a".into()),
            api_key: Some("sealed-a".into()),
        })
        .unwrap();
        let holder = hold_write(
            &db,
            &["UPDATE assistant_config SET value = 'sealed-b' WHERE key = 'api_key'"],
            300,
        );
        let started = Instant::now();
        db.update_assistant_config(|config| {
            config.model = Some("m-b".into());
            Ok(())
        })
        .expect("the save must wait for the other write, not fail");
        assert_waited(started);
        holder.join().unwrap();
        let stored = db.load_assistant_config().unwrap();
        assert_eq!(stored.model.as_deref(), Some("m-b"));
        assert_eq!(
            stored.api_key.as_deref(),
            Some("sealed-b"),
            "the other connection's write is kept"
        );
    }

    /// A new vault's verifier is stored only if none is: the check and the
    /// write are one transaction that takes the write lock first. Deferred,
    /// another connection's write (a second create) made it fail at once.
    #[test]
    fn a_vault_create_waits_for_another_connections_write() {
        let db = Database::open_at(temp_path()).unwrap();
        let holder = hold_write(
            &db,
            &["INSERT INTO config (key, value, updated_at) VALUES ('master.hash', 'first', 'now')"],
            300,
        );
        let started = Instant::now();
        let created = db
            .create_vault_verifier("master.hash", "second", "vault.created", "now")
            .expect("the create must wait for the other write, not fail");
        assert_waited(started);
        holder.join().unwrap();
        assert!(!created, "a vault created meanwhile is not replaced");
        assert_eq!(
            db.get_config("master.hash").unwrap().as_deref(),
            Some("first")
        );
        // With no vault yet, it is created.
        let fresh = Database::open_at(temp_path()).unwrap();
        assert!(fresh
            .create_vault_verifier("master.hash", "only", "vault.created", "now")
            .unwrap());
        assert_eq!(
            fresh.get_config("master.hash").unwrap().as_deref(),
            Some("only")
        );
    }

    /// Two first connections to one new host: the second saw no pin (the
    /// first was not committed yet), then failed its INSERT on the primary
    /// key instead of comparing the keys.
    #[test]
    fn a_host_key_pinned_meanwhile_by_another_connection_is_compared_not_duplicated() {
        let db = Database::open_at(temp_path()).unwrap();
        let holder = hold_write(
            &db,
            &[
                "INSERT INTO known_hosts (host, host_key, fingerprint_sha256, first_seen, source) \
               VALUES ('h:22', 'KEY-B', 'SHA256:b', 'now', 'connection')",
            ],
            300,
        );
        let started = Instant::now();
        let matches = db
            .add_known_host("h:22", "KEY-A", "SHA256:a")
            .expect("the pin must wait for the other write and compare, not fail");
        assert_waited(started);
        holder.join().unwrap();
        assert!(!matches, "a different key pinned meanwhile is a mismatch");
        assert_eq!(
            db.get_known_host("h:22").unwrap().unwrap().host_key,
            "KEY-B"
        );
        // The same key pinned meanwhile is a match.
        assert!(db.add_known_host("h:22", "KEY-B", "SHA256:b").unwrap());
        // A host nobody pinned is pinned.
        assert!(db.add_known_host("other:22", "KEY-C", "SHA256:c").unwrap());
        assert_eq!(
            db.get_known_host("other:22").unwrap().unwrap().host_key,
            "KEY-C"
        );
    }

    // ── Category walks are bounded ───────────────────────────────

    fn category(id: &str, parent: Option<&str>) -> Category {
        Category {
            id: id.into(),
            name: format!("cat-{id}"),
            parent_id: parent.map(String::from),
            scope: "key".into(),
            color: None,
            sort_index: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// `category_path_string` for `id`, or a failure if it does not finish
    /// (an unbounded walk never does). The limit is wide for a loaded
    /// machine: a walk that never ends fails it all the same.
    fn path_that_ends(db: &Database, id: &str) -> String {
        let (done, result) = std::sync::mpsc::channel();
        let (db, id) = (db.clone(), id.to_string());
        std::thread::spawn(move || {
            let _ = done.send(db.category_path_string(&id));
        });
        result
            .recv_timeout(Duration::from_secs(30))
            .expect("the category path walk must end (parent loop)")
    }

    /// A restored vault can hold parent loops (A2-45). The Bitwarden notes
    /// path of a category in one - or under one - walked them forever.
    #[test]
    fn a_category_path_ends_on_a_self_loop_a_two_node_loop_and_a_loop_above_it() {
        let db = Database::open_at(temp_path()).unwrap();
        for c in [
            category("self", Some("self")),
            category("a", Some("b")),
            category("b", Some("a")),
            category("n", Some("a")),
            category("root", None),
            category("leaf", Some("root")),
        ] {
            db.insert_category(&c).unwrap();
        }
        assert_eq!(path_that_ends(&db, "self"), "cat-self");
        assert_eq!(path_that_ends(&db, "a"), "cat-b/cat-a");
        // Reached through a category that is not part of the loop.
        assert_eq!(path_that_ends(&db, "n"), "cat-b/cat-a/cat-n");
        // A normal chain is unchanged.
        assert_eq!(path_that_ends(&db, "leaf"), "cat-root/cat-leaf");
        assert_eq!(path_that_ends(&db, "missing"), "");
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// The shared walk says whether a chain has a top, and visits each
    /// category once - a self-loop, a two-node loop and a loop reached
    /// through a category outside it all end, with no root.
    #[test]
    fn a_category_chain_ends_and_says_whether_it_has_a_top() {
        let cats = [
            category("self", Some("self")),
            category("a", Some("b")),
            category("b", Some("a")),
            category("n", Some("a")),
            category("root", None),
            category("leaf", Some("root")),
            category("orphan", Some("deleted-parent")),
        ];
        assert_eq!(
            category_chain(&cats, "self"),
            CategoryChain::NoRoot(ids(&["self"]))
        );
        assert_eq!(
            category_chain(&cats, "a"),
            CategoryChain::NoRoot(ids(&["a", "b"]))
        );
        assert_eq!(
            category_chain(&cats, "n"),
            CategoryChain::NoRoot(ids(&["n", "a", "b"]))
        );
        assert_eq!(
            category_chain(&cats, "leaf"),
            CategoryChain::Rooted(ids(&["leaf", "root"]))
        );
        // A parent that no longer exists is shown at the top level.
        assert_eq!(
            category_chain(&cats, "orphan"),
            CategoryChain::Rooted(ids(&["orphan"]))
        );
        assert_eq!(
            category_chain(&cats, "missing"),
            CategoryChain::Rooted(Vec::new())
        );
    }

    #[test]
    fn a_category_chain_stops_at_the_depth_cap() {
        let cats: Vec<Category> = (0..MAX_CATEGORY_DEPTH + 10)
            .map(|n| {
                let parent = n.checked_sub(1).map(|p| format!("c{p}"));
                category(&format!("c{n}"), parent.as_deref())
            })
            .collect();
        let deepest = format!("c{}", MAX_CATEGORY_DEPTH + 9);
        let chain = category_chain(&cats, &deepest);
        assert!(matches!(chain, CategoryChain::NoRoot(_)), "{chain:?}");
        assert_eq!(chain.ids().len(), MAX_CATEGORY_DEPTH);
        let shallow = format!("c{}", MAX_CATEGORY_DEPTH - 1);
        assert!(matches!(
            category_chain(&cats, &shallow),
            CategoryChain::Rooted(_)
        ));
    }
}
